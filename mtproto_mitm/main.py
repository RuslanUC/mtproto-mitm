import json
from asyncio import get_event_loop
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from time import time

import click
from mtproto import ConnectionRole
from mtproto.transport import Connection
from mtproto.transport.packets import ErrorPacket, QuickAckPacket, BasePacket, MessagePacket
from socks5server import DataDirection, SocksServer, PasswordAuthentication, Socks5Client
from socks5server.enums import AuthMethod, DataModify

from mtproto_mitm.protocol import MTProto, MessageContainer


class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.hex()
        elif isinstance(obj, int) and obj > 2 ** 53 - 1:
            return str(obj)
        return super().default(obj)


class ConnectionPair:
    __slots__ = ("to_server", "to_client",)

    def __init__(self):
        self.to_server: Connection = Connection(ConnectionRole.SERVER)
        self.to_client: Connection = Connection(ConnectionRole.CLIENT)


class MitmServer:
    def __init__(
            self, host: str = "0.0.0.0", port: int = 1080, no_auth: bool = False, quiet: bool = False,
            output_dir: Path | None = None
    ):
        self._server = SocksServer(host, port, no_auth)
        self._clients: dict[Socks5Client, ConnectionPair] = {}
        self._sessions: dict[Socks5Client, list[MessageContainer]] = {}
        self._quiet = quiet
        self._output_dir = output_dir
        self._output_dir.mkdir(parents=True, exist_ok=True)

        self._server.on_client_disconnected(self._on_disconnect)
        self._server.on_data_modify(self._on_data)

    def set_proxy_users(self, users: dict[str, str]):
        self._server.register_authentication(AuthMethod.PASSWORD, PasswordAuthentication(users))

    def _handle_packet(self, client: Socks5Client, packet: BasePacket, direction: DataDirection) -> None:
        sender = ConnectionRole.CLIENT if direction is DataDirection.CLIENT_TO_DST else ConnectionRole.SERVER
        arrow = "->" if direction is DataDirection.CLIENT_TO_DST else "<-"

        message = None
        if isinstance(packet, MessagePacket):
            message = MTProto.read_object(packet, sender)

        if isinstance(packet, ErrorPacket):
            if not self._quiet:
                print(f" {arrow} ERROR({packet.error_code})")
        elif isinstance(packet, QuickAckPacket):
            if not self._quiet:
                print(f" {arrow} QUICK_ACK({packet.token!r})")
        elif message is None:
            if not self._quiet:
                print(f" {arrow} UNKNOWN({packet!r}")
        else:
            self._sessions[client].append(message)
            if not self._quiet:
                print(f" {arrow} {message}")

    async def _on_data(self, client: Socks5Client, direction: DataDirection, data: bytes) -> DataModify | None:
        if client not in self._clients:
            self._clients[client] = ConnectionPair()
            self._sessions[client] = []

        conn = self._clients[client]

        current = conn.to_server if direction is DataDirection.CLIENT_TO_DST else conn.to_client
        receiver = conn.to_client if direction is DataDirection.CLIENT_TO_DST else conn.to_server

        current.data_received(data)

        to_send = b""

        while (packet := current.next_event()) is not None:
            self._handle_packet(client, packet, direction)
            to_send += receiver.send(packet)

        return to_send

    async def _on_disconnect(self, client: Socks5Client) -> None:
        if client not in self._clients:
            return
        if client not in self._sessions:
            self._sessions[client] = []

        await self._on_data(client, DataDirection.CLIENT_TO_DST, b"")
        await self._on_data(client, DataDirection.DST_TO_CLIENT, b"")

        del self._clients[client]
        await self._save(client)

    async def run_async(self) -> None:
        await self._server.serve()

    def _sync_save(self, messages: list[MessageContainer] | None) -> None:
        if messages is None:
            return

        messages_json = []
        for message in messages:
            messages_json.append({
                "metadata": {
                    "auth_key_id": message.meta.auth_key_id,
                    "message_id": message.meta.message_id,
                    "session_id": message.meta.session_id,
                    "salt": message.meta.salt,
                    "seq_no": message.meta.seq_no,
                    "msg_key": message.meta.msg_key,
                },
                "object": message.obj.to_dict() if message.obj is not None else None,
                "raw_data": b64encode(message.raw_data) if message.raw_data is not None else None,
            })

        sid = hex(messages_json[-1]["metadata"]["session_id"] or 0)[2:6] if messages_json else "0000"
        with open(self._output_dir / f"{int(time()*1000)}_{sid}.json", "w") as f:
            json.dump(messages_json, f, cls=JsonEncoder, indent=2)

    async def _save(self, client: Socks5Client) -> None:
        if not self._output_dir:
            return

        with ThreadPoolExecutor() as pool:
            await get_event_loop().run_in_executor(pool, self._sync_save, self._sessions.pop(client, None))

    def run(self) -> None:
        try:
            get_event_loop().run_until_complete(self.run_async())
        except KeyboardInterrupt:
            pass

        if not self._output_dir:
            return

        if not self._quiet:
            print("Saving sessions...")

        for client in list(self._sessions.keys()):
            self._sync_save(self._sessions.pop(client, None))


@click.command()
@click.option("--host", "-h", type=click.STRING, default="0.0.0.0", help="Proxy host to run on.")
@click.option("--port", "-p", type=click.INT, default=1080, help="Proxy port to run on.")
@click.option("--key", "-k", type=click.STRING, multiple=True, help="Hex-encoded telegram auth key.")
@click.option("--keys-file", "-f", type=click.STRING, default=None, help="File with telegram auth keys.")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Do not show requests in real time.")
@click.option("--output", "-o", type=click.STRING, default=None,
              help="Directory to which mtproto requests will be saved.")
@click.option("--proxy-no-auth", is_flag=True, default=False, help="Disable authentication for proxy.")
@click.option("--proxy-user", type=click.STRING, multiple=True, help="Proxy user in login:password format.")
def main(host: str, port: int, key: list[str], keys_file: str, quiet: bool, output: str | None, proxy_no_auth: bool,
         proxy_user: list[str]):
    if not quiet:
        print("Running...")

    for k in key:
        MTProto.register_key(bytes.fromhex(k))

    if keys_file:
        with open(keys_file) as f:
            keys = f.read().splitlines()
        for k in keys:
            MTProto.register_key(bytes.fromhex(k))

    server = MitmServer(host, port, proxy_no_auth, quiet, Path(output) if output is not None else None)
    if proxy_user:
        server.set_proxy_users({login: password for user in proxy_user for login, password in [user.split(":")]})

    server.run()


if __name__ == "__main__":
    main()
