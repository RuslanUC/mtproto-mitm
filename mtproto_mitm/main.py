import json
from asyncio import get_event_loop
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from time import time

import click
from socks5server import DataDirection, SocksServer, PasswordAuthentication, Socks5Client

from mtproto_mitm.connection import PeekBytesIO, Connection, IgnoredConn
from mtproto_mitm.protocol import MTProto, MessageContainer


class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.hex()
        elif isinstance(obj, int) and obj > 2 ** 53 - 1:
            return str(obj)
        return super().default(obj)


class MitmServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 1080, no_auth: bool = False, quiet: bool = False,
                 output_dir: Path | None = None):
        self._server = SocksServer(host, port, no_auth)
        self._clients: dict[Socks5Client, tuple[Connection, Connection]] = {}
        self._sessions: dict[Socks5Client, list[MessageContainer]] = {}
        self._quiet = quiet
        self._output_dir = output_dir
        self._output_dir.mkdir(parents=True, exist_ok=True)

        self._server.on_client_disconnected(self._on_disconnect)
        self._server.on_data(self._on_data)

    def set_proxy_users(self, users: dict[str, str]):
        self._server.register_authentication(0x02, PasswordAuthentication(users))

    async def _on_data(self, client: Socks5Client, direction: DataDirection, data: bytes):
        stream = PeekBytesIO(data)
        if client not in self._clients:
            try:
                self._clients[client] = Connection.new(stream)
            except AssertionError as e:
                if not self._quiet:
                    print(f"Protocol error: {e}")
                self._clients[client] = IgnoredConn(), IgnoredConn()
            self._sessions[client] = []

        transport_in, transport_out = self._clients[client]

        if direction == DataDirection.CLIENT_TO_DST:
            if (data := transport_out.read(stream)) is None:
                return

            obj = MTProto.read_object(data)
            self._sessions[client].append(obj)
            if not self._quiet:
                print(f" -> {obj}")
        else:
            if (data := transport_in.read(stream)) is None:
                return

            obj = MTProto.read_object(data, False)
            self._sessions[client].append(obj)
            if not self._quiet:
                print(f" <- {obj}")

    async def _on_disconnect(self, client: Socks5Client):
        if client not in self._clients:
            return
        if client not in self._sessions:
            self._sessions[client] = []

        transport_in, transport_out = self._clients[client]

        while (data := transport_out.read()) is not None:
            obj = MTProto.read_object(data)
            self._sessions[client].append(obj)
            if not self._quiet:
                print(f" -> {obj}")

        while (data := transport_in.read()) is not None:
            obj = MTProto.read_object(data, False)
            self._sessions[client].append(obj)
            if not self._quiet:
                print(f" <- {obj}")

        del self._clients[client]
        await self._save(client)

    async def run_async(self):
        await self._server.serve()

    def _sync_save(self, messages: list[MessageContainer] | None):
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

    async def _save(self, client: Socks5Client):
        if not self._output_dir:
            return

        with ThreadPoolExecutor() as pool:
            await get_event_loop().run_in_executor(pool, lambda: self._sync_save(self._sessions.pop(client, None)))

    def run(self):
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
