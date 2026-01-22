import json
import logging
import os
from asyncio import get_running_loop, get_event_loop
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from time import time

import click
from mtproto import ConnectionRole
from mtproto.transport import Connection
from mtproto.transport.packets import ErrorPacket, QuickAckPacket, BasePacket
from socks5server import DataDirection, Socks5Client

from mtproto_mitm.messages import MessageContainer
from mtproto_mitm.server import MitmServer

_save_executor = ThreadPoolExecutor(max_workers=os.cpu_count() * 2, thread_name_prefix="SaveWorker")


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


class MitmCli:
    def __init__(
            self, host: str = "0.0.0.0", port: int = 1080, no_auth: bool = False, quiet: bool = False,
            output_dir: Path | None = None,
    ):
        self.server = MitmServer(host, port, no_auth)
        self._sessions: dict[Socks5Client, list[MessageContainer]] = {}
        self._quiet = quiet
        self._output_dir = output_dir
        self._output_dir.mkdir(parents=True, exist_ok=True)

        self.server.add_client_connected_handler(self._on_connect)
        self.server.add_client_disconnected_handler(self._on_disconnect)
        self.server.add_packet_handler(self._on_packet)

    async def _on_connect(self, client: Socks5Client) -> None:
        self._sessions[client] = []

    async def _on_disconnect(self, client: Socks5Client) -> None:
        await self._save(client)
        del self._sessions[client]

    async def _on_packet(
            self, client: Socks5Client, direction: DataDirection, data: BasePacket | MessageContainer
    ) -> None:
        if isinstance(data, MessageContainer):
            self._sessions[client].append(data)

        if self._quiet:
            return

        arrow = "->" if direction is DataDirection.CLIENT_TO_DST else "<-"

        if isinstance(data, MessageContainer):
            self._sessions[client].append(data)
            print(f" {arrow} {data}")
        elif isinstance(data, ErrorPacket):
            print(f" {arrow} ERROR({data.error_code})")
        elif isinstance(data, QuickAckPacket):
            print(f" {arrow} QUICK_ACK({data.token!r})")
        else:
            print(f" {arrow} UNKNOWN({data!r}")

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
                "raw_data_decrypted": message.raw_data_decrypted,
            })

        sid = hex(messages_json[-1]["metadata"]["session_id"] or 0)[2:6] if messages_json else "0000"
        with open(self._output_dir / f"{int(time()*1000)}_{sid}.json", "w") as f:
            json.dump(messages_json, f, cls=JsonEncoder, indent=2)

    async def _save(self, client: Socks5Client) -> None:
        if not self._output_dir:
            return

        await get_running_loop().run_in_executor(_save_executor, self._sync_save, self._sessions[client])


async def _watch_keys_file(keys_file: str, server: MitmServer, stop: Event, quiet: bool) -> None:
    try:
        from watchfiles import awatch, Change
    except ImportError:
        import warnings
        warnings.warn("\"watchfiles\" is required for reloading keys at runtime")
        return

    async for changes in awatch(keys_file, debounce=1000, step=100, stop_event=stop):
        for change, path in changes:
            if change not in (Change.added, Change.modified):
                continue

            if not quiet:
                print("Reloading keys...")

            with open(keys_file) as f:
                keys = f.read().splitlines()
            server.clear_keys()
            for k in keys:
                server.register_key(bytes.fromhex(k))


@click.command()
@click.option("--host", "-h", type=click.STRING, default="0.0.0.0", help="Proxy host to run on.")
@click.option("--port", "-p", type=click.INT, default=1080, help="Proxy port to run on.")
@click.option("--key", "-k", type=click.STRING, multiple=True, help="Hex-encoded telegram auth key.")
@click.option("--keys-file", "-f", type=click.STRING, default=None, help="File with telegram auth keys.")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Do not show requests in real time.")
@click.option("--verbose", "-v", count=True, help="Enable verbose logging.")
@click.option("--output", "-o", type=click.STRING, default=None,
              help="Directory to which mtproto requests will be saved.")
@click.option("--proxy-no-auth", is_flag=True, default=False, help="Disable authentication for proxy.")
@click.option("--proxy-user", type=click.STRING, multiple=True, help="Proxy user in login:password format.")
@click.option("--reload-keys", is_flag=True, default=False, help="Enable reloading keys from file.")
def main(
        host: str, port: int, key: list[str], keys_file: str, quiet: bool, output: str | None, proxy_no_auth: bool,
        proxy_user: list[str], reload_keys: bool, verbose: int,
) -> None:
    if verbose >= 3:
        logging.basicConfig(level=logging.DEBUG)
        if verbose == 3:
            logging.getLogger("asyncio").setLevel(logging.WARNING)
            logging.getLogger("mtproto").setLevel(logging.WARNING)
    elif verbose >= 2:
        logging.basicConfig(level=logging.INFO)
    elif verbose >= 1:
        logging.basicConfig(level=logging.WARNING)

    if not quiet:
        print("Starting mtproto-mitm...")

    cli = MitmCli(host, port, proxy_no_auth, quiet, Path(output) if output is not None else None)
    server = cli.server

    for k in key:
        server.register_key(bytes.fromhex(k))

    reload_stop = None
    loop = get_event_loop()

    if keys_file:
        with open(keys_file) as f:
            keys = f.read().splitlines()
        for k in keys:
            server.register_key(bytes.fromhex(k))

        if reload_keys:
            reload_stop = Event()
            loop.create_task(_watch_keys_file(keys_file, server, reload_stop, quiet))

    if proxy_user:
        server.set_proxy_users({login: password for user in proxy_user for login, password in [user.split(":")]})

    if not quiet:
        print("Running...")

    server.run()

    if reload_stop is not None:
        reload_stop.set()


if __name__ == "__main__":
    main()
