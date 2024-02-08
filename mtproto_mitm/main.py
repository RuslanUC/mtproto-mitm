from asyncio import get_event_loop

import click
from socks5server import DataDirection, SocksServer, PasswordAuthentication, Socks5Client

from mtproto_mitm.connection import PeekBytesIO, Connection
from mtproto_mitm.protocol import MTProto, MessageContainer


class MitmServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 1080, no_auth: bool = False, quiet: bool = False):
        self._server = SocksServer(host, port, no_auth)
        self._clients: dict[Socks5Client, tuple[Connection, Connection]] = {}
        self._sessions: dict[Socks5Client, list[MessageContainer]] = {}
        self._quiet = quiet

        self._server.on_client_disconnected(self._on_disconnect)
        self._server.on_data(self._on_data)

    def set_proxy_users(self, users: dict[str, str]):
        self._server.register_authentication(0x02, PasswordAuthentication(users))

    async def _on_data(self, client: Socks5Client, direction: DataDirection, data: bytes):
        stream = PeekBytesIO(data)
        if client not in self._clients:
            self._clients[client] = Connection.new(stream)
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

    async def run(self):
        await self._server.serve()


async def _main(host: str, port: int, key: list[str], keys_file: str, quiet: bool, output: str, proxy_no_auth: bool,
                proxy_user: list[str]):
    for k in key:
        MTProto.register_key(bytes.fromhex(k))

    if keys_file:
        with open(keys_file) as f:
            keys = f.read().splitlines()
        for k in keys:
            MTProto.register_key(bytes.fromhex(k))

    server = MitmServer(host, port, proxy_no_auth, quiet)
    if proxy_user:
        server.set_proxy_users({login: password for user in proxy_user for login, password in [user.split(":")]})

    await server.run()


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
def main(host: str, port: int, key: list[str], keys_file: str, quiet: bool, output: str, proxy_no_auth: bool,
         proxy_user: list[str]):
    if not quiet:
        print("Running...")
    get_event_loop().run_until_complete(_main(host, port, key, keys_file, quiet, output, proxy_no_auth, proxy_user))


if __name__ == "__main__":
    main()
