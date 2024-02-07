from asyncio import get_event_loop

from socks5server import DataDirection, SocksServer, PasswordAuthentication, Socks5Client

from mtproto_mitm.connection import PeekBytesIO, Connection
from mtproto_mitm.protocol import MTProto, MessageContainer

MTProto.register_key(bytes.fromhex(
    "..."
))


server = SocksServer()
server.register_authentication(0x02, PasswordAuthentication({"test": "test"}))

clients: dict[Socks5Client, tuple[Connection, Connection]] = {}
sessions: dict[Socks5Client, list[MessageContainer]] = {}


@server.on_client_disconnected
async def on_disconnect(client: Socks5Client):
    if client not in clients:
        return
    if client not in sessions:
        sessions[client] = []

    transport_in, transport_out = clients[client]

    while (data := transport_out.read()) is not None:
        obj = MTProto.read_object(data)
        sessions[client].append(obj)
        print(f" -> {obj}")

    while (data := transport_in.read()) is not None:
        obj = MTProto.read_object(data, False)
        sessions[client].append(obj)
        print(f" <- {obj}")


@server.on_data
async def on_data(client: Socks5Client, direction: DataDirection, data: bytes):
    stream = PeekBytesIO(data)
    if client not in clients:
        clients[client] = Connection.new(stream)
        sessions[client] = []

    transport_in, transport_out = clients[client]

    if direction == DataDirection.CLIENT_TO_DST:
        if (data := transport_out.read(stream)) is None:
            return

        obj = MTProto.read_object(data)
        sessions[client].append(obj)
        print(f" -> {obj}")
    else:
        if (data := transport_in.read(stream)) is None:
            return

        obj = MTProto.read_object(data, False)
        sessions[client].append(obj)
        print(f" <- {obj}")


if __name__ == "__main__":
    print("Running...")
    get_event_loop().run_until_complete(server.serve())
