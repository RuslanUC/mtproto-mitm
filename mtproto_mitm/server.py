import asyncio
import hashlib
import logging
from asyncio import get_running_loop
from io import BytesIO
from typing import TypeVar, Callable, Awaitable, Any

from mtproto import ConnectionRole
from mtproto.transport import Connection
from mtproto.transport.packets import BasePacket, MessagePacket, ErrorPacket, QuickAckPacket, UnencryptedMessagePacket, \
    EncryptedMessagePacket
from socks5server import SocksServer, Socks5Client, PasswordAuthentication, DataDirection
from socks5server.enums import AuthMethod, DataModify

from mtproto_mitm.messages import MessageContainer, MessageMetadata
from mtproto_mitm.tl import TLObject

log = logging.getLogger(__name__)
T = TypeVar("T")

_PacketHandler = Callable[[Socks5Client, DataDirection, T], Awaitable[Any]]
_DataHandlerFunc = _PacketHandler[MessageContainer]
_ErrorHandlerFunc = _PacketHandler[ErrorPacket]
_QuickAckHandlerFunc = _PacketHandler[QuickAckPacket]
_UnknownHandlerFunc = _PacketHandler[BasePacket]
_AnyHandlerFunc = _PacketHandler[BasePacket | MessageContainer]

_ClientHandlerFunc = Callable[[Socks5Client], Awaitable[Any]]


class ConnectionPair:
    __slots__ = ("to_server", "to_client",)

    def __init__(self):
        self.to_server: Connection = Connection(ConnectionRole.SERVER)
        self.to_client: Connection = Connection(ConnectionRole.CLIENT)


class MitmServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 1080, no_auth: bool = False):
        self._server = SocksServer(host, port, no_auth)
        self._clients: dict[Socks5Client, ConnectionPair] = {}
        self._auth_keys = {}

        self._server.on_client_connected(self._on_connect)
        self._server.on_client_disconnected(self._on_disconnect)
        self._server.on_data_modify(self._on_data)
        
        self._on_client_connected_handlers: set[_ClientHandlerFunc] = set()
        self._on_client_disconnected_handlers: set[_ClientHandlerFunc] = set()

        self._on_data_packet_handlers: set[_DataHandlerFunc] = set()
        self._on_error_packet_handlers: set[_ErrorHandlerFunc] = set()
        self._on_quickack_packet_handlers: set[_QuickAckHandlerFunc] = set()
        self._on_unknown_packet_handlers: set[_UnknownHandlerFunc] = set()

    def set_proxy_users(self, users: dict[str, str]):
        self._server.register_authentication(AuthMethod.PASSWORD, PasswordAuthentication(users))

    def add_client_connected_handler(self, func: _ClientHandlerFunc) -> None:
        log.debug(f"Adding client connected handler: {func}")
        self._on_client_connected_handlers.add(func)

    def add_client_disconnected_handler(self, func: _ClientHandlerFunc) -> None:
        log.debug(f"Adding client disconnected handler: {func}")
        self._on_client_disconnected_handlers.add(func)

    def add_data_packet_handler(self, func: _DataHandlerFunc) -> None:
        log.debug(f"Adding handler for data packets: {func}")
        self._on_data_packet_handlers.add(func)
    
    def add_error_packet_handler(self, func: _ErrorHandlerFunc) -> None:
        log.debug(f"Adding handler for error packets: {func}")
        self._on_error_packet_handlers.add(func)
        
    def add_quickack_packet_handler(self, func: _QuickAckHandlerFunc) -> None:
        log.debug(f"Adding handler for quick-ack packets: {func}")
        self._on_quickack_packet_handlers.add(func)

    def add_unknown_packet_handler(self, func: _UnknownHandlerFunc) -> None:
        log.debug(f"Adding handler for unknown packets: {func}")
        self._on_unknown_packet_handlers.add(func)
        
    def add_packet_handler(self, func: _AnyHandlerFunc) -> None:
        log.debug(f"Adding handler for all packets: {func}")
        self.add_data_packet_handler(func)
        self.add_error_packet_handler(func)
        self.add_quickack_packet_handler(func)
        self.add_unknown_packet_handler(func)

    def on_client_connected(self, func: _ClientHandlerFunc) -> _ClientHandlerFunc:
        self.add_client_connected_handler(func)
        return func

    def on_client_disconnected(self, func: _ClientHandlerFunc) -> _ClientHandlerFunc:
        self.add_client_disconnected_handler(func)
        return func

    def on_data_packet(self, func: _DataHandlerFunc) -> _DataHandlerFunc:
        self.add_data_packet_handler(func)
        return func

    def on_error_packet_handler(self, func: _ErrorHandlerFunc) -> _ErrorHandlerFunc:
        self.add_error_packet_handler(func)
        return func

    def on_quickack_packet(self, func: _QuickAckHandlerFunc) -> _QuickAckHandlerFunc:
        self.add_quickack_packet_handler(func)
        return func

    def on_unknown_packet(self, func: _UnknownHandlerFunc) -> _UnknownHandlerFunc:
        self.add_unknown_packet_handler(func)
        return func

    def on_packet(self, func: _AnyHandlerFunc) -> _AnyHandlerFunc:
        self.add_packet_handler(func)
        return func

    async def _handle_packet(self, client: Socks5Client, packet: BasePacket, direction: DataDirection) -> None:
        loop = get_running_loop()
        tasks = []

        if isinstance(packet, MessagePacket):
            sender = ConnectionRole.CLIENT if direction is DataDirection.CLIENT_TO_DST else ConnectionRole.SERVER
            message = self._parse_data_packet(packet, sender)
            if message is not None:
                for handler in self._on_data_packet_handlers:
                    tasks.append(loop.create_task(handler(client, direction, message)))
            else:
                for handler in self._on_unknown_packet_handlers:
                    tasks.append(loop.create_task(handler(client, direction, packet)))
        elif isinstance(packet, ErrorPacket):
            for handler in self._on_error_packet_handlers:
                tasks.append(loop.create_task(handler(client, direction, packet)))
        elif isinstance(packet, QuickAckPacket):
            for handler in self._on_quickack_packet_handlers:
                tasks.append(loop.create_task(handler(client, direction, packet)))
        else:
            for handler in self._on_unknown_packet_handlers:
                tasks.append(loop.create_task(handler(client, direction, packet)))

        await asyncio.gather(*tasks)

    async def _on_connect(self, client: Socks5Client) -> None:
        log.debug(f"Client connected: {client}")

        loop = asyncio.get_running_loop()
        await asyncio.gather(*[
            loop.create_task(handler(client))
            for handler in self._on_client_connected_handlers
        ])

    async def _on_data(self, client: Socks5Client, direction: DataDirection, data: bytes) -> DataModify | None:
        if client not in self._clients:
            self._clients[client] = ConnectionPair()

        conn = self._clients[client]

        current = conn.to_server if direction is DataDirection.CLIENT_TO_DST else conn.to_client
        receiver = conn.to_client if direction is DataDirection.CLIENT_TO_DST else conn.to_server

        current.data_received(data)

        to_send = b""

        while (packet := current.next_event()) is not None:
            await self._handle_packet(client, packet, direction)
            to_send += receiver.send(packet)

        return to_send

    async def _on_disconnect(self, client: Socks5Client) -> None:
        if client not in self._clients:
            return

        log.debug(f"Client disconnected: {client}")

        await self._on_data(client, DataDirection.CLIENT_TO_DST, b"")
        await self._on_data(client, DataDirection.DST_TO_CLIENT, b"")

        loop = asyncio.get_running_loop()
        await asyncio.gather(*[
            loop.create_task(handler(client))
            for handler in self._on_client_disconnected_handlers
        ])

        del self._clients[client]

    async def run_async(self) -> None:
        await self._server.serve()

    def run(self) -> None:
        loop = asyncio.new_event_loop()
        loop.run_until_complete(self.run_async())

    def register_key(self, auth_key: bytes) -> None:
        auth_key_hash = hashlib.sha1(auth_key).digest()[-8:]
        auth_key_id = int.from_bytes(auth_key_hash, byteorder="little", signed=True)
        self._auth_keys[auth_key_id] = auth_key
        log.debug(f"Registered auth key {auth_key_id}")

    def clear_keys(self) -> None:
        log.debug(f"Clearing {len(self._auth_keys)} auth keys")
        self._auth_keys.clear()

    def _parse_data_packet(self, message: MessagePacket, sender: ConnectionRole) -> MessageContainer:
        if isinstance(message, UnencryptedMessagePacket):
            raw_data = message.message_data
            try:
                obj = TLObject.read(BytesIO(raw_data))
                raw_data = None
            except RuntimeError as e:
                log.error(f"Failed to read unencrypted object", exc_info=e)
                obj = None

            return MessageContainer(
                meta=MessageMetadata(0, message.message_id),
                obj=obj,
                raw_data=raw_data,
                raw_data_decrypted=True,
            )

        if isinstance(message, EncryptedMessagePacket):
            failed_to_decrypt_result = MessageContainer(
                meta=MessageMetadata(message.auth_key_id, None, msg_key=message.message_key),
                obj=None,
                raw_data=message.encrypted_data,
                raw_data_decrypted=False,
            )

            if message.auth_key_id not in self._auth_keys:
                log.info(f"Cannot decrypt message: unknown auth key {message.auth_key_id}")
                return failed_to_decrypt_result

            try:
                decrypted = message.decrypt(self._auth_keys[message.auth_key_id], sender)
            except ValueError as e:
                log.error(f"Cannot decrypt message: failed to decrypt", exc_info=e)
                return failed_to_decrypt_result

            raw_data = decrypted.data
            try:
                obj = TLObject.read(BytesIO(raw_data))
                raw_data = None
            except RuntimeError as e:
                log.error(f"Failed to read decrypted object", exc_info=e)
                obj = None

            return MessageContainer(
                meta=MessageMetadata(
                    auth_key_id=message.auth_key_id,
                    message_id=decrypted.message_id,
                    session_id=decrypted.session_id,
                    salt=decrypted.salt,
                    seq_no=decrypted.seq_no,
                ),
                obj=obj,
                raw_data=raw_data,
                raw_data_decrypted=True,
            )

        raise RuntimeError("Unreachable")
