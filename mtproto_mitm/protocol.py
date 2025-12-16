from hashlib import sha1
from io import BytesIO

from mtproto import ConnectionRole
from mtproto.transport.packets import MessagePacket, UnencryptedMessagePacket, EncryptedMessagePacket

from mtproto_mitm.tl import TLObject


class MessageMetadata:
    __slots__ = ("auth_key_id", "message_id", "session_id", "salt", "seq_no", "msg_key")

    def __init__(
            self, auth_key_id: int, message_id: int | None, session_id: int | None = None, salt: bytes | None = None,
            seq_no: int | None = None, msg_key: bytes | None = None
    ):
        self.auth_key_id = auth_key_id
        self.message_id = message_id
        self.session_id = session_id
        self.salt = salt
        self.seq_no = seq_no
        self.msg_key = msg_key

    def __repr__(self) -> str:
        attrs = {}
        for attr in self.__slots__:
            value = getattr(self, attr)
            if value is None:
                continue
            attrs[attr] = value

        attrs = [f"{key}={value!r}" for key, value in attrs.items()]
        attrs = ", ".join(attrs)

        return f"MessageMetadata({attrs})"


class MessageContainer:
    __slots__ = ("meta", "obj", "raw_data", "raw_data_decrypted")

    def __init__(
            self, meta: MessageMetadata, obj: TLObject | None, raw_data: bytes | None = None,
            raw_data_decrypted: bool = False
    ):
        self.meta = meta
        self.obj = obj
        self.raw_data = raw_data
        self.raw_data_decrypted = raw_data_decrypted

    def __repr__(self) -> str:
        return f"MessageContainer(meta={self.meta!r}, obj={self.obj!r})"


class MTProto:
    _auth_keys = {}

    @classmethod
    def register_key(cls, auth_key: bytes) -> None:
        auth_key_hash = sha1(auth_key).digest()[-8:]
        auth_key_id = int.from_bytes(auth_key_hash, byteorder="little")
        cls._auth_keys[auth_key_id] = auth_key

    @classmethod
    def read_object(cls, message: MessagePacket, sender: ConnectionRole = ConnectionRole.CLIENT) -> MessageContainer:
        if isinstance(message, UnencryptedMessagePacket):
            raw_data = message.message_data
            try:
                obj = TLObject.read(BytesIO(raw_data))
                raw_data = None
            except RuntimeError as e:
                print(e)
                obj = None

            return MessageContainer(
                meta=MessageMetadata(0, message.message_id),
                obj=obj,
                raw_data=raw_data,
                raw_data_decrypted=True,
            )
        elif isinstance(message, EncryptedMessagePacket):
            failed_to_decrypt_result = MessageContainer(
                    meta=MessageMetadata(message.auth_key_id, None, msg_key=message.message_key),
                    obj=None,
                    raw_data=message.encrypted_data,
                    raw_data_decrypted=False,
                )

            if message.auth_key_id not in cls._auth_keys:
                return failed_to_decrypt_result

            try:
                decrypted = message.decrypt(cls._auth_keys[message.auth_key_id], sender)
            except ValueError:
                return failed_to_decrypt_result

            raw_data = decrypted.data
            try:
                obj = TLObject.read(BytesIO(raw_data))
                raw_data = None
            except RuntimeError:
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
