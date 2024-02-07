from hashlib import sha256, sha1
from io import BytesIO

import tgcrypto

from mtproto_mitm.tl import TLObject, Long, Int


class EncryptedMessage:
    __slots__ = ["auth_key_id", "msg_key", "data"]

    def __init__(self, auth_key_id: int, msg_key: bytes, data: bytes):
        self.auth_key_id = auth_key_id
        self.msg_key = msg_key
        self.data = data


class UnencryptedMessage:
    __slots__ = ["message_id", "data"]

    def __init__(self, message_id: int, data: bytes):
        self.message_id = message_id
        self.data = data


class MessageMetadata:
    __slots__ = ["auth_key_id", "message_id", "session_id", "salt", "seq_no", "msg_key"]

    def __init__(self, auth_key_id: int, message_id: int | None, session_id: int | None = None, salt: int | None = None,
                 seq_no: int | None = None, msg_key: bytes | None = None):
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
    __slots__ = ["meta", "obj", "raw_data"]

    def __init__(self, meta: MessageMetadata, obj: TLObject | None, raw_data: bytes | None = None):
        self.meta = meta
        self.obj = obj
        self.raw_data = raw_data

    def __repr__(self) -> str:
        return f"MessageContainer(meta={self.meta!r}, obj={self.obj!r})"


def kdf(auth_key: bytes, msg_key: bytes, outgoing: bool) -> tuple:
    x = 0 if outgoing else 8

    sha256_a = sha256(msg_key + auth_key[x:x + 36]).digest()
    sha256_b = sha256(auth_key[x + 40:x + 76] + msg_key).digest()  # 76 = 40 + 36

    aes_key = sha256_a[:8] + sha256_b[8:24] + sha256_a[24:32]
    aes_iv = sha256_b[:8] + sha256_a[8:24] + sha256_b[24:32]

    return aes_key, aes_iv


class MTProto:
    _auth_keys = {}

    @classmethod
    def register_key(cls, auth_key: bytes) -> None:
        auth_key_hash = sha1(auth_key).digest()[-8:]
        auth_key_id = int.from_bytes(auth_key_hash, byteorder="little")
        cls._auth_keys[auth_key_id] = auth_key

    @classmethod
    def read_message(cls, data: bytes) -> UnencryptedMessage | EncryptedMessage:
        data = BytesIO(data)
        auth_key_id = Long.read(data)
        if auth_key_id == 0:
            message_id = Long.read(data)
            message_data_length = Int.read(data)
            message_data = data.read(message_data_length)
            return UnencryptedMessage(message_id, message_data)
        msg_key = data.read(16)
        encrypted_data = data.read()
        return EncryptedMessage(auth_key_id, msg_key, encrypted_data)

    @classmethod
    def read_object(cls, data: bytes, from_client: bool = True) -> MessageContainer:
        message = cls.read_message(data)
        if isinstance(message, UnencryptedMessage):
            return MessageContainer(
                MessageMetadata(0, message.message_id),
                TLObject.read(BytesIO(message.data))
            )
        elif isinstance(message, EncryptedMessage):
            if message.auth_key_id not in cls._auth_keys:
                return MessageContainer(
                    MessageMetadata(message.auth_key_id, None, msg_key=message.msg_key),
                    None, message.data
                )

            aes_key, aes_iv = kdf(cls._auth_keys[message.auth_key_id], message.msg_key, from_client)

            decrypted = BytesIO(tgcrypto.ige256_decrypt(message.data, aes_key, aes_iv))
            salt = Long.read(decrypted)
            session_id = Long.read(decrypted)
            message_id = Long.read(decrypted)
            seq_no = Int.read(decrypted)
            message_data_length = Int.read(decrypted)

            return MessageContainer(
                MessageMetadata(message.auth_key_id, message_id, session_id, salt, seq_no),
                TLObject.read(BytesIO(decrypted.read(message_data_length)))
            )
