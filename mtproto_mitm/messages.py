from mtproto_mitm.tl import TLObject


class AutoRepr:
    __slots__ = ()

    def __repr__(self) -> str:
        fields = ", ".join([f"{slot}={getattr(self, slot)!r}" for slot in self.__slots__])
        return f"{self.__class__.__name__}({fields})"


class MessageMetadata(AutoRepr):
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

class MessageContainer(AutoRepr):
    __slots__ = ("meta", "obj", "raw_data", "raw_data_decrypted")

    def __init__(
            self, meta: MessageMetadata, obj: TLObject | None, raw_data: bytes | None = None,
            raw_data_decrypted: bool = False
    ):
        self.meta = meta
        self.obj = obj
        self.raw_data = raw_data
        self.raw_data_decrypted = raw_data_decrypted
