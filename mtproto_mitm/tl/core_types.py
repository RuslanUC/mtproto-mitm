from __future__ import annotations

from gzip import decompress
from io import BytesIO

from mtproto_mitm import tl
from mtproto_mitm.tl import TLField, TLObject, tl_object, SerializationUtils


class Int(int):
    BIT_SIZE = 32
    SIZE = BIT_SIZE // 8

    @classmethod
    def read(cls, stream) -> Int:
        return tl.SerializationUtils.read(stream, cls)


class Long(Int):
    BIT_SIZE = 64
    SIZE = BIT_SIZE // 8


class Int128(Int):
    BIT_SIZE = 128
    SIZE = BIT_SIZE // 8


class Int256(Int):
    BIT_SIZE = 256
    SIZE = BIT_SIZE // 8


class Vector(list):
    value_type: type

    def __init__(self, *args, value_type: type, **kwargs):
        super().__init__(*args, **kwargs)
        self.value_type = value_type


@tl_object(id=0x5bb8e511, name="Message")
class Message(TLObject):
    message_id: Long = TLField()
    seq_no: Int = TLField()
    obj: TLObject = TLField()

    @classmethod
    def deserialize(cls, stream) -> TLObject:
        msg_id = Long.read(stream)
        seq_no = Int.read(stream)
        length = Int.read(stream)
        body = SerializationUtils.read(BytesIO(stream.read(length)), TLObject)

        return Message(message_id=msg_id, seq_no=seq_no, obj=body)


@tl_object(id=0x73f1f8dc, name="MsgContainer")
class MsgContainer(TLObject):
    messages: list[Message] = TLField()

    @classmethod
    def deserialize(cls, stream) -> TLObject:
        count = SerializationUtils.read(stream, Int)
        result = []

        for _ in range(count):
            result.append(Message.deserialize(stream))

        return MsgContainer(messages=result)


@tl_object(id=0xf35c6d01, name="RpcResult")
class RpcResult(TLObject):
    req_msg_id: Long = TLField()
    result: TLObject = TLField()


@tl_object(id=0x3072cfa1, name="GzipPacked")
class GzipPacked(TLObject):
    packed_data: bytes = TLField()

    @classmethod
    def deserialize(cls, stream) -> TLObject:
        packed_data = SerializationUtils.read(stream, bytes)
        decompressed_stream = BytesIO(decompress(packed_data))

        return SerializationUtils.read(decompressed_stream, TLObject)
