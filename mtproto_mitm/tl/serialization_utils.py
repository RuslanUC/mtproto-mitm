import struct
from typing import TypeVar

from mtproto_mitm import tl

T = TypeVar("T")

BOOL_TRUE = b"\xb5\x75\x72\x99"
BOOL_FALSE = b"\x37\x97\x79\xbc"
VECTOR = b"\x15\xc4\xb5\x1c"


class SerializationUtils:
    @staticmethod
    def read(stream, type_: type[T], subtype: type=None) -> T:
        if issubclass(type_, tl.Int):
            return int.from_bytes(stream.read(type_.SIZE), "little")
        elif issubclass(type_, float):
            return struct.unpack("<d", stream.read(8))[0]
        elif issubclass(type_, bool):
            return stream.read(4) == BOOL_TRUE
        elif issubclass(type_, bytes):
            count = stream.read(1)[0]
            offset = 1
            if count >= 254:
                count = stream.read(1)[0] + (stream.read(1)[0] << 8) + (stream.read(1)[0] << 16)
                offset = 4

            result = stream.read(count)
            offset += len(result)
            offset %= 4
            if offset:
                stream.read(4 - offset)

            return result
        elif issubclass(type_, str):
            return SerializationUtils.read(stream, bytes).decode("utf8")
        elif issubclass(type_, (tl.TLObject, tl.TLObjectBase)):
            constructor = int.from_bytes(stream.read(4), "little")
            if constructor not in tl.all.objects:
                raise RuntimeError(f"Unknown constructor: {constructor}")
            return tl.all.objects[constructor].deserialize(stream)
        elif issubclass(type_, list):
            assert stream.read(4) == VECTOR
            count = SerializationUtils.read(stream, tl.Int)
            result = []

            for _ in range(count):
                result.append(SerializationUtils.read(stream, subtype))

            return result

