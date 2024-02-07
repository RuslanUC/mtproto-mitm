from __future__ import annotations

from abc import ABC, abstractmethod
from io import BytesIO, SEEK_END
from typing import Callable

import tgcrypto


class PeekBytesIO(BytesIO):
    def peek(self, n: int) -> bytes:
        pos = self.tell()
        data = self.read(n)
        self.seek(pos)
        return data


class Obfuscation:
    def __init__(self, encrypt, decrypt):
        self._encrypt = encrypt
        self._decrypt = decrypt

    def read(self, buf: BytesIO | Buffer, __size=...):
        return tgcrypto.ctr256_decrypt(buf.read(__size), *self._encrypt)


class Buffer:
    def __init__(self):
        self._buffers: list[tuple[BytesIO, int]] = []

    def add(self, buf: BytesIO | None = None):
        if buf is None:
            return

        pos = buf.tell()
        buf.seek(0, SEEK_END)
        size = buf.tell()
        buf.seek(pos)
        self._buffers.append((buf, size))

    def get_size(self) -> int:
        size = 0
        for buf, s in self._buffers:
            size += s - buf.tell()

        return size

    def read(self, n: int) -> bytes:
        data = b""
        while len(data) != n:
            data += self._buffers[0][0].read(n - len(data))
            if self._buffers[0][0].tell() >= self._buffers[0][1]:
                self._buffers.pop(0)

        return data


class Connection(ABC):
    def __init__(self, obf: Obfuscation | None = None):
        self._obfuscation = obf
        self._buffer = Buffer()
        self._last_length = None

    @staticmethod
    def new(stream: PeekBytesIO) -> tuple[Connection, Connection]:
        header = stream.peek(1)

        if header == b"\xef":
            stream.read(1)
            return TCPAbridged(), TCPAbridged()
        elif header == b"\xee":
            stream.read(1)
            assert (hd := stream.read(3)) == b"\xee\xee\xee", f"Invalid TCP Intermediate header: {hd}"
            return TCPIntermediate(), TCPIntermediate()
        elif header == b"\xdd":
            stream.read(1)
            assert (hd := stream.read(3)) == b"\xdd\xdd\xdd", f"Invalid TCP Intermediate header: {hd}"
            return TCPIntermediate(), TCPIntermediate()
        else:
            soon = stream.peek(8)
            if soon[-4:] == b"\0\0\0\0":
                return TCPFull(), TCPFull()

            nonce = stream.read(64)
            temp = nonce[8:56][::-1]
            encrypt = (nonce[8:40], nonce[40:56], bytearray(1))
            decrypt = (temp[0:32], temp[32:48], bytearray(1))
            decrypted = tgcrypto.ctr256_decrypt(nonce, *encrypt)

            header = decrypted[56:56 + 4]

            obf = Obfuscation(encrypt, decrypt)
            if header == b"\xef\xef\xef\xef":
                return TCPAbridged(obf), TCPAbridged(obf)
            elif header in {b"\xee\xee\xee\xee", b"\xdd\xdd\xdd\xdd"}:
                return TCPIntermediate(obf), TCPIntermediate(obf)

        assert False, f"Transport is unknown, aborting... (header: {header})"

    def read_func(self, stream: BytesIO | None = None) -> Callable[[int], bytes]:
        self._buffer.add(stream)
        if self._obfuscation is None:
            return self._buffer.read

        return lambda i: self._obfuscation.read(self._buffer, i)

    @abstractmethod
    def read(self, stream: PeekBytesIO | None = None) -> bytes | None:
        ...


class TCPAbridged(Connection):
    def read(self, stream: PeekBytesIO | None = None) -> bytes | None:
        read = self.read_func(stream)

        if self._buffer.get_size() < 4:
            return None

        if self._last_length is None:
            length = (read(1))[0]
            length &= 0x7F
            if length & 0x7F == 0x7F:
                length = int.from_bytes(read(3), "little")

            length *= 4
        else:
            length = self._last_length

        if self._buffer.get_size() < length:
            self._last_length = length
            return None

        self._last_length = None
        return read(length)


class TCPIntermediate(Connection):
    def read(self, stream: PeekBytesIO | None = None) -> bytes | None:
        read = self.read_func(stream)

        if self._buffer.get_size() < 4:
            return None

        if self._last_length is None:
            length = int.from_bytes(read(4), byteorder="little", signed=False)
        else:
            length = self._last_length

        if self._buffer.get_size() < length:
            self._last_length = length
            return None

        self._last_length = None
        return read(length)


class TCPFull(Connection):
    def read(self, stream: PeekBytesIO | None = None) -> bytes | None:
        read = self.read_func(stream)

        if self._buffer.get_size() < 8:
            return None

        if self._last_length is None:
            length = int.from_bytes(read(4), "little", signed=False)
            read(4)
        else:
            length = self._last_length

        if self._buffer.get_size() < length - 8:
            self._last_length = length
            return None

        payload = read(length - 4 - 4 - 4)
        read(4)

        self._last_length = None
        return payload
