from __future__ import annotations

from dataclasses import dataclass, field as dc_field, MISSING
from inspect import get_annotations
from typing import Callable, get_origin, get_args, Union

from mtproto_mitm import tl


class TLObjectBase(object):
    pass


class _BaseTLObject:
    __tl_id__: int
    __tl_name__: str
    __tl_fields__: list[TLField]
    __tl_flags__: list[TLField]


@dataclass
class TLObject(_BaseTLObject):
    def __init__(self, **k):
        pass

    @classmethod
    def tlid(cls) -> int:
        return cls.__tl_id__

    @classmethod
    def tlname(cls) -> str:
        return cls.__tl_name__

    def _calculate_flags(self, field_: TLField) -> int:
        flags = 0
        for field in self.__tl_fields__:
            if field.flag != -1 and field.flagnum == field_.flagnum:
                value = getattr(self, field.name)
                flags |= 0 if value is (False if isinstance(value, bool) else None) else field.flag

        return flags

    # noinspection PyTypeChecker
    @classmethod
    def deserialize(cls, stream) -> TLObject:
        args = {}
        flags = {}
        for field in cls.__tl_fields__:
            if field.flagnum in flags and field.flag != -1 and (flags[field.flagnum] & field.flag) != field.flag:
                continue
            if field.flagnum in flags and field.flag != -1 and field.type.type == bool and not field.flag_serializable:
                args[field.name] = True
                continue

            value = tl.SerializationUtils.read(stream, field.type.type, field.type.subtype)
            args[field.name] = value
            if field.is_flags:
                flags[field.flagnum] = value

        return cls(**args)

    @classmethod
    def read(cls, stream) -> TLObject:
        return tl.SerializationUtils.read(stream, cls)

    def to_dict(self) -> dict:
        if not self.__tl_fields__:
            return {}
        for field in self.__tl_flags__:
            value = self._calculate_flags(field)
            setattr(self, field.name, value)

        result = {}
        for field in self.__tl_fields__:
            result[field.name] = getattr(self, field.name)

        return result


def _resolve_annotation(annotation: type):
    origin = get_origin(annotation) or annotation
    if origin is Union:
        return _resolve_annotation(get_args(annotation)[0])
    if origin is list:
        args = get_args(annotation)
        return list, args[0]
    if origin in (int, float, bool, str, bytes) or issubclass(origin, (int, TLObject, TLObjectBase)):
        return origin, None

    raise RuntimeError(f"Unknown annotation type {annotation}!")


# noinspection PyShadowingBuiltins
def tl_object(id: int, name: str) -> Callable:
    def wrapper(cls: type):
        setattr(cls, "__tl_id__", id)
        setattr(cls, "__tl_name__", name)
        fields: list[TLField] = []
        flags: list[TLField] = []
        cls_annotations = get_annotations(cls, eval_str=True)
        for field_name, field in cls.__dict__.items():
            if not isinstance(field, TLField):
                continue

            field.name = field_name
            field.type = TLType(*_resolve_annotation(cls_annotations[field_name]))
            fields.append(field)
            if field.is_flags:
                flags.append(field)

            default = MISSING
            if field.flag != -1:
                default = False if cls.__annotations__[field_name] == "bool" else None
            if field.is_flags:
                default = 0

            setattr(cls, field_name, dc_field(kw_only=True, default=default))

        fields.sort(key=lambda field_: field_._counter)
        setattr(cls, "__tl_fields__", fields)
        setattr(cls, "__tl_flags__", flags)

        # noinspection PyTypeChecker
        return dataclass(slots=True, order=True)(cls)

    return wrapper


@dataclass(slots=True)
class TLType:
    type: type
    subtype: type | None


@dataclass(slots=True)
class TLField:
    __COUNTER = 0

    is_flags: bool = False
    flag: int = -1
    flagnum: int = 1
    name: str = None
    type: TLType = None
    flag_serializable: bool = False
    _counter: int = dc_field(default=-1, init=False, repr=False)

    def __post_init__(self):
        object.__setattr__(self, '_counter', TLField.__COUNTER)
        TLField.__COUNTER += 1
