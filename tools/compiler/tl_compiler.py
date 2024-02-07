#  Pyrogram - Telegram MTProto API Client Library for Python
#  Copyright (C) 2017-present Dan <https://github.com/delivrance>
#
#  This file is part of Pyrogram.
#
#  Pyrogram is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Pyrogram is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with Pyrogram.  If not, see <http://www.gnu.org/licenses/>.

import os
import re
import shutil
from functools import partial
from pathlib import Path
from typing import NamedTuple, List, Tuple

HOME_PATH = Path("./tools/compiler")
DESTINATION_PATH = Path("mtproto_mitm/tl")

SECTION_RE = re.compile(r"---(\w+)---")
LAYER_RE = re.compile(r"//\sLAYER\s(\d+)")
COMBINATOR_RE = re.compile(r"^([\w.]+)#([0-9a-f]+)\s(?:.*)=\s([\w<>.]+);$", re.MULTILINE)
ARGS_RE = re.compile(r"[^{](\w+):([\w?!.<>#]+)")
FLAGS_RE = re.compile(r"flags(\d?)\.(\d+)\?")
FLAGS_RE_3 = re.compile(r"flags(\d?):#")

CORE_TYPES = ["int", "long", "int128", "int256", "double", "bytes", "string", "Bool", "true"]
CORE_TYPES_D = {"int": "Int", "long": "Long", "int128": "Int128", "int256": "Int256"}

WARNING = """
# # # # # # # # # # # # # # # # # # # # # # # #
#               !!! WARNING !!!               #
#          This is a generated file!          #
# All changes made in this file will be lost! #
# # # # # # # # # # # # # # # # # # # # # # # #
""".strip()

# noinspection PyShadowingBuiltins
open = partial(open, encoding="utf-8")

all_layers = set()
types_to_constructors = {}
types_to_functions = {}
constructors_to_functions = {}
namespaces_to_types = {}
namespaces_to_constructors = {}
namespaces_to_functions = {}


class Combinator(NamedTuple):
    section: str
    qualname: str
    namespace: str
    name: str
    id: str
    has_flags: bool
    args: List[Tuple[str, str]]
    qualtype: str
    typespace: str
    type: str
    layer: int = 0


def snake(s: str):
    # https://stackoverflow.com/q/1175208
    s = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", s)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s).lower()


def camel(s: str):
    return "".join([i[0].upper() + i[1:] for i in s.split("_")])


# noinspection PyShadowingBuiltins, PyShadowingNames
def get_type_hint(type: str, layer: int) -> str:
    is_flag = FLAGS_RE.match(type)
    is_core = False

    if is_flag:
        type = type.split("?")[1]

    if type in CORE_TYPES or type == "#":
        is_core = True

        if type == "long" or type == "#" or "int" in type:
            type = CORE_TYPES_D.get(type, "Int")
        elif type == "double":
            type = "float"
        elif type == "string":
            type = "str"
        elif type in ["Bool", "true"]:
            type = "bool"
        else:  # bytes and object
            type = "bytes"

    if type in ["Object", "!X"]:
        return "TLObject"

    if re.match("^vector", type, re.I):
        is_core = True

        sub_type = type.split("<")[1][:-1]
        type = f"list[{get_type_hint(sub_type, layer)}]"

    if is_core:
        return f"Optional[{type}]" if is_flag and type != "bool" else type
    else:
        type = "TLObject"

        return f"Optional[{type}]" if is_flag else type


def parse_schema(schema: list[str]) -> tuple[list[Combinator], int]:
    combinators = []
    layer = None
    section = None

    for line in schema:
        # Check for section changer lines
        section_match = SECTION_RE.match(line)
        if section_match:
            section = section_match.group(1)
            continue

        # Save the layer version
        layer_match = LAYER_RE.match(line)
        if layer_match:
            layer = int(layer_match.group(1))
            continue

        combinator_match = COMBINATOR_RE.match(line)
        if combinator_match:
            # noinspection PyShadowingBuiltins
            qualname, id, qualtype = combinator_match.groups()

            namespace, name = qualname.split(".") if "." in qualname else ("", qualname)
            name = camel(name)
            qualname = ".".join([namespace, name]).lstrip(".")

            typespace, type = qualtype.split(".") if "." in qualtype else ("", qualtype)
            type = camel(type)
            qualtype = ".".join([typespace, type]).lstrip(".")

            # Pingu!
            has_flags = not not FLAGS_RE_3.findall(line)

            args: list[tuple[str, str]] = ARGS_RE.findall(line)

            # Fix arg name being "self" (reserved python keyword)
            for i, item in enumerate(args):
                if item[0] == "self":
                    args[i] = ("is_self", item[1])
                elif item[0] == "from":
                    args[i] = ("from_", item[1])
                elif item[0] in ("bytes", "str", "type"):
                    args[i] = (f"{item[0]}_", item[1])

            combinator = Combinator(
                section=section,
                qualname=qualname,
                namespace=namespace,
                name=name,
                id=f"0x{id}",
                has_flags=has_flags,
                args=args,
                qualtype=qualtype,
                typespace=typespace,
                type=type
            )

            combinators.append(combinator)

    if layer is not None:
        all_layers.add(layer)
    return combinators, layer


def parse_old_schemas(schemaBase: list[Combinator]) -> dict[int, dict[str, Combinator]]:
    schemaBase = {f"{c.qualname}#{c.id}": c for c in schemaBase}

    layers = sorted([
        int(file[4:-3])
        for file in os.listdir(HOME_PATH / "api_layers")
        if file.startswith("api_") and file.endswith(".tl")
    ])

    schemas: dict[int, dict[str, Combinator]] = {}
    for layer in layers:
        with open(HOME_PATH / f"api_layers/api_{layer}.tl") as f:
            parsed = parse_schema(f.read().splitlines())[0]

        schemas[layer] = {}
        for c in parsed:
            name = f"{c.qualname}#{c.id}"
            if name in schemaBase:
                continue
            c = c._replace(layer=layer)
            schemas[layer][name] = c

    for i in range(len(layers)):
        for cname in schemas[layers[i]]:
            for j in range(i + 1, len(layers)):
                if cname in schemas[layers[j]]:
                    del schemas[layers[j]][cname]

    for layer in layers:
        if len(schemas[layer]) == 0:
            del schemas[layer]
            continue
        for cname in schemas[layer]:
            c = schemas[layer][cname]
            replacements = {
                "qualname": f"{c.qualname}_{layer}",
                "qualtype": f"{c.qualtype}_{layer}",
                "name": f"{c.name}_{layer}",
                "type": f"{c.type}_{layer}",
            }
            schemas[layer][cname] = c._replace(**replacements)

    return schemas


def parse_old_objects(schemaBase: list[Combinator]) -> list[Combinator]:
    result = []
    for schema in parse_old_schemas(schemaBase).values():
        result.extend(schema.values())

    return result


# noinspection PyShadowingBuiltins
def start():
    shutil.rmtree(DESTINATION_PATH / "types", ignore_errors=True)
    shutil.rmtree(DESTINATION_PATH / "functions", ignore_errors=True)

    with open(HOME_PATH / "api_layers/mtproto.tl") as f1, open(HOME_PATH / "api_layers/api.tl") as f2:
        schema = f1.read().splitlines() + f2.read().splitlines()

    with open(HOME_PATH / "templates/combinator.txt") as f1:
        combinator_tmpl = f1.read()

    combinators, layer = parse_schema(schema)
    combinators.extend(parse_old_objects(combinators))

    for c in combinators:
        qualtype = c.qualtype

        if qualtype.startswith("Vector"):
            qualtype = qualtype.split("<")[1][:-1]

        d = types_to_constructors if c.section == "types" else types_to_functions

        if qualtype not in d:
            d[qualtype] = []

        d[qualtype].append(c.qualname)

        if c.section == "types":
            key = c.namespace

            if key not in namespaces_to_types:
                namespaces_to_types[key] = []

            if c.type not in namespaces_to_types[key]:
                namespaces_to_types[key].append(c.type)

    for k, v in types_to_constructors.items():
        for i in v:
            try:
                constructors_to_functions[i] = types_to_functions[k]
            except KeyError:
                pass

    for c in combinators:
        fields = []
        flagnum = 0
        for arg in c.args:
            arg_type = arg[1]
            field_args = []
            if arg_type == "#":
                flagnum += 1
                field_args.append("is_flags=True")
                if flagnum > 1:
                    field_args.append(f"flagnum={flagnum}")
            if "?" in arg_type:
                bit = int(arg_type.split(".")[1].split("?")[0])
                field_args.append(f"flag=1 << {bit}")
                fieldflagnum = arg_type.split("?")[0].split(".")[0][5:]
                fieldflagnum = int(fieldflagnum) if fieldflagnum else 1
                if fieldflagnum > 1:
                    field_args.append(f"flagnum={fieldflagnum}")
                if arg_type.split("?")[1] == "Bool":
                    field_args.append(f"flag_serializable=True")
            field_args = ", ".join(field_args)
            fields.append(f"{arg[0]}: {get_type_hint(arg_type, c.layer)} = TLField({field_args})")

        fields = "\n    ".join(fields) if fields else "pass"

        compiled_combinator = combinator_tmpl.format(
            warning=WARNING,
            name=c.name,
            id=c.id,
            qualname=f"{c.section}.{c.qualname}",
            fields=fields,
        )

        directory = "types" if c.section == "types" else c.section

        dir_path = DESTINATION_PATH / directory / c.namespace

        os.makedirs(dir_path, exist_ok=True)

        module = c.name

        if module == "Updates":
            module = "UpdatesT"

        with open(dir_path / f"{snake(module)}.py", "w") as f:
            f.write(compiled_combinator)

        d = namespaces_to_constructors if c.section == "types" else namespaces_to_functions

        if c.namespace not in d:
            d[c.namespace] = []

        d[c.namespace].append(c.name)

    for namespace, types in namespaces_to_constructors.items():
        with open(DESTINATION_PATH / "types" / namespace / "__init__.py", "w") as f:
            f.write(f"{WARNING}\n\n")

            for t in types:
                module = t

                if module == "Updates":
                    module = "UpdatesT"

                f.write(f"from .{snake(module)} import {t}\n")

            if not namespace:
                f.write(f"from . import {', '.join(filter(bool, namespaces_to_constructors))}\n")

    for namespace, types in namespaces_to_functions.items():
        with open(DESTINATION_PATH / "functions" / namespace / "__init__.py", "w") as f:
            f.write(f"{WARNING}\n\n")

            for t in types:
                module = t

                if module == "Updates":
                    module = "UpdatesT"

                f.write(f"from .{snake(module)} import {t}\n")

            if not namespace:
                f.write(f"from . import {', '.join(filter(bool, namespaces_to_functions))}")

    with open(DESTINATION_PATH / "all.py", "w", encoding="utf-8") as f:
        f.write(WARNING + "\n\n")
        f.write(f"import mtproto_mitm.tl as tl\n")
        f.write(f"from mtproto_mitm.tl import core_types\n\n")
        f.write(f"min_layer = {min(all_layers)}\n")
        f.write(f"layer = {layer}\n\n")
        f.write("objects = {")

        for c in combinators:
            f.write(f'\n    {c.id}: tl.{c.section}.{c.qualname},')

        f.write(f'\n    0x5bb8e511: core_types.Message,')
        f.write(f'\n    0x73f1f8dc: core_types.MsgContainer,')
        f.write(f'\n    0xf35c6d01: core_types.RpcResult,')
        f.write(f'\n    0x3072cfa1: core_types.GzipPacked,')

        f.write("\n}\n")


if "__main__" == __name__:
    start()
