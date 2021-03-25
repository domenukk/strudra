#!/usr/bin/env python3
"""
An add-on for Ghidra, to craft byte representations of Structs with ease.

Usage:
```python
import strudra
sd = strudra.Strudra()
sd.add_struct("struct test{ int test1; char test2[2]; };")
test_struct = sd.test(test1=0x1337)
assert (test_struct.test == test_struct[0x0])
test_struct.test2 = [0x42, 0x42]
bytes(test_struct)
```
"""
import json
import struct
from datetime import datetime
from typing import Union, Dict, Optional, List, cast, Any, Type, Tuple, Set

import ghidra_bridge

SupportedTypes: Union = Union[
    bytes, int, float, "AbStrud", List[int], List[float], List["AbStrud"]
]

_big_endian_cache: Dict[ghidra_bridge.GhidraBridge, bool] = {}


def get_fmt(typename: str, typelen: int) -> str:
    """
    Get the sruct.pack format string from a Ghidra type
    :param typename: the type name from ghidra
    :param typelen: the reported type length
    :return: Format string
    """

    if "[" in typename and "]" in typename:
        type_split = typename.split("[")
        array_len = int(type_split[1].split("]")[0])
        el_fmt = get_fmt(type_split[0], int(typelen / int(array_len)))
        if el_fmt == "s":
            # multiple unknown types, not much we can do
            return "s"
        return el_fmt * array_len

    elif typename == "bool":
        return "?"
    elif typename == "char":
        return "b"
    elif typename == "uchar" or typelen == 1:
        return "B"
    elif typename == "short":
        return "H"
    elif typename == "ushort" or typelen == 2:
        return "h"
    elif typename == "int":
        return "i"
    elif typename == "long":
        return "l"
    elif typename == "long long":
        return "q"
    elif typename == "float":
        return "f"
    elif typename == "double":
        return "d"
    elif typename == "uint" or typename == "dword" or typelen == 4:
        return "I"
    elif typename == "ulong" or typelen == 8:
        return "L"
    elif typename == "ulonglong" or typelen == 16:
        return "Q"

    # pointer, *, get handled by typelen

    return "s"


class Member:
    """
    A Member
    """

    def __init__(
        self,
        big_endian: bool,
        offset: int,
        typename: str,
        length: int,
        name: Optional[str] = None,
        comment: Optional[str] = None,
    ):
        self.big_endian: bool = big_endian
        self.offset: int = offset
        self.typename: str = typename
        self.length: int = length
        self.name: str = name if name else f"field_{hex(offset)}"
        self.comment: Optional[str] = comment

        # for arrays, we get the element type
        self.el_typename: str = typename.split("[")[0]

        endianness = ">" if big_endian else "<"
        self.fmt = f"{endianness}{get_fmt(typename, length)}"

    def __len__(self) -> int:
        return self.length

    def to_bytes(self, val: SupportedTypes) -> bytes:
        """
        Get the bytes for the given val.
        If it's a bytes or bytearray object, it will return the bytes, padded with 0s.
        For big endian, they are appended to the right, for little endian to the left.

        If it's an int value, and fits this value, it will be packed accordingly.

        For arrays, pass in a list with multiple values of the type in question (or raw bytes of course).

        Else, it'll throw an exception, obviously.
        :param val: the value that should be bytified
        :return: the bytified values, as bytes
        """
        if isinstance(val, AbStrud):
            # In case we want to set an nestedded Strud, use the serialized notation directly.
            val = val.serialized
        if isinstance(val, str):
            # in case we want to set a char using chr(..) which results in a string
            val = val.encode()
        if isinstance(val, bytes) or isinstance(val, bytearray):
            if len(val) > len(self):
                raise ValueError(
                    f"passed type to large for type {self.name} (len {len(self)}), "
                    f"use <struct>.setbytes instead, if you want to overwrite a mem area."
                )
            if self.big_endian:
                return val.rjust(len(self))
            else:
                return val.ljust(len(self))
        if isinstance(val, list) and self.is_array:
            # If we have multiple values, we may use a list as param. Unpack here.
            return struct.pack(self.fmt, *val)

        if len(self) > 8:
            raise ValueError(
                f"Cannot set non-int values at this moment (type {self.name} has {len(self)} bytes)."
            )

        return struct.pack(self.fmt, val)

    @property
    def el_count(self) -> int:
        """
        The amount of elements, in case of an array
        :return: the amount of elements
        """
        # Again, we abuse that the format is always le/be indicator + all items
        return len(self.fmt) - 1

    @property
    def is_array(self) -> bool:
        """
        Returns if this type is an array
        :return: true if array
        """
        # We return if fmt is more than endiannes + single type, no extra field needed.
        return len(self.fmt) > 2

    @property
    def el_len(self) -> int:
        """
        Gets the length of each element
        :return: the length of each element
        """
        return int(len(self) / self.el_count)

    def get_repr(
        self,
        val: bytes,
        parent: "AbStrud" = None,
        all_struds: Dict[str, Type["AbStrud"]] = None,
    ) -> SupportedTypes:
        """
        Get the unpacked representation
        :param val: The stringified value
        :param parent: The enclosing struct, for nesting
        :param all_struds: a list of loaded struds. If the typename is found here, this will return the corret Strud
        :return: The respective type
        """
        if len(val) != len(self):
            raise ValueError(
                f"Could not get representation for value:"
                f"Expected bytes of len({len(self)}) but got {len(val)}: {val}"
            )
        if all_struds and self.el_typename in all_struds:
            # We found a nested Strud! Return Strud value.
            ret_strud_cls = all_struds[self.el_typename]
            el_len = self.el_len
            if self.is_array:
                return [
                    ret_strud_cls(nested_at=(parent, self.offset + i * el_len))
                    for i in range(self.el_count)
                ]
            else:
                return ret_strud_cls(nested_at=(parent, self.offset))

        else:
            unpacked = struct.unpack(self.fmt, val)
        if self.is_array:
            return list(unpacked)
        return unpacked[0]

    def __repr__(self) -> str:
        endian_str = "be" if self.big_endian else "le"
        name_str = f" name: {self.name}" if self.name else ""
        comment_str = f" comment: {self.comment}" if self.comment else ""

        return f"Member<{endian_str}@{hex(self.offset)} {self.typename} len:{hex(len(self))}{name_str}{comment_str}>"


class AbStrud:
    """
    Abstract class used for each struct loaded from Ghidra.
    """

    # This gets replaced with the actual impl later.
    def __init__(
        self,
        from_bytes: Optional[bytes] = None,
        nested_at: Optional[Tuple["AbStrud", int]] = None,
        **kwargs,
    ):
        """
        Creates a new Abstract Strudra Object.

        :param from_bytes: (optional) a parameter indicating the initial bytes for this Strud
        :param nested_at: (optional) If set, all operations on this struct will be proxied to the enclosing struct.
        :param kwargs: specifies optional data for the Strud
        """
        # We pass the following params inside kwargs as to not confuse the IDEs
        # str_repr: The string representation of a struct, from Ghidra
        # The (parsed) members of this Strud
        # The length of this Strud
        if nested_at and not len(nested_at) == 2:
            raise ValueError("Nested_at needs to be a tuple of (Strud, offset)")

        self.str_repr: str = kwargs.pop("_str_repr")
        if not self.str_repr:
            raise ValueError("Attempted to instantiate uninitialized AbStrud")
        length = kwargs.pop("_length")
        self.members: List[Member] = kwargs.pop("_members")
        if "_all_struds" in kwargs:
            # print("struds", kwargs["_all_struds"])
            self.all_struds: Optional[Dict[str, Type[AbStrud]]] = kwargs.pop(
                "_all_struds"
            )
        else:
            self.all_struds: Optional[Dict[str, Type[AbStrud]]] = None

        self._length = length
        # Cache for nestedded structs, they proxy all state anyway, so we may reuse them.
        self._nested_cache: Set[AbStrud] = set()

        if nested_at is not None:
            self.nested_at: Optional[Tuple[AbStrud, int]] = nested_at
            self._serialized: Optional[bytearray] = None
        else:
            self.nested_at: Optional[Tuple[AbStrud, int]] = None
            self._serialized: Optional[bytearray] = bytearray(length)

        if from_bytes is not None:
            if len(from_bytes) != length:
                raise ValueError(
                    f"Illegal value in from_bytes: Expected {length} bytes but got {len(from_bytes)}"
                )
            self.setbytes(0, from_bytes)
        for key, val in kwargs.items():
            self[key] = val

    def __len__(self) -> int:
        return self._length

    @property
    def serialized(self) -> bytes:
        if self.nested_at:
            return self.nested_at[0].serialized[
                self.nested_at[1] : self.nested_at[1] + len(self)
            ]
        else:
            return bytes(self._serialized)

    def setbytes(self, offset: int, b: bytes) -> None:
        """
        Writes the given bytes to the given offset
        :param offset: the offset to start writing at
        :param b: the bytes to write
        """
        if self.nested_at:
            self.nested_at[0].setbytes(self.nested_at[1] + offset, b)
        else:
            for i, byte in enumerate(b):
                self._serialized[i + offset] = byte

    def find_member(self, name_or_offset: Union[str, int]) -> Member:
        """
        Gets a member with the given value or at the given offset
        :param name_or_offset: the name (str) or offset (int)
        :return: the Member at this place
        """
        if isinstance(name_or_offset, str):
            for member in self.members:
                if member.name == name_or_offset:
                    return member
        elif isinstance(name_or_offset, int):
            for member in self.members:
                if member.offset == name_or_offset:
                    return member
        raise ValueError(
            f"Could not find struct member with name or offset '{name_or_offset}' "
            f"(you may use `setbytes(..)` to write at a mem location directly or bytes() to read values)."
        )

    def __getitem__(self, name_or_offset: Union[str, int]) -> Union[bytes, int, float]:
        """
        Get an element by name (if str is passed), or offset
        :param name_or_offset: the name or offset of this element
        :return: the bytes at name or offset with the element's len (Use `.find_member()` to get a Member instance).
        """
        member = self.find_member(name_or_offset)
        if member in self._nested_cache:
            return member
        ret = member.get_repr(
            bytes(self)[member.offset : member.offset + len(member)],
            parent=self,
            all_struds=self.all_struds,
        )
        if isinstance(ret, AbStrud):
            self._nested_cache.add(ret)
        return ret

    def __setitem__(
        self, name_or_offset: Union[str, int], value: Union[bytes, int, float]
    ) -> None:
        """
        Sets an element by name of offset to a given value
        :param name_or_offset:
        :param value: the name or offset
        """
        member = self.find_member(name_or_offset)
        self.setbytes(member.offset, member.to_bytes(value))

    def __repr__(self) -> str:
        # return f"{self.str_repr}, bytes: {self.serialized}"

        nl = "\n\t"

        def member_repr(member):
            return f"{hex(member.offset)}: ({member.typename}) {member.name} = {self[member.offset]}"

        return (
            f"Strud {self.__class__.__name__}<members: {len(self.members)}, len: {len(self)}, named: {{\n\t"
            f"{nl.join([member_repr(x) for x in self.members if not x.name.startswith('field_')])}\n}}>"
        )

    def __bytes__(self) -> bytes:
        if self.nested_at:
            return bytes(self.nested_at[0])[
                self.nested_at[1] : self.nested_at[1] + len(self)
            ]
        else:
            return bytes(self._serialized)

    def bytes(self) -> bytes:
        """
        Return the serialized bytes
        :return: The bytes
        """
        return bytes(self)

    def to_cstruct_str(self) -> str:
        """
        Create a best-effort cstruct
        :return: a c struct
        """
        cstruct = f"struct {self.__class__.__name__} {{\n"
        for member in self.members:
            if member.is_array:
                actual_type = member.typename.split("[")
                cstruct += f"{actual_type} {member.name}[{member.el_count}];\n"
            else:
                cstruct += f"{member.typename} {member.name};"

        cstruct += "\n};"
        return cstruct

    def clone(self) -> "AbStrud":
        """
        Return a clone
        :return: a fresh instance of this element, with the same values set
        """
        return self.__class__(bytes(self))

    @property
    def is_nested(self) -> bool:
        """
        A nested Strud changes the state of an enclosing strud
        :return: True if nested
        """
        return self.nested_at is not None


def parse_to_strud(
    b: ghidra_bridge.GhidraBridge,
    cstruct: str,
    all_struds: Optional[Dict[str, Type[AbStrud]]] = None,
) -> Type[AbStrud]:
    """
    Creates a Strud from a given C struct.
    Unlike `add_struct` the parsed cstruct won't be added to Ghidras DB.
    :param b: the Ghidra instance
    :param cstruct: the (c-)struct to parse
    :param all_struds: (optional) Reference to all struds, for nested types
    :return: The Strud
    """
    cstruct.replace("'''", '"""')
    try:
        parsed_struct = b.remote_eval(
            f"ghidra.app.util.cparser.C.CParser(currentProgram.getDataTypeManager()).parse('''{cstruct}''')",
            timeout_override=0.3,
        )
    except Exception as ex:
        raise ValueError(
            f"failed to parse cstruct, check ghidra for infos ({ex}): {cstruct}"
        )
    return ghidra_struct_to_strud(
        target_is_big_endian(b),
        parsed_struct.getName(),
        parsed_struct.getLength(),
        parsed_struct.toString(),
        all_struds,
    )


def add_struct(
    b: ghidra_bridge.GhidraBridge,
    cstruct: str,
    all_struds: Optional[Dict[str, Type[AbStrud]]] = None,
) -> Type[AbStrud]:
    """
    Parses and adds a (c)-Struct to ghidras Database
    :param b: the ghidra bridge instance
    :param cstruct: the new struct to parse
    :param all_struds: (optional) Reference to all struds, for nested types
    :return: the added and parsed struct object
    """
    # Keep if you use triple quotes in a struct definition, you're out of luck anyway...
    cstruct.replace("'''", '"""')
    # first, make sure we can parse this.
    # else, we time out
    try:
        b.remote_exec(
            "dtm = currentProgram.getDataTypeManager()\n"
            "try:"
            f"  parsed_struct = ghidra.app.util.cparser.C.CParser(dtm).parse('''{cstruct}''')\n"
            "except Exception as ex:\n"
            "   parsed_struct = ex\n",
            timeout_override=0.3,
        )
    except Exception as ex:
        raise ValueError(
            f"Could not parse cstruct, check Ghidra {ex} (cstruct: {cstruct})"
        )
    print(b.remote_eval("parsed_struct"))
    # This took long to debug: We need a transaction here!
    b.remote_exec(
        "t = currentProgram.startTransaction('add struct')\n"
        "try:\n"
        "    new_struct = dtm.addDataType(parsed_struct, "
        "                                 ghidra.program.model.data.DataTypeConflictHandler.DEFAULT_HANDLER)\n"
        "except Exception as ex:\n"
        "    print('Transaction failed: {}'.format(ex))\n"
        "finally:\n"
        "    currentProgram.endTransaction(t, True)\n"
    )
    new_struct = b.remote_eval("new_struct")
    return ghidra_struct_to_strud(
        target_is_big_endian(b),
        new_struct.getName(),
        new_struct.getLength(),
        new_struct.toString(),
        all_struds,
    )


def parse_struct_members(is_big_endian: bool, struct_str: str) -> List[Member]:
    """
    Instead of properly serializing the types in python inside ghidra (slooow), we use toString() and parse that.
    :return: the members of this struct
    """
    # '/exception_record_tnUnaligned\nStructure exception_record_t {
    #   0   uint   4   iLine   ""
    #   4   char *   4   szFile   ""
    #   8   char *   4   szError   ""
    #   12   uint   4   null   ""
    #   16   char[512]   512   savedStack   ""
    #   528   uint   4   savedStackPtr   ""
    #   532   registers_t   148   registers   ""
    # }
    # Size = 680   Actual Alignment = 1\n'
    members = []
    state = 0

    # tmp vars used during parsing
    length = 0  # type: int
    comment = None  # type: Optional[str]
    offset = -1  # type: int
    typename = ""  # type: str

    # print("Parsing", struct_str)
    vals = struct_str.split("{", 1)[1].rsplit("}", 1)[0].split("   ")
    for val in vals:
        if state == 0:
            # Remove the \n
            v = val.strip()
            if len(v) > 2 and v != "":
                comment = v[1:-1]
            else:
                comment = None
        if state == 1:
            offset = int(val)
        elif state == 2:
            typename = val
        elif state == 3:
            length = int(val)
        elif state == 4:
            # If someone wants to call a member "null", they are out of luck :)
            name = val if val != "null" else None
            members.append(
                Member(
                    big_endian=is_big_endian,
                    offset=offset,
                    typename=typename,
                    length=length,
                    name=name,
                    comment=comment,
                )
            )
        state += 1
        state %= 5
    return members


def target_is_big_endian(b: ghidra_bridge.GhidraBridge) -> bool:
    """
    Returns true, if the connected target is big endian
    :param b:
    :return:
    """
    if b not in _big_endian_cache:
        _big_endian_cache[b] = b.remote_eval(
            "currentProgram.getDataTypeManager().getDataOrganization().bigEndian"
        )
    return _big_endian_cache[b]


class MemberValueWrapper:
    """
    Makes it possible to use <struct>.<member> as values directly.
    """

    def __init__(self, member: Member):
        self.member = member

    def __get__(self, instance: AbStrud, owner) -> SupportedTypes:
        if instance is None:
            raise ValueError(
                "You are using a Strud class, not an instance! Call class() to get a fresh instance."
            )
        return instance[self.member.offset]

    def __set__(self, instance: AbStrud, value: SupportedTypes) -> None:
        instance[self.member.offset] = value


def define_struct(
    is_big_endian: bool,
    name: str,
    length: int,
    str_repr: str,
    members: List[Member],
    all_struds: Dict[str, Type[AbStrud]] = None,
) -> Type[AbStrud]:
    """
    Define an new Strud object
    :param is_big_endian: If this is a big endian strud
    :param name: the name of this strud
    :param length: the length
    :param str_repr: Ghidra toString() repr
    :param members: the parsed members for this strud
    :param all_struds: Reference to the list of all strud types, for nestedded struct handling
    :return: The new Strud type
    """
    struct_dict = AbStrud.__dict__.copy()
    old_init = struct_dict["__init__"]

    offset = 0x0
    # first, fill up odd bytes with "undefined" members
    filled_members = []
    for member in members:
        while member.offset > offset:
            filled_members.append(Member(is_big_endian, offset, "undefined", 1))
            offset += 1
        filled_members.append(member)
        offset = member.offset + member.length
    while length < offset:
        filled_members.append(Member(is_big_endian, offset, "undefined", 1))
        offset += 1

    members = filled_members

    def new_init(
        self,
        from_bytes: Optional[bytes] = None,
        nested_at: Optional[Tuple[AbStrud, int]] = None,
        **kwargs,
    ):
        f"""
        Create a new {name} strud
        {str_repr}
        :param self: the new object
        :param from_bytes: (optional) a parameter indicating the initial bytes for this Strud
        :param nested_at: (optional) If set to a tuple of (Strud, offset), will propagate changes to the outer Strud.
        :param kwargs: Keys and Values of members to set them immediately
        """
        old_init(
            self,
            from_bytes,
            nested_at,
            _str_repr=str_repr,
            _members=members,
            _length=length,
            _all_struds=all_struds,
            **kwargs,
        )

    # We want to give the user the option to still have a struct member called `name`
    struct_dict["_name"] = name
    struct_dict["__init__"] = new_init
    struct_dict["__doc__"] = f"A {name} Strud class for:\n{str_repr}"

    for member in members:
        # Add getter and setter for Members by name.
        # They are accessible using .field_0x.. or .name
        prop = MemberValueWrapper(member)
        struct_dict[f"field_{hex(member.offset)}"] = prop

        if member.name is not None and member.name not in struct_dict:
            struct_dict[member.name] = prop

    return cast(
        Type[AbStrud],
        type(
            name,
            (AbStrud,),
            struct_dict,
        ),
    )


def ghidra_struct_to_strud(
    is_big_endian: bool,
    name: str,
    length: int,
    string_repr: str,
    all_struds: Optional[Dict[str, Type[AbStrud]]] = None,
) -> Type[AbStrud]:
    """
    Make an strudra internal struct out of a ghidra struct
    :param is_big_endian: Endianness of this struct
    :param name: The name of this struct
    :param length: The length of this struct
    :param string_repr: The stringified representation of this struct
    :param all_struds: (optional) The list of all struds, for nested struct handling
    :return: The parsed strud
    """
    return define_struct(
        is_big_endian,
        name,
        length,
        string_repr,
        parse_struct_members(is_big_endian, string_repr),
        all_struds,
    )


def serialize_struds(data: Any, filename: str):
    """Save Data to file"""
    with open(filename, "w") as fp:
        json.dump(data, fp)


def data_from_file(
    filename: str,
) -> Dict[str, Union[str, bool, List[Dict[str, Union[str, int]]]]]:
    """Load Struds data from a file
    :returns a dict of struds, bigEndian, the name"""
    with open(filename, "r") as f:
        return json.load(f)


def data_from_ghidra(
    b: ghidra_bridge.GhidraBridge,
) -> Dict[str, Union[str, bool, List[Dict[str, Union[str, int]]]]]:
    """
    Get all structures. This uses toString on the Ghidra side and parses it.
    All other/saner ways to do it turned out to be way too slow.
    :param b: the bridge
    :return: all structs, loaded from Ghidra
    """
    is_big_endian = target_is_big_endian(b)
    # x.length
    # This is too slow (3 seconds vs 37ms), let's parse it instead.
    # return b.remote_eval("{x.getName(): (x, x.length, [(c.fieldName, c.offset, c.endOffset,
    # c.isFlexibleArrayComponent()) for c in x.components])
    # for x in currentProgram.getDataTypeManager().getAllStructures()}")
    ghidra_structs = b.remote_eval(
        "[{'name': x.getName(), 'length': x.getLength(), 'ghidra': x.toString()}"
        "for x in currentProgram.getDataTypeManager().getAllStructures()]"
    )

    data = {
        "name": b.get_flat_api().currentProgram.name,
        "timestamp": datetime.now().isoformat(),
        "big_endian": is_big_endian,
        "structs": ghidra_structs,
    }
    return data


def struds_from_data(
    data: Dict[str, Union[str, bool, List[Dict[str, Union[str, int]]]]]
) -> Tuple[Dict[str, Type[AbStrud]], bool, str]:
    """
    Deserialize the Struds from a json
    :return: Tuple of: all loaded struds, if big endian, the name
    """
    is_big_endian = data["big_endian"]
    all_struds = {}
    # x.length
    # This is too slow (3 seconds vs 37ms), let's parse it instead.
    # return b.remote_eval("{x.getName(): (x, x.length, [(c.fieldName, c.offset, c.endOffset,
    # c.isFlexibleArrayComponent()) for c in x.components])
    # for x in currentProgram.getDataTypeManager().getAllStructures()}")
    ghidra_structs: List[Dict[str, Union[str, int]]] = data["structs"]
    for x in ghidra_structs:
        all_struds[x["name"]] = ghidra_struct_to_strud(
            is_big_endian, x["name"], x["length"], x["ghidra"], all_struds
        )
    return all_struds, data["big_endian"], data["name"]


def gh_bridge(
    host: str = "127.0.0.1",
    port: int = ghidra_bridge.ghidra_bridge.DEFAULT_SERVER_PORT,
    **kwargs,
) -> ghidra_bridge.GhidraBridge:
    """
    Shorthand to create a ghidra_bridge to the given host.
    :param host: (optional) host to connect to (for remote stuff)
    :param port: (optional) port to connect to
    :param kwargs: Additional params for the bridge
    :return: the Ghidra bridge
    """
    return ghidra_bridge.GhidraBridge(
        connect_to_host=host, connect_to_port=port, **kwargs
    )


class Strudra:
    """
    Struda, craft byte structs from your ghidra db in python.
    """

    def __init__(
        self,
        bridge: ghidra_bridge.GhidraBridge = None,
        filename="struds.json",
        force_file_load=False,
    ):
        f"""
        Create a new Strudra instance
        {__doc__}

        :param bridge: (optional) the ghidra bridge, else connects to localhost
        :param filename: (optional) The filename to store ghidra structs too, locally. Defaults to struds.json.
        :param force_file_load: (optional) If true, will not try to connect to ghidra, but load from file, initially.
        """
        self.bridge: ghidra_bridge.GhidraBridge = bridge if bridge else gh_bridge()
        self.filename = filename
        self.force_file_load = force_file_load

        self._name: str = "<unloaded>"
        self.struds: Dict[str, AbStrud] = {}

        # we will load this later in reload, if force_file_load = True
        self.is_big_endian: bool = False

        if not self.force_file_load:
            try:
                self.is_big_endian: bool = target_is_big_endian(self.bridge)
            except ConnectionRefusedError as ex:
                print("Could not connect to Ghidra, loading from", filename)
                self.force_file_load = True

        # Get a copy of the initial class dict, so we can reset on `reload`

        dict_orig = self.__dict__.copy()
        # Make sure it's still there after the first reload...
        dict_orig["_dict_orig"] = dict_orig
        self._dict_orig: Dict[str, Any] = dict_orig
        self._dict_orig["_dict_orig"] = self._dict_orig

        self.reload()

    def __dir__(self) -> List[str]:
        return list(self.__dict__.keys()) + list(self.struds.keys())

    def __getitem__(self, item) -> Any:
        return self.struds.__getitem__(item)

    def reload(self, force_ghidra=False) -> None:
        """
        Reload the structs from ghidra
        :param force_ghidra: Overwrite force_file_load locally
        """
        self.__dict__ = self._dict_orig.copy()

        if self.force_file_load and not force_ghidra:
            data = data_from_file(self.filename)
        else:
            data = data_from_ghidra(self.bridge)
            serialize_struds(data, filename=self.filename)

        struds, is_big_endian, name = struds_from_data(data)
        self._name = name
        self.is_big_endian: bool = is_big_endian
        self.struds = struds

        for name, strud in self.struds.items():
            if name not in self.__dict__:
                # Make struds easily accessible
                self.__setattr__(name, strud)

    def add_struct(self, cstruct: str) -> Type[AbStrud]:
        """
        Add a c struct to ghidra
        :param cstruct:
        :return: The new Strud
        """
        ret = add_struct(self.bridge, cstruct)
        self.reload(force_ghidra=True)
        return ret

    def parse_struct(self, cstruct: str) -> Type[AbStrud]:
        """
        Parse C Struct using Ghidra, but don't add it to the internal data store
        :param cstruct: the struct to parse
        :return: The parsed Strud
        """
        return parse_to_strud(self.bridge, cstruct)
