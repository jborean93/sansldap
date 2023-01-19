# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum
import struct
import typing as t


class TagClass(enum.IntEnum):
    UNIVERSAL = 0
    APPLICATION = 1
    CONTEXT_SPECIFIC = 2
    PRIVATE = 3


class TypeTagNumber(enum.IntEnum):
    END_OF_CONTENT = 0
    BOOLEAN = 1
    INTEGER = 2
    BIT_STRING = 3
    OCTET_STRING = 4
    NULL = 5
    OBJECT_IDENTIFIER = 6
    OBJECT_DESCRIPTOR = 7
    EXTERNAL = 8
    REAL = 9
    ENUMERATED = 10
    EMBEDDED_PDV = 11
    UTF8_STRING = 12
    RELATIVE_OID = 13
    TIME = 14
    RESERVED = 15
    SEQUENCE = 16
    SEQUENCE_OF = 16
    SET = 17
    SET_OF = 17
    NUMERIC_STRING = 18
    PRINTABLE_STRING = 19
    T61_STRING = 20
    VIDEOTEX_STRING = 21
    IA5_STRING = 22
    UTC_TIME = 23
    GENERALIZED_TIME = 24
    GRAPHIC_STRING = 25
    VISIBLE_STRING = 26
    GENERAL_STRING = 27
    UNIVERSAL_STRING = 28
    CHARACTER_STRING = 29
    BMP_STRING = 30
    DATE = 31
    TIME_OF_DAY = 32
    DATE_TIME = 33
    DURATION = 34
    OID_IRL = 35
    RELATIVE_OID_IRL = 36


class ASN1Tag(t.NamedTuple):
    tag_class: TagClass
    tag_number: t.Union[int, TypeTagNumber]
    is_constructed: bool

    @classmethod
    def universal_tag(
        cls,
        number: TypeTagNumber,
        is_constructed: bool = False,
    ) -> ASN1Tag:
        return ASN1Tag(
            tag_class=TagClass.UNIVERSAL,
            tag_number=number,
            is_constructed=is_constructed,
        )


class ASN1Value(t.NamedTuple):
    """A representation of an ASN.1 TLV as a tuple.

    Defines the ASN.1 Type Length Value (TLV) values as separate objects for
    easier parsing. This is returned by :method:`unpack_asn1`.

    Attributes:
        tag (ASN1Tag): The tag
        tag_class (TagClass): The tag class of the TLV.
        constructed (bool): Whether the value is constructed or 0, 1, or more
            element encodings (True) or not (False).
        tag_number (int): The tag number of the value, can be a TypeTagNumber
            if the tag_class is `universal` otherwise it's an explicit tag
            number value.
        tag_length (int): The length of the encoded tag.
        length (int): The length of the value the tag represents.
    """

    tag: ASN1Tag
    tag_length: int
    length: int


def read_asn1_header(
    data: t.Union[bytes, bytearray, memoryview],
) -> ASN1Value:
    """Reads the ASN.1 Tag and Length octets

    Reads the raw ASN.1 value to retrieve the tag and length values.

    Args:
      data: The raw bytes to read.

    Returns:
        ASN1Value: A tuple containing the tag and length information.
    """
    view = memoryview(data)

    octet1 = struct.unpack("B", view[:1])[0]
    tag_class = TagClass((octet1 & 0b11000000) >> 6)
    constructed = bool(octet1 & 0b00100000)
    tag_number = octet1 & 0b00011111

    tag_octets = 1
    if tag_number == 31:
        tag_number, octet_count = _unpack_asn1_octet_number(view[1:])
        tag_octets += octet_count

    if tag_class == TagClass.UNIVERSAL:
        tag_number = TypeTagNumber(tag_number)

    view = view[tag_octets:]

    length = struct.unpack("B", view[:1])[0]
    length_octets = 1

    if length == 0b1000000:
        # Indefinite length, the length is not known and will be marked by two
        # NULL octets known as end-of-content octets later in the stream.
        length = -1

    elif length & 0b10000000:
        # If the MSB is set then the length octet just contains the number of
        # octets that encodes the actual length.
        length_octets += length & 0b01111111
        length = 0

        for idx in range(1, length_octets):
            octet_val = struct.unpack("B", view[idx : idx + 1])[0]
            length += octet_val << (8 * (length_octets - 1 - idx))

    return ASN1Value(
        tag=ASN1Tag(
            tag_class=tag_class,
            tag_number=tag_number,
            is_constructed=constructed,
        ),
        tag_length=tag_octets + length_octets,
        length=length,
    )


def read_asn1_enumerated(
    data: t.Union[bytes, bytearray, memoryview],
    tag: t.Optional[ASN1Tag] = None,
    hint: t.Optional[str] = None,
) -> t.Tuple[int, int]:
    """Unpacks an ASN.1 ENUMERATED value."""
    if not tag:
        tag = ASN1Tag.universal_tag(TypeTagNumber.ENUMERATED, False)
    return read_asn1_integer(data, tag, hint=hint)


def read_asn1_integer(
    data: t.Union[bytes, bytearray, memoryview],
    tag: t.Optional[ASN1Tag] = None,
    hint: t.Optional[str] = None,
) -> t.Tuple[int, int]:
    """Unpacks an ASN.1 INTEGER value."""
    if not tag:
        tag = ASN1Tag.universal_tag(TypeTagNumber.INTEGER, False)

    raw_int, consumed = _validate_tag(data, tag, hint=hint)
    b_int = bytearray(raw_int)

    is_negative = b_int[0] & 0b10000000
    if is_negative:
        # Get the two's compliment.
        for i in range(len(b_int)):
            b_int[i] = 0xFF - b_int[i]

        for i in range(len(b_int) - 1, -1, -1):
            if b_int[i] == 0xFF:
                b_int[i - 1] += 1
                b_int[i] = 0
                break

            else:
                b_int[i] += 1
                break

    int_value = 0
    for val in b_int:
        int_value = (int_value << 8) | val

    if is_negative:
        int_value *= -1

    return int_value, consumed


def read_asn1_octet_string(
    data: t.Union[bytes, bytearray, memoryview],
    tag: t.Optional[ASN1Tag] = None,
    hint: t.Optional[str] = None,
) -> t.Tuple[memoryview, int]:
    """Unpacks an ASN.1 OCTET_STRING value."""
    if not tag:
        tag = ASN1Tag.universal_tag(TypeTagNumber.OCTET_STRING, False)

    return _validate_tag(data, tag, hint=hint)


def read_asn1_sequence(
    data: t.Union[bytes, bytearray, memoryview],
    tag: t.Optional[ASN1Tag] = None,
    hint: t.Optional[str] = None,
) -> t.Tuple[memoryview, int]:
    """Unpacks an ASN.1 SEQUENCE value."""
    if not tag:
        tag = ASN1Tag.universal_tag(TypeTagNumber.SEQUENCE, True)

    return _validate_tag(data, tag, hint=hint)


def _validate_tag(
    data: t.Union[bytes, bytearray, memoryview],
    expected_tag: ASN1Tag,
    hint: t.Optional[str] = None,
) -> t.Tuple[memoryview, int]:
    view = memoryview(data)

    actual_tag, tag_length, data_length = read_asn1_header(view)
    hint_str = f" for {hint}" if hint else ""

    if actual_tag != expected_tag:
        raise ValueError(f"Expected tag {expected_tag}{hint_str} but got {actual_tag}")

    view = view[tag_length:]
    if data_length == -1:
        raise NotImplementedError("Indefinite length not implemented yet")

    if len(view) < data_length:
        raise ValueError(f"Not enough data{hint_str}: expecting {data_length} but got {len(view)}")

    return view[:data_length], tag_length + data_length


def _pack_asn1_octet_number(
    num: int,
) -> bytes:
    """Packs an int number into an ASN.1 integer value that spans multiple octets."""
    num_octets = bytearray()

    while num:
        # Get the 7 bit value of the number.
        octet_value = num & 0b01111111

        # Set the MSB if this isn't the first octet we are processing (overall last octet)
        if len(num_octets):
            octet_value |= 0b10000000

        num_octets.append(octet_value)

        # Shift the number by 7 bits as we've just processed them.
        num >>= 7

    # Finally we reverse the order so the higher octets are first.
    num_octets.reverse()

    return num_octets


def _unpack_asn1_octet_number(
    data: memoryview,
) -> t.Tuple[int, int]:
    """Unpacks an ASN.1 INTEGER value that can span across multiple octets."""
    i = 0
    idx = 0
    while True:
        element = struct.unpack("B", data[idx : idx + 1])[0]
        idx += 1

        i = (i << 7) + (element & 0b01111111)
        if not element & 0b10000000:
            break

    return i, idx  # int value and the number of octets used.


def pack_asn1(
    tag_class: TagClass,
    constructed: bool,
    tag_number: t.Union[TypeTagNumber, int],
    data: t.Union[bytes, bytearray, memoryview],
) -> bytes:
    """Pack the ASN.1 value into the ASN.1 bytes.

    Will pack the raw bytes into an ASN.1 Type Length Value (TLV) value. A TLV
    is in the form:

    | Identifier Octet(s) | Length Octet(s) | Data Octet(s) |

    Args:
        tag_class: The tag class of the data.
        constructed: Whether the data is constructed (True), i.e. contains 0,
            1, or more element encodings, or is primitive (False).
        tag_number: The type tag number if tag_class is universal else the
            explicit tag number of the TLV.
        b_data: The encoded value to pack into the ASN.1 TLV.

    Returns:
        bytes: The ASN.1 value as raw bytes.
    """
    b_asn1_data = bytearray()

    # ASN.1 Identifier octet is
    #
    # |             Octet 1             |  |              Octet 2              |
    # | 8 | 7 |  6  | 5 | 4 | 3 | 2 | 1 |  |   8   | 7 | 6 | 5 | 4 | 3 | 2 | 1 |
    # | Class | P/C | Tag Number (0-30) |  | More  | Tag number                |
    #
    # If Tag Number is >= 31 the first 5 bits are 1 and the 2nd octet is used
    # to encode the length.
    if tag_class < 0 or tag_class > 3:
        raise ValueError("tag_class must be between 0 and 3")

    identifier_octets = tag_class << 6
    identifier_octets |= (1 if constructed else 0) << 5

    if tag_number < 31:
        identifier_octets |= tag_number
        b_asn1_data.append(identifier_octets)
    else:
        # Set the first 5 bits of the first octet to 1 and encode the tag
        # number in subsequent octets.
        identifier_octets |= 31
        b_asn1_data.append(identifier_octets)
        b_asn1_data.extend(_pack_asn1_octet_number(tag_number))

    # ASN.1 Length octet for DER encoding is always in the definite form. This
    # form packs the lengths in the following octet structure:
    #
    # |                       Octet 1                       |  |            Octet n            |
    # |     8     |  7  |  6  |  5  |  4  |  3  |  2  |  1  |  | 8 | 7 | 6 | 5 | 4 | 3 | 2 | 1 |
    # | Long form | Short = length, Long = num octets       |  | Big endian length for long    |
    #
    # Basically if the length < 127 it's encoded in the first octet, otherwise
    # the first octet 7 bits indicates how many subsequent octets were used to
    # encode the length.
    length = len(data)
    if length < 128:
        b_asn1_data.append(length)
    else:
        length_octets = bytearray()
        while length:
            length_octets.append(length & 0b11111111)
            length >>= 8

        # Reverse the octets so the higher octets are first, add the initial
        # length octet with the MSB set and add them all to the main ASN.1 byte
        # array.
        length_octets.reverse()
        b_asn1_data.append(len(length_octets) | 0b10000000)
        b_asn1_data.extend(length_octets)

    return bytes(b_asn1_data) + bytes(data)


class ASN1Writer:
    def __init__(self) -> None:
        self._stack = []

    def push_sequence(
        self,
        tag: t.Optional[ASN1Tag] = None,
    ) -> ASN1Sequence:
        return ASN1Sequence(self)

    def write_integer(
        self,
        value: int,
        tag: t.Optional[ASN1Tag] = None,
    ) -> None:
        return

    def write_octet_string(
        self,
        value: bytes,
        tag: t.Optional[ASN1Tag] = None,
    ) -> None:
        return


class ASN1Sequence:
    def __init__(
        self,
        writer: ASN1Writer,
    ) -> None:
        self._writer = writer

    def __enter__(self) -> ASN1Sequence:
        return self

    def __exit__(self, *args: t.Any, **kwargs: t.Any) -> None:
        return


# def extract_asn1_tlv(
#     tlv: t.Union[bytes, ASN1Value],
#     tag_class: TagClass,
#     tag_number: t.Union[int, TypeTagNumber],
# ) -> bytes:
#     """Extract the bytes and validates the existing tag of an ASN.1 value."""
#     if isinstance(tlv, ASN1Value):
#         if tag_class == TagClass.UNIVERSAL:
#             label_name = TypeTagNumber.native_labels().get(tag_number, "Unknown tag type")
#             msg = "Invalid ASN.1 %s tags, actual tag class %s and tag number %s" % (
#                 label_name,
#                 f"{type(tlv.tag_class).__name__}.{tlv.tag_class.name}",
#                 f"{type(tlv.tag_number).__name__}.{tlv.tag_number.name}"
#                 if isinstance(tlv.tag_number, TypeTagNumber)
#                 else tlv.tag_number,
#             )

#         else:
#             msg = "Invalid ASN.1 tags, actual tag %s and number %s, expecting class %s and number %s" % (
#                 f"{type(tlv.tag_class).__name__}.{tlv.tag_class.name}",
#                 f"{type(tlv.tag_number).__name__}.{tlv.tag_number.name}"
#                 if isinstance(tlv.tag_number, TypeTagNumber)
#                 else tlv.tag_number,
#                 f"{type(tag_class).__name__}.{tag_class.name}",
#                 f"{type(tag_number).__name__}.{tag_number.name}"
#                 if isinstance(tag_number, TypeTagNumber)
#                 else tag_number,
#             )

#         if tlv.tag_class != tag_class or tlv.tag_number != tag_number:
#             raise ValueError(msg)

#         return tlv.b_data

#     return tlv


# def get_sequence_value(
#     sequence: t.Dict[int, ASN1Value],
#     tag: int,
#     structure_name: str,
#     field_name: t.Optional[str] = None,
#     unpack_func: t.Optional[t.Callable[[t.Union[bytes, ASN1Value]], t.Any]] = None,
# ) -> t.Any:
#     """Gets an optional tag entry in a tagged sequence will a further unpacking of the value."""
#     if tag not in sequence:
#         return

#     if not unpack_func:
#         return sequence[tag]

#     try:
#         return unpack_func(sequence[tag])
#     except ValueError as e:
#         where = "%s in %s" % (field_name, structure_name) if field_name else structure_name
#         raise ValueError("Failed unpacking %s: %s" % (where, str(e))) from e


# def pack_asn1_bit_string(
#     value: bytes,
#     tag: bool = True,
# ) -> bytes:
#     # First octet is the number of unused bits in the last octet from the LSB.
#     b_data = b"\x00" + value
#     if tag:
#         b_data = pack_asn1(TagClass.UNIVERSAL, False, TypeTagNumber.BIT_STRING, b_data)

#     return b_data


# def pack_asn1_enumerated(
#     value: int,
#     tag: bool = True,
# ) -> bytes:
#     """Packs an int into an ASN.1 ENUMERATED byte value with optional universal tagging."""
#     b_data = pack_asn1_integer(value, tag=False)
#     if tag:
#         b_data = pack_asn1(TagClass.UNIVERSAL, False, TypeTagNumber.enumerated, b_data)

#     return b_data


# def pack_asn1_general_string(
#     value: t.Union[str, bytes],
#     tag: bool = True,
#     encoding: str = "ascii",
# ) -> bytes:
#     """Packs an string value into an ASN.1 GeneralString byte value with optional universal tagging."""
#     b_data = value if isinstance(value, bytes) else value.encode("utf-8")
#     if tag:
#         b_data = pack_asn1(TagClass.UNIVERSAL, False, TypeTagNumber.general_string, b_data)

#     return b_data


# def pack_asn1_integer(
#     value: int,
#     tag: bool = True,
# ) -> bytes:
#     """Packs an int value into an ASN.1 INTEGER byte value with optional universal tagging."""
#     # Thanks to https://github.com/andrivet/python-asn1 for help with the negative value logic.
#     is_negative = False
#     limit = 0x7F
#     if value < 0:
#         value = -value
#         is_negative = True
#         limit = 0x80

#     b_int = bytearray()
#     while value > limit:
#         val = value & 0xFF

#         if is_negative:
#             val = 0xFF - val

#         b_int.append(val)
#         value >>= 8

#     b_int.append(((0xFF - value) if is_negative else value) & 0xFF)

#     if is_negative:
#         for idx, val in enumerate(b_int):
#             if val < 0xFF:
#                 b_int[idx] += 1
#                 break

#             b_int[idx] = 0

#     if is_negative and b_int[-1] == 0x7F:  # Two's complement corner case
#         b_int.append(0xFF)

#     b_int.reverse()

#     b_value = bytes(b_int)
#     if tag:
#         b_value = pack_asn1(TagClass.UNIVERSAL, False, TypeTagNumber.INTEGER, b_value)

#     return b_value


# def pack_asn1_object_identifier(
#     oid: str,
#     tag: bool = True,
# ) -> bytes:
#     """Packs an str value into an ASN.1 OBJECT IDENTIFIER byte value with optional universal tagging."""
#     b_oid = bytearray()
#     oid_split = [int(i) for i in oid.split(".")]

#     if len(oid_split) < 2:
#         raise ValueError("An OID must have 2 or more elements split by '.'")

#     # The first byte of the OID is the first 2 elements (x.y) as (x * 40) + y
#     b_oid.append((oid_split[0] * 40) + oid_split[1])

#     for val in oid_split[2:]:
#         b_oid.extend(_pack_asn1_octet_number(val))

#     b_value = bytes(b_oid)
#     if tag:
#         b_value = pack_asn1(TagClass.UNIVERSAL, False, TypeTagNumber.object_identifier, b_value)

#     return b_value


# def pack_asn1_octet_string(
#     b_data: bytes,
#     tag: bool = True,
# ) -> bytes:
#     """Packs an bytes value into an ASN.1 OCTET STRING byte value with optional universal tagging."""
#     if tag:
#         b_data = pack_asn1(TagClass.UNIVERSAL, False, TypeTagNumber.OCTET_STRING, b_data)

#     return b_data


# def pack_asn1_sequence(
#     sequence: t.List[bytes],
#     tag: bool = True,
# ) -> bytes:
#     """Packs a list of encoded bytes into an ASN.1 SEQUENCE byte value with optional universal tagging."""
#     b_data = b"".join(sequence)
#     if tag:
#         b_data = pack_asn1(TagClass.UNIVERSAL, True, TypeTagNumber.sequence, b_data)

#     return b_data


# def unpack_asn1_bit_string(value: t.Union[ASN1Value, bytes]) -> bytes:
#     """Unpacks an ASN.1 BIT STRING value."""
#     b_data = extract_asn1_tlv(value, TagClass.UNIVERSAL, TypeTagNumber.BIT_STRING)

#     # First octet is the number of unused bits in the last octet from the LSB.
#     unused_bits = struct.unpack("B", b_data[:1])[0]
#     last_octet = struct.unpack("B", b_data[-2:-1])[0]
#     last_octet = (last_octet >> unused_bits) << unused_bits

#     return b_data[1:-1] + struct.pack("B", last_octet)


# def unpack_asn1_boolean(value: t.Union[ASN1Value, bytes]) -> bool:
#     """Unpacks an ASN.1 BOOLEAN value."""
#     b_data = extract_asn1_tlv(value, TagClass.UNIVERSAL, TypeTagNumber.BOOLEAN)

#     return b_data != b"\x00"


# def unpack_asn1_general_string(value: t.Union[ASN1Value, bytes]) -> bytes:
#     """Unpacks an ASN.1 GeneralString value."""
#     return extract_asn1_tlv(value, TagClass.UNIVERSAL, TypeTagNumber.general_string)


# def unpack_asn1_generalized_time(value: t.Union[ASN1Value, bytes]) -> datetime.datetime:
#     """Unpacks an ASN.1 GeneralizedTime value."""
#     data = extract_asn1_tlv(value, TagClass.UNIVERSAL, TypeTagNumber.generalized_time).decode("utf-8")

#     # While ASN.1 can have a timezone encoded, KerberosTime is the only thing we use and it is always in UTC with the
#     # Z prefix. We strip out the Z because Python 2 doesn't support the %z identifier and add the UTC tz to the object.
#     # https://www.rfc-editor.org/rfc/rfc4120#section-5.2.3
#     if data.endswith("Z"):
#         data = data[:-1]

#     err = None
#     for datetime_format in ["%Y%m%d%H%M%S.%f", "%Y%m%d%H%M%S"]:
#         try:
#             dt = datetime.datetime.strptime(data, datetime_format)
#             return dt.replace(tzinfo=datetime.timezone.utc)
#         except ValueError as e:
#             err = e

#     else:
#         raise err  # type: ignore


# def unpack_asn1_object_identifier(value: t.Union[ASN1Value, bytes]) -> str:
#     """Unpacks an ASN.1 OBJECT IDENTIFIER value."""
#     b_data = extract_asn1_tlv(value, TagClass.UNIVERSAL, TypeTagNumber.object_identifier)

#     first_element = struct.unpack("B", b_data[:1])[0]
#     second_element = first_element % 40
#     ids = [(first_element - second_element) // 40, second_element]

#     idx = 1
#     while idx != len(b_data):
#         oid, octet_len = _unpack_asn1_octet_number(b_data[idx:])
#         ids.append(oid)
#         idx += octet_len

#     return ".".join([str(i) for i in ids])


# def unpack_asn1_tagged_sequence(value: t.Union[ASN1Value, bytes]) -> t.Dict[int, ASN1Value]:
#     """Unpacks an ASN.1 SEQUENCE value as a dictionary."""
#     return dict([(e.tag_number, unpack_asn1(e.b_data)[0]) for e in unpack_asn1_sequence(value)])
