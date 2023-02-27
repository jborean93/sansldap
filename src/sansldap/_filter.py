# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import base64
import dataclasses
import re
import typing as t

from .asn1 import ASN1Reader, ASN1Tag, ASN1Writer, TagClass

_ATTRIBUTE_PATTERN = re.compile(
    r"""^
(?:
    (?:
        # Alphanumeric with hyphen (must start with alpha)
        [a-zA-Z][a-zA-Z0-9\-]*
    )
    | # or
    (?:
        # OID string
        (?:
            # Number without leading 0 (except 0 itself)
            (?:[0-9])|(?:[1-9][0-9]*)
        )
        (?:
            # Optionally repeated but with . as separator
            \.(?:(?:[0-9])|(?:[1-9][0-9]*))
        )*
    )
)
(?:
    # Optional attr options start with ; and are alphanumeric with hyphen
    ;[a-zA-Z0-9\-]+
)*
$""",
    re.VERBOSE,
)
_HEX_PATTERN = re.compile("^[a-fA-F0-9]{2}$")
_LDAP_ESCAPE_PATTERN = re.compile(r"(\\.{,2})".encode("utf-8"))

# (), ), *, \, control chars, any non ASCII chars need to be escaped
_STRING_ESCAPE_PATTERN = re.compile(r"[\x00-\x1F\(\)*\\\x7F-\xFF]".encode("utf-8"))


class FilterSyntaxError(ValueError):
    """Exception used for LDAP filter syntax erros.

    This exception is raised when the code has failed to parse the LDAP filter
    string provided. It provides the full filter used as well as the offset and
    length of the subset that failed to be parsed.

    Args:
        msg: Details of the syntax error.
        offset: The offset of the filter provided that failed.
        length: The length after offset that was part of the failure.
    """

    def __init__(
        self,
        msg: str,
        filter: str,
        offset: int,
        length: int,
    ) -> None:
        super().__init__(msg)
        self.filter = filter
        self.offset = offset
        self.length = length


def _unpack_filter(
    filter: str,
    view: memoryview,
    offset: int,
    length: int,
) -> t.Tuple[LDAPFilter, int]:
    """Unpacks a filter value.

    Unpacks the filter value from the provided data.

    Args:
        filter: The full LDAPFilter string being processed.
        view: The bytes view of the full LDAPFilter string being processed.
        offset: The offset in the view that needs to be processed as a complex
            filter.
        length: The length from offset in the view that needs to be processed.

    Returns:
        Tuple[LDAPFilter, int]: The filter and bytes consumed.
    """
    # Using a memoryview means we avoid copying the string while slicing. The
    # downside is that it's a byte string (UTF-8 encoded).
    current_view = view[offset : offset + length]

    parens_start: t.Optional[int] = None
    parsed_filter: t.Optional[LDAPFilter] = None

    read = 0
    while read < len(current_view):
        current_char = chr(current_view[read])

        if current_char == " ":
            read += 1
            continue

        if current_char == ")":
            if parens_start is None:
                raise FilterSyntaxError(
                    "Unbalanced closing ')' without a starting '('",
                    filter=filter,
                    offset=offset + read,
                    length=1,
                )

            parens_start = None
            read += 1
            break

        elif parens_start is not None:
            # LDAP filter inside parens - '(objectClass=*)' or
            # '(&(test)(value))'. Determine whether it is a simple value or
            # conditional value and parse accordingly. First make sure there
            # isn't a double filter like '((objectClass=*))' or that it didn't
            # just parse one '(!(foo=*)!(bar=*))'.
            if current_char == "(":
                raise FilterSyntaxError(
                    "Nested '(' without filter conditional",
                    filter=filter,
                    offset=offset + read,
                    length=1,
                )

            sub_filter_offset = offset + read
            sub_filter_length = length - read
            if current_char in ["!", "&", "|"]:
                # LDAP filter = '(&(foo=bar)(hello=world))
                parsed_filter, sub_read = _unpack_complex_filter(
                    filter,
                    view,
                    offset=sub_filter_offset,
                    length=sub_filter_length,
                )

            else:
                # LDAP filter = '(foo=bar)'
                parsed_filter, sub_read = _unpack_simple_filter(
                    filter,
                    view,
                    offset=sub_filter_offset,
                    length=sub_filter_length,
                )

            read += sub_read

        elif current_char == "(":
            parens_start = read
            read += 1

        else:
            # An LDAP filter that is not surrounded by () - 'objectClass=*'
            parsed_filter, simple_read = _unpack_simple_filter(
                filter,
                view,
                offset=offset + read,
                length=length - read,
            )
            read += simple_read
            break

    if parens_start is not None:
        raise FilterSyntaxError(
            "Unbalanced starting '(' without a closing ')'",
            filter=filter,
            offset=offset + (parens_start or 0),
            length=length - (offset + (parens_start or 0)),
        )

    if parsed_filter is None:
        raise FilterSyntaxError(
            "No filter found",
            filter=filter,
            offset=offset,
            length=length,
        )

    return parsed_filter, read


def _unpack_complex_filter(
    filter: str,
    view: memoryview,
    offset: int,
    length: int,
) -> t.Tuple[LDAPFilter, int]:
    """Unpacks a complex filter value.

    Unpacks the complex filter value, and, or, not, from the provided data.

    Args:
        filter: The full LDAPFilter string being processed.
        view: The bytes view of the full LDAPFilter string being processed.
        offset: The offset in the view that needs to be processed as a complex
            filter.
        length: The length from offset in the view that needs to be processed.

    Returns:
        Tuple[LDAPFilter, int]: The filter and bytes consumed.
    """
    current_view = view[offset : offset + length]
    parsed_filters: t.List[LDAPFilter] = []
    complex_type = chr(current_view[0])

    read = 1
    while read < len(current_view):
        current_char = chr(current_view[read])

        if current_char == " ":
            read += 1
            continue

        if current_char == "(":
            if complex_type == "!" and len(parsed_filters):
                # LDAP filter - '!(foo=bar)(hello=*)...'
                raise FilterSyntaxError(
                    "Multiple filters found for not '!' expression",
                    filter=filter,
                    offset=offset,
                    length=length,
                )

            parsed_filter, filter_read = _unpack_filter(
                filter,
                view,
                offset + read,
                length - read - 1,
            )
            parsed_filters.append(parsed_filter)

            read += filter_read

        elif current_char == ")":
            break

        elif len(parsed_filters) > 0:
            # LDAP filter = '&(foo=bar)hello=world'
            raise FilterSyntaxError(
                "Expecting ')' to end complex filter expression",
                filter=filter,
                offset=offset + read,
                length=1,
            )

        else:
            # LDAP filter = '|foo=bar'
            raise FilterSyntaxError(
                "Expecting '(' to start after qualifier in complex filter expression",
                filter=filter,
                offset=offset + read,
                length=1,
            )

    if not parsed_filters:
        raise FilterSyntaxError(
            "No filter value found after conditional",
            filter=filter,
            offset=offset,
            length=length,
        )

    if complex_type == "!":
        return FilterNot(parsed_filters[0]), read

    elif complex_type == "&":
        return FilterAnd(parsed_filters), read

    else:
        return FilterOr(parsed_filters), read


def _unpack_simple_filter(
    filter: str,
    view: memoryview,
    offset: int,
    length: int,
) -> t.Tuple[LDAPFilter, int]:
    """Unpacks a simple filter value.

    Unpacks the simple filter value, equality, approx match, substrings, etc,
    from the provided data.

    Args:
        filter: The full LDAPFilter string being processed.
        view: The bytes view of the full LDAPFilter string being processed.
        offset: The offset in the view that needs to be processed as a simple
            filter.
        length: The length from offset in the view that needs to be processed.

    Returns:
        Tuple[LDAPFilter, int]: The filter and bytes consumed.
    """
    current_view = view[offset : offset + length]
    read = 0

    equals_idx = -1
    for i in range(len(current_view)):
        if chr(current_view[i]) == "=":
            equals_idx = i
            break

    if equals_idx == 0:
        raise FilterSyntaxError(
            "Simple filter value must not start with '='",
            filter=filter,
            offset=offset,
            length=1,
        )

    elif equals_idx == -1:
        raise FilterSyntaxError(
            "Simple filter missing '=' character",
            filter=filter,
            offset=offset,
            length=length,
        )

    elif equals_idx == length - 1:
        raise FilterSyntaxError(
            "Simple filter value is not present after '='",
            filter=filter,
            offset=offset,
            length=length,
        )

    filter_type: t.Optional[str] = chr(current_view[equals_idx - 1])
    attribute_end = equals_idx
    if filter_type in [":", ">", "<", "~"]:
        if equals_idx == 1:
            raise FilterSyntaxError(
                "Filter must define an attribute name before the equal symbol",
                filter=filter,
                offset=offset,
                length=length,
            )
        attribute_end -= 1
    else:
        filter_type = None

    attribute = current_view[:attribute_end].tobytes().decode("utf-8")
    if filter_type != ":" and not _ATTRIBUTE_PATTERN.match(attribute):
        raise FilterSyntaxError(
            "Filter attribute is invalid",
            filter=filter,
            offset=offset,
            length=attribute_end,
        )

    read += equals_idx + 1
    value_offset = offset + read

    value_length = len(current_view) - read
    for i in range(value_length):
        if chr(current_view[i + read]) == ")":
            value_length = i
            break

    raw_value = current_view[read : read + value_length].tobytes()
    read += value_length
    if filter_type or b"*" not in raw_value:
        b_value = _unpack_filter_value(
            filter,
            raw_value,
            offset=value_offset,
            length=value_length,
        )
    else:
        b_value = raw_value

    if filter_type == ":":
        ext_attribute, for_dn, rule = _unpack_filter_extensible_header(
            filter,
            attribute,
            offset=offset,
            length=attribute_end,
        )
        return FilterExtensibleMatch(rule, ext_attribute, b_value, for_dn), read

    elif filter_type == ">":
        return FilterGreaterOrEqual(attribute, b_value), read

    elif filter_type == "<":
        return FilterLessOrEqual(attribute, b_value), read

    elif filter_type == "~":
        return FilterApproxMatch(attribute, b_value), read

    elif raw_value == b"*":
        return FilterPresent(attribute), read

    elif b"*" in raw_value:
        first, values, end = _unpack_filter_substrings_value(
            filter,
            b_value,
            offset=value_offset,
            length=value_length,
        )

        return FilterSubstrings(attribute, first, values, end), read

    else:
        return FilterEquality(attribute, b_value), read


def _unpack_filter_extensible_header(
    filter: str,
    header: str,
    offset: int,
    length: int,
) -> t.Tuple[t.Optional[str], bool, t.Optional[str]]:
    """Unpacks the extensible filter header.

    Unpacks the extensible filter header, including the attribute, dn setting,
    and rule.

    Args:
        filter: The full LDAP filter being process,
        header: The header to unpack.
        offset: The offset of the header in filter.
        length: The length of the header in filter.

    Returns:
        Tuple[Optional[str], bool, Optional[str]]: The attribute, dn settings,
        and rule from the header.
    """
    attribute: t.Optional[str] = None
    rule: t.Optional[str] = None
    for_dn = False

    header_split = list(header.split(":"))
    if header_split[0]:
        if _ATTRIBUTE_PATTERN.match(header_split[0]):
            attribute = header_split[0]
        else:
            raise FilterSyntaxError(
                "Invalid extensible filter attribute",
                filter=filter,
                offset=offset,
                length=length,
            )

    header_split.pop(0)

    if header_split and header_split[0] == "dn":
        for_dn = True
        header_split.pop(0)

    if header_split:
        if _ATTRIBUTE_PATTERN.match(header_split[0]):
            rule = header_split.pop(0)
        else:
            raise FilterSyntaxError(
                "Invalid extensible filter rule",
                filter=filter,
                offset=offset,
                length=length,
            )

    if header_split:
        raise FilterSyntaxError(
            "Extra data found in extensible filter header",
            filter=filter,
            offset=offset,
            length=length,
        )

    return attribute, for_dn, rule


def _unpack_filter_substrings_value(
    filter: str,
    value: bytes,
    offset: int,
    length: int,
) -> t.Tuple[t.Optional[bytes], t.List[bytes], t.Optional[bytes]]:
    """Unpack a filter substrings value.

    Unpacks the raw filter substrings value into the first, any, and final
    bytes it represents.

    Args:
        filter: The whole filter this is included in.
        value: The value to unpack.
        offset: The offset of the value in the filter.
        length: The length of the value in the filter.

    Returns:
        Tuple[Optional[bytes], List[bytes], Optional[bytes]]: The first, and,
        and final value of the substrings filter.
    """
    first: t.Optional[bytes] = None
    values: t.List[bytes] = []
    end: t.Optional[bytes] = None

    value_split = value.split(b"*")
    for idx, v in enumerate(value_split):
        if idx == 0:
            if v:
                first = _unpack_filter_value(filter, v, offset, length)
            continue

        if idx == len(value_split) - 1:
            if v:
                end = _unpack_filter_value(filter, v, offset, length)
            continue

        if v:
            values.append(_unpack_filter_value(filter, v, offset, length))

        else:
            raise FilterSyntaxError(
                "Cannot have 2 consecutive '*' in substring filter value",
                filter,
                offset=offset,
                length=length,
            )

    return first, values, end


def _unpack_filter_value(
    filter: str,
    value: bytes,
    offset: int,
    length: int,
) -> bytes:
    """Unpack a filter value.

    Unpacks the raw filter value string into the bytes it represents. This will
    escape the ocurrences of '\\[0-9a-fA-F]{2}' with the raw byte value that
    hex escape represents.

    Args:
        filter: The whole filter this is included in.
        value: The value to unpack.
        offset: The offset of the value in the filter.
        length: The length of the value in the filter.

    Returns:
        bytes: The unpacked bytes of the value.
    """

    def rplcr(matchobj: re.Match) -> bytes:
        raw_value = matchobj.group(1)[1:].decode("utf-8", errors="surrogateescape")
        if _HEX_PATTERN.match(raw_value):
            return base64.b16decode(raw_value.upper())

        else:
            raise ValueError(f"Invalid hex characters following \\ '{raw_value}', requires 2 [0-9a-fA-F]")

    try:
        # As we are already using bytes, we can just use regex on that byte
        # string rather than go back to a string.
        return _LDAP_ESCAPE_PATTERN.sub(rplcr, value)
    except ValueError as e:
        raise FilterSyntaxError(
            str(e),
            filter=filter,
            offset=offset,
            length=length,
        )


def _serialize_filter_value(
    value: bytes,
) -> str:
    """Serializes a filter value.

    Serializes the raw filter value bytes into a string that can be used inside
    an LDAP filter string. It will escape any control char, (, ), *, \\ as well
    as any non-ASCII chars (outside of \\x7F). While it is possible to embed
    non-ASCII chars inside a filter string it safer and more portable to ensure
    they are in the escaped form to remove any ambiguity.

    Args:
        value: The raw value to serialize.

    Returns:
        str: The serialized filter value.
    """

    def rplcr(matchobj: re.Match) -> bytes:
        return f"\\{ord(matchobj.group(0)):02x}".encode("utf-8")

    return _STRING_ESCAPE_PATTERN.sub(rplcr, value).decode("utf-8")


@dataclasses.dataclass
class FilterOptions:
    """Options used for Filter packing and unpacking.

    Custom options used for packing and unpacking filter objects.

    Args:
        string_encoding: The encoding that is used to encode and decode
            strings. Defaults to utf-8.
        choices: List of known filter types.
    """

    string_encoding: str = "utf-8"
    choices: t.List[t.Type[LDAPFilter]] = dataclasses.field(
        default_factory=lambda: [
            FilterAnd,
            FilterApproxMatch,
            FilterEquality,
            FilterExtensibleMatch,
            FilterGreaterOrEqual,
            FilterLessOrEqual,
            FilterNot,
            FilterOr,
            FilterPresent,
            FilterSubstrings,
        ]
    )


@dataclasses.dataclass(frozen=True)
class LDAPFilter:
    """Base class for all LDAP filters.

    This is the base class in which all LDAP filters derive and can be used to
    implement custom filters outside of the set provided in the LDAP RFC.
    Currently the following filter types are known and implemented:

        :class:`FilterAnd`
        :class:`FilterOr`
        :class:`FilterNoe`
        :class:`FilterEquality`
        :class:`FilterSubstrings`
        :class:`FilterGreaterOrEqual`
        :class:`FilterLessOrEqual`
        :class:`FilterPresent`
        :class:`FilterApproxMatch`
        :class:`FilterExtensibleMatch`

    A custom implementation must inherit this class and provide a value for
    filter_id as well as implement the ``pack`` and ``unpack`` methods. These
    methods use the :class:`ASN1Writer` and :class:`ASN1Reader` classes
    respectively to make it easier to deal with ASN.1 structured data and more
    efficiently stream the data as needed.

    Example:
        .. code-block:: python

            @dataclasses.dataclass(frozen=True)
            class CustomFilter(LDAPFilter):
                filter_id: int = dataclasses.field(init=False, repr=False, default=1024)

                value: str

                def pack(
                    self,
                    writer: sansldap.asn1.ASN1Writer,
                    options: FilterOptions,
                ) -> None:
                    writer.write_octet_string(
                        self.value.encode(options.string_encoding),
                        tag=sansldap.asn1.ASN1Tag(
                            sansldap.asn1.TagClass.CONTEXT_SPECIFIC,
                            self.filter_id,
                            False,
                        ),
                    )

                @classmethod
                def unpack(
                    cls,
                    reader: sansldap.asn1.ASN1Reader,
                    options: FilterOptions,
                ) -> CustomFilter:
                    value = reader.read_octet_string(
                        sansldap.asn1.ASN1Tag(
                            sansldap.asn1.TagClass.CONTEXT_SPECIFIC,
                            cls.filter_id,
                            False,
                        ),
                    ).decode("utf-8")
                    return CustomFilter(value=value)

    Note:
        A custom filter must be understood by both the client and server.
    """

    # Filter ::= CHOICE {
    #      and             [0] SET SIZE (1..MAX) OF filter Filter,
    #      or              [1] SET SIZE (1..MAX) OF filter Filter,
    #      not             [2] Filter,
    #      equalityMatch   [3] AttributeValueAssertion,
    #      substrings      [4] SubstringFilter,
    #      greaterOrEqual  [5] AttributeValueAssertion,
    #      lessOrEqual     [6] AttributeValueAssertion,
    #      present         [7] AttributeDescription,
    #      approxMatch     [8] AttributeValueAssertion,
    #      extensibleMatch [9] MatchingRuleAssertion,
    #      ...  }

    filter_id: int
    "The ASN.1 choice value for this filter."

    def pack(
        self,
        writer: ASN1Writer,
        options: FilterOptions,
    ) -> None:
        """Pack the filter structure.

        Writes the filter structure into the ASN.1 writer that is then embedded
        in the :class:`SearchRequest` filter value. The tagged choice should
        also be included in the written value.

        Args:
            writer: The writer used to write ASN.1 data
            options: Options that can be used to control how the filter is
                packed.
        """
        raise NotImplementedError()  # pragma: nocover

    @classmethod
    def from_string(
        cls,
        filter: str,
    ) -> LDAPFilter:
        """Convert an LDAP filter string to a filter object.

        Converts the string provided into an LDAPFilter object based on the
        standard LDAPFilter string rules. This only supports the LDAP filters
        as defined in RFC 4511.

        Args:
            filter: The LDAP filter string to convert.

        Returns:
            LDAPFilter: The converted filter.
        """
        filter = filter.strip()
        b_filter = filter.encode("utf-8", errors="surrogateescape")
        filter_view = memoryview(b_filter)
        filter_obj, consumed = _unpack_filter(filter, filter_view, 0, len(b_filter))
        if consumed < len(b_filter):
            raise FilterSyntaxError(
                "Extra data found at filter end",
                filter=filter,
                offset=consumed,
                length=len(b_filter) - consumed,
            )

        return filter_obj

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
        options: FilterOptions,
    ) -> LDAPFilter:
        """Unpacks the filter bytes.

        Unpacks the raw bytes into the Python object.

        Args:
            reader: The reader used to read the ASN.1 data.
            options: Options that can be used to control how the filter is
                unpacked.

        Returns:
            LDAPFilter: An instance of the object that has been unpacked.
        """
        next_header = reader.peek_header()
        if next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC:
            for filter_type in options.choices:
                if filter_type.filter_id == next_header.tag.tag_number:
                    return filter_type.unpack(reader, options)

        raise NotImplementedError(f"Unknown filter object {next_header.tag}, cannot unpack")


@dataclasses.dataclass(frozen=True)
class FilterAnd(LDAPFilter):
    """LDAP Filter Any.

    An LDAP filter that is used to combine multiple filters together using the
    AND logic operation. All filters specified must be true for this filter to
    be true in a search operation. An AND LDAP filter string look like
    ``(&(condition=1)(condition=2)...)``

    Args:
        filters: The filters to use in the AND operation.
    """

    filter_id: int = dataclasses.field(init=False, repr=False, default=0)

    filters: t.List[LDAPFilter]

    def __str__(self) -> str:
        filter_strings = "".join(str(f) for f in self.filters)
        return f"(&{filter_strings})"

    def pack(
        self,
        writer: ASN1Writer,
        options: FilterOptions,
    ) -> None:
        with writer.push_set_of(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            for f in self.filters:
                f.pack(w, options)

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
        options: FilterOptions,
    ) -> FilterAnd:
        filters = []
        and_reader = reader.read_set_of(
            tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, cls.filter_id, True),
            hint="Filter.and",
        )
        while and_reader:
            filter = LDAPFilter.unpack(and_reader, options)
            filters.append(filter)

        return FilterAnd(filters=filters)


@dataclasses.dataclass(frozen=True)
class FilterOr(LDAPFilter):
    """LDAP Filter Or.

    An LDAP filter that is used to combine multiple filters together using the
    OR logic operation. Only one of the filters specified must be true for this
    filter to be true in a search operation. An OR LDAP filter string looks
    like ``(|(condition=1)(condition=2)...)``

    Args:
        filters: The filters to use in the OR operation.
    """

    filter_id: int = dataclasses.field(init=False, repr=False, default=1)

    filters: t.List[LDAPFilter]

    def __str__(self) -> str:
        filter_strings = "".join(str(f) for f in self.filters)
        return f"(|{filter_strings})"

    def pack(
        self,
        writer: ASN1Writer,
        options: FilterOptions,
    ) -> None:
        with writer.push_set_of(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            for f in self.filters:
                f.pack(w, options)

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
        options: FilterOptions,
    ) -> FilterOr:
        filters = []
        or_reader = reader.read_set_of(
            tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, cls.filter_id, True),
            hint="Filter.or",
        )
        while or_reader:
            filter = LDAPFilter.unpack(or_reader, options)
            filters.append(filter)

        return FilterOr(filters=filters)


@dataclasses.dataclass(frozen=True)
class FilterNot(LDAPFilter):
    """LDAP Filter Not.

    An LDAP filter that is used to inverse the logic of the filter present. For
    example if the filter condition is false, then the NOT filter will make it
    true and vice versa. A NOT LDAP filter string looks like
    ``(!(attribute=1))``.

    Args:
        filter: The filter to inverse.
    """

    filter_id: int = dataclasses.field(init=False, repr=False, default=2)

    filter: LDAPFilter

    def __str__(self) -> str:
        return f"(!{self.filter!s})"

    def pack(
        self,
        writer: ASN1Writer,
        options: FilterOptions,
    ) -> None:
        with writer.push_set_of(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            self.filter.pack(w, options)

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
        options: FilterOptions,
    ) -> FilterNot:
        not_reader = reader.read_sequence(
            tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, cls.filter_id, True),
            hint="Filter.not",
        )
        not_filter = LDAPFilter.unpack(not_reader, options)

        return FilterNot(filter=not_filter)


@dataclasses.dataclass(frozen=True)
class FilterEquality(LDAPFilter):
    """LDAP Filter Equality.

    An LDAP filter that is used to check if the attribtue specified is set to
    the value specified. An equality LDAP filter string looks like
    ``(attribute=1)``.

    Args:
        attribute: The attribute to match against.
        value: The value of the attribute to check.
    """

    filter_id: int = dataclasses.field(init=False, repr=False, default=3)

    attribute: str
    value: bytes

    def __str__(self) -> str:
        return f"({self.attribute}={_serialize_filter_value(self.value)})"

    def pack(
        self,
        writer: ASN1Writer,
        options: FilterOptions,
    ) -> None:
        with writer.push_sequence(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            w.write_octet_string(self.attribute.encode(options.string_encoding))
            w.write_octet_string(self.value)

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
        options: FilterOptions,
    ) -> FilterEquality:
        attribute, value = _unpack_filter_attribute_value_assertion(
            cls,
            reader,
            options,
            "FilterEquality",
        )
        return FilterEquality(attribute=attribute, value=value)


@dataclasses.dataclass(frozen=True)
class FilterSubstrings(LDAPFilter):
    """LDAP Filter Substrings.

    An LDAP filter that is used to check substrings inside an attribute value.
    It can contain an initial and final string that must match the start and
    end of the value respectively. It can also contain any values in the middle
    of the value as denoted by the any argument. A substrings LDAP filter looks
    like ``(attribute=initial*any 1*any 2*final)``.

    Args:
        attribute: The attribute to match against.
        initial: The value must start with this value if present.
        any: Values inside the whole value that are checked to be in the value.
        final: The value must end with this value if present.
    """

    filter_id: int = dataclasses.field(init=False, repr=False, default=4)

    attribute: str
    initial: t.Optional[bytes]
    any: t.List[bytes]
    final: t.Optional[bytes]

    def __str__(self) -> str:
        values = [
            _serialize_filter_value(self.initial or b""),
        ]
        for a in self.any:
            values.append(_serialize_filter_value(a))

        values.append(_serialize_filter_value(self.final or b""))

        value_str = "*".join(values)
        return f"({self.attribute}={value_str})"

    def pack(
        self,
        writer: ASN1Writer,
        options: FilterOptions,
    ) -> None:
        with writer.push_sequence(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            w.write_octet_string(self.attribute.encode(options.string_encoding))

            with w.push_sequence_of() as value_writer:
                if self.initial is not None:
                    value_writer.write_octet_string(
                        self.initial,
                        tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, 0, False),
                    )

                for value in self.any:
                    value_writer.write_octet_string(
                        value,
                        tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, 1, False),
                    )

                if self.final is not None:
                    value_writer.write_octet_string(
                        self.final,
                        tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, 2, False),
                    )

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
        options: FilterOptions,
    ) -> FilterSubstrings:
        filter_reader = reader.read_sequence(
            tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, cls.filter_id, True),
            hint="Filter.substrings",
        )

        attribute = filter_reader.read_octet_string(
            hint="Filter.substrings.type",
        ).decode(options.string_encoding)

        substrings_reader = filter_reader.read_sequence_of(
            hint="Filter.substrings.substrings",
        )
        initial: t.Optional[bytes] = None
        any_values: t.List[bytes] = []
        final: t.Optional[bytes] = None
        while substrings_reader:
            next_header = substrings_reader.peek_header()

            if next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC and next_header.tag.tag_number == 0:
                if initial is not None:
                    raise ValueError("Received multiple initial values when unpacking Filter.substrings")

                initial = substrings_reader.read_octet_string(
                    header=next_header,
                    hint="Filter.substrings.initial",
                )
                continue

            elif next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC and next_header.tag.tag_number == 1:
                value = substrings_reader.read_octet_string(
                    header=next_header,
                    hint="Filter.substrings.any",
                )
                any_values.append(value)
                continue

            elif next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC and next_header.tag.tag_number == 2:
                if final is not None:
                    raise ValueError("Received multiple final values when unpacking Filter.substrings")

                final = substrings_reader.read_octet_string(
                    header=next_header,
                    hint="Filter.substrings.initial",
                )
                continue

            substrings_reader.skip_value(next_header)

        return FilterSubstrings(
            attribute=attribute,
            initial=initial,
            any=any_values,
            final=final,
        )


@dataclasses.dataclass(frozen=True)
class FilterGreaterOrEqual(LDAPFilter):
    """LDAP Filter Greater Than.

    An LDAP filter that is used to great if the value is greater than or equal
    to the value specified. A greater than or equal LDAP filter looks like
    ``(attribute>=1)``.

    Args:
        attribute: The attribute to match against.
        value: The value that must be greater or equal to the actual value.
    """

    filter_id: int = dataclasses.field(init=False, repr=False, default=5)

    attribute: str
    value: bytes

    def __str__(self) -> str:
        return f"({self.attribute}>={_serialize_filter_value(self.value)})"

    def pack(
        self,
        writer: ASN1Writer,
        options: FilterOptions,
    ) -> None:
        with writer.push_sequence(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            w.write_octet_string(self.attribute.encode(options.string_encoding))
            w.write_octet_string(self.value)

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
        options: FilterOptions,
    ) -> FilterGreaterOrEqual:
        attribute, value = _unpack_filter_attribute_value_assertion(
            cls,
            reader,
            options,
            "FilterGreaterOrEqual",
        )
        return FilterGreaterOrEqual(attribute=attribute, value=value)


@dataclasses.dataclass(frozen=True)
class FilterLessOrEqual(LDAPFilter):
    """LDAP Filter Less Than.

    An LDAP filter that is used to great if the value is less than or equal
    to the value specified. A less than or equal LDAP filter looks like
    ``(attribute<=1)``.

    Args:
        attribute: The attribute to match against.
        value: The value that must be lesser or equal to the actual value.
    """

    filter_id: int = dataclasses.field(init=False, repr=False, default=6)

    attribute: str
    value: bytes

    def __str__(self) -> str:
        return f"({self.attribute}<={_serialize_filter_value(self.value)})"

    def pack(
        self,
        writer: ASN1Writer,
        options: FilterOptions,
    ) -> None:
        with writer.push_sequence(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            w.write_octet_string(self.attribute.encode(options.string_encoding))
            w.write_octet_string(self.value)

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
        options: FilterOptions,
    ) -> FilterLessOrEqual:
        attribute, value = _unpack_filter_attribute_value_assertion(
            cls,
            reader,
            options,
            "FilterLessOrEqual",
        )
        return FilterLessOrEqual(attribute=attribute, value=value)


@dataclasses.dataclass(frozen=True)
class FilterPresent(LDAPFilter):
    """LDAP Filter Present.

    An LDAP filter that is used to great if the attribute is present (has a
    value) in the entity being checked. A present LDAP filter looks like
    ``(attribute=*)``.

    Args:
        attribute: The attribute to check if present.
    """

    filter_id: int = dataclasses.field(init=False, repr=False, default=7)

    attribute: str

    def __str__(self) -> str:
        return f"({self.attribute}=*)"

    def pack(
        self,
        writer: ASN1Writer,
        options: FilterOptions,
    ) -> None:
        writer.write_octet_string(
            self.attribute.encode(options.string_encoding),
            tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, False),
        )

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
        options: FilterOptions,
    ) -> FilterPresent:
        value = reader.read_octet_string(
            tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, cls.filter_id, False),
            hint="Filter.present",
        ).decode(options.string_encoding)

        return FilterPresent(attribute=value)


@dataclasses.dataclass(frozen=True)
class FilterApproxMatch(LDAPFilter):
    """LDAP Filter Approx Match.

    An LDAP filter that is used to check if the value for the attribute
    specified matches a locally-defined approximate matching algorithm. An
    approx match LDAP filter looks like ``(attribute~=condition)``.

    Args:
        attribute: The attribute to match against.
        value: The value to use as the approximate matching comparison.
    """

    filter_id: int = dataclasses.field(init=False, repr=False, default=8)

    attribute: str
    value: bytes

    def __str__(self) -> str:
        return f"({self.attribute}~={_serialize_filter_value(self.value)})"

    def pack(
        self,
        writer: ASN1Writer,
        options: FilterOptions,
    ) -> None:
        with writer.push_sequence(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            w.write_octet_string(self.attribute.encode(options.string_encoding))
            w.write_octet_string(self.value)

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
        options: FilterOptions,
    ) -> FilterApproxMatch:
        attribute, value = _unpack_filter_attribute_value_assertion(
            cls,
            reader,
            options,
            "FilterApproxMatch",
        )
        return FilterApproxMatch(attribute=attribute, value=value)


@dataclasses.dataclass(frozen=True)
class FilterExtensibleMatch(LDAPFilter):
    """LDAP Filter Extensible Match.

    An LDAP filter that is used to as a more powerful way to check an attribute
    value. It can have custom rules and logic that is known to the server for
    the check. An extensible amtch LDAP filter looks like
    ``(attribute:=John)``, ``(attribute:dn:=Jordan)``, or
    ``(attribute:1.2.3:=John)``. If no rule is specified then attribute must be
    set.

    Args:
        rule: The rule name or OID string that should be used for the match or
            None if attribute is set to follow the normal rules.
        attribute: The attribute to match against if this should only be
            checked against a single value. Can be None to search all
            attributes if rule is set.
        value: The value to compare.
        dn_attributes: Use the attributes that compose the entries DN in the
            check.
    """

    filter_id: int = dataclasses.field(init=False, repr=False, default=9)

    rule: t.Optional[str]
    attribute: t.Optional[str]
    value: bytes
    dn_attributes: bool

    def __str__(self) -> str:
        headers = [self.attribute or ""]

        if self.dn_attributes:
            headers.append("dn")

        if self.rule is not None:
            headers.append(self.rule)

        header_str = ":".join(headers)
        return f"({header_str}:={_serialize_filter_value(self.value)})"

    def pack(
        self,
        writer: ASN1Writer,
        options: FilterOptions,
    ) -> None:
        with writer.push_sequence(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            if self.rule is not None:
                w.write_octet_string(
                    self.rule.encode(options.string_encoding),
                    tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, 1, False),
                )

            if self.attribute is not None:
                w.write_octet_string(
                    self.attribute.encode(options.string_encoding),
                    tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, 2, False),
                )

            w.write_octet_string(
                self.value,
                tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, 3, False),
            )

            if self.dn_attributes:
                w.write_boolean(
                    self.dn_attributes,
                    tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, 4, False),
                )

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
        options: FilterOptions,
    ) -> FilterExtensibleMatch:
        filter_reader = reader.read_sequence(
            tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, cls.filter_id, True),
            hint="Filter.extensibleMatch",
        )

        rule: t.Optional[str] = None
        attribute: t.Optional[str] = None
        value = b""
        dn_attributes = False
        while filter_reader:
            next_header = filter_reader.peek_header()

            if next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC:
                if next_header.tag.tag_number == 1:
                    rule = filter_reader.read_octet_string(
                        header=next_header,
                        hint="Filter.extensibleMatch.matchingRule",
                    ).decode(options.string_encoding)
                    continue

                elif next_header.tag.tag_number == 2:
                    attribute = filter_reader.read_octet_string(
                        header=next_header,
                        hint="Filter.extensibleMatch.type",
                    ).decode(options.string_encoding)
                    continue

                elif next_header.tag.tag_number == 3:
                    value = filter_reader.read_octet_string(
                        header=next_header,
                        hint="Filter.extensibleMatch.matchValue",
                    )
                    continue

                elif next_header.tag.tag_number == 4:
                    dn_attributes = filter_reader.read_boolean(
                        header=next_header,
                        hint="Filter.extensibleMatch.dnAttributes",
                    )
                    continue

            filter_reader.skip_value(next_header)

        return FilterExtensibleMatch(
            rule=rule,
            attribute=attribute,
            value=value,
            dn_attributes=dn_attributes,
        )


def _unpack_filter_attribute_value_assertion(
    cls: t.Type[LDAPFilter],
    reader: ASN1Reader,
    options: FilterOptions,
    name: str,
) -> t.Tuple[str, bytes]:
    filter_reader = reader.read_sequence(
        tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, cls.filter_id, True),
        hint=f"Filter.{name}",
    )

    attribute = filter_reader.read_octet_string(
        hint=f"Filter.{name}.attributeDesc",
    ).decode(options.string_encoding)
    value = filter_reader.read_octet_string(
        hint=f"Filter.{name}.assertionValue",
    )

    return attribute, value
