# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import typing as t

from .asn1 import ASN1Reader, ASN1Tag, ASN1Writer, TagClass


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


@dataclasses.dataclass
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

            @dataclasses.dataclass
            class CustomFilter(LDAPFilter):
                filter_id = dataclasses.field(init=False, repr=False, default=1024)

                value: str

                def pack(
                    self,
                    writer: ASN1Writer,
                    options: FilterOptions,
                ) -> None:
                    writer.write_octet_string(
                        self.value.encode(options.string_encoding),
                        tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, False),
                    )

                @classmethod
                def unpack(
                    cls,
                    reader: ASN1Reader,
                    options: FilterOptions,
                ) -> CustomFilter:
                    value = reader.read_octet_string(
                        ASN1Tag(TagClass.CONTEXT_SPECIFIC, cls.filter_id, False),
                    )
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
        raise NotImplementedError()

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


@dataclasses.dataclass
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


@dataclasses.dataclass
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


@dataclasses.dataclass
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


@dataclasses.dataclass
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


@dataclasses.dataclass
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

    def pack(
        self,
        writer: ASN1Writer,
        options: FilterOptions,
    ) -> None:
        with writer.push_sequence(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            w.write_octet_string(self.attribute.encode(options.string_encoding))

            with writer.push_sequence_of() as value_writer:
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


@dataclasses.dataclass
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


@dataclasses.dataclass
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


@dataclasses.dataclass
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


@dataclasses.dataclass
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


@dataclasses.dataclass
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
