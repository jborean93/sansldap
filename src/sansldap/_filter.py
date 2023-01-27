# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import typing as t

from ._asn1 import ASN1Header, ASN1Reader, ASN1Tag, ASN1Writer, TagClass


def unpack_ldap_filter(
    reader: ASN1Reader,
) -> LDAPFilter:
    choice = reader.peek_header()

    unpack_func = FILTER_UNPACKER.get(choice.tag.tag_number, None)
    if choice.tag.tag_class != TagClass.CONTEXT_SPECIFIC or not unpack_func:
        raise NotImplementedError(f"Unknown Filter object {choice.tag}")

    return unpack_func(reader, choice)


@dataclasses.dataclass
class LDAPFilter:
    filter_id: int

    def _pack_internal(
        self,
        writer: ASN1Writer,
    ) -> None:
        raise NotImplementedError()


@dataclasses.dataclass
class FilterAnd(LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=0)

    filters: t.List[LDAPFilter]

    def _pack_internal(
        self,
        writer: ASN1Writer,
    ) -> None:
        with writer.push_set_of(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            for f in self.filters:
                f._pack_internal(w)


def _unpack_filter_and(
    reader: ASN1Reader,
    header: ASN1Header,
) -> FilterAnd:
    filters = []
    and_reader = reader.read_set_of(header=header, hint="Filter.and")
    while and_reader:
        filter = unpack_ldap_filter(and_reader)
        filters.append(filter)

    return FilterAnd(filters=filters)


@dataclasses.dataclass
class FilterOr(LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=1)

    filters: t.List[LDAPFilter]

    def _pack_internal(
        self,
        writer: ASN1Writer,
    ) -> None:
        with writer.push_set_of(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            for f in self.filters:
                f._pack_internal(w)


def _unpack_filter_or(
    reader: ASN1Reader,
    header: ASN1Header,
) -> FilterOr:
    filters = []
    or_reader = reader.read_set_of(header=header, hint="Filter.or")
    while or_reader:
        filter = unpack_ldap_filter(or_reader)
        filters.append(filter)

    return FilterOr(filters=filters)


@dataclasses.dataclass
class FilterNot(LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=2)

    filter: LDAPFilter

    def _pack_internal(
        self,
        writer: ASN1Writer,
    ) -> None:
        with writer.push_set_of(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            self.filter._pack_internal(w)


def _unpack_filter_not(
    reader: ASN1Reader,
    header: ASN1Header,
) -> FilterNot:
    not_reader = reader.read_sequence(header=header, hint="Filter.not")
    not_filter = unpack_ldap_filter(not_reader)

    return FilterNot(filter=not_filter)


@dataclasses.dataclass
class FilterEquality(LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=3)

    attribute: str
    value: bytes

    def _pack_internal(
        self,
        writer: ASN1Writer,
    ) -> None:
        with writer.push_sequence(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            w.write_octet_string(self.attribute.encode("utf-8"))
            w.write_octet_string(self.value)


def _unpack_filter_equality(
    reader: ASN1Reader,
    header: ASN1Header,
) -> FilterEquality:
    attribute, value = _unpack_filter_attribute_value_assertion(
        reader,
        header,
        "FilterEquality",
    )
    return FilterEquality(attribute=attribute, value=value)


@dataclasses.dataclass
class FilterSubstrings(LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=4)

    attribute: str
    initial: t.Optional[bytes]
    any: t.List[bytes]
    final: t.Optional[bytes]

    def _pack_internal(
        self,
        writer: ASN1Writer,
    ) -> None:
        with writer.push_sequence(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            w.write_octet_string(self.attribute.encode("utf-8"))

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


def _unpack_filter_substrings(
    reader: ASN1Reader,
    header: ASN1Header,
) -> FilterSubstrings:
    filter_reader = reader.read_sequence(
        header=header,
        hint="Filter.substrings",
    )

    attribute = filter_reader.read_octet_string(
        hint="Filter.substrings.type",
    ).decode("utf-8")

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
    filter_id: int = dataclasses.field(init=False, repr=False, default=5)

    attribute: str
    value: bytes

    def _pack_internal(
        self,
        writer: ASN1Writer,
    ) -> None:
        with writer.push_sequence(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            w.write_octet_string(self.attribute.encode("utf-8"))
            w.write_octet_string(self.value)


def _unpack_filter_greater_or_equal(
    reader: ASN1Reader,
    header: ASN1Header,
) -> FilterGreaterOrEqual:
    attribute, value = _unpack_filter_attribute_value_assertion(
        reader,
        header,
        "FilterGreaterOrEqual",
    )
    return FilterGreaterOrEqual(attribute=attribute, value=value)


@dataclasses.dataclass
class FilterLessOrEqual(LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=6)

    attribute: str
    value: bytes

    def _pack_internal(
        self,
        writer: ASN1Writer,
    ) -> None:
        with writer.push_sequence(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            w.write_octet_string(self.attribute.encode("utf-8"))
            w.write_octet_string(self.value)


def _unpack_filter_less_or_equal(
    reader: ASN1Reader,
    header: ASN1Header,
) -> FilterLessOrEqual:
    attribute, value = _unpack_filter_attribute_value_assertion(
        reader,
        header,
        "FilterLessOrEqual",
    )
    return FilterLessOrEqual(attribute=attribute, value=value)


@dataclasses.dataclass
class FilterPresent(LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=7)

    attribute: str

    def _pack_internal(
        self,
        writer: ASN1Writer,
    ) -> None:
        writer.write_octet_string(
            self.attribute.encode("utf-8"),
            tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, False),
        )


def _unpack_filter_present(
    reader: ASN1Reader,
    header: ASN1Header,
) -> FilterPresent:
    value = reader.read_octet_string(
        header=header,
        hint="Filter.present",
    ).decode("utf-8")

    return FilterPresent(attribute=value)


@dataclasses.dataclass
class FilterApproxMatch(LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=8)

    attribute: str
    value: bytes

    def _pack_internal(
        self,
        writer: ASN1Writer,
    ) -> None:
        with writer.push_sequence(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            w.write_octet_string(self.attribute.encode("utf-8"))
            w.write_octet_string(self.value)


def _unpack_filter_approx_match(
    reader: ASN1Reader,
    header: ASN1Header,
) -> FilterApproxMatch:
    attribute, value = _unpack_filter_attribute_value_assertion(
        reader,
        header,
        "FilterApproxMatch",
    )
    return FilterApproxMatch(attribute=attribute, value=value)


@dataclasses.dataclass
class FilterExtensibleMatch(LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=9)

    rule: t.Optional[str]
    attribute: t.Optional[str]
    value: bytes
    dn_attributes: bool

    def _pack_internal(
        self,
        writer: ASN1Writer,
    ) -> None:
        with writer.push_sequence(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, True),
        ) as w:
            if self.rule is not None:
                w.write_octet_string(
                    self.rule.encode("utf-8"),
                    tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, 1, False),
                )

            if self.attribute is not None:
                w.write_octet_string(
                    self.attribute.encode("utf-8"),
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


def _unpack_filter_extensible_match(
    reader: ASN1Reader,
    header: ASN1Header,
) -> FilterExtensibleMatch:
    filter_reader = reader.read_sequence(
        header=header,
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
                ).decode("utf-8")
                continue

            elif next_header.tag.tag_number == 2:
                attribute = filter_reader.read_octet_string(
                    header=next_header,
                    hint="Filter.extensibleMatch.type",
                ).decode("utf-8")
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
    reader: ASN1Reader,
    header: ASN1Header,
    name: str,
) -> t.Tuple[str, bytes]:
    filter_reader = reader.read_sequence(header=header, hint=f"Filter.{name}")

    attribute = filter_reader.read_octet_string(
        hint=f"Filter.{name}.attributeDesc",
    ).decode("utf-8")
    value = filter_reader.read_octet_string(
        hint=f"Filter.{name}.assertionValue",
    )

    return attribute, value


FILTER_UNPACKER: t.Dict[int, t.Callable[[ASN1Reader, ASN1Header], LDAPFilter]] = {
    FilterAnd.filter_id: _unpack_filter_and,
    FilterOr.filter_id: _unpack_filter_or,
    FilterNot.filter_id: _unpack_filter_not,
    FilterEquality.filter_id: _unpack_filter_equality,
    FilterSubstrings.filter_id: _unpack_filter_substrings,
    FilterGreaterOrEqual.filter_id: _unpack_filter_greater_or_equal,
    FilterLessOrEqual.filter_id: _unpack_filter_less_or_equal,
    FilterPresent.filter_id: _unpack_filter_present,
    FilterApproxMatch.filter_id: _unpack_filter_approx_match,
    FilterExtensibleMatch.filter_id: _unpack_filter_extensible_match,
}
