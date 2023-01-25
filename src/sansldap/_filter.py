# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import typing as t

from ._asn1 import (
    ASN1Header,
    TagClass,
    read_asn1_boolean,
    read_asn1_header,
    read_asn1_octet_string,
    read_asn1_sequence,
    read_asn1_set,
)


@dataclasses.dataclass
class LDAPFilter:
    filter_id: int

    @classmethod
    def unpack(
        cls,
        view: memoryview,
    ) -> t.Tuple[LDAPFilter, int]:
        choice = read_asn1_header(view)

        unpack_func = FILTER_UNPACKER.get(choice.tag.tag_number, None)
        if choice.tag.tag_class != TagClass.CONTEXT_SPECIFIC or not unpack_func:
            raise NotImplementedError(f"Unknown Filter object {choice.tag}")

        return unpack_func(view, choice), choice.tag_length + choice.length


@dataclasses.dataclass
class FilterAnd(LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=0)

    filters: t.List[LDAPFilter]


def _unpack_filter_and(
    view: memoryview,
    header: ASN1Header,
) -> FilterAnd:
    set_of = read_asn1_set(view, header=header, hint="Filter.and")[0]
    filters = []
    while set_of:
        filter, consumed = LDAPFilter.unpack(set_of)
        set_of = set_of[consumed:]
        filters.append(filter)

    return FilterAnd(filters=filters)


@dataclasses.dataclass
class FilterOr(LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=1)

    filters: t.List[LDAPFilter]


def _unpack_filter_or(
    view: memoryview,
    header: ASN1Header,
) -> FilterOr:
    set_of = read_asn1_set(view, header=header, hint="Filter.or")[0]
    filters = []
    while set_of:
        filter, consumed = LDAPFilter.unpack(set_of)
        set_of = set_of[consumed:]
        filters.append(filter)

    return FilterOr(filters=filters)


@dataclasses.dataclass
class FilterNot(LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=2)

    filter: LDAPFilter


def _unpack_filter_not(
    view: memoryview,
    header: ASN1Header,
) -> FilterNot:
    data = read_asn1_octet_string(view, header=header, hint="Filter.not")[0]
    not_filter = LDAPFilter.unpack(data)[0]

    return FilterNot(filter=not_filter)


@dataclasses.dataclass
class FilterEquality(LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=3)

    attribute: str
    value: bytes


def _unpack_filter_equality(
    view: memoryview,
    header: ASN1Header,
) -> FilterEquality:
    attribute, value = _unpack_filter_attribute_value_assertion(
        view,
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


def _unpack_filter_substrings(
    view: memoryview,
    header: ASN1Header,
) -> FilterSubstrings:
    view = read_asn1_sequence(view, header=header, hint="Filter.substrings")[0]

    attribute, consumed = read_asn1_octet_string(view, hint="Filter.substrings.type")
    view = view[consumed:]

    substrings = read_asn1_sequence(view, hint="Filter.substrings.substrings")[0]
    initial: t.Optional[bytes] = None
    any_values: t.List[bytes] = []
    final: t.Optional[bytes] = None
    while substrings:
        next_header = read_asn1_header(substrings)
        if next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC and next_header.tag.tag_number == 0:
            if initial is not None:
                raise ValueError("Received multiple initial values when unpacking Filter.substrings")

            initial = read_asn1_octet_string(
                substrings,
                header=next_header,
                hint="Filter.substrings.initial",
            )[0].tobytes()

        elif next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC and next_header.tag.tag_number == 1:
            value = read_asn1_octet_string(
                substrings,
                header=next_header,
                hint="Filter.substrings.any",
            )[0]
            any_values.append(value.tobytes())

        elif next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC and next_header.tag.tag_number == 2:
            if final is not None:
                raise ValueError("Received multiple final values when unpacking Filter.substrings")

            final = read_asn1_octet_string(
                substrings,
                header=next_header,
                hint="Filter.substrings.initial",
            )[0].tobytes()

        else:
            raise ValueError(
                f"Expecting Filter.substrings entry to be CONTEXT_SPECIFIC 0, 1, or 2 but got {next_header.tag}"
            )

        substrings = substrings[next_header.tag_length + next_header.length :]

    return FilterSubstrings(
        attribute=attribute.tobytes().decode("utf-8"),
        initial=initial,
        any=any_values,
        final=final,
    )


@dataclasses.dataclass
class FilterGreaterOrEqual(LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=5)

    attribute: str
    value: bytes


def _unpack_filter_greater_or_equal(
    view: memoryview,
    header: ASN1Header,
) -> FilterGreaterOrEqual:
    attribute, value = _unpack_filter_attribute_value_assertion(
        view,
        header,
        "FilterGreaterOrEqual",
    )
    return FilterGreaterOrEqual(attribute=attribute, value=value)


@dataclasses.dataclass
class FilterLessOrEqual(LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=6)

    attribute: str
    value: bytes


def _unpack_filter_less_or_equal(
    view: memoryview,
    header: ASN1Header,
) -> FilterLessOrEqual:
    attribute, value = _unpack_filter_attribute_value_assertion(
        view,
        header,
        "FilterLessOrEqual",
    )
    return FilterLessOrEqual(attribute=attribute, value=value)


@dataclasses.dataclass
class FilterPresent(LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=7)

    attribute: str


def _unpack_filter_present(
    view: memoryview,
    header: ASN1Header,
) -> FilterPresent:
    value = read_asn1_octet_string(view, header=header, hint="Filter.present")[0]

    return FilterPresent(attribute=value.tobytes().decode("utf-8"))


@dataclasses.dataclass
class FilterApproxMatch(LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=8)

    attribute: str
    value: bytes


def _unpack_filter_approx_match(
    view: memoryview,
    header: ASN1Header,
) -> FilterApproxMatch:
    attribute, value = _unpack_filter_attribute_value_assertion(
        view,
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


def _unpack_filter_extensible_match(
    view: memoryview,
    header: ASN1Header,
) -> FilterExtensibleMatch:
    view = read_asn1_sequence(view, header=header, hint="Filter.extensibleMatch")[0]

    rule: t.Optional[str] = None
    attribute: t.Optional[str] = None
    value = b""
    dn_attributes = False
    while view:
        next_header = read_asn1_header(view)

        valid = False
        if next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC:
            if next_header.tag.tag_number == 1:
                valid = True
                rule = (
                    read_asn1_octet_string(
                        view,
                        header=next_header,
                        hint="Filter.extensibleMatch.matchingRule",
                    )[0]
                    .tobytes()
                    .decode("utf-8")
                )

            elif next_header.tag.tag_number == 2:
                valid = True
                attribute = (
                    read_asn1_octet_string(
                        view,
                        header=next_header,
                        hint="Filter.extensibleMatch.type",
                    )[0]
                    .tobytes()
                    .decode("utf-8")
                )

            elif next_header.tag.tag_number == 3:
                valid = True
                value = read_asn1_octet_string(
                    view,
                    header=next_header,
                    hint="Filter.extensibleMatch.matchValue",
                )[0].tobytes()

            elif next_header.tag.tag_number == 4:
                valid = True
                dn_attributes = read_asn1_boolean(
                    view,
                    header=next_header,
                    hint="Filter.extensibleMatch.dnAttributes",
                )[0]

        if not valid:
            f"Expecting Filter.extensibleMatch entry to be CONTEXT_SPECIFIC 1, 2, 3, or 4 but got {next_header.tag}"

        view = view[next_header.tag_length + next_header.length :]

    return FilterExtensibleMatch(
        rule=rule,
        attribute=attribute,
        value=value,
        dn_attributes=dn_attributes,
    )


def _unpack_filter_attribute_value_assertion(
    view: memoryview,
    header: ASN1Header,
    name: str,
) -> t.Tuple[str, bytes]:
    view = read_asn1_sequence(view, header=header, hint=f"Filter.{name}")[0]

    attribute, consumed = read_asn1_octet_string(
        view,
        hint=f"Filter.{name}.attributeDesc",
    )
    view = view[consumed:]

    value = read_asn1_octet_string(
        view,
        hint=f"Filter.{name}.assertionValue",
    )[0]
    return attribute.tobytes().decode("utf-8"), value.tobytes()


FILTER_UNPACKER: t.Dict[int, t.Callable[[memoryview, ASN1Header], LDAPFilter]] = {
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
