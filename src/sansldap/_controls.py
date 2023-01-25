# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import typing as t

from ._asn1 import (
    TagClass,
    TypeTagNumber,
    read_asn1_boolean,
    read_asn1_header,
    read_asn1_integer,
    read_asn1_octet_string,
    read_asn1_sequence,
)


@dataclasses.dataclass
class LDAPControl:
    """LDAP Control.

    Control ::= SEQUENCE {
            controlType             LDAPOID,
            criticality             BOOLEAN DEFAULT FALSE,
            controlValue            OCTET STRING OPTIONAL
    }
    """

    control_type: str
    critical: bool
    value: t.Optional[bytes]

    @classmethod
    def unpack(
        cls,
        view: memoryview,
    ) -> t.Tuple[LDAPControl, int]:
        control_view, consumed = read_asn1_sequence(
            view,
            hint="Control",
        )

        raw_control_type, seq_consumed = read_asn1_octet_string(control_view, hint="Control.controlType")
        control_type = raw_control_type.tobytes().decode("utf-8")
        control_view = control_view[seq_consumed:]

        criticality = False
        control_value = memoryview(b"")

        while control_view:
            # As these fields are optional we scan the header to see what the
            # next value is.
            next_header = read_asn1_header(control_view)

            if next_header.tag.tag_class == TagClass.UNIVERSAL:
                if next_header.tag.tag_number == TypeTagNumber.BOOLEAN:
                    criticality = read_asn1_boolean(
                        control_view,
                        header=next_header,
                        hint="Control.criticality",
                    )[0]

                if next_header.tag.tag_number == TypeTagNumber.OCTET_STRING:
                    control_value = read_asn1_octet_string(
                        control_view,
                        header=next_header,
                        hint="Control.controlValue",
                    )[0]

            control_view = control_view[next_header.tag_length + next_header.length :]

        unpack_func = CONTROL_UNPACKER.get(control_type, None)
        if unpack_func:
            return unpack_func(criticality, control_value), consumed

        else:
            return (
                LDAPControl(
                    control_type=control_type,
                    critical=criticality,
                    value=control_value.tobytes() if control_value else None,
                ),
                consumed,
            )


@dataclasses.dataclass
class ShowDeletedControl(LDAPControl):
    control_type: str = dataclasses.field(init=False, default="1.2.840.113556.1.4.417")
    value: t.Optional[bytes] = dataclasses.field(init=False, default=None, repr=False)


@dataclasses.dataclass
class ShowDeactivatedLinkControl(LDAPControl):
    control_type: str = dataclasses.field(init=False, default="1.2.840.113556.1.4.2065")
    value: t.Optional[bytes] = dataclasses.field(init=False, default=None, repr=False)


@dataclasses.dataclass
class PagedResultControl(LDAPControl):
    control_type: str = dataclasses.field(init=False, default="1.2.840.113556.1.4.319")
    value: t.Optional[bytes] = dataclasses.field(init=False, default=None, repr=False)

    size: int
    cookie: bytes


def _unpack_paged_result_control(
    critical: bool,
    view: memoryview,
) -> PagedResultControl:
    view = read_asn1_sequence(view, hint="PagedResultControl")[0]

    size, consumed = read_asn1_integer(view, hint="PagedResultControl.size")
    view = view[consumed:]

    cookie = read_asn1_octet_string(view, hint="PagedResultControl.cookie")[0].tobytes()

    return PagedResultControl(
        critical=critical,
        size=size,
        cookie=cookie,
    )


CONTROL_UNPACKER: t.Dict[str, t.Callable[[bool, memoryview], LDAPControl]] = {
    ShowDeletedControl.control_type: lambda c, v: ShowDeletedControl(critical=c),
    ShowDeactivatedLinkControl.control_type: lambda c, v: ShowDeactivatedLinkControl(critical=c),
    PagedResultControl.control_type: _unpack_paged_result_control,
}
