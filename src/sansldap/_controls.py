# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import typing as t

from ._asn1 import ASN1Reader, ASN1Tag, ASN1Writer, TagClass, TypeTagNumber


def unpack_ldap_control(
    reader: ASN1Reader,
) -> LDAPControl:
    control_reader = reader.read_sequence(hint="Control")

    control_type = control_reader.read_octet_string(
        hint="Control.controlType",
    ).decode("utf-8")

    unpack_func = CONTROL_UNPACKER.get(control_type, None)
    criticality = False

    next_header = control_reader.peek_header()
    if next_header.tag.tag_class == TagClass.UNIVERSAL and next_header.tag.tag_number == TypeTagNumber.BOOLEAN:
        criticality = control_reader.read_boolean(
            header=next_header,
            hint="Control.criticality",
        )
        next_header = control_reader.peek_header()

    control_value: t.Optional[bytes] = None
    if next_header.tag.tag_class == TagClass.UNIVERSAL and next_header.tag.tag_number == TypeTagNumber.OCTET_STRING:
        if unpack_func:
            value_reader = control_reader.read_sequence(
                header=next_header,
                hint="Control.controlValue",
            )

            return unpack_func(value_reader, criticality)

        else:
            control_value = control_reader.read_octet_string(
                header=next_header,
                hint="Control.controlValue",
            )

    return LDAPControl(
        control_type=control_type,
        critical=criticality,
        value=control_value,
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

    def _pack_internal(
        self,
        writer: ASN1Writer,
    ) -> None:
        with writer.push_sequence() as control_writer:
            control_writer.write_octet_string(self.control_type.encode("utf-8"))

            if self.critical:
                control_writer.write_boolean(self.critical)

            self._write_value(control_writer)

    def _write_value(
        self,
        writer: ASN1Writer,
    ) -> None:
        if self.value is not None:
            writer.write_octet_string(self.value)


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

    def _write_value(
        self,
        writer: ASN1Writer,
    ) -> None:
        # Write it like a sequence but with an OCTET_STRING tag
        with writer.push_sequence(
            ASN1Tag.universal_tag(TypeTagNumber.OCTET_STRING, False),
        ) as value_writer:
            with value_writer.push_sequence() as inner_writer:
                inner_writer.write_integer(self.size)
                inner_writer.write_octet_string(self.cookie)


def _unpack_paged_result_control(
    reader: ASN1Reader,
    critical: bool,
) -> PagedResultControl:
    control_reader = reader.read_sequence(hint="PagedResultControl")

    size = control_reader.read_integer(hint="PagedResultControl.size")
    cookie = control_reader.read_octet_string(hint="PagedResultControl.cookie")

    return PagedResultControl(
        critical=critical,
        size=size,
        cookie=cookie,
    )


CONTROL_UNPACKER: t.Dict[str, t.Callable[[ASN1Reader, bool], LDAPControl]] = {
    ShowDeletedControl.control_type: lambda r, c: ShowDeletedControl(critical=c),
    ShowDeactivatedLinkControl.control_type: lambda r, c: ShowDeactivatedLinkControl(critical=c),
    PagedResultControl.control_type: _unpack_paged_result_control,
}
