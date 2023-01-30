# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import typing as t

from ._asn1 import ASN1Reader, ASN1Tag, ASN1Writer, TagClass, TypeTagNumber


def unpack_ldap_control(
    reader: ASN1Reader,
) -> LDAPControl:
    """Unpack an LDAP control.

    Unpacks the raw ASN.1 value in the reader specified into an LDAP control
    object.

    Args:
        reader: The ASN.1 reader to read from.

    Returns:
        LDAPControl: The unpacked control object.
    """
    control_reader = reader.read_sequence(hint="Control")

    control_type = control_reader.read_octet_string(
        hint="Control.controlType",
    ).decode(reader.string_encoding)

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
        control_value = control_reader.read_octet_string(
            header=next_header,
            hint="Control.controlValue",
        )

    if unpack_func:
        return unpack_func(criticality, control_value)
    else:
        return LDAPControl(
            control_type=control_type,
            critical=criticality,
            value=control_value,
        )


@dataclasses.dataclass
class LDAPControl:
    """LDAP Control.

    An extended control used in an LDAPMessage. This can be sent by the client,
    known as client controls, or by the server, server controls. Each control
    is identified by an OID string that is meant to be unique and known by both
    the client and server. It can be marked as critical which means the peer
    should fail the operation if it does not know the control type specified.
    The Control structure is defined in `RFC 4511 4.1.11. Controls`_.

    An unpacked control object is guaranteed to have the control_type,
    critical, and value bytes set. Some controls are known by this library and
    will unpack to objects containing the unpacks value. For example when
    unpacking a PagedResultControl control, the ``value`` will contain the raw
    bytes but the ``size`` and ``cookie`` attributes will also be present. In
    the future more controls will be added.

    Args:
        control_type: The control OID string.
        critical: Whether the control is marked as critical or not.
        value: The raw control value, if any.

    Attributes:
        value:

    .. _RFC 4511 4.1.11. Controls:
        https://www.rfc-editor.org/rfc/rfc4511#section-4.1.11
    """

    # Control ::= SEQUENCE {
    #         controlType             LDAPOID,
    #         criticality             BOOLEAN DEFAULT FALSE,
    #         controlValue            OCTET STRING OPTIONAL
    # }

    control_type: str
    critical: bool
    value: t.Optional[bytes] = None

    def _pack_internal(
        self,
        writer: ASN1Writer,
    ) -> None:
        with writer.push_sequence() as control_writer:
            control_writer.write_octet_string(self.control_type.encode(writer.string_encoding))

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
class _KnownControl(LDAPControl):
    """Used internally to separate known controls from unknown ones."""

    control_type: str = dataclasses.field(init=False, default="")
    value: t.Optional[bytes] = dataclasses.field(init=False, default=None, repr=False)


@dataclasses.dataclass
class ShowDeletedControl(_KnownControl):
    """LDAP Show Deleted Control.

    Microsoft specific control that is used search tombstoned or deleted object
    during a search operation. This control has no value set.
    """

    control_type: str = dataclasses.field(init=False, default="1.2.840.113556.1.4.417")


@dataclasses.dataclass
class ShowDeactivatedLinkControl(_KnownControl):
    """LDAP Show Deactivated Control

    Microsoft specific control that is used to specify that link attributes
    that refer to deleted objects are visible to the search operation. This
    control has no value set.
    """

    control_type: str = dataclasses.field(init=False, default="1.2.840.113556.1.4.2065")


@dataclasses.dataclass
class PagedResultControl(_KnownControl):
    """Control for Simple Paged Results.

    An LDAP control used to perform simple paging of search results. It is sent
    by the client to control the rate at which an LDAP server returns the
    results of an LDAP search operation.

    Args:
        critical: Whether the control must be known by the server or not.
        size: The desired page size, this must be less than the size_limit set
            in a :class:`SearchRequest` message.
        cookie: An opaque set of bytes used to identify the search operation as
            denoted by the server response.

    Attributes:
        control_type: The control OID string.
        value: Only set when the control was unpacked from an incoming message.
            This is the raw control value.

    .. _RFC 2696 2. The Control:
        https://www.rfc-editor.org/rfc/rfc2696.html#section-2
    """

    control_type: str = dataclasses.field(init=False, default="1.2.840.113556.1.4.319")

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


T = t.TypeVar("T", bound=_KnownControl)


def _unpack_with_value(
    control_type: t.Type[T],
    critical: bool,
    value: t.Optional[bytes],
) -> T:
    obj = control_type(critical=critical)
    obj.value = value

    return obj


def _unpack_paged_result_control(
    critical: bool,
    value: t.Optional[bytes],
) -> PagedResultControl:
    reader = ASN1Reader(value or b"")
    control_reader = reader.read_sequence(hint="PagedResultControl")

    size = control_reader.read_integer(hint="PagedResultControl.size")
    cookie = control_reader.read_octet_string(hint="PagedResultControl.cookie")

    control = PagedResultControl(
        critical=critical,
        size=size,
        cookie=cookie,
    )

    # Kept for backwards compatibility, all unpacked object should have a value
    control.value = value
    return control


CONTROL_UNPACKER: t.Dict[str, t.Callable[[bool, t.Optional[bytes]], LDAPControl]] = {
    ShowDeletedControl.control_type: lambda c, v: _unpack_with_value(ShowDeletedControl, c, v),
    ShowDeactivatedLinkControl.control_type: lambda c, v: _unpack_with_value(ShowDeactivatedLinkControl, c, v),
    PagedResultControl.control_type: _unpack_paged_result_control,
}
