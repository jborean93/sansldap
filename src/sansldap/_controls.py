# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import typing as t

from .asn1 import ASN1Header, ASN1Reader, ASN1Writer, TagClass, TypeTagNumber


def unpack_ldap_control(
    reader: ASN1Reader,
    options: ControlOptions,
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
    ).decode(options.string_encoding)

    unpack_func = next(
        (c.unpack for c in options.choices if c.control_type == control_type),
        LDAPControl.unpack,
    )
    criticality = False

    next_header: t.Optional[ASN1Header] = None
    if control_reader:
        next_header = control_reader.peek_header()

    if (
        next_header
        and next_header.tag.tag_class == TagClass.UNIVERSAL
        and next_header.tag.tag_number == TypeTagNumber.BOOLEAN
    ):
        criticality = control_reader.read_boolean(
            header=next_header,
            hint="Control.criticality",
        )
        if control_reader:
            next_header = control_reader.peek_header()

    control_value: t.Optional[bytes] = None
    if (
        next_header
        and next_header.tag.tag_class == TagClass.UNIVERSAL
        and next_header.tag.tag_number == TypeTagNumber.OCTET_STRING
    ):
        control_value = control_reader.read_octet_string(
            header=next_header,
            hint="Control.controlValue",
        )

    control = unpack_func(
        control_type=control_type,
        critical=criticality,
        value=control_value,
        options=options,
    )
    # Ensures unpacking a control always has this value
    object.__setattr__(control, "value", control_value)

    return control


@dataclasses.dataclass
class ControlOptions:
    """Options used for Control packing and unpacking.

    Custom options used for packing and unpacking control objects.

    Args:
        string_encoding: The encoding that is used to encode and decode
            strings. Defaults to utf-8.
        choices: List of known controls.
    """

    string_encoding: str = "utf-8"
    choices: t.List[t.Type[LDAPControl]] = dataclasses.field(
        default_factory=lambda: [
            PagedResultControl,
            ShowDeactivatedLinkControl,
            ShowDeletedControl,
        ]
    )


@dataclasses.dataclass(frozen=True)
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

    A custom implementation must inherit this class and provide a value for
    control_type as well as implement the ``get_value`` and ``unpack``
    methods.

    Example:
        .. code-block:: python

            @dataclasses.dataclass(frozen=True)
            class CustomControl(LDAPControl):
                control_type: str = dataclasses.field(init=False, repr=False, default="1.2.3.4")
                value: t.Optional[bytes] = dataclasses.field(init=False, repr=False, default=None)

                size: int

                def get_value(
                    self,
                    options: ControlOptions,
                ) -> t.Optional[bytes]:
                    return self.size.to_bytes(4)

                @classmethod
                def unpack(
                    cls,
                    control_type: str,
                    critical: bool,
                    value: t.Optional[bytes],
                    options: ControlOptions,
                ) -> CustomControl:
                    size = struct.unpack("<I", (value or b""))[0]

                    return CustomControl(critical=critical, size=size)

    Args:
        control_type: The control OID string.
        critical: Whether the control is marked as critical or not.
        value: The raw control value, if any.

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
    value: t.Optional[bytes]

    def pack(
        self,
        writer: ASN1Writer,
        options: ControlOptions,
    ) -> None:
        with writer.push_sequence() as control_writer:
            control_writer.write_octet_string(self.control_type.encode(options.string_encoding))

            if self.critical:
                control_writer.write_boolean(self.critical)

            value = self.get_value(options)
            if value is not None:
                control_writer.write_octet_string(value)

    def get_value(
        self,
        options: ControlOptions,
    ) -> t.Optional[bytes]:
        return self.value

    @classmethod
    def unpack(
        cls,
        control_type: str,
        critical: bool,
        value: t.Optional[bytes],
        options: ControlOptions,
    ) -> LDAPControl:
        return LDAPControl(control_type, critical, value)


@dataclasses.dataclass(frozen=True)
class _KnownControl(LDAPControl):
    """Used internally to separate known controls from unknown ones."""

    control_type: str = dataclasses.field(init=False, default="")
    value: t.Optional[bytes] = dataclasses.field(init=False, default=None, repr=False)


@dataclasses.dataclass(frozen=True)
class ShowDeletedControl(_KnownControl):
    """LDAP Show Deleted Control.

    Microsoft specific control that is used search tombstoned or deleted object
    during a search operation. This control has no value set.
    """

    control_type: str = dataclasses.field(init=False, default="1.2.840.113556.1.4.417")

    @classmethod
    def unpack(
        cls,
        control_type: str,
        critical: bool,
        value: t.Optional[bytes],
        options: ControlOptions,
    ) -> ShowDeletedControl:
        return ShowDeletedControl(critical=critical)


@dataclasses.dataclass(frozen=True)
class ShowDeactivatedLinkControl(_KnownControl):
    """LDAP Show Deactivated Control

    Microsoft specific control that is used to specify that link attributes
    that refer to deleted objects are visible to the search operation. This
    control has no value set.
    """

    control_type: str = dataclasses.field(init=False, default="1.2.840.113556.1.4.2065")

    @classmethod
    def unpack(
        cls,
        control_type: str,
        critical: bool,
        value: t.Optional[bytes],
        options: ControlOptions,
    ) -> ShowDeactivatedLinkControl:
        return ShowDeactivatedLinkControl(critical=critical)


@dataclasses.dataclass(frozen=True)
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

    .. _RFC 2696 2. The Control:
        https://www.rfc-editor.org/rfc/rfc2696.html#section-2
    """

    control_type: str = dataclasses.field(init=False, default="1.2.840.113556.1.4.319")

    size: int
    cookie: bytes

    def get_value(
        self,
        options: ControlOptions,
    ) -> t.Optional[bytes]:
        writer = ASN1Writer()
        with writer.push_sequence() as inner_writer:
            inner_writer.write_integer(self.size)
            inner_writer.write_octet_string(self.cookie)

        return bytes(writer.get_data())

    @classmethod
    def unpack(
        cls,
        control_type: str,
        critical: bool,
        value: t.Optional[bytes],
        options: ControlOptions,
    ) -> PagedResultControl:
        reader = ASN1Reader(value or b"")
        control_reader = reader.read_sequence(hint="PagedResultControl")

        size = control_reader.read_integer(hint="PagedResultControl.size")
        cookie = control_reader.read_octet_string(hint="PagedResultControl.cookie")

        return PagedResultControl(critical=critical, size=size, cookie=cookie)
