# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import base64
import dataclasses
import struct
import typing as t

import sansldap._controls as c
import sansldap._messages as m
import sansldap.asn1


@dataclasses.dataclass(frozen=True)
class CustomControl(c.LDAPControl):
    control_type: str = dataclasses.field(init=False, repr=False, default="1.2.3.4")
    value: t.Optional[bytes] = dataclasses.field(init=False, repr=False, default=None)

    size: int

    def get_value(
        self,
        options: c.ControlOptions,
    ) -> t.Optional[bytes]:
        return self.size.to_bytes(4, byteorder="big")

    @classmethod
    def unpack(
        cls,
        control_type: str,
        critical: bool,
        value: t.Optional[bytes],
        options: c.ControlOptions,
    ) -> CustomControl:
        size = struct.unpack(">I", (value or b""))[0]

        return CustomControl(critical=critical, size=size)


def test_pack_custom_control() -> None:
    expected = base64.b64decode("MBsCAQBiAKAUMBIEBzEuMi4zLjQBAf8EBAAAAAo=")
    req = m.UnbindRequest(
        message_id=0,
        controls=[CustomControl(critical=True, size=10)],
    )
    actual = req.pack(m.PackingOptions())
    assert actual == expected


def test_unpack_custom_auth() -> None:
    data = base64.b64decode("MBsCAQBiAKAUMBIEBzEuMi4zLjQBAf8EBAAAAAo=")
    reader = sansldap.asn1.ASN1Reader(data)

    actual = m.unpack_ldap_message(
        reader,
        m.PackingOptions(
            control=c.ControlOptions(
                choices=[CustomControl],
            )
        ),
    )
    assert isinstance(actual, m.UnbindRequest)
    assert len(actual.controls) == 1
    assert isinstance(actual.controls[0], CustomControl)
    assert actual.controls[0].control_type == "1.2.3.4"
    assert actual.controls[0].critical is True
    assert actual.controls[0].value == b"\x00\x00\x00\x0A"
    assert actual.controls[0].size == 10


def test_unpack_custom_auth_not_registered() -> None:
    data = base64.b64decode("MBsCAQBiAKAUMBIEBzEuMi4zLjQBAf8EBAAAAAo=")
    reader = sansldap.asn1.ASN1Reader(data)

    actual = m.unpack_ldap_message(reader, m.PackingOptions())
    assert isinstance(actual, m.UnbindRequest)
    assert len(actual.controls) == 1
    assert isinstance(actual.controls[0], c.LDAPControl)
    assert actual.controls[0].control_type == "1.2.3.4"
    assert actual.controls[0].critical is True
    assert actual.controls[0].value == b"\x00\x00\x00\x0A"


def test_pack_control_no_value() -> None:
    expected = base64.b64decode("MBUCAQBiAKAOMAwEBzEuMi4zLjQBAf8=")
    req = m.UnbindRequest(
        message_id=0,
        controls=[c.LDAPControl(control_type="1.2.3.4", critical=True, value=None)],
    )
    actual = req.pack(m.PackingOptions())
    assert actual == expected


def test_unpack_control_no_value() -> None:
    data = base64.b64decode("MBUCAQBiAKAOMAwEBzEuMi4zLjQBAf8=")
    reader = sansldap.asn1.ASN1Reader(data)

    actual = m.unpack_ldap_message(reader, m.PackingOptions())
    assert isinstance(actual, m.UnbindRequest)
    assert len(actual.controls) == 1
    assert isinstance(actual.controls[0], c.LDAPControl)
    assert actual.controls[0].control_type == "1.2.3.4"
    assert actual.controls[0].critical is True
    assert actual.controls[0].value is None


def test_pack_control_not_critical_no_value() -> None:
    expected = base64.b64decode("MBICAQBiAKALMAkEBzEuMi4zLjQ=")
    req = m.UnbindRequest(
        message_id=0,
        controls=[c.LDAPControl(control_type="1.2.3.4", critical=False, value=None)],
    )
    actual = req.pack(m.PackingOptions())
    assert actual == expected


def test_unpack_control_not_critical_no_value() -> None:
    data = base64.b64decode("MBICAQBiAKALMAkEBzEuMi4zLjQ=")
    reader = sansldap.asn1.ASN1Reader(data)

    actual = m.unpack_ldap_message(reader, m.PackingOptions())
    assert isinstance(actual, m.UnbindRequest)
    assert len(actual.controls) == 1
    assert isinstance(actual.controls[0], c.LDAPControl)
    assert actual.controls[0].control_type == "1.2.3.4"
    assert actual.controls[0].critical is False
    assert actual.controls[0].value is None


def test_pack_control_critical_empty_value() -> None:
    expected = base64.b64decode("MBcCAQBiAKAQMA4EBzEuMi4zLjQBAf8EAA==")
    req = m.UnbindRequest(
        message_id=0,
        controls=[c.LDAPControl(control_type="1.2.3.4", critical=True, value=b"")],
    )
    actual = req.pack(m.PackingOptions())
    assert actual == expected


def test_unpack_control_critical_empty_value() -> None:
    data = base64.b64decode("MBcCAQBiAKAQMA4EBzEuMi4zLjQBAf8EAA==")
    reader = sansldap.asn1.ASN1Reader(data)

    actual = m.unpack_ldap_message(reader, m.PackingOptions())
    assert isinstance(actual, m.UnbindRequest)
    assert len(actual.controls) == 1
    assert isinstance(actual.controls[0], c.LDAPControl)
    assert actual.controls[0].control_type == "1.2.3.4"
    assert actual.controls[0].critical is True
    assert actual.controls[0].value == b""


def test_pack_control_not_critical_empty_value() -> None:
    expected = base64.b64decode("MBQCAQBiAKANMAsEBzEuMi4zLjQEAA==")
    req = m.UnbindRequest(
        message_id=0,
        controls=[c.LDAPControl(control_type="1.2.3.4", critical=False, value=b"")],
    )
    actual = req.pack(m.PackingOptions())
    assert actual == expected


def test_unpack_control_not_critical_empty_value() -> None:
    data = base64.b64decode("MBQCAQBiAKANMAsEBzEuMi4zLjQEAA==")
    reader = sansldap.asn1.ASN1Reader(data)

    actual = m.unpack_ldap_message(reader, m.PackingOptions())
    assert isinstance(actual, m.UnbindRequest)
    assert len(actual.controls) == 1
    assert isinstance(actual.controls[0], c.LDAPControl)
    assert actual.controls[0].control_type == "1.2.3.4"
    assert actual.controls[0].critical is False
    assert actual.controls[0].value == b""


def test_pack_control_critical_value() -> None:
    expected = base64.b64decode("MBgCAQBiAKARMA8EBzEuMi4zLjQBAf8EAQA=")
    req = m.UnbindRequest(
        message_id=0,
        controls=[c.LDAPControl(control_type="1.2.3.4", critical=True, value=b"\x00")],
    )
    actual = req.pack(m.PackingOptions())
    assert actual == expected


def test_unpack_control_critical_value() -> None:
    data = base64.b64decode("MBgCAQBiAKARMA8EBzEuMi4zLjQBAf8EAQA=")
    reader = sansldap.asn1.ASN1Reader(data)

    actual = m.unpack_ldap_message(reader, m.PackingOptions())
    assert isinstance(actual, m.UnbindRequest)
    assert len(actual.controls) == 1
    assert isinstance(actual.controls[0], c.LDAPControl)
    assert actual.controls[0].control_type == "1.2.3.4"
    assert actual.controls[0].critical is True
    assert actual.controls[0].value == b"\x00"


def test_pack_control_not_critical_value() -> None:
    expected = base64.b64decode("MBUCAQBiAKAOMAwEBzEuMi4zLjQEAQA=")
    req = m.UnbindRequest(
        message_id=0,
        controls=[c.LDAPControl(control_type="1.2.3.4", critical=False, value=b"\x00")],
    )
    actual = req.pack(m.PackingOptions())
    assert actual == expected


def test_unpack_control_not_critical_value() -> None:
    data = base64.b64decode("MBUCAQBiAKAOMAwEBzEuMi4zLjQEAQA=")
    reader = sansldap.asn1.ASN1Reader(data)

    actual = m.unpack_ldap_message(reader, m.PackingOptions())
    assert isinstance(actual, m.UnbindRequest)
    assert len(actual.controls) == 1
    assert isinstance(actual.controls[0], c.LDAPControl)
    assert actual.controls[0].control_type == "1.2.3.4"
    assert actual.controls[0].critical is False
    assert actual.controls[0].value == b"\x00"


def test_pack_show_deleted_control() -> None:
    expected = base64.b64decode("MCECAQBiAKAaMBgEFjEuMi44NDAuMTEzNTU2LjEuNC40MTc=")
    req = m.UnbindRequest(
        message_id=0,
        controls=[c.ShowDeletedControl(critical=False)],
    )
    actual = req.pack(m.PackingOptions())
    assert actual == expected


def test_unpack_show_deleted_control() -> None:
    data = base64.b64decode("MCECAQBiAKAaMBgEFjEuMi44NDAuMTEzNTU2LjEuNC40MTc=")
    reader = sansldap.asn1.ASN1Reader(data)

    actual = m.unpack_ldap_message(
        reader,
        m.PackingOptions(
            control=c.ControlOptions(
                choices=[c.ShowDeletedControl],
            )
        ),
    )
    assert isinstance(actual, m.UnbindRequest)
    assert len(actual.controls) == 1
    assert isinstance(actual.controls[0], c.ShowDeletedControl)
    assert actual.controls[0].control_type == "1.2.840.113556.1.4.417"
    assert actual.controls[0].critical is False
    assert actual.controls[0].value is None


def test_pack_show_deactivated_line_control() -> None:
    expected = base64.b64decode("MCICAQBiAKAbMBkEFzEuMi44NDAuMTEzNTU2LjEuNC4yMDY1")
    req = m.UnbindRequest(
        message_id=0,
        controls=[c.ShowDeactivatedLinkControl(critical=False)],
    )
    actual = req.pack(m.PackingOptions())
    assert actual == expected


def test_unpack_show_deactivated_line_control() -> None:
    data = base64.b64decode("MCICAQBiAKAbMBkEFzEuMi44NDAuMTEzNTU2LjEuNC4yMDY1")
    reader = sansldap.asn1.ASN1Reader(data)

    actual = m.unpack_ldap_message(
        reader,
        m.PackingOptions(
            control=c.ControlOptions(
                choices=[c.ShowDeactivatedLinkControl],
            )
        ),
    )
    assert isinstance(actual, m.UnbindRequest)
    assert len(actual.controls) == 1
    assert isinstance(actual.controls[0], c.ShowDeactivatedLinkControl)
    assert actual.controls[0].control_type == "1.2.840.113556.1.4.2065"
    assert actual.controls[0].critical is False
    assert actual.controls[0].value is None
