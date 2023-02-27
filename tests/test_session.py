# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import struct
import typing as t

import pytest

import sansldap


@dataclasses.dataclass(frozen=True)
class CustomAuth(sansldap.AuthenticationCredential):
    auth_id: int = dataclasses.field(init=False, repr=False, default=1024)

    username: str
    password: str

    def pack(
        self,
        writer: sansldap.asn1.ASN1Writer,
        options: sansldap.AuthenticationOptions,
    ) -> None:
        writer.write_octet_string(
            f"{self.username}:{self.password}".encode(options.string_encoding),
            tag=sansldap.asn1.ASN1Tag(
                sansldap.asn1.TagClass.CONTEXT_SPECIFIC,
                self.auth_id,
                False,
            ),
        )

    @classmethod
    def unpack(
        cls,
        reader: sansldap.asn1.ASN1Reader,
        options: sansldap.AuthenticationOptions,
    ) -> CustomAuth:
        value = reader.read_octet_string(
            tag=sansldap.asn1.ASN1Tag(
                sansldap.asn1.TagClass.CONTEXT_SPECIFIC,
                cls.auth_id,
                False,
            ),
            hint="CustomAuth.value",
        ).decode(options.string_encoding)
        username, _, password = value.partition(":")

        return CustomAuth(username=username, password=password)


@dataclasses.dataclass(frozen=True)
class CustomControl(sansldap.LDAPControl):
    control_type: str = dataclasses.field(init=False, repr=False, default="1.2.3.4")
    value: t.Optional[bytes] = dataclasses.field(init=False, repr=False, default=None)

    size: int

    def get_value(
        self,
        options: sansldap.ControlOptions,
    ) -> t.Optional[bytes]:
        return self.size.to_bytes(4, byteorder="big")

    @classmethod
    def unpack(
        cls,
        control_type: str,
        critical: bool,
        value: t.Optional[bytes],
        options: sansldap.ControlOptions,
    ) -> CustomControl:
        size = struct.unpack(">I", (value or b""))[0]

        return CustomControl(critical=critical, size=size)


@dataclasses.dataclass(frozen=True)
class CustomFilter(sansldap.LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=1024)

    value: str

    def pack(
        self,
        writer: sansldap.asn1.ASN1Writer,
        options: sansldap.FilterOptions,
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
        options: sansldap.FilterOptions,
    ) -> CustomFilter:
        value = reader.read_octet_string(
            sansldap.asn1.ASN1Tag(
                sansldap.asn1.TagClass.CONTEXT_SPECIFIC,
                cls.filter_id,
                False,
            ),
        ).decode(options.string_encoding)
        return CustomFilter(value=value)


def test_bind_simple() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msg_id = c.bind_simple("username", "password")
    assert msg_id == 1

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msgs = s.receive(c.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.BindRequest)
    assert msgs[0].message_id == msg_id
    assert msgs[0].controls == []
    assert msgs[0].version == 3
    assert msgs[0].name == "username"
    assert isinstance(msgs[0].authentication, sansldap.SimpleCredential)
    assert msgs[0].authentication.password == "password"

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.BINDING

    msg_id = s.bind_response(
        msgs[0].message_id,
        result_code=sansldap.LDAPResultCode.SUCCESS,
    )
    assert msg_id == 1

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.OPENED

    msgs = c.receive(s.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.BindResponse)
    assert msgs[0].message_id == 1
    assert msgs[0].controls == []
    assert msgs[0].result.result_code == sansldap.LDAPResultCode.SUCCESS
    assert msgs[0].result.diagnostics_message == ""
    assert msgs[0].result.matched_dn == ""
    assert msgs[0].result.referrals == []
    assert msgs[0].server_sasl_creds is None

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED


def test_bind_simple_failure() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msg_id = c.bind_simple("username", "password")
    assert msg_id == 1

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msgs = s.receive(c.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.BindRequest)
    assert msgs[0].message_id == msg_id
    assert msgs[0].controls == []
    assert msgs[0].version == 3
    assert msgs[0].name == "username"
    assert isinstance(msgs[0].authentication, sansldap.SimpleCredential)
    assert msgs[0].authentication.password == "password"

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.BINDING

    msg_id = s.bind_response(
        msgs[0].message_id,
        result_code=sansldap.LDAPResultCode.INVALID_CREDENTIALS,
        diagnostics_message="Invalid credential",
    )
    assert msg_id == 1

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.OPENED

    msgs = c.receive(s.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.BindResponse)
    assert msgs[0].message_id == 1
    assert msgs[0].controls == []
    assert msgs[0].result.result_code == sansldap.LDAPResultCode.INVALID_CREDENTIALS
    assert msgs[0].result.diagnostics_message == "Invalid credential"
    assert msgs[0].result.matched_dn == ""
    assert msgs[0].result.referrals == []
    assert msgs[0].server_sasl_creds is None

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED


def test_bind_sasl() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msg_id = c.bind_sasl("SASL-MECH", "dn", cred=b"\x00\x01\x02\x03")
    assert msg_id == 1

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msgs = s.receive(c.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.BindRequest)
    assert msgs[0].message_id == msg_id
    assert msgs[0].controls == []
    assert msgs[0].version == 3
    assert msgs[0].name == "dn"
    assert isinstance(msgs[0].authentication, sansldap.SaslCredential)
    assert msgs[0].authentication.mechanism == "SASL-MECH"
    assert msgs[0].authentication.credentials == b"\x00\x01\x02\x03"

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.BINDING

    msg_id = s.bind_response(
        msgs[0].message_id,
        result_code=sansldap.LDAPResultCode.SUCCESS,
    )
    assert msg_id == 1

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.OPENED

    msgs = c.receive(s.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.BindResponse)
    assert msgs[0].message_id == 1
    assert msgs[0].controls == []
    assert msgs[0].result.result_code == sansldap.LDAPResultCode.SUCCESS
    assert msgs[0].result.diagnostics_message == ""
    assert msgs[0].result.matched_dn == ""
    assert msgs[0].result.referrals == []
    assert msgs[0].server_sasl_creds is None

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED


def test_bind_sasl_multistep() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msg_id = c.bind_sasl("SASL-MECH", "dn", cred=b"\x00\x01\x02\x03")
    assert msg_id == 1

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msgs = s.receive(c.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.BindRequest)
    assert msgs[0].message_id == msg_id
    assert msgs[0].controls == []
    assert msgs[0].version == 3
    assert msgs[0].name == "dn"
    assert isinstance(msgs[0].authentication, sansldap.SaslCredential)
    assert msgs[0].authentication.mechanism == "SASL-MECH"
    assert msgs[0].authentication.credentials == b"\x00\x01\x02\x03"

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.BINDING

    msg_id = s.bind_response(
        msgs[0].message_id,
        result_code=sansldap.LDAPResultCode.SASL_BIND_IN_PROGRESS,
        sasl_creds=b"\x04\x05\x06\x07",
    )
    assert msg_id == 1

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.BINDING

    msgs = c.receive(s.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.BindResponse)
    assert msgs[0].message_id == msg_id
    assert msgs[0].controls == []
    assert msgs[0].result.result_code == sansldap.LDAPResultCode.SASL_BIND_IN_PROGRESS
    assert msgs[0].result.diagnostics_message == ""
    assert msgs[0].result.matched_dn == ""
    assert msgs[0].result.referrals == []
    assert msgs[0].server_sasl_creds == b"\x04\x05\x06\x07"

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.BINDING

    msg_id = c.bind_sasl("SASL-MECH", "dn", cred=b"\x08\x09\x0A\x0B")
    assert msg_id == 2

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.BINDING

    msgs = s.receive(c.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.BindRequest)
    assert msgs[0].message_id == msg_id
    assert msgs[0].controls == []
    assert msgs[0].version == 3
    assert msgs[0].name == "dn"
    assert isinstance(msgs[0].authentication, sansldap.SaslCredential)
    assert msgs[0].authentication.mechanism == "SASL-MECH"
    assert msgs[0].authentication.credentials == b"\x08\x09\x0A\x0B"

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.BINDING

    msg_id = s.bind_response(
        msgs[0].message_id,
        result_code=sansldap.LDAPResultCode.SUCCESS,
    )
    assert msg_id == 2

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.OPENED

    msgs = c.receive(s.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.BindResponse)
    assert msgs[0].message_id == msg_id
    assert msgs[0].controls == []
    assert msgs[0].result.result_code == sansldap.LDAPResultCode.SUCCESS
    assert msgs[0].result.diagnostics_message == ""
    assert msgs[0].result.matched_dn == ""
    assert msgs[0].result.referrals == []
    assert msgs[0].server_sasl_creds is None

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED


def test_bind_custom() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()
    s.register_auth_credential(CustomAuth)

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msg_id = c.bind("dn", CustomAuth("username", "password"))
    assert msg_id == 1

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msgs = s.receive(c.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.BindRequest)
    assert msgs[0].message_id == msg_id
    assert msgs[0].controls == []
    assert msgs[0].version == 3
    assert msgs[0].name == "dn"
    assert isinstance(msgs[0].authentication, CustomAuth)
    assert msgs[0].authentication.username == "username"
    assert msgs[0].authentication.password == "password"

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.BINDING

    msg_id = s.bind_response(
        msgs[0].message_id,
        result_code=sansldap.LDAPResultCode.SUCCESS,
    )
    assert msg_id == 1

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.OPENED

    msgs = c.receive(s.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.BindResponse)
    assert msgs[0].message_id == msg_id
    assert msgs[0].controls == []
    assert msgs[0].result.result_code == sansldap.LDAPResultCode.SUCCESS
    assert msgs[0].result.diagnostics_message == ""
    assert msgs[0].result.matched_dn == ""
    assert msgs[0].result.referrals == []
    assert msgs[0].server_sasl_creds is None

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED


def test_bind_custom_not_registered() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    c.bind("dn", CustomAuth("username", "password"))

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    with pytest.raises(
        sansldap.ProtocolError,
        match="Received invalid data from the peer, connection closing.*Unknown authentication object",
    ) as exc:
        s.receive(c.data_to_send())

    assert exc.value.response is not None

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.CLOSED

    with pytest.raises(
        sansldap.ProtocolError,
        match="Peer has sent a NoticeOfDisconnect response",
    ) as client_exc:
        c.receive(exc.value.response)

    assert c.state == sansldap.SessionState.CLOSED
    assert s.state == sansldap.SessionState.CLOSED
    assert client_exc.value.response is None


def test_unbind_from_client() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    c.bind_simple()
    s.receive(c.data_to_send())
    s.bind_response(1)
    c.receive(s.data_to_send())

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED

    c.unbind()

    assert c.state == sansldap.SessionState.CLOSED
    assert s.state == sansldap.SessionState.OPENED

    with pytest.raises(sansldap.ProtocolError, match="Received unbind request") as exc:
        s.receive(c.data_to_send())

    assert exc.value.response is None
    assert c.state == sansldap.SessionState.CLOSED
    assert s.state == sansldap.SessionState.CLOSED

    # Verify no more messages can be sent or received
    with pytest.raises(sansldap.LDAPError, match="LDAP session is CLOSED"):
        c.unbind()

    with pytest.raises(sansldap.ProtocolError, match="Cannot receive more data on a closed LDAP session"):
        c.receive(b"")

    with pytest.raises(sansldap.LDAPError, match="LDAP session is CLOSED"):
        s.unbind()

    with pytest.raises(sansldap.ProtocolError, match="Cannot receive more data on a closed LDAP session"):
        s.receive(b"")


def test_fail_another_op_during_bind() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    c.bind_simple()
    s.receive(c.data_to_send())

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.BINDING

    with pytest.raises(sansldap.LDAPError, match="LDAP session is BINDING"):
        c.extended_request("name")

    with pytest.raises(sansldap.LDAPError, match="LDAP session is BINDING"):
        s.extended_response(10)


def test_unbind_during_bind() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    c.bind_simple()
    s.receive(c.data_to_send())

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.BINDING

    c.unbind()
    s.unbind()

    assert c.state == sansldap.SessionState.CLOSED
    assert s.state == sansldap.SessionState.CLOSED


def test_extended_request() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msg_id = c.extended_request("name", b"value")
    assert msg_id == 1

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msgs = s.receive(c.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.ExtendedRequest)
    assert msgs[0].message_id == msg_id
    assert msgs[0].controls == []
    assert msgs[0].name == "name"
    assert msgs[0].value == b"value"

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED

    msg_id = s.extended_response(msgs[0].message_id, name="name", value=b"value")
    assert msg_id == 1

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED

    msgs = c.receive(s.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.ExtendedResponse)
    assert msgs[0].message_id == msg_id
    assert msgs[0].controls == []
    assert msgs[0].result.result_code == sansldap.LDAPResultCode.SUCCESS
    assert msgs[0].result.diagnostics_message == ""
    assert msgs[0].result.matched_dn == ""
    assert msgs[0].result.referrals == []
    assert msgs[0].name == "name"
    assert msgs[0].value == b"value"

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED


def test_request_with_control() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msg_id = c.extended_request(
        "name",
        b"value",
        controls=[sansldap.ShowDeletedControl(critical=True)],
    )
    assert msg_id == 1

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msgs = s.receive(c.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.ExtendedRequest)
    assert msgs[0].message_id == msg_id
    assert len(msgs[0].controls) == 1
    assert isinstance(msgs[0].controls[0], sansldap.ShowDeletedControl)
    assert msgs[0].controls[0].critical is True
    assert msgs[0].name == "name"
    assert msgs[0].value == b"value"

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED

    msg_id = s.extended_response(
        msgs[0].message_id,
        name="name",
        value=b"value",
        controls=[sansldap.ShowDeletedControl(critical=False)],
    )
    assert msg_id == 1

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED

    msgs = c.receive(s.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.ExtendedResponse)
    assert msgs[0].message_id == msg_id
    assert len(msgs[0].controls) == 1
    assert isinstance(msgs[0].controls[0], sansldap.ShowDeletedControl)
    assert msgs[0].controls[0].critical is False
    assert msgs[0].result.result_code == sansldap.LDAPResultCode.SUCCESS
    assert msgs[0].result.diagnostics_message == ""
    assert msgs[0].result.matched_dn == ""
    assert msgs[0].result.referrals == []
    assert msgs[0].name == "name"
    assert msgs[0].value == b"value"

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED


def test_request_with_custom_control() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()
    c.register_control(CustomControl)
    s.register_control(CustomControl)

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msg_id = c.extended_request(
        "name",
        b"value",
        controls=[CustomControl(True, 10)],
    )
    assert msg_id == 1

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msgs = s.receive(c.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.ExtendedRequest)
    assert msgs[0].message_id == msg_id
    assert len(msgs[0].controls) == 1
    assert isinstance(msgs[0].controls[0], CustomControl)
    assert msgs[0].controls[0].control_type == CustomControl.control_type
    assert msgs[0].controls[0].critical is True
    assert msgs[0].controls[0].size == 10
    assert msgs[0].controls[0].value == b"\x00\x00\x00\x0A"
    assert msgs[0].name == "name"
    assert msgs[0].value == b"value"

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED

    msg_id = s.extended_response(
        msgs[0].message_id,
        name="name",
        value=b"value",
        controls=[CustomControl(False, 4)],
    )
    assert msg_id == 1

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED

    msgs = c.receive(s.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.ExtendedResponse)
    assert msgs[0].message_id == msg_id
    assert len(msgs[0].controls) == 1
    assert isinstance(msgs[0].controls[0], CustomControl)
    assert msgs[0].controls[0].control_type == CustomControl.control_type
    assert msgs[0].controls[0].critical is False
    assert msgs[0].controls[0].size == 4
    assert msgs[0].controls[0].value == b"\x00\x00\x00\x04"
    assert msgs[0].result.result_code == sansldap.LDAPResultCode.SUCCESS
    assert msgs[0].result.diagnostics_message == ""
    assert msgs[0].result.matched_dn == ""
    assert msgs[0].result.referrals == []
    assert msgs[0].name == "name"
    assert msgs[0].value == b"value"

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED


def test_request_with_custom_control_unregistered() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msg_id = c.extended_request(
        "name",
        b"value",
        controls=[CustomControl(True, 10)],
    )
    assert msg_id == 1

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msgs = s.receive(c.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.ExtendedRequest)
    assert msgs[0].message_id == msg_id
    assert len(msgs[0].controls) == 1
    assert isinstance(msgs[0].controls[0], sansldap.LDAPControl)
    assert msgs[0].controls[0].control_type == CustomControl.control_type
    assert msgs[0].controls[0].critical is True
    assert msgs[0].controls[0].value == b"\x00\x00\x00\x0A"
    assert msgs[0].name == "name"
    assert msgs[0].value == b"value"

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED

    msg_id = s.extended_response(
        msgs[0].message_id,
        name="name",
        value=b"value",
        controls=[CustomControl(False, 4)],
    )
    assert msg_id == 1

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED

    msgs = c.receive(s.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.ExtendedResponse)
    assert msgs[0].message_id == msg_id
    assert len(msgs[0].controls) == 1
    assert isinstance(msgs[0].controls[0], sansldap.LDAPControl)
    assert msgs[0].controls[0].control_type == CustomControl.control_type
    assert msgs[0].controls[0].critical is False
    assert msgs[0].controls[0].value == b"\x00\x00\x00\x04"
    assert msgs[0].result.result_code == sansldap.LDAPResultCode.SUCCESS
    assert msgs[0].result.diagnostics_message == ""
    assert msgs[0].result.matched_dn == ""
    assert msgs[0].result.referrals == []
    assert msgs[0].name == "name"
    assert msgs[0].value == b"value"

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED


def test_multiple_requests_concurrently() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msg_id = c.extended_request("name", b"value")
    assert msg_id == 1

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msg_id = c.extended_request("req 2")
    assert msg_id == 2

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msgs = s.receive(c.data_to_send())
    assert len(msgs) == 2
    assert isinstance(msgs[0], sansldap.ExtendedRequest)
    assert msgs[0].message_id == 1
    assert msgs[0].controls == []
    assert msgs[0].name == "name"
    assert msgs[0].value == b"value"
    assert isinstance(msgs[1], sansldap.ExtendedRequest)
    assert msgs[1].message_id == 2
    assert msgs[1].controls == []
    assert msgs[1].name == "req 2"
    assert msgs[1].value is None

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED

    msg_id = s.extended_response(1, name="name", value=b"value")
    assert msg_id == 1

    msg_id = s.extended_response(2, name="req 2")
    assert msg_id == 2

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED

    msgs = c.receive(s.data_to_send())
    assert len(msgs) == 2
    assert isinstance(msgs[0], sansldap.ExtendedResponse)
    assert msgs[0].message_id == 1
    assert msgs[0].controls == []
    assert msgs[0].result.result_code == sansldap.LDAPResultCode.SUCCESS
    assert msgs[0].result.diagnostics_message == ""
    assert msgs[0].result.matched_dn == ""
    assert msgs[0].result.referrals == []
    assert msgs[0].name == "name"
    assert msgs[0].value == b"value"

    assert isinstance(msgs[1], sansldap.ExtendedResponse)
    assert msgs[1].message_id == 2
    assert msgs[1].controls == []
    assert msgs[1].result.result_code == sansldap.LDAPResultCode.SUCCESS
    assert msgs[1].result.diagnostics_message == ""
    assert msgs[1].result.matched_dn == ""
    assert msgs[1].result.referrals == []
    assert msgs[1].name == "req 2"
    assert msgs[1].value is None

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED


def test_receive_partial() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msg_id = c.extended_request("name", b"value")
    assert msg_id == 1

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msgs = s.receive(c.data_to_send(4))
    assert msgs == []

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msgs = s.receive(c.data_to_send(2))
    assert msgs == []

    msgs = s.receive(c.data_to_send(1024))
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.ExtendedRequest)
    assert msgs[0].message_id == msg_id
    assert msgs[0].controls == []
    assert msgs[0].name == "name"
    assert msgs[0].value == b"value"

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED

    msg_id = s.extended_response(msgs[0].message_id, name="name", value=b"value")
    assert msg_id == 1

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED

    msgs = c.receive(s.data_to_send(4))
    assert msgs == []

    msgs = c.receive(s.data_to_send(2))
    assert msgs == []

    msgs = c.receive(s.data_to_send(1024))
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.ExtendedResponse)
    assert msgs[0].message_id == msg_id
    assert msgs[0].controls == []
    assert msgs[0].result.result_code == sansldap.LDAPResultCode.SUCCESS
    assert msgs[0].result.diagnostics_message == ""
    assert msgs[0].result.matched_dn == ""
    assert msgs[0].result.referrals == []
    assert msgs[0].name == "name"
    assert msgs[0].value == b"value"

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED


def test_search_request() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msg_id = c.search_request()
    assert msg_id == 1

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msgs = s.receive(c.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.SearchRequest)
    assert msgs[0].message_id == msg_id
    assert msgs[0].controls == []
    assert msgs[0].base_object == ""
    assert msgs[0].scope == sansldap.SearchScope.SUBTREE
    assert msgs[0].deref_aliases == sansldap.DereferencingPolicy.NEVER
    assert msgs[0].size_limit == 0
    assert msgs[0].time_limit == 0
    assert msgs[0].types_only is False
    assert isinstance(msgs[0].filter, sansldap.FilterPresent)
    assert msgs[0].filter.attribute == "objectClass"
    assert msgs[0].attributes == []

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED

    msg_id = s.search_result_entry(1, "dn", [])
    assert msg_id == 1

    msg_id = s.search_result_reference(1, ["uri 1", "uri 2"])
    assert msg_id == 1

    msg_id = s.search_result_entry(
        1,
        "dn 2",
        [
            sansldap.PartialAttribute("attr 1", [b"value 1", b"value 2"]),
            sansldap.PartialAttribute("attr 2", []),
            sansldap.PartialAttribute("attr 3", [b"\x00"]),
        ],
    )
    assert msg_id == 1

    msg_id = s.search_result_done(1)
    assert msg_id == 1

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED

    msgs = c.receive(s.data_to_send())
    assert len(msgs) == 4
    assert isinstance(msgs[0], sansldap.SearchResultEntry)
    assert msgs[0].message_id == 1
    assert msgs[0].controls == []
    assert msgs[0].object_name == "dn"
    assert msgs[0].attributes == []

    assert isinstance(msgs[1], sansldap.SearchResultReference)
    assert msgs[1].message_id == 1
    assert msgs[1].controls == []
    assert msgs[1].uris == ["uri 1", "uri 2"]

    assert isinstance(msgs[2], sansldap.SearchResultEntry)
    assert msgs[2].message_id == 1
    assert msgs[2].controls == []
    assert msgs[2].object_name == "dn 2"
    assert len(msgs[2].attributes) == 3
    assert msgs[2].attributes[0].name == "attr 1"
    assert msgs[2].attributes[0].values == [b"value 1", b"value 2"]
    assert msgs[2].attributes[1].name == "attr 2"
    assert msgs[2].attributes[1].values == []
    assert msgs[2].attributes[2].name == "attr 3"
    assert msgs[2].attributes[2].values == [b"\x00"]

    assert isinstance(msgs[3], sansldap.SearchResultDone)
    assert msgs[3].message_id == 1
    assert msgs[3].controls == []
    assert msgs[3].result.result_code == sansldap.LDAPResultCode.SUCCESS
    assert msgs[3].result.diagnostics_message == ""
    assert msgs[3].result.matched_dn == ""
    assert msgs[3].result.referrals == []

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED


def test_search_request_custom_filter() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()
    s.register_filter(CustomFilter)

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msg_id = c.search_request(filter=CustomFilter("my filter"))
    assert msg_id == 1

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msgs = s.receive(c.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.SearchRequest)
    assert msgs[0].message_id == msg_id
    assert msgs[0].controls == []
    assert msgs[0].base_object == ""
    assert msgs[0].scope == sansldap.SearchScope.SUBTREE
    assert msgs[0].deref_aliases == sansldap.DereferencingPolicy.NEVER
    assert msgs[0].size_limit == 0
    assert msgs[0].time_limit == 0
    assert msgs[0].types_only is False
    assert isinstance(msgs[0].filter, CustomFilter)
    assert msgs[0].filter.value == "my filter"
    assert msgs[0].attributes == []

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED

    msg_id = s.search_result_done(1)
    assert msg_id == 1

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED

    msgs = c.receive(s.data_to_send())
    assert len(msgs) == 1
    assert isinstance(msgs[0], sansldap.SearchResultDone)
    assert msgs[0].message_id == 1
    assert msgs[0].controls == []
    assert msgs[0].result.result_code == sansldap.LDAPResultCode.SUCCESS
    assert msgs[0].result.diagnostics_message == ""
    assert msgs[0].result.matched_dn == ""
    assert msgs[0].result.referrals == []

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.OPENED


def test_search_request_custom_filter_not_registered() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    msg_id = c.search_request(filter=CustomFilter("my filter"))
    assert msg_id == 1

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    with pytest.raises(
        sansldap.ProtocolError,
        match="Received invalid data from the peer, connection closing.*Unknown filter object",
    ) as exc:
        s.receive(c.data_to_send())

    assert exc.value.response is not None

    assert c.state == sansldap.SessionState.OPENED
    assert s.state == sansldap.SessionState.CLOSED


def test_fail_register_existing_auth_credential() -> None:
    expected = "An authentication credential of the type 1024 has already been registered"
    c = sansldap.LDAPClient()
    c.register_auth_credential(CustomAuth)

    with pytest.raises(ValueError, match=expected):
        c.register_auth_credential(CustomAuth)


def test_fail_register_existing_control() -> None:
    expected = "An LDAP control of the type 1\\.2\\.3\\.4 has already been registered"
    c = sansldap.LDAPClient()
    c.register_control(CustomControl)

    with pytest.raises(ValueError, match=expected):
        c.register_control(CustomControl)


def test_fail_register_existing_filter() -> None:
    expected = "An LDAP filter of the type 1024 has already been registered"
    c = sansldap.LDAPClient()
    c.register_filter(CustomFilter)

    with pytest.raises(ValueError, match=expected):
        c.register_filter(CustomFilter)


def test_receive_notice_of_diconnect() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    c.bind_simple()
    s.receive(c.data_to_send())

    assert c.state == sansldap.SessionState.BINDING
    assert s.state == sansldap.SessionState.BINDING

    s.extended_response(1, sansldap.ExtendedOperations.LDAP_NOTICE_OF_DISCONNECTION)

    with pytest.raises(sansldap.ProtocolError, match="Peer has sent a NoticeOfDisconnect response") as exc:
        c.receive(s.data_to_send())

    assert exc.value.response is None

    assert c.state == sansldap.SessionState.CLOSED
    assert s.state == sansldap.SessionState.CLOSED


def test_fail_client_bind_with_outstanding_request() -> None:
    expected = "All outstanding requests must be completed to send a BindRequest"
    c = sansldap.LDAPClient()

    assert c.state == sansldap.SessionState.BEFORE_OPEN

    msg_id = c.extended_request("name")
    assert msg_id == 1

    assert c.state == sansldap.SessionState.OPENED

    with pytest.raises(sansldap.LDAPError, match=expected):
        c.bind_simple()

    assert c.state == sansldap.SessionState.OPENED


def test_fail_server_bind_with_outstanding_request() -> None:
    expected = "Received an LDAP bind request but server still has outstanding operations"
    c1 = sansldap.LDAPClient()
    c2 = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    assert s.state == sansldap.SessionState.BEFORE_OPEN

    c1.extended_request("name")
    c2.bind_simple()

    s.receive(c1.data_to_send())

    assert s.state == sansldap.SessionState.OPENED

    with pytest.raises(sansldap.LDAPError, match=expected):
        s.receive(c2.data_to_send())

    assert s.state == sansldap.SessionState.CLOSED


def test_fail_client_receives_request() -> None:
    expected = "Received an LDAP message that is not a response"
    c = sansldap.LDAPClient()

    assert c.state == sansldap.SessionState.BEFORE_OPEN

    c.bind_simple()

    with pytest.raises(sansldap.ProtocolError, match=expected):
        c.receive(c.data_to_send())

    assert c.state == sansldap.SessionState.CLOSED


def test_fail_server_received_response() -> None:
    expected = "Received an LDAP message that is not a request"
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    assert c.state == sansldap.SessionState.BEFORE_OPEN
    assert s.state == sansldap.SessionState.BEFORE_OPEN

    c.bind_simple()
    s.receive(c.data_to_send())
    s.bind_response(1)

    with pytest.raises(sansldap.ProtocolError, match=expected):
        s.receive(s.data_to_send())

    assert s.state == sansldap.SessionState.CLOSED


def test_fail_server_responds_to_unknown_request() -> None:
    expected = "Message BindResponse.* is a response to an unknown request"
    s = sansldap.LDAPServer()

    assert s.state == sansldap.SessionState.BEFORE_OPEN

    with pytest.raises(sansldap.LDAPError, match=expected):
        s.bind_response(1)

    assert s.state == sansldap.SessionState.OPENED


def test_fail_client_receives_unknown_msg_id() -> None:
    c = sansldap.LDAPClient()
    s = sansldap.LDAPServer()

    c.extended_request("name")
    s.receive(c.data_to_send())
    s.extended_response(1)
    data = s.data_to_send()

    c = sansldap.LDAPClient()
    expected = "Received unexpected message id response 1 from server"

    with pytest.raises(sansldap.ProtocolError, match=expected) as exc:
        c.receive(data)

    assert exc.value.response is not None
    assert c.state == sansldap.SessionState.CLOSED
