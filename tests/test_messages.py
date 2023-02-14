# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import re

import pytest

import sansldap._authentication as a
import sansldap._controls as c
import sansldap._filter as f
import sansldap._messages as m
from sansldap.asn1 import ASN1Reader, ASN1Tag, ASN1Writer, TagClass, TypeTagNumber

from .conftest import get_test_data

PACKING_OPTIONS = m.PackingOptions()


def unpack_message(data: bytes) -> m.LDAPMessage:
    reader = ASN1Reader(data)
    return m.unpack_ldap_message(reader, PACKING_OPTIONS)


class TestGenericMessages:
    def test_fail_unpack_not_application_tag(self) -> None:
        writer = ASN1Writer()
        with writer.push_sequence() as writer_seq:
            writer_seq.write_integer(0)
            writer_seq.write_octet_string(b"value")
        data = writer.get_data()

        expected = "Expecting LDAPMessage.protocolOp to be an APPLICATION but got ASN1Tag(tag_class=<TagClass.UNIVERSAL: 0>, tag_number=<TypeTagNumber.OCTET_STRING: 4>, is_constructed=False)"
        with pytest.raises(ValueError, match=re.escape(expected)):
            unpack_message(data)

    def test_fail_unpack_unknown_protocol_op(self) -> None:
        writer = ASN1Writer()
        with writer.push_sequence() as writer_seq:
            writer_seq.write_integer(0)
            writer_seq.write_octet_string(b"value", tag=ASN1Tag(TagClass.APPLICATION, 1024, False))
        data = writer.get_data()

        expected = "Unknown LDAPMessage.protocolOp choice 1024"
        with pytest.raises(NotImplementedError, match=re.escape(expected)):
            unpack_message(data)

    def test_unpack_extra_data_in_header(self) -> None:
        # UnbindRequest with a random OCTET_STRING between the protocolOp and
        # controls
        data = base64.b64decode(b"MCkCAQBiAAQFZHVtbXmgGzAZBBcxLjIuODQwLjExMzU1Ni4xLjQuMjA2NQ==")

        actual = unpack_message(data)
        assert isinstance(actual, m.UnbindRequest)
        assert len(actual.controls) == 1
        assert isinstance(actual.controls[0], c.ShowDeactivatedLinkControl)
        assert actual.controls[0].critical is False

    def test_unpack_extra_context_specific_data_in_header(self) -> None:
        # UnbindRequest with a random CONTEXT_SPECIFIC tagged OCTET_STRING
        # between the protocolOp and controls
        data = base64.b64decode(b"MCsCAQBiAJ+IAAVkdW1teaAbMBkEFzEuMi44NDAuMTEzNTU2LjEuNC4yMDY1")

        actual = unpack_message(data)
        assert isinstance(actual, m.UnbindRequest)
        assert len(actual.controls) == 1
        assert isinstance(actual.controls[0], c.ShowDeactivatedLinkControl)
        assert actual.controls[0].critical is False


class TestLDAPResultCode:
    def test_add_missing_member(self) -> None:
        value = m.LDAPResultCode(666)
        assert isinstance(value, m.LDAPResultCode)
        assert value.name == "UNKNOWN 0x0000029A"
        assert value.value == 666

    def test_fail_adding_non_integer(self) -> None:
        with pytest.raises(ValueError, match="'abc' is not a valid LDAPResultCode"):
            m.LDAPResultCode("abc")  # type: ignore[arg-type]  # Testing this


class TestBindRequest:
    def test_simple_create(self) -> None:
        msg = m.BindRequest(
            message_id=2,
            controls=[],
            version=3,
            name="CN=User",
            authentication=a.SimpleCredential("password"),
        )
        actual = msg.pack(PACKING_OPTIONS)
        assert isinstance(actual, bytes)

        unpacked = unpack_message(actual)
        assert isinstance(unpacked, m.BindRequest)
        assert unpacked.message_id == 2
        assert unpacked.controls == []
        assert unpacked.version == 3
        assert unpacked.name == "CN=User"
        assert isinstance(unpacked.authentication, a.SimpleCredential)
        assert unpacked.authentication.password == "password"

    def test_simple_parse(self) -> None:
        data = get_test_data("bind_request_simple")
        actual = unpack_message(data)

        assert isinstance(actual, m.BindRequest)
        assert actual.message_id == 1
        assert actual.controls == []
        assert actual.version == 3
        assert actual.name == "vagrant"
        assert isinstance(actual.authentication, a.SimpleCredential)
        assert actual.authentication.password == "vagrant"

    def test_sasl_create(self) -> None:
        msg = m.BindRequest(
            message_id=2,
            controls=[],
            version=3,
            name="UserName",
            authentication=a.SaslCredential(
                mechanism="GSSAPI",
                credentials=b"abcdef\x00",
            ),
        )
        actual = msg.pack(PACKING_OPTIONS)
        assert isinstance(actual, bytes)

        unpacked = unpack_message(actual)
        assert isinstance(unpacked, m.BindRequest)
        assert unpacked.message_id == 2
        assert unpacked.controls == []
        assert unpacked.version == 3
        assert unpacked.name == "UserName"
        assert isinstance(unpacked.authentication, a.SaslCredential)
        assert unpacked.authentication.mechanism == "GSSAPI"
        assert unpacked.authentication.credentials == b"abcdef\x00"

    def test_sasl_parse(self) -> None:
        data = get_test_data("bind_request_sasl")
        actual = unpack_message(data)

        assert isinstance(actual, m.BindRequest)
        assert actual.message_id == 1
        assert actual.controls == []
        assert actual.version == 3
        assert actual.name == ""
        assert isinstance(actual.authentication, a.SaslCredential)
        assert actual.authentication.mechanism == "GSS-SPNEGO"
        assert isinstance(actual.authentication.credentials, bytes)
        assert len(actual.authentication.credentials) == 1526


class TestBindResponse:
    def test_create(self) -> None:
        msg = m.BindResponse(
            message_id=2,
            controls=[],
            result=m.LDAPResult(
                result_code=m.LDAPResultCode.SUCCESS,
                matched_dn="CN=User,DC=domain,DC=test",
                diagnostics_message="Some random message",
                referrals=None,
            ),
            server_sasl_creds=b"abc\x00",
        )
        actual = msg.pack(PACKING_OPTIONS)
        assert isinstance(actual, bytes)

        unpacked = unpack_message(actual)
        assert isinstance(unpacked, m.BindResponse)
        assert unpacked.message_id == 2
        assert unpacked.controls == []
        assert unpacked.result.result_code == m.LDAPResultCode.SUCCESS
        assert unpacked.result.diagnostics_message == "Some random message"
        assert unpacked.result.matched_dn == "CN=User,DC=domain,DC=test"
        assert unpacked.result.referrals is None
        assert unpacked.server_sasl_creds == b"abc\x00"

    def test_create_no_sasl_cred(self) -> None:
        msg = m.BindResponse(
            message_id=1,
            controls=[],
            result=m.LDAPResult(
                result_code=m.LDAPResultCode.SUCCESS,
                matched_dn="",
                diagnostics_message="",
                referrals=None,
            ),
            server_sasl_creds=None,
        )
        actual = msg.pack(PACKING_OPTIONS)
        assert isinstance(actual, bytes)

        unpacked = unpack_message(actual)
        assert isinstance(unpacked, m.BindResponse)
        assert unpacked.server_sasl_creds is None

    def test_parse(self) -> None:
        data = get_test_data("bind_response")
        actual = unpack_message(data)

        assert isinstance(actual, m.BindResponse)
        assert actual.message_id == 1
        assert actual.controls == []
        assert actual.result.result_code == m.LDAPResultCode.SUCCESS
        assert actual.result.diagnostics_message == ""
        assert actual.result.matched_dn == ""
        assert actual.result.referrals is None
        assert isinstance(actual.server_sasl_creds, bytes)
        assert len(actual.server_sasl_creds) == 186

    def test_parse_with_extra_data(self) -> None:
        data = base64.b64decode("MBgCAQFhEwoBAAQABAAEBWR1bW15hwNhYmM=")

        actual = unpack_message(data)
        assert isinstance(actual, m.BindResponse)
        assert actual.message_id == 1
        assert actual.controls == []
        assert actual.result.result_code == m.LDAPResultCode.SUCCESS
        assert actual.result.diagnostics_message == ""
        assert actual.result.matched_dn == ""
        assert actual.result.referrals is None
        assert actual.server_sasl_creds == b"abc"


class TestSearchRequest:
    def test_create(self) -> None:
        msg = m.SearchRequest(
            message_id=2,
            controls=[],
            base_object="CN=BaseObject",
            scope=m.SearchScope.ONE_LEVEL,
            deref_aliases=m.DereferencingPolicy.ALWAYS,
            size_limit=1024,
            time_limit=2048,
            types_only=True,
            filter=f.FilterPresent("myAttribute"),
            attributes=["attr1", "attr 2"],
        )
        actual = msg.pack(PACKING_OPTIONS)
        assert isinstance(actual, bytes)

        unpacked = unpack_message(actual)
        assert isinstance(unpacked, m.SearchRequest)
        assert unpacked.message_id == 2
        assert unpacked.controls == []
        assert unpacked.base_object == "CN=BaseObject"
        assert unpacked.scope == m.SearchScope.ONE_LEVEL
        assert unpacked.deref_aliases == m.DereferencingPolicy.ALWAYS
        assert unpacked.size_limit == 1024
        assert unpacked.time_limit == 2048
        assert unpacked.types_only is True
        assert isinstance(unpacked.filter, f.FilterPresent)
        assert unpacked.filter.attribute == "myAttribute"
        assert unpacked.attributes == ["attr1", "attr 2"]

    def test_parse(self) -> None:
        data = get_test_data("search_request")
        actual = unpack_message(data)

        assert isinstance(actual, m.SearchRequest)
        assert actual.message_id == 2
        assert len(actual.controls) == 1
        assert isinstance(actual.controls[0], c.PagedResultControl)
        assert actual.controls[0].control_type == c.PagedResultControl.control_type
        assert actual.controls[0].critical is False
        assert actual.controls[0].size == 1000
        assert actual.controls[0].cookie == b""
        assert actual.base_object == ""
        assert actual.scope == m.SearchScope.BASE
        assert actual.deref_aliases == m.DereferencingPolicy.NEVER
        assert actual.size_limit == 0
        assert actual.time_limit == 180
        assert actual.types_only is False
        assert isinstance(actual.filter, f.FilterPresent)
        assert actual.filter.attribute == "objectClass"
        assert actual.attributes == [
            "defaultNamingContext",
            "dnsHostName",
            "subschemaSubentry",
            "supportedControl",
        ]


class TestSearchResultEntry:
    def test_create(self) -> None:
        msg = m.SearchResultEntry(
            message_id=2,
            controls=[],
            object_name="CN=Object",
            attributes=[
                m.PartialAttribute("name1", [b"value 1", b"value 2\x00"]),
                m.PartialAttribute("name 2", []),
                m.PartialAttribute("name 3", [b"foo bar"]),
            ],
        )
        actual = msg.pack(PACKING_OPTIONS)
        assert isinstance(actual, bytes)

        unpacked = unpack_message(actual)
        assert isinstance(unpacked, m.SearchResultEntry)
        assert unpacked.message_id == 2
        assert unpacked.controls == []
        assert unpacked.object_name == "CN=Object"
        assert len(unpacked.attributes) == 3

        assert isinstance(unpacked.attributes[0], m.PartialAttribute)
        assert unpacked.attributes[0].name == "name1"
        assert unpacked.attributes[0].values == [b"value 1", b"value 2\x00"]

        assert isinstance(unpacked.attributes[1], m.PartialAttribute)
        assert unpacked.attributes[1].name == "name 2"
        assert unpacked.attributes[1].values == []

        assert isinstance(unpacked.attributes[2], m.PartialAttribute)
        assert unpacked.attributes[2].name == "name 3"
        assert unpacked.attributes[2].values == [b"foo bar"]

    def test_parse(self) -> None:
        data = get_test_data("search_result_entry")
        actual = unpack_message(data)

        assert isinstance(actual, m.SearchResultEntry)
        assert actual.message_id == 2
        assert actual.controls == []
        assert actual.object_name == ""
        assert len(actual.attributes) == 4

        assert isinstance(actual.attributes[0], m.PartialAttribute)
        assert actual.attributes[0].name == "subschemaSubentry"
        assert actual.attributes[0].values == [b"CN=Aggregate,CN=Schema,CN=Configuration,DC=domain,DC=test"]

        assert isinstance(actual.attributes[1], m.PartialAttribute)
        assert actual.attributes[1].name == "defaultNamingContext"
        assert actual.attributes[1].values == [b"DC=domain,DC=test"]

        assert isinstance(actual.attributes[2], m.PartialAttribute)
        assert actual.attributes[2].name == "supportedControl"
        assert len(actual.attributes[2].values) == 38

        assert isinstance(actual.attributes[3], m.PartialAttribute)
        assert actual.attributes[3].name == "dnsHostName"
        assert actual.attributes[3].values == [b"DC01.domain.test"]


class TestSearchResultDone:
    def test_create(self) -> None:
        msg = m.SearchResultDone(
            message_id=2,
            controls=[],
            result=m.LDAPResult(
                result_code=m.LDAPResultCode.SUCCESS,
                matched_dn="CN=User,DC=domain,DC=test",
                diagnostics_message="Some random message",
                referrals=None,
            ),
        )
        actual = msg.pack(PACKING_OPTIONS)
        assert isinstance(actual, bytes)

        unpacked = unpack_message(actual)
        assert isinstance(unpacked, m.SearchResultDone)
        assert unpacked.message_id == 2
        assert unpacked.controls == []
        assert unpacked.result.result_code == m.LDAPResultCode.SUCCESS
        assert unpacked.result.matched_dn == "CN=User,DC=domain,DC=test"
        assert unpacked.result.diagnostics_message == "Some random message"
        assert unpacked.result.referrals is None

    def test_create_with_control(self) -> None:
        msg = m.SearchResultDone(
            message_id=2,
            controls=[c.PagedResultControl(False, 1024, b"cookie")],
            result=m.LDAPResult(
                result_code=m.LDAPResultCode.SUCCESS,
                matched_dn="",
                diagnostics_message="",
                referrals=None,
            ),
        )
        actual = msg.pack(PACKING_OPTIONS)
        assert isinstance(actual, bytes)

        unpacked = unpack_message(actual)
        assert isinstance(unpacked, m.SearchResultDone)
        assert unpacked.message_id == 2
        assert len(unpacked.controls) == 1
        assert isinstance(unpacked.controls[0], c.PagedResultControl)
        assert unpacked.controls[0].control_type == "1.2.840.113556.1.4.319"
        assert unpacked.controls[0].critical is False
        assert unpacked.controls[0].size == 1024
        assert unpacked.controls[0].cookie == b"cookie"
        assert unpacked.result.result_code == m.LDAPResultCode.SUCCESS
        assert unpacked.result.matched_dn == ""
        assert unpacked.result.diagnostics_message == ""
        assert unpacked.result.referrals is None

    def test_create_with_referral(self) -> None:
        msg = m.SearchResultDone(
            message_id=2,
            controls=[],
            result=m.LDAPResult(
                result_code=m.LDAPResultCode.REFERRAL,
                matched_dn="",
                diagnostics_message="",
                referrals=[
                    "ldap://CN=Referal1,DC=domain",
                    "ldap://CN=Referal2,DC=test",
                ],
            ),
        )
        actual = msg.pack(PACKING_OPTIONS)
        assert isinstance(actual, bytes)

        unpacked = unpack_message(actual)
        assert isinstance(unpacked, m.SearchResultDone)
        assert unpacked.message_id == 2
        assert unpacked.controls == []
        assert unpacked.result.result_code == m.LDAPResultCode.REFERRAL
        assert unpacked.result.matched_dn == ""
        assert unpacked.result.diagnostics_message == ""
        assert unpacked.result.referrals == [
            "ldap://CN=Referal1,DC=domain",
            "ldap://CN=Referal2,DC=test",
        ]

    def test_parse_with_control(self) -> None:
        data = get_test_data("search_result_done_control")
        actual = unpack_message(data)

        assert isinstance(actual, m.SearchResultDone)
        assert actual.message_id == 13
        assert len(actual.controls) == 1
        assert isinstance(actual.controls[0], c.PagedResultControl)
        assert actual.controls[0].control_type == "1.2.840.113556.1.4.319"
        assert actual.controls[0].critical is False
        assert actual.controls[0].size == 0
        assert isinstance(actual.controls[0].cookie, bytes)
        assert len(actual.controls[0].cookie) > 0
        assert actual.result.result_code == m.LDAPResultCode.SUCCESS
        assert actual.result.matched_dn == ""
        assert actual.result.diagnostics_message == ""
        assert actual.result.referrals is None

    def test_parse_with_referral(self) -> None:
        data = get_test_data("search_result_done_referral")
        actual = unpack_message(data)

        assert isinstance(actual, m.SearchResultDone)
        assert actual.message_id == 4
        assert len(actual.controls) == 1
        assert isinstance(actual.controls[0], c.PagedResultControl)
        assert actual.controls[0].control_type == "1.2.840.113556.1.4.319"
        assert actual.controls[0].critical is False
        assert actual.controls[0].size == 0
        assert actual.controls[0].cookie == b""
        assert actual.result.result_code == m.LDAPResultCode.REFERRAL
        assert actual.result.matched_dn == ""
        assert (
            actual.result.diagnostics_message
            == "0000202B: RefErr: DSID-0310078A, data 0, 1 access points\n\tref 1: 'foo.ldap.test'\n\x00"
        )
        assert actual.result.referrals == ["ldap://foo.ldap.test/DC=foo,DC=ldap,DC=test"]


class TestSearchResultReference:
    def test_create(self) -> None:
        msg = m.SearchResultReference(
            message_id=2,
            controls=[],
            uris=["uri 1", "uri 2"],
        )
        actual = msg.pack(PACKING_OPTIONS)
        assert isinstance(actual, bytes)

        unpacked = unpack_message(actual)
        assert isinstance(unpacked, m.SearchResultReference)
        assert unpacked.message_id == 2
        assert unpacked.controls == []
        assert unpacked.uris == ["uri 1", "uri 2"]


class TestExtendedRequest:
    def test_create(self) -> None:
        msg = m.ExtendedRequest(
            message_id=1,
            controls=[],
            name="1.2.3.1293.492190.1",
            value=b"abc\x00",
        )
        actual = msg.pack(PACKING_OPTIONS)
        assert isinstance(actual, bytes)

        unpacked = unpack_message(actual)
        assert isinstance(unpacked, m.ExtendedRequest)
        assert unpacked.message_id == 1
        assert unpacked.controls == []
        assert unpacked.name == "1.2.3.1293.492190.1"
        assert unpacked.value == b"abc\x00"

    def test_create_no_data(self) -> None:
        msg = m.ExtendedRequest(
            message_id=1,
            controls=[],
            name="1.2.3.1293.492190.1",
            value=None,
        )
        actual = msg.pack(PACKING_OPTIONS)
        assert isinstance(actual, bytes)

        unpacked = unpack_message(actual)
        assert isinstance(unpacked, m.ExtendedRequest)
        assert unpacked.message_id == 1
        assert unpacked.controls == []
        assert unpacked.name == "1.2.3.1293.492190.1"
        assert unpacked.value is None

    def test_parse(self) -> None:
        data = get_test_data("extended_request")
        actual = unpack_message(data)

        assert isinstance(actual, m.ExtendedRequest)
        assert actual.message_id == 1
        assert actual.name == "1.3.6.1.4.1.1466.20037"
        assert actual.value is None

    def test_parse_with_extra_data(self) -> None:
        data = base64.b64decode("MCsCAQF3JoAWMS4zLjYuMS40LjEuMTQ2Ni4yMDAzNwQFZHVtbXmBBXZhbHVl")

        actual = unpack_message(data)
        assert isinstance(actual, m.ExtendedRequest)
        assert actual.message_id == 1
        assert actual.name == "1.3.6.1.4.1.1466.20037"
        assert actual.value == b"value"


class TestExtendedResponse:
    def test_create(self) -> None:
        msg = m.ExtendedResponse(
            message_id=1,
            controls=[],
            result=m.LDAPResult(
                result_code=m.LDAPResultCode.SUCCESS,
                matched_dn="",
                diagnostics_message="",
                referrals=None,
            ),
            name="1.2.3.1293.492190.1",
            value=b"abc\x00",
        )
        actual = msg.pack(PACKING_OPTIONS)
        assert isinstance(actual, bytes)

        unpacked = unpack_message(actual)
        assert isinstance(unpacked, m.ExtendedResponse)
        assert unpacked.message_id == 1
        assert unpacked.controls == []
        assert unpacked.result.result_code == m.LDAPResultCode.SUCCESS
        assert unpacked.result.matched_dn == ""
        assert unpacked.result.diagnostics_message == ""
        assert unpacked.result.referrals is None
        assert unpacked.name == "1.2.3.1293.492190.1"
        assert unpacked.value == b"abc\x00"

    def test_create_no_name_value(self) -> None:
        msg = m.ExtendedResponse(
            message_id=1,
            controls=[],
            result=m.LDAPResult(
                result_code=m.LDAPResultCode.SUCCESS,
                matched_dn="",
                diagnostics_message="",
                referrals=None,
            ),
            name=None,
            value=None,
        )
        actual = msg.pack(PACKING_OPTIONS)
        assert isinstance(actual, bytes)

        unpacked = unpack_message(actual)
        assert isinstance(unpacked, m.ExtendedResponse)
        assert unpacked.message_id == 1
        assert unpacked.controls == []
        assert unpacked.result.result_code == m.LDAPResultCode.SUCCESS
        assert unpacked.result.matched_dn == ""
        assert unpacked.result.diagnostics_message == ""
        assert unpacked.result.referrals is None
        assert unpacked.name is None
        assert unpacked.value is None

    def test_parse(self) -> None:
        data = get_test_data("extended_response")
        actual = unpack_message(data)

        assert isinstance(actual, m.ExtendedResponse)
        assert actual.message_id == 1
        assert actual.result.result_code == m.LDAPResultCode.SUCCESS
        assert actual.result.diagnostics_message == ""
        assert actual.result.matched_dn == ""
        assert actual.result.referrals is None
        assert actual.name == "1.3.6.1.4.1.1466.20037"
        assert actual.value is None

    def test_parse_ms_ad_notice_of_disconnect(self) -> None:
        data = get_test_data("notice_of_disconnect_ad")
        actual = unpack_message(data)

        assert isinstance(actual, m.ExtendedResponse)
        assert actual.message_id == 0
        assert actual.result.result_code == m.LDAPResultCode.PROTOCOL_ERROR
        assert (
            actual.result.diagnostics_message
            == "00000057: LdapErr: DSID-00000000, comment: Error decoding ldap message, data 0, v4563\x00"
        )
        assert actual.result.matched_dn == ""
        assert actual.result.referrals is None
        assert actual.name == "1.3.6.1.4.1.1466.20036"
        assert actual.value is None

    def test_parse_with_extra_data(self) -> None:
        data = base64.b64decode("MC4CAQF4KQoBAAQABACKEzEuMi4zLjEyOTMuNDkyMTkwLjEEBWR1bW15iwRhYmMA")

        actual = unpack_message(data)
        assert isinstance(actual, m.ExtendedResponse)
        assert actual.message_id == 1
        assert actual.controls == []
        assert actual.result.result_code == m.LDAPResultCode.SUCCESS
        assert actual.result.matched_dn == ""
        assert actual.result.diagnostics_message == ""
        assert actual.result.referrals is None
        assert actual.name == "1.2.3.1293.492190.1"
        assert actual.value == b"abc\x00"

    def test_parse_with_extra_context_specific_data(self) -> None:
        data = base64.b64decode("MDACAQF4KwoBAAQABACKEzEuMi4zLjEyOTMuNDkyMTkwLjGfiAAFZHVtbXmLBGFiYwA=")

        actual = unpack_message(data)
        assert isinstance(actual, m.ExtendedResponse)
        assert actual.message_id == 1
        assert actual.controls == []
        assert actual.result.result_code == m.LDAPResultCode.SUCCESS
        assert actual.result.matched_dn == ""
        assert actual.result.diagnostics_message == ""
        assert actual.result.referrals is None
        assert actual.name == "1.2.3.1293.492190.1"
        assert actual.value == b"abc\x00"
