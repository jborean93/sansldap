# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import sansldap._controls as c
import sansldap._filter as f
import sansldap._messages as m

from .conftest import get_test_data


class TestBindRequest:
    def test_simple_create(self) -> None:
        msg = m.BindRequest(
            message_id=2,
            controls=[],
            version=3,
            name="CN=User",
            authentication=m.SimpleCredential("password"),
        )
        actual = msg.pack()
        assert isinstance(actual, bytes)

        unpacked, consumed = m.LDAPMessage.unpack(actual)
        assert consumed == len(actual)
        assert isinstance(unpacked, m.BindRequest)
        assert unpacked.message_id == 2
        assert unpacked.controls == []
        assert unpacked.version == 3
        assert unpacked.name == "CN=User"
        assert isinstance(unpacked.authentication, m.SimpleCredential)
        assert unpacked.authentication.password == "password"

    def test_simple_parse(self) -> None:
        data = get_test_data("bind_request_simple")
        actual, consumed = m.LDAPMessage.unpack(data)

        assert len(data) == consumed
        assert isinstance(actual, m.BindRequest)
        assert actual.message_id == 1
        assert actual.controls == []
        assert actual.version == 3
        assert actual.name == "vagrant"
        assert isinstance(actual.authentication, m.SimpleCredential)
        assert actual.authentication.password == "vagrant"

    def test_sasl_create(self) -> None:
        msg = m.BindRequest(
            message_id=2,
            controls=[],
            version=3,
            name="UserName",
            authentication=m.SaslCredential(
                mechanism="GSSAPI",
                credentials=b"abcdef\x00",
            ),
        )
        actual = msg.pack()
        assert isinstance(actual, bytes)

        unpacked, consumed = m.LDAPMessage.unpack(actual)
        assert consumed == len(actual)
        assert isinstance(unpacked, m.BindRequest)
        assert unpacked.message_id == 2
        assert unpacked.controls == []
        assert unpacked.version == 3
        assert unpacked.name == "UserName"
        assert isinstance(unpacked.authentication, m.SaslCredential)
        assert unpacked.authentication.mechanism == "GSSAPI"
        assert unpacked.authentication.credentials == b"abcdef\x00"

    def test_sasl_parse(self) -> None:
        data = get_test_data("bind_request_sasl")
        actual, consumed = m.LDAPMessage.unpack(data)

        assert len(data) == consumed
        assert isinstance(actual, m.BindRequest)
        assert actual.message_id == 1
        assert actual.controls == []
        assert actual.version == 3
        assert actual.name == ""
        assert isinstance(actual.authentication, m.SaslCredential)
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
        actual = msg.pack()
        assert isinstance(actual, bytes)

        unpacked, consumed = m.LDAPMessage.unpack(actual)
        assert consumed == len(actual)
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
        actual = msg.pack()
        assert isinstance(actual, bytes)

        unpacked, consumed = m.LDAPMessage.unpack(actual)
        assert consumed == len(actual)
        assert isinstance(unpacked, m.BindResponse)
        assert unpacked.server_sasl_creds is None

    def test_parse(self) -> None:
        data = get_test_data("bind_response")
        actual, consumed = m.LDAPMessage.unpack(data)

        assert len(data) == consumed
        assert isinstance(actual, m.BindResponse)
        assert actual.message_id == 1
        assert actual.controls == []
        assert actual.result.result_code == m.LDAPResultCode.SUCCESS
        assert actual.result.diagnostics_message == ""
        assert actual.result.matched_dn == ""
        assert actual.result.referrals is None
        assert isinstance(actual.server_sasl_creds, bytes)
        assert len(actual.server_sasl_creds) == 186


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
        actual = msg.pack()
        assert isinstance(actual, bytes)

        unpacked, consumed = m.LDAPMessage.unpack(actual)
        assert consumed == len(actual)
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
        actual, consumed = m.LDAPMessage.unpack(data)

        assert len(data) == consumed
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
        actual = msg.pack()
        assert isinstance(actual, bytes)

        unpacked, consumed = m.LDAPMessage.unpack(actual)
        assert consumed == len(actual)
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
        actual, consumed = m.LDAPMessage.unpack(data)

        assert len(data) == consumed
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
        actual = msg.pack()
        assert isinstance(actual, bytes)

        unpacked, consumed = m.LDAPMessage.unpack(actual)
        assert consumed == len(actual)
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
        actual = msg.pack()
        assert isinstance(actual, bytes)

        unpacked, consumed = m.LDAPMessage.unpack(actual)
        assert consumed == len(actual)
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
        actual = msg.pack()
        assert isinstance(actual, bytes)

        unpacked, consumed = m.LDAPMessage.unpack(actual)
        assert consumed == len(actual)
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
        actual, consumed = m.LDAPMessage.unpack(data)

        assert len(data) == consumed
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
        actual, consumed = m.LDAPMessage.unpack(data)

        assert len(data) == consumed
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


class TestExtendedRequest:
    def test_create(self) -> None:
        msg = m.ExtendedRequest(
            message_id=1,
            controls=[],
            name="1.2.3.1293.492190.1",
            value=b"abc\x00",
        )
        actual = msg.pack()
        assert isinstance(actual, bytes)

        unpacked, consumed = m.LDAPMessage.unpack(actual)
        assert consumed == len(actual)
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
        actual = msg.pack()
        assert isinstance(actual, bytes)

        unpacked, consumed = m.LDAPMessage.unpack(actual)
        assert consumed == len(actual)
        assert isinstance(unpacked, m.ExtendedRequest)
        assert unpacked.message_id == 1
        assert unpacked.controls == []
        assert unpacked.name == "1.2.3.1293.492190.1"
        assert unpacked.value is None

    def test_parse(self) -> None:
        data = get_test_data("extended_request")
        actual, consumed = m.LDAPMessage.unpack(data)

        assert len(data) == consumed
        assert isinstance(actual, m.ExtendedRequest)
        assert actual.message_id == 1
        assert actual.name == "1.3.6.1.4.1.1466.20037"
        assert actual.value is None


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
        actual = msg.pack()
        assert isinstance(actual, bytes)

        unpacked, consumed = m.LDAPMessage.unpack(actual)
        assert consumed == len(actual)
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
        actual = msg.pack()
        assert isinstance(actual, bytes)

        unpacked, consumed = m.LDAPMessage.unpack(actual)
        assert consumed == len(actual)
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
        actual, consumed = m.LDAPMessage.unpack(data)

        assert len(data) == consumed
        assert isinstance(actual, m.ExtendedResponse)
        assert actual.message_id == 1
        assert actual.result.result_code == m.LDAPResultCode.SUCCESS
        assert actual.result.diagnostics_message == ""
        assert actual.result.matched_dn == ""
        assert actual.result.referrals is None
        assert actual.name == "1.3.6.1.4.1.1466.20037"
        assert actual.value is None
