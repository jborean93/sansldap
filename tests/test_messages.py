# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import sansldap._controls as c
import sansldap._filter as f
import sansldap._messages as m

from .conftest import get_test_data


def test_bind_simple_create() -> None:
    data = get_test_data("bind_request_simple")
    actual, consumed = m.LDAPMessage.unpack(data)

    assert len(data) == consumed
    assert isinstance(actual, m.BindRequestSimple)
    assert actual.message_id == 1
    assert actual.controls == []
    assert actual.version == 3
    assert actual.name == "vagrant"
    assert actual.password == "vagrant"


def test_bind_request_sasl_parse() -> None:
    data = get_test_data("bind_request_sasl")
    actual, consumed = m.LDAPMessage.unpack(data)

    assert len(data) == consumed
    assert isinstance(actual, m.BindRequestSasl)
    assert actual.message_id == 1
    assert actual.controls == []
    assert actual.version == 3
    assert actual.name == ""
    assert actual.mechanism == "GSS-SPNEGO"
    assert isinstance(actual.credentials, bytes)
    assert len(actual.credentials) == 1526


def test_bind_response_parse() -> None:
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


def test_search_request() -> None:
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


def test_search_result_entry() -> None:
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


def test_search_result_done_with_control() -> None:
    data = get_test_data("search_result_done_control")
    actual, consumed = m.LDAPMessage.unpack(data)

    assert len(data) == consumed
    assert isinstance(actual, m.SearchResultDone)
    assert actual.message_id == 13
    assert len(actual.controls) == 1
    assert isinstance(actual.controls[0], c.PagedResultControl)
    assert actual.controls[0].control_type == "1.2.840.113556.1.4.319"
    assert actual.controls[0].critical is False
    assert isinstance(actual.controls[0].cookie, bytes)
    assert len(actual.controls[0].cookie) > 0
    assert actual.result.result_code == m.LDAPResultCode.SUCCESS
    assert actual.result.matched_dn == ""
    assert actual.result.diagnostics_message == ""
    assert actual.result.referrals is None


def test_search_result_done_with_referral() -> None:
    data = get_test_data("search_result_done_referral")
    actual, consumed = m.LDAPMessage.unpack(data)

    assert len(data) == consumed
    assert isinstance(actual, m.SearchResultDone)
    assert actual.message_id == 4
    assert len(actual.controls) == 1
    assert isinstance(actual.controls[0], c.PagedResultControl)
    assert actual.controls[0].control_type == "1.2.840.113556.1.4.319"
    assert actual.controls[0].critical is False
    assert actual.controls[0].cookie == b""
    assert actual.result.result_code == m.LDAPResultCode.REFERRAL
    assert actual.result.matched_dn == ""
    assert (
        actual.result.diagnostics_message
        == "0000202B: RefErr: DSID-0310078A, data 0, 1 access points\n\tref 1: 'foo.ldap.test'\n\x00"
    )
    assert actual.result.referrals == ["ldap://foo.ldap.test/DC=foo,DC=ldap,DC=test"]


def test_extended_request() -> None:
    data = get_test_data("extended_request")
    actual, consumed = m.LDAPMessage.unpack(data)

    assert len(data) == consumed
    assert isinstance(actual, m.ExtendedRequest)
    assert actual.message_id == 1
    assert actual.name == "1.3.6.1.4.1.1466.20037"
    assert actual.value is None


def test_extended_response() -> None:
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
