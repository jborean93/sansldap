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
