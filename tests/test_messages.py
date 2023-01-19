# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import sansldap._messages as m

from .conftest import get_test_data


def test_bind_simple_create() -> None:
    a = ""


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
