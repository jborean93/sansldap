# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64

import sansldap._filter as f


def test_filter_and_unpack() -> None:
    data = base64.b64decode(
        "oEmjCgQDZm9vBANiYXKgO6QYBARhdHRyMBCAA2FiY4EEdGVzdIIDZW5kqRKBBHJ1bGWCBGF0dHKDBHRlc3SgC6UJBAR0ZXN0BAEx"
    )
    actual, consumed = f.LDAPFilter.unpack(memoryview(data))

    assert consumed == len(data)
    assert isinstance(actual, f.FilterAnd)
    assert len(actual.filters) == 2

    assert isinstance(actual.filters[0], f.FilterEquality)
    assert actual.filters[0].attribute == "foo"
    assert actual.filters[0].value == b"bar"

    assert isinstance(actual.filters[1], f.FilterAnd)
    assert len(actual.filters[1].filters) == 3

    assert isinstance(actual.filters[1].filters[0], f.FilterSubstrings)
    assert actual.filters[1].filters[0].initial == b"abc"
    assert actual.filters[1].filters[0].any == [b"test"]
    assert actual.filters[1].filters[0].final == b"end"

    assert isinstance(actual.filters[1].filters[1], f.FilterExtensibleMatch)
    assert actual.filters[1].filters[1].rule == "rule"
    assert actual.filters[1].filters[1].attribute == "attr"
    assert actual.filters[1].filters[1].value == b"test"
    assert actual.filters[1].filters[1].dn_attributes is False

    assert isinstance(actual.filters[1].filters[2], f.FilterAnd)
    assert len(actual.filters[1].filters[2].filters) == 1
    assert isinstance(actual.filters[1].filters[2].filters[0], f.FilterGreaterOrEqual)
    assert actual.filters[1].filters[2].filters[0].attribute == "test"
    assert actual.filters[1].filters[2].filters[0].value == b"1"


def test_filter_or_unpack() -> None:
    data = base64.b64decode("oTijCgQDZm9vBANiYXKhKocEYXR0cqkVgQRydWxlggRhdHRygwR0ZXN0hAH/oAumCQQEdGVzdAQBMQ==")
    actual, consumed = f.LDAPFilter.unpack(memoryview(data))

    assert consumed == len(data)
    assert isinstance(actual, f.FilterOr)
    assert len(actual.filters) == 2

    assert isinstance(actual.filters[0], f.FilterEquality)
    assert actual.filters[0].attribute == "foo"
    assert actual.filters[0].value == b"bar"

    assert isinstance(actual.filters[1], f.FilterOr)
    assert len(actual.filters[1].filters) == 3

    assert isinstance(actual.filters[1].filters[0], f.FilterPresent)
    assert actual.filters[1].filters[0].attribute == "attr"

    assert isinstance(actual.filters[1].filters[1], f.FilterExtensibleMatch)
    assert actual.filters[1].filters[1].rule == "rule"
    assert actual.filters[1].filters[1].attribute == "attr"
    assert actual.filters[1].filters[1].value == b"test"
    assert actual.filters[1].filters[1].dn_attributes is True

    assert isinstance(actual.filters[1].filters[2], f.FilterAnd)
    assert len(actual.filters[1].filters[2].filters) == 1
    assert isinstance(actual.filters[1].filters[2].filters[0], f.FilterLessOrEqual)
    assert actual.filters[1].filters[2].filters[0].attribute == "test"
    assert actual.filters[1].filters[2].filters[0].value == b"1"


def test_filter_not_unpack() -> None:
    data = base64.b64decode("og6iDKMKBANmb28EA2Jhcg==")
    actual, consumed = f.LDAPFilter.unpack(memoryview(data))

    assert consumed == len(data)
    assert isinstance(actual, f.FilterNot)
    assert isinstance(actual.filter, f.FilterNot)
    assert isinstance(actual.filter.filter, f.FilterEquality)
    assert actual.filter.filter.attribute == "foo"
    assert actual.filter.filter.value == b"bar"
