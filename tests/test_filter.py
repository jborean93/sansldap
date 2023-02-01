# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import typing as t

import pytest

import sansldap._filter as f
from sansldap.asn1 import ASN1Reader


def unpack_filter(data: bytes) -> f.LDAPFilter:
    reader = ASN1Reader(data)
    return f.LDAPFilter.unpack(reader, f.FilterOptions())


def test_filter_and_unpack() -> None:
    data = base64.b64decode(
        "oEmjCgQDZm9vBANiYXKgO6QYBARhdHRyMBCAA2FiY4EEdGVzdIIDZW5kqRKBBHJ1bGWCBGF0dHKDBHRlc3SgC6UJBAR0ZXN0BAEx"
    )
    actual = unpack_filter(data)

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
    actual = unpack_filter(data)

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
    actual = unpack_filter(data)

    assert isinstance(actual, f.FilterNot)
    assert isinstance(actual.filter, f.FilterNot)
    assert isinstance(actual.filter.filter, f.FilterEquality)
    assert actual.filter.filter.attribute == "foo"
    assert actual.filter.filter.value == b"bar"


def test_filter_equality_unpack() -> None:
    data = base64.b64decode("oyUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp")
    actual = unpack_filter(data)

    assert isinstance(actual, f.FilterEquality)
    assert actual.attribute == "objectClass;test"
    assert actual.value == "abc def ☺ café".encode("utf-8")


@pytest.mark.parametrize(
    "attribute, initial, any_values, final, data",
    [
        (
            "objectClass;test",
            None,
            ["abc ", "def ☺ ", "café"],
            None,
            "pCsEEG9iamVjdENsYXNzO3Rlc3QwF4EEYWJjIIEIZGVmIOKYuiCBBWNhZsOp",
        ),
        (
            "objectClass;test",
            "abc ",
            ["def ☺ ", "café"],
            None,
            "pCsEEG9iamVjdENsYXNzO3Rlc3QwF4AEYWJjIIEIZGVmIOKYuiCBBWNhZsOp",
        ),
        (
            "objectClass;test",
            None,
            ["abc ", "def ☺ "],
            "café",
            "pCsEEG9iamVjdENsYXNzO3Rlc3QwF4EEYWJjIIEIZGVmIOKYuiCCBWNhZsOp",
        ),
        (
            "objectClass;test",
            "abc ",
            ["def ☺ "],
            "café",
            "pCsEEG9iamVjdENsYXNzO3Rlc3QwF4AEYWJjIIEIZGVmIOKYuiCCBWNhZsOp",
        ),
    ],
    ids=[
        "no_initial_and_no_final",
        "initial_and_no_final",
        "no_initial_and_final",
        "initial_and_final",
    ],
)
def test_filter_substrings_unpack(
    attribute: str,
    initial: t.Optional[str],
    any_values: t.List[str],
    final: t.Optional[str],
    data: str,
) -> None:
    b_data = base64.b64decode(data)
    actual = unpack_filter(b_data)

    assert isinstance(actual, f.FilterSubstrings)
    assert actual.attribute == attribute
    assert actual.initial == (initial.encode("utf-8") if initial else None)
    assert actual.any == [a.encode("utf-8") for a in any_values]
    assert actual.final == (final.encode("utf-8") if final else None)


def test_filter_greater_or_equal_unpack() -> None:
    data = base64.b64decode("pSUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp")
    actual = unpack_filter(data)

    assert isinstance(actual, f.FilterGreaterOrEqual)
    assert actual.attribute == "objectClass;test"
    assert actual.value == "abc def ☺ café".encode("utf-8")


def test_filter_less_or_equal_unpack() -> None:
    data = base64.b64decode("piUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp")
    actual = unpack_filter(data)

    assert isinstance(actual, f.FilterLessOrEqual)
    assert actual.attribute == "objectClass;test"
    assert actual.value == "abc def ☺ café".encode("utf-8")


def test_filter_present_unpack() -> None:
    data = base64.b64decode("hxIxLjIuMy4zNDEuMC4xO3Rlc3Q=")
    actual = unpack_filter(data)

    assert isinstance(actual, f.FilterPresent)
    assert actual.attribute == "1.2.3.341.0.1;test"


def test_filter_approx_match_unpack() -> None:
    data = base64.b64decode("qCUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp")
    actual = unpack_filter(data)

    assert isinstance(actual, f.FilterApproxMatch)
    assert actual.attribute == "objectClass;test"
    assert actual.value == "abc def ☺ café".encode("utf-8")


# FIXME: Add tests for this
# def test_filter_extensible_match_unpack() -> None:
#     data = base64.b64decode("")
#     actual = unpack_filter(data)
