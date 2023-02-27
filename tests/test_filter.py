# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import base64
import dataclasses
import re
import typing as t

import pytest

import sansldap._filter as f
import sansldap._messages as m
from sansldap.asn1 import ASN1Reader, ASN1Tag, ASN1Writer, TagClass


def pack_filter(filter: f.LDAPFilter) -> bytes:
    writer = ASN1Writer()
    filter.pack(writer, f.FilterOptions())
    return writer.get_data()


def unpack_filter(data: bytes) -> f.LDAPFilter:
    reader = ASN1Reader(data)
    return f.LDAPFilter.unpack(reader, f.FilterOptions())


class TestFilterFromStringGeneric:
    def test_fail_extra_data(self) -> None:
        ldap_filter = "(objectClass=*)foo=bar"
        expected = "Extra data found at filter end"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 15
        assert exc.value.length == 7

    def test_fail_unbalanced_closing_paren(self) -> None:
        ldap_filter = ")"
        expected = "Unbalanced closing ')' without a starting '('"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 0
        assert exc.value.length == 1

    def test_fail_filter_nested_complex_without_conditional(self) -> None:
        ldap_filter = "((objectClass=*))"
        expected = "Nested '(' without filter conditional"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 1
        assert exc.value.length == 1

    def test_fail_unbalance_no_closing_simple(self) -> None:
        ldap_filter = "(objectClass=*"
        expected = "Unbalanced starting '(' without a closing ')'"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 0
        assert exc.value.length == 14

    def test_fail_no_filter(self) -> None:
        ldap_filter = "()"
        expected = "No filter found"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 0
        assert exc.value.length == 2

    def test_fail_complex_no_value(self) -> None:
        ldap_filter = "(&"
        expected = "No filter value found after conditional"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 1
        assert exc.value.length == 1

    @pytest.mark.parametrize(
        "attribute",
        [
            "objectClass",
            "sAMAccountName",
            "sAMAccountName;option",
            "objectClass;option1;option2;-option3",
            "Test-attr",
            "test-",
            "test-;option1;x-option",
            "test0",
            "test1",
            "0",
            "0;option",
            "0;option1;-xoption2",
            "0.0",
            "1.0.1",
            "9.54",
            "3.2.454.23436.1",
            "2.123434.1219214.4394",
        ],
    )
    def test_attribute_parsing(self, attribute: str) -> None:
        ldap_filter = f"{attribute}=*"
        actual = f.LDAPFilter.from_string(ldap_filter)

        assert isinstance(actual, f.FilterPresent)
        assert actual.attribute == attribute

    @pytest.mark.parametrize(
        "attribute",
        [
            "1attribute",
            "attribute_test",
            "1.02.2320",
            "attribute;option;",
        ],
    )
    def test_fail_invalid_attribute(self, attribute: str) -> None:
        ldap_filter = f"{attribute}=*"
        expected = "Filter attribute is invalid"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 0
        assert exc.value.length == len(attribute)

    def test_fail_simple_filter_no_attribute(self) -> None:
        ldap_filter = "=foo"
        expected = "Simple filter value must not start with '='"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 0
        assert exc.value.length == 1

    def test_fail_simple_filter_no_equals(self) -> None:
        ldap_filter = "foo"
        expected = "Simple filter missing '=' character"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 0
        assert exc.value.length == 3

    def test_fail_simple_filter_no_value(self) -> None:
        ldap_filter = "foo="
        expected = "Simple filter value is not present after '='"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 0
        assert exc.value.length == 4

    @pytest.mark.parametrize(
        "value_str, value, filter_str",
        [
            ("simple_123", b"simple_123", "simple_123"),
            ("café", b"caf\xC3\xA9", r"caf\c3\a9"),
            ("test with space", b"test with space", "test with space"),
            (r"null \00", b"null \x00", r"null \00"),
            (r"open paren \28", b"open paren (", r"open paren \28"),
            (r"close paren \29", b"close paren )", r"close paren \29"),
            (r"asterisk \2a", b"asterisk *", r"asterisk \2a"),
            (r"backslash \5C", b"backslash \\", r"backslash \5c"),
            (r"any escaped \20", b"any escaped  ", "any escaped  "),
            ("happy face ☺", b"happy face \xE2\x98\xBA", r"happy face \e2\98\ba"),
            ("embedded bytes \uDCFFtest\uDCF1", b"embedded bytes \xFFtest\xF1", r"embedded bytes \fftest\f1"),
            ("control char\n\v\ttest", b"control char\n\x0B\ttest", r"control char\0a\0b\09test"),
        ],
    )
    def test_parse_value(
        self,
        value_str: str,
        value: bytes,
        filter_str: str,
    ) -> None:
        actual = f.LDAPFilter.from_string(f"foo={value_str}")
        assert isinstance(actual, f.FilterEquality)
        assert actual.attribute == "foo"
        assert actual.value == value

        expected_filter_str = f"(foo={filter_str})"
        assert str(actual) == expected_filter_str

    @pytest.mark.parametrize(
        "value, err_msg",
        [
            ("abc\\", ""),
            ("abc\\0", "0"),
            ("abc\\az", "az"),
            ("abc\\9g", "9g"),
        ],
    )
    def test_fail_invalid_escaped_value(self, value: str, err_msg: str) -> None:
        ldap_filter = f"foo={value}"
        expected = f"Invalid hex characters following \\ '{err_msg}', requires 2 [0-9a-fA-F]"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 4
        assert exc.value.length == len(value)

    def test_parse_with_whitespace(self) -> None:
        actual = f.LDAPFilter.from_string("   (   foo=bar )   ")
        assert isinstance(actual, f.FilterEquality)
        assert actual.attribute == "foo"
        assert actual.value == b"bar "

    def test_parse_complex_with_whitespace(self) -> None:
        actual = f.LDAPFilter.from_string("   (! (  foo=bar ) )  ")
        assert isinstance(actual, f.FilterNot)
        assert isinstance(actual.filter, f.FilterEquality)
        assert actual.filter.attribute == "foo"
        assert actual.filter.value == b"bar "


class TestFilterAnd:
    def test_simple(self) -> None:
        ldap_filter = "(&(foo=bar)(attr=*))"
        actual = f.LDAPFilter.from_string(ldap_filter)

        assert isinstance(actual, f.FilterAnd)
        assert str(actual) == ldap_filter
        assert len(actual.filters) == 2

        assert isinstance(actual.filters[0], f.FilterEquality)
        assert actual.filters[0].attribute == "foo"
        assert actual.filters[0].value == b"bar"

        assert isinstance(actual.filters[1], f.FilterPresent)
        assert actual.filters[1].attribute == "attr"

    def test_compound(self) -> None:
        ldap_filter = "(&(foo=bar)(&(attr=abc*test*end)(attr:rule:=test)(&(test>=1))))"
        actual = f.LDAPFilter.from_string(ldap_filter)

        assert isinstance(actual, f.FilterAnd)
        assert str(actual) == ldap_filter
        assert len(actual.filters) == 2

        assert isinstance(actual.filters[0], f.FilterEquality)
        assert actual.filters[0].attribute == "foo"
        assert actual.filters[0].value == b"bar"

        assert isinstance(actual.filters[1], f.FilterAnd)
        assert len(actual.filters[1].filters) == 3

        assert isinstance(actual.filters[1].filters[0], f.FilterSubstrings)
        assert actual.filters[1].filters[0].attribute == "attr"
        assert actual.filters[1].filters[0].initial == b"abc"
        assert actual.filters[1].filters[0].any == [b"test"]
        assert actual.filters[1].filters[0].final == b"end"

        assert isinstance(actual.filters[1].filters[1], f.FilterExtensibleMatch)
        assert actual.filters[1].filters[1].attribute == "attr"
        assert actual.filters[1].filters[1].dn_attributes is False
        assert actual.filters[1].filters[1].rule == "rule"
        assert actual.filters[1].filters[1].value == b"test"

        assert isinstance(actual.filters[1].filters[2], f.FilterAnd)
        assert len(actual.filters[1].filters[2].filters) == 1

        assert isinstance(actual.filters[1].filters[2].filters[0], f.FilterGreaterOrEqual)
        assert actual.filters[1].filters[2].filters[0].attribute == "test"
        assert actual.filters[1].filters[2].filters[0].value == b"1"

    @pytest.mark.parametrize(
        "ldap_filter, expected",
        [
            (
                "(&(foo=bar)(attr=*))",
                "oBKjCgQDZm9vBANiYXKHBGF0dHI=",
            ),
            (
                "(&(foo=bar)(&(attr=abc*test*end)(attr:rule:=test)(&(test>=1))))",
                "oEmjCgQDZm9vBANiYXKgO6QYBARhdHRyMBCAA2FiY4EEdGVzdIIDZW5kqRKBBHJ1bGWCBGF0dHKDBHRlc3SgC6UJBAR0ZXN0BAEx",
            ),
        ],
        ids=["simple", "complex"],
    )
    def test_roundtrip(self, ldap_filter: str, expected: str) -> None:
        expected_data = base64.b64decode(expected)

        actual_filter = f.LDAPFilter.from_string(ldap_filter)
        assert str(actual_filter) == ldap_filter

        actual_data = pack_filter(actual_filter)
        assert actual_data == expected_data

        unpacked_filter = unpack_filter(actual_data)
        assert str(unpacked_filter) == ldap_filter

    def test_fail_from_string_no_new_group(self) -> None:
        ldap_filter = "(&(objectClass=*)foo=bar)"
        expected = "Expecting ')' to end complex filter expression"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 17
        assert exc.value.length == 1

    def test_fail_from_string_not_started(self) -> None:
        ldap_filter = "(&objectClass=*)"
        expected = "Expecting '(' to start after qualifier in complex filter expression"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 2
        assert exc.value.length == 1

    def test_fail_from_string_no_value(self) -> None:
        ldap_filter = "(&)"
        expected = "No filter value found after conditional"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 1
        assert exc.value.length == 2

    def test_unpack(self) -> None:
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


class TestFilterOr:
    def test_simple(self) -> None:
        ldap_filter = "(|(foo=bar)(attr=*))"

        actual = f.LDAPFilter.from_string(ldap_filter)

        assert isinstance(actual, f.FilterOr)
        assert str(actual) == ldap_filter
        assert len(actual.filters) == 2

        assert isinstance(actual.filters[0], f.FilterEquality)
        assert actual.filters[0].attribute == "foo"
        assert actual.filters[0].value == b"bar"

        assert isinstance(actual.filters[1], f.FilterPresent)
        assert actual.filters[1].attribute == "attr"

    def test_compound(self) -> None:
        ldap_filter = "(|(foo=bar)(|(attr=*)(attr:dn:rule:=test)(&(test<=1))))"
        actual = f.LDAPFilter.from_string(ldap_filter)

        assert isinstance(actual, f.FilterOr)
        assert str(actual) == ldap_filter
        assert len(actual.filters) == 2

        assert isinstance(actual.filters[0], f.FilterEquality)
        assert actual.filters[0].attribute == "foo"
        assert actual.filters[0].value == b"bar"

        assert isinstance(actual.filters[1], f.FilterOr)
        assert len(actual.filters[1].filters) == 3

        assert isinstance(actual.filters[1].filters[0], f.FilterPresent)
        assert actual.filters[1].filters[0].attribute == "attr"

        assert isinstance(actual.filters[1].filters[1], f.FilterExtensibleMatch)
        assert actual.filters[1].filters[1].attribute == "attr"
        assert actual.filters[1].filters[1].dn_attributes is True
        assert actual.filters[1].filters[1].rule == "rule"
        assert actual.filters[1].filters[1].value == b"test"

        assert isinstance(actual.filters[1].filters[2], f.FilterAnd)
        assert len(actual.filters[1].filters[2].filters) == 1

        assert isinstance(actual.filters[1].filters[2].filters[0], f.FilterLessOrEqual)
        assert actual.filters[1].filters[2].filters[0].attribute == "test"

    @pytest.mark.parametrize(
        "ldap_filter, expected",
        [
            (
                "(|(foo=bar)(attr=*))",
                "oRKjCgQDZm9vBANiYXKHBGF0dHI=",
            ),
            (
                "(|(foo=bar)(|(attr=*)(attr:dn:rule:=test)(&(test<=1))))",
                "oTijCgQDZm9vBANiYXKhKocEYXR0cqkVgQRydWxlggRhdHRygwR0ZXN0hAH/oAumCQQEdGVzdAQBMQ==",
            ),
        ],
        ids=["simple", "complex"],
    )
    def test_roundtrip(self, ldap_filter: str, expected: str) -> None:
        expected_data = base64.b64decode(expected)

        actual_filter = f.LDAPFilter.from_string(ldap_filter)
        assert str(actual_filter) == ldap_filter

        actual_data = pack_filter(actual_filter)
        assert actual_data == expected_data

        unpacked_filter = unpack_filter(actual_data)
        assert str(unpacked_filter) == ldap_filter

    def test_fail_from_string_no_new_group(self) -> None:
        ldap_filter = "(|(objectClass=*)foo=bar)"
        expected = "Expecting ')' to end complex filter expression"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 17
        assert exc.value.length == 1

    def test_fail_from_string_not_started(self) -> None:
        ldap_filter = "(|objectClass=*)"
        expected = "Expecting '(' to start after qualifier in complex filter expression"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 2
        assert exc.value.length == 1

    def test_fail_from_string_no_value(self) -> None:
        ldap_filter = "(|)"
        expected = "No filter value found after conditional"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 1
        assert exc.value.length == 2

    def test_unpack(self) -> None:
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


class TestFilterNot:
    def test_simple(self) -> None:
        ldap_filter = "(!(foo=bar))"

        actual = f.LDAPFilter.from_string(ldap_filter)

        assert isinstance(actual, f.FilterNot)
        assert str(actual) == ldap_filter
        assert isinstance(actual.filter, f.FilterEquality)
        assert actual.filter.attribute == "foo"
        assert actual.filter.value == b"bar"

    def test_compound(self) -> None:
        ldap_filter = "(!(!(foo=bar)))"

        actual = f.LDAPFilter.from_string(ldap_filter)

        assert isinstance(actual, f.FilterNot)
        assert str(actual) == ldap_filter
        assert isinstance(actual.filter, f.FilterNot)

        assert isinstance(actual.filter.filter, f.FilterEquality)
        assert actual.filter.filter.attribute == "foo"
        assert actual.filter.filter.value == b"bar"

    @pytest.mark.parametrize(
        "ldap_filter, expected",
        [
            (
                "(!(foo=bar))",
                "ogyjCgQDZm9vBANiYXI=",
            ),
            (
                "(!(!(foo=bar)))",
                "og6iDKMKBANmb28EA2Jhcg==",
            ),
        ],
        ids=["simple", "complex"],
    )
    def test_roundtrip(self, ldap_filter: str, expected: str) -> None:
        expected_data = base64.b64decode(expected)

        actual_filter = f.LDAPFilter.from_string(ldap_filter)
        assert str(actual_filter) == ldap_filter

        actual_data = pack_filter(actual_filter)
        assert actual_data == expected_data

        unpacked_filter = unpack_filter(actual_data)
        assert str(unpacked_filter) == ldap_filter

    def test_fail_multiple_values(self) -> None:
        ldap_filter = "(!(objectClass=*)(foo=bar))"
        expected = "Multiple filters found for not '!' expression"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 1
        assert exc.value.length == 26

    def test_fail_from_string_not_started(self) -> None:
        ldap_filter = "(!objectClass=*)"
        expected = "Expecting '(' to start after qualifier in complex filter expression"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 2
        assert exc.value.length == 1

    def test_fail_from_string_no_value(self) -> None:
        ldap_filter = "(!)"
        expected = "No filter value found after conditional"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 1
        assert exc.value.length == 2

    def test_unpack(self) -> None:
        data = base64.b64decode("og6iDKMKBANmb28EA2Jhcg==")
        actual = unpack_filter(data)

        assert isinstance(actual, f.FilterNot)
        assert isinstance(actual.filter, f.FilterNot)
        assert isinstance(actual.filter.filter, f.FilterEquality)
        assert actual.filter.filter.attribute == "foo"
        assert actual.filter.filter.value == b"bar"


class TestFilterEquality:
    @pytest.mark.parametrize(
        "filter, attribute, value",
        [
            ("objectClass=user", "objectClass", b"user"),
            ("(objectClass=user)", "objectClass", b"user"),
            ("objectClass;test=abc\\20def", "objectClass;test", b"abc def"),
            (b"(foo=\xFFtest\xF1\x1F)".decode("utf-8", errors="surrogateescape"), "foo", b"\xFFtest\xF1\x1F"),
        ],
        ids=[
            "not_wrapped",
            "wrapped",
            "attr_comment",
            "embedded_bytes",
        ],
    )
    def test_from_string(
        self,
        filter: str,
        attribute: str,
        value: bytes,
    ) -> None:
        actual = f.LDAPFilter.from_string(filter)
        assert isinstance(actual, f.FilterEquality)
        assert actual.attribute == attribute
        assert actual.value == value

    def test_stringify(self) -> None:
        expected = "(foo=happy \\e2\\98\\ba caf\\c3\\a9\\2a\\00)"
        filter = f.LDAPFilter.from_string(r"foo=happy\20☺ café\2a\00")

        assert isinstance(filter, f.FilterEquality)
        assert str(filter) == expected

    def test_roundtrip(self) -> None:
        ldap_filter = r"(objectClass;test=abc def \e2\98\ba caf\c3\a9)"
        expected_data = base64.b64decode("oyUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp")

        actual_filter = f.LDAPFilter.from_string(ldap_filter)
        assert str(actual_filter) == ldap_filter

        actual_data = pack_filter(actual_filter)
        assert actual_data == expected_data

        unpacked_filter = unpack_filter(actual_data)
        assert str(unpacked_filter) == ldap_filter

    def test_unpack(self) -> None:
        data = base64.b64decode("oyUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp")
        actual = unpack_filter(data)

        assert isinstance(actual, f.FilterEquality)
        assert actual.attribute == "objectClass;test"
        assert actual.value == "abc def ☺ café".encode("utf-8")


class TestFilterSubstrings:
    @pytest.mark.parametrize(
        "filter_str, attribute, initial, any_values, final",
        [
            ("attr=test*value", "attr", b"test", [], b"value"),
            ("attr=test*", "attr", b"test", [], None),
            ("attr=*test", "attr", None, [], b"test"),
            ("attr=initial*any*final", "attr", b"initial", [b"any"], b"final"),
            ("attr=*any1*any2*", "attr", None, [b"any1", b"any2"], None),
            ("attr=*any1*any2*final", "attr", None, [b"any1", b"any2"], b"final"),
            ("attr=initial*any1*any2*", "attr", b"initial", [b"any1", b"any2"], None),
            ("attr=initial*any1*any2*final", "attr", b"initial", [b"any1", b"any2"], b"final"),
        ],
        ids=[
            "no_any",
            "no_any_and_final",
            "no_any_and_initial",
            "all_three",
            "multiple_any_no_initial_and_final",
            "multiple_any_no_initial",
            "multiple_any_no_final",
            "multiple_any",
        ],
    )
    def test_from_string(
        self,
        filter_str: str,
        attribute: str,
        initial: t.Optional[bytes],
        any_values: t.List[bytes],
        final: t.Optional[bytes],
    ) -> None:
        for wrapping in ["{}", "({})"]:
            actual = f.LDAPFilter.from_string(wrapping.format(filter_str))
            assert isinstance(actual, f.FilterSubstrings)
            assert actual.attribute == attribute
            assert actual.initial == initial
            assert actual.any == any_values
            assert actual.final == final

    @pytest.mark.parametrize(
        "ldap_filter, offset, length",
        [
            ("(attr=**)", 6, 2),
            ("(attr=initial**)", 6, 9),
            ("(attr=**final)", 6, 7),
            ("(attr=*any**final)", 6, 11),
            ("(attr=initial**any*final)", 6, 18),
            ("(attr=initial*any**any*final)", 6, 22),
        ],
    )
    def test_fail_multiple_asterisk(self, ldap_filter: str, offset: int, length: int) -> None:
        expected = "Cannot have 2 consecutive '*' in substring filter value"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == offset
        assert exc.value.length == length

    @pytest.mark.parametrize(
        "attribute, initial, any_values, final, expected",
        [
            (
                "foo",
                None,
                ["happy ☺".encode("utf-8"), "café*".encode("utf-8")],
                None,
                r"(foo=*happy \e2\98\ba*caf\c3\a9\2a*)",
            ),
            (
                "foo",
                "happy ☺".encode("utf-8"),
                [],
                None,
                r"(foo=happy \e2\98\ba*)",
            ),
            (
                "foo",
                None,
                [],
                "happy ☺".encode("utf-8"),
                r"(foo=*happy \e2\98\ba)",
            ),
            (
                "foo",
                "happy ☺".encode("utf-8"),
                ["happy ☺".encode("utf-8"), "café*".encode("utf-8")],
                None,
                r"(foo=happy \e2\98\ba*happy \e2\98\ba*caf\c3\a9\2a*)",
            ),
            (
                "foo",
                None,
                ["happy ☺".encode("utf-8"), "café*".encode("utf-8")],
                "happy ☺".encode("utf-8"),
                r"(foo=*happy \e2\98\ba*caf\c3\a9\2a*happy \e2\98\ba)",
            ),
            (
                "foo",
                "happy ☺".encode("utf-8"),
                [],
                "happy ☺".encode("utf-8"),
                r"(foo=happy \e2\98\ba*happy \e2\98\ba)",
            ),
            (
                "foo",
                "happy ☺".encode("utf-8"),
                ["happy ☺".encode("utf-8"), "café*".encode("utf-8")],
                "happy ☺".encode("utf-8"),
                r"(foo=happy \e2\98\ba*happy \e2\98\ba*caf\c3\a9\2a*happy \e2\98\ba)",
            ),
        ],
        ids=[
            "only_any",
            "initial_only",
            "final_only",
            "initial_any",
            "final_any",
            "initial_final",
            "initial_any_final",
        ],
    )
    def test_stringify(
        self,
        attribute: str,
        initial: t.Optional[bytes],
        any_values: t.List[bytes],
        final: t.Optional[bytes],
        expected: str,
    ) -> None:
        filter = f.FilterSubstrings(
            attribute=attribute,
            initial=initial,
            any=any_values,
            final=final,
        )

        assert str(filter) == expected

    @pytest.mark.parametrize(
        "ldap_filter, expected",
        [
            (
                r"(objectClass;test=*abc *def \e2\98\ba *caf\c3\a9*)",
                "pCsEEG9iamVjdENsYXNzO3Rlc3QwF4EEYWJjIIEIZGVmIOKYuiCBBWNhZsOp",
            ),
            (
                r"(objectClass;test=abc *def \e2\98\ba *caf\c3\a9*)",
                "pCsEEG9iamVjdENsYXNzO3Rlc3QwF4AEYWJjIIEIZGVmIOKYuiCBBWNhZsOp",
            ),
            (
                r"(objectClass;test=*abc *def \e2\98\ba *caf\c3\a9)",
                "pCsEEG9iamVjdENsYXNzO3Rlc3QwF4EEYWJjIIEIZGVmIOKYuiCCBWNhZsOp",
            ),
            (
                r"(objectClass;test=abc *def \e2\98\ba *caf\c3\a9)",
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
    def test_roundtrip(self, ldap_filter: str, expected: str) -> None:
        expected_data = base64.b64decode(expected)

        actual_filter = f.LDAPFilter.from_string(ldap_filter)
        assert str(actual_filter) == ldap_filter

        actual_data = pack_filter(actual_filter)
        assert actual_data == expected_data

        unpacked_filter = unpack_filter(actual_data)
        assert str(unpacked_filter) == ldap_filter

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
    def test_unpack(
        self,
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

    def test_unpack_ignore_untagged_values(self) -> None:
        data = base64.b64decode("pBQEBGF0dHIwDJ+IAANhYmOBA2FiYw==")

        actual = unpack_filter(data)
        assert isinstance(actual, f.FilterSubstrings)
        assert actual.attribute == "attr"
        assert actual.initial is None
        assert actual.any == [b"abc"]
        assert actual.final is None

    def test_fail_unpack_multiple_initial(self) -> None:
        expected = "Received multiple initial values when unpacking Filter.substrings"
        data = base64.b64decode("pBIEBGF0dHIwCoADYWJjgANhYmM=")

        with pytest.raises(ValueError, match=re.escape(expected)):
            unpack_filter(data)

    def test_fail_unpack_multiple_final(self) -> None:
        expected = "Received multiple final values when unpacking Filter.substrings"
        data = base64.b64decode("pBIEBGF0dHIwCoIDYWJjggNhYmM=")

        with pytest.raises(ValueError, match=re.escape(expected)):
            unpack_filter(data)


class TestFilterGreaterOrEqual:
    @pytest.mark.parametrize(
        "filter, attribute, value",
        [
            ("objectClass>=user", "objectClass", b"user"),
            ("(objectClass>=user)", "objectClass", b"user"),
            ("objectClass;test>=abc\\20def", "objectClass;test", b"abc def"),
            (b"(foo>=\xFFtest\xF1\x1F)".decode("utf-8", errors="surrogateescape"), "foo", b"\xFFtest\xF1\x1F"),
        ],
        ids=[
            "not_wrapped",
            "wrapped",
            "attr_comment",
            "embedded_bytes",
        ],
    )
    def test_from_string(
        self,
        filter: str,
        attribute: str,
        value: bytes,
    ) -> None:
        actual = f.LDAPFilter.from_string(filter)
        assert isinstance(actual, f.FilterGreaterOrEqual)
        assert actual.attribute == attribute
        assert actual.value == value

    def test_stringify(self) -> None:
        expected = "(foo>=happy \\e2\\98\\ba caf\\c3\\a9\\2a\\00)"
        filter = f.LDAPFilter.from_string(r"foo>=happy\20☺ café\2a\00")

        assert isinstance(filter, f.FilterGreaterOrEqual)
        assert str(filter) == expected

    def test_roundtrip(self) -> None:
        ldap_filter = r"(objectClass;test>=abc def \e2\98\ba caf\c3\a9)"
        expected_data = base64.b64decode("pSUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp")

        actual_filter = f.LDAPFilter.from_string(ldap_filter)
        assert str(actual_filter) == ldap_filter

        actual_data = pack_filter(actual_filter)
        assert actual_data == expected_data

        unpacked_filter = unpack_filter(actual_data)
        assert str(unpacked_filter) == ldap_filter

    def test_unpack(self) -> None:
        data = base64.b64decode("pSUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp")
        actual = unpack_filter(data)

        assert isinstance(actual, f.FilterGreaterOrEqual)
        assert actual.attribute == "objectClass;test"
        assert actual.value == "abc def ☺ café".encode("utf-8")


class TestFilterLessOrEqual:
    @pytest.mark.parametrize(
        "filter, attribute, value",
        [
            ("objectClass<=user", "objectClass", b"user"),
            ("(objectClass<=user)", "objectClass", b"user"),
            ("objectClass;test<=abc\\20def", "objectClass;test", b"abc def"),
            (b"(foo<=\xFFtest\xF1\x1F)".decode("utf-8", errors="surrogateescape"), "foo", b"\xFFtest\xF1\x1F"),
        ],
        ids=[
            "not_wrapped",
            "wrapped",
            "attr_comment",
            "embedded_bytes",
        ],
    )
    def test_from_string(
        self,
        filter: str,
        attribute: str,
        value: bytes,
    ) -> None:
        actual = f.LDAPFilter.from_string(filter)
        assert isinstance(actual, f.FilterLessOrEqual)
        assert actual.attribute == attribute
        assert actual.value == value

    def test_stringify(self) -> None:
        expected = "(foo<=happy \\e2\\98\\ba caf\\c3\\a9\\2a\\00)"
        filter = f.LDAPFilter.from_string(r"foo<=happy\20☺ café\2a\00")

        assert isinstance(filter, f.FilterLessOrEqual)
        assert str(filter) == expected

    def test_roundtrip(self) -> None:
        ldap_filter = r"(objectClass;test<=abc def \e2\98\ba caf\c3\a9)"
        expected_data = base64.b64decode("piUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp")

        actual_filter = f.LDAPFilter.from_string(ldap_filter)
        assert str(actual_filter) == ldap_filter

        actual_data = pack_filter(actual_filter)
        assert actual_data == expected_data

        unpacked_filter = unpack_filter(actual_data)
        assert str(unpacked_filter) == ldap_filter

    def test_unpack(self) -> None:
        data = base64.b64decode("piUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp")
        actual = unpack_filter(data)

        assert isinstance(actual, f.FilterLessOrEqual)
        assert actual.attribute == "objectClass;test"
        assert actual.value == "abc def ☺ café".encode("utf-8")


class TestFilterPresent:
    @pytest.mark.parametrize(
        "filter_str, attribute",
        [
            ("objectClass=*", "objectClass"),
            ("(objectClass=*)", "objectClass"),
            ("objectClass;test=*", "objectClass;test"),
            ("(objectClass;test=*)", "objectClass;test"),
            ("1.2.3.4.0.12912=*", "1.2.3.4.0.12912"),
            ("(1.2.3.4.0.12912=*)", "1.2.3.4.0.12912"),
            ("1.2.3.4.0.12912;comment=*", "1.2.3.4.0.12912;comment"),
            ("(1.2.3.4.0.12912;comment=*)", "1.2.3.4.0.12912;comment"),
        ],
        ids=[
            "name",
            "name_wrapped",
            "name_options",
            "name_options_wrapped",
            "oid",
            "oid_wrapped",
            "oid_options",
            "oid_options_wrapped",
        ],
    )
    def test_from_string(
        self,
        filter_str: str,
        attribute: str,
    ) -> None:
        actual = f.LDAPFilter.from_string(filter_str)
        assert isinstance(actual, f.FilterPresent)
        assert actual.attribute == attribute
        assert str(actual) == f"({actual.attribute}=*)"

    def test_roundtrip(self) -> None:
        ldap_filter = "(1.2.3.341.0.1;test=*)"
        expected_data = base64.b64decode("hxIxLjIuMy4zNDEuMC4xO3Rlc3Q=")

        actual_filter = f.LDAPFilter.from_string(ldap_filter)
        assert str(actual_filter) == ldap_filter

        actual_data = pack_filter(actual_filter)
        assert actual_data == expected_data

        unpacked_filter = unpack_filter(actual_data)
        assert str(unpacked_filter) == ldap_filter

    def test_unpack(self) -> None:
        data = base64.b64decode("hxIxLjIuMy4zNDEuMC4xO3Rlc3Q=")
        actual = unpack_filter(data)

        assert isinstance(actual, f.FilterPresent)
        assert actual.attribute == "1.2.3.341.0.1;test"


class TestFilterApproxMatch:
    @pytest.mark.parametrize(
        "filter, attribute, value",
        [
            ("objectClass~=user", "objectClass", b"user"),
            ("(objectClass~=user)", "objectClass", b"user"),
            ("objectClass;test~=abc\\20def", "objectClass;test", b"abc def"),
            (b"(foo~=\xFFtest\xF1\x1F)".decode("utf-8", errors="surrogateescape"), "foo", b"\xFFtest\xF1\x1F"),
        ],
        ids=[
            "not_wrapped",
            "wrapped",
            "attr_comment",
            "embedded_bytes",
        ],
    )
    def test_from_string(
        self,
        filter: str,
        attribute: str,
        value: bytes,
    ) -> None:
        actual = f.LDAPFilter.from_string(filter)
        assert isinstance(actual, f.FilterApproxMatch)
        assert actual.attribute == attribute
        assert actual.value == value

    def test_stringify(self) -> None:
        expected = "(foo~=happy \\e2\\98\\ba caf\\c3\\a9\\2a\\00)"
        filter = f.LDAPFilter.from_string(r"foo~=happy\20☺ café\2a\00")

        assert isinstance(filter, f.FilterApproxMatch)
        assert str(filter) == expected

    def test_roundtrip(self) -> None:
        ldap_filter = r"(objectClass;test~=abc def \e2\98\ba caf\c3\a9)"
        expected_data = base64.b64decode("qCUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp")

        actual_filter = f.LDAPFilter.from_string(ldap_filter)
        assert str(actual_filter) == ldap_filter

        actual_data = pack_filter(actual_filter)
        assert actual_data == expected_data

        unpacked_filter = unpack_filter(actual_data)
        assert str(unpacked_filter) == ldap_filter

    def test_unpack(self) -> None:
        data = base64.b64decode("qCUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp")
        actual = unpack_filter(data)

        assert isinstance(actual, f.FilterApproxMatch)
        assert actual.attribute == "objectClass;test"
        assert actual.value == "abc def ☺ café".encode("utf-8")


class TestFilterExtensibleMatch:
    @pytest.mark.parametrize(
        "filter_str, attribute, dn_attributes, rule, value",
        [
            ("attr:=value", "attr", False, None, b"value"),
            ("0:=value", "0", False, None, b"value"),
            ("1.2:=value", "1.2", False, None, b"value"),
            ("1.0.2;option1:=value", "1.0.2;option1", False, None, b"value"),
            (
                "4.0.58;option1;x-Option2;-Option3;dn:=value",
                "4.0.58;option1;x-Option2;-Option3;dn",
                False,
                None,
                b"value",
            ),
            ("attr:dn:=value", "attr", True, None, b"value"),
            ("2.20.2495;option:dn:=value", "2.20.2495;option", True, None, b"value"),
            ("attr:rule:=value", "attr", False, "rule", b"value"),
            ("attr:dn:rule:=value", "attr", True, "rule", b"value"),
            (
                "attr;option1;x-option2;-option3:rule;option1;x-option2;-Option3:=value",
                "attr;option1;x-option2;-option3",
                False,
                "rule;option1;x-option2;-Option3",
                b"value",
            ),
            (
                "attr;option1;x-option2;-option3:dn:rule;option1;x-option2;-Option3:=value",
                "attr;option1;x-option2;-option3",
                True,
                "rule;option1;x-option2;-Option3",
                b"value",
            ),
            (":rule:=value", None, False, "rule", b"value"),
            (":rule;option1-;-option2:=value", None, False, "rule;option1-;-option2", b"value"),
            (":0:=value", None, False, "0", b"value"),
            (":0.1:=value", None, False, "0.1", b"value"),
            (":9.0:=value", None, False, "9.0", b"value"),
            (":3.84196.0.156:=value", None, False, "3.84196.0.156", b"value"),
            (":dn:rule:=value", None, True, "rule", b"value"),
            (":dn:rule;option1-;option2:=value", None, True, "rule;option1-;option2", b"value"),
            (":dn:6.54.0.58:=value", None, True, "6.54.0.58", b"value"),
        ],
        ids=[
            "only_attribute",
            "only_attribute_oid_0",
            "only_attribute_oid",
            "only_attribute_oid_options",
            "only_attribute_multiple_options",
            "attribute_dn",
            "attribute_oid_dn",
            "attribute_rule",
            "attribute_dn_rule",
            "attribute_rule_options",
            "attribute_dn_rule_options",
            "only_rule",
            "only_rule_options",
            "only_rule_oid_0",
            "only_rule_oid_decimal",
            "only_rule_oid_trailing_0",
            "only_rule_oid",
            "only_rule_dn",
            "only_rule_dn_options",
            "only_rule_dn_oid",
        ],
    )
    def test_from_string(
        self,
        filter_str: str,
        attribute: t.Optional[str],
        dn_attributes: bool,
        rule: t.Optional[str],
        value: bytes,
    ) -> None:
        for wrapping in ["{}", "({})"]:
            actual = f.LDAPFilter.from_string(wrapping.format(filter_str))

            assert isinstance(actual, f.FilterExtensibleMatch)
            assert actual.attribute == attribute
            assert actual.dn_attributes == dn_attributes
            assert actual.rule == rule
            assert actual.value == value

    def test_fail_no_attribute_or_rule(self) -> None:
        ldap_filter = "(:=value)"
        expected = "Filter must define an attribute name before the equal symbol"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 1
        assert exc.value.length == 8

    def test_fail_invalid_attribute(self) -> None:
        ldap_filter = "(1attribute:=value)"
        expected = "Invalid extensible filter attribute"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 1
        assert exc.value.length == 10

    def test_fail_invalid_rule(self) -> None:
        ldap_filter = "(:1rule:=value)"
        expected = "Invalid extensible filter rule"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(ldap_filter)

        assert exc.value.filter == ldap_filter
        assert exc.value.offset == 1
        assert exc.value.length == 6

    @pytest.mark.parametrize(
        "filter_str, length",
        [
            ("(attr:rule:extra:=value)", 15),
            ("(attr:dn:rule:extra:=value)", 18),
        ],
    )
    def test_fail_extra_data(self, filter_str: str, length: int) -> None:
        expected = "Extra data found in extensible filter header"

        with pytest.raises(f.FilterSyntaxError, match=re.escape(expected)) as exc:
            f.LDAPFilter.from_string(filter_str)

        assert exc.value.filter == filter_str
        assert exc.value.offset == 1
        assert exc.value.length == length

    @pytest.mark.parametrize(
        "ldap_filter, expected",
        [
            (
                r"(objectClass:=def \e2\98\ba)",
                "qRaCC29iamVjdENsYXNzgwdkZWYg4pi6",
            ),
            (
                r"(objectClass:dn:=def \e2\98\ba)",
                "qRmCC29iamVjdENsYXNzgwdkZWYg4pi6hAH/",
            ),
            (
                r"(:rule:=def \e2\98\ba)",
                "qQ+BBHJ1bGWDB2RlZiDimLo=",
            ),
            (
                r"(:dn:rule:=def \e2\98\ba)",
                "qRKBBHJ1bGWDB2RlZiDimLqEAf8=",
            ),
            (
                r"(objectClass:rule:=def \e2\98\ba)",
                "qRyBBHJ1bGWCC29iamVjdENsYXNzgwdkZWYg4pi6",
            ),
            (
                r"(objectClass:dn:rule:=def \e2\98\ba)",
                "qR+BBHJ1bGWCC29iamVjdENsYXNzgwdkZWYg4pi6hAH/",
            ),
        ],
        ids=[
            "only_attribute",
            "only_attribute_dn",
            "only_rule",
            "only_rule_dn",
            "attribute_and_rule",
            "attribute_and_rule_dn",
        ],
    )
    def test_roundtrip(self, ldap_filter: str, expected: str) -> None:
        expected_data = base64.b64decode(expected)

        actual_filter = f.LDAPFilter.from_string(ldap_filter)
        assert str(actual_filter) == ldap_filter

        actual_data = pack_filter(actual_filter)
        assert actual_data == expected_data

        unpacked_filter = unpack_filter(actual_data)
        assert str(unpacked_filter) == ldap_filter

    @pytest.mark.parametrize(
        "attribute, dn_attributes, rule, value, data, expected_str",
        [
            (
                "objectClass",
                False,
                None,
                "def ☺".encode("utf-8"),
                "qRaCC29iamVjdENsYXNzgwdkZWYg4pi6",
                r"(objectClass:=def \e2\98\ba)",
            ),
            (
                "objectClass",
                True,
                None,
                "def ☺".encode("utf-8"),
                "qRmCC29iamVjdENsYXNzgwdkZWYg4pi6hAH/",
                r"(objectClass:dn:=def \e2\98\ba)",
            ),
            (
                None,
                False,
                "rule",
                "def ☺".encode("utf-8"),
                "qQ+BBHJ1bGWDB2RlZiDimLo=",
                r"(:rule:=def \e2\98\ba)",
            ),
            (
                None,
                True,
                "rule",
                "def ☺".encode("utf-8"),
                "qRKBBHJ1bGWDB2RlZiDimLqEAf8=",
                r"(:dn:rule:=def \e2\98\ba)",
            ),
            (
                "objectClass",
                False,
                "rule",
                "def ☺".encode("utf-8"),
                "qRyBBHJ1bGWCC29iamVjdENsYXNzgwdkZWYg4pi6",
                r"(objectClass:rule:=def \e2\98\ba)",
            ),
            (
                "objectClass",
                True,
                "rule",
                "def ☺".encode("utf-8"),
                "qR+BBHJ1bGWCC29iamVjdENsYXNzgwdkZWYg4pi6hAH/",
                r"(objectClass:dn:rule:=def \e2\98\ba)",
            ),
        ],
        ids=[
            "only_attribute",
            "only_attribute_dn",
            "only_rule",
            "only_rule_dn",
            "attribute_and_rule",
            "attribute_and_rule_dn",
        ],
    )
    def test_unpack(
        self,
        attribute: t.Optional[str],
        dn_attributes: bool,
        rule: t.Optional[str],
        value: bytes,
        data: str,
        expected_str: str,
    ) -> None:
        b_data = base64.b64decode(data)
        actual = unpack_filter(b_data)

        assert isinstance(actual, f.FilterExtensibleMatch)
        assert actual.attribute == attribute
        assert actual.dn_attributes == dn_attributes
        assert actual.rule == rule
        assert actual.value == value
        assert str(actual) == expected_str

    def test_unpack_ignore_untagged_values(self) -> None:
        data = base64.b64decode("qRqfiAADZm9vgQRydWxlggRhdHRygwV2YWx1ZQ==")

        actual = unpack_filter(data)
        assert isinstance(actual, f.FilterExtensibleMatch)
        assert actual.rule == "rule"
        assert actual.attribute == "attr"
        assert actual.dn_attributes is False
        assert actual.value == b"value"

    def test_unpack_ignore_untagged_values_not_context_specific(self) -> None:
        data = base64.b64decode("qRgEA2Zvb4EEcnVsZYIEYXR0coMFdmFsdWU=")

        actual = unpack_filter(data)
        assert isinstance(actual, f.FilterExtensibleMatch)
        assert actual.rule == "rule"
        assert actual.attribute == "attr"
        assert actual.dn_attributes is False
        assert actual.value == b"value"


@dataclasses.dataclass(frozen=True)
class CustomFilter(f.LDAPFilter):
    filter_id: int = dataclasses.field(init=False, repr=False, default=1024)

    value: str

    def pack(
        self,
        writer: ASN1Writer,
        options: f.FilterOptions,
    ) -> None:
        writer.write_octet_string(
            self.value.encode(options.string_encoding),
            tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.filter_id, False),
        )

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
        options: f.FilterOptions,
    ) -> CustomFilter:
        value = reader.read_octet_string(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, cls.filter_id, False),
        ).decode(options.string_encoding)
        return CustomFilter(value=value)


class TestFilterCustom:
    def test_pack(self) -> None:
        expected = base64.b64decode("MB8CAQBjGgQACgEACgEAAgEAAgEAAQEAn4gAA2ZvbzAA")
        req = m.SearchRequest(
            message_id=0,
            controls=[],
            base_object="",
            scope=m.SearchScope.BASE,
            deref_aliases=m.DereferencingPolicy.NEVER,
            size_limit=0,
            time_limit=0,
            types_only=False,
            filter=CustomFilter(value="foo"),
            attributes=[],
        )
        actual = req.pack(m.PackingOptions())
        assert actual == expected

    def test_pack_custom_encoding(self) -> None:
        expected = base64.b64decode("MCICAQBjHQQACgEACgEAAgEAAgEAAQEAn4gABmYAbwBvADAA")
        req = m.SearchRequest(
            message_id=0,
            controls=[],
            base_object="",
            scope=m.SearchScope.BASE,
            deref_aliases=m.DereferencingPolicy.NEVER,
            size_limit=0,
            time_limit=0,
            types_only=False,
            filter=CustomFilter(value="foo"),
            attributes=[],
        )
        actual = req.pack(
            m.PackingOptions(
                filter=f.FilterOptions(
                    string_encoding="utf-16-le",
                )
            )
        )
        assert actual == expected

    def test_unpack(self) -> None:
        data = base64.b64decode("MB8CAQBjGgQACgEACgEAAgEAAgEAAQEAn4gAA2ZvbzAA")
        reader = ASN1Reader(data)

        actual = m.unpack_ldap_message(
            reader,
            m.PackingOptions(
                filter=f.FilterOptions(
                    choices=[CustomFilter],
                )
            ),
        )
        assert isinstance(actual, m.SearchRequest)
        assert isinstance(actual.filter, CustomFilter)
        assert actual.filter.value == "foo"

    def test_unpack_custom_encoding(self) -> None:
        data = base64.b64decode("MCICAQBjHQQACgEACgEAAgEAAgEAAQEAn4gABmYAbwBvADAA")
        reader = ASN1Reader(data)

        actual = m.unpack_ldap_message(
            reader,
            m.PackingOptions(
                filter=f.FilterOptions(
                    string_encoding="utf-16-le",
                    choices=[CustomFilter],
                )
            ),
        )
        assert isinstance(actual, m.SearchRequest)
        assert isinstance(actual.filter, CustomFilter)
        assert actual.filter.value == "foo"

    def test_fail_unpack_not_registered(self) -> None:
        expected = "Unknown filter object ASN1Tag(tag_class=<TagClass.CONTEXT_SPECIFIC: 2>, tag_number=1024, is_constructed=False), cannot unpack"

        data = base64.b64decode("MB8CAQBjGgQACgEACgEAAgEAAgEAAQEAn4gAA2ZvbzAA")
        reader = ASN1Reader(data)

        with pytest.raises(NotImplementedError, match=re.escape(expected)):
            m.unpack_ldap_message(reader, m.PackingOptions())

    def test_fail_unpack_filter_not_context_specific(self) -> None:
        expected = "Unknown filter object ASN1Tag(tag_class=<TagClass.UNIVERSAL: 0>, tag_number=<TypeTagNumber.OCTET_STRING: 4>, is_constructed=False), cannot unpack"

        data = base64.b64decode("MB0CAQBjGAQACgEACgEAAgEAAgEAAQEABANmb28wAA==")
        reader = ASN1Reader(data)

        with pytest.raises(NotImplementedError, match=re.escape(expected)):
            m.unpack_ldap_message(reader, m.PackingOptions())
