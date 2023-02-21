# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import pytest

import sansldap.schema as schema


class TestAttributeTypeDescription:
    def test_parse(self) -> None:
        value = "( 2.5.18.1 NAME 'createTimestamp' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )"

        actual = schema.AttributeTypeDescription.from_string(value)
        assert actual.oid == "2.5.18.1"
        assert actual.names == ["createTimestamp"]
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.super_type is None
        assert actual.equality == "generalizedTimeMatch"
        assert actual.ordering == "generalizedTimeOrderingMatch"
        assert actual.substrings is None
        assert actual.syntax == "1.3.6.1.4.1.1466.115.121.1.24"
        assert actual.syntax_length is None
        assert actual.single_value is True
        assert actual.collective is False
        assert actual.no_user_modification is True
        assert actual.usage == "directoryOperation"

        assert str(actual) == value

    def test_parse_with_extensions(self) -> None:
        value = "( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} X-ORIGIN 'RFC 1274' )"

        actual = schema.AttributeTypeDescription.from_string(value)
        assert actual.oid == "0.9.2342.19200300.100.1.1"
        assert actual.names == ["uid"]
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.super_type is None
        assert actual.equality == "caseIgnoreMatch"
        assert actual.ordering is None
        assert actual.substrings == "caseIgnoreSubstringsMatch"
        assert actual.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        assert actual.syntax_length == 256
        assert actual.single_value is False
        assert actual.collective is False
        assert actual.no_user_modification is False
        assert actual.usage == "userApplications"

        # FUTURE: Actually test what extensions were added
        assert (
            str(actual)
            == "( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        )

    def test_parse_ad_syntax_oid(self) -> None:
        value = "( 1.2.840.113556.1.4.149 NAME 'attributeSecurityGUID' SYNTAX '1.3.6.1.4.1.1466.115.121.1.40' SINGLE-VALUE )"

        actual = schema.AttributeTypeDescription.from_string(value)
        assert actual.oid == "1.2.840.113556.1.4.149"
        assert actual.names == ["attributeSecurityGUID"]
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.super_type is None
        assert actual.equality is None
        assert actual.ordering is None
        assert actual.substrings is None
        assert actual.syntax == "1.3.6.1.4.1.1466.115.121.1.40"
        assert actual.syntax_length is None
        assert actual.single_value is True
        assert actual.collective is False
        assert actual.no_user_modification is False
        assert actual.usage == "userApplications"

        assert (
            str(actual)
            == "( 1.2.840.113556.1.4.149 NAME 'attributeSecurityGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )"
        )

    def test_parse_ad_syntax_desc(self) -> None:
        value = "( 1.2.840.113556.1.2.83 NAME 'repsTo' SYNTAX 'OctetString' NO-USER-MODIFICATION )"

        actual = schema.AttributeTypeDescription.from_string(value)
        assert actual.oid == "1.2.840.113556.1.2.83"
        assert actual.names == ["repsTo"]
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.super_type is None
        assert actual.equality is None
        assert actual.ordering is None
        assert actual.substrings is None
        assert actual.syntax == "OctetString"
        assert actual.syntax_length is None
        assert actual.single_value is False
        assert actual.collective is False
        assert actual.no_user_modification is True
        assert actual.usage == "userApplications"

        assert str(actual) == "( 1.2.840.113556.1.2.83 NAME 'repsTo' SYNTAX OctetString NO-USER-MODIFICATION )"

    def test_parse_no_names(self) -> None:
        value = "( 1.0 )"

        actual = schema.AttributeTypeDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == []
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.super_type is None
        assert actual.equality is None
        assert actual.ordering is None
        assert actual.substrings is None
        assert actual.syntax is None
        assert actual.syntax_length is None
        assert actual.single_value is False
        assert actual.collective is False
        assert actual.no_user_modification is False
        assert actual.usage == "userApplications"

        assert str(actual) == value

    def test_parse_multiple_names(self) -> None:
        value = "(1.0  NAME ('name1' 'name2' ) )"

        actual = schema.AttributeTypeDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == ["name1", "name2"]
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.super_type is None
        assert actual.equality is None
        assert actual.ordering is None
        assert actual.substrings is None
        assert actual.syntax is None
        assert actual.syntax_length is None
        assert actual.single_value is False
        assert actual.collective is False
        assert actual.no_user_modification is False
        assert actual.usage == "userApplications"

        assert str(actual) == "( 1.0 NAME ( 'name1' 'name2' ) )"

    def test_parse_with_description(self) -> None:
        value = "( 1.0 DESC   'foo \\5c\\27bar\\5C\\27' )"

        actual = schema.AttributeTypeDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == []
        assert actual.description == "foo \\'bar\\'"
        assert actual.obsolete is False
        assert actual.super_type is None
        assert actual.equality is None
        assert actual.ordering is None
        assert actual.substrings is None
        assert actual.syntax is None
        assert actual.syntax_length is None
        assert actual.single_value is False
        assert actual.collective is False
        assert actual.no_user_modification is False
        assert actual.usage == "userApplications"

        assert str(actual) == "( 1.0 DESC 'foo \\5c\\27bar\\5c\\27' )"

    def test_parse_with_obsolete(self) -> None:
        value = "( 1.0 OBSOLETE )"

        actual = schema.AttributeTypeDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == []
        assert actual.description is None
        assert actual.obsolete is True
        assert actual.super_type is None
        assert actual.equality is None
        assert actual.ordering is None
        assert actual.substrings is None
        assert actual.syntax is None
        assert actual.syntax_length is None
        assert actual.single_value is False
        assert actual.collective is False
        assert actual.no_user_modification is False
        assert actual.usage == "userApplications"

        assert str(actual) == value

    def test_parse_with_super_type(self) -> None:
        value = "( 1.0 SUP 1.2.34  )"

        actual = schema.AttributeTypeDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == []
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.super_type == "1.2.34"
        assert actual.equality is None
        assert actual.ordering is None
        assert actual.substrings is None
        assert actual.syntax is None
        assert actual.syntax_length is None
        assert actual.single_value is False
        assert actual.collective is False
        assert actual.no_user_modification is False
        assert actual.usage == "userApplications"

        assert str(actual) == "( 1.0 SUP 1.2.34 )"

    def test_parse_with_collective(self) -> None:
        value = "( 1.0 COLLECTIVE   )"

        actual = schema.AttributeTypeDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == []
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.super_type is None
        assert actual.equality is None
        assert actual.ordering is None
        assert actual.substrings is None
        assert actual.syntax is None
        assert actual.syntax_length is None
        assert actual.single_value is False
        assert actual.collective is True
        assert actual.no_user_modification is False
        assert actual.usage == "userApplications"

        assert str(actual) == "( 1.0 COLLECTIVE )"

    @pytest.mark.parametrize(
        "usage",
        [
            "userApplications",
            "directoryOperation",
            "distributedOperation",
            "dSAOperation",
        ],
    )
    def test_parse_with_usage(self, usage: str) -> None:
        value = f"( 1.0 USAGE {usage} )"

        actual = schema.AttributeTypeDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == []
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.super_type is None
        assert actual.equality is None
        assert actual.ordering is None
        assert actual.substrings is None
        assert actual.syntax is None
        assert actual.syntax_length is None
        assert actual.single_value is False
        assert actual.collective is False
        assert actual.no_user_modification is False
        assert actual.usage == usage

        if usage == "userApplications":
            assert str(actual) == f"( 1.0 )"
        else:
            assert str(actual) == f"( 1.0 USAGE {usage} )"

    @pytest.mark.parametrize(
        "value",
        [
            "1.0 )",
            "( 1.0",
            "( NAME 'test' )",
            "( 1.0 USAGE invalidValue )",
        ],
    )
    def test_fail_parse(self, value: str) -> None:
        with pytest.raises(ValueError, match="value is not a valid AttributeTypeDescription"):
            schema.AttributeTypeDescription.from_string(value)
