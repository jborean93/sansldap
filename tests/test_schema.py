# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import pytest

import sansldap.schema as schema


class TestObjectClassDescription:
    def test_parse(self) -> None:
        value = "( 2.5.6.2 NAME 'country' SUP top STRUCTURAL MUST c MAY ( searchGuide $ description ) )"

        actual = schema.ObjectClassDescription.from_string(value)
        assert actual.oid == "2.5.6.2"
        assert actual.names == ["country"]
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.super_types == ["top"]
        assert actual.kind == schema.ObjectClassKind.STRUCTURAL
        assert actual.must == ["c"]
        assert actual.may == ["searchGuide", "description"]
        assert actual.extensions == {}

        assert str(actual) == value

    def test_parse_ad(self) -> None:
        value = "( 2.5.6.14 NAME 'device' SUP top STRUCTURAL MUST (cn ) MAY (serialNumber $ l $ o $ ou $ owner $ seeAlso $ msSFU30Name $ msSFU30Aliases $ msSFU30NisDomain $ nisMapName ) )"

        actual = schema.ObjectClassDescription.from_string(value)
        assert actual.oid == "2.5.6.14"
        assert actual.names == ["device"]
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.super_types == ["top"]
        assert actual.kind == schema.ObjectClassKind.STRUCTURAL
        assert actual.must == ["cn"]
        assert actual.may == [
            "serialNumber",
            "l",
            "o",
            "ou",
            "owner",
            "seeAlso",
            "msSFU30Name",
            "msSFU30Aliases",
            "msSFU30NisDomain",
            "nisMapName",
        ]
        assert actual.extensions == {}

        assert (
            str(actual)
            == "( 2.5.6.14 NAME 'device' SUP top STRUCTURAL MUST cn MAY ( serialNumber $ l $ o $ ou $ owner $ seeAlso $ msSFU30Name $ msSFU30Aliases $ msSFU30NisDomain $ nisMapName ) )"
        )

    def test_parse_no_optional(self) -> None:
        value = "( 1.0 )"

        actual = schema.ObjectClassDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == []
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.super_types == []
        assert actual.kind == schema.ObjectClassKind.STRUCTURAL
        assert actual.must == []
        assert actual.may == []
        assert actual.extensions == {}

        assert str(actual) == "( 1.0 STRUCTURAL )"

    def test_parse_with_extensions(self) -> None:
        value = r"( 1.0 X-ORIGIN 'RFC 1274' X-OTHER-abc ('\27ext 1\27'   'ext 2' ))"

        actual = schema.ObjectClassDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == []
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.super_types == []
        assert actual.kind == schema.ObjectClassKind.STRUCTURAL
        assert actual.must == []
        assert actual.may == []
        assert actual.extensions == {
            "ORIGIN": ["RFC 1274"],
            "OTHER-abc": ["'ext 1'", "ext 2"],
        }

        assert str(actual) == r"( 1.0 STRUCTURAL X-ORIGIN 'RFC 1274' X-OTHER-abc ( '\27ext 1\27' 'ext 2' ) )"

    def test_parse_with_multiple_names(self) -> None:
        value = "(1.0  NAME ('name1' 'name2' ) )"

        actual = schema.ObjectClassDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == ["name1", "name2"]
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.super_types == []
        assert actual.kind == schema.ObjectClassKind.STRUCTURAL
        assert actual.must == []
        assert actual.may == []
        assert actual.extensions == {}

        assert str(actual) == "( 1.0 NAME ( 'name1' 'name2' ) STRUCTURAL )"

    def test_parse_with_description(self) -> None:
        value = "( 1.0 DESC   'foo \\27bar\\27' )"

        actual = schema.ObjectClassDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == []
        assert actual.description == "foo 'bar'"
        assert actual.obsolete is False
        assert actual.super_types == []
        assert actual.kind == schema.ObjectClassKind.STRUCTURAL
        assert actual.must == []
        assert actual.may == []
        assert actual.extensions == {}

        assert str(actual) == "( 1.0 DESC 'foo \\27bar\\27' STRUCTURAL )"

    def test_parse_with_obsolete(self) -> None:
        value = "( 1.0 OBSOLETE )"

        actual = schema.ObjectClassDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == []
        assert actual.description is None
        assert actual.obsolete is True
        assert actual.super_types == []
        assert actual.kind == schema.ObjectClassKind.STRUCTURAL
        assert actual.must == []
        assert actual.may == []
        assert actual.extensions == {}

        assert str(actual) == "( 1.0 OBSOLETE STRUCTURAL )"

    def test_parse_with_one_super_type(self) -> None:
        value = "(1.0  SUP 1.2.3.4 )"

        actual = schema.ObjectClassDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == []
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.super_types == ["1.2.3.4"]
        assert actual.kind == schema.ObjectClassKind.STRUCTURAL
        assert actual.must == []
        assert actual.may == []
        assert actual.extensions == {}

        assert str(actual) == "( 1.0 SUP 1.2.3.4 STRUCTURAL )"

    def test_parse_with_multiple_super_types(self) -> None:
        value = "(1.0  SUP (name$1.10.3845 $other ) )"

        actual = schema.ObjectClassDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == []
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.super_types == ["name", "1.10.3845", "other"]
        assert actual.kind == schema.ObjectClassKind.STRUCTURAL
        assert actual.must == []
        assert actual.may == []
        assert actual.extensions == {}

        assert str(actual) == "( 1.0 SUP ( name $ 1.10.3845 $ other ) STRUCTURAL )"

    @pytest.mark.parametrize(
        "kind",
        [
            schema.ObjectClassKind.STRUCTURAL,
            schema.ObjectClassKind.ABSTRACT,
            schema.ObjectClassKind.AUXILIARY,
        ],
    )
    def test_parse_kind(self, kind: schema.ObjectClassKind) -> None:
        value = f"( 1.0 {kind.value} )"

        actual = schema.ObjectClassDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == []
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.super_types == []
        assert actual.kind == kind
        assert actual.must == []
        assert actual.may == []
        assert actual.extensions == {}

        assert str(actual) == value

    @pytest.mark.parametrize(
        "value",
        [
            "1.0 )",
            "( 1.0",
            "( NAME 'test' )",
            "( 1.0 invalidValue )",
        ],
    )
    def test_fail_parse(self, value: str) -> None:
        with pytest.raises(ValueError, match="value is not a valid ObjectClassDescription"):
            schema.ObjectClassDescription.from_string(value)


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
        assert actual.usage == schema.AttributeTypeUsage.DIRECTORY_OPERATION
        assert actual.extensions == {}

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
        assert actual.usage == schema.AttributeTypeUsage.USER_APPLICATIONS
        assert actual.extensions == {"ORIGIN": ["RFC 1274"]}

        assert (
            str(actual)
            == "( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} X-ORIGIN 'RFC 1274' )"
        )

    def test_parse_multiple_extensions(self) -> None:
        value = "( 1.0 X-ABC_DEF-GHI 'first \\27value\\27' X--ABC- (  'first1' '\\5c\\27café\\5C\\27' '1234'   ) )"

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
        assert actual.usage == schema.AttributeTypeUsage.USER_APPLICATIONS
        assert actual.extensions == {
            "ABC_DEF-GHI": ["first 'value'"],
            "-ABC-": ["first1", "\\'café\\'", "1234"],
        }

        assert (
            str(actual)
            == "( 1.0 X-ABC_DEF-GHI 'first \\27value\\27' X--ABC- ( 'first1' '\\5c\\27café\\5c\\27' '1234' ) )"
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
        assert actual.usage == schema.AttributeTypeUsage.USER_APPLICATIONS
        assert actual.extensions == {}

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
        assert actual.usage == schema.AttributeTypeUsage.USER_APPLICATIONS
        assert actual.extensions == {}

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
        assert actual.usage == schema.AttributeTypeUsage.USER_APPLICATIONS
        assert actual.extensions == {}

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
        assert actual.usage == schema.AttributeTypeUsage.USER_APPLICATIONS
        assert actual.extensions == {}

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
        assert actual.usage == schema.AttributeTypeUsage.USER_APPLICATIONS
        assert actual.extensions == {}

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
        assert actual.usage == schema.AttributeTypeUsage.USER_APPLICATIONS
        assert actual.extensions == {}

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
        assert actual.usage == schema.AttributeTypeUsage.USER_APPLICATIONS
        assert actual.extensions == {}

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
        assert actual.usage == schema.AttributeTypeUsage.USER_APPLICATIONS
        assert actual.extensions == {}

        assert str(actual) == "( 1.0 COLLECTIVE )"

    @pytest.mark.parametrize(
        "usage",
        [
            schema.AttributeTypeUsage.USER_APPLICATIONS,
            schema.AttributeTypeUsage.DIRECTORY_OPERATION,
            schema.AttributeTypeUsage.DISTRIBUTED_OPERATION,
            schema.AttributeTypeUsage.DSA_OPERATION,
        ],
    )
    def test_parse_with_usage(self, usage: schema.AttributeTypeUsage) -> None:
        value = f"( 1.0 USAGE {usage.value} )"

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
        assert actual.extensions == {}

        if usage == schema.AttributeTypeUsage.USER_APPLICATIONS:
            assert str(actual) == f"( 1.0 )"
        else:
            assert str(actual) == f"( 1.0 USAGE {usage.value} )"

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


class TestDITContentRule:
    def test_parse(self) -> None:
        value = "( 2.5.6.4 DESC 'content rule for organization' NOT ( x121Address $ telexNumber ) )"

        actual = schema.DITContentRuleDescription.from_string(value)
        assert actual.oid == "2.5.6.4"
        assert actual.names == []
        assert actual.description == "content rule for organization"
        assert actual.obsolete is False
        assert actual.aux == []
        assert actual.must == []
        assert actual.may == []
        assert actual.never == ["x121Address", "telexNumber"]
        assert actual.extensions == {}

        assert str(actual) == value

    def test_parse_ad(self) -> None:
        value = "( 1.2.840.113556.1.5.282 NAME 'msDS-GroupManagedServiceAccount' AUX ( mailRecipient $ posixGroup $ ipHost ) MUST (objectSid $ sAMAccountName ) MAY (info $ garbageCollPeriod$ msExchAssistantName ))"

        actual = schema.DITContentRuleDescription.from_string(value)
        assert actual.oid == "1.2.840.113556.1.5.282"
        assert actual.names == ["msDS-GroupManagedServiceAccount"]
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.aux == ["mailRecipient", "posixGroup", "ipHost"]
        assert actual.must == ["objectSid", "sAMAccountName"]
        assert actual.may == ["info", "garbageCollPeriod", "msExchAssistantName"]
        assert actual.never == []
        assert actual.extensions == {}

        assert (
            str(actual)
            == "( 1.2.840.113556.1.5.282 NAME 'msDS-GroupManagedServiceAccount' AUX ( mailRecipient $ posixGroup $ ipHost ) MUST ( objectSid $ sAMAccountName ) MAY ( info $ garbageCollPeriod $ msExchAssistantName ) )"
        )

    def test_parse_no_optional(self) -> None:
        value = "( 1.0 )"

        actual = schema.DITContentRuleDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == []
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.aux == []
        assert actual.must == []
        assert actual.may == []
        assert actual.never == []
        assert actual.extensions == {}

        assert str(actual) == value

    def test_parse_with_extensions(self) -> None:
        value = "( 1.0 X-ORIGIN 'RFC 1274' X-OTHER-abc ('\\27ext 1\\27'   'ext 2' ))"

        actual = schema.DITContentRuleDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == []
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.aux == []
        assert actual.must == []
        assert actual.may == []
        assert actual.never == []
        assert actual.extensions == {
            "ORIGIN": ["RFC 1274"],
            "OTHER-abc": ["'ext 1'", "ext 2"],
        }

        assert str(actual) == "( 1.0 X-ORIGIN 'RFC 1274' X-OTHER-abc ( '\\27ext 1\\27' 'ext 2' ) )"

    def test_parse_with_multiple_names(self) -> None:
        value = "(1.0  NAME ('name1' 'name2' ) )"

        actual = schema.DITContentRuleDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == ["name1", "name2"]
        assert actual.description is None
        assert actual.obsolete is False
        assert actual.aux == []
        assert actual.must == []
        assert actual.may == []
        assert actual.never == []
        assert actual.extensions == {}

        assert str(actual) == "( 1.0 NAME ( 'name1' 'name2' ) )"

    def test_parse_with_obsolete(self) -> None:
        value = "( 1.0 OBSOLETE )"

        actual = schema.DITContentRuleDescription.from_string(value)
        assert actual.oid == "1.0"
        assert actual.names == []
        assert actual.description is None
        assert actual.obsolete is True
        assert actual.aux == []
        assert actual.must == []
        assert actual.may == []
        assert actual.never == []
        assert actual.extensions == {}

        assert str(actual) == value

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
        with pytest.raises(ValueError, match="value is not a valid DITContentRuleDescription"):
            schema.DITContentRuleDescription.from_string(value)
