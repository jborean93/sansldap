# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import base64
import dataclasses
import re

import pytest

import sansldap._authentication as a
import sansldap._messages as m
import sansldap.asn1


@dataclasses.dataclass(frozen=True)
class CustomAuth(a.AuthenticationCredential):
    auth_id: int = dataclasses.field(init=False, repr=False, default=1024)

    username: str
    password: str

    def pack(
        self,
        writer: sansldap.asn1.ASN1Writer,
        options: a.AuthenticationOptions,
    ) -> None:
        writer.write_octet_string(
            f"{self.username}:{self.password}".encode(options.string_encoding),
            tag=sansldap.asn1.ASN1Tag(
                sansldap.asn1.TagClass.CONTEXT_SPECIFIC,
                self.auth_id,
                False,
            ),
        )

    @classmethod
    def unpack(
        cls,
        reader: sansldap.asn1.ASN1Reader,
        options: a.AuthenticationOptions,
    ) -> CustomAuth:
        value = reader.read_octet_string(
            tag=sansldap.asn1.ASN1Tag(
                sansldap.asn1.TagClass.CONTEXT_SPECIFIC,
                cls.auth_id,
                False,
            ),
            hint="CustomAuth.value",
        ).decode(options.string_encoding)
        username, _, password = value.partition(":")

        return CustomAuth(username=username, password=password)


def test_pack_custom_auth() -> None:
    expected = base64.b64decode("MCMCAQBgHgIBAwQEbmFtZZ+IABF1c2VybmFtZTpwYXNzd29yZA==")
    req = m.BindRequest(
        message_id=0,
        controls=[],
        version=3,
        name="name",
        authentication=CustomAuth("username", "password"),
    )
    actual = req.pack(m.PackingOptions())
    assert actual == expected


def test_pack_custom_auth_and_encoding() -> None:
    expected = base64.b64decode("MDQCAQBgLwIBAwQEbmFtZZ+IACJ1AHMAZQByAG4AYQBtAGUAOgBwAGEAcwBzAHcAbwByAGQA")
    req = m.BindRequest(
        message_id=0,
        controls=[],
        version=3,
        name="name",
        authentication=CustomAuth("username", "password"),
    )
    actual = req.pack(m.PackingOptions(authentication=a.AuthenticationOptions(string_encoding="utf-16-le")))
    assert actual == expected


def test_unpack_custom_auth() -> None:
    data = base64.b64decode("MCMCAQBgHgIBAwQEbmFtZZ+IABF1c2VybmFtZTpwYXNzd29yZA==")
    reader = sansldap.asn1.ASN1Reader(data)

    actual = m.unpack_ldap_message(
        reader,
        m.PackingOptions(
            authentication=a.AuthenticationOptions(
                choices=[CustomAuth],
            )
        ),
    )
    assert isinstance(actual, m.BindRequest)
    assert isinstance(actual.authentication, CustomAuth)
    assert actual.authentication.username == "username"
    assert actual.authentication.password == "password"


def test_unpack_custom_auth_and_encoding() -> None:
    data = base64.b64decode("MDQCAQBgLwIBAwQEbmFtZZ+IACJ1AHMAZQByAG4AYQBtAGUAOgBwAGEAcwBzAHcAbwByAGQA")
    reader = sansldap.asn1.ASN1Reader(data)

    actual = m.unpack_ldap_message(
        reader,
        m.PackingOptions(
            authentication=a.AuthenticationOptions(
                string_encoding="utf-16-le",
                choices=[CustomAuth],
            )
        ),
    )
    assert isinstance(actual, m.BindRequest)
    assert isinstance(actual.authentication, CustomAuth)
    assert actual.authentication.username == "username"
    assert actual.authentication.password == "password"


def test_unpack_custom_auth_fail_not_registered() -> None:
    expected = "Unknown authentication object ASN1Tag(tag_class=<TagClass.CONTEXT_SPECIFIC: 2>, tag_number=1024, is_constructed=False), cannot unpack"

    data = base64.b64decode("MCMCAQBgHgIBAwQEbmFtZZ+IABF1c2VybmFtZTpwYXNzd29yZA==")
    reader = sansldap.asn1.ASN1Reader(data)

    with pytest.raises(NotImplementedError, match=re.escape(expected)):
        m.unpack_ldap_message(reader, m.PackingOptions())


def test_unpack_custom_auth_not_context_specific() -> None:
    expected = "Unknown authentication object ASN1Tag(tag_class=<TagClass.UNIVERSAL: 0>, tag_number=<TypeTagNumber.OCTET_STRING: 4>, is_constructed=False), cannot unpack"

    data = base64.b64decode("MCECAQBgHAIBAwQEbmFtZQQRdXNlcm5hbWU6cGFzc3dvcmQ=")
    reader = sansldap.asn1.ASN1Reader(data)

    with pytest.raises(NotImplementedError, match=re.escape(expected)):
        m.unpack_ldap_message(reader, m.PackingOptions())


def test_pack_sasl_with_cred() -> None:
    expected = base64.b64decode("MBkCAQBgFAIBAwQEbmFtZaMJBARtZWNoBAEA")
    req = m.BindRequest(
        message_id=0,
        controls=[],
        version=3,
        name="name",
        authentication=a.SaslCredential(mechanism="mech", credentials=b"\x00"),
    )
    actual = req.pack(m.PackingOptions())
    assert actual == expected


def test_unpack_sasl_with_cred() -> None:
    data = base64.b64decode("MBkCAQBgFAIBAwQEbmFtZaMJBARtZWNoBAEA")
    reader = sansldap.asn1.ASN1Reader(data)

    actual = m.unpack_ldap_message(
        reader,
        m.PackingOptions(
            authentication=a.AuthenticationOptions(
                choices=[a.SaslCredential],
            )
        ),
    )
    assert isinstance(actual, m.BindRequest)
    assert isinstance(actual.authentication, a.SaslCredential)
    assert actual.authentication.mechanism == "mech"
    assert actual.authentication.credentials == b"\x00"


def test_pack_sasl_with_no_cred() -> None:
    expected = base64.b64decode("MBYCAQBgEQIBAwQEbmFtZaMGBARtZWNo")
    req = m.BindRequest(
        message_id=0,
        controls=[],
        version=3,
        name="name",
        authentication=a.SaslCredential(mechanism="mech", credentials=None),
    )
    actual = req.pack(m.PackingOptions())
    assert actual == expected


def test_unpack_sasl_with_no_cred() -> None:
    data = base64.b64decode("MBYCAQBgEQIBAwQEbmFtZaMGBARtZWNo")
    reader = sansldap.asn1.ASN1Reader(data)

    actual = m.unpack_ldap_message(
        reader,
        m.PackingOptions(
            authentication=a.AuthenticationOptions(
                choices=[a.SaslCredential],
            )
        ),
    )
    assert isinstance(actual, m.BindRequest)
    assert isinstance(actual.authentication, a.SaslCredential)
    assert actual.authentication.mechanism == "mech"
    assert actual.authentication.credentials is None
