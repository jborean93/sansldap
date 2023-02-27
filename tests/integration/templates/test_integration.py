# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import pathlib
import ssl
import sys
import typing as t

import pytest
from cldap.asyncio import create_async_ldap_client
from cldap.exceptions import LDAPResultError
from cldap.sasl import External, Gssapi, GssSpnego
from cldap.sync import create_sync_ldap_client
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_key_and_certificates,
)

import sansldap

DOMAIN_REALM = "{{ domain_name }}"
DOMAIN_NETBIOS = DOMAIN_REALM.split(".")[0].upper()
ROOT_DC = f"dc01.{DOMAIN_REALM}"
FOO_DC = f"dc02.{{ hostvars['DC02']['domain_name_prefix'] }}{DOMAIN_REALM}"
BAR_DC = f"dc03.{{ hostvars['DC03']['domain_name_prefix'] }}{DOMAIN_REALM}"
USERNAME = "{{ domain_username | lower }}"
PASSWORD = "{{ domain_password }}"
USER_UPN = f"{USERNAME}@{DOMAIN_REALM.upper()}"
USER_CERT = pathlib.Path(__file__).parent / "user-cert.pfx"


def load_client_pfx_certificate(tmpdir: pathlib.Path, ssl_context: ssl.SSLContext) -> None:
    cert_pem_path = tmpdir / "cert.pem"

    with open(USER_CERT.absolute(), mode="rb") as fd:
        private_key, certificate, _ = load_key_and_certificates(fd.read(), PASSWORD.encode("utf-8"))

    if not private_key or not certificate:
        raise Exception(f"Failed to load pfx at '{USER_CERT.absolute()}'")

    with open(cert_pem_path, mode="wb") as fd:
        cert = certificate.public_bytes(
            encoding=Encoding.PEM,
        )
        key = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        fd.write(cert)
        fd.write(b"\n")
        fd.write(key)

    ssl_context.load_cert_chain(str(cert_pem_path))


@pytest.mark.parametrize("mode", ["ldap", "ldaps", "start_tls"])
def test_sync_simple(mode: str) -> None:
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_default_certs()

    create_kwargs: t.Dict[str, t.Any] = {}
    if mode == "ldaps":
        create_kwargs["ssl_context"] = ssl_context

    with create_sync_ldap_client(ROOT_DC, **create_kwargs) as client:
        if mode == "start_tls":
            client.start_tls(ssl_context)

        client.bind_simple(USER_UPN, PASSWORD)

        actual = client.whoami()
        assert actual == f"u:{DOMAIN_NETBIOS}\\{USERNAME}"


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["ldap", "ldaps", "start_tls"])
async def test_async_simple(mode: str) -> None:
    if mode == "start_tls" and sys.version_info < (3, 11):
        pytest.skip("StartTLS only works on Python 3.11 or newer")

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_default_certs()

    create_kwargs: t.Dict[str, t.Any] = {}
    if mode == "ldaps":
        create_kwargs["ssl_context"] = ssl_context

    async with (await create_async_ldap_client(ROOT_DC, **create_kwargs)) as client:
        if mode == "start_tls":
            await client.start_tls(ssl_context)

        await client.bind_simple(USER_UPN, PASSWORD)

        actual = await client.whoami()
        assert actual == f"u:{DOMAIN_NETBIOS}\\{USERNAME}"


@pytest.mark.parametrize("mode", ["ldap", "ldaps", "start_tls"])
def test_sync_implicit_kerberos(mode: str) -> None:
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_default_certs()

    create_kwargs: t.Dict[str, t.Any] = {}
    if mode == "ldaps":
        create_kwargs["ssl_context"] = ssl_context

    with create_sync_ldap_client(ROOT_DC, **create_kwargs) as client:
        if mode == "start_tls":
            client.start_tls(ssl_context)

        client.bind_sasl(
            Gssapi(
                hostname=client.server,
                encrypt=mode == "ldap",
                sign=mode == "ldap",
            ),
        )

        actual = client.whoami()
        assert actual == f"u:{DOMAIN_NETBIOS}\\{USERNAME}"


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["ldap", "ldaps", "start_tls"])
async def test_async_implicit_kerberos(mode: str) -> None:
    if mode == "start_tls" and sys.version_info < (3, 11):
        pytest.skip("StartTLS only works on Python 3.11 or newer")

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_default_certs()

    create_kwargs: t.Dict[str, t.Any] = {}
    if mode == "ldaps":
        create_kwargs["ssl_context"] = ssl_context

    async with (await create_async_ldap_client(ROOT_DC, **create_kwargs)) as client:
        if mode == "start_tls":
            await client.start_tls(ssl_context)

        await client.bind_sasl(
            Gssapi(
                hostname=client.server,
                encrypt=mode == "ldap",
                sign=mode == "ldap",
            ),
        )

        actual = await client.whoami()
        assert actual == f"u:{DOMAIN_NETBIOS}\\{USERNAME}"


@pytest.mark.parametrize("mode", ["ldap", "ldaps", "start_tls"])
def test_sync_explicit_kerberos(mode: str) -> None:
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_default_certs()

    create_kwargs: t.Dict[str, t.Any] = {}
    if mode == "ldaps":
        create_kwargs["ssl_context"] = ssl_context

    with create_sync_ldap_client(ROOT_DC, **create_kwargs) as client:
        if mode == "start_tls":
            client.start_tls(ssl_context)

        client.bind_sasl(
            Gssapi(
                username=USER_UPN,
                password=PASSWORD,
                hostname=client.server,
                encrypt=mode == "ldap",
                sign=mode == "ldap",
            ),
        )

        actual = client.whoami()
        assert actual == f"u:{DOMAIN_NETBIOS}\\{USERNAME}"


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["ldap", "ldaps", "start_tls"])
async def test_async_explicit_kerberos(mode: str) -> None:
    if mode == "start_tls" and sys.version_info < (3, 11):
        pytest.skip("StartTLS only works on Python 3.11 or newer")

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_default_certs()

    create_kwargs: t.Dict[str, t.Any] = {}
    if mode == "ldaps":
        create_kwargs["ssl_context"] = ssl_context

    async with (await create_async_ldap_client(ROOT_DC, **create_kwargs)) as client:
        if mode == "start_tls":
            await client.start_tls(ssl_context)

        await client.bind_sasl(
            Gssapi(
                username=USER_UPN,
                password=PASSWORD,
                hostname=client.server,
                encrypt=mode == "ldap",
                sign=mode == "ldap",
            ),
        )

        actual = await client.whoami()
        assert actual == f"u:{DOMAIN_NETBIOS}\\{USERNAME}"


@pytest.mark.parametrize("mode", ["ldap", "ldaps", "start_tls"])
def test_sync_implicit_spnego(mode: str) -> None:
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_default_certs()

    create_kwargs: t.Dict[str, t.Any] = {}
    if mode == "ldaps":
        create_kwargs["ssl_context"] = ssl_context

    with create_sync_ldap_client(ROOT_DC, **create_kwargs) as client:
        if mode == "start_tls":
            client.start_tls(ssl_context)

        client.bind_sasl(
            GssSpnego(
                hostname=client.server,
                encrypt=mode == "ldap",
                sign=mode == "ldap",
            ),
        )

        actual = client.whoami()
        assert actual == f"u:{DOMAIN_NETBIOS}\\{USERNAME}"


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["ldap", "ldaps", "start_tls"])
async def test_async_implicit_spnego(mode: str) -> None:
    if mode == "start_tls" and sys.version_info < (3, 11):
        pytest.skip("StartTLS only works on Python 3.11 or newer")

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_default_certs()

    create_kwargs: t.Dict[str, t.Any] = {}
    if mode == "ldaps":
        create_kwargs["ssl_context"] = ssl_context

    async with (await create_async_ldap_client(ROOT_DC, **create_kwargs)) as client:
        if mode == "start_tls":
            await client.start_tls(ssl_context)

        await client.bind_sasl(
            GssSpnego(
                hostname=client.server,
                encrypt=mode == "ldap",
                sign=mode == "ldap",
            ),
        )

        actual = await client.whoami()
        assert actual == f"u:{DOMAIN_NETBIOS}\\{USERNAME}"


@pytest.mark.parametrize("mode", ["ldap", "ldaps", "start_tls"])
def test_sync_explicit_spnego(mode: str) -> None:
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_default_certs()

    create_kwargs: t.Dict[str, t.Any] = {}
    if mode == "ldaps":
        create_kwargs["ssl_context"] = ssl_context

    with create_sync_ldap_client(ROOT_DC, **create_kwargs) as client:
        if mode == "start_tls":
            client.start_tls(ssl_context)

        client.bind_sasl(
            GssSpnego(
                username=USER_UPN,
                password=PASSWORD,
                hostname=client.server,
                encrypt=mode == "ldap",
                sign=mode == "ldap",
            ),
        )

        actual = client.whoami()
        assert actual == f"u:{DOMAIN_NETBIOS}\\{USERNAME}"


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["ldap", "ldaps", "start_tls"])
async def test_async_explicit_spnego(mode: str) -> None:
    if mode == "start_tls" and sys.version_info < (3, 11):
        pytest.skip("StartTLS only works on Python 3.11 or newer")

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_default_certs()

    create_kwargs: t.Dict[str, t.Any] = {}
    if mode == "ldaps":
        create_kwargs["ssl_context"] = ssl_context

    async with (await create_async_ldap_client(ROOT_DC, **create_kwargs)) as client:
        if mode == "start_tls":
            await client.start_tls(ssl_context)

        await client.bind_sasl(
            GssSpnego(
                username=USER_UPN,
                password=PASSWORD,
                hostname=client.server,
                encrypt=mode == "ldap",
                sign=mode == "ldap",
            ),
        )

        actual = await client.whoami()
        assert actual == f"u:{DOMAIN_NETBIOS}\\{USERNAME}"


@pytest.mark.parametrize("mode", ["ldaps", "start_tls"])
def test_sync_certificate_auth(mode: str, tmpdir: pathlib.Path) -> None:
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_default_certs()

    load_client_pfx_certificate(tmpdir, ssl_context)

    create_kwargs: t.Dict[str, t.Any] = {}
    if mode == "ldaps":
        create_kwargs["ssl_context"] = ssl_context

    with create_sync_ldap_client(ROOT_DC, **create_kwargs) as client:
        if mode == "start_tls":
            client.start_tls(ssl_context)

        if mode == "start_tls":
            client.bind_sasl(External())

        actual = client.whoami()
        assert actual == f"u:{DOMAIN_NETBIOS}\\{USERNAME}"


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["ldaps", "start_tls"])
async def test_async_certificate_auth(mode: str, tmpdir: pathlib.Path) -> None:
    if mode == "start_tls" and sys.version_info < (3, 11):
        pytest.skip("StartTLS only works on Python 3.11 or newer")

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_default_certs()

    load_client_pfx_certificate(tmpdir, ssl_context)

    create_kwargs: t.Dict[str, t.Any] = {}
    if mode == "ldaps":
        create_kwargs["ssl_context"] = ssl_context

    async with (await create_async_ldap_client(ROOT_DC, **create_kwargs)) as client:
        if mode == "start_tls":
            await client.start_tls(ssl_context)

        if mode == "start_tls":
            await client.bind_sasl(External())

        actual = await client.whoami()
        assert actual == f"u:{DOMAIN_NETBIOS}\\{USERNAME}"


def test_sync_search_result() -> None:
    with create_sync_ldap_client(ROOT_DC) as client:
        client.bind_sasl(
            GssSpnego(
                hostname=client.server,
                encrypt=True,
                sign=True,
            ),
        )

        root_dse = list(
            client.search_request(
                "",
                scope=sansldap.SearchScope.BASE,
                attributes=["subschemaSubentry"],
            )
        )[0]
        assert isinstance(root_dse, sansldap.SearchResultEntry)
        schema_subentry = root_dse.attributes[0].values[0].decode("utf-8")

        for res in client.search_request(
            schema_subentry,
            scope=sansldap.SearchScope.BASE,
            attributes=["attributeTypes", "dITContentRules", "objectClasses"],
        ):
            assert isinstance(
                res,
                (
                    sansldap.SearchResultEntry,
                    sansldap.SearchResultReference,
                    sansldap.SearchResultDone,
                ),
            )

            if isinstance(res, sansldap.SearchResultEntry):
                for attr in res.attributes:
                    if attr.name == "attributeTypes":
                        sansldap.schema.AttributeTypeDescription.from_string(attr.values[0].decode())

                    elif attr.name == "dITContentRules":
                        sansldap.schema.DITContentRuleDescription.from_string(attr.values[0].decode())

                    else:
                        sansldap.schema.ObjectClassDescription.from_string(attr.values[0].decode())

            elif isinstance(res, sansldap.SearchResultDone):
                assert res.result.result_code == sansldap.LDAPResultCode.SUCCESS


@pytest.mark.asyncio
async def test_async_search_result() -> None:
    async with (await create_async_ldap_client(ROOT_DC)) as client:
        await client.bind_sasl(
            GssSpnego(
                hostname=client.server,
                encrypt=True,
                sign=True,
            ),
        )

        root_dse = None
        async for res in client.search_request(
            "",
            scope=sansldap.SearchScope.BASE,
            attributes=["subschemaSubentry"],
        ):
            if isinstance(res, sansldap.SearchResultEntry):
                root_dse = res

        assert isinstance(root_dse, sansldap.SearchResultEntry)
        schema_subentry = root_dse.attributes[0].values[0].decode("utf-8")

        async for res in client.search_request(
            schema_subentry,
            scope=sansldap.SearchScope.BASE,
            attributes=["attributeTypes", "dITContentRules", "objectClasses"],
        ):
            assert isinstance(
                res,
                (
                    sansldap.SearchResultEntry,
                    sansldap.SearchResultReference,
                    sansldap.SearchResultDone,
                ),
            )

            if isinstance(res, sansldap.SearchResultEntry):
                for attr in res.attributes:
                    if attr.name == "attributeTypes":
                        sansldap.schema.AttributeTypeDescription.from_string(attr.values[0].decode())

                    elif attr.name == "dITContentRules":
                        sansldap.schema.DITContentRuleDescription.from_string(attr.values[0].decode())

                    else:
                        sansldap.schema.ObjectClassDescription.from_string(attr.values[0].decode())

            elif isinstance(res, sansldap.SearchResultDone):
                assert res.result.result_code == sansldap.LDAPResultCode.SUCCESS


def test_sync_with_referral() -> None:
    foo_components = FOO_DC.split(".")[1:]
    foo_dn = f"DC={',DC='.join(foo_components)}"

    with create_sync_ldap_client(BAR_DC) as client:
        client.bind_sasl(
            GssSpnego(
                hostname=client.server,
                encrypt=True,
                sign=True,
            ),
        )

        with pytest.raises(LDAPResultError, match="Received LDAPResult error search request failed - REFERRAL") as exc:
            for _ in client.search_request(
                foo_dn,
                scope=sansldap.SearchScope.SUBTREE,
            ):
                pass

        assert exc.value.result.result_code == sansldap.LDAPResultCode.REFERRAL
        assert exc.value.result.referrals == [f"ldap://{'.'.join(foo_components)}/{foo_dn}"]


@pytest.mark.asyncio
async def test_async_with_referral() -> None:
    foo_components = FOO_DC.split(".")[1:]
    foo_dn = f"DC={',DC='.join(foo_components)}"

    async with (await create_async_ldap_client(BAR_DC)) as client:
        await client.bind_sasl(
            GssSpnego(
                hostname=client.server,
                encrypt=True,
                sign=True,
            ),
        )

        with pytest.raises(LDAPResultError, match="Received LDAPResult error search request failed - REFERRAL") as exc:
            async for _ in client.search_request(
                foo_dn,
                scope=sansldap.SearchScope.SUBTREE,
            ):
                pass

        assert exc.value.result.result_code == sansldap.LDAPResultCode.REFERRAL
        assert exc.value.result.referrals == [f"ldap://{'.'.join(foo_components)}/{foo_dn}"]
