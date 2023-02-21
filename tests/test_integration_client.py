# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import ssl

import sansldap

from .examples.asyncio import AsyncLDAPClient
from .examples.sasl import Gssapi, GssSpnego
from .examples.sync import SyncLDAPClient


def test_sync_simple_bind(sync_client: SyncLDAPClient) -> None:
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    with sync_client:
        username = os.environ.get("SANSLDAP_USERNAME", None)
        password = os.environ.get("SANSLDAP_PASSWORD", None)

        # sync_client.start_tls(ssl_context)

        # await client.bind_simple(username, password=password)

        sync_client.bind_sasl(
            Gssapi(
                username=username,
                password=password,
                hostname=sync_client.server,
                encrypt=True,
                sign=True,
            ),
        )

        a = sync_client.whoami()
        b = ""

        # for res in sync_client.search_request(
        #     "DC=domain,DC=test",
        #     filter=sansldap.FilterEquality("objectClass", b"user"),
        #     scope=sansldap.SearchScope.SUBTREE,
        #     attributes=[
        #         "sAMAccountName",
        #         "userPrincipalName",
        #     ],
        # ):
        #     a = ""


async def test_async_simple_bind(async_client: AsyncLDAPClient) -> None:
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    async with async_client:
        username = os.environ.get("SANSLDAP_USERNAME", None)
        password = os.environ.get("SANSLDAP_PASSWORD", None)

        # await client.start_tls(ssl_context)

        # await client.bind_simple(username, password=password)

        await async_client.bind_sasl(
            Gssapi(
                username=username,
                password=password,
                hostname=async_client.server,
                encrypt=True,
                sign=True,
            ),
        )

        a = await async_client.whoami()
        b = ""

        # async for res in async_client.search_request(
        #     "DC=domain,DC=test",
        #     filter=sansldap.FilterEquality("objectClass", b"user"),
        #     scope=sansldap.SearchScope.SUBTREE,
        #     attributes=[
        #         "sAMAccountName",
        #         "userPrincipalName",
        #     ],
        # ):
        #     a = ""

    return
