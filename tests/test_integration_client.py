# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import ssl

from .examples.asyncio.client import LDAPClient
from .examples.asyncio.sasl import Gssapi, GssSpnego


async def test_simple_bind(client: LDAPClient) -> None:
    async with client:
        username = os.environ.get("SANSLDAP_USERNAME", None)
        password = os.environ.get("SANSLDAP_PASSWORD", None)

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        await client.start_tls(ssl_context)

        # await client.bind_simple(username, password=password)

        await client.bind_sasl(
            Gssapi(
                username=username,
                password=password,
                hostname=client.server,
                encrypt=True,
                sign=True,
            ),
        )

        a = await client.whoami()
        b = ""

        # async for res in client.search_request(
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
