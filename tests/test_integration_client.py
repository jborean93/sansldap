# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os

import sansldap

from .examples.asyncio.client import LDAPClient


async def test_simple_bind(client: LDAPClient) -> None:
    async with client:
        username = os.environ.get("SANSLDAP_USERNAME", None)
        password = os.environ.get("SANSLDAP_PASSWORD", None)
        await client.bind_simple(username, password=password)

        async for res in client.search_request(
            "DC=domain,DC=test",
            filter=sansldap.FilterEquality("objectClass", b"user"),
            scope=sansldap.SearchScope.SUBTREE,
            attributes=[
                "sAMAccountName",
                "userPrincipalName",
            ],
        ):
            a = ""

    return
