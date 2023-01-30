# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os

from .examples.client_asyncio import LDAPClient


async def test_simple_bind(client: LDAPClient) -> None:
    username = os.environ.get("SANSLDAP_USERNAME", None)
    password = os.environ.get("SANSLDAP_PASSWORD", None)
    await client.bind_simple(username, password=password)

    return
