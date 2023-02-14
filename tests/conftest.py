# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import os
import pathlib

import pytest

from .examples.asyncio import AsyncLDAPClient, create_async_ldap_client
from .examples.sync import SyncLDAPClient, create_sync_ldap_client


def get_test_data(name: str) -> bytes:
    test_path = pathlib.Path(__file__).parent / "data" / name
    return test_path.read_bytes()


@pytest.fixture
async def async_client() -> AsyncLDAPClient:
    server = os.environ.get("SANSLDAP_SERVER", None)
    if not server:
        return pytest.skip("SANSLDAP_SERVER env var must be set for client integration tests")

    port = os.environ.get("SANSLDAP_PORT", None)
    ldap_client = await create_async_ldap_client(
        server=server,
        port=int(port) if port else None,
    )

    return ldap_client


@pytest.fixture
def sync_client() -> SyncLDAPClient:
    server = os.environ.get("SANSLDAP_SERVER", None)
    if not server:
        return pytest.skip("SANSLDAP_SERVER env var must be set for client integration tests")

    port = os.environ.get("SANSLDAP_PORT", None)
    ldap_client = create_sync_ldap_client(
        server=server,
        port=int(port) if port else None,
    )

    return ldap_client
