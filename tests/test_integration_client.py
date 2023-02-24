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

        root_dse = next(
            res
            for res in sync_client.search_request(
                "",
                scope=sansldap.SearchScope.BASE,
                attributes=["subschemaSubentry"],
            )
            if isinstance(res, sansldap.SearchResultEntry)
        )

        attribute_types = []
        content_rules = []
        object_classes = []

        for res in sync_client.search_request(
            root_dse.attributes[0].values[0].decode("utf-8"),
            scope=sansldap.SearchScope.BASE,
            attributes=[
                "attributeTypes",
                "dITContentRules",
                "objectClasses",
            ],
        ):
            if not isinstance(res, sansldap.SearchResultEntry):
                continue

            for attr in res.attributes:
                if attr.name == "attributeTypes":
                    for attr_type in attr.values:
                        attribute_types.append(
                            sansldap.schema.AttributeTypeDescription.from_string(attr_type.decode("utf-8"))
                        )

                elif attr.name == "dITContentRules":
                    for content_rule in attr.values:
                        content_rules.append(
                            sansldap.schema.DITContentRuleDescription.from_string(content_rule.decode("utf-8"))
                        )

                elif attr.name == "objectClasses":
                    for obj_class in attr.values:
                        object_classes.append(
                            sansldap.schema.ObjectClassDescription.from_string(obj_class.decode("utf-8"))
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
