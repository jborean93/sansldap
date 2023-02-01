# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import asyncio
import functools
import ssl
import typing as t

import sansldap


class LDAPResultError(Exception):
    def __init__(
        self,
        msg: str,
        result: sansldap.LDAPResult,
    ) -> None:
        super().__init__(msg)
        self.result = result

    def __str__(self) -> str:
        inner_msg = super().__str__()
        msg = f"Received LDAPResult error {inner_msg} - {self.result.result_code.name}"
        if self.result.matched_dn:
            msg += f" - Matched DN {self.result.matched_dn}"

        if self.result.diagnostics_message:
            msg += f" - {self.result.diagnostics_message}"

        return msg


async def create_ldap_client(
    server: str,
    port: t.Optional[int] = None,
    ssl_context: t.Optional[ssl.SSLContext] = None,
) -> LDAPClient:
    port = port if port is not None else (389 if ssl_context is None else 636)

    reader, writer = await asyncio.open_connection(
        server,
        port=port,
        ssl=ssl_context,
    )

    return LDAPClient(reader, writer)


class ResponseAwaiter:
    def __init__(
        self,
    ) -> None:
        self._lock = asyncio.Event()
        self._exc: t.Optional[Exception] = None

    async def wait(self) -> None:
        await self._lock.wait()
        if self._exc:
            raise Exception(f"Response handler raised exception: {self._exc}") from self._exc

    def free(
        self,
        exc: t.Optional[Exception] = None,
    ) -> None:
        self._exc = exc
        self._lock.set()


class LDAPClient:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.protocol = sansldap.LDAPClient()
        self._incoming_messages: t.Dict[int, ResponseAwaiter] = {}
        self._reader = reader
        self._writer = writer
        self._reader_task = asyncio.create_task(self._read_loop())

    @property
    def state(self) -> sansldap.SessionState:
        return self.protocol.state

    async def bind_simple(
        self,
        username: t.Optional[str] = None,
        password: t.Optional[str] = None,
    ) -> None:
        msg_id = self.protocol.bind_simple(username, password)
        await self._send_and_wait(msg_id)

    async def search_request(
        self,
        base_object: str,
    ) -> None:
        msg_id = self.protocol.search_request(
            base_object=base_object,
            scope=sansldap.SearchScope.SUBTREE,
            dereferencing_policy=sansldap.DereferencingPolicy.NEVER,
            size_limit=0,
            time_limit=0,
            types_only=False,
            filter=sansldap.FilterPresent("objectClass"),
            attributes=["schemaNamingContext"],
            controls=None,
        )
        await self._send_and_wait(msg_id)

    async def _read_loop(self) -> None:
        while True:
            try:
                resp = await self._reader.read(4096)
            except Exception as e:
                for awaiter in self._incoming_messages.values():
                    awaiter.free(e)

                self._incoming_messages = {}
                break

            try:
                self.protocol.receive(resp)
            except sansldap.ProtocolError as e:
                # FIXME: Shutdown client properly
                for awaiter in self._incoming_messages.values():
                    awaiter.free(e)

                self._incoming_messages = {}
                break

            response = self.protocol.next_event()
            if response:
                response_awaiter = self._incoming_messages.pop(response.message_id)

                try:
                    await self._process_msg(response)
                except Exception as e:
                    response_awaiter.free(e)
                else:
                    response_awaiter.free()

    async def _send_and_wait(
        self,
        msg_id: int,
    ) -> None:
        response_awaiter = ResponseAwaiter()
        self._incoming_messages[msg_id] = response_awaiter

        data = self.protocol.data_to_send()
        self._writer.write(data)
        await self._writer.drain()

        await response_awaiter.wait()

    @functools.singledispatchmethod
    async def _process_msg(self, msg: sansldap.LDAPMessage) -> None:
        return

    @_process_msg.register
    async def _(self, msg: sansldap.BindResponse) -> None:
        if msg.result.result_code != sansldap.LDAPResultCode.SUCCESS:
            raise LDAPResultError("Bind error", msg.result)
