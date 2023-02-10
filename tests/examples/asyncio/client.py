# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import asyncio
import ssl
import typing as t

import sansldap

from .sasl import SaslProvider

MessageType = t.TypeVar("MessageType", bound=sansldap.LDAPMessage)


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

    return LDAPClient(server, reader, writer)


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


class ResponseHandler(t.Generic[MessageType]):
    def __init__(
        self,
        message_id: int,
        message_types: t.Tuple[t.Type[MessageType], ...],
    ) -> None:
        self._message_id = message_id
        self._message_types = message_types
        self._condition = asyncio.Condition()
        self._exp: t.Optional[Exception] = None
        self._results: t.List[MessageType] = []

    def __aiter__(self) -> t.AsyncIterator[MessageType]:
        return self._aiter_next()

    async def append(
        self,
        value: t.Union[Exception, MessageType],
    ) -> None:
        async with self._condition:
            if isinstance(value, Exception):
                self._exp = value
            elif isinstance(value, self._message_types) and value.message_id == self._message_id:
                self._results.append(value)
            else:
                return

            self._condition.notify_all()

    async def _aiter_next(self) -> t.AsyncIterator[MessageType]:
        idx = 0
        while True:
            async with self._condition:
                if self._exp:
                    raise Exception(f"Exception from receiving task: {self._exp}") from self._exp

                if idx < len(self._results):
                    value = self._results[idx]
                    idx += 1
                    yield value

                else:
                    await self._condition.wait()


class LDAPClient:
    def __init__(
        self,
        server: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.server = server
        self._protocol = sansldap.LDAPClient()

        self._reader = reader
        self._writer = writer
        self._reader_task = asyncio.create_task(self._read_loop())
        self._response_handler: t.List[ResponseHandler] = []
        self._sasl_provider: t.Optional[SaslProvider] = None

    @property
    def state(self) -> sansldap.SessionState:
        return self._protocol.state

    async def __aenter__(self) -> LDAPClient:
        return self

    async def __aexit__(
        self,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> None:
        await self.close()

    async def bind_sasl(
        self,
        provider: SaslProvider,
    ) -> None:
        tls_channel: t.Optional[ssl.SSLObject] = None
        in_token: t.Optional[bytes] = None

        while True:
            out_token = provider.step(in_token=in_token, tls_channel=tls_channel)
            if out_token is None:
                break

            msg_id = self._protocol.bind_sasl(provider.mechanism, cred=out_token)
            response = await self._write_and_wait_one(msg_id, sansldap.BindResponse)

            if response.result.result_code not in [
                sansldap.LDAPResultCode.SUCCESS,
                sansldap.LDAPResultCode.SASL_BIND_IN_PROGRESS,
            ]:
                raise LDAPResultError("SASL bind failed", response.result)

            in_token = response.server_sasl_creds

        if response.result.result_code != sansldap.LDAPResultCode.SUCCESS:
            raise LDAPResultError("SASL bind failed", response.result)

        self._sasl_provider = provider

    async def bind_simple(
        self,
        username: t.Optional[str] = None,
        password: t.Optional[str] = None,
    ) -> None:
        msg_id = self._protocol.bind_simple(username, password)
        response = await self._write_and_wait_one(msg_id, sansldap.BindResponse)

        self._valid_result(response.result, "simple bind failed")

    async def close(self) -> None:
        self._writer.close()
        await self._writer.wait_closed()
        await self._reader_task

    async def search_request(
        self,
        base_object: t.Optional[str] = None,
        scope: t.Union[int, sansldap.SearchScope] = sansldap.SearchScope.SUBTREE,
        dereferencing_policy: t.Union[int, sansldap.DereferencingPolicy] = sansldap.DereferencingPolicy.NEVER,
        size_limit: int = 0,
        time_limit: int = 0,
        types_only: bool = False,
        filter: t.Optional[t.Union[str, sansldap.LDAPFilter]] = None,
        attributes: t.Optional[t.List[str]] = None,
        controls: t.Optional[t.List[sansldap.LDAPControl]] = None,
    ) -> t.AsyncIterator[t.Union[sansldap.SearchResultEntry, sansldap.SearchResultReference]]:
        ldap_filter: t.Optional[sansldap.LDAPFilter] = None
        if isinstance(filter, sansldap.LDAPFilter):
            ldap_filter = filter
        elif filter:
            ldap_filter = sansldap.LDAPFilter.from_string(filter)

        msg_id = self._protocol.search_request(
            base_object=base_object,
            scope=scope,
            dereferencing_policy=dereferencing_policy,
            size_limit=size_limit,
            time_limit=time_limit,
            types_only=types_only,
            filter=ldap_filter,
            attributes=attributes,
            controls=controls,
        )

        handler = self._register_response_handler(
            msg_id,
            sansldap.SearchResultEntry,
            sansldap.SearchResultReference,
            sansldap.SearchResultDone,
        )
        try:
            await self._write_msg()
            async for res in handler:
                if isinstance(res, sansldap.SearchResultDone):
                    self._valid_result(res.result, "search request failed")
                    break

                else:
                    yield res  # type: ignore[misc]

        finally:
            self._unregister_response_handler(handler)

    async def start_tls(
        self,
        options: ssl.SSLContext,
        *,
        server_hostname: t.Optional[str] = None,
        ssl_handshake_timeout: t.Optional[int] = None,
    ) -> None:
        # start_tls was added in Python 3.11
        if not hasattr(self._writer, "start_tls"):
            raise Exception("Need Python 3.11 for StartTLS")

        msg_id = self._protocol.extended_request(sansldap.ExtendedOperations.LDAP_START_TLS.value)
        response = await self._write_and_wait_one(msg_id, sansldap.ExtendedResponse)
        self._valid_result(response.result, "StartTLS failed")

        await self._writer.start_tls(
            options,
            server_hostname=server_hostname,
            ssl_handshake_timeout=ssl_handshake_timeout,
        )

    async def whoami(self) -> str:
        msg_id = self._protocol.extended_request("1.3.6.1.4.1.4203.1.11.3")
        response = await self._write_and_wait_one(msg_id, sansldap.ExtendedResponse)
        self._valid_result(response.result, "whoami request failed")

        return response.value.decode("utf-8") if response.value else ""

    async def _read_loop(self) -> None:
        data_buffer = bytearray()
        while True:
            try:
                resp = await self._reader.read(4096)
                if not resp:
                    raise Exception("LDAP connection has been shutdown")

                data_buffer.extend(resp)

                while data_buffer:
                    if self._sasl_provider and False:
                        dec_data, enc_len = self._sasl_provider.unwrap(data_buffer)
                        if enc_len == 0:
                            continue

                        data_buffer = data_buffer[enc_len:]
                    else:
                        dec_data = bytes(data_buffer)
                        data_buffer = bytearray()

                    for msg in self._protocol.receive(dec_data):
                        for handler in self._response_handler:
                            await handler.append(msg)

            except sansldap.ProtocolError as e:
                if e.response:
                    self._writer.write(e.response)
                    await self._writer.drain()

                for handler in self._response_handler:
                    await handler.append(e)
                break

            except Exception as e:
                for handler in self._response_handler:
                    await handler.append(e)
                break

    def _register_response_handler(
        self,
        msg_id: int,
        *message_types: t.Type[MessageType],
    ) -> ResponseHandler[MessageType]:
        handler = ResponseHandler(
            msg_id,
            message_types,
        )
        self._response_handler.append(handler)

        return handler

    def _unregister_response_handler(
        self,
        handler: ResponseHandler,
    ) -> None:
        self._response_handler.remove(handler)

    def _valid_result(
        self,
        result: sansldap.LDAPResult,
        msg: str,
    ) -> None:
        if result.result_code != sansldap.LDAPResultCode.SUCCESS:
            raise LDAPResultError(msg, result)

    async def _write_and_wait_one(
        self,
        msg_id: int,
        message_type: t.Type[MessageType],
    ) -> MessageType:
        handler = self._register_response_handler(msg_id, message_type)
        try:
            await self._write_msg()

            return await handler.__aiter__().__anext__()

        finally:
            self._unregister_response_handler(handler)

    async def _write_msg(self) -> None:
        data = self._protocol.data_to_send()
        if self._sasl_provider:
            data = self._sasl_provider.wrap(data)

        self._writer.write(data)
        await self._writer.drain()
