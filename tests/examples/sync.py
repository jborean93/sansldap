# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import socket
import ssl
import threading
import typing as t

import sansldap

from .exceptions import LDAPResultError
from .sasl import SaslProvider

MessageType = t.TypeVar("MessageType", bound=sansldap.LDAPMessage)


def create_sync_ldap_client(
    server: str,
    port: t.Optional[int] = None,
    ssl_context: t.Optional[ssl.SSLContext] = None,
) -> SyncLDAPClient:
    """Creates the LDAP client.

    Creates the LDAP client with an asyncio connection.

    Args:
        server: The server to connect to.
        port: The port to connect with, defaults to 389 if no ssl_context is
            set, else 636 (LDAPS).
        ssl_context: The SSL context to use, when set LDAPS is used and the
            default port changes to 636.

    Returns:
        LDAPClient: The LDAP client.
    """
    port = port if port is not None else (389 if ssl_context is None else 636)

    sock = socket.create_connection((server, port))
    if ssl_context:
        sock = ssl_context.wrap_socket(sock, server_hostname=server)

    return SyncLDAPClient(server, sock)


class ResponseHandler(t.Generic[MessageType]):
    def __init__(
        self,
        message_id: int,
        message_types: t.Tuple[t.Type[MessageType], ...],
    ) -> None:
        self._message_id = message_id
        self._message_types = message_types
        self._condition = threading.Condition()
        self._exp: t.Optional[Exception] = None
        self._results: t.List[MessageType] = []

    def __iter__(self) -> t.Iterator[MessageType]:
        return self._iter_next()

    def append(
        self,
        value: t.Union[Exception, MessageType],
    ) -> None:
        with self._condition:
            if isinstance(value, Exception):
                self._exp = value
            elif isinstance(value, self._message_types) and value.message_id == self._message_id:
                self._results.append(value)
            else:
                return

            self._condition.notify_all()

    def _iter_next(self) -> t.Iterator[MessageType]:
        idx = 0
        while True:
            with self._condition:
                if self._exp:
                    raise Exception(f"Exception from receiving task: {self._exp}") from self._exp

                if idx < len(self._results):
                    value = self._results[idx]
                    idx += 1
                    yield value

                else:
                    self._condition.wait()


class SyncLDAPClient:
    def __init__(
        self,
        server: str,
        sock: t.Union[socket.socket, ssl.SSLSocket],
    ) -> None:
        self.server = server

        self._protocol = sansldap.LDAPClient()
        self._sock = sock
        self._response_handler: t.List[ResponseHandler] = []
        self._sasl_provider: t.Optional[SaslProvider] = None
        self._reader_task = threading.Thread(
            target=self._read_loop,
            name=f"LDAP({server})",
        )
        self._reader_task.start()
        self._wait_tls: t.Optional[threading.Event] = None

    def __enter__(self) -> SyncLDAPClient:
        return self

    def __exit__(self, *args: t.Any, **kwargs: t.Any) -> None:
        self.close()

    def bind_sasl(
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
            response = self._write_and_wait_one(msg_id, sansldap.BindResponse)

            if response.result.result_code not in [
                sansldap.LDAPResultCode.SUCCESS,
                sansldap.LDAPResultCode.SASL_BIND_IN_PROGRESS,
            ]:
                raise LDAPResultError("SASL bind failed", response.result)

            in_token = response.server_sasl_creds

        if response.result.result_code != sansldap.LDAPResultCode.SUCCESS:
            raise LDAPResultError("SASL bind failed", response.result)

        self._sasl_provider = provider

    def bind_simple(
        self,
        username: t.Optional[str] = None,
        password: t.Optional[str] = None,
    ) -> None:
        msg_id = self._protocol.bind_simple(username, password)
        response = self._write_and_wait_one(msg_id, sansldap.BindResponse)

        self._valid_result(response.result, "simple bind failed")

    def close(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass  # May have already been closed
        self._sock.close()
        self._reader_task.join()

    def search_request(
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
    ) -> t.Iterator[t.Union[sansldap.SearchResultDone, sansldap.SearchResultReference, sansldap.SearchResultEntry]]:
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
            self._write_msg()
            for res in handler:
                if isinstance(res, sansldap.SearchResultDone):
                    self._valid_result(res.result, "search request failed")

                    yield res
                    break

                else:
                    yield res  # type: ignore[misc]

        finally:
            self._unregister_response_handler(handler)

    def start_tls(
        self,
        options: ssl.SSLContext,
        *,
        server_hostname: t.Optional[str] = None,
    ) -> None:
        msg_id = self._protocol.extended_request(sansldap.ExtendedOperations.LDAP_START_TLS.value)
        self._wait_tls = wait_event = threading.Event()
        try:
            response = self._write_and_wait_one(msg_id, sansldap.ExtendedResponse)
            self._valid_result(response.result, "StartTLS failed")

            self._sock = options.wrap_socket(
                self._sock,
                server_hostname=server_hostname or self.server,
            )
        finally:
            wait_event.set()

    def whoami(self) -> str:
        """LDAP Whoami.

        Performs an LDAP Whoami extended request to get the authenticated user
        name for the bound connection.

        Returns:
            str: The authenticated user returned by the server.
        """
        msg_id = self._protocol.extended_request("1.3.6.1.4.1.4203.1.11.3")
        response = self._write_and_wait_one(msg_id, sansldap.ExtendedResponse)
        self._valid_result(response.result, "whoami request failed")

        return response.value.decode("utf-8") if response.value else ""

    def _read_loop(self) -> None:
        data_buffer = bytearray()
        while True:
            try:
                resp = self._sock.recv(4096)
                if not resp:
                    raise Exception("LDAP connection has been shutdown")

                data_buffer.extend(resp)

                while data_buffer:
                    if self._sasl_provider:
                        dec_data, enc_len = self._sasl_provider.unwrap(data_buffer)
                        if enc_len == 0:
                            break

                        data_buffer = data_buffer[enc_len:]
                    else:
                        dec_data = bytes(data_buffer)
                        data_buffer = bytearray()

                    for msg in self._protocol.receive(dec_data):
                        for handler in self._response_handler:
                            handler.append(msg)

                        if (
                            isinstance(msg, sansldap.ExtendedResponse)
                            and msg.name == sansldap.ExtendedOperations.LDAP_START_TLS.value
                            and self._wait_tls
                        ):
                            # Need to wait until the sock object has been
                            # updated in start_tls() before issuing another
                            # recv.
                            self._wait_tls.wait()
                            self._wait_tls = None

            except sansldap.ProtocolError as e:
                if e.response:
                    self._sock.sendall(e.response)

                for handler in self._response_handler:
                    handler.append(e)
                break

            except Exception as e:
                for handler in self._response_handler:
                    handler.append(e)
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

    def _valid_result(
        self,
        result: sansldap.LDAPResult,
        msg: str,
    ) -> None:
        if result.result_code != sansldap.LDAPResultCode.SUCCESS:
            raise LDAPResultError(msg, result)

    def _unregister_response_handler(
        self,
        handler: ResponseHandler,
    ) -> None:
        self._response_handler.remove(handler)

    def _write_and_wait_one(
        self,
        msg_id: int,
        message_type: t.Type[MessageType],
    ) -> MessageType:
        handler = self._register_response_handler(msg_id, message_type)
        try:
            self._write_msg()

            return handler.__iter__().__next__()

        finally:
            self._unregister_response_handler(handler)

    def _write_msg(self) -> None:
        data = self._protocol.data_to_send()
        if self._sasl_provider:
            data = self._sasl_provider.wrap(data)

        self._sock.sendall(data)
