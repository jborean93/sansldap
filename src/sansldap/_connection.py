# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum
import typing as t

from ._controls import LDAPControl
from ._filter import LDAPFilter
from ._messages import (
    BindRequest,
    DereferencingPolicy,
    ExtendedRequest,
    LDAPMessage,
    SaslCredential,
    SearchRequest,
    SearchScope,
    SimpleCredential,
    UnbindRequest,
)


class SessionState(enum.Enum):
    BEFORE_OPEN = enum.auto()
    BINDING = enum.auto()
    OPENED = enum.auto()
    CLOSED = enum.auto()


class LDAPConnection:
    def __init__(self) -> None:
        self._buffer = bytearray()
        self._message_counter = 1

    def _send(
        self,
        msg: LDAPMessage,
    ) -> int:
        msg_id = self._message_counter
        self._message_counter += 1
        self._buffer.extend(msg.pack())

        return msg_id

    def data_to_send(self) -> bytes:
        data = bytes(self._buffer)
        self._buffer = bytearray()

        return data

    def receive(self) -> None:
        ...

    def next_event(self) -> None:
        ...


class LDAPClient(LDAPConnection):
    def bind(
        self,
        dn: str,
        password: str,
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        msg = BindRequest(
            message_id=0,
            controls=controls or [],
            version=3,
            name=dn,
            authentication=SimpleCredential(password=password),
        )
        return self._send(msg)

    def sasl_bind(
        self,
        dn: str,
        mechanism: str,
        cred: bytes,
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        msg = BindRequest(
            message_id=0,
            controls=controls or [],
            version=3,
            name=dn,
            authentication=SaslCredential(
                mechanism=mechanism,
                credentials=cred,
            ),
        )
        return self._send(msg)

    def extended_request(
        self,
        name: str,
        value: t.Optional[bytes] = None,
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        msg = ExtendedRequest(
            message_id=0,
            controls=controls or [],
            name=name,
            value=value,
        )
        return self._send(msg)

    def search_request(
        self,
        base_object: str,
        scope: t.Union[int, SearchScope],
        dereferencing_policy: t.Union[int, DereferencingPolicy],
        size_limit: int,
        time_limit: int,
        types_only: bool,
        filter: LDAPFilter,
        attributes: t.List[str],
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        msg = SearchRequest(
            message_id=0,
            controls=controls or [],
            base_object=base_object,
            scope=SearchScope(scope),
            deref_aliases=DereferencingPolicy(dereferencing_policy),
            size_limit=size_limit,
            time_limit=time_limit,
            types_only=types_only,
            filter=filter,
            attributes=attributes,
        )
        return self._send(msg)

    def unbind(self) -> int:
        msg = UnbindRequest(
            message_id=0,
            controls=[],
        )
        return self._send(msg)


class LDAPServer(LDAPConnection):
    ...
