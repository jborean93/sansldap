# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum
import typing as t


class SessionState(enum.Enum):
    BEFORE_OPEN = enum.auto()
    BINDING = enum.auto()
    OPENED = enum.auto()
    CLOSED = enum.auto()


class LDAPConnection:
    def __init__(self) -> None:
        pass

    def send(self) -> None:
        ...

    def data_to_send(self) -> bytes:
        return b""

    def receive(self) -> None:
        ...

    def next_event(self) -> None:
        ...


class LDAPClient(LDAPConnection):
    def bind(
        self,
        dn: str,
        password: str,
        controls: t.Optional[t.Iterable[t.Any]] = None,
    ) -> int:
        return 0

    def sasl_bind(
        self,
        dn: str,
        mechanism: str,
        cred: bytes,
        controls: t.Optional[t.Iterable[t.Any]] = None,
    ) -> int:
        return 0

    def extended_request(
        self,
        name: str,
        value: t.Optional[bytes] = None,
        controls: t.Optional[t.Iterable[t.Any]] = None,
    ) -> int:
        return 0

    def search_request(
        self,
        base_object: str,
        scope: int,
        dereferencing_policy: int,
        size_limit: int,
        time_limit: int,
        types_only: bool,
        filter: str,
        attributes: t.List[str],
        controls: t.Optional[t.Iterable[t.Any]] = None,
    ) -> int:
        return 0

    def unbind(self) -> int:
        return 0


class LDAPServer(LDAPConnection):
    ...
