# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum
import typing as t

from ._asn1 import NotEnougData
from ._controls import LDAPControl
from ._filter import LDAPFilter
from ._messages import (
    BindRequest,
    BindResponse,
    DereferencingPolicy,
    ExtendedRequest,
    LDAPMessage,
    LDAPResult,
    LDAPResultCode,
    SaslCredential,
    SearchRequest,
    SearchScope,
    SimpleCredential,
    UnbindRequest,
)


class ProtocolError(Exception):
    """Generic error to signal a protocol exception occurred."""


class SessionState(enum.Enum):
    BEFORE_OPEN = enum.auto()
    BINDING = enum.auto()
    OPENED = enum.auto()
    CLOSED = enum.auto()


class LDAPConnection:
    def __init__(self) -> None:
        self.state = SessionState.BEFORE_OPEN
        self.version = 3

        self._outgoing_buffer = bytearray()
        self._incoming_buffer = bytearray()
        self._incoming_msgs: t.Dict[int, LDAPMessage] = {}

    def _send(
        self,
        msg: LDAPMessage,
    ) -> int:
        self._outgoing_buffer.extend(msg.pack())

        return msg.message_id

    def data_to_send(
        self,
        amount: t.Optional[int] = None,
    ) -> bytes:
        """Get data to send to the peer.

        Gets the data available in the outgoing buffer to send to the peer. If
        amount is not specified then the whole outgoing buffer is returned.
        Otherwise only the data up to the amount specified is returned.

        Args:
            amount: The length of the output to return, otherwise all data will
                be returned if None.

        Returns:
            bytes: The data to send to the peer.
        """
        if amount is None:
            amount = len(self._outgoing_buffer)

        data = bytes(self._outgoing_buffer[:amount])
        self._data_to_send = self._outgoing_buffer[amount:]

        return data

    def receive(
        self,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> None:
        """Receive data to process.

        Receives the data from the peer and unpack the messages found into
        LDAPMessages. Any LDAP payloads received will be stored internally
        retrieved by :func:next_event. A ProtocolError indicates something fatal
        occurred when trying to parse the incoming data and the connection is
        no longer in a valid state. The caller SHOULD send the notice of
        disconnection payload available in :func:data_to_send and MUST close
        the underlying connection. A ProtocolError does not include a valid
        LDAPMessage response with a result code that is not SUCCESS.

        Args:
            data: The data to process.

        Raises:
            ProtocolError: A protocol violation occurred and the connection is
                no longer valid.
        """
        # If there is leftover data in the buffer then use that, otherwise
        # try to unpack directly from the input to avoid copying it if it's not
        # needed.
        try:
            if self._incoming_buffer:
                self._incoming_buffer.extend(data)
                while self._incoming_buffer:
                    try:
                        msg, consumed = LDAPMessage.unpack(self._incoming_buffer)
                    except NotEnougData:
                        break

                    self._incoming_buffer = self._incoming_buffer[consumed:]
                    self._add_incoming_message(msg)

            else:
                view = memoryview(data)

                while view:
                    try:
                        msg, consumed = LDAPMessage.unpack(view)
                    except NotEnougData:
                        self._incoming_buffer.extend(view)
                        break

                    view = view[consumed:]
                    self._add_incoming_message(msg)
        except (ValueError, NotImplementedError) as e:
            # FIXME: Unbind or some other request here?
            raise ProtocolError(f"Received invalid data from the peer, connection closing: {e}") from e

    def next_event(
        self,
        message_id: t.Optional[int] = None,
    ) -> t.Optional[LDAPMessage]:
        """Get the next LDAP message received.

        Gets the next LDAP message received or the message matching the
        message_id if specified.

        Args:
            message_id: Optionally get the next LDAP message for the message id
                specified. If not set then the next LDAP message is returned.

        Returns:
            Optional[LDAPMessage]: The next LDAP message, or None if there are
            no messages.
        """
        if message_id is not None:
            return self._incoming_msgs.pop(message_id, None)

        elif len(self._incoming_msgs):
            message_id = next(iter(self._incoming_msgs.keys()))
            return self._incoming_msgs.pop(message_id)

        return None

    def _add_incoming_message(
        self,
        msg: LDAPMessage,
    ) -> None:
        self._incoming_msgs[msg.message_id] = msg


class LDAPClient(LDAPConnection):
    def __init__(self) -> None:
        super().__init__()
        self._outstanding_requests: t.Set[int] = set()
        self._message_counter = 1

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
            version=self.version,
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

    def _add_incoming_message(
        self,
        msg: LDAPMessage,
    ) -> None:
        if msg.message_id not in self._outstanding_requests:
            raise Exception("FIXME exc type: Received unexpected response")

        return super()._add_incoming_message(msg)

    def _send(
        self,
        msg: LDAPMessage,
    ) -> int:
        msg_id = self._message_counter
        self._message_counter += 1
        msg.message_id = msg_id
        self._outstanding_requests.add(msg_id)

        return super()._send(msg)


class LDAPServer(LDAPConnection):
    def bind_response(
        self,
        message_id: int,
        result_code: LDAPResultCode = LDAPResultCode.SUCCESS,
        matched_dn: t.Optional[str] = None,
        diagnostics_message: t.Optional[str] = None,
        referrals: t.Optional[t.List[str]] = None,
        sasl_creds: t.Optional[bytes] = None,
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        msg = BindResponse(
            message_id=message_id,
            controls=controls or [],
            result=LDAPResult(
                result_code=result_code,
                matched_dn=matched_dn or "",
                diagnostics_message=diagnostics_message or "",
                referrals=referrals or [],
            ),
            server_sasl_creds=sasl_creds,
        )
        return self._send(msg)
