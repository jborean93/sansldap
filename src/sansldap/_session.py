# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum
import typing as t

from ._asn1 import ASN1Reader, NotEnougData
from ._controls import LDAPControl
from ._filter import LDAPFilter
from ._messages import (
    BindRequest,
    BindResponse,
    DereferencingPolicy,
    ExtendedRequest,
    ExtendedResponse,
    LDAPMessage,
    LDAPResult,
    LDAPResultCode,
    SaslCredential,
    SearchRequest,
    SearchScope,
    SimpleCredential,
    UnbindRequest,
    unpack_ldap_message,
)

LDAP_NOTICE_OF_DISCONNECTION = "1.3.6.1.4.1.1466.20036"


class LDAPError(Exception):
    """Base LDAP error class."""


class StateError(LDAPError):
    """LDAP session is not in the required state."""


class ProtocolError(LDAPError):
    """Generic LDAP protocol errors.

    An exception used to signal a fatal error during the LDAP session. It can
    be caused by trying to parse an invalid input message or from a Notice of
    Disconnection error from the server. The caller should immediately close
    the underlying connection upon receiving this error.

    Args:
        result: The LDAPResult if present that may contain more details.
    """

    def __init__(
        self,
        msg: str,
        result: t.Optional[LDAPResult] = None,
    ) -> None:
        super().__init__(msg)
        self.result = result


class SessionState(enum.Enum):
    """The state of the LDAP session."""

    BEFORE_OPEN = enum.auto()
    "The session has not been opened and no messages were created or received."

    BINDING = enum.auto()
    "The session is currently being bound."

    OPENED = enum.auto()
    "The session is opened and ready for additional requests."

    CLOSED = enum.auto()
    "The session has been closed either from an Unbind or ProtocolError."


class LDAPSession:
    def __init__(self) -> None:
        self.state = SessionState.BEFORE_OPEN
        self.version = 3

        self._outgoing_buffer = bytearray()
        self._incoming_buffer = bytearray()
        self._incoming_msgs: t.Dict[int, LDAPMessage] = {}

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
        if self.state == SessionState.CLOSED:
            raise ProtocolError("Cannot receive more data on a closed LDAP session")

        # If there is leftover data in the buffer then use that, otherwise
        # try to unpack directly from the input to avoid copying it if it's not
        # needed.
        try:
            incoming_msgs: t.List[LDAPMessage] = []

            if self._incoming_buffer:
                self._incoming_buffer.extend(data)
                reader = ASN1Reader(self._incoming_buffer)
                while reader:
                    try:
                        msg = unpack_ldap_message(reader)
                    except NotEnougData:
                        break

                    incoming_msgs.append(msg)

                self._incoming_buffer = bytearray(reader.get_remaining_data())

            else:
                reader = ASN1Reader(data)

                while reader:
                    try:
                        msg = unpack_ldap_message(reader)
                    except NotEnougData:
                        self._incoming_buffer = bytearray(reader.get_remaining_data())
                        break

                    incoming_msgs.append(msg)

            for msg in incoming_msgs:
                # Check to see if the msg is a NoticeOfDisconnect
                if isinstance(msg, ExtendedResponse) and msg.name == LDAP_NOTICE_OF_DISCONNECTION:
                    self.state = SessionState.CLOSED
                    error_msg = f"Peer has sent a NoticeOfDisconnect response {msg.result.result_code.name}"
                    if msg.result.diagnostics_message:
                        error_msg += f": {msg.result.diagnostics_message}"
                    raise ProtocolError(error_msg, result=msg.result)

                elif isinstance(msg, UnbindRequest):
                    self.state = SessionState.CLOSED

                self._add_incoming_message(msg)

        except (ValueError, NotImplementedError) as e:
            raise ProtocolError(f"Received invalid data from the peer, connection closing: {e}") from e

        except ProtocolError:
            raise

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

    def unbind(self) -> None:
        """Send an unbind request.

        Sends the UnbindRequest message to the peer. This will mark the state
        as closed and no more operations can be issued after calling this
        function. The caller should also close the TCP connection once sending
        the UnbindRequest payload. No response is expected for this request.
        """
        msg = UnbindRequest(
            message_id=0,
            controls=[],
        )
        self._send(msg)
        self.state = SessionState.CLOSED

    def _add_incoming_message(
        self,
        msg: LDAPMessage,
    ) -> None:
        self._incoming_msgs[msg.message_id] = msg

    def _send(
        self,
        msg: LDAPMessage,
    ) -> int:
        if self.state == SessionState.CLOSED:
            raise StateError("LDAP session is CLOSED, cannot send any new messages.")

        self._outgoing_buffer.extend(msg.pack())

        return msg.message_id


class LDAPClient(LDAPSession):
    def __init__(self) -> None:
        super().__init__()
        self._outstanding_requests: t.Set[int] = set()
        self._message_counter = 1

    def bind_simple(
        self,
        dn: t.Optional[str] = None,
        password: t.Optional[str] = None,
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        return self._bind(
            dn or "",
            authentication=SimpleCredential(password=password or ""),
            controls=controls,
        )

    def bind_sasl(
        self,
        dn: str,
        mechanism: str,
        cred: bytes,
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        return self._bind(
            dn,
            authentication=SaslCredential(
                mechanism=mechanism,
                credentials=cred,
            ),
            controls=controls,
        )

    def _bind(
        self,
        dn: str,
        authentication: t.Union[SimpleCredential, SaslCredential],
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        if self._outstanding_requests:
            raise StateError("All outstanding requests must be completed to send a BindRequest")

        msg = BindRequest(
            message_id=0,
            controls=controls or [],
            version=self.version,
            name=dn,
            authentication=authentication,
        )

        msg_id = self._send(msg)
        self.state = SessionState.BINDING
        return msg_id

    def extended_request(
        self,
        name: str,
        value: t.Optional[bytes] = None,
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        if self.state == SessionState.BINDING:
            raise StateError("Cannot send an ExtendedRequest while the session is BINDING")

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
        if self.state != SessionState.OPENED:
            raise StateError(f"Cannot send a SearchRequest while the session is {self.state.name} and not OPENED")

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

    def _add_incoming_message(
        self,
        msg: LDAPMessage,
    ) -> None:
        if msg.message_id not in self._outstanding_requests:
            raise ProtocolError(f"Received unexpected message id response {msg.message_id} from server")

        elif isinstance(msg, BindResponse) and msg.result.result_code == LDAPResultCode.SUCCESS:
            self.state = SessionState.OPENED

        self._outstanding_requests.remove(msg.message_id)

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


class LDAPServer(LDAPSession):
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
        if result_code == LDAPResultCode.SUCCESS:
            self.state == SessionState.OPENED

        return self._send(msg)

    def extended_response(
        self,
        message_id: int,
        result_code: LDAPResultCode = LDAPResultCode.SUCCESS,
        matched_dn: t.Optional[str] = None,
        diagnostics_message: t.Optional[str] = None,
        referrals: t.Optional[t.List[str]] = None,
        name: t.Optional[str] = None,
        value: t.Optional[bytes] = None,
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        msg = ExtendedResponse(
            message_id=message_id,
            controls=controls or [],
            result=LDAPResult(
                result_code=result_code,
                matched_dn=matched_dn or "",
                diagnostics_message=diagnostics_message or "",
                referrals=referrals or [],
            ),
            name=name,
            value=value,
        )
        return self._send(msg)

    def receive(
        self,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> None:
        try:
            return super().receive(data)
        except ProtocolError as e:
            if self.state != SessionState.CLOSED:
                self.extended_response(
                    message_id=0,
                    result_code=LDAPResultCode.PROTOCOL_ERROR,
                    diagnostics_message=str(e),
                    name=LDAP_NOTICE_OF_DISCONNECTION,
                )
                self.state = SessionState.CLOSED

            raise

    def _add_incoming_message(
        self,
        msg: LDAPMessage,
    ) -> None:
        if isinstance(msg, BindRequest):
            self.state = SessionState.BINDING

        super()._add_incoming_message(msg)
