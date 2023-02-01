# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum
import typing as t

from ._authentication import (
    AuthenticationCredential,
    AuthenticationOptions,
    SaslCredential,
    SimpleCredential,
)
from ._controls import ControlOptions, LDAPControl
from ._filter import FilterOptions, FilterPresent, LDAPFilter
from ._messages import (
    BindRequest,
    BindResponse,
    DereferencingPolicy,
    ExtendedRequest,
    ExtendedResponse,
    LDAPMessage,
    LDAPResult,
    LDAPResultCode,
    PackingOptions,
    Request,
    Response,
    SearchRequest,
    SearchScope,
    UnbindRequest,
    unpack_ldap_message,
)
from .asn1 import ASN1Reader, NotEnougData


class ExtendedOperations(enum.StrEnum):
    """Known LDAP Extended Operation Names."""

    LDAP_NOTICE_OF_DISCONNECTION = "1.3.6.1.4.1.1466.20036"
    LDAP_START_TLS = "1.3.6.1.4.1.1466.20037"


class LDAPError(Exception):
    """Base LDAP error class."""


class ProtocolError(LDAPError):
    """Generic LDAP protocol errors.

    An exception used to signal a fatal error during the LDAP session. It can
    be caused by trying to parse an invalid input message or from a Notice of
    Disconnection error from the server. The caller should send the response,
    if present, to the peer and then close the underlying connection upon
    receiving this error.

    Args:
        request: The incoming message that caused the protocol error, or None
            if the incoming data could not be unpacked.
        response: Optional message to send to the peer to notify of it being
            disconnected.
    """

    def __init__(
        self,
        msg: str,
        request: t.Optional[LDAPMessage] = None,
        response: t.Optional[bytes] = None,
    ) -> None:
        super().__init__(msg)
        self.request = request
        self.response = response


class SessionState(enum.Enum):
    """The state of the LDAP session."""

    BEFORE_OPEN = enum.auto()
    "The session has not been opened and no messages were created or received."

    BINDING = enum.auto()
    "The session is currently going through a binding operation."

    OPENED = enum.auto()
    "The session has been opened and a message sent or received."

    CLOSED = enum.auto()
    "The session has been closed either from an Unbind or ProtocolError."


class LDAPSession:
    def __init__(self) -> None:
        self.state = SessionState.BEFORE_OPEN
        self.version = 3

        string_encoding = "utf-8"

        self._outgoing_buffer = bytearray()
        self._outstanding_requests: t.Set[int] = set()
        self._packing_options = PackingOptions(
            string_encoding=string_encoding,
            authentication=AuthenticationOptions(string_encoding=string_encoding),
            control=ControlOptions(string_encoding=string_encoding),
            filter=FilterOptions(string_encoding=string_encoding),
        )
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
                        msg = unpack_ldap_message(reader, self._packing_options)
                    except NotEnougData:
                        break

                    incoming_msgs.append(msg)

                self._incoming_buffer = bytearray(reader.get_remaining_data())

            else:
                reader = ASN1Reader(data)

                while reader:
                    try:
                        msg = unpack_ldap_message(reader, self._packing_options)
                    except NotEnougData:
                        self._incoming_buffer = bytearray(reader.get_remaining_data())
                        break

                    incoming_msgs.append(msg)

            for msg in incoming_msgs:
                # Check to see if the msg is a NoticeOfDisconnect
                if (
                    isinstance(msg, ExtendedResponse)
                    and msg.name == ExtendedOperations.LDAP_NOTICE_OF_DISCONNECTION.value
                ):
                    error_msg = f"Peer has sent a NoticeOfDisconnect response {msg.result.result_code.name}"
                    if msg.result.diagnostics_message:
                        error_msg += f": {msg.result.diagnostics_message}"
                    raise ProtocolError(error_msg, request=msg)

                elif isinstance(msg, UnbindRequest):
                    raise ProtocolError("Received unbind request, connection is closed", request=msg)

                self._add_incoming_message(msg)

        except (ValueError, NotImplementedError) as e:
            raise ProtocolError(f"Received invalid data from the peer, connection closing: {e}") from e

        except ProtocolError:
            self.state = SessionState.CLOSED
            self._outstanding_requests = set()
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

    def register_auth_choice(self, choice: t.Type[AuthenticationCredential]) -> None:
        self._packing_options.authentication.choices.append(choice)

    def register_control(self, control: t.Type[LDAPControl]) -> None:
        self._packing_options.control.choices.append(control)

    def register_filter_choice(self, filter: t.Type[LDAPFilter]) -> None:
        self._packing_options.filter.choices.append(filter)

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
        self._outstanding_requests = set()
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
            raise LDAPError("LDAP session is CLOSED, cannot send any new messages.")

        elif self.state == SessionState.BINDING and not isinstance(msg, (UnbindRequest, BindRequest, BindResponse)):
            raise LDAPError(
                f"LDAP session is BINDING, can only send a BindRequest, BindResponse, or UnbindRequest not {type(msg).__name__}"
            )

        elif self.state == SessionState.BEFORE_OPEN:
            self.state = SessionState.OPENED

        self._outgoing_buffer.extend(msg.pack(self._packing_options))

        return msg.message_id


class LDAPClient(LDAPSession):
    def __init__(self) -> None:
        super().__init__()
        self._message_counter = 1

    def bind_simple(
        self,
        dn: t.Optional[str] = None,
        password: t.Optional[str] = None,
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        return self.bind(
            dn or "",
            authentication=SimpleCredential(password=password or ""),
            controls=controls,
        )

    def bind_sasl(
        self,
        mechanism: str,
        dn: t.Optional[str] = None,
        cred: t.Optional[bytes] = None,
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        return self.bind(
            dn or "",
            authentication=SaslCredential(
                mechanism=mechanism,
                credentials=cred,
            ),
            controls=controls,
        )

    def bind(
        self,
        dn: str,
        authentication: AuthenticationCredential,
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        if self._outstanding_requests:
            raise LDAPError("All outstanding requests must be completed to send a BindRequest")

        msg = BindRequest(
            message_id=0,
            controls=controls or [],
            version=self.version,
            name=dn,
            authentication=authentication,
        )

        self.state = SessionState.BINDING
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
        base_object: t.Optional[str] = None,
        scope: t.Union[int, SearchScope] = SearchScope.SUBTREE,
        dereferencing_policy: t.Union[int, DereferencingPolicy] = DereferencingPolicy.NEVER,
        size_limit: int = 0,
        time_limit: int = 0,
        types_only: bool = False,
        filter: t.Optional[LDAPFilter] = None,
        attributes: t.Optional[t.List[str]] = None,
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        msg = SearchRequest(
            message_id=0,
            controls=controls or [],
            base_object=base_object or "",
            scope=SearchScope(scope),
            deref_aliases=DereferencingPolicy(dereferencing_policy),
            size_limit=size_limit,
            time_limit=time_limit,
            types_only=types_only,
            filter=filter or FilterPresent("objectClass"),
            attributes=attributes or [],
        )
        return self._send(msg)

    def receive(
        self,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> None:
        try:
            return super().receive(data)
        except ProtocolError as e:
            if e.request is None or (
                not isinstance(e.request, UnbindRequest)
                and not (
                    isinstance(e.request, ExtendedResponse)
                    and e.request.name == ExtendedOperations.LDAP_NOTICE_OF_DISCONNECTION.name
                )
            ):
                msg = UnbindRequest(
                    message_id=0,
                    controls=[],
                )
                e.response = msg.pack(self._packing_options)

            raise

    def _add_incoming_message(
        self,
        msg: LDAPMessage,
    ) -> None:
        if not isinstance(msg, Response):
            raise ProtocolError(f"Received an LDAP message that is not a response {type(msg).__name__}, cannot process")

        elif msg.message_id not in self._outstanding_requests:
            raise ProtocolError(f"Received unexpected message id response {msg.message_id} from server")

        if isinstance(msg, BindResponse) and msg.result.result_code == LDAPResultCode.SUCCESS:
            self.state = SessionState.OPENED

        self._outstanding_requests.remove(msg.message_id)

        return super()._add_incoming_message(msg)

    def _send(
        self,
        msg: LDAPMessage,
    ) -> int:
        if isinstance(msg, UnbindRequest):
            return super()._send(msg)

        msg_id = self._message_counter
        msg.message_id = msg_id

        super()._send(msg)

        self._message_counter += 1
        self._outstanding_requests.add(msg_id)

        return msg_id


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
            if e.request is None or not isinstance(e.request, UnbindRequest):
                msg = ExtendedResponse(
                    message_id=0,
                    controls=[],
                    result=LDAPResult(
                        result_code=LDAPResultCode.PROTOCOL_ERROR,
                        matched_dn="",
                        diagnostics_message=str(e),
                        referrals=None,
                    ),
                    name=ExtendedOperations.LDAP_NOTICE_OF_DISCONNECTION.value,
                    value=None,
                )
                e.response = msg.pack(self._packing_options)

            raise

    def _add_incoming_message(
        self,
        msg: LDAPMessage,
    ) -> None:
        if not isinstance(msg, Request):
            raise ProtocolError(f"Received an LDAP message that is not a request {type(msg).__name__}, cannot process")

        if isinstance(msg, BindRequest):
            if self._outstanding_requests:
                raise ProtocolError("Received an LDAP bind request but server still has outstanding operations")

            self.state = SessionState.BINDING

        elif self.state == SessionState.BEFORE_OPEN:
            self.state = SessionState.OPENED

        self._outstanding_requests.add(msg.message_id)
        super()._add_incoming_message(msg)

    def _send(
        self,
        msg: LDAPMessage,
    ) -> int:
        msg_id = super()._send(msg)

        if not isinstance(msg, UnbindRequest):
            if msg_id in self._outstanding_requests:
                self._outstanding_requests.remove(msg_id)
            else:
                raise LDAPError(f"Message {msg} is a response to an unknown request")

        return msg_id
