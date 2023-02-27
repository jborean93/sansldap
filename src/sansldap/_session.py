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
    PartialAttribute,
    Request,
    Response,
    SearchRequest,
    SearchResultDone,
    SearchResultEntry,
    SearchResultReference,
    SearchScope,
    UnbindRequest,
    unpack_ldap_message,
)
from .asn1 import ASN1Reader, NotEnougData


class ExtendedOperations(str, enum.Enum):
    """Known LDAP Extended Operation Names."""

    LDAP_NOTICE_OF_DISCONNECTION = "1.3.6.1.4.1.1466.20036"
    LDAP_START_TLS = "1.3.6.1.4.1.1466.20037"


class LDAPError(Exception):
    """Base LDAP error class."""


class ProtocolError(LDAPError):
    """Generic LDAP protocol errors.

    An exception used to signal a fatal error during the LDAP session. It can
    be caused by trying to parse an invalid input message, from a Notice of
    Disconnection error from the server, or from an UnbindRequest. The caller
    should send the response data, if present, to the peer and then close the
    underlying connection upon receiving this error.

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
    """The state of the LDAP session.

    A new LDAPSession will start with the BEFORE_OPEN state and can send any
    message to the peer.

    The BINDING state occurs when the client sends a BindRequest or the
    server receives that request. Only a BindRequest or BindResponse can be
    sent when BINDING. Once the client receives or the server sends a
    successful BindResponse the state is changed to OPENED.

    The OPENED state either occurs after a successful bind operation occurs or
    when the first message is sent by the client or received by the server that
    is not a BindRequest/BindResponse.

    The CLOSED state occurs when an UnbindRequest is sent/received, an invalid
    payload is received, or a Notice of Disconnection is send/received. Once in
    this state the session can no longer be used.
    """

    BEFORE_OPEN = enum.auto()
    "The session has not been opened and no messages were created or received."

    BINDING = enum.auto()
    "The session is currently going through a binding operation."

    OPENED = enum.auto()
    "The session has been opened and a message sent or received."

    CLOSED = enum.auto()
    "The session has been closed either from an Unbind or ProtocolError."


class LDAPSession:
    """LDAP Session.

    The base class for a client and server LDAP session. It contains the common
    code needed to exchange LDAP messages.

    Attributes:
        state: The current session state.
        version: The LDAP protocol version, currently this is only set to 3.
    """

    def __init__(self) -> None:
        self.state = SessionState.BEFORE_OPEN
        self.version = 3

        string_encoding = "utf-8"

        self._outgoing_buffer = bytearray()
        self._outstanding_requests: t.Set[int] = set()
        self._search_requests: t.Set[int] = set()
        self._packing_options = PackingOptions(
            string_encoding=string_encoding,
            authentication=AuthenticationOptions(string_encoding=string_encoding),
            control=ControlOptions(string_encoding=string_encoding),
            filter=FilterOptions(string_encoding=string_encoding),
        )
        self._incoming_buffer = bytearray()

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
        self._outgoing_buffer = self._outgoing_buffer[amount:]

        return data

    def receive(
        self,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> t.List[LDAPMessage]:
        """Receive data to process.

        Receives the data from the peer and unpack the messages found into
        LDAPMessages. Any complete LDAP messages received will be returned and
        any remaining data will be stored in an internal buffer.A ProtocolError
        indicates something fatal has occurred when trying to parse the
        incoming data and the connection is no longer in a valid state. The
        caller SHOULD send the notice of disconnection payload available in
        :func:`data_to_send` and MUST close the underlying connection.

        Note:
            A ProtocolError is not raised when receiving a valid LDAP response
            with a result code that is not ``SUCCESS``. Only critical errors
            where the session is no longer viable will raise this error.

        Args:
            data: The data to process.

        Returns:
            t.List[LDAPMessage]: A list of messages that have been unpacked.

        Raises:
            ProtocolError: A protocol violation occurred and the connection is
                no longer valid.
        """
        if self.state == SessionState.CLOSED:
            raise ProtocolError("Cannot receive more data on a closed LDAP session")

        incoming_msgs: t.List[LDAPMessage] = []
        try:
            # If there is leftover data in the buffer then use that, otherwise
            # try to unpack directly from the input to avoid copying it if it's
            # not needed.
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

                self._process_incoming_message(msg)

        except (ValueError, NotImplementedError) as e:
            self.state = SessionState.CLOSED
            self._outstanding_requests = set()
            raise ProtocolError(f"Received invalid data from the peer, connection closing: {e}") from e

        except ProtocolError:
            self.state = SessionState.CLOSED
            self._outstanding_requests = set()
            raise

        return incoming_msgs

    def register_auth_credential(
        self,
        auth: t.Type[AuthenticationCredential],
    ) -> None:
        """Register a custom authentication credential.

        Registers a custom :class:`AuthenticationCredential` class that can be
        used for a bind.

        Args:
            auth: The custom authentication credential type to register.
        """
        existing = next(
            (a for a in self._packing_options.authentication.choices if auth.auth_id == a.auth_id),
            None,
        )
        if existing:
            raise ValueError(
                f"An authentication credential of the type {auth.auth_id} has already been registered {type(existing).__name__}"
            )
        self._packing_options.authentication.choices.append(auth)

    def register_control(
        self,
        control: t.Type[LDAPControl],
    ) -> None:
        """Register a custom LDAP control.

        Registers a custom :class:`LDAPControl` class that can be used for
        controls in a request/response.

        Args:
            control: The custom LDAP control type to register.
        """
        existing = next(
            (c for c in self._packing_options.control.choices if control.control_type == c.control_type),
            None,
        )
        if existing:
            raise ValueError(
                f"An LDAP control of the type {control.control_type} has already been registered {type(existing).__name__}"
            )
        self._packing_options.control.choices.append(control)

    def register_filter(
        self,
        filter: t.Type[LDAPFilter],
    ) -> None:
        """Register a custom LDAP filter

        Registers a custom :class:`LDAPFilter` class that can be used for a
        SearchRequest.

        Args:
            filter: The custom LDAP filter type to register.
        """
        existing = next(
            (f for f in self._packing_options.filter.choices if filter.filter_id == f.filter_id),
            None,
        )
        if existing:
            raise ValueError(
                f"An LDAP filter of the type {filter.filter_id} has already been registered {type(existing).__name__}"
            )
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

    def _process_incoming_message(
        self,
        msg: LDAPMessage,
    ) -> None:
        pass

    def _send(
        self,
        msg: LDAPMessage,
    ) -> int:
        if self.state == SessionState.CLOSED:
            raise LDAPError("LDAP session is CLOSED, cannot send any new messages.")

        elif self.state == SessionState.BINDING and (
            not isinstance(msg, (UnbindRequest, BindRequest, BindResponse))
            and not (isinstance(msg, ExtendedResponse) and msg.name == ExtendedOperations.LDAP_NOTICE_OF_DISCONNECTION)
        ):
            raise LDAPError(
                f"LDAP session is BINDING, can only send a BindRequest, BindResponse, or UnbindRequest not {type(msg).__name__}"
            )

        elif self.state == SessionState.BEFORE_OPEN:
            self.state = SessionState.OPENED

        self._outgoing_buffer.extend(msg.pack(self._packing_options))

        return msg.message_id


class LDAPClient(LDAPSession):
    """LDAP Client session.

    The LDAP client session class that is used to send client LDAP messages.
    """

    def __init__(self) -> None:
        super().__init__()
        self._message_counter = 1

    def bind_simple(
        self,
        dn: t.Optional[str] = None,
        password: t.Optional[str] = None,
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        """Send a Simple BIND request.

        Creates a SIMPLE bind request to perform an anonymous, unauthenticate,
        or authenticated bind. The format of dn depends on the LDAP server
        implementation. For example MS AD supports the sAMAccountName value
        while OpenLDAP would require the distinguished name of the user to bind
        as.

        Note:
            You can only run a bind if there are no outstanding requests on the
            session. Once a bind has started, no other requests can be started
            until the bind is complete.

        Args:
            dn: The name of the Directory object that the client wishes to bind
                as. Set to None or an empty string to perform an anonymous
                bind.
            password: The password to bind with, set to None or an empty string
                to perform an unauthenticated bind.
            controls: Optional client controls to send with the request.

        Returns:
            int: The message id associated with the request.
        """
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
        """Send a SASL BIND request.

        Creates a SASL bind request using the mechanism and credential
        specified. A SASL bind operation may require multiple requests for the
        bind to be completed. It is up to the caller to process any server
        SASL credential responses in the BindResponse and then create a new
        SASL BindRequest with the new credential vaue.

        Common mechanisms are ``EXTERNAL``, ``GSSAPI``, ``GSS-SPNEGO``.
        ``DIGEST-MD5``.

        The ``EXTERNAL`` SASL mech is used for TLS Client Authentication. No
        cred is used as it relies on the certificate to be presented during the
        TLS handshake performed prior.

        The ``GSSAPI`` SASL mech is used for Kerberos authentication. It will
        send the Kerberos token as the first step in cred, then negotiate the
        SASL security factors for signing and encryption in the subsequent
        credential.

        The ``GSS-SPNEGO`` SASL mech is used for Negotiate authentication. It
        will send the Negotiate (Kerberos with NTLM fallback) cred and
        subsequent tokens during the authentication phase.

        The ``DIGEST-MD5`` SASL mech is used for authentication using the RFC
        2831 spec.

        Using an empty string for mechanism can be used to cancel an existing
        SASL bind request that is currently in operation.

        Note:
            You can only run a bind if there are no outstanding requests on the
            session. Once a bind has started, no other requests can be started
            until the bind is complete.

        Args:
            mechanism: The SASL mechanism to authenticate with.
            dn: The user to bind as, this is typically not set for SASL as the
                cred contains the user information.
            cred: The SASL bytes to authenticate with.
            controls: Optional client controls to send with the request.

        Returns:
            int: The message id associated with the request.
        """
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
        """Send a BIND request.

        Creates a bind request with the authentication payload specified. This
        can be used to bind with a custom set of credentials that have been
        registered with :func:`LDAPSession.register_auth_credential`. it is
        recommended to use :func:`bind_simple` or :func:`bind_sasl` instead of
        this function.

        Args:
            dn: The name of the Directory object that the client wishes to bind
                as.
            authentication: The authentication object to bind with. This must
                be registered first with
                :func:`LDAPSession.register_auth_credential`.
            controls: Optional client controls to send with the request.

        Returns:
            int: The message id associated with the request.
        """
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
        """Send an Extended request.

        Creates an extended request to perform custom operations on the server.
        An extended request must be supported by both the client and server.

        Args:
            name: The extended request OID string.
            value: The value for the request, can be None if the request does
                not hae a value.
            controls: Optional client controls to send with the request.

        Returns:
            int: The message id associated with the request.
        """
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
        """Send a Search Request.

        Creates a search request. This request can result in 3 different
        responses from the server; :class:`SearchResultEntry`,
        :class:`SearchResultReference`, and :class:`SearchResultDone`. The
        operation is not considered to be complete until the
        :class:`SearchResultDone` response has been received from the server.

        While a limit can be placed for the size and time, these will be
        ignored by the server if their configured limits is less than what is
        requested.


        The following are special attributes that can be requested:

        ``*``: Requests all attributes in addition to the explicitly defined
            ones.
        ``1.1``: No attributes are to be returned. Is ignored if there are any
            other attributes specified.

        Note:
            If using a custom filter, ensure it has been registered with
            :func:`register_filter`.

        Args:
            base_object: The name of the base object entry, or None/empty
                string for root, which the search is to be performed.
            scope: The scope of the search. See :class:`SearchScope` for more
                details. Defaults to ``SUBTREE``.
            dereferencing_policy: Indicates how alias entries are to be
                dereferenced, see :class:`DereferencingPolicy` for more
                details. Defaults to ``NEVER``.
            size_limit: The maximum number of entries to be returned. A value
                of 0 has no restrictions.
            time_limit: The maximum time, in seconds, allowed for the
                operation. A value of 0 has no time restrictions.
            types_only: Only return ttribute names and no values in the search
                result.
            filter: The LDAP filter to search by. See :class:`LDAPFilter` for
                more information.
            attributes: A list of attributes to be returned from each entry
                that match the search filter. The default requests the return
                of all user attributes.
            controls: Optional client controls to send with the request.

        Returns:
            int: The message id associated with the request.
        """
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
        msg_id = self._send(msg)
        self._search_requests.add(msg_id)

        return msg_id

    def receive(
        self,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> t.List[LDAPMessage]:
        try:
            return super().receive(data)
        except ProtocolError as e:
            if e.request is None or (
                not isinstance(e.request, UnbindRequest)
                and not (
                    isinstance(e.request, ExtendedResponse)
                    and e.request.name == ExtendedOperations.LDAP_NOTICE_OF_DISCONNECTION.value
                )
            ):
                msg = UnbindRequest(
                    message_id=0,
                    controls=[],
                )
                e.response = msg.pack(self._packing_options)

            raise

    def _process_incoming_message(
        self,
        msg: LDAPMessage,
    ) -> None:
        remove_id = True
        if not isinstance(msg, Response):
            raise ProtocolError(f"Received an LDAP message that is not a response {type(msg).__name__}, cannot process")

        elif msg.message_id in self._search_requests:
            if isinstance(msg, SearchResultDone):
                self._search_requests.remove(msg.message_id)

            else:
                remove_id = False

        elif msg.message_id not in self._outstanding_requests:
            raise ProtocolError(f"Received unexpected message id response {msg.message_id} from server")

        if isinstance(msg, BindResponse) and msg.result.result_code != LDAPResultCode.SASL_BIND_IN_PROGRESS:
            self.state = SessionState.OPENED

        if remove_id:
            self._outstanding_requests.remove(msg.message_id)

        return super()._process_incoming_message(msg)

    def _send(
        self,
        msg: LDAPMessage,
    ) -> int:
        if isinstance(msg, UnbindRequest):
            return super()._send(msg)

        msg_id = self._message_counter
        object.__setattr__(msg, "message_id", msg_id)

        super()._send(msg)

        self._message_counter += 1
        self._outstanding_requests.add(msg_id)

        return msg_id


class LDAPServer(LDAPSession):
    """LDAP Server session.

    The LDAP server session class that is used to send server LDAP messages.
    """

    def bind_response(
        self,
        message_id: int,
        sasl_creds: t.Optional[bytes] = None,
        result_code: LDAPResultCode = LDAPResultCode.SUCCESS,
        matched_dn: t.Optional[str] = None,
        diagnostics_message: t.Optional[str] = None,
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        """Send a Bind Response.

        Responds to a bind request. The state will be changed to ``OPENED``
        unless the result code is ``SASL_BIND_IN_PROGRESS``.

        Args:
            message_id: The message id this is responding to.
            sasl_creds: The SASL response credential needed for the client to
                complete the SASL authentication process.
            result_code: The result code. The default is ``SUCCESS`` which
                means the bind was successful.
            matched_dn: The subject the result is for. This is used for
                diagnostic purposes by the client when receiving an
                unsuccesful response.
            diagnostics_message: A string containing a textual diagnostic
                message. This is not standardized and should not be parsed. It
                is used for display purposes only on the client.
            controls: Optional server controls to send with the request.

        Returns:
            int: The message id associated with the request.
        """
        msg = BindResponse(
            message_id=message_id,
            controls=controls or [],
            result=LDAPResult(
                result_code=result_code,
                matched_dn=matched_dn or "",
                diagnostics_message=diagnostics_message or "",
                referrals=[],
            ),
            server_sasl_creds=sasl_creds,
        )
        if result_code != LDAPResultCode.SASL_BIND_IN_PROGRESS:
            self.state = SessionState.OPENED

        return self._send(msg)

    def extended_response(
        self,
        message_id: int,
        name: t.Optional[str] = None,
        value: t.Optional[bytes] = None,
        result_code: LDAPResultCode = LDAPResultCode.SUCCESS,
        matched_dn: t.Optional[str] = None,
        diagnostics_message: t.Optional[str] = None,
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        """Send an Extended Response.

        Responds to an extended request. The name and value are dependent on
        the extended request values. It is up to the caller to determine
        whether they need to be set on the response.

        Args:
            message_id: The message id this is responding to.
            name: The extended response OID string.
            value: The extended response value.
            result_code: The result code. The default is ``SUCCESS`` which
                means the bind was successful.
            matched_dn: The subject the result is for. This is used for
                diagnostic purposes by the client when receiving an
                unsuccesful response.
            diagnostics_message: A string containing a textual diagnostic
                message. This is not standardized and should not be parsed. It
                is used for display purposes only on the client.
            controls: Optional server controls to send with the request.

        Returns:
            int: The message id associated with the request.
        """
        msg = ExtendedResponse(
            message_id=message_id,
            controls=controls or [],
            result=LDAPResult(
                result_code=result_code,
                matched_dn=matched_dn or "",
                diagnostics_message=diagnostics_message or "",
                referrals=[],
            ),
            name=name,
            value=value,
        )
        msg_id = self._send(msg)
        if name == ExtendedOperations.LDAP_NOTICE_OF_DISCONNECTION:
            self.state = SessionState.CLOSED

        return msg_id

    def search_result_entry(
        self,
        message_id: int,
        object_name: str,
        attributes: t.List[PartialAttribute],
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        """Send a Search Result Entry Response.

        Responds to a search request with an entry result. This contains the
        search results for the object specified. A search result can have
        more than 1 result entry depending on what is found. The search
        result is finalised when :func:`search_result_done` is called.

        Args:
            message_id: The message id this is responding to.
            object_name: The object the entry is associated with.
            attributes: List of attributes and their values.
            controls: Optional server controls to send with the request.

        Returns:
            int: The message id associated with the request.
        """
        msg = SearchResultEntry(
            message_id=message_id,
            controls=controls or [],
            object_name=object_name,
            attributes=attributes,
        )
        return self._send(msg)

    def search_result_reference(
        self,
        message_id: int,
        uris: t.List[str],
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        """Send a Search Result Reference.

        Responds to a search request with a reference result. This is a result
        that indicates the server is unable, or unwilling, to search one or
        more non-local entries. The message contains reference(s) to one or
        more set of servers for the client to continue the operation.

        Args:
            message_id: The message id this is responding to.
            uris: The references for the client.
            controls: Optional server controls to send with the request.

        Returns:
            int: The message id associated with the request.
        """
        msg = SearchResultReference(
            message_id=message_id,
            controls=controls or [],
            uris=uris,
        )
        return self._send(msg)

    def search_result_done(
        self,
        message_id: int,
        result_code: LDAPResultCode = LDAPResultCode.SUCCESS,
        matched_dn: t.Optional[str] = None,
        diagnostics_message: t.Optional[str] = None,
        controls: t.Optional[t.List[LDAPControl]] = None,
    ) -> int:
        """Finish a Search Operation.

        This is the final search operation response that indicates to the
        client that the search is done and to expect no more responses for that
        operation.

        Args:
            message_id: The message id this is responding to.
            result_code: The result code. The default is ``SUCCESS`` which
                means the bind was successful.
            matched_dn: The subject the result is for. This is used for
                diagnostic purposes by the client when receiving an
                unsuccesful response.
            diagnostics_message: A string containing a textual diagnostic
                message. This is not standardized and should not be parsed. It
                is used for display purposes only on the client.
            controls: Optional server controls to send with the request.

        Returns:
            int: The message id associated with the request.
        """
        msg = SearchResultDone(
            message_id=message_id,
            controls=controls or [],
            result=LDAPResult(
                result_code=result_code,
                matched_dn=matched_dn or "",
                diagnostics_message=diagnostics_message or "",
                referrals=[],
            ),
        )
        msg_id = self._send(msg)
        self._search_requests.remove(msg_id)
        return msg_id

    def receive(
        self,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> t.List[LDAPMessage]:
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

    def _process_incoming_message(
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

        if isinstance(msg, SearchRequest):
            self._search_requests.add(msg.message_id)

        self._outstanding_requests.add(msg.message_id)
        super()._process_incoming_message(msg)

    def _send(
        self,
        msg: LDAPMessage,
    ) -> int:
        msg_id = super()._send(msg)

        if not isinstance(msg, UnbindRequest):
            if msg_id in self._outstanding_requests:
                if not isinstance(msg, (SearchResultEntry, SearchResultReference)):
                    self._outstanding_requests.remove(msg_id)
            else:
                raise LDAPError(f"Message {msg} is a response to an unknown request")

        return msg_id
