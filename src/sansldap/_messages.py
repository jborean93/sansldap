# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum
import typing as t

from ._authentication import AuthenticationCredential, AuthenticationOptions
from ._controls import ControlOptions, LDAPControl, unpack_ldap_control
from ._filter import FilterOptions, LDAPFilter
from .asn1 import ASN1Reader, ASN1Tag, ASN1Writer, TagClass


@dataclasses.dataclass
class PackingOptions:
    """Packing Options.

    Various options to control the packing and unpacking phase of LDAP messages.

    Args:
        string_encoding: The encoding used for encoding and decoding bytes.
        authentication: Options used to pack/unpack Authentication credentials.
        control: Options used to pack/unpack Control values.
        filter: Options used to pack/unpack LDAP filters.
    """

    string_encoding: str = "utf-8"
    authentication: AuthenticationOptions = dataclasses.field(default_factory=AuthenticationOptions)
    control: ControlOptions = dataclasses.field(default_factory=ControlOptions)
    filter: FilterOptions = dataclasses.field(default_factory=FilterOptions)


def unpack_ldap_message(
    reader: ASN1Reader,
    options: PackingOptions,
) -> LDAPMessage:
    """Unpack an LDAP message.

    Unpacks the raw ASN.1 value in the reader specified into an LDAP message
    object.

    Args:
        reader: The ASN.1 reader to read from.
        packing: Custom options to control the unpack methods.

    Returns:
        LDAPMessage: The unpacked message object.
    """
    message = reader.read_sequence(hint="LDAPMessage")
    message_id = message.read_integer(hint="LDAPMessage.messageId")

    protocol_op_header = message.peek_header()
    protocol_op_tag = protocol_op_header.tag
    if protocol_op_tag.tag_class != TagClass.APPLICATION:
        raise ValueError(f"Expecting LDAPMessage.protocolOp to be an APPLICATION but got {protocol_op_tag}")

    unpack_func = PROTOCOL_PACKER.get(protocol_op_tag.tag_number, None)
    if not unpack_func:
        raise NotImplementedError(f"Unknown LDAPMessage.protocolOp choice {protocol_op_tag.tag_number}")

    protocol_reader = message.read_sequence(
        header=protocol_op_header,
        hint="LDAPMessage.protocolOp",
    )

    controls: t.List[LDAPControl] = []
    response_name: t.Optional[str] = None
    while message:
        next_header = message.peek_header()

        if next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC:
            if next_header.tag.tag_number == 0:
                control_reader = message.read_sequence(
                    header=next_header,
                    hint="LDAPMessage.controls",
                )
                while control_reader:
                    control = unpack_ldap_control(control_reader, options.control)
                    controls.append(control)

                continue

            elif next_header.tag.tag_number == 10:
                # Defined in MS-ADTS - NoticeOfDisconnectionLDAPMessage.
                # This is an extension of LDAPMessage in the RFC but AD
                # replies with this on critical failures where it has torn
                # down the connection.
                # responseName    [10] LDAPOID
                response_name = message.read_octet_string(
                    header=next_header,
                    hint="LDAPMessage.responseName",
                ).decode(options.string_encoding)
                continue

        message.skip_value(next_header)

    msg = unpack_func(protocol_reader, options, message_id, controls)

    # Need to inject the MS-ADTS extension to this message.
    if isinstance(msg, ExtendedResponse) and response_name and not msg.name:
        object.__setattr__(msg, "name", response_name)

    return msg


class DereferencingPolicy(enum.IntEnum):
    """Control alias dereferencing during a search."""

    NEVER = 0
    """
    Do not reference aliases in search or in locating the base object the search.
    """

    IN_SEARCHING = 1
    """
    While searching subordinates of the base object, dereference any alias
    within the search scope.
    """

    FINDING_BASE_OBJ = 2
    """
    Dereference aliases in locating the base object of the search, but not when
    searching subordinates of the base object.
    """

    ALWAYS = 3
    """
    Dererence aliases both in searching and in locating the base object of the
    search.
    """


class LDAPResultCode(enum.IntEnum):
    """The known LDAP result codes."""

    SUCCESS = 0
    OPERATIONS_ERROR = 1
    PROTOCOL_ERROR = 2
    TIME_LIMIT_EXCEEDED = 3
    SIZE_LIMIT_EXCEEDED = 4
    COMPARE_FALSE = 5
    COMPARE_TRUE = 6
    AUTH_METHOD_NOT_SUPPORTED = 7
    STRONG_AUTH_REQUIRED = 8
    REFERRAL = 10
    ADMIN_LIMIT_EXCEEDED = 11
    UNAVAILABLE_CRITICAL_EXTENSION = 12
    CONFIDENTIALITY_REQUIRED = 13
    SASL_BIND_IN_PROGRESS = 14
    NO_SUCH_ATTRIBUTE = 16
    UNDEFINED_ATTRIBUTE_TYPE = 17
    INAPPROPRIATE_MATCHING = 18
    CONSTRAINT_VIOLATION = 19
    ATTRIBUTE_OR_VALUE_EXISTS = 20
    INVALID_ATTRIBUTE_SYNTAX = 21
    NO_SUCH_OBJECT = 32
    ALIAS_PROBLEM = 33
    INVALID_DN_SYNTAX = 34
    ALIAS_DEREFERENCING_PROBLEM = 36
    INAPPROPRIATE_AUTHENTICATION = 48
    INVALID_CREDENTIALS = 49
    INSUFFICIENT_ACCESS_RIGHTS = 50
    BUSY = 51
    UNAVAILABLE = 52
    UNWILLING_TO_PERFORM = 53
    LOOP_DETECT = 54
    NAMING_VIOLATION = 64
    OBJECT_CLASS_VIOLATION = 65
    NOT_ALLOWED_ON_NON_LEAF = 66
    NOT_ALLOWED_ON_RDN = 67
    ENTRY_ALREADY_EXISTS = 68
    OBJECT_CLASS_MODS_PROHIBITED = 69
    AFFECTS_MULTIPLE_DSAS = 71
    OTHER = 80

    @classmethod
    def _missing_(cls, value: object) -> t.Any:
        # As the result codes are extensible it is possible to receive a code
        # that the client does not know about, handle that gracefully here.
        if not isinstance(value, int):
            return None

        new_member = int.__new__(cls)
        new_member._name_ = "UNKNOWN 0x{0:08X}".format(value)
        new_member._value_ = value

        return cls._value2member_map_.setdefault(value, new_member)


class SearchScope(enum.IntEnum):
    """Specifies the scope of the search to perform."""

    BASE = 0
    "The scope is constrained to the entry named by base_object"

    ONE_LEVEL = 1
    "The scope is constrained to the immediate subordinates of base_object."

    SUBTREE = 2
    "The scope is constrained to base_object and all its subordinates."


class Request:
    "Identifies LDAP requests"


class Response:
    "Identifies LDAP responses"


@dataclasses.dataclass(frozen=True)
class LDAPMessage:
    """The base LDAP Message object.

    This is the base object used for all LDAP messages. The base message
    structure is defined in `RFC 4511 4.1.1. Message Envelope`_.

    Args:
        message_id: The unique identifier for the request.
        controls: A list of controls associated with the message.
        tag_number: The protocolOp choice for this message type. This is
            defined on each LDAPMessage sub class.

    .. _RFC 4511 4.1.1. Message Envelope:
        https://www.rfc-editor.org/rfc/rfc4511#section-4.1.1
    """

    # LDAPMessage ::= SEQUENCE {
    #         messageID       MessageID,
    #         protocolOp      CHOICE {
    #             bindRequest           BindRequest,
    #             bindResponse          BindResponse,
    #             unbindRequest         UnbindRequest,
    #             searchRequest         SearchRequest,
    #             searchResEntry        SearchResultEntry,
    #             searchResDone         SearchResultDone,
    #             searchResRef          SearchResultReference,
    #             modifyRequest         ModifyRequest,
    #             modifyResponse        ModifyResponse,
    #             addRequest            AddRequest,
    #             addResponse           AddResponse,
    #             delRequest            DelRequest,
    #             delResponse           DelResponse,
    #             modDNRequest          ModifyDNRequest,
    #             modDNResponse         ModifyDNResponse,
    #             compareRequest        CompareRequest,
    #             compareResponse       CompareResponse,
    #             abandonRequest        AbandonRequest,
    #             extendedReq           ExtendedRequest,
    #             extendedResp          ExtendedResponse,
    #             ...,
    #             intermediateResponse  IntermediateResponse },
    #         controls       [0] Controls OPTIONAL }

    tag_number: int = dataclasses.field(init=False, default=0)

    message_id: int
    controls: t.List[LDAPControl]

    def pack(
        self,
        options: PackingOptions,
    ) -> bytes:
        """Packs the current message.

        Packs the current message and returns the bytes string that can be
        exchanged with the peer.

        Returns:
            bytes: The ASN.1 BER encoded message.
        """
        writer = ASN1Writer()

        with writer.push_sequence() as seq:
            seq.write_integer(self.message_id)

            with seq.push_sequence(
                ASN1Tag(TagClass.APPLICATION, self.tag_number, True),
            ) as inner:
                self._pack_inner(inner, options)

            if self.controls:
                with seq.push_sequence(
                    ASN1Tag(TagClass.CONTEXT_SPECIFIC, 0, True),
                ) as control_writer:
                    for control in self.controls:
                        control.pack(control_writer, options.control)

        return bytes(writer.get_data())

    def _pack_inner(
        self,
        writer: ASN1Writer,
        packing: PackingOptions,
    ) -> None:
        return


@dataclasses.dataclass(frozen=True)
class BindRequest(LDAPMessage, Request):
    """The bind request message.

    This object is used to exchange authentication and security-related
    semantics between the client and server. The BindRequest structure is
    defined in `RFC 4511 4.2. Bind Operation`_.

    Args:
        message_id: The unique identifier for the request.
        controls: A list of controls associated with the message.
        version: The version of the LDAP protocol to be used. Currently only
            version 3 is supported.
        name: The name of the directory object that the client wishes to bind
            as. An empty string is used for SASL authentiction or with
            anonymous binds.
        authentication: The authentication information, currently either a
            :class:`SimpleCredential` or :class:`SaslCredential` is supported.

    .. _RFC 4511 4.2. Bind Operation:
        https://www.rfc-editor.org/rfc/rfc4511#section-4.2
    """

    # BindRequest ::= [APPLICATION 0] SEQUENCE {
    #      version                 INTEGER (1 ..  127),
    #      name                    LDAPDN,
    #      authentication          AuthenticationChoice }

    # AuthenticationChoice ::= CHOICE {
    #      simple                  [0] OCTET STRING,
    #                              -- 1 and 2 reserved
    #      sasl                    [3] SaslCredentials,
    #      ...  }

    tag_number = 0
    "The LDAP message protocol op tag."

    version: int
    name: str
    authentication: AuthenticationCredential

    def _pack_inner(
        self,
        writer: ASN1Writer,
        options: PackingOptions,
    ) -> None:
        writer.write_integer(self.version)
        writer.write_octet_string(self.name.encode(options.string_encoding))
        self.authentication.pack(writer, options.authentication)


def _unpack_bind_request(
    reader: ASN1Reader,
    options: PackingOptions,
    message_id: int,
    controls: t.List[LDAPControl],
) -> BindRequest:
    version = reader.read_integer(hint="BindRequest.version")
    name = reader.read_octet_string(hint="BindRequest.name").decode(options.string_encoding)
    authentication = AuthenticationCredential.unpack(reader, options.authentication)

    return BindRequest(
        message_id=message_id,
        controls=controls,
        version=version,
        name=name,
        authentication=authentication,
    )


@dataclasses.dataclass(frozen=True)
class BindResponse(LDAPMessage, Response):
    """The bind response message.

    This is the response to a :class:`BindRequest`. It contains the status
    of the client's bind operation and potentially a SASL response token. The
    BindResponse structure is defined in `RFC 4511 4.2.2. Bind Response`_.

    Args:
        message_id: The unique identifier for the request.
        controls: A list of controls associated with the message.
        result: The LDAP response.
        server_sasl_creds: Contains the SASL challenge/response.

    .. _RFC 4511 4.2.2. Bind Response:
        https://www.rfc-editor.org/rfc/rfc4511#section-4.2.2
    """

    # BindResponse ::= [APPLICATION 1] SEQUENCE {
    #      COMPONENTS OF LDAPResult,
    #      serverSaslCreds    [7] OCTET STRING OPTIONAL }

    tag_number = 1
    "The LDAP message protocol op tag."

    result: LDAPResult
    server_sasl_creds: t.Optional[bytes] = None

    def _pack_inner(
        self,
        writer: ASN1Writer,
        options: PackingOptions,
    ) -> None:
        self.result._pack_inner(writer, options)

        if self.server_sasl_creds is not None:
            writer.write_octet_string(
                self.server_sasl_creds,
                ASN1Tag(TagClass.CONTEXT_SPECIFIC, 7, False),
            )


def _unpack_bind_response(
    reader: ASN1Reader,
    options: PackingOptions,
    message_id: int,
    controls: t.List[LDAPControl],
) -> BindResponse:
    result = _unpack_ldap_result(reader, options)

    sasl_creds: t.Optional[bytes] = None
    while reader:
        next_header = reader.peek_header()

        if next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC and next_header.tag.tag_number == 7:
            sasl_creds = reader.read_octet_string(
                header=next_header,
                hint="BindResponse.serverSaslCreds",
            )
            continue

        reader.skip_value(next_header)

    return BindResponse(
        message_id=message_id,
        controls=controls,
        result=result,
        server_sasl_creds=sasl_creds,
    )


@dataclasses.dataclass(frozen=True)
class UnbindRequest(LDAPMessage, Request):
    """The unbind request message.

    A message used to signal the LDAP session is to be terminated. There is no
    response as the client or server will terminate the connection after
    sending. The UnbindRequest structure is defined in
    `RFC 4511 4.3. Unbind Operation`_.

    Args:
        message_id: The unique identifier for the request.
        controls: A list of controls associated with the message.

    .. _RFC 4511 4.3. Unbind Operation:
        https://www.rfc-editor.org/rfc/rfc4511#section-4.3
    """

    tag_number = 2
    "The LDAP message protocol op tag."

    # UnbindRequest ::= [APPLICATION 2] NULL


@dataclasses.dataclass(frozen=True)
class SearchRequest(LDAPMessage, Request):
    """The search request message.

    This object is used to start a search operation with the parameters
    requested. The SearchRequest structure is defined in
    `RFC 4511 4.5.1. Search Request`_.

    The LDAP filter is a special object that derives from :class:`LDAPFilter`
    and is not the LDAP filter string most implementations use. See that class
    docstring for more information on how to build the LDAPFilter object.

    The following are special attributes that can be requested:

        ``*``: Requests all attributes in addition to the explicitly defined
            ones.
        ``1.1``: No attributes are to be returned. Is ignored if there are any
            other attributes specified.

    Args:
        message_id: The unique identifier for the request.
        controls: A list of controls associated with the message.
        base_object: The name of the base object entry (or empty string for
            root) which the search is to be performed.
        scope: The scope of the search. See :class:`SearchScope` for more
            details.
        deref_aliases: Indicates how alias entries are to be dereferenced, see
            :class:`DereferencingPolicy` for more details.
        size_limit: Retricts the maximum number of entries to be returned. A
            value of 0 indicates no client requested size limit is in place.
            The server may also enforce a maximum number of entries to return.
        time_limit: The time limit, in seconds, allowed for a search. A value
            of 0 indicates no client requested time limit is in place. The
            server may enforce its own time limit for a search.
        types_only: Set to True to only return attribute names and no values in
            the search result.
        filter: The LDAP filter to search by. See :class:`LDAPFilter` for more
            information.
        attributes: A list of attributes to be returned from each entry that
            matches the search filter. An empty list requests the return of all
            user attributes.

    .. _RFC 4511 4.5.1. Search Request:
        https://www.rfc-editor.org/rfc/rfc4511#section-4.5.1
    """

    # SearchRequest ::= [APPLICATION 3] SEQUENCE {
    #      baseObject      LDAPDN,
    #      scope           ENUMERATED {
    #           baseObject              (0),
    #           singleLevel             (1),
    #           wholeSubtree            (2),
    #           ...  },
    #      derefAliases    ENUMERATED {
    #           neverDerefAliases       (0),
    #           derefInSearching        (1),
    #           derefFindingBaseObj     (2),
    #           derefAlways             (3) },
    #      sizeLimit       INTEGER (0 ..  maxInt),
    #      timeLimit       INTEGER (0 ..  maxInt),
    #      typesOnly       BOOLEAN,
    #      filter          Filter,
    #      attributes      AttributeSelection }

    tag_number = 3
    "The LDAP message protocol op tag."

    base_object: str
    scope: SearchScope
    deref_aliases: DereferencingPolicy
    size_limit: int
    time_limit: int
    types_only: bool
    filter: LDAPFilter
    attributes: t.List[str]

    def _pack_inner(
        self,
        writer: ASN1Writer,
        options: PackingOptions,
    ) -> None:
        writer.write_octet_string(self.base_object.encode(options.string_encoding))
        writer.write_enumerated(self.scope.value)
        writer.write_enumerated(self.deref_aliases.value)
        writer.write_integer(self.size_limit)
        writer.write_integer(self.time_limit)
        writer.write_boolean(self.types_only)
        self.filter.pack(writer, options.filter)

        with writer.push_sequence_of() as attr_writer:
            for attr in self.attributes:
                attr_writer.write_octet_string(attr.encode(options.string_encoding))


def _unpack_search_request(
    reader: ASN1Reader,
    options: PackingOptions,
    message_id: int,
    controls: t.List[LDAPControl],
) -> SearchRequest:
    base_object = reader.read_octet_string(hint="SearchRequest.baseObject")
    scope = reader.read_enumerated(SearchScope, hint="SearchRequest.scope")
    deref_aliases = reader.read_enumerated(
        DereferencingPolicy,
        hint="SearchRequest.derefAliases",
    )
    size_limit = reader.read_integer(hint="SearchRequest.sizeLimt")
    time_limit = reader.read_integer(hint="SearchRequest.timeLimit")
    types_only = reader.read_boolean(hint="SearchRequest.typesOnly")
    filter = LDAPFilter.unpack(reader, options.filter)

    attributes: t.List[str] = []
    attributes_reader = reader.read_sequence(hint="SearchRequest.attributes")
    while attributes_reader:
        attr = attributes_reader.read_octet_string(
            hint="SearchRequest.attributes.value",
        )
        attributes.append(attr.decode(options.string_encoding))

    return SearchRequest(
        message_id=message_id,
        controls=controls,
        base_object=base_object.decode(options.string_encoding),
        scope=scope,
        deref_aliases=deref_aliases,
        size_limit=size_limit,
        time_limit=time_limit,
        types_only=types_only,
        filter=filter,
        attributes=attributes,
    )


@dataclasses.dataclass(frozen=True)
class SearchResultEntry(LDAPMessage, Response):
    """The search result entry message.

    This object is used as a response to a search request. The
    SearchResultEntry structure is defined in `RFC 4511 4.5.2. Search Result`_.

    Args:
        message_id: The unique identifier for the request.
        controls: A list of controls associated with the message.
        object_name: The object the result is associated with.
        attributes: A list of attributes and their values.

    .. _RFC 4511 4.5.2. Search Result:
        https://www.rfc-editor.org/rfc/rfc4511#section-4.5.2
    """

    # SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
    #      objectName      LDAPDN,
    #      attributes      PartialAttributeList }

    # PartialAttributeList ::= SEQUENCE OF
    #                      partialAttribute PartialAttribute

    tag_number = 4
    "The LDAP message protocol op tag."

    object_name: str
    attributes: t.List[PartialAttribute]

    def _pack_inner(
        self,
        writer: ASN1Writer,
        options: PackingOptions,
    ) -> None:
        writer.write_octet_string(self.object_name.encode(options.string_encoding))

        with writer.push_sequence_of() as attr_writer:
            for attribute in self.attributes:
                attribute._pack_inner(attr_writer, options)


def _unpack_search_result_entry(
    reader: ASN1Reader,
    options: PackingOptions,
    message_id: int,
    controls: t.List[LDAPControl],
) -> SearchResultEntry:
    # SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
    #      objectName      LDAPDN,
    #      attributes      PartialAttributeList }

    # PartialAttributeList ::= SEQUENCE OF
    #                      partialAttribute PartialAttribute

    object_name = reader.read_octet_string(
        hint="SearchResultEntry.objectName",
    ).decode(options.string_encoding)

    attributes: t.List[PartialAttribute] = []
    attr_reader = reader.read_sequence(hint="SearchResultEntry.attributes")

    while attr_reader:
        attr = _unpack_partial_attribute(attr_reader, options)
        attributes.append(attr)

    return SearchResultEntry(
        message_id=message_id,
        controls=controls,
        object_name=object_name,
        attributes=attributes,
    )


@dataclasses.dataclass(frozen=True)
class SearchResultDone(LDAPMessage, Response):
    """The search result done message.

    This object is used as a response to a search request and marks the end of
    any results for a search operation. The SearchResultDone structure is
    defined in `RFC 4511 4.5.2. Search Result`_.

    Args:
        message_id: The unique identifier for the request.
        controls: A list of controls associated with the message.
        result: The LDAP result of the search operation.

    .. _RFC 4511 4.5.2. Search Result:
        https://www.rfc-editor.org/rfc/rfc4511#section-4.5.2
    """

    # SearchResultDone ::= [APPLICATION 5] LDAPResult

    tag_number = 5
    "The LDAP message protocol op tag."

    result: LDAPResult

    def _pack_inner(
        self,
        writer: ASN1Writer,
        options: PackingOptions,
    ) -> None:
        self.result._pack_inner(writer, options)


def _unpack_search_result_done(
    reader: ASN1Reader,
    options: PackingOptions,
    message_id: int,
    controls: t.List[LDAPControl],
) -> SearchResultDone:
    result = _unpack_ldap_result(reader, options)
    return SearchResultDone(
        message_id=message_id,
        controls=controls,
        result=result,
    )


@dataclasses.dataclass(frozen=True)
class SearchResultReference(LDAPMessage, Response):
    """The search result reference message.

    Sent by the server in a search request operation when it is unable, or
    unwilling, to search one or more non-local entries. The result reference
    contains reference(s) to one or more set of server for continuing the
    operation. The SearchResultReference structure is defined in
    `RFC 4511 4.5.2. Search Result`_.

    Args:
        message_id: The unique identifier for the request.
        controls: A list of controls associated with the message.
        uris: The URIs of servers that can be used to continue the search. The
            URI may be an ``ldap://`` URI but the syntax is not part of this
            library to interpret.

    .. _RFC 4511 4.5.2. Search Result:
        https://www.rfc-editor.org/rfc/rfc4511#section-4.5.2
    """

    # SearchResultReference ::= [APPLICATION 19] SEQUENCE
    #                           SIZE (1..MAX) OF uri URI

    tag_number = 19
    "The LDAP message protocol op tag."

    uris: t.List[str]

    def _pack_inner(
        self,
        writer: ASN1Writer,
        options: PackingOptions,
    ) -> None:
        for uri in self.uris:
            writer.write_octet_string(uri.encode(options.string_encoding))


def _unpack_search_result_reference(
    reader: ASN1Reader,
    options: PackingOptions,
    message_id: int,
    controls: t.List[LDAPControl],
) -> SearchResultReference:
    uris: t.List[str] = []
    while reader:
        uri = reader.read_octet_string(
            hint="SearchResultReference.uri",
        ).decode(options.string_encoding)
        uris.append(uri)

    return SearchResultReference(
        message_id=message_id,
        controls=controls,
        uris=uris,
    )


@dataclasses.dataclass(frozen=True)
class ExtendedRequest(LDAPMessage, Request):
    """The extended request message.

    An extended operation is a custom operation not strictly defined in the
    LDAP RFC. It is used to extend the existing set of operations with custom
    ones that could be known to the client and server. For example the StartTLS
    protocol uses an extended operation to start embedding the transport with
    TLS. The ExtendedRequest structure is defined in
    `RFC 4511 4.12. Extended Operation`_.

    Args:
        message_id: The unique identifier for the request.
        controls: A list of controls associated with the message.
        name: The extended operation OID string.
        value: The extended operation value as a byte string. Can be None if
            the operation does not require a value.

    .. _RFC 4511 4.12. Extended Operation:
        https://www.rfc-editor.org/rfc/rfc4511#section-4.12
    """

    # ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
    #      requestName      [0] LDAPOID,
    #      requestValue     [1] OCTET STRING OPTIONAL }

    tag_number = 23
    "The LDAP message protocol op tag."

    name: str
    value: t.Optional[bytes]

    def _pack_inner(
        self,
        writer: ASN1Writer,
        options: PackingOptions,
    ) -> None:
        writer.write_octet_string(
            self.name.encode(options.string_encoding),
            tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, 0, False),
        )

        if self.value is not None:
            writer.write_octet_string(
                self.value,
                tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, 1, False),
            )


def _unpack_extended_request(
    reader: ASN1Reader,
    options: PackingOptions,
    message_id: int,
    controls: t.List[LDAPControl],
) -> ExtendedRequest:
    # ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
    #      requestName      [0] LDAPOID,
    #      requestValue     [1] OCTET STRING OPTIONAL }

    name = reader.read_octet_string(
        tag=ASN1Tag(
            tag_class=TagClass.CONTEXT_SPECIFIC,
            tag_number=0,
            is_constructed=False,
        ),
        hint="ExtendedRequest.requestName",
    ).decode(options.string_encoding)

    value: t.Optional[bytes] = None
    while reader:
        next_header = reader.peek_header()

        if next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC and next_header.tag.tag_number == 1:
            value = reader.read_octet_string(
                header=next_header,
                hint="ExtendedRequest.requestValue",
            )
            continue

        reader.skip_value(next_header)

    return ExtendedRequest(
        message_id=message_id,
        controls=controls,
        name=name,
        value=value,
    )


@dataclasses.dataclass(frozen=True)
class ExtendedResponse(LDAPMessage, Response):
    """The extended response message.

    The response to an extended request and contains the result of the
    operation as well as extra data associated with the operation. The
    ExtendedResponse structure is defined in
    `RFC 4511 4.12. Extended Operation`_.

    Args:
        message_id: The unique identifier for the request.
        controls: A list of controls associated with the message.
        result: The result of the operation.
        name: The operation OID string that was performced. This is optionally
            returned by the server.
        value: The operation data is specific to the operation performed. This
            is optionally returned by the server.

    .. _RFC 4511 4.12. Extended Operation:
        https://www.rfc-editor.org/rfc/rfc4511#section-4.12
    """

    # ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
    #      COMPONENTS OF LDAPResult,
    #      responseName     [10] LDAPOID OPTIONAL,
    #      responseValue    [11] OCTET STRING OPTIONAL }

    tag_number = 24
    "The LDAP message protocol op tag."

    result: LDAPResult
    name: t.Optional[str]
    value: t.Optional[bytes]

    def _pack_inner(
        self,
        writer: ASN1Writer,
        options: PackingOptions,
    ) -> None:
        self.result._pack_inner(writer, options)

        if self.name is not None:
            writer.write_octet_string(
                self.name.encode(options.string_encoding),
                ASN1Tag(TagClass.CONTEXT_SPECIFIC, 10, False),
            )

        if self.value is not None:
            writer.write_octet_string(
                self.value,
                ASN1Tag(TagClass.CONTEXT_SPECIFIC, 11, False),
            )


def _unpack_extended_response(
    reader: ASN1Reader,
    options: PackingOptions,
    message_id: int,
    controls: t.List[LDAPControl],
) -> ExtendedResponse:
    # ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
    #      COMPONENTS OF LDAPResult,
    #      responseName     [10] LDAPOID OPTIONAL,
    #      responseValue    [11] OCTET STRING OPTIONAL }
    result = _unpack_ldap_result(reader, options)

    name: t.Optional[str] = None
    value: t.Optional[bytes] = None

    while reader:
        next_header = reader.peek_header()

        if next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC:
            if next_header.tag.tag_number == 10:
                name = reader.read_octet_string(
                    header=next_header,
                    hint="ExtendedResponse.responseName",
                ).decode(options.string_encoding)
                continue

            elif next_header.tag.tag_number == 11:
                value = reader.read_octet_string(
                    header=next_header,
                    hint="ExtendedResponse.responseValue",
                )
                continue

        reader.skip_value(next_header)

    return ExtendedResponse(
        message_id=message_id,
        controls=controls,
        result=result,
        name=name,
        value=value,
    )


@dataclasses.dataclass(frozen=True)
class LDAPResult:
    """The LDAPResult message.

    This is the base object that contains the various response results from a
    server. The LDAPResult structure is defined in
    `RFC 4511 4.1.9. Result Message`_.

    Args:
        result_code: The result status of the operation.
        matched_dn: The subject to the name of the last entry used in finding
            the target of base object. Can be an empty string if not relevant.
        diagnostics_message: A string containing textual diagnostic messages.
            This is not standardized and should not be parsed, used for display
            purposes.
        referrals: Used when the result_code is ``REFERRAL``, contains the
            references to one or more servers/services that may be accessed by
            LDAP.

    .. _RFC 4511 4.1.9. Result Message:
        https://www.rfc-editor.org/rfc/rfc4511#section-4.1.9
    """

    # LDAPResult ::= SEQUENCE {
    #      resultCode         ENUMERATED {
    #           success                      (0),
    #           operationsError              (1),
    #           protocolError                (2),
    #           timeLimitExceeded            (3),
    #           sizeLimitExceeded            (4),
    #           compareFalse                 (5),
    #           compareTrue                  (6),
    #           authMethodNotSupported       (7),
    #           strongerAuthRequired         (8),
    #                -- 9 reserved --
    #           referral                     (10),
    #           adminLimitExceeded           (11),
    #           unavailableCriticalExtension (12),
    #           confidentialityRequired      (13),
    #           saslBindInProgress           (14),
    #           noSuchAttribute              (16),
    #           undefinedAttributeType       (17),
    #           inappropriateMatching        (18),
    #           constraintViolation          (19),
    #           attributeOrValueExists       (20),
    #           invalidAttributeSyntax       (21),
    #                -- 22-31 unused --
    #           noSuchObject                 (32),
    #           aliasProblem                 (33),
    #           invalidDNSyntax              (34),
    #                -- 35 reserved for undefined isLeaf --
    #           aliasDereferencingProblem    (36),
    #                -- 37-47 unused --
    #           inappropriateAuthentication  (48),
    #           invalidCredentials           (49),
    #           insufficientAccessRights     (50),
    #           busy                         (51),
    #           unavailable                  (52),
    #           unwillingToPerform           (53),
    #           loopDetect                   (54),
    #                -- 55-63 unused --
    #           namingViolation              (64),
    #           objectClassViolation         (65),
    #           notAllowedOnNonLeaf          (66),
    #           notAllowedOnRDN              (67),
    #           entryAlreadyExists           (68),
    #           objectClassModsProhibited    (69),
    #                -- 70 reserved for CLDAP --
    #           affectsMultipleDSAs          (71),
    #                -- 72-79 unused --
    #           other                        (80),
    #           ...  },
    #      matchedDN          LDAPDN,
    #      diagnosticMessage  LDAPString,
    #      referral           [3] Referral OPTIONAL }
    #
    # Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI
    #
    # URI ::= LDAPString     -- limited to characters permitted in
    #                        -- URIs

    result_code: LDAPResultCode
    matched_dn: str
    diagnostics_message: str
    referrals: t.Optional[t.List[str]] = None

    def _pack_inner(
        self,
        writer: ASN1Writer,
        options: PackingOptions,
    ) -> None:
        writer.write_enumerated(self.result_code.value)
        writer.write_octet_string(self.matched_dn.encode(options.string_encoding))
        writer.write_octet_string(self.diagnostics_message.encode(options.string_encoding))

        if self.referrals is not None:
            with writer.push_sequence(ASN1Tag(TagClass.CONTEXT_SPECIFIC, 3, True)) as referrals:
                for r in self.referrals:
                    referrals.write_octet_string(r.encode(options.string_encoding))


def _unpack_ldap_result(
    reader: ASN1Reader,
    options: PackingOptions,
) -> LDAPResult:
    result_code = reader.read_enumerated(
        LDAPResultCode,
        hint="LDAPResult.resultCode",
    )
    matched_dn = reader.read_octet_string(
        hint="LDAPResult.matchedDN",
    ).decode(options.string_encoding)

    diagnostics_message = reader.read_octet_string(
        hint="LDAPResult.diagnosticMessage",
    ).decode(options.string_encoding)

    referrals: t.Optional[t.List[str]] = None
    if reader:
        next_header = reader.peek_header()

        if next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC and next_header.tag.tag_number == 3:
            referral_reader = reader.read_sequence(
                header=next_header,
                hint="LDAPResult.referral",
            )

            referrals = []
            while referral_reader:
                r = referral_reader.read_octet_string(
                    hint="LDAPResult.referral",
                ).decode(options.string_encoding)
                referrals.append(r)

    return LDAPResult(
        result_code=result_code,
        matched_dn=matched_dn,
        diagnostics_message=diagnostics_message,
        referrals=referrals,
    )


@dataclasses.dataclass(frozen=True)
class PartialAttribute:
    """The PartialAttribute object.

    This is the object that contains the attribute description/name and values.
    The set of attribute values is unordered and implementations MUST NOT rely
    upon the ordering being repeatable. The PartialAttribute structure is
    defined in `RFC 4511 4.1.7. Attribute and PartialAttribute`_.

    Args:
        name: The attribute name.
        values: The attribute values, this list may be empty if no values are
            set.

    .. _RFC 4511 4.1.7. Attribute and PartialAttribute:
        https://www.rfc-editor.org/rfc/rfc4511#section-4.1.7
    """

    # PartialAttribute ::= SEQUENCE {
    #      type       AttributeDescription,
    #      vals       SET OF value AttributeValue }

    name: str
    values: t.List[bytes]

    def _pack_inner(
        self,
        writer: ASN1Writer,
        options: PackingOptions,
    ) -> None:
        with writer.push_sequence() as val:
            val.write_octet_string(self.name.encode(options.string_encoding))

            with val.push_set_of() as values:
                for v in self.values:
                    values.write_octet_string(v)


def _unpack_partial_attribute(
    reader: ASN1Reader,
    options: PackingOptions,
) -> PartialAttribute:
    attr_reader = reader.read_sequence(hint="PartialAttribute")

    name = attr_reader.read_octet_string(
        hint="PartialAttribute.type",
    ).decode(options.string_encoding)

    values: t.List[bytes] = []
    value_reader = attr_reader.read_set(hint="PartialAttribute.vals")
    while value_reader:
        val = value_reader.read_octet_string(hint="PartialAttribute.vals.value")
        values.append(val)

    return PartialAttribute(name=name, values=values)


PROTOCOL_PACKER: t.Dict[int, t.Callable[[ASN1Reader, PackingOptions, int, t.List[LDAPControl]], LDAPMessage]] = {
    BindRequest.tag_number: _unpack_bind_request,
    BindResponse.tag_number: _unpack_bind_response,
    UnbindRequest.tag_number: lambda r, o, m, c: UnbindRequest(message_id=m, controls=c),
    SearchRequest.tag_number: _unpack_search_request,
    SearchResultEntry.tag_number: _unpack_search_result_entry,
    SearchResultDone.tag_number: _unpack_search_result_done,
    SearchResultReference.tag_number: _unpack_search_result_reference,
    ExtendedRequest.tag_number: _unpack_extended_request,
    ExtendedResponse.tag_number: _unpack_extended_response,
}
