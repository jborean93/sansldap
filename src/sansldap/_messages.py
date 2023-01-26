# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum
import typing as t

from ._asn1 import (
    ASN1Sequence,
    ASN1Tag,
    ASN1Writer,
    TagClass,
    TypeTagNumber,
    pack_asn1,
    read_asn1_boolean,
    read_asn1_enumerated,
    read_asn1_header,
    read_asn1_integer,
    read_asn1_octet_string,
    read_asn1_sequence,
    read_asn1_set,
)
from ._controls import LDAPControl
from ._filter import LDAPFilter


class DereferencingPolicy(enum.IntEnum):
    NEVER = 0
    IN_SEARCHING = 1
    FINDING_BASE_OBJ = 2
    ALWAYS = 3


class LDAPResultCode(enum.IntEnum):
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


class SearchScope(enum.IntEnum):
    BASE = 0
    ONE_LEVEL = 1
    SUBTREE = 2


@dataclasses.dataclass
class LDAPMessage:
    """The base LDAP Message object.

    This is the base object used for all LDAP messages.

    Args:
        message_id: The unique identifier for the request.
        controls: A list of controls

    Attributes:
        tag_number: The protocolOp choice for this message type.


    LDAPMessage ::= SEQUENCE {
            messageID       MessageID,
            protocolOp      CHOICE {
                bindRequest           BindRequest,
                bindResponse          BindResponse,
                unbindRequest         UnbindRequest,
                searchRequest         SearchRequest,
                searchResEntry        SearchResultEntry,
                searchResDone         SearchResultDone,
                searchResRef          SearchResultReference,
                modifyRequest         ModifyRequest,
                modifyResponse        ModifyResponse,
                addRequest            AddRequest,
                addResponse           AddResponse,
                delRequest            DelRequest,
                delResponse           DelResponse,
                modDNRequest          ModifyDNRequest,
                modDNResponse         ModifyDNResponse,
                compareRequest        CompareRequest,
                compareResponse       CompareResponse,
                abandonRequest        AbandonRequest,
                extendedReq           ExtendedRequest,
                extendedResp          ExtendedResponse,
                ...,
                intermediateResponse  IntermediateResponse },
            controls       [0] Controls OPTIONAL }

    https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.1
    """

    tag_number: int = dataclasses.field(init=False, default=0)

    message_id: int
    controls: t.List[LDAPControl]

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> t.Tuple[LDAPMessage, int]:
        view = memoryview(data)
        sequence_view, total_consumed = read_asn1_sequence(
            view,
            hint="LDAPMessage",
        )

        message_id, consumed = read_asn1_integer(
            sequence_view,
            hint="LDAPMessage.messageID",
        )
        sequence_view = sequence_view[consumed:]

        protocol_op_header = read_asn1_header(sequence_view)
        protocol_op_tag = protocol_op_header.tag
        if protocol_op_tag.tag_class != TagClass.APPLICATION:
            raise ValueError(f"Expecting LDAPMessage.protocolOp to be an APPLICATION but got {protocol_op_tag}")

        unpack_func = PROTOCOL_PACKER.get(protocol_op_tag.tag_number, None)
        if not unpack_func:
            raise NotImplementedError(f"Unknown LDAPMessage.protocolOp choice {protocol_op_tag.tag_number}")

        msg_sequence, consumed = read_asn1_sequence(
            sequence_view,
            header=protocol_op_header,
            hint="LDAPMessage.protocolOp",
        )
        sequence_view = sequence_view[consumed:]

        controls: t.List[LDAPControl] = []
        response_name: t.Optional[str] = None
        while sequence_view:
            next_header = read_asn1_header(sequence_view)

            if next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC:
                if next_header.tag.tag_number == 0:
                    controls_view = read_asn1_sequence(
                        sequence_view,
                        header=next_header,
                        hint="LDAPMessage.controls",
                    )[0]
                    while controls_view:
                        control, control_consumed = LDAPControl.unpack(controls_view)
                        controls_view = controls_view[control_consumed:]
                        controls.append(control)

                elif next_header.tag.tag_number == 10:
                    # Defined in MS-ADTS - NoticeOfDisconnectionLDAPMessage.
                    # This is an extension of LDAPMessage in the RFC but AD
                    # replies with this on critical failures where it has torn
                    # down the connection.
                    # responseName    [10] LDAPOID
                    b_response_name = read_asn1_octet_string(
                        sequence_view,
                        header=next_header,
                        hint="LDAPMessage.responseName",
                    )[0]
                    response_name = b_response_name.tobytes().decode("utf-8")

            sequence_view = sequence_view[next_header.tag_length + next_header.length :]

        msg = unpack_func[1](msg_sequence, message_id, controls)

        # Need to inject the MS-ADTS extension to this message.
        if isinstance(msg, ExtendedResponse) and response_name and not msg.name:
            msg.name = response_name

        return msg, total_consumed

    def pack(self) -> bytes:
        writer = ASN1Writer()

        pack_func = PROTOCOL_PACKER[self.tag_number][0]
        pack_func(writer)

        return b""


@dataclasses.dataclass
class BindRequest(LDAPMessage):
    tag_number = 0

    version: int
    name: str


def _pack_bind_request(
    writer: ASN1Writer,
) -> None:
    raise NotImplementedError()


def _unpack_bind_request(
    view: memoryview,
    message_id: int,
    controls: t.List[LDAPControl],
) -> BindRequest:
    version, consumed = read_asn1_integer(view, hint="BindRequest.version")
    view = view[consumed:]

    b_name, consumed = read_asn1_octet_string(view, hint="BindRequest.name")
    name = b_name.tobytes().decode("utf-8")
    view = view[consumed:]

    next_tag = read_asn1_header(view)[0]
    if next_tag.tag_class != TagClass.CONTEXT_SPECIFIC:
        raise ValueError(f"Expecting BindRequest authentication choice but got {next_tag}")

    unpack_func = BIND_REQUEST_UNPACKER.get(next_tag.tag_number, None)
    if not unpack_func:
        raise NotImplementedError(f"Unknown BindRequest authentication choice {next_tag.tag_number}")

    return unpack_func(view, next_tag, message_id, controls, version, name)


@dataclasses.dataclass
class BindRequestSimple(BindRequest):
    bind_request_choice = 0

    password: str


def _unpack_bind_request_simple(
    view: memoryview,
    tag: ASN1Tag,
    message_id: int,
    controls: t.List[LDAPControl],
    version: int,
    name: str,
) -> BindRequestSimple:

    password = read_asn1_octet_string(
        view,
        tag=tag,
        hint="BindRequest.authentication.simple",
    )[0]

    return BindRequestSimple(
        message_id=message_id,
        controls=controls,
        version=version,
        name=name,
        password=password.tobytes().decode("utf-8"),
    )


@dataclasses.dataclass
class BindRequestSasl(BindRequest):
    bind_request_choice = 3

    mechanism: str
    credentials: t.Optional[bytes]


def _unpack_bind_request_sasl(
    view: memoryview,
    tag: ASN1Tag,
    message_id: int,
    controls: t.List[LDAPControl],
    version: int,
    name: str,
) -> BindRequestSasl:
    sequence_view, consumed = read_asn1_sequence(
        view,
        tag=tag,
        hint="BindRequest.authentication.sasl",
    )
    sequence_view = sequence_view[:consumed]

    mechanism, consumed = read_asn1_octet_string(
        sequence_view,
        hint="BindRequest.authentication.sasl.mechanism",
    )
    sequence_view = sequence_view[consumed:]

    credentials = read_asn1_octet_string(
        sequence_view,
        hint="BindRequest.authentication.sasl.credentials",
    )[0]

    return BindRequestSasl(
        message_id=message_id,
        controls=controls,
        version=version,
        name=name,
        mechanism=mechanism.tobytes().decode("utf-8"),
        credentials=credentials.tobytes() if credentials else None,
    )


@dataclasses.dataclass
class BindResponse(LDAPMessage):
    tag_number = 1

    result: LDAPResult
    server_sasl_creds: t.Optional[bytes] = None


def _pack_bind_response(
    writer: ASN1Writer,
) -> None:
    raise NotImplementedError()


def _unpack_bind_response(
    view: memoryview,
    message_id: int,
    controls: t.List[LDAPControl],
) -> BindResponse:
    result, consumed = _unpack_ldap_result(view)
    view = view[consumed:]

    sasl_creds: t.Optional[bytes] = None
    while view:
        header = read_asn1_header(view)
        if header.tag.tag_class == TagClass.CONTEXT_SPECIFIC and header.tag.tag_number == 7:
            sasl_creds = read_asn1_octet_string(
                view,
                header=header,
                hint="BindResponse.serverSaslCreds",
            )[0].tobytes()
            break

        view = view[header.tag_length + header.length :]

    return BindResponse(
        message_id=message_id,
        controls=controls,
        result=result,
        server_sasl_creds=sasl_creds,
    )


@dataclasses.dataclass
class UnbindRequest(LDAPMessage):
    tag_number = 2


def _pack_unbind_request(
    writer: ASN1Writer,
) -> None:
    raise NotImplementedError()


@dataclasses.dataclass
class SearchRequest(LDAPMessage):
    tag_number = 3

    base_object: str
    scope: SearchScope
    deref_aliases: DereferencingPolicy
    size_limit: int
    time_limit: int
    types_only: bool
    filter: LDAPFilter
    attributes: t.List[str]


def _pack_search_request(
    writer: ASN1Writer,
) -> None:
    raise NotImplementedError()


def _unpack_search_request(
    view: memoryview,
    message_id: int,
    controls: t.List[LDAPControl],
) -> SearchRequest:
    base_object, consumed = read_asn1_octet_string(view, hint="SearchRequest.baseObject")
    view = view[consumed:]

    scope, consumed = read_asn1_enumerated(view, hint="SearchRequest.scope")
    view = view[consumed:]

    deref_aliases, consumed = read_asn1_enumerated(view, hint="SearchRequest.derefAliases")
    view = view[consumed:]

    size_limit, consumed = read_asn1_integer(view, hint="SearchRequest.sizeLimt")
    view = view[consumed:]

    time_limit, consumed = read_asn1_integer(view, hint="SearchRequest.timeLimit")
    view = view[consumed:]

    types_only, consumed = read_asn1_boolean(view, hint="SearchRequest.typesOnly")
    view = view[consumed:]

    ldap_filter, consumed = LDAPFilter.unpack(view)
    view = view[consumed:]

    attributes_view = read_asn1_sequence(view, hint="SearchRequest.attributes")[0]
    attributes: t.List[str] = []
    while attributes_view:
        attr_value, consumed = read_asn1_octet_string(
            attributes_view,
            hint="SearchRequest.attributes.value",
        )
        attributes_view = attributes_view[consumed:]

        attributes.append(attr_value.tobytes().decode("utf-8"))

    return SearchRequest(
        message_id=message_id,
        controls=controls,
        base_object=base_object.tobytes().decode("utf-8"),
        scope=SearchScope(scope),
        deref_aliases=DereferencingPolicy(deref_aliases),
        size_limit=size_limit,
        time_limit=time_limit,
        types_only=types_only,
        filter=ldap_filter,
        attributes=attributes,
    )


@dataclasses.dataclass
class SearchResultEntry(LDAPMessage):
    tag_number = 4

    object_name: str
    attributes: t.List[PartialAttribute]


def _pack_search_result_entry(
    writer: ASN1Writer,
) -> None:
    raise NotImplementedError()


def _unpack_search_result_entry(
    view: memoryview,
    message_id: int,
    controls: t.List[LDAPControl],
) -> SearchResultEntry:
    # SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
    #      objectName      LDAPDN,
    #      attributes      PartialAttributeList }

    # PartialAttributeList ::= SEQUENCE OF
    #                      partialAttribute PartialAttribute

    object_name, consumed = read_asn1_octet_string(view, hint="SearchResultEntry.objectName")
    view = view[consumed:]

    attr_view = read_asn1_sequence(view, hint="SearchResultEntry.attributes")[0]
    attributes: t.List[PartialAttribute] = []
    while attr_view:
        attr, consumed = _unpack_partial_attribute(attr_view)
        attributes.append(attr)
        attr_view = attr_view[consumed:]

    return SearchResultEntry(
        message_id=message_id,
        controls=controls,
        object_name=object_name.tobytes().decode("utf-8"),
        attributes=attributes,
    )


@dataclasses.dataclass
class SearchResultDone(LDAPMessage):
    tag_number = 5

    result: LDAPResult


def _pack_search_result_done(
    writer: ASN1Writer,
) -> None:
    raise NotImplementedError()


def _unpack_search_result_done(
    view: memoryview,
    message_id: int,
    controls: t.List[LDAPControl],
) -> SearchResultDone:
    result = _unpack_ldap_result(view)[0]
    return SearchResultDone(
        message_id=message_id,
        controls=controls,
        result=result,
    )


@dataclasses.dataclass
class SearchResultReference(LDAPMessage):
    tag_number = 19

    uris: t.List[str]


def _pack_search_result_reference(
    writer: ASN1Writer,
) -> None:
    raise NotImplementedError()


def _unpack_search_result_reference(
    view: memoryview,
    message_id: int,
    controls: t.List[LDAPControl],
) -> SearchResultReference:
    uris: t.List[str] = []
    while view:
        uri, consumed = read_asn1_octet_string(view, hint="SearchResultReference.uri")
        view = view[consumed:]
        uris.append(uri.tobytes().decode("utf-8"))

    return SearchResultReference(
        message_id=message_id,
        controls=controls,
        uris=uris,
    )


@dataclasses.dataclass
class ExtendedRequest(LDAPMessage):
    tag_number = 23

    name: str
    value: t.Optional[bytes]


def _pack_extended_request(
    writer: ASN1Writer,
) -> None:
    raise NotImplementedError()


def _unpack_extended_request(
    view: memoryview,
    message_id: int,
    controls: t.List[LDAPControl],
) -> ExtendedRequest:
    # ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
    #      requestName      [0] LDAPOID,
    #      requestValue     [1] OCTET STRING OPTIONAL }

    name, consumed = read_asn1_octet_string(
        view,
        tag=ASN1Tag(
            tag_class=TagClass.CONTEXT_SPECIFIC,
            tag_number=0,
            is_constructed=False,
        ),
        hint="ExtendedRequest.requestName",
    )
    view = view[consumed:]

    value: t.Optional[bytes] = None
    while view:
        next_header = read_asn1_header(view)

        if next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC and next_header.tag.tag_number == 1:
            value = read_asn1_octet_string(
                view,
                header=next_header,
                hint="ExtendedRequest.requestValue",
            )[0].tobytes()
            break

        view = view[next_header.tag_length + next_header.length :]

    return ExtendedRequest(
        message_id=message_id,
        controls=controls,
        name=name.tobytes().decode("utf-8"),
        value=value,
    )


@dataclasses.dataclass
class ExtendedResponse(LDAPMessage):
    tag_number = 24

    result: LDAPResult
    name: t.Optional[str]
    value: t.Optional[bytes]


def _pack_extended_response(
    writer: ASN1Writer,
) -> None:
    raise NotImplementedError()


def _unpack_extended_response(
    view: memoryview,
    message_id: int,
    controls: t.List[LDAPControl],
) -> ExtendedResponse:
    # ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
    #      COMPONENTS OF LDAPResult,
    #      responseName     [10] LDAPOID OPTIONAL,
    #      responseValue    [11] OCTET STRING OPTIONAL }
    result, consumed = _unpack_ldap_result(view)
    view = view[consumed:]
    name: t.Optional[str] = None
    value: t.Optional[bytes] = None

    while view:
        next_header = read_asn1_header(view)
        if next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC:
            if next_header.tag.tag_number == 10:
                name = (
                    read_asn1_octet_string(
                        view,
                        header=next_header,
                        hint="ExtendedResponse.responseName",
                    )[0]
                    .tobytes()
                    .decode("utf-8")
                )

            elif next_header.tag.tag_number == 11:
                value = read_asn1_octet_string(
                    view,
                    header=next_header,
                    hint="ExtendedResponse.responseValue",
                )[0].tobytes()

        view = view[next_header.tag_length + next_header.length :]

    return ExtendedResponse(
        message_id=message_id,
        controls=controls,
        result=result,
        name=name,
        value=value,
    )


@dataclasses.dataclass
class LDAPResult:
    result_code: LDAPResultCode
    matched_dn: str
    diagnostics_message: str
    referrals: t.Optional[t.List[str]] = None


def _unpack_ldap_result(
    view: memoryview,
) -> t.Tuple[LDAPResult, int]:
    total = 0
    result_code, consumed = read_asn1_enumerated(
        view,
        hint="LDAPResult.resultCode",
    )
    total += consumed
    view = view[consumed:]

    matched_dn, consumed = read_asn1_octet_string(
        view,
        hint="LDAPResult.matchedDN",
    )
    total += consumed
    view = view[consumed:]

    diagnostics_message, consumed = read_asn1_octet_string(
        view,
        hint="LDAPResult.diagnosticMessage",
    )
    total += consumed
    view = view[consumed:]

    referrals: t.Optional[t.List[str]] = None
    if view:
        next_tag = read_asn1_header(view)[0]

        if next_tag.tag_class == TagClass.CONTEXT_SPECIFIC and next_tag.tag_number == 3:
            referral_view, consumed = read_asn1_sequence(
                view,
                tag=next_tag,
                hint="LDAPResult.referral",
            )
            total == consumed

            referrals = []
            while referral_view:
                r, consumed = read_asn1_octet_string(
                    referral_view,
                    hint="LDAPResult.referral",
                )
                referral_view = referral_view[consumed:]
                referrals.append(r.tobytes().decode("utf-8"))

    return (
        LDAPResult(
            result_code=LDAPResultCode(result_code),
            matched_dn=matched_dn.tobytes().decode("utf-8"),
            diagnostics_message=diagnostics_message.tobytes().decode("utf-8"),
            referrals=referrals,
        ),
        total,
    )


@dataclasses.dataclass
class PartialAttribute:
    name: str
    values: t.List[bytes]


def _unpack_partial_attribute(
    view: memoryview,
) -> t.Tuple[PartialAttribute, int]:
    view, total_consumed = read_asn1_sequence(view, hint="PartialAttribute")

    description, consumed = read_asn1_octet_string(view, hint="PartialAttribute.type")
    view = view[consumed:]

    values_view = read_asn1_set(view, hint="PartialAttribute.vals")[0]
    values: t.List[bytes] = []
    while values_view:
        val, consumed = read_asn1_octet_string(values_view, hint="PartialAttribute.vals.value")
        values_view = values_view[consumed:]
        values.append(val.tobytes())

    return (
        PartialAttribute(
            name=description.tobytes().decode("utf-8"),
            values=values,
        ),
        total_consumed,
    )


BIND_REQUEST_UNPACKER: t.Dict[
    int, t.Callable[[memoryview, ASN1Tag, int, t.List[LDAPControl], int, str], BindRequest]
] = {
    BindRequestSimple.bind_request_choice: _unpack_bind_request_simple,
    BindRequestSasl.bind_request_choice: _unpack_bind_request_sasl,
}

PROTOCOL_PACKER: t.Dict[
    int,
    t.Tuple[
        t.Callable[[ASN1Writer], None],
        t.Callable[[memoryview, int, t.List[LDAPControl]], LDAPMessage],
    ],
] = {
    BindRequest.tag_number: (_pack_bind_request, _unpack_bind_request),
    BindResponse.tag_number: (_pack_bind_response, _unpack_bind_response),
    UnbindRequest.tag_number: (_pack_unbind_request, lambda v, m, c: UnbindRequest(message_id=m, controls=c)),
    SearchRequest.tag_number: (_pack_search_request, _unpack_search_request),
    SearchResultEntry.tag_number: (_pack_search_result_entry, _unpack_search_result_entry),
    SearchResultDone.tag_number: (_pack_search_result_done, _unpack_search_result_done),
    SearchResultReference.tag_number: (_pack_search_result_reference, _unpack_search_result_reference),
    ExtendedRequest.tag_number: (_pack_extended_request, _unpack_extended_request),
    ExtendedResponse.tag_number: (_pack_extended_response, _unpack_extended_response),
}
