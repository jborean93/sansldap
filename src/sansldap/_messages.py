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
    read_asn1_enumerated,
    read_asn1_header,
    read_asn1_integer,
    read_asn1_octet_string,
    read_asn1_sequence,
)
from ._controls import LDAPControl


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
    tag_number: int = dataclasses.field(init=False, default=0)

    message_id: int
    controls: t.List[LDAPControl]

    def to_bytes(self) -> bytes:
        pack_asn1(TagClass.APPLICATION, True, self.tag_number, b"")
        return b""

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

        protocol_op_tag = read_asn1_header(sequence_view)[0]
        if protocol_op_tag.tag_class != TagClass.APPLICATION:
            raise ValueError(f"Expecting LDAPMessage protocolOp to be an APPLICATION but got {protocol_op_tag}")

        unpack_func = PROTOCOL_UNPACKER.get(protocol_op_tag.tag_number, None)
        if not unpack_func:
            raise NotImplementedError(f"Unknown LDAPMessage protocolOp choice {protocol_op_tag.tag_number}")

        msg_sequence, consumed = read_asn1_sequence(
            sequence_view,
            tag=protocol_op_tag,
            hint="LDAPMessage.protocolOp",
        )
        sequence_view = sequence_view[consumed:]

        controls: t.List[LDAPControl] = []
        response_name: t.Optional[str] = None
        while sequence_view:
            next_tag = read_asn1_header(sequence_view)[0]

            tag_consumed = None

            if next_tag.tag_class == TagClass.CONTEXT_SPECIFIC:
                if next_tag.tag_number == 0:
                    control, tag_consumed = LDAPControl.unpack(sequence_view)
                    controls.append(control)

                elif next_tag.tag_number == 10:
                    # Defined in MS-ADTS - NoticeOfDisconnectionLDAPMessage.
                    # This is an extension of LDAPMessage in the RFC but AD
                    # replies with this on critical failures where it has torn
                    # down the connection.
                    # responseName    [10] LDAPOID
                    b_response_name, tag_consumed = read_asn1_octet_string(
                        sequence_view, tag=next_tag, hint="LDAPMessage.responseName"
                    )
                    response_name = b_response_name.tobytes().decode("utf-8")

            if not tag_consumed:
                # Received something we don't know (or care about), just
                # continue iterating the sequence.
                _, tag_consumed = read_asn1_octet_string(
                    sequence_view,
                    tag=next_tag,
                    hint="LDAPMessage.controls",
                )

            sequence_view = sequence_view[tag_consumed:]

        msg = unpack_func(msg_sequence, message_id, controls)

        # Need to inject the MS-ADTS extension to this message.
        if isinstance(msg, ExtendedResponse) and response_name and not msg.name:
            msg.name = response_name

        return msg, total_consumed


@dataclasses.dataclass
class BindRequest(LDAPMessage):
    tag_number = 0

    version: int
    name: str

    def to_bytes(self) -> bytes:
        # pack_asn1(TagClass.APPLICATION, False, TypeTagNumber.INTEGER, self.version)
        # pack_asn1(TagClass.APPLICATION, False, TypeTagNumber.OCTET_STRING, self.name.encode("utf-8"))

        return b""


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

    def to_bytes(self) -> bytes:
        # writer = ASN1Writer()

        # with writer.push_sequence(ASN1Tag(TagClass.APPLICATION, self.tag_number, True)):
        #     writer.write_integer(self.version)
        #     writer.write_octet_string(self.name.encode("utf-8"))

        #     writer.write_octet_string(
        #         self.password.encode("utf-8"),
        #         tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, 0, False),
        #     )

        return b""


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

    def to_bytes(self) -> bytes:
        # writer = ASN1Writer()

        # with writer.push_sequence(ASN1Tag(TagClass.APPLICATION, self.tag_number, True)):
        #     writer.write_integer(self.version)
        #     writer.write_octet_string(self.name.encode("utf-8"))

        #     with writer.push_sequence(ASN1Tag(TagClass.CONTEXT_SPECIFIC, 3, False)):
        #         writer.write_octet_string(self.mechanism.encode("utf-8"))

        #         if self.credentials:
        #             writer.write_octet_string(self.credentials)

        return b""


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


def _unpack_bind_response(
    view: memoryview,
    message_id: int,
    controls: t.List[LDAPControl],
) -> BindResponse:
    result, consumed = _unpack_ldap_result(view)
    view = view[consumed:]

    sasl_creds: t.Optional[bytes] = None
    while view:
        next_tag = read_asn1_header(view)[0]
        if next_tag.tag_class == TagClass.CONTEXT_SPECIFIC and next_tag.tag_number == 7:
            sasl_creds = read_asn1_octet_string(
                view,
                tag=next_tag,
                hint="BindResponse.serverSaslCreds",
            )[0].tobytes()
            break

        else:
            _, consumed = read_asn1_octet_string(
                view,
                tag=next_tag,
                hint="BindResponse",
            )
            view = view[consumed:]

    return BindResponse(
        message_id=message_id,
        controls=controls,
        result=result,
        server_sasl_creds=sasl_creds,
    )


@dataclasses.dataclass
class UnbindRequest(LDAPMessage):
    tag_number = 2


@dataclasses.dataclass
class SearchRequest(LDAPMessage):
    tag_number = 3

    base_object: str
    scope: SearchScope
    deref_aliases: DereferencingPolicy
    size_limit: int
    time_limit: int
    types_only: bool
    filter: bytes


@dataclasses.dataclass
class SearchResultEntry(LDAPMessage):
    tag_number = 4

    object_name: str
    attributes: t.List[PartialAttribute]


@dataclasses.dataclass
class SearchResultDone(LDAPMessage):
    tag_number = 5

    result: LDAPResult


@dataclasses.dataclass
class SearchResultReference(LDAPMessage):
    tag_number = 19

    uris: t.List[str]


@dataclasses.dataclass
class ExtendedRequest(LDAPMessage):
    tag_number = 23

    name: str
    value: t.Optional[bytes]


@dataclasses.dataclass
class ExtendedResponse(LDAPMessage):
    tag_number = 24

    result: LDAPResult
    name: t.Optional[str]
    value: t.Optional[bytes]


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


BIND_REQUEST_UNPACKER: t.Dict[
    int, t.Callable[[memoryview, ASN1Tag, int, t.List[LDAPControl], int, str], BindRequest]
] = {
    BindRequestSimple.bind_request_choice: _unpack_bind_request_simple,
    BindRequestSasl.bind_request_choice: _unpack_bind_request_sasl,
}

PROTOCOL_UNPACKER: t.Dict[int, t.Callable[[memoryview, int, t.List[LDAPControl]], LDAPMessage]] = {
    BindRequest.tag_number: _unpack_bind_request,
    BindResponse.tag_number: _unpack_bind_response,
}
