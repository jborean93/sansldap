# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum
import typing as t

from ._asn1 import (
    ASN1Reader,
    ASN1Tag,
    ASN1Writer,
    TagClass,
    _read_asn1_boolean,
    _read_asn1_enumerated,
    _read_asn1_header,
    _read_asn1_integer,
    _read_asn1_octet_string,
    _read_asn1_sequence,
    _read_asn1_set,
)
from ._controls import LDAPControl, unpack_ldap_control
from ._filter import LDAPFilter, unpack_ldap_filter


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
        reader = ASN1Reader(data)
        info = reader.peek_header()

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
                        control = unpack_ldap_control(control_reader)
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
                    ).decode("utf-8")
                    continue

            message.skip_value(next_header)

        msg = unpack_func(protocol_reader, message_id, controls)

        # Need to inject the MS-ADTS extension to this message.
        if isinstance(msg, ExtendedResponse) and response_name and not msg.name:
            msg.name = response_name

        return msg, info.tag_length + info.length

    def pack(self) -> bytes:
        writer = ASN1Writer()

        with writer.push_sequence() as seq:
            seq.write_integer(self.message_id)

            with seq.push_sequence(
                ASN1Tag(TagClass.APPLICATION, self.tag_number, True),
            ) as inner:
                self._pack_inner(inner)

            if self.controls:
                with seq.push_sequence(
                    ASN1Tag(TagClass.CONTEXT_SPECIFIC, 0, True),
                ) as control_writer:
                    for control in self.controls:
                        control._pack_internal(control_writer)

        return bytes(writer.get_data())

    def _pack_inner(
        self,
        writer: ASN1Writer,
    ) -> None:
        return


@dataclasses.dataclass
class BindRequest(LDAPMessage):
    tag_number = 0

    version: int
    name: str
    authentication: t.Union[SimpleCredential, SaslCredential]

    def _pack_inner(
        self,
        writer: ASN1Writer,
    ) -> None:
        writer.write_integer(self.version)
        writer.write_octet_string(self.name.encode("utf-8"))
        self.authentication._pack_inner(writer)


def _unpack_bind_request(
    reader: ASN1Reader,
    message_id: int,
    controls: t.List[LDAPControl],
) -> BindRequest:
    version = reader.read_integer(hint="BindRequest.version")
    name = reader.read_octet_string(hint="BindRequest.name").decode("utf-8")

    next_header = reader.peek_header()
    authentication: t.Optional[t.Union[SimpleCredential, SaslCredential]] = None
    if next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC:
        if next_header.tag.tag_number == SimpleCredential.authentication_id:
            password = reader.read_octet_string(
                header=next_header,
                hint="BindRequest.authentication.simple",
            )
            authentication = SimpleCredential(password=password.decode("utf-8"))

        elif next_header.tag.tag_number == SaslCredential.authentication_id:
            sasl_reader = reader.read_sequence(
                header=next_header,
                hint="BindRequest.authentication.sasl",
            )

            mechanism = sasl_reader.read_octet_string(
                hint="BindRequest.authentication.sasl.mechanism",
            ).decode("utf-8")

            credentials = sasl_reader.read_octet_string(
                hint="BindRequest.authentication.sasl.credentials",
            )

            authentication = SaslCredential(
                mechanism=mechanism,
                credentials=credentials,
            )

    if authentication is None:
        raise ValueError(f"Expecting BindRequest authentication choice of 0 or 3 but got {next_header}")

    return BindRequest(
        message_id=message_id,
        controls=controls,
        version=version,
        name=name,
        authentication=authentication,
    )


@dataclasses.dataclass
class BindResponse(LDAPMessage):
    tag_number = 1

    result: LDAPResult
    server_sasl_creds: t.Optional[bytes] = None

    def _pack_inner(
        self,
        writer: ASN1Writer,
    ) -> None:
        self.result._pack_inner(writer)

        if self.server_sasl_creds is not None:
            writer.write_octet_string(
                self.server_sasl_creds,
                ASN1Tag(TagClass.CONTEXT_SPECIFIC, 7, False),
            )


def _unpack_bind_response(
    reader: ASN1Reader,
    message_id: int,
    controls: t.List[LDAPControl],
) -> BindResponse:
    result = _unpack_ldap_result(reader)

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
    filter: LDAPFilter
    attributes: t.List[str]

    def _pack_inner(
        self,
        writer: ASN1Writer,
    ) -> None:
        writer.write_octet_string(self.base_object.encode("utf-8"))
        writer.write_enumerated(self.scope.value)
        writer.write_enumerated(self.deref_aliases.value)
        writer.write_integer(self.size_limit)
        writer.write_integer(self.time_limit)
        writer.write_boolean(self.types_only)
        self.filter._pack_internal(writer)

        with writer.push_sequence_of() as attr_writer:
            for attr in self.attributes:
                attr_writer.write_octet_string(attr.encode("utf-8"))


def _unpack_search_request(
    reader: ASN1Reader,
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
    filter = unpack_ldap_filter(reader)

    attributes: t.List[str] = []
    attributes_reader = reader.read_sequence(hint="SearchRequest.attributes")
    while attributes_reader:
        attr = attributes_reader.read_octet_string(
            hint="SearchRequest.attributes.value",
        )
        attributes.append(attr.decode("utf-8"))

    return SearchRequest(
        message_id=message_id,
        controls=controls,
        base_object=base_object.decode("utf-8"),
        scope=scope,
        deref_aliases=deref_aliases,
        size_limit=size_limit,
        time_limit=time_limit,
        types_only=types_only,
        filter=filter,
        attributes=attributes,
    )


@dataclasses.dataclass
class SearchResultEntry(LDAPMessage):
    tag_number = 4

    object_name: str
    attributes: t.List[PartialAttribute]

    def _pack_inner(
        self,
        writer: ASN1Writer,
    ) -> None:
        writer.write_octet_string(self.object_name.encode("utf-8"))

        with writer.push_sequence_of() as attr_writer:
            for attribute in self.attributes:
                attribute._pack_inner(attr_writer)


def _unpack_search_result_entry(
    reader: ASN1Reader,
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
    ).decode("utf-8")

    attributes: t.List[PartialAttribute] = []
    attr_reader = reader.read_sequence(hint="SearchResultEntry.attributes")

    while attr_reader:
        attr = _unpack_partial_attribute(attr_reader)
        attributes.append(attr)

    return SearchResultEntry(
        message_id=message_id,
        controls=controls,
        object_name=object_name,
        attributes=attributes,
    )


@dataclasses.dataclass
class SearchResultDone(LDAPMessage):
    tag_number = 5

    result: LDAPResult

    def _pack_inner(
        self,
        writer: ASN1Writer,
    ) -> None:
        self.result._pack_inner(writer)


def _unpack_search_result_done(
    reader: ASN1Reader,
    message_id: int,
    controls: t.List[LDAPControl],
) -> SearchResultDone:
    result = _unpack_ldap_result(reader)
    return SearchResultDone(
        message_id=message_id,
        controls=controls,
        result=result,
    )


@dataclasses.dataclass
class SearchResultReference(LDAPMessage):
    tag_number = 19

    uris: t.List[str]

    def _pack_inner(
        self,
        writer: ASN1Writer,
    ) -> None:
        for uri in self.uris:
            writer.write_octet_string(uri.encode("utf-8"))


def _unpack_search_result_reference(
    reader: ASN1Reader,
    message_id: int,
    controls: t.List[LDAPControl],
) -> SearchResultReference:
    uris: t.List[str] = []
    while reader:
        uri = reader.read_octet_string(
            hint="SearchResultReference.uri",
        ).decode("utf-8")
        uris.append(uri)

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

    def _pack_inner(self, writer: ASN1Writer) -> None:
        writer.write_octet_string(
            self.name.encode("utf-8"),
            tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, 0, False),
        )

        if self.value is not None:
            writer.write_octet_string(
                self.value,
                tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, 1, False),
            )


def _unpack_extended_request(
    reader: ASN1Reader,
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
    ).decode("utf-8")

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


@dataclasses.dataclass
class ExtendedResponse(LDAPMessage):
    tag_number = 24

    result: LDAPResult
    name: t.Optional[str]
    value: t.Optional[bytes]

    def _pack_inner(self, writer: ASN1Writer) -> None:
        self.result._pack_inner(writer)

        if self.name is not None:
            writer.write_octet_string(
                self.name.encode("utf-8"),
                ASN1Tag(TagClass.CONTEXT_SPECIFIC, 10, False),
            )

        if self.value is not None:
            writer.write_octet_string(
                self.value,
                ASN1Tag(TagClass.CONTEXT_SPECIFIC, 11, False),
            )


def _unpack_extended_response(
    reader: ASN1Reader,
    message_id: int,
    controls: t.List[LDAPControl],
) -> ExtendedResponse:
    # ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
    #      COMPONENTS OF LDAPResult,
    #      responseName     [10] LDAPOID OPTIONAL,
    #      responseValue    [11] OCTET STRING OPTIONAL }
    result = _unpack_ldap_result(reader)

    name: t.Optional[str] = None
    value: t.Optional[bytes] = None

    while reader:
        next_header = reader.peek_header()

        if next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC:
            if next_header.tag.tag_number == 10:
                name = reader.read_octet_string(
                    header=next_header,
                    hint="ExtendedResponse.responseName",
                ).decode("utf-8")
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


@dataclasses.dataclass
class SimpleCredential:
    authentication_id: int = dataclasses.field(init=False, repr=False, default=0)

    password: str

    def _pack_inner(
        self,
        writer: ASN1Writer,
    ) -> None:
        writer.write_octet_string(
            self.password.encode("utf-8"),
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.authentication_id, False),
        )


@dataclasses.dataclass
class SaslCredential:
    authentication_id: int = dataclasses.field(init=False, repr=False, default=3)

    mechanism: str
    credentials: t.Optional[bytes]

    def _pack_inner(
        self,
        writer: ASN1Writer,
    ) -> None:
        with writer.push_sequence(
            ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.authentication_id, True),
        ) as sasl_writer:
            sasl_writer.write_octet_string(self.mechanism.encode("utf-8"))
            if self.credentials is not None:
                sasl_writer.write_octet_string(self.credentials)


@dataclasses.dataclass
class LDAPResult:
    result_code: LDAPResultCode
    matched_dn: str
    diagnostics_message: str
    referrals: t.Optional[t.List[str]] = None

    def _pack_inner(
        self,
        writer: ASN1Writer,
    ) -> None:
        writer.write_enumerated(self.result_code.value)
        writer.write_octet_string(self.matched_dn.encode("utf-8"))
        writer.write_octet_string(self.diagnostics_message.encode("utf-8"))

        if self.referrals is not None:
            with writer.push_sequence(ASN1Tag(TagClass.CONTEXT_SPECIFIC, 3, True)) as referrals:
                for r in self.referrals:
                    referrals.write_octet_string(r.encode("utf-8"))


def _unpack_ldap_result(
    reader: ASN1Reader,
) -> LDAPResult:
    result_code = reader.read_enumerated(
        LDAPResultCode,
        hint="LDAPResult.resultCode",
    )
    matched_dn = reader.read_octet_string(
        hint="LDAPResult.matchedDN",
    ).decode("utf-8")

    diagnostics_message = reader.read_octet_string(
        hint="LDAPResult.diagnosticMessage",
    ).decode("utf-8")

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
                ).decode("utf-8")
                referrals.append(r)

    return LDAPResult(
        result_code=result_code,
        matched_dn=matched_dn,
        diagnostics_message=diagnostics_message,
        referrals=referrals,
    )


@dataclasses.dataclass
class PartialAttribute:
    name: str
    values: t.List[bytes]

    def _pack_inner(
        self,
        writer: ASN1Writer,
    ) -> None:
        with writer.push_sequence() as val:
            val.write_octet_string(self.name.encode("utf-8"))

            with val.push_set_of() as values:
                for v in self.values:
                    values.write_octet_string(v)


def _unpack_partial_attribute(
    reader: ASN1Reader,
) -> PartialAttribute:
    attr_reader = reader.read_sequence(hint="PartialAttribute")

    name = attr_reader.read_octet_string(
        hint="PartialAttribute.type",
    ).decode("utf-8")

    values: t.List[bytes] = []
    value_reader = attr_reader.read_set(hint="PartialAttribute.vals")
    while value_reader:
        val = value_reader.read_octet_string(hint="PartialAttribute.vals.value")
        values.append(val)

    return PartialAttribute(name=name, values=values)


PROTOCOL_PACKER: t.Dict[int, t.Callable[[ASN1Reader, int, t.List[LDAPControl]], LDAPMessage]] = {
    BindRequest.tag_number: _unpack_bind_request,
    BindResponse.tag_number: _unpack_bind_response,
    UnbindRequest.tag_number: lambda r, m, c: UnbindRequest(message_id=m, controls=c),
    SearchRequest.tag_number: _unpack_search_request,
    SearchResultEntry.tag_number: _unpack_search_result_entry,
    SearchResultDone.tag_number: _unpack_search_result_done,
    SearchResultReference.tag_number: _unpack_search_result_reference,
    ExtendedRequest.tag_number: _unpack_extended_request,
    ExtendedResponse.tag_number: _unpack_extended_response,
}
