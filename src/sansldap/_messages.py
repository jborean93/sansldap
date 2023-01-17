# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import enum
import typing as t

from ._asn1 import ASN1Sequence, ASN1Tag, ASN1Writer, TagClass, TypeTagNumber, pack_asn1


class DereferencingPolicy(enum.IntEnum):
    NEVER = 0
    IN_SEARCHING = 1
    FINDING_BASE_OBJ = 2
    ALWAYS = 3


class SearchScope(enum.IntEnum):
    BASE = 0
    ONE_LEVEL = 1
    SUBTREE = 2


@dataclasses.dataclass
class LDAPMessage:
    tag_number: int = dataclasses.field(init=False, default=0)

    message_id: int
    controls: t.List[t.Any]

    def to_bytes(self) -> bytes:
        pack_asn1(TagClass.APPLICATION, True, self.tag_number, b"")
        return b""


@dataclasses.dataclass
class BindRequest(LDAPMessage):
    tag_number = 0

    version: int
    name: str

    def to_bytes(self) -> bytes:
        pack_asn1(TagClass.APPLICATION, False, TypeTagNumber.INTEGER, self.version)
        pack_asn1(TagClass.APPLICATION, False, TypeTagNumber.OCTET_STRING, self.name.encode("utf-8"))

        return b""


@dataclasses.dataclass
class BindRequestSimple(BindRequest):
    password: str

    def to_bytes(self) -> bytes:
        writer = ASN1Writer()

        with writer.push_sequence(ASN1Tag(TagClass.APPLICATION, self.tag_number, True)):
            writer.write_integer(self.version)
            writer.write_octet_string(self.name.encode("utf-8"))

            writer.write_octet_string(
                self.password.encode("utf-8"),
                tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, 0, False),
            )

        return b""


@dataclasses.dataclass
class BindRequestSasl(BindRequest):
    mechanism: str
    credentials: bytes

    def to_bytes(self) -> bytes:
        writer = ASN1Writer()

        with writer.push_sequence(ASN1Tag(TagClass.APPLICATION, self.tag_number, True)):
            writer.write_integer(self.version)
            writer.write_octet_string(self.name.encode("utf-8"))

            with writer.push_sequence(ASN1Tag(TagClass.CONTEXT_SPECIFIC, 3, False)):
                writer.write_octet_string(self.mechanism.encode("utf-8"))

                if self.credentials:
                    writer.write_octet_string(self.credentials)

        return b""


@dataclasses.dataclass
class BindResponse(LDAPMessage):
    tag_number = 1

    result: LDAPResult
    server_sasl_creds: t.Optional[bytes] = None


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
    result_code: int
    matched_dn: str
    diagnostics_message: str
    referrals: t.Optional[str] = None


@dataclasses.dataclass
class PartialAttribute:
    name: str
    values: t.List[bytes]
