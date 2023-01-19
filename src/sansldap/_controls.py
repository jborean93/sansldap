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
    read_asn1_header,
    read_asn1_integer,
    read_asn1_octet_string,
    read_asn1_sequence,
)


@dataclasses.dataclass
class LDAPControl:
    control_type: str
    critical: bool
    value: bytes

    @classmethod
    def unpack(
        cls,
        view: memoryview,
    ) -> t.Tuple[LDAPControl, int]:
        return LDAPControl("", False, b""), 0
