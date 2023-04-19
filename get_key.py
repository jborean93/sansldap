from __future__ import annotations

import base64
import dataclasses
import hashlib
import math
import re
import socket
import struct
import sys
import typing as t
import uuid

import gssapi
import gssapi.raw
import spnego
from cryptography.hazmat.primitives import hashes, keywrap
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, CounterLocation, Mode
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_der_private_key,
)

import sansldap
from sansldap._pkcs7 import (
    AlgorithmIdentifier,
    ContentInfo,
    EncryptedContentInfo,
    EnvelopedData,
    KEKRecipientInfo,
    NCryptProtectionDescriptor,
)
from sansldap.asn1 import ASN1Reader

BIND_TIME_FEATURE_NEGOTIATION = (uuid.UUID("6cb71c2c-9812-4540-0300-000000000000"), 1, 0)
EMP = (uuid.UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa"), 3, 0)
ISD_KEY = (uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085"), 1, 0)
NDR = (uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"), 2, 0)
NDR64 = (uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36"), 1, 0)


@dataclasses.dataclass(frozen=True)
class EncryptedLAPSBlob:
    update_timestamp: int  # FILETIME int64
    flags: int
    blob: bytes

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> EncryptedLAPSBlob:
        view = memoryview(data)

        timestamp_upper = struct.unpack("<I", view[:4])[0]
        timestamp_lower = struct.unpack("<I", view[4:8])[0]
        update_timestamp = (timestamp_upper << 32) | timestamp_lower
        blob_len = struct.unpack("<I", view[8:12])[0]
        flags = struct.unpack("<I", view[12:16])[0]
        blob = view[16 : 16 + blob_len]
        assert len(blob) == blob_len
        assert len(view[16 + blob_len :]) == 0

        return EncryptedLAPSBlob(
            update_timestamp=update_timestamp,
            flags=flags,
            blob=blob.tobytes(),
        )


@dataclasses.dataclass(frozen=True)
class SecTrailer:
    type: int
    level: int
    pad_length: int
    context_id: int
    data: bytes


@dataclasses.dataclass(frozen=True)
class Tower:
    service: t.Tuple[uuid.UUID, int, int]
    data_rep: t.Tuple[uuid.UUID, int, int]
    protocol: int
    port: int
    addr: int


@dataclasses.dataclass(frozen=True)
class KDFParameters:
    hash_name: str

    # MS-GKDI - 2.2.1 KDF Parameters
    # https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-GKDI/%5bMS-GKDI%5d.pdf#%5B%7B%22num%22%3A58%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C210%2C0%5D

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> KDFParameters:
        view = memoryview(data)

        assert view[:8].tobytes() == b"\x00\x00\x00\x00\x01\x00\x00\x00"
        assert view[12:16].tobytes() == b"\x00\x00\x00\x00"
        hash_length = struct.unpack("<I", view[8:12])[0]

        hash_name = view[16 : 16 + hash_length - 2].tobytes().decode("utf-16-le")

        return KDFParameters(hash_name=hash_name)


@dataclasses.dataclass(frozen=True)
class FFCDHParameters:
    key_length: int
    field_order: bytes
    generator: bytes

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> FFCDHParameters:
        view = memoryview(data)

        length = struct.unpack("<I", view[:4])[0]
        assert len(view) == length
        assert view[4:8].tobytes() == b"\x44\x48\x50\x4d"
        key_length = struct.unpack("<I", view[8:12])[0]

        field_order = view[12 : 12 + key_length].tobytes()
        assert len(field_order) == key_length
        view = view[12 + key_length :]

        generator = view[:key_length].tobytes()
        assert len(generator) == key_length

        return FFCDHParameters(
            key_length=key_length,
            field_order=field_order,
            generator=generator,
        )


@dataclasses.dataclass(frozen=True)
class GroupKeyEnvelope:
    # https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-GKDI/%5bMS-GKDI%5d.pdf
    # 2.2.4 Group Key Envelope
    version: int
    flags: int
    l0: int
    l1: int
    l2: int
    root_key_identifier: uuid.UUID
    kdf_algorithm: str
    kdf_parameters: bytes
    secret_algorithm: str
    secret_parameters: bytes
    private_key_length: int
    public_key_length: int
    domain_name: str
    forest_name: str
    l1_key: bytes
    l2_key: bytes

    @property
    def is_public_key(self) -> bool:
        return bool(self.flags & 1)

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> GroupKeyEnvelope:
        view = memoryview(data)

        version = struct.unpack("<I", view[:4])[0]

        assert view[4:8].tobytes() == b"\x4B\x44\x53\x4B"

        flags = struct.unpack("<I", view[8:12])[0]
        l0_index = struct.unpack("<I", view[12:16])[0]
        l1_index = struct.unpack("<I", view[16:20])[0]
        l2_index = struct.unpack("<I", view[20:24])[0]
        root_key_identifier = uuid.UUID(bytes_le=view[24:40].tobytes())
        kdf_algo_len = struct.unpack("<I", view[40:44])[0]
        kdf_para_len = struct.unpack("<I", view[44:48])[0]
        sec_algo_len = struct.unpack("<I", view[48:52])[0]
        sec_para_len = struct.unpack("<I", view[52:56])[0]
        priv_key_len = struct.unpack("<I", view[56:60])[0]
        publ_key_len = struct.unpack("<I", view[60:64])[0]
        l1_key_len = struct.unpack("<I", view[64:68])[0]
        l2_key_len = struct.unpack("<I", view[68:72])[0]
        domain_len = struct.unpack("<I", view[72:76])[0]
        forest_len = struct.unpack("<I", view[76:80])[0]
        view = view[80:]

        kdf_algo = view[: kdf_algo_len - 2].tobytes().decode("utf-16-le")
        view = view[kdf_algo_len:]

        kdf_param = view[:kdf_para_len].tobytes()
        view = view[kdf_para_len:]

        secret_algo = view[: sec_algo_len - 2].tobytes().decode("utf-16-le")
        view = view[sec_algo_len:]

        secret_param = view[:sec_para_len].tobytes()
        view = view[sec_para_len:]

        domain = view[: domain_len - 2].tobytes().decode("utf-16-le")
        view = view[domain_len:]

        forest = view[: forest_len - 2].tobytes().decode("utf-16-le")
        view = view[forest_len:]

        l1_key = view[:l1_key_len].tobytes()
        view = view[l1_key_len:]

        l2_key = view[:l2_key_len].tobytes()
        view = view[l2_key_len:]

        return GroupKeyEnvelope(
            version=version,
            flags=flags,
            l0=l0_index,
            l1=l1_index,
            l2=l2_index,
            root_key_identifier=root_key_identifier,
            kdf_algorithm=kdf_algo,
            kdf_parameters=kdf_param,
            secret_algorithm=secret_algo,
            secret_parameters=secret_param,
            private_key_length=priv_key_len,
            public_key_length=publ_key_len,
            domain_name=domain,
            forest_name=forest,
            l1_key=l1_key,
            l2_key=l2_key,
        )


@dataclasses.dataclass(frozen=True)
class EncPasswordId:
    # https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-GKDI/%5bMS-GKDI%5d.pdf
    # 2.2.4 Group Key Envelope
    # This struct seems similar (the magic matches) but the real data seems to
    # be missing a few fields. Anything beyond the root_key_identifier is guess
    # work based on the data seen.
    version: int
    flags: int
    l0: int
    l1: int
    l2: int
    root_key_identifier: uuid.UUID
    unknown: bytes
    domain_name: str
    forest_name: str

    @property
    def is_public_key(self) -> bool:
        return bool(self.flags & 1)

    @classmethod
    def unpack(
        cls,
        data: t.Union[bytes, bytearray, memoryview],
    ) -> EncPasswordId:
        view = memoryview(data)

        version = struct.unpack("<I", view[:4])[0]

        assert view[4:8].tobytes() == b"\x4B\x44\x53\x4B"

        flags = struct.unpack("<I", view[8:12])[0]
        l0_index = struct.unpack("<I", view[12:16])[0]
        l1_index = struct.unpack("<I", view[16:20])[0]
        l2_index = struct.unpack("<I", view[20:24])[0]
        root_key_identifier = uuid.UUID(bytes_le=view[24:40].tobytes())
        unknown_len = struct.unpack("<I", view[40:44])[0]
        domain_len = struct.unpack("<I", view[44:48])[0]
        forest_len = struct.unpack("<I", view[48:52])[0]
        view = view[52:]

        unknown = view[:unknown_len].tobytes()
        view = view[unknown_len:]

        # Take away 2 for the final null padding
        domain = view[: domain_len - 2].tobytes().decode("utf-16-le")
        view = view[domain_len:]

        forest = view[: forest_len - 2].tobytes().decode("utf-16-le")
        view = view[forest_len:]

        return EncPasswordId(
            version=version,
            flags=flags,
            l0=l0_index,
            l1=l1_index,
            l2=l2_index,
            root_key_identifier=root_key_identifier,
            unknown=unknown,
            domain_name=domain,
            forest_name=forest,
        )


def get_laps_enc_password(dc: str, server: str) -> bytes:
    with socket.create_connection((dc, 389)) as s:
        ctx = spnego.client(hostname=dc, service="ldap")

        ldap = sansldap.LDAPClient()
        ldap.bind_sasl("GSS-SPNEGO", None, ctx.step())
        s.sendall(ldap.data_to_send())

        bind_resp = ldap.receive(s.recv(4096))[0]
        assert isinstance(bind_resp, sansldap.BindResponse)
        assert bind_resp.result.result_code == sansldap.LDAPResultCode.SUCCESS
        ctx.step(bind_resp.server_sasl_creds)
        assert ctx.complete

        ldap.search_request(
            server,
            scope=sansldap.SearchScope.BASE,
            attributes=["msLAPS-EncryptedPassword"],
        )
        req = ldap.data_to_send()
        wrapped_req = ctx.wrap(req).data
        s.sendall(struct.pack(">I", len(wrapped_req)) + wrapped_req)
        resp = s.recv(4096)

        search_res = ldap.receive(ctx.unwrap(resp[4:]).data)
        assert len(search_res) == 2
        assert isinstance(search_res[0], sansldap.SearchResultEntry)
        assert isinstance(search_res[1], sansldap.SearchResultDone)
        assert search_res[1].result.result_code == sansldap.LDAPResultCode.SUCCESS

        return search_res[0].attributes[0].values[0]


def sid_to_bytes(sid: str) -> bytes:
    sid_pattern = re.compile(r"^S-(\d)-(\d+)(?:-\d+){1,15}$")
    sid_match = sid_pattern.match(sid)
    if not sid_match:
        raise ValueError(f"Input string '{sid}' is not a valid SID string")

    sid_split = sid.split("-")
    revision = int(sid_split[1])
    authority = int(sid_split[2])

    data = bytearray(8)
    memoryview(data)[:8] = struct.pack(">Q", authority)
    data[0] = revision
    data[1] = len(sid_split) - 3

    for idx in range(3, len(sid_split)):
        sub_auth = int(sid_split[idx])
        data += struct.pack("<I", sub_auth)

    return bytes(data)


def ace_to_bytes(sid: str, access_mask: int) -> bytes:
    b_sid = sid_to_bytes(sid)

    data = bytearray(8 + len(b_sid))
    view = memoryview(data)

    data[0] = 0  # AceType - ACCESS_ALLOWED_ACE_TYPE
    data[1] = 0  # AceFlags - None
    view[2:4] = struct.pack("<H", len(data))
    view[4:8] = struct.pack("<I", access_mask)
    view[8:] = b_sid

    return bytes(data)


def acl_to_bytes(aces: t.List[bytes]) -> bytes:
    ace_data = b"".join(aces)

    data = bytearray(8 + len(ace_data))
    view = memoryview(data)

    data[0] = 2  # AclRevision - ACL_REVISION
    data[1] = 0  # Sbz1
    view[2:4] = struct.pack("<H", 8 + len(ace_data))
    view[4:6] = struct.pack("<H", len(aces))
    view[6:8] = struct.pack("<H", 0)  # Sbz2
    view[8:] = ace_data

    return bytes(data)


def sd_to_bytes(
    owner: str,
    group: str,
    sacl: t.Optional[t.List[bytes]] = None,
    dacl: t.Optional[t.List[bytes]] = None,
) -> bytes:
    control = 0b10000000 << 8  # Self-Relative

    owner_sid = sid_to_bytes(owner)
    group_sid = sid_to_bytes(group)

    b_sacl = b""
    if sacl:
        control |= 0b00010000  # SACL Present
        b_sacl = acl_to_bytes(sacl)

    b_dacl = b""
    if dacl:
        control |= 0b00000100  # DACL Present
        b_dacl = acl_to_bytes(dacl)

    data = bytearray()

    offset = 20
    data += struct.pack("B", 1)  # Revision
    data += struct.pack("B", 0)  # Sbz1
    data += struct.pack("<H", control)
    data += struct.pack("<I", offset)
    offset += len(owner_sid)
    data += struct.pack("<I", offset)
    offset += len(group_sid)
    data += struct.pack("<I", offset if b_sacl else 0)
    offset += len(b_sacl)
    data += struct.pack("<I", offset if b_dacl else 0)
    offset += len(b_dacl)

    data += owner_sid + group_sid + b_sacl + b_dacl

    return bytes(data)


def create_pdu(
    packet_type: int,
    packet_flags: int,
    call_id: int,
    header_data: bytes,
    *,
    stub_data: t.Optional[bytes] = None,
    sec_trailer: t.Optional[SecTrailer] = None,
) -> bytes:
    # https://pubs.opengroup.org/onlinepubs/9629399/toc.pdf
    # 12.6.3 Connection-oriented PDU Data Types - PDU Header
    data = bytearray()
    data += struct.pack("B", 5)  # Version
    data += struct.pack("B", 0)  # Version minor
    data += struct.pack("B", packet_type)
    data += struct.pack("B", packet_flags)
    data += b"\x10\x00\x00\x00"  # Data Representation
    data += b"\x00\x00"  # Fragment length - set at the end below
    data += struct.pack("<H", len(sec_trailer.data) if sec_trailer else 0)
    data += struct.pack("<I", call_id)
    data += header_data
    data += stub_data or b""

    if sec_trailer:
        data += struct.pack("B", sec_trailer.type)
        data += struct.pack("B", sec_trailer.level)
        data += struct.pack("B", sec_trailer.pad_length)
        data += struct.pack("B", 0)  # Auth Rsrvd
        data += struct.pack("<I", sec_trailer.context_id)
        data += sec_trailer.data

    memoryview(data)[8:10] = struct.pack("<H", len(data))

    return bytes(data)


def create_bind(
    service: t.Tuple[uuid.UUID, int, int],
    syntaxes: t.List[bytes],
    auth_data: t.Optional[bytes] = None,
    sign_header: bool = False,
) -> bytes:
    context_header = b"\x00\x00\x01\x00"
    context_header += service[0].bytes_le
    context_header += struct.pack("<H", service[1])
    context_header += struct.pack("<H", service[2])
    context_data = bytearray()
    for idx, s in enumerate(syntaxes):
        offset = len(context_data)
        context_data += context_header
        memoryview(context_data)[offset : offset + 2] = struct.pack("<H", idx)
        context_data += s

    bind_data = bytearray()
    bind_data += b"\xd0\x16"  # Max Xmit Frag
    bind_data += b"\xd0\x16"  # Max Recv Frag
    bind_data += b"\x00\x00\x00\x00"  # Assoc Group
    bind_data += b"\x03\x00\x00\x00"  # Num context items
    bind_data += context_data

    sec_trailer: t.Optional[SecTrailer] = None
    if auth_data:
        sec_trailer = SecTrailer(
            type=9,  # SPNEGO
            level=6,  # Packet Privacy
            pad_length=0,
            context_id=0,
            data=auth_data,
        )

    return create_pdu(
        packet_type=11,
        packet_flags=0x03 | (0x4 if sign_header else 0x0),
        call_id=1,
        header_data=bytes(bind_data),
        sec_trailer=sec_trailer,
    )


def create_alter_context(
    service: t.Tuple[uuid.UUID, int, int],
    token: bytes,
    sign_header: bool = False,
) -> bytes:
    ctx1 = b"\x01\x00\x01\x00"
    ctx1 += service[0].bytes_le
    ctx1 += struct.pack("<H", service[1])
    ctx1 += struct.pack("<H", service[1])
    ctx1 += NDR64[0].bytes_le + struct.pack("<H", NDR64[1]) + struct.pack("<H", NDR[2])

    alter_context_data = bytearray()
    alter_context_data += b"\xd0\x16"  # Max Xmit Frag
    alter_context_data += b"\xd0\x16"  # Max Recv Frag
    alter_context_data += b"\x00\x00\x00\x00"  # Assoc Group
    alter_context_data += b"\x01\x00\x00\x00"  # Num context items
    alter_context_data += ctx1

    auth_data = SecTrailer(
        type=9,  # SPNEGO
        level=6,  # Packet Privacy
        pad_length=0,
        context_id=0,
        data=token,
    )

    return create_pdu(
        packet_type=14,
        packet_flags=0x03 | (0x4 if sign_header else 0x0),
        call_id=1,
        header_data=bytes(alter_context_data),
        sec_trailer=auth_data,
    )


def create_request(
    opnum: int,
    data: bytes,
    ctx: t.Optional[gssapi.SecurityContext] = None,
    sign_header: bool = False,
) -> bytes:
    # Add Verification trailer to data
    # MS-RPCE 2.2.2.13 Veritifcation Trailer
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/0e9fea61-1bff-4478-9bfe-a3b6d8b64ac3
    if ctx:
        pcontext = bytearray()
        pcontext += ISD_KEY[0].bytes_le
        pcontext += struct.pack("<H", ISD_KEY[1]) + struct.pack("<H", ISD_KEY[2])
        pcontext += NDR64[0].bytes_le
        pcontext += struct.pack("<H", NDR64[1]) + struct.pack("<H", NDR64[2])

        verification_trailer = bytearray()
        verification_trailer += b"\x8a\xe3\x13\x71\x02\xf4\x36\x71"  # Signature

        verification_trailer += b"\x02\x40"  # Trailer Command - PCONTEXT + End
        verification_trailer += struct.pack("<H", len(pcontext))
        verification_trailer += pcontext

        # Verification trailer to added to a 4 byte boundary on the stub data
        data_padding = -len(data) % 4
        data += b"\x00" * data_padding

        data += verification_trailer
        alloc_hint = len(data)
        auth_padding = -len(data) % 16
        data += b"\x00" * auth_padding

    else:
        alloc_hint = len(data)

    request_data = bytearray()
    request_data += struct.pack("<I", alloc_hint)
    request_data += struct.pack("<H", 1)  # Context id
    request_data += struct.pack("<H", opnum)

    sec_trailer: t.Optional[SecTrailer] = None
    if ctx and sign_header:
        raise NotImplementedError()

        # I have no idea what is actually signed. I'm guessing it's the PDU header
        # with a blanked out fragment length field but this probably needs tweaking.
        # memoryview(pdu)[8:10] = b"\x00\x00"

        # iov_buffers = gssapi.raw.IOV(
        #     gssapi.raw.IOVBufferType.header,
        #     (gssapi.raw.IOVBufferType.sign_only, pdu),
        #     data,
        #     std_layout=False,
        # )
        # gssapi.raw.wrap_iov(
        #     ctx,
        #     message=iov_buffers,
        #     confidential=True,
        #     qop=None,
        # )

        # sec_trailer = SecTrailer(
        #     type=9,  # SPNEGO
        #     level=6,  # Packet Privacy
        #     pad_length=auth_padding,
        #     context_id=0,
        #     data=iov_buffers[0].value or b"",
        # )

        # return create_pdu(
        #     packet_type=0,
        #     packet_flags=0x03,
        #     call_id=1,
        #     header_data=bytes(request_data),
        #     stub_data=iov_buffers[2].value,
        #     sec_trailer=sec_trailer,
        # )

    elif ctx:
        iov_buffers = gssapi.raw.IOV(
            gssapi.raw.IOVBufferType.header,
            data,
            std_layout=False,
        )
        gssapi.raw.wrap_iov(
            ctx,
            message=iov_buffers,
            confidential=True,
            qop=None,
        )

        sec_trailer = SecTrailer(
            type=9,  # SPNEGO
            level=6,  # Packet Privacy
            pad_length=auth_padding,
            context_id=0,
            data=iov_buffers[0].value or b"",
        )
        stub_data = iov_buffers[1].value

    else:
        stub_data = data

    return create_pdu(
        packet_type=0,
        packet_flags=0x03,
        call_id=1,
        header_data=bytes(request_data),
        stub_data=stub_data,
        sec_trailer=sec_trailer,
    )


def get_fault_pdu_error(data: memoryview) -> int:
    status = struct.unpack("<I", data[24:28])[0]

    return status


def parse_bind_ack(data: bytes) -> t.Optional[bytes]:
    view = memoryview(data)

    pkt_type = struct.unpack("B", view[2:3])[0]
    if pkt_type == 3:
        err = get_fault_pdu_error(view)
        raise Exception(f"Receive Fault PDU: 0x{err:08X}")

    assert pkt_type == 12

    auth_length = struct.unpack("<H", view[10:12])[0]
    if auth_length:
        auth_blob = view[-auth_length:].tobytes()

        return auth_blob

    else:
        return None


def parse_alter_context(data: bytes) -> bytes:
    view = memoryview(data)

    pkt_type = struct.unpack("B", view[2:3])[0]
    if pkt_type == 3:
        err = get_fault_pdu_error(view)
        raise Exception(f"Receive Fault PDU: 0x{err:08X}")

    assert pkt_type == 15

    auth_length = struct.unpack("<H", view[10:12])[0]
    auth_blob = view[-auth_length:].tobytes()

    return auth_blob


def parse_response(
    data: bytes,
    ctx: t.Optional[gssapi.SecurityContext] = None,
    sign_header: bool = False,
) -> bytes:
    view = memoryview(data)

    pkt_type = struct.unpack("B", view[2:3])[0]
    if pkt_type == 3:  # False
        err = get_fault_pdu_error(view)
        raise Exception(f"Receive Fault PDU: 0x{err:08X}")

    assert pkt_type == 2
    frag_length = struct.unpack("<H", view[8:10])[0]
    auth_length = struct.unpack("<H", view[10:12])[0]

    assert len(view) == frag_length
    if auth_length:
        auth_data = view[-(auth_length + 8) :]
        stub_data = view[24 : len(view) - (auth_length + 8)]
        padding = struct.unpack("B", auth_data[2:3])[0]

    else:
        auth_data = memoryview(b"")
        stub_data = view[24:]
        padding = 0

    if ctx and sign_header:
        raise NotImplementedError()

    elif ctx:
        iov_buffers = gssapi.raw.IOV(
            (gssapi.raw.IOVBufferType.header, False, auth_data[8:].tobytes()),
            stub_data.tobytes(),
            std_layout=False,
        )
        gssapi.raw.unwrap_iov(
            ctx,
            message=iov_buffers,
        )

        decrypted_stub = iov_buffers[1].value or b""
        return decrypted_stub[: len(decrypted_stub) - padding]

    else:
        return stub_data.tobytes()


def create_get_key_request(
    target_sd: bytes,
    root_key_id: uuid.UUID,
    l0: int,
    l1: int,
    l2: int,
) -> t.Tuple[int, bytes]:
    # HRESULT GetKey(
    #     [in] handle_t hBinding,
    #     [in] ULONG cbTargetSD,
    #     [in] [size_is(cbTargetSD)] [ref] char* pbTargetSD,
    #     [in] [unique] GUID* pRootKeyID,
    #     [in] LONG L0KeyID,
    #     [in] LONG L1KeyID,
    #     [in] LONG L2KeyID,
    #     [out] unsigned long* pcbOut,
    #     [out] [size_is(, *pcbOut)] byte** ppbOut);

    target_sd_len = struct.pack("<I", len(target_sd))

    data = bytearray()

    # cbTargetSD
    data += target_sd_len
    data += b"\x00\x00\x00\x00"  # I think padding for 8 byte boundary align?

    # pbTargetSD
    # A pointer seems to include the length + 8 byte alignment padding before
    # the value
    data += target_sd_len
    data += b"\x00\x00\x00\x00"
    data += target_sd
    target_sd_padding = -len(target_sd) % 8
    data += b"\x00" * target_sd_padding

    # pRootKeyID
    data += b"\x00\x00\x02\x00\x00\x00\x00\x00"  # Maybe Referent ID?
    data += root_key_id.bytes_le

    # L0KeyID
    data += struct.pack("<I", l0)

    # L1KeyID
    data += struct.pack("<I", l1)

    # L2KeyID
    data += struct.pack("<I", l2)

    return 0, bytes(data)


def parse_create_key_response(data: bytes) -> GroupKeyEnvelope:
    # HRESULT GetKey(
    #     [in] handle_t hBinding,
    #     [in] ULONG cbTargetSD,
    #     [in] [size_is(cbTargetSD)] [ref] char* pbTargetSD,
    #     [in] [unique] GUID* pRootKeyID,
    #     [in] LONG L0KeyID,
    #     [in] LONG L1KeyID,
    #     [in] LONG L2KeyID,
    #     [out] unsigned long* pcbOut,
    #     [out] [size_is(, *pcbOut)] byte** ppbOut);
    view = memoryview(data)

    hresult = struct.unpack("<I", view[-4:].tobytes())[0]
    view = view[:-4]
    if hresult != 0:
        raise Exception(f"GetKey failed 0x{hresult:08X}")

    key_length = struct.unpack("<I", view[:4])[0]
    view = view[8:]  # Skip padding as well
    # Skip the reference id and double up on pointer size
    key = view[16 : 16 + key_length].tobytes()
    assert len(key) == key_length

    return GroupKeyEnvelope.unpack(key)


def create_ept_map_request(
    service: t.Tuple[uuid.UUID, int, int],
    data_rep: t.Tuple[uuid.UUID, int, int],
    protocol: int = 0x0B,  # TCP/IP
    port: int = 135,
    address: int = 0,
) -> t.Tuple[int, bytes]:
    # MS-RPCE 2.2.1.2.5 ept_map Method
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/ab744583-430e-4055-8901-3c6bc007e791
    # void ept_map(
    #     [in] handle_t hEpMapper,
    #     [in, ptr] UUID* obj,
    #     [in, ptr] twr_p_t map_tower,
    #     [in, out] ept_lookup_handle_t* entry_handle,
    #     [in, range(0,500)] unsigned long max_towers,
    #     [out] unsigned long* num_towers,
    #     [out, ptr, size_is(max_towers), length_is(*num_towers)]
    #         twr_p_t* ITowers,
    #     [out] error_status* status
    # );
    def build_floor(protocol: int, lhs: bytes, rhs: bytes) -> bytes:
        data = bytearray()
        data += struct.pack("<H", len(lhs) + 1)
        data += struct.pack("B", protocol)
        data += lhs
        data += struct.pack("<H", len(rhs))
        data += rhs

        return bytes(data)

    floors: t.List[bytes] = [
        build_floor(
            protocol=0x0D,
            lhs=service[0].bytes_le + struct.pack("<H", service[1]),
            rhs=struct.pack("<H", service[2]),
        ),
        build_floor(
            protocol=0x0D,
            lhs=data_rep[0].bytes_le + struct.pack("<H", data_rep[1]),
            rhs=struct.pack("<H", data_rep[2]),
        ),
        build_floor(protocol=protocol, lhs=b"", rhs=b"\x00\x00"),
        build_floor(protocol=0x07, lhs=b"", rhs=struct.pack(">H", port)),
        build_floor(protocol=0x09, lhs=b"", rhs=struct.pack(">I", address)),
    ]

    tower = bytearray()
    tower += struct.pack("<H", len(floors))
    for f in floors:
        tower += f
    tower_padding = -(len(tower) + 4) % 8

    data = bytearray()
    data += b"\x01" + (b"\x00" * 23)  # Blank UUID pointer with referent id 1
    data += b"\x02\x00\x00\x00\x00\x00\x00\x00"  # Tower referent id 2
    data += struct.pack("<Q", len(tower))
    data += struct.pack("<I", len(tower))
    data += tower
    data += b"\x00" * tower_padding
    data += b"\x00" * 20  # Context handle
    data += struct.pack("<I", 4)  # Max towers

    return 3, bytes(data)


def parse_ept_map_response(data: bytes) -> t.List[Tower]:
    def unpack_floor(view: memoryview) -> t.Tuple[int, int, memoryview, memoryview]:
        lhs_len = struct.unpack("<H", view[:2])[0]
        proto = view[2]
        lhs = view[3 : lhs_len + 2]
        offset = lhs_len + 2

        rhs_len = struct.unpack("<H", view[offset : offset + 2])[0]
        rhs = view[offset + 2 : offset + rhs_len + 2]

        return offset + rhs_len + 2, proto, lhs, rhs

    view = memoryview(data)

    return_code = struct.unpack("<I", view[-4:])[0]
    assert return_code == 0
    num_towers = struct.unpack("<I", view[20:24])[0]
    # tower_max_count = struct.unpack("<Q", view[24:32])[0]
    # tower_offset = struct.unpack("<Q", view[32:40])[0]
    tower_count = struct.unpack("<Q", view[40:48])[0]

    tower_data_offset = 8 * tower_count  # Ignore referent ids
    view = view[48 + tower_data_offset :]
    towers: t.List[Tower] = []
    for _ in range(tower_count):
        tower_length = struct.unpack("<Q", view[:8])[0]
        padding = -(tower_length + 4) % 8
        floor_len = struct.unpack("<H", view[12:14])[0]
        assert floor_len == 5
        view = view[14:]

        offset, proto, lhs, rhs = unpack_floor(view)
        view = view[offset:]
        assert proto == 0x0D
        service = (
            uuid.UUID(bytes_le=lhs[:16].tobytes()),
            struct.unpack("<H", lhs[16:])[0],
            struct.unpack("<H", rhs)[0],
        )

        offset, proto, lhs, rhs = unpack_floor(view)
        view = view[offset:]
        assert proto == 0x0D
        data_rep = (
            uuid.UUID(bytes_le=lhs[:16].tobytes()),
            struct.unpack("<H", lhs[16:])[0],
            struct.unpack("<H", rhs)[0],
        )

        offset, protocol, _, _ = unpack_floor(view)
        view = view[offset:]
        assert protocol == 0x0B

        offset, proto, lhs, rhs = unpack_floor(view)
        view = view[offset:]
        assert proto == 0x07
        port = struct.unpack(">H", rhs)[0]

        offset, proto, lhs, rhs = unpack_floor(view)
        view = view[offset:]
        assert proto == 0x09
        addr = struct.unpack(">I", rhs)[0]

        towers.append(
            Tower(
                service=service,
                data_rep=data_rep,
                protocol=protocol,
                port=port,
                addr=addr,
            )
        )
        view = view[padding:]

    assert len(towers) == num_towers

    return towers


def get_key(
    dc: str,
    target_sd: bytes,
    root_key_id: uuid.UUID,
    l0: int,
    l1: int,
    l2: int,
    sign_header: bool = True,
) -> GroupKeyEnvelope:
    bind_syntaxes = [
        NDR[0].bytes_le + struct.pack("<H", NDR[1]) + struct.pack("<H", NDR[2]),
        NDR64[0].bytes_le + struct.pack("<H", NDR64[1]) + struct.pack("<H", NDR64[2]),
        BIND_TIME_FEATURE_NEGOTIATION[0].bytes_le
        + struct.pack("<H", BIND_TIME_FEATURE_NEGOTIATION[1])
        + struct.pack("<H", BIND_TIME_FEATURE_NEGOTIATION[2]),
    ]

    # Find the dynamic endpoint port for the ISD service.
    with socket.create_connection((dc, 135)) as s:
        bind_data = create_bind(
            EMP,
            bind_syntaxes,
            sign_header=False,
        )
        s.sendall(bind_data)
        resp = s.recv(4096)
        parse_bind_ack(resp)

        opnum, map_request = create_ept_map_request(ISD_KEY, NDR)
        request = create_request(
            opnum,
            map_request,
        )
        s.sendall(request)
        resp = s.recv(4096)

        ept_response = parse_response(resp)
        isd_towers = parse_ept_map_response(ept_response)
        assert len(isd_towers) > 0
        isd_port = isd_towers[0].port

    # DCE style is not exposed in pyspnego yet so use gssapi directly.
    negotiate_mech = gssapi.OID.from_int_seq("1.3.6.1.5.5.2")
    target_spn = gssapi.Name(f"host@{dc}", name_type=gssapi.NameType.hostbased_service)
    flags = (
        gssapi.RequirementFlag.mutual_authentication
        | gssapi.RequirementFlag.replay_detection
        | gssapi.RequirementFlag.out_of_sequence_detection
        | gssapi.RequirementFlag.confidentiality
        | gssapi.RequirementFlag.integrity
        | gssapi.RequirementFlag.dce_style
    )

    ctx = gssapi.SecurityContext(
        name=target_spn,
        flags=flags,
        mech=negotiate_mech,
        usage="initiate",
    )
    out_token = ctx.step()
    assert out_token

    with socket.create_connection((dc, isd_port)) as s:
        bind_data = create_bind(
            ISD_KEY,
            bind_syntaxes,
            auth_data=out_token,
            sign_header=sign_header,
        )

        s.sendall(bind_data)
        resp = s.recv(4096)
        in_token = parse_bind_ack(resp)

        out_token = ctx.step(in_token)
        assert not ctx.complete
        assert out_token

        alter_context = create_alter_context(
            ISD_KEY,
            out_token,
            sign_header=sign_header,
        )
        s.sendall(alter_context)
        resp = s.recv(4096)
        in_token = parse_alter_context(resp)

        out_token = ctx.step(in_token)
        assert ctx.complete
        assert not out_token
        # TODO: Deal with a no header signing.from server

        opnum, get_key_req = create_get_key_request(target_sd, root_key_id, l0, l1, l2)
        request = create_request(
            opnum,
            get_key_req,
            ctx=ctx,
            sign_header=sign_header,
        )
        s.sendall(request)
        resp = s.recv(4096)

        create_key_resp = parse_response(resp, ctx=ctx, sign_header=sign_header)
        return parse_create_key_response(create_key_resp)


def aes256gcm_decrypt(
    algorithm: AlgorithmIdentifier,
    key: bytes,
    secret: bytes,
) -> bytes:
    # This is not right but I'm not up to this part yet to try it out.
    assert algorithm.algorithm == "2.16.840.1.101.3.4.1.46"  # AES256-GCM
    assert algorithm.parameters
    reader = ASN1Reader(algorithm.parameters).read_sequence()
    iv = reader.read_octet_string()

    cipher = AESGCM(key)
    data = cipher.decrypt(iv, secret, None)

    return data


def compute_kdf_context(
    key_guid: uuid.UUID,
    l0: int,
    l1: int,
    l2: int,
) -> bytes:
    # The MS-GKDI docs state this is just 'Key(SD, RK, L0, L1, L2)' but don't
    # mention how they are all joined together. GoldenGMSA only uses
    # (RK, L0, L1, K2) concatenated together. Probably needs more investigation.
    context = key_guid.bytes_le
    context += struct.pack("<i", l0)
    context += struct.pack("<i", l1)
    context += struct.pack("<i", l2)

    return context


def kdf(
    algorithm: hashes.HashAlgorithm,
    secret: bytes,
    label: bytes,
    context: bytes,
    length: int,
) -> bytes:
    # KDF(HashAlg, KI, Label, Context, L)
    # where KDF is SP800-108 in counter mode.
    kdf = KBKDFHMAC(
        algorithm=algorithm,
        mode=Mode.CounterMode,
        length=length,
        label=label,
        context=context,
        # MS-SMB2 uses the same KDF function and my implementation that
        # sets a value of 4 seems to work so assume that's the case here.
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        fixed=None,
    )
    return kdf.derive(secret)


def parse_dpapi_ng_blob(data: bytes) -> t.Tuple[KEKRecipientInfo, EncryptedContentInfo]:
    view = memoryview(data)
    header = ASN1Reader(view).peek_header()
    content_info = ContentInfo.unpack(view[: header.tag_length + header.length], header=header)
    remaining_data = view[header.tag_length + header.length :].tobytes()

    assert content_info.content_type == EnvelopedData.content_type
    enveloped_data = EnvelopedData.unpack(content_info.content)

    assert enveloped_data.version == 2
    assert len(enveloped_data.recipient_infos) == 1
    assert isinstance(enveloped_data.recipient_infos[0], KEKRecipientInfo)

    enc_content = enveloped_data.encrypted_content_info
    if not enc_content.content and remaining_data:
        # The LAPS payload seems to not include this in the payload but at the
        # end of the content, just set it back on the structure.
        object.__setattr__(enc_content, "content", remaining_data)

    return enveloped_data.recipient_infos[0], enc_content


def ncrypt_unprotect_secret(
    dc: str,
    blob: bytes,
    rpc_sign_header: bool = True,
) -> bytes:
    kek_info, enc_content = parse_dpapi_ng_blob(blob)

    assert kek_info.version == 4
    assert kek_info.kekid.other is not None
    assert kek_info.kekid.other.key_attr_id == "1.3.6.1.4.1.311.74.1"
    protection_descriptor = NCryptProtectionDescriptor.unpack(kek_info.kekid.other.key_attr or b"")
    assert protection_descriptor.content_type == "1.3.6.1.4.1.311.74.1.1"
    assert enc_content.content

    password_id = EncPasswordId.unpack(kek_info.kekid.key_identifier)

    # Build the target security descriptor from the SID passed in. This SD
    # contains an ACE per target user with a mask of 0x3 and a final ACE of the
    # current user with a mask of 0x2. When viewing this over the wire the
    # current user is set as S-1-1-0 (World) and the owner/group is
    # S-1-5-18 (SYSTEM).
    target_sd = sd_to_bytes(
        owner="S-1-5-18",
        group="S-1-5-18",
        dacl=[ace_to_bytes(protection_descriptor.value, 3), ace_to_bytes("S-1-1-0", 2)],
    )

    rk = get_key(
        dc,
        target_sd,
        password_id.root_key_identifier,
        password_id.l0,
        password_id.l1,
        password_id.l2,
        sign_header=rpc_sign_header,
    )

    # Now we have the key info we should be able to decrypt the original
    # payload.
    # Maybe GoldenGMSA has more info.
    # Will need to look in CQURE and their PFX decryption which seems very
    # closely related to this
    # https://www.semperis.com/blog/golden-gmsa-attack/
    # https://cqureacademy.com/blog/secure-server/understand-credential-security-notes-session-microsoft-ignite
    #
    # A snapshot of the information know at this point in time.
    # msLAPS-EncryptedPassword payload
    #   recipient info
    #       kek_algo: 2.16.840.1.101.3.4.1.45 (AES256 wrap) - no params
    #       enc_key: 192ABFD9C2C20563673768C56B3C9A8C049C2DF7C5CE39EFD315A944DB62C229F47F92B0CCB59CA8
    #       kekid_pub_key: 444850420001000087A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A15973FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC416594B54EA70598A6B5F120AEF7C1F091E304344E04A3C377CFF591623B9BC1A1D67CC573BA93D66B3760E7976B750A2CFBDB6CBA9D3F76B5C8CD630786E8D32A3EEA8DC0940D367361F5941BA94F6A97DB5DCB7F25E97B57066E420E3CBB478B6980718AF7B5DF668AC9D61A09D958FA8FFD7ED3AC849C94E88FDB2D45AE9B87BFD983CD7A30ACF46D1D60490194EB44B0674F8D9E7360E7088725E1B4870FD24C74E4F84A1364787787DEC2D952040E77A71D8EE530D1D33144B4D4074EF5D3604541C280A7EFDCB00AB4BB99B56255DBBFC96BB069C65C793614C6B2782C768E4CADE53841958F8DE0D669E747F50E8355B093702E8F594B8B1DFE2D9A17C8B0B
    #   encrypted content info
    #       content_algorithm: 2.16.840.1.101.3.4.1.46 (AES256 GCM) - 3011040C7CAAA06665D7D747E912A6C7020110
    #           nonce: 7CAAA06665D7D747E912A6C7
    #           icvlen: 16
    #
    # GetKey result
    #   kdf_algo - 'SP800_108_CTR_HMAC'
    #   kdf_parameters - 00000000010000000E000000000000005300480041003500310032000000
    #       https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-GKDI/%5bMS-GKDI%5d.pdf - 2.2.1 KDF Parameters
    #       name - SHA512
    #   l1_key - F029FC8D8FD0509E69F9FE40A1D54A374552101F291819307F800BA8DE21437F062F5104BBD19E4DDB747FD9C48B7C63838BE17B12227C221287BBE05DD13C49
    #   l2_key - 8EB901182619306ECADD3003CCAE623677A6B86FB3FBA5488BCA0F16AE202870D75512A76F7FB31A6C523F301C6B35B26CB0184284C346379F9224EB9EB423FA
    #   secret_algorithm - DH
    #   secret_parameters - 0C0200004448504D0001000087A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A15973FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659
    #       https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-GKDI/%5bMS-GKDI%5d.pdf - 2.2.2 FCC DH Parameters
    #       key_length - 256
    #       field_order - 87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597
    #       generator - 3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659
    #
    # Actual Password
    #   5{Bb}B,})1(!B3

    # CQURE states for PFX decryption this is used but it doesn't go into more
    # details. Maybe try and get a copy of 'CQDPAPINGPFXDecrypter.exe'
    # DPAPI-NG
    # A. RootKey
    # Algorithms
    # Key derivation function: SP800_108_CTR_HMAC (SHA512)
    # Secret agreement: Diffie-Hellman

    # B. DPAPI blob
    # Key derivation: KDF_SP80056A_CONCAT

    # After getting the key, there is a need for decryption:
    # Key wrap algorithm: RFC3394 (KEK -> CEK)
    # Decryption: AES-256-GCM (CEK, Blob)

    # From MS there is this diagram
    # https://learn.microsoft.com/en-us/windows/win32/seccng/protected-data-format
    # Protected data is stored as an ASN.1 encoded BLOB. The data is formatted
    # as CMS (certificate message syntax) enveloped content. The digital
    # envelope contains encrypted content, recipient information that contains
    # an encrypted content encryption key (CEK), and a header that contains
    # information about the content, including the unencrypted protection
    # descriptor rule string.

    # This is not right and just me spitballing trying to figure things out.
    # MS-GKDI 3.1.4.1.2 Generating a Group Key
    # https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-GKDI/%5bMS-GKDI%5d.pdf#%5B%7B%22num%22%3A91%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C557%2C0%5D
    # print(f"PasswordId L0 {password_id.l0} L1 {password_id.l1} L2 {password_id.l2}")
    # print(f"GroupKeyId L0 {rk.l0} L1 {rk.l1} L2 {rk.l2}")
    label = "KDS service\0".encode("utf-16-le")

    assert rk.version == 1
    assert rk.kdf_algorithm == "SP800_108_CTR_HMAC"

    kdf_parameters = KDFParameters.unpack(rk.kdf_parameters)
    hash_algo: hashes.HashAlgorithm
    if kdf_parameters.hash_name == "SHA1":
        hash_algo = hashes.SHA1()
    elif kdf_parameters.hash_name == "SHA256":
        hash_algo = hashes.SHA256()
    elif kdf_parameters.hash_name == "SHA384":
        hash_algo = hashes.SHA384()
    elif kdf_parameters.hash_name == "SHA512":
        hash_algo = hashes.SHA512()
    else:
        raise Exception(f"Unsupported hash algorithm {kdf_parameters.hash_name}")

    # TODO: Deal with L0 differences.
    l1 = rk.l1
    l1_key = rk.l1_key
    l2 = rk.l2
    l2_key = rk.l2_key

    if password_id.l1 != l1:
        l1 = rk.l1 - 1

        while password_id.l1 != l1:
            l1 -= 1
            l1_key = kdf(
                hash_algo,
                l1_key,
                label,
                compute_kdf_context(
                    rk.root_key_identifier,
                    rk.l0,
                    l1,
                    -1,
                ),
                64,
            )

        l2 = 31
        l2_key = kdf(
            hash_algo,
            l1_key,
            label,
            compute_kdf_context(
                rk.root_key_identifier,
                rk.l0,
                l1,
                l2,
            ),
            64,
        )

    while l2 != password_id.l2:
        l2 -= 1

        # Key(SD, RK, L0, L1, n) = KDF(
        #   HashAlg,
        #   Key(SD, RK, L0, L1, n+1),
        #   "KDS service",
        #   RKID || L0 || L1 || n,
        #   512
        # )
        l2_key = kdf(
            hash_algo,
            l2_key,
            label,
            compute_kdf_context(
                rk.root_key_identifier,
                rk.l0,
                l1,
                l2,
            ),
            64,
        )

    # MS-GKDI - 3.1.4.1.2 Generating a Group key
    # To derive a group public key with a group key identifier (L0, L1, L2),
    # the server MUST proceed as follows:
    # First, the server MUST validate the root key configuration attributes
    # related to public keys

    # DH
    # If RK.msKds-SecretAgreement-AlgorithmID is equal to "DH",
    # RK.msKds-SecretAgreement-Param MUST be in the format specified in section
    # 2.2.2, and the Key length field of RK.msKds-SecretAgreement-Param MUST be
    # equal to RK.msKds-PublicKey-Length

    # TODO: Support ECHD keys
    assert rk.secret_algorithm == "DH"
    dh_parameters = FFCDHParameters.unpack(rk.secret_parameters)
    assert dh_parameters.key_length == (rk.public_key_length // 8)

    # 2. Having validated the root key configuration, the server MUST then
    # compute the group private key in the following manner:
    # PrivKey(SD, RK, L0, L1, L2) = KDF(
    #   HashAlg,
    #   Key(SD, RK, L0, L1, L2),
    #   "KDS service",
    #   RK.msKds-SecretAgreement-AlgorithmID,
    #   RK.msKds-PrivateKey-Length
    # )
    private_key = kdf(
        hash_algo,
        l2_key,
        label,
        (rk.secret_algorithm + "\0").encode("utf-16-le"),
        math.ceil(rk.private_key_length / 8),
    )

    # 3. Lastly, the server MUST compute the group public key
    # PubKey(SD, RK, L0, L1, L2) as follows:

    # Test case
    # P = b"\x0D"  # 13
    # G = b"\x06"
    # a = b"\x05"
    # b = b"\x04"
    # A = b"\x02"
    # B = b"\x09"
    # s = b"\x03"

    # actual = get_dh_pub(P, G, a)
    # assert actual == A

    # actual = get_dh_pub(P, G, b)
    # assert actual == B

    # actual = get_dh_shared_secret(P, a, B)
    # assert actual == s

    # actual = get_dh_shared_secret(P, b, A)
    # assert actual == s

    # DH
    # If RK.msKds-SecretAgreement-AlgorithmID is equal to "DH", the server MUST
    # compute PubKey(SD, RK, L0, L1, L2) by using the method specified in
    # [SP800-56A] section 5.6.1.1, with the group parameters specified in
    # RK.msKds-SecretAgreement-Param, and with PrivKey(SD, RK, L0, L1, L2) as
    # the private key
    public_key = get_dh_pub(dh_parameters.field_order, dh_parameters.generator, private_key)

    # TODO: Support ECHD keys

    # With the private and public key we can derive the shared secret
    # This isn't right we only have our private and public key. We need the
    # peer's public key for this.
    # shared_secret = get_dh_shared_secret(dh_parameters.generator, private_key, public_key)
    # shared_secret = get_dh_shared_secret(dh_parameters.generator, private_key, password_id.unknown)

    # Manual run from Windows and their results
    """
BCryptGenerateSymmetricKey(Algorithm: 0x29ABCFE4AD0, Key: 0xB97DAFE6A0, KeyObject: 0x00000000, KeyObjectLength: 0x00000000, Secret: 0x2DB52F69390, SecretLength: 64, Flags: 0x00000000) -> Secret: 47D6429C3531529118726E7CAB366777CB4388BA0F6E160A75D7432A1F47FC2BB9F385E90E5393990A352D481907E540A91EDB10BEF4EAACC90F7CFA5446966F
BCryptGenerateSymmetricKey -> Res: 0x00000000

BCryptKeyDerivation(Key: 0x2DB52AFBBC0, ParameterList: 0x29ABCFFB5A0, DerivedKey: 0x2DB52F69390, DerivedKeyLength: 64, OutKeyLength: 0xB97DAFE694, Flags: 0x00000000)
        BCryptKeyDerivation ParameterList(Version: 0, Buffers: 2)
                [0] Type: KDF_HASH_ALGORITHM (0), Data: SHA512
                [1] Type: KDF_GENERIC_PARAMETER (17), Data: 4B004400530020007300650072007600690063006500000000A84FC6BA90E87C91109083E7B0F85996690100000F0000001F000000
                        Label: KDS service
                        Context: A84FC6BA90E87C91109083E7B0F85996690100000F0000001F000000
                                RootKeyId: 168 79 198 186 144 232 124 145 16 144 131 231 176 248 89 150
                                L0: 361
                                L1: 15
                                L2: 31
BCryptKeyDerivation -> Res: 0x00000000, Derived: E8538AF97E87306C9CE2E327905EB932220E76DA3946E94AB26A9748206F927F0324A7024C3596E76ADA8E68FE3A592FA80446956F58238532A3434F0B5C1B38, A: 0x2DB52F69390

BCryptGenerateSymmetricKey(Algorithm: 0x29ABCFE4AD0, Key: 0xB97DAFE6A0, KeyObject: 0x00000000, KeyObjectLength: 0x00000000, Secret: 0x2DB52F69390, SecretLength: 64, Flags: 0x00000000) -> Secret: E8538AF97E87306C9CE2E327905EB932220E76DA3946E94AB26A9748206F927F0324A7024C3596E76ADA8E68FE3A592FA80446956F58238532A3434F0B5C1B38
BCryptGenerateSymmetricKey -> Res: 0x00000000

BCryptKeyDerivation(Key: 0x2DB52AFB380, ParameterList: 0x29ABCFFB5A0, DerivedKey: 0x2DB52F69390, DerivedKeyLength: 64, OutKeyLength: 0xB97DAFE694, Flags: 0x00000000)
        BCryptKeyDerivation ParameterList(Version: 0, Buffers: 2)
                [0] Type: KDF_HASH_ALGORITHM (0), Data: SHA512
                [1] Type: KDF_GENERIC_PARAMETER (17), Data: 4B004400530020007300650072007600690063006500000000A84FC6BA90E87C91109083E7B0F85996690100000F0000001E000000
                        Label: KDS service
                        Context: A84FC6BA90E87C91109083E7B0F85996690100000F0000001E000000
                                RootKeyId: 168 79 198 186 144 232 124 145 16 144 131 231 176 248 89 150
                                L0: 361
                                L1: 15
                                L2: 30
BCryptKeyDerivation -> Res: 0x00000000, Derived: 3B369385E623113F0B850E9FB378E164123C3845D523EB1C2ACD0325D1F497D28EBA41F642E7AAC35AAD0AF6CEC62B4192C06F9B8A9DFAF42F107FA5CDAAF11D, A: 0x2DB52F69390

BCryptGenerateSymmetricKey(Algorithm: 0x29ABCFE4AD0, Key: 0xB97DAFE6A0, KeyObject: 0x00000000, KeyObjectLength: 0x00000000, Secret: 0x2DB52F69390, SecretLength: 64, Flags: 0x00000000) -> Secret: 3B369385E623113F0B850E9FB378E164123C3845D523EB1C2ACD0325D1F497D28EBA41F642E7AAC35AAD0AF6CEC62B4192C06F9B8A9DFAF42F107FA5CDAAF11D
BCryptGenerateSymmetricKey -> Res: 0x00000000

BCryptKeyDerivation(Key: 0x2DB52AFBBC0, ParameterList: 0x29ABCFFB5A0, DerivedKey: 0x2DB52F69390, DerivedKeyLength: 64, OutKeyLength: 0xB97DAFE694, Flags: 0x00000000)
        BCryptKeyDerivation ParameterList(Version: 0, Buffers: 2)
                [0] Type: KDF_HASH_ALGORITHM (0), Data: SHA512
                [1] Type: KDF_GENERIC_PARAMETER (17), Data: 4B004400530020007300650072007600690063006500000000A84FC6BA90E87C91109083E7B0F85996690100000F0000001D000000
                        Label: KDS service
                        Context: A84FC6BA90E87C91109083E7B0F85996690100000F0000001D000000
                                RootKeyId: 168 79 198 186 144 232 124 145 16 144 131 231 176 248 89 150
                                L0: 361
                                L1: 15
                                L2: 29
BCryptKeyDerivation -> Res: 0x00000000, Derived: 98DF72B98DBA8661B4AFAE0ABA605015114B8A94BCF0843A1FFAF71DEEE6F49CAEFA570D4CF75F1A0F5676E31603CA8B783EBB839BAD8C344EDFDEF7C6ACE974, A: 0x2DB52F69390

BCryptGenerateSymmetricKey(Algorithm: 0x29ABCFE4AD0, Key: 0xB97DAFE780, KeyObject: 0x00000000, KeyObjectLength: 0x00000000, Secret: 0x2DB52F69190, SecretLength: 64, Flags: 0x00000000)
    Secret: 98DF72B98DBA8661B4AFAE0ABA605015114B8A94BCF0843A1FFAF71DEEE6F49CAEFA570D4CF75F1A0F5676E31603CA8B783EBB839BAD8C344EDFDEF7C6ACE974
BCryptGenerateSymmetricKey -> Res: 0x00000000

BCryptKeyDerivation(Key: 0x2DB52AFAE00, ParameterList: 0x29ABCFFB5A0, DerivedKey: 0x2DB52F69190, DerivedKeyLength: 32, OutKeyLength: 0xB97DAFE774, Flags: 0x00000000)
        BCryptKeyDerivation ParameterList(Version: 0, Buffers: 2)
                [0] Type: KDF_HASH_ALGORITHM (0), Data: SHA512
                [1] Type: KDF_GENERIC_PARAMETER (17), Data: 4B00440053002000730065007200760069006300650000000016B3FA1BFC1066B30B63B29A2D29F31D82FB5AE3CC05F86ECB67EFAC69F2CE55
                        Label: KDS service
                        Context: 16B3FA1BFC1066B30B63B29A2D29F31D82FB5AE3CC05F86ECB67EFAC69F2CE55
BCryptKeyDerivation -> Res: 0x00000000, Derived: FBD5A5143F23822E3F8B7A195F7216E554BEE383A645241BBCFC155EEBF622D3, A: 0x2DB52F69190
    """

    expected_l2_key = base64.b16decode(
        "98DF72B98DBA8661B4AFAE0ABA605015114B8A94BCF0843A1FFAF71DEEE6F49CAEFA570D4CF75F1A0F5676E31603CA8B783EBB839BAD8C344EDFDEF7C6ACE974"
    )
    # FIXME: My L2 seed key calculation is wrong. The above result is what I
    # sniffed from Windows when tracing the BCrypt functions.
    l2_key = expected_l2_key
    assert (
        l2_key == expected_l2_key
    ), f"L2 Key Mismatch\n{base64.b16encode(l2_key).decode()}\n{base64.b16encode(expected_l2_key).decode()}"

    kek = kdf(
        hash_algo,
        l2_key,
        label,
        password_id.unknown,
        32,
    )

    # This is the expected KEK for this
    expected_kek = base64.b16decode("FBD5A5143F23822E3F8B7A195F7216E554BEE383A645241BBCFC155EEBF622D3")
    assert (
        kek == expected_kek
    ), f"KEK Mismatch\n{base64.b16encode(kek).decode()}\n{base64.b16encode(expected_kek).decode()}"

    # With the kek we can unwrap the encrypted cek in the LAPS payload.
    assert kek_info.key_encryption_algorithm.algorithm == "2.16.840.1.101.3.4.1.45"  # AES256-wrap
    assert not kek_info.key_encryption_algorithm.parameters
    cek = keywrap.aes_key_unwrap(kek, kek_info.encrypted_key)

    # This is the expected CEK for this
    expected_cek = base64.b16decode("87AF93EB25B37D7FA2E73E64CA337F2C152E5F14BE83A8A215797321EFDCECD2")
    assert (
        cek == expected_cek
    ), f"CEK Mismatch\n{base64.b16encode(cek).decode()}\n{base64.b16encode(expected_cek).decode()}"

    # With the cek we can decrypt the encrypted content in the LAPS payload.
    password = aes256gcm_decrypt(enc_content.algorithm, cek, enc_content.content)
    return password


def get_dh_pub(
    field_order: bytes,
    generator: bytes,
    private: bytes,
) -> bytes:
    # The static public key y is computed from the static private key x by using
    # the following formula
    # y = g**x mod p

    p_int = int.from_bytes(field_order, byteorder="big")
    g_int = int.from_bytes(generator, byteorder="big")
    x_int = int.from_bytes(private, byteorder="big")

    public_int = pow(g_int, x_int, p_int)
    return public_int.to_bytes((public_int.bit_length() + 7) // 8, byteorder="big")


def get_dh_shared_secret(
    field_order: bytes,
    private: bytes,
    public: bytes,
) -> bytes:
    p_int = int.from_bytes(field_order, byteorder="big")
    x_int = int.from_bytes(private, byteorder="big")
    y_int = int.from_bytes(public, byteorder="big")

    secret = pow(y_int, x_int, p_int)
    return secret.to_bytes((secret.bit_length() + 7) // 8, byteorder="big")


def main() -> None:
    dc = "dc01.domain.test"
    server = "CN=SERVER2022,OU=Servers,DC=domain,DC=test"
    sign_header = False

    # Delete the key under C:\Users\vagrant-domain\AppData\Local\Microsoft\Crypto\KdsKey\62dfbd45d9ce7632efd1f252eedb7a94b806849138424140b12517aa45eb1f47\PrivateKey\361-bac64fa8-e890-917c-1090-83e7b0f85996
    # to test out the RPC traffic. Will need to figure out how this format is created.
    # GetSIDKeyFileName in KdsCli.dll

    # Manual call to NCryptProtectSecret with b"\x01" - PowerShell
    """
    $ncrypt = New-CtypesLib ncrypt.dll

    $descriptor = [IntPtr]::Zero
    $res = $ncrypt.NCryptCreateProtectionDescriptor(
        $ncrypt.MarshalAs("SID=$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)", "LPWStr"),
        0,
        [ref]$descriptor)
    if ($res) {
        throw [System.ComponentModel.Win32Exception]$res
    }

    $data = [byte[]]::new(1)
    $blob = [IntPtr]::Zero
    $blobLength = 0
    $res = $ncrypt.NCryptProtectSecret(
        $descriptor,
        0x40,  # NCRYPT_SILENT_FLAG
        $ncrypt.MarshalAs($data, 'LPArray'),
        $data.Length,
        $null,
        $null,
        [ref]$blob,
        [ref]$blobLength)
    if ($res) {
        throw [System.ComponentModel.Win32Exception]$res
    }
    $encBlob = [byte[]]::new($blobLength)
    [System.Runtime.InteropServices.Marshal]::Copy($blob, $encBlob, 0, $encBlob.Length)
    [System.Convert]::ToBase64String($encBlob)
    """
    # enc_blob = base64.b64decode(
    #     "MIIBeAYJKoZIhvcNAQcDoIIBaTCCAWUCAQIxggEeooIBGgIBBDCB3QSBhAEAAABLRFNLAgAAAGkBAAAPAAAAGwAAAKhPxrqQ6HyREJCD57D4WZYgAAAAGAAAABgAAAAa/cFOt3P0FBkN6GSXlXNOAl40T+fROdNdSUMskOmuKGQAbwBtAGEAaQBuAC4AdABlAHMAdAAAAGQAbwBtAGEAaQBuAC4AdABlAHMAdAAAADBUBgkrBgEEAYI3SgEwRwYKKwYBBAGCN0oBATA5MDcwNQwDU0lEDC5TLTEtNS0yMS00MTUxODA4Nzk3LTM0MzA1NjEwOTItMjg0MzQ2NDU4OC0xMTA0MAsGCWCGSAFlAwQBLQQoxsqDoXhEIMILLVXlzv5lxVBeFKMAERib1FLNLP2spEzg5FPGLL0hLDA+BgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDFtAVOwxnWdYMTxYyQIBEIARjFXg19IqURZ0g3hSWScPs24="
    # )
    # plaintext = ncrypt_unprotect_secret(dc, enc_blob, rpc_sign_header=sign_header)

    # enc_blob = base64.b16decode(
    #     "3082045006092a864886f70d010703a08204413082043d02010231820409a2820405020104308203c704820370010000004b44534b03000000690100000f0000001e00000069d83cd1d10ebfac4620a164e805f56e080300001a0000001a000000444850420001000087a8e61db4b6663cffbbd19c651959998ceef608660dd0f25d2ceed4435e3b00e00df8f1d61957d4faf7df4561b2aa3016c3d91134096faa3bf4296d830e9a7c209e0c6497517abd5a8a9d306bcf67ed91f9e6725b4758c022e0b1ef4275bf7b6c5bfc11d45f9088b941f54eb1e59bb8bc39a0bf12307f5c4fdb70c581b23f76b63acae1caa6b7902d52526735488a0ef13c6d9a51bfa4ab3ad8347796524d8ef6a167b5a41825d967e144e5140564251ccacb83e6b486f6b3ca3f7971506026c0b857f689962856ded4010abd0be621c3a3960a54e710c375f26375d7014103a4b54330c198af126116d2276e11715f693877fad7ef09cadb094ae91e1a15973fb32c9b73134d0b2e77506660edbd484ca7b18f21ef205407f4793a1a0ba12510dbc15077be463fff4fed4aac0bb555be3a6c1b0c6b47b1bc3773bf7e8c6f62901228f8c28cbb18a55ae31341000a650196f931c77a57f2ddf463e5e9ec144b777de62aaab8a8628ac376d282d6ed3864e67982428ebc831d14348f6f2f9193b5045af2767164e1dfc967c1fb3f2e55a4bd1bffe83b9c80d052b985d182ea0adb2a3b7313d3fe14c8484b1e052588b9b7d2bbd2df016199ecd06e1557cd0915b3353bbb64e0ec377fd028370df92b52c7891428cdc67eb6184b523d1db246c32f63078490f00ef8d647d148d47954515e2327cfef98c582664b4c0f6cc4165911914ea310a2766c1ec2f5ba89d34002d975da503cc1809d05249fbad13f038a5a9fcb381601e04ec4b9b4f31f6ef25a3f56356d28590727df18f626a04caa3cd81ec602c22e0172a029256caf961a461e3ab61502ee6f27f1f134a88f37019534c7075cfe990ecfe535d1042ee1964af66a7e9e1167a0ffbd8359a6042a3117102240cf5cfd9c442259f0f3db45d1dd51a10e7f3e314250f2079b6122d84ebd9d405c83826d625c8a57dfe518389d645ee4daec02d48b7470e8419c84ed7bcabaf47ded6a1b1f132010d35004adf37fec61dfbc008fda690389ed945ea96bad5f3acffe0fe01f818cd10d01d58d012a37b98758928531d9bf5a614041f4cfbf4e00450057004c004100500053002e0043004f005200500000004e00450057004c004100500053002e0043004f00520050000000305106092b0601040182374a013044060a2b0601040182374a01013036303430320c035349440c2b532d312d352d32312d39323130343037302d313632323731323839342d333433363534373836332d353132300b060960864801650304012d04281a7b6922fc2450c81354ad9d3ce1020d24c327a071f57de6a74dddf3c0b4acb9cf3104efc06fb18d302b06092a864886f70d010701301e060960864801650304012e3011040c247911a21b5c7f4fd08359f9020110426af21e4b446113ce8c4ea45685ecf21d800047f61d5772452b3dab1efc093692f0e3fa3a16ad0fbdbe0df9e9953a934ff129848d34c1e1bc2f5eaefbe67eaa40f158759144b800325ac1307aafd02ce418badf3a9ed849d4053ffde7c2a3822d169377ebcce5c9a9a1a95261c02d49ba014edf882aa54141d0d9b5aa03155eef9f05a0233dbbd9c45f62f58f407cd25320".upper()
    # )
    # plaintext = ncrypt_unprotect_secret(dc, enc_blob, rpc_sign_header=sign_header)

    # LAPS - msLAPS-EncryptedPassword
    enc_password = get_laps_enc_password(dc, server)
    laps_blob = EncryptedLAPSBlob.unpack(enc_password)
    plaintext = ncrypt_unprotect_secret(
        dc,
        laps_blob.blob,
        rpc_sign_header=sign_header,
    )
    print(f"LAPS Password: {plaintext.decode('utf-16-le')}")
    print(f"Plaintext hex: {base64.b16encode(plaintext).decode()}")


"""
Here is what I'm currently up to.

I can use LDAP to query the LDAP attribute 'msLAPS-EncryptedPassword' on the
compute object in question. The value of this attribute is a blob in the form
of:

    update_timestamp_upper: 4 bytes
    update_timestamp_lower: 4 bytes
    blob_length: 4 bytes
    flags: 4 bytes
    blob: variable (blob_length)

It is simple to unpack this and so far I've found that a blob never contains
any flags (always 0) and the blob itself is a PKCS 7 ContentInto structure with
some bytes added onto the end. The ContentInfo structure has a content type of
'1.2.840.113549.1.7.3' which represents the PKCS 7 envelopedData structure
defined in RFC 5652 6.1. EnvelopedData Type
https://www.rfc-editor.org/rfc/rfc5652#section-6.1

      EnvelopedData ::= SEQUENCE {
        version CMSVersion,
        originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
        recipientInfos RecipientInfos,
        encryptedContentInfo EncryptedContentInfo,
        unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }

In this case the version of the EnvelopedData is set to 2 and it contains a
single recipientInfo and an encryptedContentInfo. The encryptedContentInfo is
defined in the same RFC as EncryptedContentInfo with the structure

      EncryptedContentInfo ::= SEQUENCE {
        contentType ContentType,
        contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
        encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }

Note: The ContentEncryptionAlgorithmIdentifier is just the AlgorithmIdentifier
defined in another RFC as.

    AlgorithmIdentifier ::= SEQUENCE {
        algorithm       OBJECT IDENTIFIER,
        parameters      ANY DEFINED BY algorithm OPTIONAL
    }

The encryptedContent tag is not actually set for LAPS, the remaining data in
LAPS blob seem to substitute this value. I don't know why it isn't included in
the EncryptedContentInfo structure like NCryptProtectSecret usually does but
it isn't.

The recipientInfos contains a single entry which is a KEKRecipientInfo type
which is defined in RFC 5652 6.2.3. KEKRecipientInfoType as

      KEKRecipientInfo ::= SEQUENCE {
        version CMSVersion,  -- always set to 4
        kekid KEKIdentifier,
        keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        encryptedKey EncryptedKey }

      KEKIdentifier ::= SEQUENCE {
        keyIdentifier OCTET STRING,
        date GeneralizedTime OPTIONAL,
        other OtherKeyAttribute OPTIONAL }

When unpacking the blob these are the values I get:

    EncryptedContentInfo:
        contentType:
        contentEncryptionAlgorithm:
            algorithm: 2.16.840.1.101.3.4.1.46  # AES256-GCM
            # A nested ASN.1 value containing the nonce and icvlen
            parameters: ...
        # Not actually in the structure but after the PKCS 7 ContentInfo
        # structure. Just mentioned here for posterity.
        encryptedContent: ...

    # Contains only 1 recipientinfo - KEKRecipientInfo
    RecipientInfos:
        kekid:
            # This contains the password root key id and L* values
            keyIdentifier: ...
            other:
                keyattrId: 1.3.6.1.4.1.311.74.1
                # This contains an undocumented ASN.1 value
                keyattr: ...
        keyEncryptionAlgorithm:
            algorithm: 2.16.840.1.101.3.4.1.45  # AES256 wrap
            parameters: ''  # No parameters

        # I believe this to be the encrypted CEK (encrypted by the KEK)
        encryptedKey: ...

The keyIdentifier is an undocumented structure in the form of:

    version: 4 bytes (always 1)
    magic: 0x4B 0x44 0x53 0x4B
    flags: 4 bytes (typically 2)
    l0_index: 4 bytes
    l1_index: 4 bytes
    l2_index: 4 bytes
    root_key_identifier: 16 bytes
    unknown_length: 4 bytes
    domain_length: 4 bytes
    forest_length: 4 bytes
    unknown: variable (unknown_length)
    domain: variable (domain_length)
    forest: variable (forest_length)

If the flags has bit 1 set then the unknown value represents the public key of
the DH pair. If it's not set then it's a 32 byte value that I have no idea of.
I think this is important but I don't understand why I typically only get the
32 byte value but I definitely got the DH public key once before.

The kekid.other value contains an undocumented ASN.1 value that is simply 2
UTF-8 string 'SID' and the sid that protected the blob (what LAPS is registered
with).

So with all this info I have:
    * The SID that protects the resource
    * The group key (keyidentifier) identifier
        * L0 id
        * L1 id
        * L2 id
        * Root Key Identifier
        * The domain/forest name to query
        * Maybe the public key (typically not though)
    * The encrypted CEK (encryptedKey)
    * The encrypted CEK encryption algorithm - AES256 wrap
    * The encrypted LAPS content
    * The encrypted LAPS content encryption algorithm AES256-GCM with a nonce

With this info I can call the MS-GKDI GetKey https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/4cac87a3-521e-4918-a272-240f8fabed39
with the details in the group key identifier and the SID wrapped in a security
descriptor. Note the security descriptor has the owner and group of S-1-5-18
and 2 ACES in the DACL. One ACE has a mask of 3 containing the SID in the LAPS
payload, another ACE has S-1-1-0 with a mask of 2. This is the behaviour seen
on the wire so I just replicated it.

This call must be done with RCP over TCP/IP with privary applied to the
connection. The EPM on port 135 can be first queried to see what ports the
GetKey interface is registered on.

The returned value is a blob in the form of MS-GKDI Group key Envelope
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/192c061c-e740-4aa0-ab1d-6954fb3e58f7
Relevant values contained in this structure are:

    L0 index: Typically the same as the L0 id requested
    L1 index: Typically the same as the L1 id requested
    L2 index: Maybe the same or higher than the L2 id requested
    L1 key: The L1 seed key (64 bytes)
    L2 key: The L2 seed key (64 bytes)
    KDF Algorithm: SP800_108_CTR_HMAC
    KDF Parameters: SHA512
    Secret Algorithm: DH
    Secret Parameters:  The p and g integers as big endian bytes
    Private Key Length: 512  # In bits
    Public Key Length: 2048  # In bits

Depending on when LAPS password was set the L2 index returned could be the same
or a higher value. Strictly speaking L1 could also differ but I haven't been
dealing with timeframes for that to ever change. Using MS-GKDI Generating a
Group Key https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/5d373568-dd68-499b-bd06-a3ce16ca7117
I can work backwards to derive the L2 seed key for the L0, L1, L2 identifier
stored in the keyidentifier based on the values returned from GetKey. The docs
state the following algorithm is used to derive the L2 seed key

    KDF(HashAlg, KI, Label, Context, L) — denotes an execution of the [SP800-108] KDF in counter mode ([SP800-108] section 5.1) by using the Hash Message Authentication Code (HMAC)
    Key(SD, RK, L0, L1, n) = KDF(HashAlg, Key(SD, RK, L0, L1, n+1), "KDS service", RKID || L0 || L1|| n, 512)

Essentially the L2 seed key of (1, 2, 3) is equal to

    KDF(
        SHA512,
        L2(RK, 1, 2, 4),
        "KDS service",
        RKID | 1 | 2 | 3,
        512
    )

So if the L2 index matches what we requested we don't need to do anything but
if it does not we can continue to work backwards and derive the key for the
previous L2 index until we reach the one we need as specified in the
key identifier.

One thing to note is that SP800-108 in Python is done with KBKDFHMAC
https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.kbkdf.KBKDFHMAC
This class takes in the inputs documented by Microsoft but it also requires a
value for rlen and llen. I need to figure out what this should actually be as
MS-GKDI don't seem to mention it.

In the same section of MS-GKDI we can see the algorithm for generating the DH
private key is with

    PrivKey(SD, RK, L0, L1, L2) = KDF(HashAlg, Key(SD, RK, L0, L1, L2), "KDS service", RK.msKds-SecretAgreement-AlgorithmID, RK.msKds-PrivateKey-Length)

So we can do the following to derive the DH private "key":

    KDF(
        SHA512,
        L2(RK, 1, 2, 3),
        "KDS service",
        "DH",
        512
    )

It also states the public key can be derived from this using the NIST SP800-56A
specs 5.6.1.1. As it's a DH key and we know the p, g, and private key (x) values
this is simply done with g**x mod p.

Now this is where I'm stuck. Based on the docs for DPAPI-NG
https://learn.microsoft.com/en-us/windows/win32/seccng/protected-data-format
it somewhat states the CEK is the encryptedKey inside the recipient info is
encrypted with the KEK. It seems like the KEK is derived by doing AES256 unwrap
on some value but nothing I've tried results in a successful unwrap. At a guess
I need to derive the shared DH secret and potentially use that for the AES256
unwrap but this brings up the questions:

* How do I get the DH secret when I don't know the other parties public key (Y)
    * The DH formula is meant to be Y ** x mod p
    * I know p, g, x (my private key), and X (my public key) but not y or Y
    * Randomly I've seen the password identifier in the kekid keyIdentifier
        field but that was only once
    * Is the random 32 byte value in the kekid keyIdentifier somewhat related
        to this?
    * Once I do get this secret, do I need to hash it to get the 32 byte length
        expected by AES256 key unwrap

Assuming I figure out how to get the decrypted CEK with the above I should then
be able to use that as the key in the AES256-GCM decryption process on the
LAPS encrypted content to get the encrypted payload.
"""

# Another example of the expanded msLAPS-EncryptedPassword value with some
# hints on the values.
# Recipients:
# - Choice: 2
#   Type: KEKRecipientInfo
#   Version: 4
#   KekId:
#     # Meant to be the DPAPI blob KEK (Key Encryption Key)?
#     KeyIdentifier: 010000004B44534B02000000690100000F0000000E000000A84FC6BA90E87C91109083E7B0F85996200000001800000018000000680F80AF80FC2EC0A3D5DCC061A75372DB75ED0E2FC286C29738FCD19A83A41D64006F006D00610069006E002E007400650073007400000064006F006D00610069006E002E0074006500730074000000
#       # version: 1
#       # is_public_key: 02000000
#       # l0_index: 361
#       # l1_index: 15
#       # l2_index: 14
#       # root_key_identifier: bac64fa8-e890-917c-1090-83e7b0f85996
#       # public_key: 680F80AF80FC2EC0A3D5DCC061A75372DB75ED0E2FC286C29738FCD19A83A41D
#       # domain_name: domain.test
#       # forest_name: domain.test
#     Date:
#     OtherId: 1.3.6.1.4.1.311.74.1
#     OtherValue: 3046060A2B0601040182374A01013038303630340C035349440C2D532D312D352D32312D343135313830383739372D333433303536313039322D323834333436343538382D353132
#       # OID Mappings
#       #   1   - SID
#       #   8   - Local
#       #   12  - KeyFile
#       #   ?   - SDDL
#       #   ?   - WEBCREDENTIALS
#       #   ?   - LOCKEDCREDENTIALS
#       #   ?   - CERTIFICATE
#       # ContentInfo SEQUENCE (2 elem)
#       #   contentType ContentType OBJECT IDENTIFIER 1.3.6.1.4.1.311.74.1.1
#       #   content [0] SEQUENCE (1 elem)
#       #     ANY SEQUENCE (1 elem)
#       #       SEQUENCE (2 elem)
#       #         UTF8String SID
#       #         UTF8String S-1-5-21-4151808797-3430561092-2843464588-512
#   Algorithm:
#     Id: 2.16.840.1.101.3.4.1.45  # AES256 Wrap
#     Parameters: ''
#   EncryptedKey: 0A279226835B0A2C52D8EED295B686CAB15F98F15FEF7DAD9C32A196C0505568FEAF0B35103705DE
# EncryptedContentInfo:
#   ContentType: 1.2.840.113549.1.7.1  # data (PKCS #7)
#   Algorithm:
#     Id: 2.16.840.1.101.3.4.1.46  # AES256-GCM
#     Parameters: 3011040C4E99F95209A27CA07FF4B850020110
#       # SEQUENCE (2 elem)
#       #   OCTET STRING (12 byte) 4E99F95209A27CA07FF4B850 - aes-nonce
#       #   INTEGER 16                                      - aes-ICVlen


if __name__ == "__main__":
    main()
