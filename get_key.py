import base64
import dataclasses
import re
import socket
import struct
import typing as t
import uuid

import gssapi
import gssapi.raw
import spnego

import sansldap
from sansldap._pkcs7 import (
    ContentInfo,
    EnvelopedData,
    KEKRecipientInfo,
    GroupKeyEnvelope,
    ManagedPasswordId,
    NCryptProtectionDescriptor,
)

ISD_KEY = uuid.UUID("b9785960-524f-11df-8b6d-83dcded72085")
NDR = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")
NDR64 = uuid.UUID("71710533-beba-4937-8319-b5dbef9ccc36")


@dataclasses.dataclass(frozen=True)
class SecTrailer:
    type: int
    level: int
    pad_length: int
    context_id: int
    data: bytes


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
    service_id: uuid.UUID,
    version_major: int,
    version_minor: int,
    token: bytes,
    sign_header: bool = False,
) -> bytes:
    bind_negotiation = uuid.UUID("6cb71c2c-9812-4540-0300-000000000000")

    ctx1 = b"\x00\x00\x01\x00"
    ctx1 += service_id.bytes_le
    ctx1 += struct.pack("<H", version_major)
    ctx1 += struct.pack("<H", version_minor)
    ctx1 += NDR.bytes_le + b"\x02\x00\x00\x00"

    ctx2 = b"\x01\x00\x01\x00"
    ctx2 += service_id.bytes_le
    ctx2 += struct.pack("<H", version_major)
    ctx2 += struct.pack("<H", version_minor)
    ctx2 += NDR64.bytes_le + b"\x01\x00\x00\x00"

    ctx3 = b"\x02\x00\x01\x00"
    ctx3 += service_id.bytes_le + b"\x01\x00\x00\x00"
    ctx3 += bind_negotiation.bytes_le + b"\x01\x00\x00\x00"

    bind_data = bytearray()
    bind_data += b"\xd0\x16"  # Max Xmit Frag
    bind_data += b"\xd0\x16"  # Max Recv Frag
    bind_data += b"\x00\x00\x00\x00"  # Assoc Group
    bind_data += b"\x03\x00\x00\x00"  # Num context items
    bind_data += ctx1 + ctx2 + ctx3

    auth_data = SecTrailer(
        type=9,  # SPNEGO
        level=6,  # Packet Privacy
        pad_length=0,
        context_id=0,
        data=token,
    )

    return create_pdu(
        packet_type=11,
        packet_flags=0x03 | (0x4 if sign_header else 0x0),
        call_id=1,
        header_data=bytes(bind_data),
        sec_trailer=auth_data,
    )


def create_alter_context(
    service_id: uuid.UUID,
    version_major: int,
    version_minor: int,
    token: bytes,
    sign_header: bool = False,
) -> bytes:
    ctx1 = b"\x01\x00\x01\x00"
    ctx1 += service_id.bytes_le
    ctx1 += struct.pack("<H", version_major)
    ctx1 += struct.pack("<H", version_minor)
    ctx1 += NDR64.bytes_le + b"\x01\x00\x00\x00"

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
    ctx: gssapi.SecurityContext,
    sign_header: bool = False,
) -> bytes:
    # Add Verification trailer to data
    # MS-RPCE 2.2.2.13 Veritifcation Trailer
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/0e9fea61-1bff-4478-9bfe-a3b6d8b64ac3
    pcontext = bytearray()
    pcontext += ISD_KEY.bytes_le
    pcontext += struct.pack("<I", 1)  # ISD_KEY version
    pcontext += NDR64.bytes_le
    pcontext += struct.pack("<I", 1)

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

    request_data = bytearray()
    request_data += struct.pack("<I", alloc_hint)
    request_data += struct.pack("<H", 1)  # Context id
    request_data += struct.pack("<H", opnum)

    if sign_header:
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

    else:
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

        return create_pdu(
            packet_type=0,
            packet_flags=0x03,
            call_id=1,
            header_data=bytes(request_data),
            stub_data=iov_buffers[1].value,
            sec_trailer=sec_trailer,
        )


def create_get_key_request(
    target: str,
    root_key_id: uuid.UUID,
    l0: int,
    l1: int,
    l2: int,
) -> bytes:
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

    # First need to build the target security descriptor from the SID passed
    # in. This SD contains an ACE per target user with a mask of 0x3 and a
    # final ACE of the current user with a mask of 0x2. When viewing this over
    # the wire the current user is set as S-1-1-0 (World) and the owner/group
    # is S-1-5-18 (SYSTEM).
    target_sd = sd_to_bytes(
        owner="S-1-5-18",
        group="S-1-5-18",
        dacl=[ace_to_bytes(target, 3), ace_to_bytes("S-1-1-0", 2)],
    )
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

    return bytes(data)


def get_fault_pdu_error(data: memoryview) -> int:
    status = struct.unpack("<I", data[24:28])[0]

    return status


def parse_bind_ack(data: bytes) -> bytes:
    view = memoryview(data)

    pkt_type = struct.unpack("B", view[2:3])[0]
    if pkt_type == 3:
        err = get_fault_pdu_error(view)
        raise Exception(f"Receive Fault PDU: 0x{err:08X}")

    assert pkt_type == 12

    auth_length = struct.unpack("<H", view[10:12])[0]
    auth_blob = view[-auth_length:].tobytes()

    return auth_blob


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
    ctx: gssapi.SecurityContext,
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
    auth_data = view[-(auth_length + 8) :]
    stub_data = view[24 : len(view) - (auth_length + 8)]

    padding = struct.unpack("B", auth_data[2:3])[0]

    if sign_header:
        raise NotImplementedError()

    else:
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


def extract_enc_password_details(data: bytes) -> t.Tuple[str, uuid.UUID, int, int, int]:
    ci = ContentInfo.unpack(data[16:])
    assert ci.content_type == EnvelopedData.content_type

    enveloped_data = EnvelopedData.unpack(ci.content)
    assert len(enveloped_data.recipient_infos) == 1
    assert isinstance(enveloped_data.recipient_infos[0], KEKRecipientInfo)
    assert enveloped_data.recipient_infos[0].kekid.other is not None
    assert enveloped_data.recipient_infos[0].kekid.other.key_attr_id == "1.3.6.1.4.1.311.74.1"
    protection_descriptor = NCryptProtectionDescriptor.unpack(
        enveloped_data.recipient_infos[0].kekid.other.key_attr or b""
    )
    assert protection_descriptor.content_type == "1.3.6.1.4.1.311.74.1.1"

    password_id = ManagedPasswordId.unpack(enveloped_data.recipient_infos[0].kekid.key_identifier)
    return (
        protection_descriptor.value,
        password_id.root_key_identifier,
        password_id.l0,
        password_id.l1,
        password_id.l2,
    )


def main() -> None:
    dc = "dc01.domain.test"
    server = "CN=SERVER2022,OU=Servers,DC=domain,DC=test"
    sign_header = False

    enc_password = get_laps_enc_password(dc, server)
    target_sid, root_key_id, l0, l1, l2 = extract_enc_password_details(enc_password)

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

    # TODO: Use EPM to find the dynamic port for this service.
    with socket.create_connection((dc, 49672)) as s:
        bind_data = create_bind(
            ISD_KEY,
            1,
            0,
            out_token,
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
            1,
            0,
            out_token,
            sign_header=sign_header,
        )
        s.sendall(alter_context)
        resp = s.recv(4096)
        in_token = parse_alter_context(resp)

        out_token = ctx.step(in_token)
        assert ctx.complete
        assert not out_token
        # FUTURE: Deal with a no header signing.from server

        get_key_req = create_get_key_request(target_sid, root_key_id, l0, l1, l2)
        request = create_request(
            0,
            get_key_req,
            ctx,
            sign_header=sign_header,
        )
        s.sendall(request)
        resp = s.recv(4096)

        create_key_resp = parse_response(resp, ctx, sign_header=sign_header)
        key = parse_create_key_response(create_key_resp)


if __name__ == "__main__":
    main()
