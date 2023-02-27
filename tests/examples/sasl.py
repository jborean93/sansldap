# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum
import ssl
import struct
import typing as t

import spnego
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


class SaslSecurityFlags(enum.IntFlag):
    """SASL flags used during SSF negotiation."""

    NONE = 0
    NO_SECURITY = 1
    INTEGRITY = 2
    CONFIDENTIALITY = 4


class SaslProvider:
    @property
    def mechanism(self) -> str:
        """The SASL mechanism name."""
        raise NotImplementedError()

    def step(
        self,
        in_token: t.Optional[bytes] = None,
        *,
        tls_channel: t.Optional[ssl.SSLObject] = None,
    ) -> t.Optional[bytes]:
        """Perform a SASL token exchange.

        Performs a token exchange with the SASL provider and returns the token
        to send to the server.

        Args:
            in_token: The input token from the server if any have been provided.
            tls_channel: The SSLObject the LDAP connection is using for LDAPS
                or StartTLS. This is None if no TLS is used.

        Returns:
            Optional[bytes]: The token to send back to the server in the
            BindRequest. None is returned when no token is left to exchange and
            the provider is set up. Note that b"" is treated as a token to
            send.
        """
        raise NotImplementedError()

    def wrap(
        self,
        data: bytes,
    ) -> bytes:
        """Wraps the data.

        Wraps (signs or encrypts) the data to send to the peer using the SASL
        context. If signing or encryption wasn't requested then the same data
        is returned.

        Args:
            data: The data to wrap.

        Returns:
            bytes: The wrapped data.
        """
        return data

    def unwrap(
        self,
        data: bytes,
    ) -> t.Tuple[bytes, int]:
        """Unwraps the data.

        Unwraps (verifies or decrypts) the data received from the peer using
        the SASL context. If signing or encryption wasn't requested then the
        same data is returned.

        Args:
            data: The data to unwrap.

        Returns:
            Tuple[bytes, int]: The unwrapped data and the length of the input
            data that was consumed.
        """
        return data, len(data)


class External(SaslProvider):
    """The SASL EXTERNAL Provider.

    This provider is used to signify an external channel is used to
    authenticate the client. An example would be TLS client authentication
    where the client certificate presented during the TLS handshake is used to
    authenticate the client. This should only be used with a StartTLS bound
    connection. Using LDAPS will automatically be bound to the user supplied
    certificate in the TLS handshake.
    """

    def __init__(self) -> None:
        self._complete = False

    @property
    def mechanism(self) -> str:
        return "EXTERNAL"

    def step(
        self,
        in_token: t.Optional[bytes] = None,
        *,
        tls_channel: t.Optional[ssl.SSLObject] = None,
    ) -> t.Optional[bytes]:
        # Needs to return b"" on the first call only.
        if self._complete:
            return None
        else:
            self._complete = True
            return b""


class Gssapi(SaslProvider):
    """The SASL GSSAPI Provider.

    This provider is used for Kerberos authentication through GSSAPI or SSPI.
    Unlike :class:`GssSpnego` it only supports Kerberos authentication and not
    Negotiate (Kerberos with NTLM fallback). It also requires up to 2 extra
    network roundtrips to complete the exchange due to the SSF negotiation that
    occurs after the user is authenticated.

    If no username or password is specified, the current user is used during
    authentication. For Linux this only works if a ticket has been retrieved
    using a tool like kinit and the current cache is accessible. If only the
    username is supplied, a ticket for that principal will be used if available.

    It is recommended to use :class:`GssSpnego` instead of this due to the
    reduced network traffic required and ability to negotiate the
    authentication protocol.

    Note:
        When communicating with a Microsoft Active Directory LDAP server over
        LDAPS or with StartTLS, you much specify sign=False and encrypt=False.
        MS AD does not support signatures and encryption inside the TLS
        channel.

    Args:
        username: The username to authenticate with.
        password: The password to authenticate with.
        hostname: The LDAP server name used to build the SPN.
        service: The LDAP service used to build the SPN, defaults to ldap.
        sign: Whether to sign the data when wrapping it.
        encrypt: Whether to encrypt the data when wrapping it, this implies
            sign as well.
    """

    def __init__(
        self,
        username: t.Optional[str] = None,
        password: t.Optional[str] = None,
        hostname: str = "unspecified",
        service: str = "ldap",
        sign: bool = True,
        encrypt: bool = True,
    ) -> None:
        self.sign = sign
        self.encrypt = encrypt
        self.context = spnego.client(
            username=username,
            password=password,
            hostname=hostname,
            service=service,
            protocol="kerberos",
        )
        self.ssf_negotiated = False

    @property
    def mechanism(self) -> str:
        return "GSSAPI"

    def step(
        self,
        in_token: t.Optional[bytes] = None,
        *,
        tls_channel: t.Optional[ssl.SSLObject] = None,
    ) -> t.Optional[bytes]:
        if not self.context.complete:
            cbt = _get_tls_channel_bindings(tls_channel)
            out_token = self.context.step(in_token=in_token, channel_bindings=cbt)

            # If the context was complete in this call the out_token won't be
            # present. This starts the SSF negotiation phase where the client
            # sends an empty token and waits for the server response
            return out_token or b""

        elif self.ssf_negotiated:
            return None

        # Once the context is set up, the client expects a signed payload from
        # the server.
        if not in_token:
            raise Exception("Expecting input token to verify server security context with SASL SSF")

        unwrapped_token = self.context.unwrap(in_token).data
        if len(unwrapped_token) != 4:
            raise Exception("Input token for SASL SSF negotiation was not the expected size")

        # The bytes are big endianed ordered, the first byte is the server flags
        # indicating the signing/encryption capabilities and the subsequent
        # bytes are the max server message length.
        context_info = struct.unpack(">I", unwrapped_token)[0]
        server_flags = SaslSecurityFlags((context_info & 0xFF000000) >> 24)
        max_server_message_length = context_info & 0x00FFFFFF

        if server_flags == SaslSecurityFlags.NO_SECURITY and max_server_message_length != 0:
            raise Exception(
                f"Server did not respond with 0 for the server message length but was {max_server_message_length}"
            )

        client_flags = SaslSecurityFlags.NO_SECURITY
        if self.sign:
            client_flags |= SaslSecurityFlags.INTEGRITY

        if self.encrypt:
            client_flags |= SaslSecurityFlags.INTEGRITY | SaslSecurityFlags.CONFIDENTIALITY

        max_client_wrap_length = 0
        if client_flags != SaslSecurityFlags.NO_SECURITY:
            # Should call gss_wrap_size_limit on Linux. Windows does not have
            # this so return the server value.
            max_client_wrap_length = max_server_message_length

        client_context_info = max_client_wrap_length | (client_flags.value << 24)
        raw_ci = client_context_info.to_bytes(4, byteorder="big")

        self.ssf_negotiated = True
        return self.context.wrap(raw_ci, encrypt=False).data

    def wrap(
        self,
        data: bytes,
    ) -> bytes:
        if self.context is None or not self.context.complete:
            raise Exception("Cannot wrap without a completed context")

        elif not self.sign and not self.encrypt:
            return data

        wrapped_data = self.context.wrap(data, encrypt=self.encrypt).data
        return len(wrapped_data).to_bytes(4, byteorder="big") + wrapped_data

    def unwrap(
        self,
        data: bytes,
    ) -> t.Tuple[bytes, int]:
        if self.context is None or not self.context.complete:
            raise Exception("Cannot unwrap without a completed context")

        elif not self.sign and not self.encrypt:
            return data, len(data)

        data_view = memoryview(data)
        data_len = struct.unpack(">I", data_view[:4])[0]
        data_view = data_view[4:]
        if len(data_view) < data_len:
            return b"", 0

        data_view = data_view[:data_len]

        return self.context.unwrap(data_view.tobytes()).data, data_len + 4


class GssSpnego(SaslProvider):
    """The SASL GSS-SPNEGO Provider.

    This is a special SASL provider used by Microsoft Active Directory
    implementations. It is designed to be more efficient than :class:`Gssapi`
    by removing the extra SSF negotiation tokens and support the Negotiate
    protocol.

    If no username or password is specified, the current user is used during
    authentication. For Linux this only works if a ticket has been retrieved
    using a tool like kinit and the current cache is accessible. If only the
    username is supplied, a ticket for that principal will be used if available.

    Note:
        When communicating with a Microsoft Active Directory LDAP server over
        LDAPS or with StartTLS, you much specify sign=False and encrypt=False.
        MS AD does not support signatures and encryption inside the TLS
        channel.

    Args:
        username: The username to authenticate with.
        password: The password to authenticate with.
        protocol: The underlying authentication protocol to use, default to
            negotiate.
        hostname: The LDAP server name used to build the SPN.
        service: The LDAP service used to build the SPN, defaults to ldap.
        sign: Whether to sign the data when wrapping it.
        encrypt: Whether to encrypt the data when wrapping it, this implies
            sign as well.
    """

    def __init__(
        self,
        username: t.Optional[str] = None,
        password: t.Optional[str] = None,
        protocol: str = "negotiate",
        hostname: str = "unspecified",
        service: str = "ldap",
        sign: bool = True,
        encrypt: bool = True,
    ) -> None:
        self.sign = sign
        self.encrypt = encrypt

        context_req = spnego.ContextReq.mutual_auth
        if self.sign:
            context_req |= spnego.ContextReq.integrity | spnego.ContextReq.sequence_detect

        if self.encrypt:
            context_req |= (
                spnego.ContextReq.integrity | spnego.ContextReq.sequence_detect | spnego.ContextReq.confidentiality
            )

        if not self.sign and not self.encrypt:
            # GSS-SPNEGO relies on the context attributes to negotiate the
            # SASL SSF. As Kerberos by default always uses the integrity
            # attributes we need to tell it explicitly not to use integrity
            # for this use case.
            context_req |= spnego.ContextReq.no_integrity

        self.context = spnego.client(
            username=username,
            password=password,
            hostname=hostname,
            service=service,
            protocol=protocol,
            context_req=context_req,
        )

    @property
    def mechanism(self) -> str:
        return "GSS-SPNEGO"

    def step(
        self,
        in_token: t.Optional[bytes] = None,
        *,
        tls_channel: t.Optional[ssl.SSLObject] = None,
    ) -> t.Optional[bytes]:
        cbt = _get_tls_channel_bindings(tls_channel)
        return self.context.step(in_token=in_token, channel_bindings=cbt)

    def wrap(
        self,
        data: bytes,
    ) -> bytes:
        if not self.context.complete:
            raise Exception("Cannot wrap without a completed context")

        elif not self.sign and not self.encrypt:
            return data

        wrapped_data = self.context.wrap(data, encrypt=self.encrypt).data
        return len(wrapped_data).to_bytes(4, byteorder="big") + wrapped_data

    def unwrap(
        self,
        data: bytes,
    ) -> t.Tuple[bytes, int]:
        if not self.context.complete:
            raise Exception("Cannot unwrap without a completed context")

        elif not self.sign and not self.encrypt:
            return data, len(data)

        data_view = memoryview(data)
        data_len = struct.unpack(">I", data_view[:4])[0]
        data_view = data_view[4:]
        if len(data_view) < data_len:
            return b"", 0

        data_view = data_view[:data_len]

        return self.context.unwrap(data_view.tobytes()).data, data_len + 4


def _get_tls_channel_bindings(
    tls_channel: t.Optional[ssl.SSLObject] = None,
) -> t.Optional[spnego.channel_bindings.GssChannelBindings]:
    if not tls_channel:
        return None

    cert_bytes = tls_channel.getpeercert(True)
    if not cert_bytes:
        return None

    backend = default_backend()

    cert = x509.load_der_x509_certificate(cert_bytes, backend)
    try:
        hash_algorithm = cert.signature_hash_algorithm
    except UnsupportedAlgorithm:
        hash_algorithm = None

    # If the cert signature algorithm is unknown, md5, or sha1 then use sha256 otherwise use the signature
    # algorithm of the cert itself.
    if not hash_algorithm or hash_algorithm.name in ["md5", "sha1"]:
        digest = hashes.Hash(hashes.SHA256(), backend)
    else:
        digest = hashes.Hash(hash_algorithm, backend)

    digest.update(cert_bytes)
    cert_hash = digest.finalize()

    return spnego.channel_bindings.GssChannelBindings(
        application_data=b"tls-server-end-point:" + cert_hash,
    )
