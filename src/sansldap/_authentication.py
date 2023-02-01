# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses
import typing as t

from .asn1 import ASN1Reader, ASN1Tag, ASN1Writer, TagClass


@dataclasses.dataclass
class AuthenticationOptions:
    """Options used for Authentication packing and unpacking.

    Custom options used for packing and unpacking authentication objects.

    Attributes:
        string_encoding: The encoding that is used to encode and decode
            strings. Defaults to utf-8.
        choices: List of known authentication types.
    """

    string_encoding: str = "utf-8"
    choices: t.List[t.Type[AuthenticationCredential]] = dataclasses.field(
        default_factory=lambda: [
            SaslCredential,
            SimpleCredential,
        ]
    )


@dataclasses.dataclass
class AuthenticationCredential:
    """Base class for Bind Request Authentication choices.

    This is the base class for bind request authentiction that can be used to
    provide custom authentication choices used in the :class:`BindRequest`. By
    default the :class:`SimpleCredential` and :class:`SaslCredential` choices
    are available. Each implementation must provide a value for auth_id,
    is_primitive as well as implement the ``pack`` and ``unpack`` methods. If
    no field is defined for is_primitive it defaults to ``True``.

    Example:
        .. code-block:: python

            @dataclasses.dataclass
            class CustomAuthentication(AuthenticationCredential):
                auth_id = dataclasses.field(init=False, repr=false, default=1024)

                username: str
                password: str

                def pack(
                    self,
                    options: SerializationOptions,
                ) -> bytes:
                    return f"{self.username}:{self.password}".encode(options.string_encoding)

                @classmethod
                def unpack(
                    cls,
                    data: bytes,
                    options: SerializationOptions,
                ) -> CustomAuthentication:
                    username, password = data.decode(options.string_encoding).split(":")
                    return CustomAuthentication(username=username, password=password)

    Note:
        A custom authentication credential must be understood by both the
        client and server.
    """

    auth_id: int
    "The ASN.1 choice value for this credential."

    def pack(
        self,
        writer: ASN1Writer,
        options: AuthenticationOptions,
    ) -> None:
        """Pack the authentication structure.

        Writes the authentication structure into the ASN.1 writer that is then
        embedded in the :class:`BindRequest` authentication value. The tagged
        choice should also be included in the written value.

        Args:
            writer: The writer used to write ASN.1 data.
            options: Options that can be used to control how the authentication
                credential is packed.
        """
        raise NotImplementedError()

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
        options: AuthenticationOptions,
    ) -> AuthenticationCredential:
        """Unpacks the authentication bytes.

        Unpacks the raw bytes into the Python object.

        Args:
            reader: The reader used to read the ASN.1 data.
            options: Options that can be used to control how the authentication
                credential is unpacked.

        Returns:
            AuthenticationCredential: An instance of the object that has been
            unpacked.
        """
        next_header = reader.peek_header()
        if next_header.tag.tag_class == TagClass.CONTEXT_SPECIFIC:
            for auth_type in options.choices:
                if auth_type.auth_id == next_header.tag.tag_number:
                    return auth_type.unpack(reader, options)

        raise NotImplementedError(f"Unknown authentication object {next_header.tag}, cannot unpack")


@dataclasses.dataclass
class SimpleCredential(AuthenticationCredential):
    """The Simple Credential.

    This object is used to encode the simple password for a
    :class:`BindRequest`.

    Args:
        password: The password to authenticate with or an empty string for an
            identity only, or anonymous, bind operation.
    """

    auth_id: int = dataclasses.field(init=False, repr=False, default=0)

    password: str

    def pack(
        self,
        writer: ASN1Writer,
        options: AuthenticationOptions,
    ) -> None:
        writer.write_octet_string(
            self.password.encode(options.string_encoding),
            tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.auth_id, False),
        )

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
        options: AuthenticationOptions,
    ) -> SimpleCredential:
        password = reader.read_octet_string(
            tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, cls.auth_id, False),
            hint="SimpleCredential.password",
        ).decode(options.string_encoding)
        return SimpleCredential(password=password)


@dataclasses.dataclass
class SaslCredential(AuthenticationCredential):
    """The SASL Credential.

    This object is used to store the SASL credential for a
    :class:`BindRequest`. It contains the SASL mechanism used and the
    credential byte string for that credential. The SaslCredentials structure
    is defined in `RFC 4511 4.2 Bind Operation`_.

    Args:
        mechanism: The SASL mechanism.
        credentials: The SASL credential bytes to exchange, if any.

    .. _RFC 4511 4.2. Bind Operation:
        https://www.rfc-editor.org/rfc/rfc4511#section-4.2
    """

    # SaslCredentials ::= SEQUENCE {
    #      mechanism               LDAPString,
    #      credentials             OCTET STRING OPTIONAL }

    auth_id: int = dataclasses.field(init=False, repr=False, default=3)
    is_primitive: bool = dataclasses.field(init=False, repr=False, default=False)

    mechanism: str
    credentials: t.Optional[bytes]

    def pack(
        self,
        writer: ASN1Writer,
        options: AuthenticationOptions,
    ) -> None:
        with writer.push_sequence(
            tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, self.auth_id, True),
        ) as sasl_writer:
            sasl_writer.write_octet_string(
                self.mechanism.encode(options.string_encoding),
            )
            if self.credentials is not None:
                sasl_writer.write_octet_string(self.credentials)

    @classmethod
    def unpack(
        cls,
        reader: ASN1Reader,
        options: AuthenticationOptions,
    ) -> SaslCredential:
        sasl_reader = reader.read_sequence(
            hint="SaslCredential",
            tag=ASN1Tag(TagClass.CONTEXT_SPECIFIC, cls.auth_id, True),
        )

        mechanism = sasl_reader.read_octet_string(
            hint="SaslCredential.mechanism",
        ).decode(options.string_encoding)
        credentials: t.Optional[bytes] = None
        if sasl_reader:
            credentials = sasl_reader.read_octet_string(
                hint="SaslCredential.credentials",
            )

        return SaslCredential(mechanism=mechanism, credentials=credentials)
