# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import base64
import dataclasses
import enum
import re
import typing as t

OptionalString = t.TypeVar("OptionalString", str, None)

DOLLAR = r"\$"
DOT = r"\."
LCURLY = r"\{"
RCURLY = r"\}"
LPAREN = r"\("
RPAREN = r"\)"
WSP = r"[\ ]*"
SP = r"[\ ]+"
HYPHEN = "-"
SQUOTE = "'"
USCORE = "_"
ESC = r"\\"

LDIGIT = "[1-9]"
NUMBER = rf"([0-9]|{LDIGIT}[0-9]+)"
NUMERICOID = rf"{NUMBER}({DOT}{NUMBER})+"

LEADKEYCHAR = "[a-zA-Z]"
KEYCHAR = "([a-zA-Z0-9-])"
KEYSTRING = f"{LEADKEYCHAR}({KEYCHAR})*"

DESCR = f"{KEYSTRING}"
QDESCR = f"{SQUOTE}{DESCR}{SQUOTE}"
QDESCRLIST = f"({QDESCR}({SP}{QDESCR})*)?"
QDESCRS = f"({QDESCR}|{LPAREN}{WSP}{QDESCRLIST}{WSP}{RPAREN})"

OID = f"({DESCR}|{NUMERICOID})"
OIDLIST = f"({OID}({WSP}{DOLLAR}{WSP}{OID})*)"
OIDS = f"({OID}|{LPAREN}{WSP}{OIDLIST}{WSP}{RPAREN})"
NOIDLEN = f"{NUMERICOID}({LCURLY}{NUMBER}{RCURLY})?"
NOIDLEN_MATCH = re.compile(f"(?P<value>{NUMERICOID}){LCURLY}(?P<len>{NUMBER}){RCURLY}")

# Unicode territory, there be dragons here

# \27 - escaped representation of '
QQ = f"{ESC}27"

# \5c or \6C - escaped representation of \
QS = f"{ESC}5[Cc]"

# Any Unicode codepoint except for \ or '. Used for UTF-8 chars inside single
# quotes hence the need for the escape characters and a way to escape a
# a backslash.
QUTF8 = r"[^'\\]+"
DSTRING = f"({QS}|{QQ}|{QUTF8})+"
QDSTRING = f"{SQUOTE}{DSTRING}{SQUOTE}"
QDSTRINGLIST = f"({QDSTRING}({SP}{QDSTRING})*)?"
QDSTRINGS = f"({QDSTRING}|{LPAREN}{WSP}{QDSTRINGLIST}{WSP}{RPAREN})"


XSTRING = f"[xX]{HYPHEN}([a-zA-Z]|{HYPHEN}|{USCORE})+"
EXTENSIONS = f"({SP}(?P<xstring>{XSTRING}){SP}{QDSTRINGS})*"


def _encode_oids(value: t.List[str]) -> str:
    if len(value) == 1:
        return value[0]

    else:
        value_str = " $ ".join(value)
        return f"( {value_str} )"


def _encode_qdstring(value: str) -> str:
    def rplcr(matchobj: re.Match) -> str:
        return f"\\{ord(matchobj.group(0)):02x}"

    desc_str = re.sub(r"[\\|']", rplcr, value)

    return f"'{desc_str}'"


def _parse_oids(value: t.Optional[str]) -> t.List[str]:
    if not value:
        return []

    return [v.strip() for v in value.strip("() ").split("$")]


def _parse_qdstring(value: OptionalString) -> OptionalString:
    if value is None:
        return None

    def rplcr(matchobj: re.Match) -> str:
        return base64.b16decode(matchobj.group(0)[1:].upper()).decode()

    return re.sub(f"{QS}|{QQ}", rplcr, value.strip("'"))


def _parse_extensions(value: t.Optional[str]) -> t.Dict[str, t.List[str]]:
    if not value:
        return {}

    def _extract_qdstring(value: str) -> t.Tuple[str, str]:
        entry, remaining = value[1:].split("'", 1)
        parsed_value = _parse_qdstring(entry)

        return parsed_value, remaining.lstrip(" ")

    value = value.lstrip(" ")
    res: t.Dict[str, t.List[str]] = {}
    while value:
        key, remaining = value.lstrip(" ").split(" ", 1)
        key = key[2:]

        entries: t.List[str] = []
        if remaining.startswith("("):
            remaining = remaining[1:].lstrip(" ")
            while not remaining.startswith(")"):
                entry, remaining = _extract_qdstring(remaining)
                entries.append(entry)

            value = remaining[1:]

        else:
            entry, value = _extract_qdstring(remaining)
            entries.append(entry)

        res[key] = entries

    return res


# The ABNF notation of an ObjectClassDescription is:
#     ObjectClassDescription = LPAREN WSP
#         numericoid                 ; object identifier
#         [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
#         [ SP "DESC" SP qdstring ]  ; description
#         [ SP "OBSOLETE" ]          ; not active
#         [ SP "SUP" SP oids ]       ; superior object classes
#         [ SP kind ]                ; kind of class
#         [ SP "MUST" SP oids ]      ; attribute types
#         [ SP "MAY" SP oids ]       ; attribute types
#         extensions WSP RPAREN
#
#     kind = "ABSTRACT" / "STRUCTURAL" / "AUXILIARY"
OBJECT_CLASS_DESCRIPTION = re.compile(
    f"""
{LPAREN}{WSP}
    (?P<oid>{NUMERICOID})
    ({SP}NAME{SP}(?P<name>{QDESCRS}))?
    ({SP}DESC{SP}(?P<desc>{QDSTRING}))?
    (?P<obsolete>{SP}OBSOLETE)?
    ({SP}SUP{SP}(?P<sup>{OIDS}))?
    ({SP}(?P<kind>ABSTRACT|STRUCTURAL|AUXILIARY))?
    ({SP}MUST{SP}(?P<must>{OIDS}))?
    ({SP}MAY{SP}(?P<may>{OIDS}))?
    (?P<extensions>{EXTENSIONS})
{WSP}{RPAREN}
""",
    re.VERBOSE,
)


class ObjectClassKind(str, enum.Enum):
    ABSTRACT = "ABSTRACT"
    STRUCTURAL = "STRUCTURAL"
    AUXILIARY = "AUXILIARY"


@dataclasses.dataclass(frozen=True)
class ObjectClassDescription:
    """Object Class definition.

    Object is used to define object classes inside an LDAP database. This
    object is defined in `RFC 4512 4.1.1. Object Class Definitions`_.

    Args:
        oid: The object identifier for this object class.
        names: The named identifying this object class.
        description: A short description of the object class.
        obsolete: Indicates the object class is not active.
        super_types: The direct superclasses of this object class.
        kind: The kind of object class.
        must: Required attribute types by OID.
        may: Allowed attribute types by OID.
        extensions: Optional extensions to the object class.

    .. _RFC 4512 4.1.1. Object Class Definitions:
        https://www.rfc-editor.org/rfc/rfc4512#section-4.1.1
    """

    oid: str
    names: t.List[str] = dataclasses.field(default_factory=list)
    description: t.Optional[str] = None
    obsolete: bool = False
    super_types: t.List[str] = dataclasses.field(default_factory=list)
    kind: ObjectClassKind = ObjectClassKind.STRUCTURAL
    must: t.List[str] = dataclasses.field(default_factory=list)
    may: t.List[str] = dataclasses.field(default_factory=list)
    extensions: t.Dict[str, t.List[str]] = dataclasses.field(default_factory=dict)

    def __str__(self) -> str:
        values = []

        if len(self.names) == 1:
            values.append(f" NAME '{self.names[0]}'")
        elif self.names:
            names_str = "' '".join([n for n in self.names])
            values.append(f" NAME ( '{names_str}' )")

        if self.description is not None:
            values.append(f" DESC {_encode_qdstring(self.description)}")

        if self.obsolete:
            values.append(" OBSOLETE")

        if self.super_types:
            values.append(f" SUP {_encode_oids(self.super_types)}")

        values.append(f" {self.kind.value}")

        if self.must:
            values.append(f" MUST {_encode_oids(self.must)}")

        if self.may:
            values.append(f" MAY {_encode_oids(self.may)}")

        for attr, ext_values in self.extensions.items():
            if len(ext_values) == 1:
                values.append(f" X-{attr} {_encode_qdstring(ext_values[0])}")

            else:
                values_str = " ".join([_encode_qdstring(v) for v in ext_values])
                values.append(f" X-{attr} ( {values_str} )")

        return f"( {self.oid}{''.join(values)} )"

    @classmethod
    def from_string(self, value: str) -> ObjectClassDescription:
        m = OBJECT_CLASS_DESCRIPTION.match(value)
        if not m:
            raise ValueError("value is not a valid ObjectClassDescription")

        oid = m.group("oid")
        names = m.group("name")
        desc = m.group("desc")
        obsolete = m.group("obsolete")
        sup = m.group("sup")
        raw_kind = m.group("kind")
        must = m.group("must")
        may = m.group("may")
        extensions = m.group("extensions")

        kind = {
            ObjectClassKind.ABSTRACT.value: ObjectClassKind.ABSTRACT,
            ObjectClassKind.AUXILIARY.value: ObjectClassKind.AUXILIARY,
        }.get(raw_kind, ObjectClassKind.STRUCTURAL)

        return ObjectClassDescription(
            oid=oid,
            names=[n.strip("'") for n in names.strip("()").split(" ") if n] if names else [],
            description=_parse_qdstring(desc),
            obsolete=bool(obsolete),
            super_types=_parse_oids(sup),
            kind=kind,
            must=_parse_oids(must),
            may=_parse_oids(may),
            extensions=_parse_extensions(extensions),
        )


# The ABNF notation of an AttributeTypeDescription is:
#     AttributeTypeDescription = LPAREN WSP
#         numericoid                    ; object identifier
#         [ SP "NAME" SP qdescrs ]      ; short names (descriptors)
#         [ SP "DESC" SP qdstring ]     ; description
#         [ SP "OBSOLETE" ]             ; not active
#         [ SP "SUP" SP oid ]           ; supertype
#         [ SP "EQUALITY" SP oid ]      ; equality matching rule
#         [ SP "ORDERING" SP oid ]      ; ordering matching rule
#         [ SP "SUBSTR" SP oid ]        ; substrings matching rule
#         [ SP "SYNTAX" SP noidlen ]    ; value syntax
#         [ SP "SINGLE-VALUE" ]         ; single-value
#         [ SP "COLLECTIVE" ]           ; collective
#         [ SP "NO-USER-MODIFICATION" ] ; not user modifiable
#         [ SP "USAGE" SP usage ]       ; usage
#         extensions WSP RPAREN         ; extensions
#
#     usage = "userApplications"     /  ; user
#             "directoryOperation"   /  ; directory operational
#             "distributedOperation" /  ; DSA-shared operational
#             "dSAOperation"            ; DSA-specific operational
ATTRIBUTE_TYPE_DESCRIPTION = re.compile(
    f"""
{LPAREN}{WSP}
    (?P<oid>{NUMERICOID})
    ({SP}NAME{SP}(?P<name>{QDESCRS}))?
    ({SP}DESC{SP}(?P<desc>{QDSTRING}))?
    (?P<obsolete>{SP}OBSOLETE)?
    ({SP}SUP{SP}(?P<sup>{OID}))?
    ({SP}EQUALITY{SP}(?P<equality>{OID}))?
    ({SP}ORDERING{SP}(?P<ordering>{OID}))?
    ({SP}SUBSTR{SP}(?P<substr>{OID}))?
    # It's not in the spec but MS AD uses a qdstring for SYNTAX
    ({SP}SYNTAX{SP}(?P<syntax>{NOIDLEN}|{QDSTRING}))?
    (?P<single_value>{SP}SINGLE-VALUE)?
    (?P<collective>{SP}COLLECTIVE)?
    (?P<no_user_modification>{SP}NO-USER-MODIFICATION)?
    ({SP}USAGE{SP}(?P<usage>userApplications|directoryOperation|distributedOperation|dSAOperation))?
    (?P<extensions>{EXTENSIONS})
{WSP}{RPAREN}
""",
    re.VERBOSE,
)


class AttributeTypeUsage(str, enum.Enum):
    USER_APPLICATIONS = "userApplications"
    DIRECTORY_OPERATION = "directoryOperation"
    DISTRIBUTED_OPERATION = "distributedOperation"
    DSA_OPERATION = "dSAOperation"


@dataclasses.dataclass(frozen=True)
class AttributeTypeDescription:
    """Attribute Type definition.

    Object is used to define attribute types inside an LDAP database. This
    object is defined in `RFC 4512 4.1.2. Attribute Types`_. Typically
    Microsoft Active Directory only defines the oid, single name entry, syntax,
    single_value, and no_user_modification elements of the definition.

    Args:
        oid: The object identifier for this attribute type.
        names: The named identifying this attribute type.
        description: A short description of the attribute type.
        obsolete: Indicates the attribute type is not active.
        super_type: The OID of the super type of this type.
        equality: The OID of the equality matching rule.
        ordering: The OID of the ordering matching rule.
        substrings: The OID of the substrings matching rule.
        syntax: Identifies the value syntax type.
        syntax_length: Optional upper bound length of the syntax value.
        single_value: Indicates that the attribute is restricted to a single
            value or not.
        collective: Indicates the attribute type is collective.
        no_user_modification: Indicates the attribute type is not user
            modifiable.
        usage: The application of the attribute type. Can be set to
            userApplications, directoryOperation, distributedOperation, or
            dSAOperation.
        extensions: Optional extensions to the attribute type.

    .. _RFC 4512 4.1.2. Attribute Types:
        https://www.rfc-editor.org/rfc/rfc4512#section-4.1.2
    """

    oid: str
    names: t.List[str] = dataclasses.field(default_factory=list)
    description: t.Optional[str] = None
    obsolete: bool = False
    super_type: t.Optional[str] = None
    equality: t.Optional[str] = None
    ordering: t.Optional[str] = None
    substrings: t.Optional[str] = None
    syntax: t.Optional[str] = None
    syntax_length: t.Optional[int] = None
    single_value: bool = False
    collective: bool = False
    no_user_modification: bool = False
    usage: AttributeTypeUsage = AttributeTypeUsage.USER_APPLICATIONS
    extensions: t.Dict[str, t.List[str]] = dataclasses.field(default_factory=dict)

    def __str__(self) -> str:
        values = []

        if len(self.names) == 1:
            values.append(f" NAME '{self.names[0]}'")
        elif self.names:
            names_str = "' '".join([n for n in self.names])
            values.append(f" NAME ( '{names_str}' )")

        if self.description is not None:
            values.append(f" DESC {_encode_qdstring(self.description)}")

        if self.obsolete:
            values.append(" OBSOLETE")

        if self.super_type is not None:
            values.append(f" SUP {self.super_type}")

        if self.equality is not None:
            values.append(f" EQUALITY {self.equality}")

        if self.ordering is not None:
            values.append(f" ORDERING {self.ordering}")

        if self.substrings is not None:
            values.append(f" SUBSTR {self.substrings}")

        if self.syntax is not None:
            values.append(f" SYNTAX {self.syntax}")
            if self.syntax_length is not None:
                values.append(f"{{{self.syntax_length}}}")

        if self.single_value:
            values.append(" SINGLE-VALUE")

        if self.collective:
            values.append(" COLLECTIVE")

        if self.no_user_modification:
            values.append(" NO-USER-MODIFICATION")

        if self.usage != AttributeTypeUsage.USER_APPLICATIONS:
            values.append(f" USAGE {self.usage.value}")

        for attr, ext_values in self.extensions.items():
            if len(ext_values) == 1:
                values.append(f" X-{attr} {_encode_qdstring(ext_values[0])}")

            else:
                values_str = " ".join([_encode_qdstring(v) for v in ext_values])
                values.append(f" X-{attr} ( {values_str} )")

        return f"( {self.oid}{''.join(values)} )"

    @classmethod
    def from_string(self, value: str) -> AttributeTypeDescription:
        m = ATTRIBUTE_TYPE_DESCRIPTION.match(value)
        if not m:
            raise ValueError("value is not a valid AttributeTypeDescription")

        oid = m.group("oid")
        names = m.group("name")
        desc = m.group("desc")
        obsolete = m.group("obsolete")
        sup = m.group("sup")
        equality = m.group("equality")
        ordering = m.group("ordering")
        substr = m.group("substr")
        raw_syntax = m.group("syntax")
        single_value = m.group("single_value")
        collective = m.group("collective")
        no_user_modification = m.group("no_user_modification")
        raw_usage = m.group("usage")
        extensions = m.group("extensions")

        syntax = None
        syntax_length = None
        if raw_syntax:
            syntax = raw_syntax.strip("'")
            len_match = re.match(NOIDLEN_MATCH, syntax)
            if len_match:
                syntax = len_match.group("value")
                syntax_length = int(len_match.group("len"))

        usage = {
            AttributeTypeUsage.DIRECTORY_OPERATION.value: AttributeTypeUsage.DIRECTORY_OPERATION,
            AttributeTypeUsage.DISTRIBUTED_OPERATION.value: AttributeTypeUsage.DISTRIBUTED_OPERATION,
            AttributeTypeUsage.DSA_OPERATION.value: AttributeTypeUsage.DSA_OPERATION,
        }.get(raw_usage, AttributeTypeUsage.USER_APPLICATIONS)

        return AttributeTypeDescription(
            oid=oid,
            names=[n.strip("'") for n in names.strip("()").split(" ") if n] if names else [],
            description=_parse_qdstring(desc),
            obsolete=bool(obsolete),
            super_type=sup,
            equality=equality,
            ordering=ordering,
            substrings=substr,
            syntax=syntax.strip("'") if syntax else None,
            syntax_length=syntax_length,
            single_value=bool(single_value),
            collective=bool(collective),
            no_user_modification=bool(no_user_modification),
            usage=usage,
            extensions=_parse_extensions(extensions),
        )


# The ABNF notation of an DITContentRuleDescription is:
#     DITContentRuleDescription = LPAREN WSP
#         numericoid                 ; object identifier
#         [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
#         [ SP "DESC" SP qdstring ]  ; description
#         [ SP "OBSOLETE" ]          ; not active
#         [ SP "AUX" SP oids ]       ; auxiliary object classes
#         [ SP "MUST" SP oids ]      ; attribute types
#         [ SP "MAY" SP oids ]       ; attribute types
#         [ SP "NOT" SP oids ]       ; attribute types
#         extensions WSP RPAREN      ; extensions
DIT_CONTENT_RULE_DESCRIPTION = re.compile(
    f"""
{LPAREN}{WSP}
    (?P<oid>{NUMERICOID})
    ({SP}NAME{SP}(?P<name>{QDESCRS}))?
    ({SP}DESC{SP}(?P<desc>{QDSTRING}))?
    (?P<obsolete>{SP}OBSOLETE)?
    ({SP}AUX{SP}(?P<aux>{OIDS}))?
    ({SP}MUST{SP}(?P<must>{OIDS}))?
    ({SP}MAY{SP}(?P<may>{OIDS}))?
    ({SP}NOT{SP}(?P<not>{OIDS}))?
    (?P<extensions>{EXTENSIONS})
{WSP}{RPAREN}
""",
    re.VERBOSE,
)


@dataclasses.dataclass(frozen=True)
class DITContentRuleDescription:
    """DIT Content Rule.

    Object is used to define DIT content rules that govern the content of
    entries of a particular structural object class. This object is defined in
    `RFC 4512 4.1.6. DIT Content Rules`_.

    Args:
        oid: The object identifier for this DIT content rule.
        names: The named identifying this DIT content rule.
        description: A short description of this DIT content rule.
        obsolete: Indicates the DIT content rule is not active.
        aux: List of auxiliary object class OIDS that entries subject to this
            DIT content rule may belong to.
        must: Required attribute types by OID.
        may: Allowed attribute types by OID.
        never: Precluded attribute types by OID.
        extensions: Optional extensions to the DIT content rule.

    .. _RFC 4512 4.1.6. DIT Content Rules:
        https://www.rfc-editor.org/rfc/rfc4512#section-4.1.6
    """

    oid: str
    names: t.List[str] = dataclasses.field(default_factory=list)
    description: t.Optional[str] = None
    obsolete: bool = False
    aux: t.List[str] = dataclasses.field(default_factory=list)
    must: t.List[str] = dataclasses.field(default_factory=list)
    may: t.List[str] = dataclasses.field(default_factory=list)
    never: t.List[str] = dataclasses.field(default_factory=list)
    extensions: t.Dict[str, t.List[str]] = dataclasses.field(default_factory=dict)

    def __str__(self) -> str:
        values = []

        if len(self.names) == 1:
            values.append(f" NAME '{self.names[0]}'")
        elif self.names:
            names_str = "' '".join([n for n in self.names])
            values.append(f" NAME ( '{names_str}' )")

        if self.description is not None:
            values.append(f" DESC {_encode_qdstring(self.description)}")

        if self.obsolete:
            values.append(" OBSOLETE")

        if self.aux:
            values.append(f" AUX {_encode_oids(self.aux)}")

        if self.must:
            values.append(f" MUST {_encode_oids(self.must)}")

        if self.may:
            values.append(f" MAY {_encode_oids(self.may)}")

        if self.never:
            values.append(f" NOT {_encode_oids(self.never)}")

        for attr, ext_values in self.extensions.items():
            if len(ext_values) == 1:
                values.append(f" X-{attr} {_encode_qdstring(ext_values[0])}")

            else:
                values_str = " ".join([_encode_qdstring(v) for v in ext_values])
                values.append(f" X-{attr} ( {values_str} )")

        return f"( {self.oid}{''.join(values)} )"

    @classmethod
    def from_string(self, value: str) -> DITContentRuleDescription:
        m = DIT_CONTENT_RULE_DESCRIPTION.match(value)
        if not m:
            raise ValueError("value is not a valid DITContentRuleDescription")

        oid = m.group("oid")
        names = m.group("name")
        desc = m.group("desc")
        obsolete = m.group("obsolete")
        aux = m.group("aux")
        must = m.group("must")
        may = m.group("may")
        never = m.group("not")
        extensions = m.group("extensions")

        return DITContentRuleDescription(
            oid=oid,
            names=[n.strip("'") for n in names.strip("()").split(" ") if n] if names else [],
            description=_parse_qdstring(desc),
            obsolete=bool(obsolete),
            aux=_parse_oids(aux),
            must=_parse_oids(must),
            may=_parse_oids(may),
            never=_parse_oids(never),
            extensions=_parse_extensions(extensions),
        )


__all__ = [
    "AttributeTypeDescription",
    "AttributeTypeUsage",
    "DITContentRuleDescription",
    "ObjectClassDescription",
    "ObjectClassKind",
]
