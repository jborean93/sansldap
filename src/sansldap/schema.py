# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import base64
import dataclasses
import re
import typing as t

DOT = r"\."
LCURLY = r"\{"
RCURLY = r"\}"
LPAREN = r"\("
RPAREN = "\\)"
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
KEYCHAR = f"([a-zA-Z0-9-])"
KEYSTRING = f"{LEADKEYCHAR}({KEYCHAR})*"

DESCR = f"{KEYSTRING}"
QDESCR = f"{SQUOTE}{DESCR}{SQUOTE}"
QDESCRLIST = f"({QDESCR}({SP}{QDESCR})*)?"
QDESCRS = f"({QDESCR}|{LPAREN}{WSP}{QDESCRLIST}{WSP}{RPAREN})"

QS = f"{ESC}5[Cc]"
QQ = f"{ESC}27"
QUTF1 = r"[\x00-\x26\x28-\x5B\x5D-\x7f]"
UTF0 = r"[\x80-\xbf]"
UTF2 = rf"[\xc2-\xdf]{UTF0}"
UTF3 = rf"(\xe0[\xa0-\xbf]{UTF0}|[\xe1-\xec]({UTF0}){{2}}|\xed[\x80-\x9f]{UTF0}|[\xee-\xef]({UTF0}){{2}})"
UTF4 = f"(\\xf0[\\x90-\\xbf]({UTF0}){{2}}|[\\xf1-\\xf3]({UTF0}){{3}}|\\xf4[\\x80-\\x8f]({UTF0}){{2}})"
UTFMB = f"({UTF2}|{UTF3}|{UTF4})"
QUTF8 = f"({QUTF1}|{UTFMB})"
DSTRING = f"({QS}|{QQ}|{QUTF8})+"
QDSTRING = f"{SQUOTE}{DSTRING}{SQUOTE}"
QDSTRINGLIST = f"({QDSTRING}({SP}{QDSTRING})*)?"
QDSTRINGS = f"({QDSTRING}|{LPAREN}{WSP}{QDSTRINGLIST}{WSP}{RPAREN})"

OID = f"({DESCR}|{NUMERICOID})"
NOIDLEN = f"{NUMERICOID}({LCURLY}{NUMBER}{RCURLY})?"
NOIDLEN_MATCH = re.compile(f"(?P<value>{NUMERICOID}){LCURLY}(?P<len>{NUMBER}){RCURLY}")

XSTRING = f"[xX]{HYPHEN}([a-zA-Z]|{HYPHEN}|{USCORE})+"
EXTENSIONS = f"({SP}{XSTRING}{SP}{QDSTRINGS})*"


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


def _parse_qdstring(value: t.Optional[str]) -> t.Optional[str]:
    if not value:
        return None

    raw_value = value[1 : len(value) - 1]

    def rplcr(matchobj: re.Match) -> str:
        return base64.b16decode(matchobj.group(0)[1:].upper()).decode()

    return re.sub(f"{QS}|{QQ}", rplcr, raw_value)


@dataclasses.dataclass(frozen=True)
class AttributeTypeDescription:
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
    usage: str = "userApplications"

    def __str__(self) -> str:
        values = []

        if len(self.names) == 1:
            values.append(f" NAME '{self.names[0]}'")
        elif self.names:
            names_str = "' '".join([n for n in self.names])
            values.append(f" NAME ( '{names_str}' )")

        if self.description is not None:

            def rplcr(matchobj: re.Match) -> str:
                return f"\\{ord(matchobj.group(0)):02x}"

            desc_str = re.sub(r"[\\|']", rplcr, self.description)
            values.append(f" DESC '{desc_str}'")

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

        if self.usage != "userApplications":
            values.append(f" USAGE {self.usage}")

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
        usage = m.group("usage")
        # extensions = m.group("extensions")

        syntax = None
        syntax_length = None
        if raw_syntax:
            syntax = raw_syntax.strip("'")
            len_match = re.match(NOIDLEN_MATCH, syntax)
            if len_match:
                syntax = len_match.group("value")
                syntax_length = int(len_match.group("len"))

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
            usage=usage or "userApplications",
            # extensions=None,
        )


__all__ = [
    "AttributeTypeDescription",
]
