#!/usr/bin/env python
"""
ViperMonkey: VBA Grammar - Identifiers

ViperMonkey is a specialized engine to parse, analyze and interpret Microsoft
VBA macros (Visual Basic for Applications), mainly for malware analysis.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

Project Repository:
https://github.com/decalage2/ViperMonkey
"""

# === LICENSE ==================================================================

# ViperMonkey is copyright (c) 2015-2016 Philippe Lagadec (http://www.decalage.info)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
import re

__version__ = '0.02'

# ------------------------------------------------------------------------------
# TODO:

# --- IMPORTS ------------------------------------------------------------------

from pyparsing import *
from reserved import *
from logger import log

# --- IDENTIFIER -------------------------------------------------------------

# TODO: see MS-VBAL 3.3.5 page 33
# 3.3.5 Identifier Tokens
#
# MS-GRAMMAR: Latin-identifier = first-Latin-identifier-character *subsequent-Latin-identifier-character
# MS-GRAMMAR: first-Latin-identifier-character = (%x0041-005A / %x0061-007A) ; A-Z / a-z
# MS-GRAMMAR: subsequent-Latin-identifier-character = first-Latin-identifier-character / DIGIT / %x5F ; underscore
# MS-GRAMMAR: identifier = expression

general_identifier = Word(initChars=alphas + alphas8bit, bodyChars=alphanums + '_' + alphas8bit) + Suppress(Optional("^")) + Suppress(Optional("%"))

# MS-GRAMMAR: lex-identifier = Latin-identifier / codepage-identifier / Japanese-identifier /
# MS-GRAMMAR: Korean-identifier / simplified-Chinese-identifier / traditional-Chinese-identifier
# TODO: add other identifier types
lex_identifier = general_identifier | Regex(r"%\w+%")

# 3.3.5.2 Reserved Identifiers and IDENTIFIER
# IDENTIFIER = <any lex-identifier that is not a reserved-identifier>

identifier = NotAny(reserved_identifier) + lex_identifier

# convert identifier to a string:
identifier.setParseAction(lambda t: t[0])

# --- ENTITY NAMES -----------------------------------------------------------

# 3.3.5.3 Special Identifier Forms
#
# MS-GRAMMAR: FOREIGN-NAME = "[" foreign-identifier "]"
# MS-GRAMMAR: foreign-identifier = 1*non-line-termination-character
#
# A <FOREIGN-NAME> is a token (section 3.3) that represents a text sequence that is used as if it
# was an identifier but which does not conform to the VBA rules for forming an identifier. Typically, a
# <FOREIGN-NAME> is used to refer to an entity (section 2.2) that is created using some
# programming language other than VBA.

foreign_name = Literal('[') + CharsNotIn('\x0D\x0A') + Literal(']')

# MS-GRAMMAR: BUILTIN-TYPE = reserved-type-identifier / ("[" reserved-type-identifier "]")
#                            / "object" / "[object]"

builtin_type = reserved_type_identifier | (Suppress("[") + reserved_type_identifier + Suppress("]")) \
               | CaselessKeyword("object") | CaselessLiteral("[object]")

# A <TYPED-NAME> is an <IDENTIFIER> that is immediately followed by a <type-suffix> with no
# intervening whitespace.
# <type-suffix> Declared Type
# % Integer
# & Long
# ^ LongLong
# ! Single
# # Double
# @ Currency
# $ String
# Don't parse 'c&' in 'c& d& e' as a typed_name. It's a string concat.
#type_suffix = Word(r"%&^!#@$", exact=1) + NotAny(Word(alphanums) | '"')
type_suffix = Word(r"%&^!#@$", exact=1) + NotAny((Optional(White()) + Word(alphanums)) | '"')
typed_name = Combine(identifier + type_suffix)

# 5.1 Module Body Structure
# Throughout this specification the following common grammar rules are used for expressing various
# forms of entity (section 2.2) names:
# TODO: for now, disabled foreign_name
untyped_name = identifier #| foreign_name
# NOTE: here typed_name must come before untyped_name
entity_name = typed_name | untyped_name
unrestricted_name = entity_name | reserved_identifier

# --- TODO IDENTIFIER OR OBJECT.ATTRIB ----------------------------------------

# TODO: reduce this list when corresponding statements are implemented
reserved_keywords = Regex(re.compile(
    'Chr[BW]?|Asc|Case|On|Sub|If|Kill|For|Next|Public|Private|Declare|Function', re.IGNORECASE))

TODO_identifier_or_object_attrib = Combine(
    NotAny(reserved_keywords)
    + Combine(Literal('.') + lex_identifier) | Combine(entity_name + Optional(Literal('.') + lex_identifier))
    + Optional(CaselessLiteral('$'))
    + Optional(CaselessLiteral('#'))
    + Optional(CaselessLiteral('%'))
)

TODO_identifier_or_object_attrib_loose = Combine(
    Combine(Literal('.') + lex_identifier) | Combine(entity_name + Optional(Literal('.') + lex_identifier))
    + Optional(CaselessLiteral('$'))
    + Optional(CaselessLiteral('#'))
    + Optional(CaselessLiteral('%'))
)
