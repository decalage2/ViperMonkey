#!/usr/bin/env python
"""
ViperMonkey: VBA Grammar - Literals

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

__version__ = '0.02'

# --- IMPORTS ------------------------------------------------------------------

from pyparsing import *

from logger import log

# --- BOOLEAN ------------------------------------------------------------

boolean_literal = CaselessKeyword('True') | CaselessKeyword('False')
boolean_literal.setParseAction(lambda t: bool(t[0].lower() == 'true'))

# --- NUMBER TOKENS ----------------------------------------------------------

# 3.3.2 Number Tokens

# here Combine() is required to avoid spaces between elements:
decimal_literal = Combine(pyparsing_common.signed_integer + Suppress(Optional(Word('%&^', exact=1)))) + \
                  Suppress(Optional(CaselessLiteral('!') | CaselessLiteral('#') | CaselessLiteral('@')))
decimal_literal.setParseAction(lambda t: int(t[0]))

octal_literal = Combine(Suppress(Literal('&') + Optional((CaselessLiteral('o')))) + Word(srange('[0-7]'))
                        + Suppress(Optional(Word('%&^', exact=1))))
octal_literal.setParseAction(lambda t: int(t[0], base=8))

hex_literal = Combine(Suppress(CaselessLiteral('&h')) + Word(srange('[0-9a-fA-F]'))
                      + Suppress(Optional(Word('%&^', exact=1))))
hex_literal.setParseAction(lambda t: int(t[0], base=16))

integer = decimal_literal | octal_literal | hex_literal

# NOTE: here WordStart is to avoid matching a number preceded by letters (e.g. "VBT1"), when using scanString
# TO DO: remove WordStart if scanString is not used

# TODO: Handle exponents as needed.
float_literal = decimal_literal + Suppress(CaselessLiteral('.')) + decimal_literal + \
                Suppress(Optional(CaselessLiteral('!') | CaselessLiteral('#') | CaselessLiteral('@')))
float_literal.setParseAction(lambda t: float(str(t[0]) + "." + str(t[1])))

# --- QUOTED STRINGS ---------------------------------------------------------

# 3.3.4 String Tokens
quoted_string = QuotedString('"', escQuote='""')
quoted_string.setParseAction(lambda t: str(t[0]))

quoted_string_keep_quotes = QuotedString('"', escQuote='""', unquoteResults=False)
quoted_string_keep_quotes.setParseAction(lambda t: str(t[0]))

# --- DATE TOKENS ------------------------------------------------------------

# TODO: 3.3.3 Date Tokens

# TODO: For now just handle a date literal as a string.
date_string = QuotedString('#')
date_string.setParseAction(lambda t: str(t[0]))

# --- LITERALS ---------------------------------------------------------------

# TODO: 5.6.5 Literal Expressions

literal = boolean_literal | integer | quoted_string | date_string | float_literal
literal.setParseAction(lambda t: t[0])

