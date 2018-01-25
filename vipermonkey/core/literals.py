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


# ------------------------------------------------------------------------------
# CHANGELOG:
# 2015-02-12 v0.01 PL: - first prototype
# 2015-2016        PL: - many updates
# 2016-06-11 v0.02 PL: - split vipermonkey into several modules

__version__ = '0.02'

# ------------------------------------------------------------------------------
# TODO:

# --- IMPORTS ------------------------------------------------------------------

from pyparsing import *

from logger import log
log.debug('importing literals')

# --- BOOLEAN ------------------------------------------------------------

boolean_literal = CaselessKeyword('True') | CaselessKeyword('False')
boolean_literal.setParseAction(lambda t: bool(t[0].lower() == 'true'))

# --- NUMBER TOKENS ----------------------------------------------------------

# 3.3.2 Number Tokens
# INTEGER = integer-literal ["%" / "&" / "^"]
# integer-literal = decimal-literal / octal-literal / hex-literal
# decimal-literal = 1*decimal-digit
# octal-literal = "&" [%x004F / %x006F] 1*octal-digit
# ; & or &o or &O
# hex-literal = "&" (%x0048 / %x0068) 1*hex-digit
# ; &h or &H
# octal-digit = "0" / "1" / "2" / "3" / "4" / "5" / "6" / "7"
# decimal-digit = octal-digit / "8" / "9"
# hex-digit = decimal-digit / %x0041-0046 / %x0061-0066 ;A-F / a-f

# here Combine() is required to avoid spaces between elements:
decimal_literal = Combine(pyparsing_common.signed_integer + Suppress(Optional(Word('%&^', exact=1))))
decimal_literal.setParseAction(lambda t: int(t[0]))

octal_literal = Combine(Suppress(Literal('&') + Optional((CaselessLiteral('o')))) + Word(srange('[0-7]'))
                        + Suppress(Optional(Word('%&^', exact=1))))
octal_literal.setParseAction(lambda t: int(t[0], base=8))

hex_literal = Combine(Suppress(CaselessLiteral('&h')) + Word(srange('[0-9a-fA-F]'))
                      + Suppress(Optional(Word('%&^', exact=1))))
hex_literal.setParseAction(lambda t: int(t[0], base=16))

integer = decimal_literal | octal_literal | hex_literal

# decimal_int = (WordStart(alphanums) + Word(nums))
# decimal_int.setParseAction(lambda t: int(t[0]))
# NOTE: here WordStart is to avoid matching a number preceded by letters (e.g. "VBT1"), when using scanString
# TO DO: remove WordStart if scanString is not used

# FLOAT = (floating-point-literal [floating-point-type-suffix] ) / (decimal-literal floating-
# point-type-suffix)
# floating-point-literal = (integer-digits exponent) / (integer-digits "." [fractional-digits]
# [exponent]) / ( "." fractional-digits [exponent])
# integer-digits = decimal-literal
# fractional-digits = decimal-literal
# exponent = exponent-letter [sign] decimal-literal
# exponent-letter = %x0044 / %x0045 / %x0064 / %x0065
# floating-point-type-suffix = "!" / "#" / "@"

# TODO: Handle exponents as needed.
float_literal = decimal_literal + Suppress(CaselessLiteral('.')) + decimal_literal + \
                Suppress(Optional(CaselessLiteral('!') | CaselessLiteral('#') | CaselessLiteral('@')))
float_literal.setParseAction(lambda t: float(str(t[0]) + "." + str(t[1])))

# --- QUOTED STRINGS ---------------------------------------------------------

# 3.3.4 String Tokens
# STRING = double-quote *string-character (double-quote / line-continuation / LINE-END)
# double-quote = %x0022 ; "
# string-character = NO-LINE-CONTINUATION ((double-quote double-quote) termination-character)
quoted_string = QuotedString('"', escQuote='""')
quoted_string.setParseAction(lambda t: str(t[0]))

quoted_string_keep_quotes = QuotedString('"', escQuote='""', unquoteResults=False)
quoted_string_keep_quotes.setParseAction(lambda t: str(t[0]))

# --- DATE TOKENS ------------------------------------------------------------

# TODO: 3.3.3 Date Tokens
# DATE = "#" *WSC [date-or-time *WSC] "#"
# date-or-time = (date-value 1*WSC time-value) / date-value / time-value
# date-value = left-date-value date-separator middle-date-value [date-separator right-date-
# value]
# left-date-value = decimal-literal / month-name
# middle-date-value = decimal-literal / month-name
# right-date-value = decimal-literal / month-name
# date-separator = 1*WSC / (*WSC ("/" / "-" / ",") *WSC)
# month-name = English-month-name / English-month-abbreviation
# English-month-name = "january" / "february" / "march" / "april" / "may" / "june" / "august" /
# "september" / "october" / "november" / "december" English-month-abbreviation = "jan" / "feb"
# / "mar" / "apr" / "jun" / "jul" / "aug" / "sep" / "oct" / "nov" / "dec"
# time-value = (hour-value ampm) / (hour-value time-separator minute-value [time-separator
# second-value] [ampm])
# hour-value = decimal-literal
# minute-value = decimal-literal
# second-value = decimal-literal
# time-separator = *WSC (":" / ".") *WSC
# ampm = *WSC ("am" / "pm" / "a" / "p")

# TODO: For now just handle a date literal as a string.
date_string = QuotedString('#')
date_string.setParseAction(lambda t: str(t[0]))

# --- FILE POINTER ---------------------------------------------------------------

file_pointer = Suppress('#') + decimal_literal
file_pointer.setParseAction(lambda t: "#" + str(t[0]))

# --- LITERALS ---------------------------------------------------------------

# TODO: 5.6.5 Literal Expressions

#literal = boolean_literal | pointer | integer | quoted_string | date_string | float_literal
literal = boolean_literal | integer | quoted_string | date_string | float_literal | file_pointer
literal.setParseAction(lambda t: t[0])

