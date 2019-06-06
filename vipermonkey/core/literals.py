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

import re

from pyparsing import *

from logger import log
from vba_object import VBA_Object

# --- BOOLEAN ------------------------------------------------------------

boolean_literal = Regex(re.compile('(True|False)', re.IGNORECASE))
boolean_literal.setParseAction(lambda t: bool(t[0].lower() == 'true'))

# --- NUMBER TOKENS ----------------------------------------------------------

# 3.3.2 Number Tokens
#
# MS-GRAMMAR: INTEGER = integer-literal ["%" / "&" / "^"]
# MS-GRAMMAR: integer-literal = decimal-literal / octal-literal / hex-literal
# MS-GRAMMAR: decimal-literal = 1*decimal-digit
# MS-GRAMMAR: octal-literal = "&" [%x004F / %x006F] 1*octal-digit ; & or &o or &O
# MS-GRAMMAR: hex-literal = "&" (%x0048 / %x0068) 1*hex-digit; &h or &H
# MS-GRAMMAR: octal-digit = "0" / "1" / "2" / "3" / "4" / "5" / "6" / "7"
# MS-GRAMMAR: decimal-digit = octal-digit / "8" / "9"
# MS-GRAMMAR: hex-digit = decimal-digit / %x0041-0046 / %x0061-0066 ;A-F / a-f

# here Combine() is required to avoid spaces between elements:
decimal_literal = Regex(re.compile('(?P<value>[+\-]?\d+)[%&^]?[!#@]?'))
decimal_literal.setParseAction(lambda t: int(t.value))

octal_literal = Regex(re.compile('&o?(?P<value>[0-7]+)[%&^]?', re.IGNORECASE))
octal_literal.setParseAction(lambda t: int(t.value, base=8))

hex_literal = Regex(re.compile('&h(?P<value>[0-9a-f]+)[%&^]?', re.IGNORECASE))
hex_literal.setParseAction(lambda t: int(t.value, base=16))

integer = decimal_literal | octal_literal | hex_literal

# MS-GRAMMAR: decimal_int = (WordStart(alphanums) + Word(nums))
# MS-GRAMMAR: decimal_int.setParseAction(lambda t: int(t[0]))
#
# NOTE: here WordStart is to avoid matching a number preceded by letters (e.g. "VBT1"), when using scanString
# TO DO: remove WordStart if scanString is not used

# MS-GRAMMAR: FLOAT = (floating-point-literal [floating-point-type-suffix] ) / (decimal-literal floating-
# MS-GRAMMAR: point-type-suffix)
# MS-GRAMMAR: floating-point-literal = (integer-digits exponent) / (integer-digits "." [fractional-digits]
# MS-GRAMMAR: [exponent]) / ( "." fractional-digits [exponent])
# MS-GRAMMAR: integer-digits = decimal-literal
# MS-GRAMMAR: fractional-digits = decimal-literal
# MS-GRAMMAR: exponent = exponent-letter [sign] decimal-literal
# MS-GRAMMAR: exponent-letter = %x0044 / %x0045 / %x0064 / %x0065
# MS-GRAMMAR: floating-point-type-suffix = "!" / "#" / "@"

float_literal = Regex(re.compile('(?P<value>[+\-]?\d+\.\d*([eE][+\-]?\d+)?)[!#@]?'))
float_literal.setParseAction(lambda t: float(t.value))
# --- QUOTED STRINGS ---------------------------------------------------------

# 3.3.4 String Tokens
#
# MS-GRAMMAR: STRING = double-quote *string-character (double-quote / line-continuation / LINE-END)
# MS-GRAMMAR: double-quote = %x0022 ; "
# MS-GRAMMAR: string-character = NO-LINE-CONTINUATION ((double-quote double-quote) termination-character)

class String(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(String, self).__init__(original_str, location, tokens)
        self.value = tokens[0]
        if (self.value.startswith('"') and self.value.endswith('"')):
            self.value = self.value[1:-1]
        # Replace Python control characters.
        """
        self.value = self.value.\
                     replace("\0","\\0").\
                     replace("\1","\\1").\
                     replace("\2","\\2").\
                     replace("\3","\\3").\
                     replace("\4","\\4").\
                     replace("\5","\\5").\
                     replace("\6","\\6").\
                     replace("\7","\\7").\
                     replace("\n", "\\n").\
                     replace("\t", "\\t").\
                     replace("\f", "\\f").\
                     replace("\a", "\\a").\
                     replace("\b", "\\b").\
                     replace("\r", "\\r").\
                     replace("\v", "\\v")
        """
        # Some maldocs use the above characters in strings to decode. Replacing
        # them breaks decoding, so they are commented out until something else
        # breaks.
        self.value = self.value.\
                     replace("\0","\\0").\
                     replace("\n", "\\n").\
                     replace("\t", "\\t").\
                     replace("\f", "\\f").\
                     replace("\b", "\\b").\
                     replace("\r", "\\r").\
                     replace("\v", "\\v")
        
        log.debug('parsed "%r" as String' % self)

    def __repr__(self):
        return str(self.value)

    def eval(self, context, params=None):
        r = self.value
        log.debug("String.eval: return " + r)
        return r

# NOTE: QuotedString creates a regex, so speed should not be an issue.
quoted_string = (QuotedString('"', escQuote='""') | QuotedString("'", escQuote="''"))('value')
quoted_string.setParseAction(String)

quoted_string_keep_quotes = QuotedString('"', escQuote='""', unquoteResults=False)
quoted_string_keep_quotes.setParseAction(lambda t: str(t[0]))

# --- DATE TOKENS ------------------------------------------------------------

# TODO: 3.3.3 Date Tokens
#
# MS-GRAMMAR: DATE = "#" *WSC [date-or-time *WSC] "#"
# MS-GRAMMAR: date-or-time = (date-value 1*WSC time-value) / date-value / time-value
# MS-GRAMMAR: date-value = left-date-value date-separator middle-date-value [date-separator right-date-
# value]
# MS-GRAMMAR: left-date-value = decimal-literal / month-name
# MS-GRAMMAR: middle-date-value = decimal-literal / month-name
# MS-GRAMMAR: right-date-value = decimal-literal / month-name
# MS-GRAMMAR: date-separator = 1*WSC / (*WSC ("/" / "-" / ",") *WSC)
# MS-GRAMMAR: month-name = English-month-name / English-month-abbreviation
# MS-GRAMMAR: English-month-name = "january" / "february" / "march" / "april" / "may" / "june" / "august" / "september" / "october" / "november" / "december"
# MS-GRAMMAR: English-month-abbreviation = "jan" / "feb" / "mar" / "apr" / "jun" / "jul" / "aug" / "sep" / "oct" / "nov" / "dec"
# MS-GRAMMAR: time-value = (hour-value ampm) / (hour-value time-separator minute-value [time-separator
# MS-GRAMMAR: second-value] [ampm])
# MS-GRAMMAR: hour-value = decimal-literal
# MS-GRAMMAR: minute-value = decimal-literal
# MS-GRAMMAR: second-value = decimal-literal
# MS-GRAMMAR: time-separator = *WSC (":" / ".") *WSC
# MS-GRAMMAR: ampm = *WSC ("am" / "pm" / "a" / "p")

# TODO: For now just handle a date literal as a string.
date_string = QuotedString('#')
date_string.setParseAction(lambda t: str(t[0]))

# --- LITERALS ---------------------------------------------------------------

# TODO: 5.6.5 Literal Expressions

literal = boolean_literal | integer | quoted_string | date_string | float_literal
literal.setParseAction(lambda t: t[0])

