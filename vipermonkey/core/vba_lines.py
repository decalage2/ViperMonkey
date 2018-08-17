#!/usr/bin/env python
"""
ViperMonkey: VBA Grammar - Lines

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

from logger import log

from pyparsing import *

# --- WSC = White Space Character --------------------------------------------

# Important: need to change the default pyparsing whitespace setting, because CRLF is not a whitespace for VBA.
# see MS-VBAL 3.2.2 page 25:
# WSC = (tab-character / eom-character /space-character / DBCS-whitespace / most-Unicode-class-Zs)
# tab-character = %x0009
# eom-character = %x0019
# space-character = %x0020
# DBCS-whitespace = %x3000
# most-Unicode-class-Zs = <all members of Unicode class Zs which are not CP2-characters>
# => see http://www.fileformat.info/info/unicode/category/Zs/list.htm

# TODO: add unicode WS characters, if unicode is properly supported

ParserElement.setDefaultWhitespaceChars(' \t\x19')

# IMPORTANT NOTE: it seems preferable NOT to use pyparsing's LineEnd()/lineEnd,
#                 but line_terminator instead (defined below)

# --- VBA Physical/Logical Lines ---------------------------------------------

# 3.2.1 Physical Line Grammar
# module-body-physical-structure = *source-line [non-terminated-line]
# source-line = *non-line-termination-character line-terminator
# non-terminated-line = *non-line-termination-character
# line-terminator = (%x000D %x000A) / %x000D / %x000A / %x2028 / %x2029
# non-line-termination-character = <any character other than %x000D / %x000A / %x2028 / %x2029>
non_line_termination_character = CharsNotIn('\x0D\x0A', exact=1)  # exactly one non_line_termination_character
line_terminator = Literal('\x0D\x0A') | Literal('\x0D') | Literal('\x0A')
non_terminated_line = Optional(CharsNotIn('\x0D\x0A'))  # any number of non_line_termination_character
source_line = Optional(CharsNotIn('\x0D\x0A')) + line_terminator
module_body_physical_structure = ZeroOrMore(source_line) + Optional(non_terminated_line)

# 3.2.2 Logical Line Grammar
# module-body-logical-structure = *extended-line
# extended-line = *(line-continuation / non-line-termination-character) line-terminator
# line-continuation = *WSC underscore *WSC line-terminator
# module-body-lines = *logical-line
# logical-line = LINE-START *extended-line LINE-END

# NOTE: according to tests with MS Office 2007, and contrary to MS-VBAL, the line continuation pattern requires at
#      least one whitespace before the underscore, but not after.
# line_continuation = (White(min=1) + '_' + White(min=0) + line_terminator).leaveWhitespace()
whitespaces = Word(' \t\x19').leaveWhitespace()
line_continuation = (whitespaces + '_' + Optional(whitespaces) + line_terminator).leaveWhitespace()
# replace line_continuation by a single space:
line_continuation.setParseAction(replaceWith(' '))
extended_line = Combine(ZeroOrMore(line_continuation | non_line_termination_character) + line_terminator)
module_body_logical_structure = ZeroOrMore(extended_line)
logical_line = LineStart() + ZeroOrMore(extended_line.leaveWhitespace()) + line_terminator  # rather than LineEnd()
module_body_lines = Combine(ZeroOrMore(logical_line))  # .setDebug()

# === FUNCTIONS ==============================================================

def vba_collapse_long_lines(vba_code):
    """
    Parse a VBA module code to detect continuation line characters (underscore) and
    collapse split lines. Continuation line characters are replaced by spaces.

    :param vba_code: str, VBA module code
    :return: str, VBA module code with long lines collapsed
    """
    # make sure the last line ends with a newline char, otherwise the parser breaks:
    if vba_code[-1] != '\n':
        vba_code += '\n'
    # return module_body_lines.parseString(vba_code, parseAll=True)[0]
    # quicker solution without pyparsing:
    # TODO: use a regex instead, to allow whitespaces after the underscore?
    vba_code = vba_code.replace(' _\r\n', ' ')
    vba_code = vba_code.replace(' _\r', ' ')
    vba_code = vba_code.replace(' _\n', ' ')
    return vba_code
