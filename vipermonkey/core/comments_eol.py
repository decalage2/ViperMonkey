#!/usr/bin/env python
"""
ViperMonkey: VBA Grammar - Comments and End of Line

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

from vba_lines import line_terminator

from logger import log
log.debug('importing comments_eol')


# --- COMMENT ----------------------------------------------------------------

# 3.3.1 Separator and Special Tokens
# single-quote = %x0027 ; '
# comment-body = *(line-continuation / non-line-termination-character) LINE-END
single_quote = Literal("'")
comment_body = SkipTo(line_terminator)  # + line_terminator
# NOTE: the comment body should NOT include the line terminator

# single quote comment
comment_single_quote = Combine(single_quote + comment_body)

# 5.4.1.2 Rem Statement
# rem-statement = "Rem" comment-body
rem_statement = Suppress(Combine(CaselessKeyword('Rem') + comment_body))


# --- SEPARATOR AND SPECIAL TOKENS ---------------------------------------

# 3.3.1 Separator and Special Tokens
# WS = 1*(WSC / line-continuation)
# special-token = "," / "." / "!" / "#" / "&" / "(" / ")" / "*" / "+" / "-" / "/" / ":" / ";"
# / "<" / "=" / ">" / "?" / "\" / "^"
# NO-WS = <no whitespace characters allowed here>
# NO-LINE-CONTINUATION = <a line-continuation is not allowed here>
# EOL = [WS] LINE-END / single-quote comment-body
# EOS = *(EOL / ":") ;End Of Statement

# End Of Line, INCLUDING line terminator
EOL = Optional(comment_single_quote) + line_terminator

# End Of Statement, INCLUDING line terminator
EOS = Suppress(Optional(";")) + OneOrMore(EOL | Literal(':'))

