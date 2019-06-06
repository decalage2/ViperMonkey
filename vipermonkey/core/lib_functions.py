#!/usr/bin/env python
"""
ViperMonkey: VBA Grammar - Library Functions

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

from vba_object import *
from literals import *

from logger import log

# --- VBA Expressions ---------------------------------------------------------

# 5.6 Expressions
# See below

# any VBA expression: need to pre-declare using Forward() because it is recursive
expression = Forward()

# --- CHR --------------------------------------------------------------------

class Chr(VBA_Object):
    """
    6.1.2.11.1.4 VBA Chr function
    """

    def __init__(self, original_str, location, tokens):
        super(Chr, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # Here the arg is expected to be either an int or a VBA_Object
        self.arg = tokens[0]
        log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def eval(self, context, params=None):
        # NOTE: in the specification, the parameter is expected to be an integer
        # But in reality, VBA accepts a string containing the representation
        # of an integer in decimal, hexadecimal or octal form.
        # It also ignores leading and trailing spaces.
        # Examples: Chr("65"), Chr("&65 "), Chr(" &o65"), Chr("  &H65")
        # => need to parse the string as integer
        # It also looks like floating point numbers are allowed.
        # First, eval the argument:
        param = eval_arg(self.arg, context)

        # Get the ordinal value.
        if isinstance(param, basestring):
            try:
                param = integer.parseString(param.strip())[0]
            except:
                log.error("%r is not a valid chr() value. Returning ''." % param)
                return ''            
        elif isinstance(param, float):
            log.debug('Chr: converting float %r to integer' % param)
            try:
                param = int(round(param))
            except:
                log.error("%r is not a valid chr() value. Returning ''." % param)
                return ''
        elif isinstance(param, int):
            pass
        else:
            log.error('Chr: parameter must be an integer or a string, not %s' % type(param))
            return ''
            
        # Figure out whether to create a unicode or ascii character.
        converter = chr
        if (param > 255):
            converter = unichr
        if (param < 0):
            param = param * -1
            
        # Do the conversion.
        try:
            r = converter(param)
            log.debug("Chr(" + str(param) + ") = " + r)
            return r
        except Exception as e:
            log.error(str(e))
            log.error("%r is not a valid chr() value. Returning ''." % param)
            return ""

    def __repr__(self):
        return 'Chr(%s)' % repr(self.arg)

# Chr, Chr$, ChrB, ChrW()
chr_ = (
    Suppress(Regex(re.compile('Chr[BW]?\$?', re.IGNORECASE)))
    + Suppress('(')
    + expression
    + Suppress(')')
)
chr_.setParseAction(Chr)

# --- ASC --------------------------------------------------------------------

class Asc(VBA_Object):
    """
    VBA Asc function
    """

    def __init__(self, original_str, location, tokens):
        super(Asc, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # Here the arg is expected to be either a character or a VBA_Object
        self.arg = tokens[0]

    def eval(self, context, params=None):
        r = 0
        try:
            r = ord(eval_arg(self.arg, context)[0])
        except:
            pass
        log.debug("Asc(%r): return %r" % (self.arg, r))
        return r

    def __repr__(self):
        return 'Asc(%s)' % repr(self.arg)


# Asc()
# TODO: see MS-VBAL 6.1.2.11.1.1 page 240 => AscB, AscW
asc = Suppress((CaselessKeyword('Asc') | CaselessKeyword('AscW'))  + '(') + expression + Suppress(')')
asc.setParseAction(Asc)

# --- StrReverse() --------------------------------------------------------------------

class StrReverse(VBA_Object):
    """
    VBA StrReverse function
    """

    def __init__(self, original_str, location, tokens):
        super(StrReverse, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # Here the arg is expected to be either a string or a VBA_Object
        self.arg = tokens[0]

    def eval(self, context, params=None):
        # return the string with all characters in reverse order:
        return eval_arg(self.arg, context)[::-1]

    def __repr__(self):
        return 'StrReverse(%s)' % repr(self.arg)

# StrReverse()
strReverse = Suppress(CaselessLiteral('StrReverse') + Literal('(')) + expression + Suppress(Literal(')'))
strReverse.setParseAction(StrReverse)

# --- ENVIRON() --------------------------------------------------------------------

class Environ(VBA_Object):
    """
    VBA Environ function
    """

    def __init__(self, original_str, location, tokens):
        super(Environ, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # Here the arg is expected to be either a string or a VBA_Object
        self.arg = tokens.arg

    def eval(self, context, params=None):
        # return the environment variable name surrounded by % signs:
        # e.g. Environ("TEMP") => "%TEMP%"
        arg = eval_arg(self.arg, context=context)
        value = '%%%s%%' % arg
        log.debug('evaluating Environ(%s) => %r' % (arg, value))
        return value

    def __repr__(self):
        return 'Environ(%s)' % repr(self.arg)

# Environ("name") => just translated to "%name%", that is enough for malware analysis
environ = Suppress(CaselessKeyword('Environ') + '(') + expression('arg') + Suppress(')')
environ.setParseAction(Environ)
