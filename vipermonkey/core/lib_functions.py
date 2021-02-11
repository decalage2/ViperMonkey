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

from curses_ascii import isprint
import logging
from pyparsing import *

from vba_object import *
from literals import *
import vb_str

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
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def to_python(self, context, params=None, indent=0):
        arg_str = to_python(self.arg, context)
        r = "core.vba_library.run_function(\"_Chr\", vm_context, [" + arg_str + "])"
        return r

    def return_type(self):
        return "STRING"
    
    def eval(self, context, params=None):

        # This is implemented in the common vba_library._Chr handler class.
        import vba_library
        chr_handler = vba_library._Chr()
        param = eval_arg(self.arg, context)
        return chr_handler.eval(context, [param])

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

        # This could be a asc(...) call or a reference to a variable called asc.
        # If there are parsed arguments it is a call.
        self.arg = None
        if (len(tokens) > 0):
            # Here the arg is expected to be either a character or a VBA_Object        
            self.arg = tokens[0]

    def to_python(self, context, params=None, indent=0):
        return "ord(" + to_python(self.arg, context) + ")"

    def return_type(self):
        return "INTEGER"
    
    def eval(self, context, params=None):

        # Are we just looking up a variable called 'asc'?
        if (self.arg is None):
            try:
                return context.get("asc")
            except KeyError:
                return "NULL"
        
        # Eval the argument.
        c = eval_arg(self.arg, context)

        # Don't modify the "**MATCH ANY**" special value.
        c_str = None
        try:
            c_str = str(c).strip()
        except UnicodeEncodeError:
            c_str = filter(isprint, c).strip()
        if (c_str == "**MATCH ANY**"):
            return c

        # Looks like Asc(NULL) is NULL?
        if (c == "NULL"):
            return 0
        
        # Calling Asc() on int?
        if (isinstance(c, int)):
            r = c
        else:

            # Got a string.

            # Should this match anything?
            if (c_str == "**MATCH ANY**"):
                r = "**MATCH ANY**"

            # This is an unmodified Asc() call.
            else:
                r = vb_str.get_ms_ascii_value(c_str)

        # Return the result.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Asc: return %r" % r)
        return r

    def __repr__(self):
        return 'Asc(%s)' % repr(self.arg)


# Asc()
# TODO: see MS-VBAL 6.1.2.11.1.1 page 240 => AscB, AscW
asc = Suppress((CaselessKeyword('Asc') | CaselessKeyword('AscW')))  + Optional(Suppress('(') + expression + Suppress(')'))
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

    def return_type(self):
        return "STRING"
        
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

    def return_type(self):
        return "STRING"        

    def eval(self, context, params=None):
        # return the environment variable name surrounded by % signs:
        # e.g. Environ("TEMP") => "%TEMP%"
        arg = eval_arg(self.arg, context=context)
        value = '%%%s%%' % arg
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('evaluating Environ(%s) => %r' % (arg, value))
        return value

    def __repr__(self):
        return 'Environ(%s)' % repr(self.arg)

# Environ("name") => just translated to "%name%", that is enough for malware analysis
environ = Suppress(CaselessKeyword('Environ') + '(') + expression('arg') + Suppress(')')
environ.setParseAction(Environ)
