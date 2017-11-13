#!/usr/bin/env python
"""
ViperMonkey: VBA Library

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

import math

from vba_context import VBA_LIBRARY

from logger import log
log.debug('importing vba_library')


# === VBA LIBRARY ============================================================

# TODO: Word 2013 object model reference: https://msdn.microsoft.com/EN-US/library/office/ff837519.aspx
# TODO: Excel
# TODO: other MS Office apps?

class MsgBox(object):
    """
    6.1.2.8.1.13 MsgBox
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        context.report_action('Display Message', params[0], 'MsgBox')
        return 1  # vbOK


class Len(object):
    """
    TODO: Len
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        return len(params[0])


class Mid(object):
    """
    6.1.2.11.1.25 Mid / MidB function

    IMPORTANT NOTE: Not to be confused with the Mid statement 5.4.3.5!
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        if ((len(params) > 0) and (params[0] == "ActiveDocument")):
            params = params[1:]
        assert len(params) in (2,3)
        s = params[0]
        # "If String contains the data value Null, Null is returned."
        if s == None: return None
        if not isinstance(s, basestring):
            s = str(s)
        start = params[1]
        assert isinstance(start, int)
        # "If Start is greater than the number of characters in String,
        # Mid returns a zero-length string ("")."
        if start>len(s):
            log.debug('Mid: start>len(s) => return ""')
            return ''
        # What to do when start<=0 is not specified:
        if start<=0:
            start = 1
        # If length not specified, return up to the end of the string:
        if len(params) == 2:
            log.debug('Mid: no length specified, return s[%d:]=%r' % (start-1, s[start-1:]))
            return s[start-1:]
        length = params[2]
        assert isinstance(length, int)
        # "If omitted or if there are fewer than Length characters in the text
        # (including the character at start), all characters from the start
        # position to the end of the string are returned."
        if start+length-1 > len(s):
            log.debug('Mid: start+length-1>len(s), return s[%d:]' % (start-1))
            return s[start-1:]
        # What to do when length<=0 is not specified:
        if length <= 0:
            return ''
        log.debug('Mid: return s[%d:%d]=%r' % (start - 1, start-1+length, s[start - 1:start-1+length]))
        return s[start - 1:start-1+length]

class Left(object):
    """
    Left function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        if (len(params) > 2):
            params = params[-2:]
        assert len(params) == 2
        s = params[0]
        # "If String contains the data value Null, Null is returned."
        if s == None: return None
        if not isinstance(s, basestring):
            s = str(s)
        start = params[1]
        assert isinstance(start, int)
        # "If Start is greater than the number of characters in String,
        # Left returns the whole string.
        if start>len(s):
            log.debug('Left: start>len(s) => return s')
            return s
        # Return empty string if start <= 0.
        if start<=0:
            return ""

        # Return characters from start of string.
        r = s[:start]
        log.debug('Left: return s[0:%d]=%r' % (start, r))
        return r

class Right(object):
    """
    Right function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        if (len(params) > 2):
            params = params[-2:]
        assert len(params) == 2
        s = params[0]
        # "If String contains the data value Null, Null is returned."
        if s == None: return None
        if not isinstance(s, basestring):
            s = str(s)
        start = params[1]
        assert isinstance(start, int)
        # "If Start is greater than the number of characters in String,
        # Right returns the whole string.
        if start>len(s):
            log.debug('Right: start>len(s) => return s')
            return s
        # Return empty string if start <= 0.
        if start<=0:
            return ""

        # Return characters from end of string.
        r = s[(len(s) - start):]
        log.debug('Right: return s[%d:]=%r' % (start, r))
        return r

meta = None
    
class BuiltInDocumentProperties(object):
    """
    Simulate calling ActiveDocument.BuiltInDocumentProperties('PROPERTYNAME')
    """

    def eval(self, context, params=None):

        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert len(params) == 1
        prop = params[0]

        # Make sure we read in the metadata.
        if (meta is None):
            log.error("BuiltInDocumentProperties: Metadata not read.")
            return ""
                
        # See if we can find the metadata attribute.
        if (not hasattr(meta, prop.lower())):
            log.error("BuiltInDocumentProperties: Metadata field '" + prop + "' not found.")
            return ""

        # We have the attribute. Return it.
        r = getattr(meta, prop.lower())
        log.debug("BuiltInDocumentProperties: return %r -> %r" % (prop, r))
        return r

class Item(BuiltInDocumentProperties):
    """
    Assumes that Item() is only called on BuiltInDocumentProperties.
    """
    pass
    
class Shell(object):
    """
    6.1.2.8.1.15 Shell
    Function Shell(PathName As Variant, Optional WindowStyle As VbAppWinStyle = vbMinimizedFocus)
    As Double

    Runs an executable program and returns a Double representing the implementation-defined
    program's task ID if successful, otherwise it returns the data value 0.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        try:
            params.remove('ThisDocument')
            params.remove('BuiltInDocumentProperties')
        except:
            pass
        command = params[0]
        log.info('Shell(%r)' % command)
        context.report_action('Execute Command', command, 'Shell function')
        return 0

class Array(object):
    """
    Create an array.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        r = []
        for v in params:
            r.append(v)
        log.debug("Array: return %r" % r)
        return r

class UBound(object):
    """
    UBound() array function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert len(params) > 0
        arr = params[0]
        # TODO: Handle multidimensional arrays.
        r = len(arr) - 1
        log.debug("UBound: return %r" % r)
        return r

class LBound(object):
    """
    LBound() array function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert len(params) > 0
        arr = params[0]
        # TODO: Handle multidimensional arrays.
        r = 0
        log.debug("LBound: return %r" % r)
        return r

class Trim(object):
    """
    Trim() string function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert len(params) > 0
        r = params[0].strip()
        log.debug("Trim: return %r" % r)
        return r

class StrConv(object):
    """
    StrConv() string function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert len(params) > 0
        # TODO: Actually implement this.
        r = str(params[0])
        log.debug("StrConv: return %r" % r)
        return r

class Split(object):
    """
    Split() string function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert len(params) > 0
        # TODO: Actually implement this properly.
        string = params[0]
        sep = ","
        if (len(params) > 1):
            sep = params[1]        
        r = string.split(sep)
        log.debug("Split: return %r" % r)
        return r

class Int(object):
    """
    Int() function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert len(params) > 0
        # TODO: Actually implement this properly.
        val = params[0]
        r = int(val)
        log.debug("Int: return %r" % r)
        return r

class StrReverse(object):
    """
    StrReverse() string function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert len(params) > 0
        # TODO: Actually implement this properly.
        string = params[0]
        r = string[::-1]
        log.debug("StrReverse: return %r" % r)
        return r

class Replace(object):
    """
    Replace() string function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert len(params) == 3
        string = params[0]
        pat = params[1]
        rep = params[2]
        r = string.replace(pat, rep)
        log.debug("Replace: return %r" % r)
        return r

class InStr(object):
    """
    InStr() string function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert len(params) >= 2

        # Were we given a start position?
        start = 0
        s1 = params[0]
        s2 = params[1]
        if (isinstance(params[0], int)):
            start = params[0] - 1
            if (start < 0):
                start = 0
            s1 = params[1]
            s2 = params[2]

        # Were we given a search type?
        search_type = 1
        if (isinstance(params[-1], int)):
            search_type = params[-1]
            if (search_type not in (0, 1)):
                search_type = 1

        # TODO: Figure out how VB binary search works. For now just do text search.
        r = None
        if (len(s1) == 0):
            r = 0
        elif (len(s2) == 0):
            r = start
        elif (start > len(s1)):
            r = 0
        else:
            if (s2 in s1):
                r = s1[start:].index(s2) + start + 1
            else:
                r = 0
        log.debug("InStr: %r returns %r" % (self, r))
        return r

class Sgn(object):
    """
    Sgn() math function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 1 and isinstance(params[0], int))
        num = params[0]
        r = int(math.copysign(1, num))
        log.debug("Sgn: %r returns %r" % (self, r))
        return r

class Sqr(object):
    """
    Sqr() math function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 1)
        num = params[0]
        r = math.sqrt(num)
        log.debug("Sqr: %r returns %r" % (self, r))
        return r

for _class in (MsgBox, Shell, Len, Mid, Left, Right,
               BuiltInDocumentProperties, Array, UBound, LBound, Trim,
               StrConv, Split, Int, Item, StrReverse, InStr, Replace,
               Sgn, Sqr):
    name = _class.__name__.lower()
    VBA_LIBRARY[name] = _class()

log.debug('VBA Library contains: %s' % ', '.join(VBA_LIBRARY.keys()))

# --- VBA CONSTANTS ----------------------------------------------------------

# TODO: 6.1.1 Predefined Enums => complete the library here

for name, value in (
        # 6.1.1.12 VbMsgBoxStyle
        ('vbAbortRetryIgnore', 2),
        ('vbApplicationModal', 0),
        ('vbCritical', 16),
        ('vbDefaultButton1', 0),
        ('vbDefaultButton2', 256),
        ('vbDefaultButton3', 512),
        ('vbDefaultButton4', 768),
        ('vbExclamation', 48),
        ('vbInformation', 64),
        ('vbMsgBoxHelpButton', 16384),
        ('vbMsgBoxRight', 524288),
        ('vbMsgBoxRtlReading', 1048576),
        ('vbMsgBoxSetForeground', 65536),
        ('vbOKCancel', 1),
        ('vbOKOnly', 0),
        ('vbQuestion', 32),
        ('vbRetryCancel', 5),
        ('vbSystemModal', 4096),
        ('vbYesNo', 4),
        ('vbYesNoCancel', 3),

        # 6.1.2.2 Constants Module
        ('vbBack', '\n'),
        ('vbCr', '\r'),
        ('vbCrLf', '\r\n'),
        ('vbFormFeed', '\f'),
        ('vbLf', '\n'),
        ('vbNewLine', '\r\n'),
        ('vbNullChar', '\x00'),
        ('vbTab', '\t'),
        ('vbVerticalTab', '\v'),
        ('vbNullString', None),
        ('vbObjectError', -2147221504),
):
    VBA_LIBRARY[name.lower()] = value


