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

__version__ = '0.02'

# --- IMPORTS ------------------------------------------------------------------

from datetime import datetime
import time
import array
import math
import base64
import re
from hashlib import sha256
import sys
import os
import random
from .from_unicode_str import *
from .vba_object import int_convert
from .vba_object import str_convert
import decimal

from .vba_context import VBA_LIBRARY
from .vba_object import eval_arg
from .vba_object import VbaLibraryFunc
from .vba_object import excel_col_letter_to_index
from . import expressions

from .logger import log

from .setting import COUNTRY

# === VBA LIBRARY ============================================================

# TODO: Word 2013 object model reference: https://msdn.microsoft.com/EN-US/library/office/ff837519.aspx
# TODO: Excel
# TODO: other MS Office apps?

class Format(VbaLibraryFunc):
    """
    VBA Format function
    """

    def eval(self, context, params=None):
        r = params[0]
        log.debug("Format(%r): return %r" % (self, r))
        return r

class MsgBox(VbaLibraryFunc):
    """
    6.1.2.8.1.13 MsgBox
    """

    def eval(self, context, params=None):
        context.report_action('Display Message', params[0], 'MsgBox', strip_null_bytes=True)
        return 1  # vbOK

class Switch(VbaLibraryFunc):
    """
    Switch() logic flow function.
    """

    def eval(self, context, params=None):

        # We need an even number of parameters.
        if ((len(params) == 0) or
            (len(params) % 2 != 0)):
            return 'NULL'

        # Return the 1st true case.
        pos = 0
        while (pos < (len(params) - 1)):
            if (params[pos] == True):
                log.debug("Switch(%r): return %r" % (self, params[pos + 1]))
                return params[pos + 1]
            pos += 2

        # If we get here nothing is true.
        return 'NULL'
            
class Len(VbaLibraryFunc):
    """
    Len() function.
    """

    def eval(self, context, params=None):
        val = str_convert(params[0])
        if (hasattr(params[0], '__len__')):
            return len(val)
        else:
            log.error("Len: " + str(type(params[0])) + " object has no len(). Returning 0.")
            return 0

class LenB(VbaLibraryFunc):
    """
    LenB() function.
    """

    def eval(self, context, params=None):
        # TODO: Somehow take the default character set into account.
        return len(params[0])

class Sleep(VbaLibraryFunc):
    """
    Stubbed Sleep() function.
    """

    def eval(self, context, params=None):
        pass

class Mid(VbaLibraryFunc):
    """
    6.1.2.11.1.25 Mid / MidB function

    IMPORTANT NOTE: Not to be confused with the Mid statement 5.4.3.5!
    """

    def eval(self, context, params=None):
        if ((len(params) > 0) and (params[0] == "ActiveDocument")):
            params = params[1:]
        assert len(params) in (2,3)
        s = params[0]
        # "If String contains the data value Null, Null is returned."
        if s == None: return None
        if not isinstance(s, str):
            s = str(s)
        start = 0
        try:
            start = int_convert(params[1])
        except:
            pass
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
        length = 0
        try:
            length = int_convert(params[2])
        except:
            pass
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

class MidB(Mid):
    pass

class Left(VbaLibraryFunc):
    """
    Left function.
    """

    def eval(self, context, params=None):
        if (len(params) > 2):
            params = params[-2:]
        assert len(params) == 2
        s = params[0]
        # "If String contains the data value Null, Null is returned."
        if s == None: return None
        if not isinstance(s, str):
            s = str(s)
        start = 0
        try:
            start = int_convert(params[1])
        except:
            pass
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

class Right(VbaLibraryFunc):
    """
    Right function.
    """

    def eval(self, context, params=None):
        if (len(params) > 2):
            params = params[-2:]
        assert len(params) == 2
        s = params[0]
        # "If String contains the data value Null, Null is returned."
        if s == None: return None
        if not isinstance(s, str):
            s = str(s)
        start = 0
        try:
            start = int_convert(params[1])
        except:
            pass
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
    
class BuiltInDocumentProperties(VbaLibraryFunc):
    """
    Simulate calling ActiveDocument.BuiltInDocumentProperties('PROPERTYNAME')
    """

    def eval(self, context, params=None):

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
    
class Shell(VbaLibraryFunc):
    """
    6.1.2.8.1.15 Shell
    Function Shell(PathName As Variant, Optional WindowStyle As VbAppWinStyle = vbMinimizedFocus)
    As Double

    Runs an executable program and returns a Double representing the implementation-defined
    program's task ID if successful, otherwise it returns the data value 0.
    """

    def eval(self, context, params=None):
        try:
            params.remove('ThisDocument')
            params.remove('BuiltInDocumentProperties')
        except:
            pass
        command = params[0]
        log.debug("Shell command type: " + str(type(command)))
        log.info('Shell(%r)' % command)
        context.report_action('Execute Command', command, 'Shell function', strip_null_bytes=True)
        return 0

class Array(VbaLibraryFunc):
    """
    Create an array.
    """

    def eval(self, context, params=None):
        r = []
        for v in params:
            r.append(v)
        log.debug("Array: return %r" % r)
        return r

class UBound(VbaLibraryFunc):
    """
    UBound() array function.
    """

    def eval(self, context, params=None):
        assert len(params) > 0
        arr = params[0]
        # TODO: Handle multidimensional arrays.
        if (arr is None):
            log.error("UBound(None) cannotbe computed.")
            return 0
        r = len(arr) - 1
        log.debug("UBound: return %r" % r)
        return r

class LBound(VbaLibraryFunc):
    """
    LBound() array function.
    """

    def eval(self, context, params=None):
        assert len(params) > 0
        arr = params[0]
        # TODO: Handle multidimensional arrays.
        r = 0
        log.debug("LBound: return %r" % r)
        return r

class Trim(VbaLibraryFunc):
    """
    Trim() string function.
    """

    def eval(self, context, params=None):
        assert len(params) > 0
        r = None
        if (isinstance(params[0], int)):
            r = str(params[0])
        else:
            r = params[0].strip()
        log.debug("Trim: return %r" % r)
        return r

class RTrim(VbaLibraryFunc):
    """
    RTrim() string function.
    """

    def eval(self, context, params=None):
        assert len(params) > 0
        r = None
        if (isinstance(params[0], int)):
            r = str(params[0])
        else:
            r = params[0].rstrip()
        log.debug("RTrim: return %r" % r)
        return r

class LTrim(VbaLibraryFunc):
    """
    LTrim() string function.
    """

    def eval(self, context, params=None):
        assert len(params) > 0
        r = None
        if (isinstance(params[0], int)):
            r = str(params[0])
        else:
            r = params[0].lstrip()
        log.debug("LTrim: return %r" % r)
        return r

class AscW(VbaLibraryFunc):
    """
    AscW() character function.
    """

    def eval(self, context, params=None):
        assert len(params) == 1
        c = params[0]
        if (isinstance(c, int)):
            r = c
        else:
            r = ord(str(c)[0])
        log.debug("AscW: return %r" % r)
        return r

class AscB(AscW):
    pass

class StrComp(VbaLibraryFunc):
    """
    StrComp() string function.
    """

    def eval(self, context, params=None):
        assert len(params) >= 2
        s1 = params[0]
        s2 = params[1]
        method = 0
        if (len(params) >= 3):
            try:
                method = int_convert(params[2])
            except Exception as e:
                log.error("StrComp: Invalid comparison method. " + str(e))
                pass
        if (method == 0):
            s1 = s1.lower()
            s2 = s2.lower()
        if (s1 == s2):
            return 0
        if (s1 < s2):
            return -1
        return 1
                
class StrConv(VbaLibraryFunc):
    """
    StrConv() string function.
    """

    def eval(self, context, params=None):
        assert len(params) > 0

        # TODO: Actually implement this properly.

        # Get the conversion type to perform.
        conv = None
        if (len(params) > 1):
            conv = int_convert(eval_arg(params[1], context=context))

        # Do the conversion.
        r = params[0]
        if (isinstance(r, str)):
            if (conv):
                if (conv == 1):
                    r = r.upper()
                if (conv == 2):
                    r = r.lower()
                if (conv == 64):

                    # We are converting the string to unicode. ViperMonkey assumes
                    # unless otherwise noted that all strings are unicode. Make sure
                    # that the string is represented as a regular str object so that
                    # it is treated as unicode.
                    r = str(r)

                if (conv == 128):

                    # The string is being converted from unicode to ascii. Mark this
                    # by representing the string with the from_unicode_str class.
                    r = from_unicode_str(r)

        elif (isinstance(r, list)):

            # Handle list of ASCII values.
            all_int = True
            for i in r:
                if (not isinstance(i, int)):
                    all_int = False
                    break
            if (all_int):
                tmp = ""
                for i in r:
                    if (i < 0):
                        continue
                    try:
                        tmp += chr(i)
                        #if (conv == 64):
                        #    tmp += "\0"
                    except:
                        pass
                r = tmp

            else:
                log.error("StrConv: Unhandled type.")
                r = ''
                        
        log.debug("StrConv: return %r" % r)
        return r

class Assert(VbaLibraryFunc):
    """
    Assert() debug function. Stubbed.
    """

    def eval(self, context, params=None):
        pass

class Shapes(VbaLibraryFunc):
    """
    Shapes() object reference. Stubbed.
    """

    def eval(self, context, params=None):

        # Just return the string representation of the access. This is used in
        # vba_object._read_from_object_text()
        return "Shapes('" + str(params[0]) + "')"
    
class Split(VbaLibraryFunc):
    """
    Split() string function.
    """

    def eval(self, context, params=None):
        assert len(params) > 0
        # TODO: Actually implement this properly.
        string = params[0]
        sep = ","
        if ((len(params) > 1) and (isinstance(params[1], str))):
            sep = params[1]            
        r = string.split(sep)
        log.debug("Split: return %r" % r)
        return r

class VarType(VbaLibraryFunc):
    """
    VarType() function. NOTE: Currently stubbed.
    """

    def eval(self, context, params=None):
        assert len(params) > 0
        # TODO: Actually implement this properly.
        return 8
    
class Int(VbaLibraryFunc):
    """
    Int() function.
    """

    def eval(self, context, params=None):
        assert len(params) > 0
        # TODO: Actually implement this properly.
        val = params[0]
        try:
            if (isinstance(val, str) and (("e" in val) or ("E" in val))):
                r = int(decimal.Decimal(val))
            else:
                r = int_convert(val)
            if ((r > 2147483647) or (r < -2147483647)):
                r = "ERROR"
            log.debug("Int: return %r" % r)
            return r
        except Exception as e:
            log.error("Int(): Invalid call int(%r) [%s]. Returning ''." % (val, str(e)))
            return ''

class CInt(Int):
    """
    Same as Int() for our purposes.
    """
    pass

class Oct(VbaLibraryFunc):
    """
    Oct() function.
    """

    def eval(self, context, params=None):
        assert len(params) > 0
        val = params[0]
        try:
            r = oct(val)
            log.debug("Oct: return %r" % r)
            return r
        except:
            log.error("Oct(): Invalid call oct(%r). Returning ''." % val)
            return ''

class StrReverse(VbaLibraryFunc):
    """
    StrReverse() string function.
    """

    def eval(self, context, params=None):
        assert len(params) > 0
        # TODO: Actually implement this properly.
        string = params[0]
        if (string is None):
            string = ''
        r = string[::-1]
        log.debug("StrReverse: return %r" % r)
        return r

class Replace(VbaLibraryFunc):
    """
    Replace() string function.
    """

    def eval(self, context, params=None):
        assert len(params) == 3
        string = params[0]
        if (string is None):
            string = ''
        pat = params[1]
        if (pat is None):
            pat = ''
        rep = params[2]
        if ((rep is None) or (rep == 0)):
            rep = ''
        r = string.replace(pat, rep)
        log.debug("Replace: return %r" % r)
        return r

class Join(VbaLibraryFunc):
    """
    Join() string function.
    """

    def eval(self, context, params=None):
        assert len(params) > 0
        strings = params[0]
        sep = " "
        if (len(params) > 1):
            sep = str(params[1])
        r = ""
        if (isinstance(strings, list)):
            for s in strings:
                r += s + sep
        else:
            r = str(strings)
        log.debug("Join: return %r" % r)
        return r

class InStr(VbaLibraryFunc):
    """
    InStr() string function.
    """

    def eval(self, context, params=None):
        assert len(params) >= 2

        # Were we given a start position?
        start = 0
        s1 = params[0]
        if (s1 is None):
            s1 = ''
        s2 = params[1]
        if (s2 is None):
            s2 = ''
        if (isinstance(params[0], int)):
            if (len(params) < 3):
                return False
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

        # Only works on lists or strings.
        if ((not isinstance(s1, list)) and (not isinstance(s1, str))):
            return None
        if ((not isinstance(s2, list)) and (not isinstance(s2, str))):
            return None
                
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

class CVar(VbaLibraryFunc):
    """
    CVar() type conversion function.
    """

    def eval(self, context, params=None):
        assert len(params) >= 1

        # We are not tracking variant types, so work as a pass-through.
        return params[0]

class IsNumeric(VbaLibraryFunc):
    """
    IsNumeric() function.
    """

    def eval(self, context, params=None):
        assert len(params) >= 1

        arg = str(params[0])
        try:
            tmp = float(arg)
            return True
        except:
            return False
    
class InStrRev(VbaLibraryFunc):
    """
    InStrRev() string function.
    """

    def eval(self, context, params=None):
        assert len(params) >= 2

        # Were we given a start position?
        start = 0
        s1 = params[0]
        if (s1 is None):
            s1 = ''
        s2 = params[1]
        if (s2 is None):
            s2 = ''
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
                r = s1[start:].rindex(s2) + start + 1
            else:
                r = 0
        log.debug("InStr: %r returns %r" % (self, r))
        return r

    
class Sgn(VbaLibraryFunc):
    """
    Sgn() math function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        num = params[0]
        r = ''
        try:
            r = int(math.copysign(1, int_convert(num)))
        except:
            pass
        log.debug("Sgn: %r returns %r" % (self, r))
        return r
        
class Sqr(VbaLibraryFunc):
    """
    Sqr() math function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        r = ''
        try:
            num = int_convert(params[0]) + 0.0
            r = math.sqrt(num)
        except:
            pass
        log.debug("Sqr: %r returns %r" % (self, r))
        return r

class Abs(VbaLibraryFunc):
    """
    Abs() math function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        r = ''
        try:
            num = int_convert(params[0])
            r = abs(num)
        except:
            pass
        log.debug("Abs: %r returns %r" % (self, r))
        return r

class Fix(VbaLibraryFunc):
    """
    Fix() math function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        r = ''
        try:
            num = float(params[0])
            r = math.floor(num)
        except:
            pass
        log.debug("Fix: %r returns %r" % (self, r))
        return r

class Round(VbaLibraryFunc):
    """
    Round() math function.
    """

    def eval(self, context, params=None):
        assert ((len(params) == 1) or (len(params) == 2))
        r = ''
        try:
            num = float(params[0])
            sig = 0
            if (len(params) == 2):
                sig = int_convert(params(1))                
            r = round(num, sig)
        except:
            pass
        log.debug("Round: %r returns %r" % (self, r))
        return r

class Hex(VbaLibraryFunc):
    """
    Hex() math function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        r = ''
        try:
            num = int_convert(params[0])
            r = hex(num).replace("0x","").upper()
        except:
            pass
        log.debug("Hex: %r returns %r" % (self, r))
        return r

class CByte(VbaLibraryFunc):
    """
    CByte() math function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        r = ''
        try:
            tmp = params[0].upper()
            if (tmp.startswith("&H")):
                tmp = tmp.replace("&H", "0x")
                tmp = int(tmp, 16)
            num = int(round(float(tmp)))
            r = num
            if (r > 255):
                r = 255
        except:
            pass 
        log.debug("CByte: %r returns %r" % (self, r))
        return r

class CLng(VbaLibraryFunc):
    """
    CLng() math function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        r = ''
        try:
            tmp = params[0]
            if (isinstance(tmp, str)):
                tmp = params[0].upper()
                if (tmp.startswith("&H")):
                    tmp = tmp.replace("&H", "0x")
                    tmp = int(tmp, 16)
                elif (len(tmp) == 1):
                    tmp = ord(tmp)
            r = int(tmp)
        except:
            pass 
        log.debug("CLng: %r returns %r" % (self, r))
        return r
    
class CBool(VbaLibraryFunc):
    """
    CBool() type conversion function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        val = params[0]
        r = 0
        if ((val == True) or (val == 1)):
            r = 1
        log.debug("CBool: %r returns %r" % (self, r))
        return r

class CDate(VbaLibraryFunc):
    """
    CDate() type conversion function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        # TODO: For now this is stubbed out. Handling dates correctly is hard.
        r = 12345
        log.debug("CDate: %r returns %r" % (self, r))
        return r

class CStr(VbaLibraryFunc):
    """
    CStr() type conversion function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        val = params[0]
        r = str(val)
        log.debug("CStr: %r returns %r" % (self, r))
        return r

class CSng(VbaLibraryFunc):
    """
    CSng() type conversion function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        r = ''
        try:
            tmp = params[0].upper()
            if (tmp.startswith("&H")):
                tmp = tmp.replace("&H", "0x")
                tmp = int(tmp, 16)
            r = float(tmp)
        except:
            pass 
        log.debug("CSng: CSng(%r) returns %r" % (params[0], r))
        return r
    
class Atn(VbaLibraryFunc):
    """
    Atn() math function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        r = ''
        try:
            num = float(params[0])
            r = math.atan(num)
        except:
            pass
        log.debug("Atn: %r returns %r" % (self, r))
        return r

class Tan(VbaLibraryFunc):
    """
    Tan() math function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        r = ''
        try:
            num = float(params[0])
            r = math.tan(num)
        except:
            pass
        log.debug("Tan: %r returns %r" % (self, r))
        return r
        
class Cos(VbaLibraryFunc):
    """
    Cos() math function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        r = ''
        try:
            num = float(params[0])
            r = math.cos(num)
        except:
            pass
        log.debug("Cos: %r returns %r" % (self, r))
        return r
        
class Log(VbaLibraryFunc):
    """
    Log() math function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        r = ''
        try:
            num = float(params[0])
            r = math.log(num)
        except ValueError:
            pass
        log.debug("Log: %r returns %r" % (self, r))
        return r
    
class String(VbaLibraryFunc):
    """
    String() repeated character string creation function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 2)
        r = ''
        try:
            num = int_convert(params[0])
            char = params[1]
            r = char * num
        except:
            pass
        log.debug("String: %r returns %r" % (self, r))
        return r

class Dir(VbaLibraryFunc):
    """
    Dir() file/directory finding function.
    """

    def eval(self, context, params=None):
        assert (len(params) >= 1)
        pat = params[0]
        attrib = None
        # TODO: Handle multiple attributes.
        if (len(params) > 1):
            attrib = params[1]
        r = ""
        # TODO: Figure out how to simulate actual file searches.            
        log.debug("Dir: %r returns %r" % (self, r))
        return r

class RGB(VbaLibraryFunc):
    """
    RGB() color function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 3)
        r = ''
        try:
            red = int_convert(params[0])
            green = int_convert(params[1])
            blue = int_convert(params[2])
            r = red + (green * 256) + (blue * 65536)
        except:
            pass
        log.debug("RGB: %r returns %r" % (self, r))
        return r

class Exp(VbaLibraryFunc):
    """
    Exp() math function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        r = ''
        try:
            num = float(params[0])
            r = math.exp(num)
        except:
            pass
        log.debug("Exp: %r returns %r" % (self, r))
        return r
            
class Sin(VbaLibraryFunc):
    """
    Sin() math function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        r = ''
        try:
            num = float(params[0])
            r = math.sin(num)
        except:
            pass
        log.debug("Sin: %r returns %r" % (self, r))
        return r
            
class Str(VbaLibraryFunc):
    """
    Str() convert number to string function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        r = str(params[0])
        log.debug("Str: %r returns %r" % (self, r))
        return r

class Val(VbaLibraryFunc):
    """
    Val() convert string to number function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)

        # Sanity check.
        if ((params[0] is None) or (not isinstance(params[0], str))):
            r = ''
            log.debug("Str: %r returns %r" % (self, r))
            return r
        
        # Ignore whitespace.
        tmp = str_convert(params[0]).strip().replace(" ", "")

        # The VB Val() function is ugly. Look for VB hex encoding.
        nums = re.compile(r"&[Hh][0-9A-Fa-f]+")
        matches = nums.search(tmp)
        if (hasattr(matches, "group")):
            tmp = nums.search(tmp).group(0).replace("&H", "0x").replace("&h", "0x")
            r = float(int(tmp, 16))
            log.debug("Val: %r returns %r" % (self, r))
            return r
        
        # The VB Val() function is ugly. Try to use a regular expression to pick out
        # the 1st valid number string.
        nums = re.compile(r"[+-]?\d+(?:\.\d+)?")
        matches = nums.search(tmp)
        if (hasattr(matches, "group")):
            tmp = nums.search(tmp).group(0)

            # Convert this to a float or int.
            r = None
            if ("." in tmp):
                r = float(tmp)
            else:
                r = int(tmp)
            log.debug("Val: %r returns %r" % (self, r))
            return r

        # Can't find a valid number to convert. This is probably incorrect behavior.
        r = 0
        log.debug("Val: Invalid Value: %r returns %r" % (self, r))
        return r
    
class Base64Decode(VbaLibraryFunc):
    """
    Base64Decode() function used by some malware. Note that this is not part of Visual Basic.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        txt = params[0]
        if (txt is None):
            txt = ''
        r = base64.b64decode(txt)
        log.debug("Base64Decode: %r returns %r" % (self, r))
        return r

class Base64DecodeString(Base64Decode):
    pass
    
class CleanString(VbaLibraryFunc):
    """
    CleanString() function removes certain characters from the character stream, or translates them
    https://docs.microsoft.com/en-us/office/vba/api/word.application.cleanstring
    """

    def eval(self,context,params=None):
        assert (len(params) == 1)
        txt=params[0]
        if (txt is None):
            txt = ''
        if isinstance(txt,str):
            a = [c for c in txt]
            for i in range(len(a)):
                c = a[i]
                if ord(c) == 7:
                    if i>0 and ord(a[i-1]) == 13:
                        a[i] = chr(9)
                    else:
                        a[i] = ''
                if ord(c) == 10:
                    if i>0 and ord(a[i-1]) == 13:
                        a[i] = ''
                    else:
                        a[i] = chr(13)
                if ord(c) == 31 or ord(c) == 172 or ord(c) == 182:
                    a[i] = ''
                if ord(c) == 160 or ord(c) == 176 or ord(c) == 183:
                    a[i] = chr(32)
            r = "".join(a)
        else:
            # punt for things like CleanString(99), which shows up as an integer
            r = txt
        log.debug("CleanString: %r returns %r" % (self,r))
        return r

class Pmt(VbaLibraryFunc):
    """
    Pmt() payment computation function.

    Returns a Double specifying the payment for an annuity based on
    periodic, fixed payments and a fixed interest rate.

    Pmt(rate, nper, pv [, fv [, type ]] ) 

    The Pmt function has these named arguments:

    rate Required. Double specifying interest rate per period. For
    example, if you get a car loan at an annual percentage rate (APR)
    of 10 percent and make monthly payments, the rate per period is
    0.1/12, or 0.0083.

    nper Required. Integer specifying total number of payment periods
    in the annuity. For example, if you make monthly payments on a
    four-year car loan, your loan has a total of 4 * 12 (or 48)
    payment periods.

    pv Required. Double specifying present value (or lump sum) that a
    series of payments to be paid in the future is worth now. For
    example, when you borrow money to buy a car, the loan amount is
    the present value to the lender of the monthly car payments you
    will make.

    fv Optional. Variant specifying future value or cash balance you
    want after you've made the final payment. For example, the future
    value of a loan is $0 because that's its value after the final
    payment. However, if you want to save $50,000 over 18 years for
    your child's education, then $50,000 is the future value. If
    omitted, 0 is assumed.

    type Optional. Variant specifying when payments are due. Use 0 if
    payments are due at the end of the payment period, or use 1 if
    payments are due at the beginning of the period. If omitted, 0 is
    assumed.

    '               This function, together with the four following
    '               it (Pv, Fv, NPer and Rate), can calculate
    '               a certain value associated with a regular series of
    '               equal-sized payments.  This series can be fully described
    '               by these values:
    '                     Pv   - present value
    '                     Fv   - future value (at end of series)
    '                     PMT  - the regular payment
    '                     nPer - the number of 'periods' over which the
    '                            money is paid
    '                     Rate - the interest rate per period.
    '                            (type - payments at beginning (1) or end (0) of
    '                            the period).
    '               Each function can determine one of the values, given the others.
    '
    '               General Function for the above values:
    '
    '                                                      (1+rate)^nper - 1
    '               pv * (1+rate)^nper + PMT*(1+rate*type)*----------------- + fv  = 0
    '                                                            rate
    '               rate == 0  ->  pv + PMT*nper + fv = 0
    '
    '               Thus:
    '                     (-fv - pv*(1+rate)^nper) * rate
    '               PMT = -------------------------------------
    '                     (1+rate*type) * ( (1+rate)^nper - 1 )
    '
    '               PMT = (-fv - pv) / nper    : if rate == 0
    """
    def eval(self, context, params=None):
        assert (len(params) >= 3)

        r = ''
        try:
            # Pull out the arguments.
            rate = float(params[0])
            nper = int_convert(params[1]) + 0.0
            pv = float(params[2])
            fv = 0
            if (len(params) >= 4):
                fv = float(params[3])
            typ = 0
            if (len(params) >= 5):
                typ = float(params[4])

            # Compute the payments.
            if (((1 + rate * typ) * (pow(1 + rate, nper) - 1)) != 0):
                r = ((-fv - pv * pow(1 + rate, nper)) * rate)/((1 + rate * typ) * (pow(1 + rate, nper) - 1))
            else:
                r = 0
        except:
            pass
        
        log.debug("Pmt: %r returns %r" % (self, r))
        return r

class Day(VbaLibraryFunc):
    """
    Day() function. This is currently partially implemented.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        txt = params[0]
        if ((txt is None) or (txt == "NULL")):
            txt = ''
        r = str(txt)

        # It looks like this should pull the day out of a date string. See if we can
        # handle a simple date string.
        f = r.split("/")
        if (len(f) == 3):
            try:
                r = int(f[1])
            except:
                pass

        log.debug("Day: %r returns %r" % (self, r))
        return r

class Space(VbaLibraryFunc):
    """
    Space() string function.
    """

    def eval(self, context, params=None):
        n = int_convert(params[0])
        r = " " * n
        return r
    
class UCase(VbaLibraryFunc):
    """
    UCase() string function.
    """

    def eval(self, context, params=None):
        r = str(params[0]).upper()
        log.debug("UCase: %r returns %r" % (self, r))
        return r

class LCase(VbaLibraryFunc):
    """
    LCase() string function.
    """

    def eval(self, context, params=None):
        r = str(params[0]).lower()
        log.debug("LCase: %r returns %r" % (self, r))
        return r

class Randomize(VbaLibraryFunc):
    """
    Randomize RNG function.
    """

    def eval(self, context, params=None):
        log.debug("Randomize(): Stubbed out as NOP")
        return ''

class Rnd(VbaLibraryFunc):
    """
    Rnd() RNG function.
    """

    def eval(self, context, params=None):
        return random.random()

class Environ(VbaLibraryFunc):
    """
    Environ() function for getting environment variable values.
    """

    def eval(self, context, params=None):
        # TODO: Actually simulate getting common environment variable values.
        r = "%" + str(params[0]).upper() + "%"
        log.debug("Environ: %r returns %r" % (self, r))
        return r

class DriveExists(VbaLibraryFunc):
    """
    DriveExists() function for checking to see if a drive exists.
    """

    def eval(self, context, params=None):
        assert (len(params) >= 1)
        drive = str(params[0]).lower()
        r = False
        # Assume the C: drive is always there.
        if ((drive == 'c') or (drive == 'c:')):
            r = True
        return r

class Navigate(VbaLibraryFunc):
    """
    Navigate() function for loading a URL in a web browser.
    """

    def eval(self, context, params=None):
        assert (len(params) >= 1)
        url = str(params[0])
        context.report_action("GET", url, 'Load in browser', strip_null_bytes=True)
        
class IIf(VbaLibraryFunc):
    """
    IIf() if-like function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 3)
        guard = params[0]
        true_part = params[1]
        false_part = params[2]
        if (guard):
            return true_part
        else:
            return false_part

class CVErr(VbaLibraryFunc):
    """
    CVErr() Excel error string function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        err = None
        try:
            err = int(params[0])
        except:
            pass
        vals = {2007 : "#DIV/0!",
                2042 : "#N/A",
                2029 : "#NAME?",
                2000 : "#NULL!",
                2036 : "#NUM!",
                2023 : "#REF!",
                2015 : "#VALUE!"}
        if (err in vals):
            return vals[err]
        return ""

class CallByName(VbaLibraryFunc):
    """
    CallByName() function.
    """

    def eval(self, context, params=None):
        assert (len(params) >= 3)
        cmd = params[1]
        obj = str(params[0])
        args = ''
        if (len(params) >= 4):
            args = params[3]
        if (("Run" in cmd) or ("WScript.Shell" in obj)):
            context.report_action("Run", args, 'Interesting Function Call', strip_null_bytes=True)
        # CallByName("['WinHttp.WinHttpRequest.5.1', 'Open', 1, 'GET', 'http://deciodc.org/bin/office1...")
        if (("Open" in cmd) and ("WinHttpRequest" in obj)):
            context.report_action("GET", params[4], 'Interesting Function Call', strip_null_bytes=True)
        # CallByName(([DoBas, 'Arguments', VbLet, aas], {}))
        if ((cmd == "Arguments") or (cmd == "Path")):
            context.report_action("CallByName", args, 'Possible Scheduled Task Setup', strip_null_bytes=True)
            
class Close(VbaLibraryFunc):
    """
    File Close statement.
    """

    def eval(self, context, params=None):

        # Are we closing a file pointer?
        file_id = None
        if ((params is not None) and
            (len(params) == 1) and
            (params[0] is not None) and
            (isinstance(params[0], str)) and
            (params[0].startswith('#'))):

            # Get the ID of the file being closed.
            file_id = params[0]

        # Close() object method call?
        else:

            # TODO: Currently the object on which Close() is being called is not
            # being tracked. We will only handle the Close() if there is only 1
            # current open file.
            if ((context.open_files is None) or (len(context.open_files) == 0)):
                log.error("Cannot process Close(). No open files.")
                return
            if (len(context.open_files) > 1):
                log.error("Cannot process Close(). Too many open files.")
                return

            # Get the ID of the file.
            file_id = list(context.open_files.keys())[0]

        # We are actually closing a file.
        context.dump_file(file_id)
        
class Put(VbaLibraryFunc):
    """
    File Put statement.
    """

    def eval(self, context, params=None):
        assert ((len(params) == 2) or (len(params) == 3))

        # Get the ID of the file.
        file_id = params[0]

        # TODO: Handle writing at a given file position.

        # Get the data.
        data = params[1]
        if (len(params) == 3):
            data = params[2]

        # Has the file been opened?
        if (file_id not in context.open_files):
            context.open_file(file_id)
            
        # Are we writing a string?
        if (isinstance(data, str)):
            for c in data:
                context.open_files[file_id]["contents"].append(ord(c))

        # Are we writing a list?
        elif (isinstance(data, list)):
            for c in data:
                context.open_files[file_id]["contents"].append(c)

        # Unhandled.
        else:
            log.error("Unhandled Put() data type to write. " + str(type(data)) + ".")

class WriteLine(VbaLibraryFunc):
    """
    File WriteLine() method.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)

        # Get the data.
        data = params[0]
        if (len(params) == 3):
            data = params[2]
        
        # Save writes that look like they are writing URLs.
        data_str = str(data)
        if (("http:" in data_str) or ("https:" in data_str)):
            context.report_action('Write URL', data_str, 'File Write')
        
        # TODO: Currently the object on which WriteLine() is being called is not
        # being tracked. We will only handle the WriteLine() if there is only 1
        # current open file.
        if ((context.open_files is None) or (len(context.open_files) == 0)):
            log.error("Cannot process WriteLine(). No open files.")
            return
        if (len(context.open_files) > 1):
            log.error("Cannot process WriteLine(). Too many open files.")
            return
        
        # Get the ID of the file.
        file_id = list(context.open_files.keys())[0]
        
        # TODO: Handle writing at a given file position.

        # Are we writing a string?
        if (isinstance(data, str)):
            for c in data:
                context.open_files[file_id]["contents"].append(ord(c))
            context.open_files[file_id]["contents"].append(ord("\n"))

        # Are we writing a list?
        elif (isinstance(data, list)):
            for c in data:
                context.open_files[file_id]["contents"].append(c)
            context.open_files[file_id]["contents"].append(ord("\n"))
                
        # Unhandled.
        else:
            log.error("Unhandled Put() data type to write. " + str(type(data)) + ".")

class CurDir(VbaLibraryFunc):
    """
    CurDir() function.
    """

    def eval(self, context, params=None):
        return "~"

class KeyString(VbaLibraryFunc):
    """
    KeyString() function.
    """

    def eval(self, context, params=None):

        # Key string value map.
        key_vals = {
            1 : "Left Button",
            2 : "Right Button",
            3 : "Cancel",
            4 : "Middle Button",
            8 : "Backspace",
            9 : "Tab",
            12 : "Clear (Num 5)",
            13 : "Return",
            16 : "Shift",
            17 : "Control",
            18 : "Alt",
            19 : "Pause",
            20 : "Caps Lock",
            27 : "Esc",
            32 : "Space",
            33 : "Page Up",
            34 : "Page Down",
            35 : "End",
            36 : "Home",
            37 : "Left",
            38 : "Up",
            39 : "Right",
            40 : "Down",
            41 : "Not Avail",
            42 : "Not Avail",
            43 : "Not Avail",
            44 : "Print Screen",
            45 : "Insert",
            46 : "Del",
            47 : "Not Avail",
            48 : "0",
            49 : "1",
            50 : "2",
            51 : "3",
            52 : "4",
            53 : "5",
            54 : "6",
            55 : "7",
            56 : "8",
            57 : "9",
            65 : "A",
            66 : "B",
            67 : "C",
            68 : "D",
            69 : "E",
            70 : "F",
            71 : "G",
            72 : "H",
            73 : "I",
            74 : "J",
            75 : "K",
            76 : "L",
            77 : "M",
            78 : "N",
            79 : "O",
            80 : "P",
            81 : "Q",
            82 : "R",
            83 : "S",
            84 : "T",
            85 : "U",
            86 : "V",
            87 : "W",
            88 : "X",
            89 : "Y",
            90 : "Z",
            96 : "Num 0",
            97 : "Num 1",
            98 : "Num 2",
            99 : "Num 3",
            100 : "Num 4",
            101 : "Num 5",
            102 : "Num 6",
            103 : "Num 7",
            104 : "Num 8",
            105 : "Num 9",
            106 : "Num *",
            107 : "Num +",
            108 : "Not Avail",
            109 : "Num -",
            110 : "Num .",
            111 : "Num /",
            112 : "F1",
            113 : "F2",
            114 : "F3",
            115 : "F4",
            116 : "F5",
            117 : "F6",
            118 : "F7",
            119 : "F8",
            120 : "F9",
            121 : "F10",
            122 : "F11",
            123 : "F12",
            124 : "F13",
            125 : "F14",
            126 : "F15",
            127 : "F16",
            128 : "F17",
            129 : "F18",
            130 : "F19",
            131 : "F20",
            132 : "F21",
            133 : "F22",
            134 : "F23",
            135 : "F24",
            144 : "Num Lock",
            145 : "Scroll Lock",
            160 : "Shift",
            161 : "Shift",
            162 : "Ctrl",
            163 : "Ctrl",
            164 : "Alt",
            165 : "Alt",
            172 : "M",
            173 : "D",
            174 : "C",
            175 : "B",
            176 : "P",
            177 : "Q",
            178 : "J",
            179 : "G",
            183 : "F",
            186 : ";",
            187 : "=",
            188 : ",",
            189 : "-",
            190 : ".",
            191 : "/",
            192 : "`",
            194 : "F15",
            219 : "[",
            220 : "\\",
            221 : "]",
            222 : "'",
            226 : "\\"
        }

        v1 = None
        v2 = None
        try:
            v1 = int(params[0])
            if (len(params) >= 2):
                v2 = int(params[1])
        except Exception as e:
            log.error("KeyString: Invalid args " + str(params) + ". " + str(e))
            return ""

        r = ""
        if (v1 in key_vals):
            r += key_vals[v1]
        if (v2 is not None):
            r += ","
            if (v2 in key_vals):
                key_vals[v2]

        log.debug("KeyString: args = " + str(params) + ", return " + r)
        return r
        
class Run(VbaLibraryFunc):
    """
    Application.Run() function.
    """

    def eval(self, context, params=None):
        assert (len(params) >= 1)

        # Get the name of the function to call.
        func_name = params[0]
            
        # Get any parameters to pass to the function to call.
        call_params = None
        if (len(params) > 1):
            call_params = params[1:]
        
        # Can we find the function to call?
        try:
            context.report_action("Run", func_name, 'Interesting Function Call', strip_null_bytes=True)
            s = context.get(func_name)
            return s.eval(context=context, params=call_params)
        except KeyError:
            log.error("Application.Run() failed. Cannot find function " + str(func_name) + ".")

class Exec(Run):
    """
    Treat Exec() like the Run() function.
    """
    pass

class WinExec(VbaLibraryFunc):
    """
    WinExec() function.
    """

    def eval(self, context, params=None):
        assert (len(params) >= 1)

        cmd = params[0]
        context.report_action("Run", cmd, 'Interesting Command Execution', strip_null_bytes=True)
        return ''
        
class CreateObject(VbaLibraryFunc):
    """
    CreateObject() function (stubbed).
    """

    def eval(self, context, params=None):
        assert (len(params) >= 1)
        
        # Track contents of data written to 'ADODB.Stream'.
        obj_type = str(params[0])
        if (obj_type == 'ADODB.Stream'):
            context.open_file('ADODB.Stream')

        # Just return a string representation of the name of the object
        # being created.
        return str(obj_type)

class ReadText(VbaLibraryFunc):
    """
    ReadText() stream method (stubbed).
    """

    def eval(self, context, params=None):
        
        # TODO: Currently the stream object on which ReadText() is
        # being called is not being tracked. We will only handle the
        # ReadText() if there is only 1 current open file.
        if ((context.open_files is None) or (len(context.open_files) == 0)):
            log.error("Cannot process ReadText(). No open streams.")
            return
        if (len(context.open_files) > 1):
            log.error("Cannot process ReadText(). Too many open streams.")
            return

        # Simulate the read.

        # Get the ID of the file.
        file_id = list(context.open_files.keys())[0]

        # Get the data to read.
        data = context.open_files[file_id]["contents"]
        raw_data = array.array('B', data).tostring()

        # Return the data.
        return raw_data

class CheckSpelling(VbaLibraryFunc):
    """
    Application.CheckSpelling() function. Currently stubbed.
    """

    def eval(self, context, params=None):

        # TODO: Find and use a Python spell checker to check the spelling
        # of the argument.

        # For now just say everything is correctly spelled.
        return True

class Specialfolders(VbaLibraryFunc):
    """
    Excel Specialfolders() function. Currently stubbed.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        return "%" + str(params[0]) + "%"

class Cells(VbaLibraryFunc):
    """
    Excel Cells() function.
    Currently only handles Cells(x, y) calls.
    """

    def eval(self, context, params=None):

        # Do we have a loaded Excel file?
        if (context.loaded_excel is None):
            log.warning("Cannot process Cells() call. No Excel file loaded.")
            return "NULL"
        
        # Currently only handles Cells(x, y) calls.
        if (len(params) != 2):
            log.warning("Only 2 argument Cells() calls supported. Returning NULL.")
            return "NULL"

        # Guess that we want the 1st sheet.
        sheet = None
        try:
            sheet = context.loaded_excel.sheet_by_index(0)
        except:
            log.warning("Cannot process Cells() call. No sheets in file.")
            return "NULL"

        # Get the indices of the cell.
        col = None
        row = None
        try:
            col = int(params[0]) - 1
            row = int(params[1]) - 1
        except:
            log.warning("Cannot process Cells() call. Row or column invalid.")
            return "NULL"

        # Return the cell contents.
        try:
            r = sheet.cell(col, row)
            log.debug("Cell(" + str(col) + ", " + str(row) + ") = " + str(r))
            return r

        except:
        
            # Failed to read cell.
            log.warning("Failed to read Cell(" + str(col) + ", " + str(row) + ")")
            return "NULL"

class Range(VbaLibraryFunc):
    """
    Excel Range() function.
    """

    def eval(self, context, params=None):

        # Do we have a loaded Excel file?
        if (context.loaded_excel is None):
            log.warning("Cannot process Range() call. No Excel file loaded.")
            return "NULL"
        
        # Currently only handles Range(x) calls.
        if (len(params) != 1):
            log.warning("Only 1 argument Range() calls supported. Returning NULL.")
            return "NULL"

        # Guess that we want the 1st sheet.
        sheet = None
        try:
            sheet = context.loaded_excel.sheet_by_index(0)
        except:
            log.warning("Cannot process Cells() call. No sheets in file.")
            return "NULL"

        # Get the cell contents.
        try:

            # Pull out the cell index.
            cell_index = str(params[0]).replace('"', "").replace("'", "")

            # Pull out the cell column and row.
            col = ""
            row = ""
            for c in cell_index:
                if (c.isalpha()):
                    col += c
                else:
                    row += c
                    
            # Convert the row and column to numeric indices for xlrd.
            row = int(row) - 1
            col = excel_col_letter_to_index(col)
            
            # Pull out the cell value.
            val = str(sheet.cell_value(row, col))
            
            # Return the cell value.
            log.info("Read cell (" + str(cell_index) + ") from sheet 1")
            log.debug("Cell value = '" + val + "'")
            return val            

        except Exception as e:
        
            # Failed to read cell.
            log.warning("Failed to read Range(" + str(params[0]) + "). " + str(e))
            return "NULL"
        
class Year(VbaLibraryFunc):
    """
    Year() function. Currently stubbed.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        t = params[0]
        r = 0
        if (isinstance(t, datetime)):
            r = int(t.year)
        return r

class Minute(VbaLibraryFunc):
    """
    Minute() function. Currently stubbed.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        t = params[0]
        r = 0
        if (isinstance(t, datetime)):
            r = int(t.minute)
        return r

class Second(VbaLibraryFunc):
    """
    Second() function. Currently stubbed.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        t = params[0]
        r = 0
        if (isinstance(t, datetime)):
            r = int(t.second)
        return r

class Variable(VbaLibraryFunc):
    """
    Get document variable.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        var = str(params[0]).strip()
        var = var.replace("activedocument.customdocumentproperties(", "").\
              replace(")", "").\
              replace("'","").\
              replace('"',"").\
              replace('.value',"").\
              strip()
        r = context.get_doc_var(var)
        if (r is None):
            r = ""
        log.debug("ActiveDocument.Variable(" + var + ") = " + str(r))
        return r

class Variables(Variable):
    pass
    
class CDbl(VbaLibraryFunc):
    """
    CDbl() type conversion function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        try:
            # Handle hex.
            tmp = str(params[0]).upper()
            if (tmp.startswith("&H")):
                tmp = tmp.replace("&H", "0x")
                tmp = int(tmp, 16)

            # VBA rounds the significant digits.
            #return round(float(params[0]), 11)
            return float(tmp)

        except Exception as e:
            log.error("CDbl(" + str(params[0]) + ") failed. " + str(e))
            return 0

class Print(VbaLibraryFunc):
    """
    Debug.Print function.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)

        # Save writes that look like they are writing URLs.
        data_str = str(params[0])
        if (("http:" in data_str) or ("https:" in data_str)):
            context.report_action('Write URL', data_str, 'Debug Print')

        context.report_action("Debug Print", str(params[0]), '')

class URLDownloadToFile(VbaLibraryFunc):
    """
    URLDownloadToFile() external function.
    """

    def eval(self, context, params=None):
        if (len(params) >= 3):
            context.report_action('Download URL', str(params[1]), 'External Function: urlmon.dll / URLDownloadToFile', strip_null_bytes=True)
            context.report_action('Write File', str(params[2]), 'External Function: urlmon.dll / URLDownloadToFile', strip_null_bytes=True)

class FollowHyperlink(VbaLibraryFunc):
    """
    FollowHyperlink() function.
    """

    def eval(self, context, params=None):
        if (len(params) >= 1):
            context.report_action('Download URL', str(params[0]), 'FollowHyperLink', strip_null_bytes=True)
            
class CreateTextFile(VbaLibraryFunc):
    """
    CreateTextFile() method.
    """

    def eval(self, context, params=None):
        assert (len(params) >= 1)

        # Get the name of the file being opened.
        fname = str(params[0])

        # Save that the file is opened.
        context.open_file(fname)

class Open(CreateTextFile):
    """
    Open() file function. Also Open() HTTP function.
    """

    def eval(self, context, params=None):

        # Is this a HTTP GET?
        if ((len(params) >= 2) and (str(params[0]).strip() == "GET")):
            context.report_action("GET", str(params[1]), 'Interesting Function Call', strip_null_bytes=True)

class Timer(VbaLibraryFunc):
    """
    Timer() method (stubbed).
    """

    def eval(self, context, params=None):
        return int(time.mktime(datetime.now().timetuple()))

class Write(VbaLibraryFunc):
    """
    Write() method.
    """

    def eval(self, context, params=None):
        assert (len(params) >= 1)

        # Get the data being written.
        dat = str(params[0])

        # Save writes that look like they are writing URLs.
        data_str = str(dat)
        if (("http:" in data_str) or ("https:" in data_str)):
            context.report_action('Write URL', data_str, 'File Write', strip_null_bytes=True)
        
        # TODO: Currently the object on which Write() is being called is not
        # being tracked. We will only handle the Write() if there is only 1
        # current open file.
        if ((context.open_files is None) or (len(context.open_files) == 0)):
            log.error("Cannot process Write(). No open files.")
            return
        if (len(context.open_files) > 1):
            log.error("Cannot process Write(). Too many open files.")
            return

        # Simulate the write.

        # Get the ID of the file.
        file_id = list(context.open_files.keys())[0]

        # Get the data.
        data = params[0]

        # Are we writing a string?
        if (isinstance(data, str)):
            for c in data:
                context.open_files[file_id]["contents"].append(ord(c))

        # Are we writing a list?
        elif (isinstance(data, list)):
            for c in data:
                context.open_files[file_id]["contents"].append(c)

        # Unhandled.
        else:
            log.error("Unhandled Write() data type to write. " + str(type(data)) + ".")

class International(VbaLibraryFunc):
    """
    Application.International() function.
    """

    def eval(self, context, params=None):
        if params is not None:
            if str(params[0]) == 'NULL':
                return COUNTRY

# add your own implemented code here
for _class in (MsgBox, Shell, Len, Mid, MidB, Left, Right,
               BuiltInDocumentProperties, Array, UBound, LBound, Trim,
               StrConv, Split, Int, Item, StrReverse, InStr, Replace,
               Sgn, Sqr, Base64Decode, Abs, Fix, Hex, String, CByte, Atn,
               Dir, RGB, Log, Cos, Exp, Sin, Str, Val, CInt, Pmt, Day, Round,
               UCase, Randomize, CBool, CDate, CStr, CSng, Tan, Rnd, Oct,
               Environ, IIf, CleanString, Base64DecodeString, CLng, Close, Put, Run, InStrRev,
               LCase, RTrim, LTrim, AscW, AscB, CurDir, LenB, CreateObject,
               CheckSpelling, Specialfolders, StrComp, Space, Year, Variable,
               Exec, CDbl, Print, CreateTextFile, Write, Minute, Second, WinExec,
               CallByName, ReadText, Variables, Timer, Open, CVErr, WriteLine,
               URLDownloadToFile, FollowHyperlink, Join, VarType, DriveExists, Navigate,
               KeyString, CVar, IsNumeric, Assert, Sleep, Cells, Shapes,
               Format, Range, Switch, International):
    name = _class.__name__.lower()
    VBA_LIBRARY[name] = _class()

log.debug('VBA Library contains: %s' % ', '.join(list(VBA_LIBRARY.keys())))

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
        ('vbNullString', ''),
        ('vbObjectError', -2147221504),

        # Shell Constants
        ('vbHide', 0),
        ('vbNormalFocus', 1),
        ('vbMinimizedFocus.', 2),
        ('vbMaximizedFocus', 3),
        ('vbNormalNoFocus', 4),
        ('vbMinimizedNoFocus', 6),
):
    VBA_LIBRARY[name.lower()] = value

