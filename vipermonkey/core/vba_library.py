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
import base64
import re

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
        start = 0
        try:
            start = int(params[1])
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
            length = int(params[2])
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
        start = 0
        try:
            start = int(params[1])
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
        start = 0
        try:
            start = int(params[1])
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
        r = None
        if (isinstance(params[0], int)):
            r = str(params[0])
        else:
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
        if (len(params) > 1):
            conv = int(params[1])
            if (conv == 1):
                r = r.upper()
            if (conv == 2):
                r = r.lower()
            if (conv == 64):
                padded = ""
                for c in r:
                    padded += c + "\0"
                r = padded
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

class CInt(Int):
    """
    Same as Int() for our purposes.
    """
    pass
    
class StrReverse(object):
    """
    StrReverse() string function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert len(params) > 0
        # TODO: Actually implement this properly.
        string = params[0]
        if (string is None):
            string = ''
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
        if (string is None):
            string = ''
        pat = params[1]
        if (pat is None):
            pat = ''
        rep = params[2]
        if (rep is None):
            rep = ''
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
        assert (len(params) == 1)
        num = params[0]
        try:
            r = int(math.copysign(1, num))
            log.debug("Sgn: %r returns %r" % (self, r))
            return r
        except:
            r = ''
            log.error("Sgn: %r returns %r" % (self, r))
            return r

class Sqr(object):
    """
    Sqr() math function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 1)
        num = int(params[0]) + 0.0
        r = ''
        try:
            r = math.sqrt(num)
        except ValueError:
            pass
        log.debug("Sqr: %r returns %r" % (self, r))
        return r

class Abs(object):
    """
    Abs() math function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 1)
        num = int(params[0])
        r = abs(num)
        log.debug("Abs: %r returns %r" % (self, r))
        return r

class Fix(object):
    """
    Fix() math function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 1)
        num = float(params[0])
        r = math.floor(num)
        log.debug("Fix: %r returns %r" % (self, r))
        return r

class Round(object):
    """
    Round() math function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 1)
        num = float(params[0])
        r = round(num)
        log.debug("Round: %r returns %r" % (self, r))
        return r

class Hex(object):
    """
    Hex() math function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 1)
        num = int(params[0])
        r = hex(num).replace("0x","").upper()
        log.debug("Hex: %r returns %r" % (self, r))
        return r

class CByte(object):
    """
    CByte() math function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 1)
        tmp = params[0].upper()
        if (tmp.startswith("&H")):
            tmp = tmp.replace("&H", "0x")
            tmp = int(tmp, 16)
        num = int(round(float(tmp)))
        r = num
        if (r > 255):
            r = 255
        log.debug("CByte: %r returns %r" % (self, r))
        return r

class Atn(object):
    """
    Atn() math function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 1)
        num = float(params[0])
        try:
            r = math.atan(num)
            log.debug("Atn: %r returns %r" % (self, r))
            return r
        except:
            r = ''
            log.error("Atn: %r returns %r" % (self, r))
            return r

class Cos(object):
    """
    Cos() math function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 1)
        num = float(params[0])
        try:
            r = math.cos(num)
            log.debug("Cos: %r returns %r" % (self, r))
            return r
        except:
            r = ''
            log.error("Cos: %r returns %r" % (self, r))
            return r
            
class Log(object):
    """
    Log() math function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 1)
        num = float(params[0])
        r = ''
        try:
            r = math.log(num)
        except ValueError:
            pass
        log.debug("Log: %r returns %r" % (self, r))
        return r
    
class String(object):
    """
    String() repeated character string creation function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 2)
        num = int(params[0])
        char = params[1]
        r = char * num
        log.debug("String: %r returns %r" % (self, r))
        return r

class Dir(object):
    """
    Dir() file/directory finding function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
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

class RGB(object):
    """
    RGB() color function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 3)
        red = int(params[0])
        green = int(params[1])
        blue = int(params[2])
        r = red + (green * 256) + (blue * 65536)
        # TODO: Figure out how to simulate actual file searches.            
        log.debug("RGB: %r returns %r" % (self, r))
        return r

class Exp(object):
    """
    Exp() math function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 1)
        num = float(params[0])
        try:
            r = math.exp(num)
            log.debug("Exp: %r returns %r" % (self, r))
            return r
        except:
            r = ''
            log.error("Exp: %r returns %r" % (self, r))
            return r
            
class Sin(object):
    """
    Sin() math function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 1)
        num = float(params[0])
        try:
            r = math.sin(num)
            log.debug("Sin: %r returns %r" % (self, r))
            return r
        except:
            r = ''
            log.error("Sin: %r returns %r" % (self, r))
            return r
            
class Str(object):
    """
    Str() convert number to string function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 1)
        r = str(params[0])
        log.debug("Str: %r returns %r" % (self, r))
        return r

class Val(object):
    """
    Val() convert string to number function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 1)

        # Sanity check.
        if ((params[0] is None) or (not isinstance(params[0], str))):
            r = ''
            log.debug("Str: %r returns %r" % (self, r))
            return r
        
        # Ignore whitespace.
        tmp = params[0].strip().replace(" ", "")

        # The VB Val() function is ugly. Look for VB hex encoding.
        nums = re.compile(r"&H[0-9A-Fa-f]+")
        matches = nums.search(tmp)
        if (hasattr(matches, "group")):
            tmp = nums.search(tmp).group(0).replace("&H", "0x")
            r = float(int(tmp, 16))
            log.debug("Val: %r returns %r" % (self, r))
            return r
        
        # The VB Val() function is ugly. Try to use a regular expression to pick out
        # the 1st valid number string.
        nums = re.compile(r"[+-]?\d+(?:\.\d+)?")
        matches = nums.search(tmp)
        if (hasattr(matches, "group")):
            tmp = nums.search(tmp).group(0)

            # Convert this to a float.
            r = float(tmp)
            log.debug("Val: %r returns %r" % (self, r))
            return r

        # Can't find a valid number to convert. This is probably incorrect behavior.
        r = 0
        log.debug("Val: Invalid Value: %r returns %r" % (self, r))
        return r
    
class Base64Decode(object):
    """
    Base64Decode() function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 1)
        txt = params[0]
        if (txt is None):
            txt = ''
        r = base64.b64decode(txt)
        log.debug("Base64Decode: %r returns %r" % (self, r))
        return r

class Pmt(object):
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
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) >= 3)

        # Pull out the arguments.
        rate = float(params[0])
        nper = int(params[1]) + 0.0
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
            
        log.debug("Pmt: %r returns %r" % (self, r))
        return r

class Day(object):
    """
    Day() function. This is currently partially implemented.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        assert (len(params) == 1)
        txt = params[0]
        if (txt is None):
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

class UCase(object):
    """
    UCase() string function.
    """

    def eval(self, context, params=None):
        # assumption: here the params have already been evaluated by Call_Function beforehand
        r = str(params[0]).upper()
        log.debug("UCase: %r returns %r" % (self, r))
        return r

class Randomize(object):
    """
    Randomize RNG function.
    """

    def eval(self, context, params=None):
        log.debug("Randomize: Stubbed out as NOP")
        return r
    
for _class in (MsgBox, Shell, Len, Mid, Left, Right,
               BuiltInDocumentProperties, Array, UBound, LBound, Trim,
               StrConv, Split, Int, Item, StrReverse, InStr, Replace,
               Sgn, Sqr, Base64Decode, Abs, Fix, Hex, String, CByte, Atn,
               Dir, RGB, Log, Cos, Exp, Sin, Str, Val, CInt, Pmt, Day, Round,
               UCase, Randomize):
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
        ('vbNullString', ''),
        ('vbObjectError', -2147221504),
):
    VBA_LIBRARY[name.lower()] = value


