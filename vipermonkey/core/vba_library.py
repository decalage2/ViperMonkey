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

# ViperMonkey is copyright (c) 2015-2019 Philippe Lagadec (http://www.decalage.info)
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
from from_unicode_str import *
import decimal
from curses_ascii import isprint

from pyparsing import *

from vba_context import VBA_LIBRARY
from vba_object import str_convert
from vba_object import int_convert
from vba_object import eval_arg
from vba_object import VbaLibraryFunc
from vba_object import VBA_Object
from vba_object import excel_col_letter_to_index
from vba_object import strip_nonvb_chars
import expressions
import meta
import modules
import strip_lines

from logger import log

# === VBA LIBRARY ============================================================

# TODO: Word 2013 object model reference: https://msdn.microsoft.com/EN-US/library/office/ff837519.aspx
# TODO: Excel
# TODO: other MS Office apps?

# Track the unresolved arguments to the current call.
var_names = None

class WeekDay(VbaLibraryFunc):
    """
    VBA WeekDay function
    """

    def eval(self, context, params=None):

        # Get date string.
        if (len(params) == 0):
            return 1
        date_str = str(params[0]).replace("#", "")
        date_obj = None
        
        # TODO: Handle more and more date formats.

        # 4/20/1889
        if (date_str.count("/") == 2):
            try:
                date_obj = datetime.strptime(date_str, '%m/%d/%Y')
            except:
                pass

        if (date_obj is not None):
            r = date_obj.weekday()
            # Looks like VBA week day is off by 2 from Python week day.
            r += 2
            log.debug("WeekDay(%r): return %r" % (date_str, r))
            return r
        return 1

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

class QBColor(VbaLibraryFunc):
    """
    QBColor() color lookup function.
    """

    def eval(self, context, params=None):
        if (len(params) == 0):
            return 0
        val = int(params[0])
        if ((val < 0) or (val > 15)):
            return 0
        lookup = {
            0 : 0,
            1 : 8388608,
            2 : 32768,
            3 : 8421376,
            4 : 128,
            5 : 8388736,
            6 : 32896,
            7 : 12632256,
            8 : 8421504,
            9 : 16711680,
            10 : 65280,
            11 : 16776960,
            12 : 255,
            13 : 16711935,
            14 : 65535,
            15 : 16777215
        }
        return lookup[val]

class FolderExists(VbaLibraryFunc):
    """
    FolderExists() VB function (stubbed).
    """

    def eval(self, context, params=None):
        return False

class FileExists(VbaLibraryFunc):
    """
    FileExists() VB function (stubbed).
    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) == 0)):
            return False
        fname = str(params[0])
        if ("powershell" in fname.lower()):
            return True
        if ("cmd.exe" in fname.lower()):
            return True
        return False
        
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
        if (isinstance(params[0], int)):
            return 2
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
        if (params is None):
            log.error("Invalid arguments " + str(params) + " to Mid().")
            return ""
        if ((len(params) > 0) and (params[0] == "ActiveDocument")):
            params = params[1:]
        if (params is None):
            log.error("Invalid arguments " + str(params) + " to Mid().")
            return ""
        if (len(params) not in (2,3)):
            log.error("Invalid arguments " + str(params) + " to Mid().")
            return ""
        s = params[0]
        # "If String contains the data value Null, Null is returned."
        if s == None: return None
        if not isinstance(s, basestring):
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

        # Don't modify the "**MATCH ANY**" special value.
        if (s == "**MATCH ANY**"):
            return s
        
        # "If String contains the data value Null, Null is returned."
        if s == None: return None
        if not isinstance(s, basestring):
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

class PrivateProfileString(VbaLibraryFunc):
    """
    PrivateProfileString method.
    """

    def eval(self, context, params=None):
        return "**MATCH ANY**"
    
class Right(VbaLibraryFunc):
    """
    Right function.
    """

    def eval(self, context, params=None):
        if (len(params) > 2):
            params = params[-2:]
        assert len(params) == 2
        s = params[0]

        # Don't modify the "**MATCH ANY**" special value.
        if (s == "**MATCH ANY**"):
            return s
        
        # "If String contains the data value Null, Null is returned."
        if s == None: return None
        if not isinstance(s, basestring):
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

class BuiltInDocumentProperties(VbaLibraryFunc):
    """
    Simulate calling ActiveDocument.BuiltInDocumentProperties('PROPERTYNAME')
    """

    def eval(self, context, params=None):

        if (params is None):
            return "NULL"
        assert len(params) == 1

        # Get the property we are looking for.
        prop = params[0]
        return meta.read_metadata_item(prop)

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

        # This might be the string "shell".
        if (params is None):
            return "shell"
        try:
            params.remove('ThisDocument')
            params.remove('BuiltInDocumentProperties')
        except:
            pass

        # Get the command to run.
        command = params[0]

        # Is the command invalid?
        if (not isinstance(command, str)):

            # No, Shell() will throw an error.
            context.got_error = True
            log.warning("Shell(" + str(command) + ") throws an error.")
            return 0

        # We have a valid shell command. Track it.
        log.debug("Shell command type: " + str(type(command)))
        log.info('Shell(%r)' % command)
        context.report_action('Execute Command', command, 'Shell function', strip_null_bytes=True)
        return 0

class ExecuteStatement(Shell):
    pass
    
class ShellExecute(Shell):
    """
    shell.application.ShellExecute() function.
    """
    
    def eval(self, context, params=None):

        if (len(params) < 2):
            return 0
        command = str(params[0])
        args = str(params[1])
        log.info('ShellExecute(%r %r)' % (command, args))
        context.report_action('Execute Command', command + " " + args, 'Shell function', strip_null_bytes=True)
        return 0

class Eval(VbaLibraryFunc):
    """
    VBScript expression Eval() function.
    """
    
    def eval(self, context, params=None):

        # Pull out the expression to eval.
        if (len(params) < 1):
            return 0
        expr = strip_nonvb_chars(str(params[0]))

        # We are executing a string, so any "" in the string are really '"' when
        # we execute the string.
        expr = expr.replace('""', '"')
        
        try:

            # Parse it. Assume this is an expression.
            obj = expressions.expression.parseString(expr, parseAll=True)[0]
            
            # Evaluate the expression in the current context.
            # TODO: Does this actually get evalled in the current context?
            r = obj
            if (isinstance(obj, VBA_Object)):
                r = obj.eval(context)
            return r

        except ParseException:
            log.error("Parse error. Cannot evaluate '" + expr + "'")
            return "NULL"

class Execute(VbaLibraryFunc):
    """
    WScript Execute() function.
    """

    def eval(self, context, params=None):

        # Sanity check.
        if ((len(params) == 0) or
            (isinstance(params[0], VBA_Object)) or
            (isinstance(params[0], VbaLibraryFunc))):
            return "NULL"
        
        # Save the command.
        command = strip_nonvb_chars(str(params[0]))
        # Why am I doing this?
        #command = command.replace('""', '"')
        context.report_action('Execute Command', command, 'Execute() String', strip_null_bytes=True)
        command += "\n"

        # Fix invalid string assignments.
        command = strip_lines.fix_vba_code(command)

        # We are executing a string, so any "" in the string are really '"' when
        # we execute the string.
        orig_command = command
        command = command.replace('""', '"')
        
        # Parse it.
        obj = None
        try:
            obj = modules.module.parseString(command, parseAll=True)[0]
        except ParseException:

            # Maybe replacing the '""' with '"' was a bad idea. Try the original
            # command.
            try:
                obj = modules.module.parseString(orig_command, parseAll=True)[0]
            except ParseException:
                if (len(orig_command) > 50):
                    orig_command = orig_command[:50] + " ..."
                log.error("Parse error. Cannot evaluate '" + orig_command + "'")
                return "NULL"
            
        # Evaluate the expression in the current context.
        # TODO: Does this actually get evalled in the current context?
        r = obj
        if (isinstance(obj, VBA_Object)):

            # Load any new function definitions into the current context.
            obj.load_context(context)
            
            # Emulate the parsed code.
            r = obj.eval(context)
            
        # Add any functions declared in the execution to the global
        # context.
        return r

class ExecuteGlobal(Execute):
    """
    WScript ExecuteGlobal() function.
    """
    pass

class AddCode(Execute):
    """
    Visual Basic script control AddCode() method..
    """
    pass

class AddFromString(Execute):
    """
    Office programmatic macro editing method..
    """
    pass

class Add(VbaLibraryFunc):
    """
    Add() VB object method. Currently only adds to Scripting.Dictionary objects is supported.
    """

    def eval(self, context, params=None):
        """
        params[0] = object
        params[1] = key
        params[2] = value
        """

        # Sanity check.
        if (len(params) != 3):
            return

        # Get the object (dict), key, and value.
        obj = params[0]
        key = params[1]
        val = params[2]
        if (not isinstance(obj, dict)):
            return
        obj[key] = val

class Array(VbaLibraryFunc):
    """
    Create an array.
    """

    def eval(self, context, params=None):
        r = []
        if ((len(params) == 1) and (params[0] == "NULL")):
            return []        
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
        if ((arr is None) or (not hasattr(arr, '__len__'))):
            log.error("UBound(" + str(arr) + ") cannot be computed.")
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
        
        # Sanity check arguments.
        if ((params is None) or (len(params) == 0)):
            log.error("Invalid paramater to Trim().")
            return ""

        # Trim the string.
        r = str(params[0]).strip()
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

class International(VbaLibraryFunc):
    """
    application.international() Function.
    """

    def eval(self, context, params=None):

        # Match anything compared to this result.
        return "**MATCH ANY**"

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

class StrPtr(VbaLibraryFunc):
    """
    External StrPtr() string function.
    """

    def eval(self, context, params=None):
        assert len(params) > 0
        return ("&" + str(params[0]))
    
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

class InlineShapes(VbaLibraryFunc):
    """
    InlineShapes() object reference. Stubbed.
    """

    def eval(self, context, params=None):

        # Just return the string representation of the access. This is used in
        # vba_object._read_from_object_text()
        return "InlineShapes('" + str(params[0]) + "')"

class GetCursorPos(VbaLibraryFunc):
    """
    Faked GetCursorPos() function. Returns random location.
    """

    def eval(self, context, params=None):
        if ((var_names is None) or (len(var_names) == 0)):
            return 1

        # Set the given parameter to a random position.
        var_name = str(var_names[0])
        context.set(var_name + ".*", random.randint(100, 10000), force_global=True)
        
        return 0
    
class GetByteCount_2(VbaLibraryFunc):
    """
    String encoder object method.
    """

    def eval(self, context, params=None):
        if ((len(params) == 0) or (not isinstance(params[0], str))):
            return 0
        return len(params[0])

class GetBytes_4(VbaLibraryFunc):
    """
    String encoder object method.
    """

    def eval(self, context, params=None):
        if ((len(params) == 0) or (not isinstance(params[0], str))):
            return []
        r = []
        for c in params[0]:
            r.append(ord(c))
        return r

class TransformFinalBlock(VbaLibraryFunc):
    """
    Base64 encoder object method.
    """

    def eval(self, context, params=None):
        if ((len(params) != 3) or (not isinstance(params[0], list))):
            return "NULL"

        # Pull out the byte values and start/end of the bytes to decode.
        vals = params[0]
        start = 0
        try:
            start = int(params[1])
        except:
            pass
        end = len(vals) - 1
        try:
            end = int(params[2])
        except:
            pass
        if (end > len(vals) - 1):
            end = len(vals) - 1
        if (start > end):
            start = end - 1

        # Reconstruct the base64 encoded string.
        base64_str = ""
        end += 1
        for b in vals[start : end]:
            base64_str += chr(b)

        # Decode the base64 encoded string.
        r = "NULL"
        try:
            log.debug("eval_arg: Try base64 decode of '" + base64_str + "'...")
            base64_str = filter(isprint, str(base64_str).strip())
            r = base64.b64decode(base64_str).replace(chr(0), "")
            log.debug("eval_arg: Base64 decode success.")
        except Exception as e:
            log.debug("eval_arg: Base64 decode fail. " + str(e))

        # Return the decoded string.
        log.debug("Decoded string: " + r)
        return r
            
class Split(VbaLibraryFunc):
    """
    Split() string function.
    """

    def eval(self, context, params=None):
        if (params is None):
            return ""
        assert len(params) > 0
        # TODO: Actually implement this properly.
        string = str(params[0])
        sep = " "
        if ((len(params) > 1) and
            (isinstance(params[1], str)) and
            (len(params[1]) > 0)):
            sep = str(params[1])
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
            if (isinstance(val, str) and (val.lower().startswith("&h"))):
                val = "0x" + val[2:]
                r = int(val, 16)
            elif (isinstance(val, str) and (("e" in val) or ("E" in val))):
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
        string =''
        if (params[0] is not None):
            string = str(params[0])
        r = string[::-1]
        log.debug("StrReverse: return %r" % r)
        return r

class RegWrite(VbaLibraryFunc):
    """
    RegWrite() function.
    """

    def eval(self, context, params=None):
        context.report_action("Registry Write", str(params), "Registry Write", strip_null_bytes=True)
        return "NULL"

class Replace(VbaLibraryFunc):
    """
    Replace() string function.

    The Replace function syntax has these named arguments:

    expression	Required. String expression containing substring to replace.
    find	Required. Substring being searched for.
    replace	Required. Replacement substring.
    start	Optional. Start position for the substring of expression to be searched and returned. If omitted, 1 is assumed.
    count	Optional. Number of substring substitutions to perform. If omitted, the default value is -1, which means, make all possible substitutions.
    compare	Optional. Numeric value indicating the kind of comparison to use when evaluating substrings. See Settings section for values.
    """

    def eval(self, context, params=None):
        assert len(params) >= 3
        # TODO: Handle start, count, and compare parameters.
        string = str(params[0])
        if (string is None):
            string = ''
        pat = str(params[1])
        if (pat is None):
            pat = ''
        rep = str(params[2])
        if ((rep is None) or (rep == 0)):
            rep = ''

        # regex replacement?
        if (params[-1] == "<-- USE REGEX -->"):
            
            # Don't do a regex replacement of everything.
            if (pat.strip() != "."):
                try:
                    pat1 = pat.replace("$", "\\$").replace("-", "\\-")
                    r = re.sub(pat1, rep, string)
                except:
                    r = string

        # Regular string replacement?
        else:
            r = string.replace(pat, rep)

        # Done.
        log.debug("Replace: return %r" % r)
        return r

class SaveToFile(VbaLibraryFunc):
    """
    SaveToFile() ADODB.Stream method.
    """

    def eval(self, context, params=None):

        # Sanity check.
        if (len(params) == 0):
            return ""

        # Just return the file name. This is used in
        # expressions.MemberAccessExpression._handle_savetofile().
        return str(params[0])
    
class LoadXML(VbaLibraryFunc):
    """
    LoadXML() MSXML2.DOMDocument.3.0 method.
    """

    def eval(self, context, params=None):

        # Sanity check.
        if (len(params) == 0):
            return ""

        # Get the XML.
        xml = str(params[0]).strip()

        # Is this some base64?
        if (xml.startswith("<B64DECODE")):

            # Yes it is. Pull it out.
            start = xml.index(">") + 1
            end = xml.rindex("<")
            xml = xml[start:end].strip()

            # It looks like maybe this magically does base64 decode? Try that.
            try:
                log.debug("eval_arg: Try base64 decode of '" + xml + "'...")
                xml = base64.b64decode(xml).replace(chr(0), "")
                log.debug("eval_arg: Base64 decode success.")
            except Exception as e:
                log.debug("eval_arg: Base64 decode fail. " + str(e))

        # Return the XML or base64 string.
        return xml
        
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
            if (s2 in s1[start:]):
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
            if (len(params) < 3):
                return 0
            s1 = params[1]
            s2 = params[2]

        # Were we given a search type?
        s1 = str(s1)
        s2 = str(s2)
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
            n = int_convert(num)
            if n == 0:
                r = 0
            else:
                r = int(math.copysign(1, n))
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

        # Handle abstracted pointers to memory.
        val = params[0]
        if (isinstance(val, str) and
            (not val.startswith("&H")) and
            (val.startswith("&"))):
            return val

        # Actually try to convert to a number.
        r = ''
        try:
            tmp = val
            if (isinstance(tmp, str)):
                tmp = val.upper()
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
        r = params[0]
        try:
            num = float(params[0])
            r = math.log(num)
        except ValueError as e:
            log.error("Log(" + str(params[0]) + ") failed. " + str(e))
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

        # Just act like we found something always.
        r = pat.replace("*", "foo")

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
        r = params[0]
        try:
            num = float(params[0])
            r = math.exp(num)
        except Exception as e:
            log.error("Exp(" + str(params[0]) + ") failed. " + str(e))
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
        if ((params is None) or (len(params[0]) == 0)):
            return ""
        r = str(params[0])
        log.debug("Str: %r returns %r" % (self, r))
        return r

class Val(VbaLibraryFunc):
    """
    Val() convert string to number function.
    """

    def eval(self, context, params=None):

        if (params is None):
            return ''
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

        # Common environment variables.
        env_vars = {}
        env_vars["ALLUSERSPROFILE".lower()] = 'C:\\ProgramData'
        env_vars["APPDATA".lower()] = 'C:\\Users\\admin\\AppData\\Roaming'
        env_vars["CommonProgramFiles".lower()] = 'C:\\Program Files\\Common Files'
        env_vars["CommonProgramFiles(x86)".lower()] = 'C:\\Program Files (x86)\\Common Files'
        env_vars["CommonProgramW6432".lower()] = 'C:\\Program Files\\Common Files'
        env_vars["COMPUTERNAME".lower()] = 'ADJH676F'
        env_vars["ComSpec".lower()] = 'C:\\WINDOWS\\system32\\cmd.exe'
        env_vars["DriverData".lower()] = 'C:\\Windows\\System32\\Drivers\\DriverData'
        env_vars["HOMEDRIVE".lower()] = 'C:'
        env_vars["HOMEPATH".lower()] = '\\Users\\admin'
        env_vars["LOCALAPPDATA".lower()] = 'C:\\Users\\admin\\AppData\\Local'
        env_vars["LOGONSERVER".lower()] = '\\\\HEROG76'
        env_vars["NUMBER_OF_PROCESSORS".lower()] = '4'
        env_vars["OneDrive".lower()] = 'C:\\Users\\admin\\OneDrive'
        env_vars["OS".lower()] = 'Windows_NT'
        env_vars["Path".lower()] = 'C:\\ProgramData\\Oracle\\Java\\javapath'
        env_vars["PATHEXT".lower()] = '.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC'
        env_vars["PROCESSOR_ARCHITECTURE".lower()] = 'AMD64'
        env_vars["PROCESSOR_IDENTIFIER".lower()] = 'Intel64 Family 6 Model 158 Stepping 9, GenuineIntel'
        env_vars["PROCESSOR_LEVEL".lower()] = '6'
        env_vars["PROCESSOR_REVISION".lower()] = '9e09'
        env_vars["ProgramData".lower()] = 'C:\\ProgramData'
        env_vars["ProgramFiles".lower()] = 'C:\\Program Files'
        env_vars["ProgramFiles(x86)".lower()] = 'C:\\Program Files (x86)'
        env_vars["ProgramW6432".lower()] = 'C:\\Program Files'
        env_vars["PROMPT".lower()] = '$P$G'
        env_vars["PSModulePath".lower()] = 'C:\\Program Files\\WindowsPowerShell\\Modules;C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\Modules;C:\\Program Files\\Microsoft Message Analyzer\\PowerShell\\'
        env_vars["PUBLIC".lower()] = 'C:\\Users\\Public'
        env_vars["SESSIONNAME".lower()] = 'Console'
        env_vars["SystemDrive".lower()] = 'C:'
        env_vars["SystemRoot".lower()] = 'C:\\WINDOWS'
        env_vars["TEMP".lower()] = 'C:\\Users\\admin\\AppData\\Local\\Temp'
        env_vars["TMP".lower()] = 'C:\\Users\\admin\\AppData\\Local\\Temp'
        env_vars["USERDNSDOMAIN".lower()] = 'REMOTE.FOURTHWALL.COM'
        env_vars["USERDOMAIN".lower()] = 'FOURTHWALL'
        env_vars["USERDOMAIN_ROAMINGPROFILE".lower()] = 'FOURTHWALL'
        env_vars["USERNAME".lower()] = 'admin'
        env_vars["USERPROFILE".lower()] = 'C:\\Users\\admin'
        env_vars["VS110COMNTOOLS".lower()] = 'C:\\Program Files (x86)\\Microsoft Visual Studio 11.0\\Common7\\Tools\\'
        env_vars["VS120COMNTOOLS".lower()] = 'C:\\Program Files (x86)\\Microsoft Visual Studio 12.0\\Common7\\Tools\\'
        env_vars["VS140COMNTOOLS".lower()] = 'C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\Common7\\Tools\\'
        env_vars["VSSDK140Install".lower()] = 'C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VSSDK\\'
        env_vars["windir".lower()] = 'C:\\WINDOWS'

        var_name = str(params[0]).strip('%')
        # Is this an environment variable we know?
        if context.expand_env_vars and var_name.lower() in env_vars:
            r = env_vars[var_name.lower()]
        else:
            r = "%{}%".format(var_name.upper())

        # Done.
        log.debug("Environ: %r returns %r" % (self, r))
        return r

class ExpandEnvironmentStrings(Environ):
    pass
    
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
        if (url.startswith("tp://")):
            url = "ht" + url
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

        # Report interesting external commands run.
        cmd = str(params[1])
        obj = str(params[0])
        args = ''
        if (len(params) >= 4):
            args = params[3]
        if (("Run" in cmd) or ("WScript.Shell" in obj)):
            context.report_action("Run", args, 'Interesting Function Call', strip_null_bytes=True)
        # CallByName("['WinHttp.WinHttpRequest.5.1', 'Open', 1, 'GET', 'http://deciodc.org/bin/office1...")
        if ((("Open" in cmd) and ("WinHttpRequest" in obj)) or
            ((len(params) > 5) and (params[3].lower() == "get"))):
            url = str(params[4])
            if (url.startswith("tp://")):
                url = "ht" + url
            context.report_action("GET", url, 'Interesting Function Call', strip_null_bytes=True)
        # CallByName(([DoBas, 'Arguments', VbLet, aas], {}))
        if ((cmd == "Arguments") or (cmd == "Path")):
            context.report_action("CallByName", args, 'Possible Scheduled Task Setup', strip_null_bytes=True)

        # Are we using this to read text from a GUI element?
        if ((cmd == "Tag") or (cmd == "Text")):

            # Looks like it. Lets return the text. This is read from a for variable.
            try:
                return context.get(str(params[0]) + "." + cmd)
            except KeyError:
                pass

        # Do nothing.
        return None

class Raise(VbaLibraryFunc):
    """
    Raise() exception/error function.
    """

    def eval(self, context, params=None):
        context.got_error = True
        log.warning("Raise exception " + str(params))
            
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
            try:
                file_id = context.get(params[0])
            except KeyError:
                file_id = str(params[0])

        # Close() object method call?
        else:

            # TODO: Currently the object on which Close() is being called is not
            # being tracked. We will only handle the Close() if there is only 1
            # current open file.
            if not context.open_files:
                log.error("Cannot process Close(). No open files.")
                return

            if len(context.open_files) > 1:
                log.warning("More than 1 file is open. Closing an arbitrary file.")
                file_id = context.get_interesting_fileid()
            else:
                # Get the ID of the file.
                file_id = context.open_files.keys()[0]

        # We are actually closing a file.
        context.close_file(file_id)


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

        context.write_file(file_id, data)


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
        file_id = None
        if (len(context.open_files) > 1):
            log.warning("More than 1 file is open. Writing to an arbitrary file.")
            file_id = context.get_interesting_fileid()
            log.warning("Writing to '" + str(file_id) + "' .")
        else:        

            # Get the ID of the file.
            file_id = context.open_files.keys()[0]
        
        # TODO: Handle writing at a given file position.

        context.write_file(file_id, data)
        context.write_file(file_id, b'\n')


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
                r += key_vals[v2]

        log.debug("KeyString: args = " + str(params) + ", return " + r)
        return r
        
class Run(VbaLibraryFunc):
    """
    Application.Run() function.
    """

    def eval(self, context, params=None):
        assert (len(params) >= 1)

        # Get the name of the function to call.
        func_name = str(params[0])
        
        # Strip the name of the function down if needed.
        if ("." in func_name):
            func_name = func_name[func_name.rindex(".") + 1:]
        
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

class Exec(VbaLibraryFunc):
    """
    Application.Exec() function.
    """

    def eval(self, context, params=None):
        assert (len(params) >= 1)

        # Get the command to run.
        cmd = str(params[0])
        context.report_action("Execute Command", cmd, 'Shell function', strip_null_bytes=True)

        # Say it was successful.
        return 0

class ExecQuery(VbaLibraryFunc):
    """
    Application.ExecQuery() function.
    """

    def eval(self, context, params=None):
        assert (len(params) >= 1)

        # Get the query to run.
        cmd = str(params[0])
        context.report_action("Execute Query", cmd, 'Query', strip_null_bytes=True)

        # Say it was successful.
        return ["", ""]
        
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

        # Handle certain object types.
        if (obj_type == "Scripting.Dictionary"):
            return {}
            
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
        if not context.open_files:
            log.error("Cannot process ReadText(). No open streams.")
            return
        if len(context.open_files) > 1:
            log.error("Cannot process ReadText(). Too many open streams.")
            return

        # Simulate the read.

        # Get the ID of the file.
        file_id = context.open_files.keys()[0]

        # TODO: This function takes a parameter that specifies the number of bytes to read!!

        # Get the data to read.
        raw_data = context.open_files[file_id]

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

class IsArray(VbaLibraryFunc):
    """
    IsArray() function.
    """

    def eval(self, context, params=None):
        assert (len(params) > 0)
        return isinstance(params[0], list)

class Month(VbaLibraryFunc):
    """
    Excel Month() function. Currently stubbed.
    """

    def eval(self, context, params=None):
        assert (len(params) == 1)
        try:
            arg = int(params[0])
            if (arg == 1):
                return 12
            if (arg < 33):
                return 1
            if (arg < 61):
                return 2
            if (arg < 92):
                return 3
            if (arg < 101):
                return 4

            # TODO: Handle other values.
            return 1

        except:
            pass

        return 1

ticks = 100000
class GetTickCount(VbaLibraryFunc):
    """
    GetTickCount() function. Randomly increments the tick count.
    """

    def eval(self, context, params=None):
        global ticks
        ticks += random.randint(100, 10000)
        return ticks

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

        # Get the indices of the cell.
        col = None
        try:
            col = int(params[1]) - 1
        except:
            try:
                col = excel_col_letter_to_index(params[1])
            except:
                log.warning("Cannot process Cells() call. Column " + str(params[1]) + " invalid.")
                return "NULL"
        row = None
        try:
            row = int(params[0]) - 1
        except:
            log.warning("Cannot process Cells() call. Row " + str(params[0]) + " invalid.")
            return "NULL"
        
        # Try each sheet until we read a cell.
        # TODO: Figure out the actual sheet to load.
        for sheet_index in range(0, len(context.loaded_excel.sheet_names())):
            
            # Load the current sheet.
            sheet = None
            try:
                sheet = context.loaded_excel.sheet_by_index(sheet_index)
            except:
                log.warning("Cannot process Cells() call. No sheets in file.")
                return "NULL"

            # Return the cell contents.
            try:
                r = str(sheet.cell(row, col)).replace("text:", "").replace("'", "")
                if (r.startswith('u')):
                    r = r[1:]
                log.debug("Excel Read: Cell(" + str(col) + ", " + str(row) + ") = '" + str(r) + "'")
                return r

            except Exception as e:
        
                # Failed to read cell.
                continue

        # Can't read the cell.
        log.warning("Failed to read Cell(" + str(col) + ", " + str(row) + ").")
        return "NULL"

class Range(VbaLibraryFunc):
    """
    Excel Range() function.
    """

    def eval(self, context, params=None):

        # Do we have a loaded Excel file?
        if (context.loaded_excel is None):

            # It can be the case that we have Range object in Word macro 
            if len(params) == 2 and isinstance(params[0], int) and isinstance(params[1], int):
                return context.globals["activedocument.content.text"][params[0]:params[1]]

            else:
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
        try:
            d = datetime.strptime(t, '%H:%M:%S')
            r = int(d.second)
        except:
            pass
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

        # Regular Debug.Print() ?
        if (len(params) != 1):
            log.warning("Wrong # of arguments for Print " + str(params))
            return

        # Save writes that look like they are writing URLs.
        data_str = str(params[0])
        if (("http:" in data_str) or ("https:" in data_str)):
            context.report_action('Write URL', data_str, 'Debug Print')

        context.report_action("Debug Print", str(params[0]), '')

class Debug(Print):
    """
    Debug() debugging function.
    """
    pass

class Echo(Print):
    """
    WScript.Echo() debugging function.
    """
    pass
        
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

class GetExtensionName(VbaLibraryFunc):

    def eval(self, context, params=None):
        r = ""
        if (len(params) >= 1):
            fname = str(params[0])
            if ("." in fname):
                r = fname[fname.rindex("."):]
        return r
                
class CreateTextFile(VbaLibraryFunc):
    """
    CreateTextFile() method.
    """

    def eval(self, context, params=None):
        if not params:
            return "NULL"

        # Get the name of the file being opened.
        try:
            fname = context.get(params[0])
        except KeyError:
            fname = str(params[0])

        # Save that the file is opened.
        context.open_file(fname)

        # How about returning the name of the opened file.
        return fname

class Open(CreateTextFile):
    """
    Open() file function. Also Open() HTTP function.
    """

    def eval(self, context, params=None):

        # Is this a HTTP GET?
        if ((len(params) >= 2) and (str(params[0]).strip() == "GET")):
            url = str(params[1])
            if (url.startswith("tp://")):
                url = "ht" + url
            context.report_action("GET", url, 'Interesting Function Call', strip_null_bytes=True)

        # It is a regular file open.
        else:
            super(Open, self).eval(context, params)

class OpenTextFile(CreateTextFile):
    """
    OpenTextFile() file function.
    """
    pass
            
class Timer(VbaLibraryFunc):
    """
    Timer() method (stubbed).
    """

    def eval(self, context, params=None):
        return int(time.mktime(datetime.now().timetuple()))

class Unescape(VbaLibraryFunc):
    """
    Unescape() strin unescaping method (stubbed).
    """

    def eval(self, context, params=None):

        # Get the string to unescape.
        assert len(params) > 0
        s = str(params[0])

        # It reverses the transformation performed by the Escape
        # method by removing the escape character ("\") from each
        # character escaped by the method. These include the \, *, +,
        # ?, |, {, [, (,), ^, $, ., #, and white space characters.
        s = s.replace("\\\\", "\\")
        s = s.replace("\\*", "*")
        s = s.replace("\\+", "+")
        s = s.replace("\\?", "?")
        s = s.replace("\\|", "|")
        s = s.replace("\\{", "{")
        s = s.replace("\\[", "[")
        s = s.replace("\\(", "(")
        s = s.replace("\\)", ")")
        s = s.replace("\\^", "^")
        s = s.replace("\\$", "$")
        s = s.replace("\\.", ".")
        s = s.replace("\\#", "#")
        s = s.replace("\\ ", " ")
        # TODO: Figure out more whitespace characters.

        # In addition, the Unescape method unescapes the closing
        # bracket (]) and closing brace (}) characters.
        if ("\\]" in s):
            start = s.rindex("\\]")
            end = start + len("\\]")
            s = s[:start] + "]" + s[end:]
        if ("\\}" in s):
            start = s.rindex("\\}")
            end = start + len("\\}")
            s = s[:start] + "}" + s[end:]

        # It replaces the hexadecimal values in verbatim string
        # literals with the actual printable characters. For example,
        # it replaces @"\x07" with "\a", or @"\x0A" with "\n". It
        # converts to supported escape characters such as \a, \b, \e,
        # \n, \r, \f, \t, \v, and alphanumeric characters.
        #
        # TODO: Do the hex unescaping.

        # Not documented, but it looks like %xx% is also handled as hex
        # unescaping.
        pat = r"%([0-9a-fA-F][0-9a-fA-F])"
        hex_strs = re.findall(pat, s)
        for h in hex_strs:            
            s = s.replace("%" + h, chr(int("0x" + h, 16)))

        # Return the unsescaped string.
        return s

class InternetGetConnectedState(VbaLibraryFunc):
    """
    InternetGetConnectedState() function from wininet.dll.
    """

    def eval(self, context, params=None):

        # Always connected.
        return True

class Not(VbaLibraryFunc):
    """
    Boolean Not() called as a function.
    """

    def eval(self, context, params=None):

        if ((len(params) == 0) or (not isinstance(params[0], bool))):
            log.warning("Cannot compute Not(" + str(params) + ").")
            return "NULL"
        return (not params[0])
                
class InternetOpenA(VbaLibraryFunc):
    """
    InternetOpenA() function from wininet.dll.
    """

    def eval(self, context, params=None):

        # Always succeeds.
        return True

class FreeFile(VbaLibraryFunc):
    """
    FreeFile() function.
    """

    def eval(self, context, params=None):

        # Return index of next open file.
        v = len(context.open_files) + 1
        return v

class Write(VbaLibraryFunc):
    """
    Write() method.
    """

    def eval(self, context, params=None):
        assert params and len(params) >= 1

        # Get the data.
        data = params[0]

        # Save writes that look like they are writing URLs.
        if (("http:" in data) or ("https:" in data)):
            context.report_action('Write URL', data, 'File Write', strip_null_bytes=True)

        # TODO: Currently the object on which Write() is being called is not
        # being tracked. We will only handle the Write() if there is only 1
        # current open file.
        if not context.open_files:
            log.error("Cannot process Write(). No open files.")
            return
        if len(context.open_files) > 1:
            log.error("Cannot process Write(). Too many open files.")
            return

        # Simulate the write.

        # Get the ID of the file.
        file_id = context.open_files.keys()[0]
        log.info("Writing data to " + str(file_id) + " .")

        context.write_file(file_id, data)


for _class in (MsgBox, Shell, Len, Mid, MidB, Left, Right,
               BuiltInDocumentProperties, Array, UBound, LBound, Trim,
               StrConv, Split, Int, Item, StrReverse, InStr, Replace,
               Sgn, Sqr, Base64Decode, Abs, Fix, Hex, String, CByte, Atn,
               Dir, RGB, Log, Cos, Exp, Sin, Str, Val, CInt, Pmt, Day, Round,
               UCase, Randomize, CBool, CDate, CStr, CSng, Tan, Rnd, Oct,
               Environ, IIf, CleanString, Base64DecodeString, CLng, Close, Put, Run, InStrRev,
               LCase, RTrim, LTrim, AscW, AscB, CurDir, LenB, CreateObject,
               CheckSpelling, Specialfolders, StrComp, Space, Year, Variable,
               Exec, CDbl, Print, OpenTextFile, CreateTextFile, Write, Minute, Second, WinExec,
               CallByName, ReadText, Variables, Timer, Open, CVErr, WriteLine,
               URLDownloadToFile, FollowHyperlink, Join, VarType, DriveExists, Navigate,
               KeyString, CVar, IsNumeric, Assert, Sleep, Cells, Shapes,
               Format, Range, Switch, WeekDay, ShellExecute, OpenTextFile, GetTickCount,
               Month, ExecQuery, ExpandEnvironmentStrings, Execute, Eval, ExecuteGlobal,
               Unescape, FolderExists, IsArray, FileExists, Debug, GetExtensionName,
               AddCode, StrPtr, International, ExecuteStatement, InlineShapes,
               RegWrite, QBColor, LoadXML, SaveToFile, InternetGetConnectedState, InternetOpenA,
               FreeFile, GetByteCount_2, GetBytes_4, TransformFinalBlock, Add, Raise, Echo,
               AddFromString, Not, PrivateProfileString, GetCursorPos):
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

        # Shell Constants
        ('vbHide', 0),
        ('vbNormalFocus', 1),
        ('vbMinimizedFocus.', 2),
        ('vbMaximizedFocus', 3),
        ('vbNormalNoFocus', 4),
        ('vbMinimizedNoFocus', 6),
):
    VBA_LIBRARY[name.lower()] = value

