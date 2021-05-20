"""@package expressions Utility functions.

"""

# pylint: disable=pointless-string-statement
"""
ViperMonkey - Utility functions.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

Project Repository:
https://github.com/decalage2/ViperMonkey
"""

#=== LICENSE ==================================================================

# ViperMonkey is copyright (c) 2015-2018 Philippe Lagadec (http://www.decalage.info)
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

import re
from curses_ascii import isascii
from curses_ascii import isprint
import base64
import string

import logging

# for logging
try:
    from core.logger import log
except ImportError:
    from logger import log
try:
    from core.logger import CappedFileHandler
except ImportError:
    from logger import CappedFileHandler
from logging import LogRecord
from logging import FileHandler

def safe_str_convert(s):
    """Convert a string to ASCII without throwing a unicode decode error.

    @param s (any) The thing to convert to a str.

    @return (str) The given thing as a string.

    """

    # Handle Excel strings.
    if (isinstance(s, dict) and ("value" in s)):
        s = s["value"]

    # Do the actual string conversion.
    try:
        return str(s)
    except UnicodeDecodeError:
        return filter(isprint, s)
    except UnicodeEncodeError:
        return filter(isprint, s)

class Infix(object):
    """Used to define our own infix operators.

    """
    def __init__(self, function):
        self.function = function
    def __ror__(self, other):
        return Infix(lambda x, self=self, other=other: self.function(other, x))
    def __or__(self, other):
        return self.function(other)
    def __rlshift__(self, other):
        return Infix(lambda x, self=self, other=other: self.function(other, x))
    def __rshift__(self, other):
        return self.function(other)
    def __call__(self, value1, value2):
        return self.function(value1, value2)

def safe_plus(x,y):
    """Handle "x + y" where x and y could be some combination of ints and
    strs.

    @param x (any) LHS of the addition.
    @param y (any) RHS of the addition.

    @return (str, float, or int) The result of x+y based on the types
    of x and y.

    """

    # Handle Excel Cell objects. Grrr.
    import excel
    if excel.is_cell_dict(x):
        x = x["value"]
    if excel.is_cell_dict(y):
        y = y["value"]
    
    # Handle NULLs.
    if (y == "NULL"):
        y = 0
    if (x == "NULL"):

        # Ugh. If x is uninitialized and we are adding a string to it
        # it looks like maybe VB makes this whole thing a string?
        if isinstance(y, str):
            x = ""
        else:
            x = 0

    # Loosely typed languages are terrible. 1 + "3" == 4 while "1" + 3
    # = "13". The type of the 1st argument drives the dynamic type
    # casting (I think) minus variable type information (Dim a as
    # String:a = 1 + "3" gets "13", we're ignoring that here). Pure
    # garbage.
    import vba_conversion
    if (isinstance(x, str)):
        y = vba_conversion.str_convert(y)
    if (isinstance(x, int)):
        y = vba_conversion.int_convert(y)

    # Easy case first.
    if (isinstance(x, (float, int)) and
        isinstance(y, (float, int))):
        return x + y
        
    # Fix data types.
    if (isinstance(y, str)):

        # NULL string in VB.
        if (x == 0):
            x = ""

        # String concat.
        return str(x) + y

    if (isinstance(x, str)):

        # NULL string in VB.
        if (y == 0):
            y = ""

        # String concat.
        return x + str(y)

    # Punt. We are not doing pure numeric addition and
    # we have already handled string concatentaion. Just
    # convert things to strings and hope for the best.
    return str(x) + str(y)


# Safe plus infix operator. Ugh.
# pylint: disable=unnecessary-lambda
plus=Infix(lambda x,y: safe_plus(x, y))

def safe_equals(x,y):
    """Handle "x = y" where x and y could be some combination of ints and
    strs.

    @param x (any) LHS of the equality check.
    @param y (any) RHS of the equality check.

    @return (boolean) The result of the equality check, taking into
    account the implicit type conversions VB performs to "help" the
    programmer.

    """

    # Handle NULLs.
    if (x == "NULL"):
        x = 0
    if (y == "NULL"):
        y = 0
    
    # Easy case first.
    # pylint: disable=unidiomatic-typecheck
    if (type(x) == type(y)):
        return x == y

    # Booleans and ints can be directly compared.
    if ((isinstance(x, bool) and (isinstance(y, int))) or
        (isinstance(y, bool) and (isinstance(x, int)))):
        return x == y
        
    # Punt. Just convert things to strings and hope for the best.
    return str(x) == str(y)


# Safe equals and not equals infix operators. Ugh. Loosely typed languages are terrible.
# pylint: disable=unnecessary-lambda
eq=Infix(lambda x,y: safe_equals(x, y))
neq=Infix(lambda x,y: (not safe_equals(x, y)))

def safe_print(text):
    """Sometimes printing large strings when running in a Docker
    container triggers exceptions.  This function just wraps a print
    in a try/except block to not crash ViperMonkey when this happens.

    @param text (any) The thing to print.

    """
    text = safe_str_convert(text)
    try:
        print(text)
    except Exception as e:
        msg = "ERROR: Printing text failed (len text = " + str(len(text)) + ". " + str(e)
        if (len(msg) > 100):
            msg = msg[:100]
        try:
            print(msg)
        except Exception:
            pass

    # if our logger has a FileHandler, we need to tee this print to a file as well
    for handler in log.handlers:
        if isinstance(handler, (FileHandler, CappedFileHandler)):
            # set the format to be like a print, not a log, then set it back
            handler.setFormatter(logging.Formatter("%(message)s"))
            handler.emit(LogRecord(log.name, logging.INFO, "", None, text, None, None, "safe_print"))
            handler.setFormatter(logging.Formatter("%(levelname)-8s %(message)s"))

def fix_python_overlap(var_name):
    """Eliminate collisions between VB variable/function names and Python
    builtin names.

    @param var_name (str) The VB variable/functio name.
    
    @return (str) The variable/function name (possibly) modified so
    that it does not collide with any Python builtin names.

    """
    builtins = set(["str", "list", "bytes", "pass"])
    if (var_name.lower() in builtins):
        var_name = "MAKE_UNIQUE_" + var_name
    var_name = var_name.replace("$", "__DOLLAR__")
    # RegExp object?
    if ((not var_name.endswith(".Pattern")) and
        (not var_name.endswith(".Global"))):
        var_name = var_name.replace(".", "")
    return var_name

def b64_decode(value):
    """Base64 decode a string.

    @param value (str) The string to decode.

    @return (str) On success return the base64 decode results, on
    error return None.

    """

    try:
        # Make sure this is a potentially valid base64 string
        tmp_str = ""
        try:
            tmp_str = filter(isascii, str(value).strip())
        except UnicodeDecodeError:
            return None
        tmp_str = tmp_str.replace(" ", "").replace("\x00", "")
        b64_pat = r"^[A-Za-z0-9+/=]+$"
        if (re.match(b64_pat, tmp_str) is not None):
            
            # Pad out the b64 string if needed.
            missing_padding = len(tmp_str) % 4
            if missing_padding:
                tmp_str += b'='* (4 - missing_padding)
        
            # Return the decoded value.
            conv_val = base64.b64decode(tmp_str)
            return conv_val
    
    # Base64 conversion error.
    except Exception:
        pass

    # No valid base64 decode.
    return None

class vb_RegExp(object):
    """Class to simulate a VBS RegEx object in python.

    """

    def __init__(self):
        self.Pattern = None
        self.Global = False

    def __repr__(self):
        return "<RegExp Object: Pattern = '" + str(self.Pattern) + "', Global = " + str(self.Global) + ">"
        
    def _get_python_pattern(self):
        pat = self.Pattern
        if (pat is None):
            return None
        if (pat.strip() != "."):
            pat1 = pat.replace("$", "\\$").replace("-", "\\-")
            fix_dash_pat = r"(\[.\w+)\\\-(\w+\])"
            pat1 = re.sub(fix_dash_pat, r"\1-\2", pat1)
            fix_dash_pat1 = r"\((\w+)\\\-(\w+)\)"
            pat1 = re.sub(fix_dash_pat1, r"[\1-\2]", pat1)
            pat = pat1
        return pat
        
    def Test(self, string):
        """Emulation of the VB Regex object Test() method.

        @param string (str) The string to test against the already set
        regex pattern.

        @return (boolean) True if the pattern matches, False if not.

        """
        pat = self._get_python_pattern()
        #print "PAT: '" + pat + "'"
        #print "STR: '" + string + "'"
        #print re.findall(pat, string)
        if (pat is None):
            return False
        return (re.match(pat, string) is not None)

    def Replace(self, string, rep):
        """Emulation of the VB Regex object Replace() method. The already set
        regex pattern is used.

        @param string (str) The string in which to replace substrings.

        @param rep (str) The replacement value.

        @return (boolean) True if the pattern matches, False if not.

        """
        pat = self._get_python_pattern()
        if (pat is None):
            return string
        rep = re.sub(r"\$(\d)", r"\\\1", rep)
        r = string
        try:
            r = re.sub(pat, rep, string)
        except Exception:
            pass
        return r

def get_num_bytes(i):
    """Get the minimum number of bytes needed to represent a given int
    value.

    @param i (int) The integer to check.

    @return (int) The number of bytes needed to represent the given
    int.

    """
    
    # 1 byte?
    if ((i & 0x00000000FF) == i):
        return 1
    # 2 bytes?
    if ((i & 0x000000FFFF) == i):
        return 2
    # 4 bytes?
    if ((i & 0x00FFFFFFFF) == i):
        return 4
    # Lets go with 8 bytes.
    return 8

def strip_nonvb_chars(s):
    """Strip invalid VB characters from a string.

    @param s (str) The string from which to strip invalid characters.
    
    @return (str) The cleaned up string.

    """

    # Handle unicode strings.
    if (isinstance(s, unicode)):
        s = s.encode('ascii','replace')
    
    # Sanity check.
    if (not isinstance(s, str)):
        return s

    # Do we need to do this?
    if (re.search(r"[^\x09-\x7e]", s) is None):
        return s
    
    # Strip non-ascii printable characters.
    r = re.sub(r"[^\x09-\x7e]", "", s)
    
    # Strip multiple 'NULL' substrings from the string.
    if (r.count("NULL") > 10):
        r = r.replace("NULL", "")
    return r
    
