"""@package vipermonkey.core.vba_library Emulation of builtin
VBScript/VBA functions.

Each function is represented with a class in this package.

"""

# pylint: disable=pointless-string-statement
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

# ViperMonkey is copyright (c) 2015-2020 Philippe Lagadec (http://www.decalage.info)
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

import logging
from datetime import datetime
from datetime import date
import time
import math
import re
import random
from from_unicode_str import from_unicode_str
import decimal
#import sys
#import traceback

from pyparsing import ParseException

import vb_str
from vba_context import VBA_LIBRARY
from vba_object import eval_arg
from vba_object import VbaLibraryFunc
from vba_object import VBA_Object
import expressions
import excel
import modules
import strip_lines
from python_jit import _eval_python
import utils
from excel import pull_cells_sheet, get_largest_sheet, get_num_rows
import vba_conversion

from logger import log

# === VBA LIBRARY ============================================================

# TODO: Word 2013 object model reference: https://msdn.microsoft.com/EN-US/library/office/ff837519.aspx

def member_access(var, field, globals_calling_scope=None):
    """Read a field from an object. Used in Python JIT code.

    @param var (any) The variable from which to read a field. If this
    is a dict the field will be read from the dict.

    @param field (str) The name of the field to read. If var is not a
    dict a global or local variable with the name of the given field
    will be returned if it exists.
    
    @param global_calling_scope (boolean) If True only look for
    defined variables in the global scope (no local).

    @return (any) If found the value of the read field will be
    returned, if not found "NULL" or the value of the var parameter
    will be returned.
    """

    # Were we given the globals in the calling scope?
    if (globals_calling_scope is None):
        globals_calling_scope = {}
    
    # Reading a field from a dict?
    field = utils.safe_str_convert(field)
    field_l = field.lower()
    if (isinstance(var, dict)):

        # Regular member access?
        if (field_l in var):
            return var[field_l]

        # Accessing text field?
        elif ((field_l == "text") and ("value" in var)):
            return var["value"]

        # Accessing cell column?
        elif ((field_l == "column") and ("col" in var)):
            return var["col"] + 1

        # Accessing cell row?
        elif ((field_l == "row") and ("row" in var)):
            return var["row"] + 1
        
        # Can't find field.
        return "NULL"

    # Reading the Text field of some object that is supposed to have a
    # .Text field?
    if (field == "Text"):

        # We know that the var is not a dict. Hope that there is a
        # Pyhton variable that already holds the text value.
        field = var
    
    # Punt and just see if we can return the value of a variable
    # with the same name as the field.
    if (field in locals()):
        # The globals dict is subscriptable.
        # pylint: disable=unsubscriptable-object
        return locals[field]
    elif (field in globals()):
        # The globals dict is subscriptable.
        # pylint: disable=unsubscriptable-object
        return globals[field]
    elif (field in globals_calling_scope):
        return globals_calling_scope[field]
    return var

# This function is here to ensure that we return the same global
# shellcode variable as what is updated by emulated VBA functions
# defined in this file.
def get_raw_shellcode_data():
    """Read the current shellcode bytes written during emulation.

    @return (dict) A dict mapping shellcode byte addresses (int) to
    shellcode byte values (int).
    """
    import vba_context
    return vba_context.shellcode
    
def run_external_function(func_name, context, params, lib_info):
    """Fake running an external DLL function with the given
    parameters. Saves an action of calling the given function in the
    given context.

    @param func_name (str) The name of the function.
    
    @param context (Context object) The current program state. This
    will be updated.
    
    @param params (list) The function call parameters.
    
    @param lib_info (str) The name of the DLL from which the function
    is imported.
    """
    call_str = utils.safe_str_convert(func_name) + "(" + utils.safe_str_convert(params) + ")"
    context.report_action('External Call', call_str, lib_info)
    return 1
    
def run_function(func_name, context, params):
    """Run an emulated VBA library function with the given
    parameters. Used in Python JIT code.

    @param func_name (str) The name of the function.
    
    @param context (Context object) The current program state. This
    will be updated.
    
    @param params (list) The function call parameters.
    
    @return (any) On success return the result of emulating the given
    function call, on failure return None.
    """

    # Rename python WScript.Shell.Run() calls.
    func_name = func_name.lower()
    if (func_name == "run"):
        func_name = "runshell"
    
    # Create an object for emulating the function.
    if (func_name not in VBA_LIBRARY):
        return None
    func_obj = VBA_LIBRARY[func_name]
    return func_obj.eval(context, params=params)
    

# Track the unresolved arguments to the current call.
var_names = None

class ExecuteExcel4Macro(VbaLibraryFunc):
    """Emulate ExecuteExcel4Macro() dynamic XLM evaluation function.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) == 0)):
            return 0
        xlm = utils.safe_str_convert(params[0])
        context.report_action('XLM Macro Execution', xlm, 'Dynamic XLM Macro Execution', strip_null_bytes=True)
        return 0

    def num_args(self):
        return 1
    
class GetSaveAsFilename(VbaLibraryFunc):
    """Emulate GetSaveAsFilename() function (stubbed).

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        return 'C:\\Users\\admin\\AppData\\Local\\Faked_SaveAs_File_Name.dat'

    def num_args(self):
        return 0

    def return_type(self):
        return "STRING"

class CreateFolder(VbaLibraryFunc):
    """Emulate CreatFolder() method.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) == 0)):
            return "NULL"
        folder = utils.safe_str_convert(params[0])
        context.report_action('Create Folder', folder, 'CreateFolder()', strip_null_bytes=True)
        return 0

    def num_args(self):
        return 1
    
class BuildPath(VbaLibraryFunc):
    """Emulate BuildPath() method

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) < 2)):
            return "NULL"
        return utils.safe_str_convert(params[0]) + utils.safe_str_convert(params[1])
    
class GetSpecialFolder(VbaLibraryFunc):
    """Emulate GetSpecialFolder() function

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
            return "UNKNOWN_FOLDER\\"
        try:
            typ = int(params[0])
            if (typ == 0):
                return "C:\\Windows\\"
            elif (typ == 1):
                return "C:\\Windows\\system32\\"
            elif (typ == 2):
                return "C:\\Documents and Settings\\admin\\Local Settings\\Temp\\"
            return "UNKNOWN_FOLDER\\"
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("GetSpecialFolder() exception: " + utils.safe_str_convert(e))
            return "UNKNOWN_FOLDER\\"

    def num_args(self):
        return 1

    def return_type(self):
        return "STRING"

class GetFolder(VbaLibraryFunc):
    """Emulate GetFolder() function

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) == 0)):
            return "UNKNOWN_FOLDER\\"
        context.report_action('Get Folder', "GetFolder(" + utils.safe_str_convert(params) + ")", '---', strip_null_bytes=True)
        return params[0]

    def num_args(self):
        return 1

    def return_type(self):
        return "STRING"
    
class MonthName(VbaLibraryFunc):
    """Emulate MonthName() function. Currently only returns results in
    Italian.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
            return "NULL"
        num = params[0]
        if ((not isinstance(num, int)) or (num > 12) or (num < 1)):
            return "NULL"
        # TODO: Somehow specify the language for the months.
        months = ["Gennaio", "Febbraio", "Marzo", "Aprile",
                  "Maggio", "Giugno", "Luglio", "Agosto",
                  "Settembre", "Ottobre", "Novembre", "Dicembre"]
        return months[num-1]

    def num_args(self):
        return 1

    def return_type(self):
        return "STRING"
    
class MultiByteToWideChar(VbaLibraryFunc):
    """Emulate MultiByteToWideChar() kernel32.dll function.

    """

    def eval(self, context, params=None):

        # Sanity check.
        if ((params is None) or (len(params) < 5)):
            return "NULL"

        # We have (hopefully) preprocessed this call so that the entire byte array
        # is passed as the 3rd parameter.
        data = params[2]
        if (not isinstance(data, list)):
            return "NULL"

        # Is the given string represented in wide chars?
        is_wide_char = True
        skip = False
        for b in data:
            skip = (not skip)
            if (skip):
                continue
            if (b != 0):
                is_wide_char = False
                break
        
        # Convert this to a string. If this is a ASCII string represented in wide
        # chars skip every 2nd byte (assume these are 0).
        r = ""
        skip = True
        for b in data:
            skip = (not skip)            
            if (((not isinstance(b, int)) or (b > 255) or skip) and
                (is_wide_char)):
                continue
            r += chr(b)

        # Get the name of the variable where the result is stored.
        name = params[4]

        # Update the result variable with the converted string.
        context.set(name, r)
        return len(r)

    def num_args(self):
        return 5
    
class IsEmpty(VbaLibraryFunc):
    """Emulate IsEmpty() function.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) == 0)):
            return True
        item = params[0]

        # Handle flat out empty values.
        if ((item is None) or (item == "NULL")):
            return True

        # Handle Excel cells.
        if (isinstance(item, dict) and ("value" in item)):
            return self.eval(context, [item["value"]])
        if (item == "empty:u''"):
            return True
        
        # Handle list type data structures.
        if ((hasattr(item, '__len__')) and (len(item) == 0)):
            return True
        return False

    def num_args(self):
        return 1
    
class LanguageID(VbaLibraryFunc):
    """Emulate LanguageID() reference (stubbed).

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint
        
        # This is usually used for gating, so have it match anything.
        return "**MATCH ANY**"

    def num_args(self):
        return 1
    
class URLDownloadToFile(VbaLibraryFunc):
    """Emulate URLDownloadToFile() external function.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) < 3)):
            return 0
        context.report_action('Download URL', utils.safe_str_convert(params[1]), 'External Function: urlmon.dll / URLDownloadToFile', strip_null_bytes=True)
        context.report_action('Write File', utils.safe_str_convert(params[2]), 'External Function: urlmon.dll / URLDownloadToFile', strip_null_bytes=True)
        return 1

    def num_args(self):
        return 3
    
class URLDownloadToFileA(URLDownloadToFile):
    pass

class URLDownloadToFileW(URLDownloadToFile):
    pass
        
class WeekDay(VbaLibraryFunc):
    """Emulate VBA WeekDay function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Get date string.
        if ((params is None) or (len(params) == 0)):
            return 1
        date_str = utils.safe_str_convert(params[0]).replace("#", "")
        date_obj = None
        
        # TODO: Handle more and more date formats.

        # 4/20/1889
        if (date_str.count("/") == 2):
            try:
                date_obj = datetime.strptime(date_str, '%m/%d/%Y')
            except Exception as e:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("WeekDay() exception: " + utils.safe_str_convert(e))

        if (date_obj is not None):
            r = date_obj.weekday()
            # Looks like VBA week day is off by 2 from Python week day.
            r += 2
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("WeekDay(%r): return %r" % (date_str, r))
            return r
        return 1

    def num_args(self):
        return 1
    
class Format(VbaLibraryFunc):
    """Emulate VBA Format function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            return "NULL"
        
        # Are we faking a value for this particular format call?
        r = params[0]
        if (len(params) > 1):
            typ = utils.safe_str_convert(params[1])

            # Fake up a date if needed.
            # TODO: Currently this fake date is specific to a campaign targeting Italy.
            if (typ.lower() == "long date"):
                r = "gioved\xc3\xac 27 giugno 2019"

            # Let's match any currency checks.
            if (typ.lower() == "currency"):
                r = "**MATCH ANY**"

        # Done.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Format(%r): return %r" % (self, r))
        return r

    def num_args(self):
        return 1

    def return_type(self):
        return "STRING"
    
class MsgBox(VbaLibraryFunc):
    """Emulate MsgBox() function. Stubbed to just track the message
    box call as an action and always return vbOK.

    """

    def eval(self, context, params=None):
        context.report_action('Display Message', params[0], 'MsgBox', strip_null_bytes=True)
        return 1  # vbOK

    def num_args(self):
        return 1
    
class Kill(VbaLibraryFunc):
    """Emulate Kill() function.

    """

    def eval(self, context, params=None):
        if ((params is not None) and (len(params) > 0)):
            context.report_action('Delete File', params[0], 'Kill', strip_null_bytes=True)
        return ""

    def num_args(self):
        return 1

    def return_type(self):
        return "STRING"
    
class RmDir(VbaLibraryFunc):
    """Emulate RmDir() function.

    """

    def eval(self, context, params=None):
        if ((params is not None) and (len(params) > 0)):
            context.report_action('Delete Directory', params[0], 'RmDir', strip_null_bytes=True)
        return ""  # vbOK

    def num_args(self):
        return 1

    def return_type(self):
        return "STRING"

class _Chr(VbaLibraryFunc):
    """Implementation of Chr() and ChrW() used in Python JIT code.  This
    is also used under the covers by lib_functions.Chr.eval().

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
            return "NULL"

        # Chr() called basically on a Cell object?
        param = params[0]
        if (isinstance(param, dict) and ("value" in param)):
            param = param["value"]
        
        # Proper float conversion for Chr().
        if (isinstance(param, float)):
            param = int(round(param))
        
        # NOTE: in the specification, the parameter is expected to be an integer
        # But in reality, VBA accepts a string containing the representation
        # of an integer in decimal, hexadecimal or octal form.
        # It also ignores leading and trailing spaces.
        # Examples: Chr("65"), Chr("&65 "), Chr(" &o65"), Chr("  &H65")
        # => need to parse the string as integer
        # It also looks like floating point numbers are allowed.
        try:
            param = vba_conversion.coerce_to_int(param)
        except Exception as e:
            log.error("%r is not a valid chr() value. Returning ''. %r" % (params[0], utils.safe_str_convert(e)))
            return ''
        
        # Figure out whether to create a unicode or ascii character.
        converter = chr
        if (param < 0):
            param = param * -1
        if (param > 255):
            converter = unichr
            
        # Do the conversion.
        try:
            r = converter(param)
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Chr(" + utils.safe_str_convert(param) + ") = " + r)
            return r
        except Exception as e:
            log.error(utils.safe_str_convert(e))
            log.error("%r is not a valid chr() value. Returning ''." % param)
            return ""

    def num_args(self):
        return 1

    def return_type(self):
        return "STRING"

class Chr(_Chr):
    pass

class ChrB(_Chr):
    pass

class ChrW(_Chr):
    pass
    
class ChDir(VbaLibraryFunc):
    """Emulate ChDir() function.

    """

    def eval(self, context, params=None):
        if ((params is not None) and (len(params) > 0)):
            context.report_action('Change Directory', params[0], 'ChDir', strip_null_bytes=True)
        return ""  # vbOK

    def num_args(self):
        return 1

    def return_type(self):
        return "STRING"
    
class Quit(VbaLibraryFunc):
    """Emulate Wscript.Quit() (stubbed), just keeps going.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        log.warning("Ignoring Wscript.Quit() call. Execution is continuing...")
        return 1

    def num_args(self):
        return 0
    
class QBColor(VbaLibraryFunc):
    """Emulate QBColor() color lookup function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
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

    def num_args(self):
        return 1
    
class MakeSureDirectoryPathExists(VbaLibraryFunc):
    """Emulate MakeSureDirectoryPathExists() VB function (stubbed).

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) == 0)):
            return 1
        context.report_action("Create Folder", params[0], 'Interesting Function Call', strip_null_bytes=True)
        return 1

    def num_args(self):
        return 1
    
class FolderExists(VbaLibraryFunc):
    """Emulate FolderExists() VB function (stubbed).

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            return False

        # Is this a directory that is expected to exist?
        expected_dirs = set(["c:\\users", "c:\\programdata"])
        curr_dir = utils.safe_str_convert(params[0]).lower()
        return ((curr_dir in expected_dirs) or (curr_dir[:-1] in expected_dirs))

    def num_args(self):
        return 1

class GetFile(VbaLibraryFunc):
    """Emulate GetFile() VB method (stubbed).

    """

    def eval(self, context, params=None):
        if (params is None):
            return
        context.report_action('Get File', "GetFile(" + utils.safe_str_convert(params) + ")", '---', strip_null_bytes=True)

    def num_args(self):
        return 1

class FileLen(VbaLibraryFunc):
    """Emulate FileLen() VB function (stubbed). Always returns -1.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) == 0)):
            return -1
        context.report_action('Check File Length', "FileLen(" + utils.safe_str_convert(params) + ")", '---', strip_null_bytes=True)
        return -1

    def num_args(self):
        return 1
    
class FileCopy(VbaLibraryFunc):
    """Emulate FileCopy() VB function (stubbed).

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) < 2)):
            return
        context.report_action('Copy File', "FileCopy(" + utils.safe_str_convert(params) + ")", '---', strip_null_bytes=True)

    def num_args(self):
        return 2

class CopyFile(FileCopy):
    pass
    
class CopyHere(VbaLibraryFunc):
    """Emulate CopyHere() VB function (stubbed).

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) == 0)):
            return
        context.report_action('Copy File', "CopyHere(" + utils.safe_str_convert(params) + ")", '---', strip_null_bytes=True)

    def num_args(self):
        return 1
        
class FileExists(VbaLibraryFunc):
    """Emulate FileExists() VB function (stubbed). For some files it
    always says they exist ("cmd.exe", etc.), for the rest it always
    says they do not exist.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
            return False
        fname = utils.safe_str_convert(params[0])
        if ("powershell" in fname.lower()):
            return True
        if ("cmd.exe" in fname.lower()):
            return True
        if ("explorer.exe" in fname.lower()):
            return True
        if ("c:\\programdata" in fname.lower()):
            return True
        # Lets say some log files exist.
        tmp_log_pat = r"c:[\\]{1,6}temp[\\]{1,6}[^\.]{1,200}\.log"
        if (re.search(tmp_log_pat, fname.lower()) is not None):
            return True
        return False

    def num_args(self):
        return 1
    
class Switch(VbaLibraryFunc):
    """Emulate Switch() logic flow function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        # We need an even number of parameters.
        if ((len(params) == 0) or
            (len(params) % 2 != 0)):
            return 'NULL'

        # Return the 1st true case.
        pos = 0
        while (pos < (len(params) - 1)):
            # We actually want to explicitly check for True.
            # pylint: disable=singleton-comparison
            if (params[pos] is True):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Switch(%r): return %r" % (self, params[pos + 1]))
                return params[pos + 1]
            pos += 2

        # If we get here nothing is true.
        return 'NULL'

    def num_args(self):
        return 2
    
class Len(VbaLibraryFunc):
    """Emulate Len() function.

    """

    def eval(self, context, params=None):
        if (isinstance(params[0], int)):
            return len(utils.safe_str_convert(params[0]))
        val = params[0]
        if (hasattr(params[0], '__len__')):

            # Is this a string?            
            if (isinstance(val, str)):

                # If this is VBScript strings are sensible and we can just return the length.
                if (context.is_vbscript):
                    return len(val)

                # Convert the string to a VbStr to handle mized ASCII/wide char weirdness.
                vb_val = vb_str.VbStr(val, context.is_vbscript)
                return vb_val.len()

            # Something with a length that is not a string.
            else:
                return len(val)
        else:
            log.error("Len: " + utils.safe_str_convert(type(params[0])) + " object has no len(). Returning 0.")
            return 0

    def num_args(self):
        return 1
        
class LenB(VbaLibraryFunc):
    """Emulate LenB() function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
            return 0
        # TODO: Somehow take the default character set into account.
        try:
            return len(params[0])
        except TypeError:
            return 0

    def num_args(self):
        return 1
        
class Sleep(VbaLibraryFunc):
    """Emulate Sleep() function (stubbed). Does nothing.
    
    """

    def eval(self, context, params=None):
        pass

    def num_args(self):
        return 1
    
class TypeName(VbaLibraryFunc):
    """Emulate TypeName() function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            return "NULL"

        # Return VB type.
        val = params[0]
        if ((val == "NULL") or (val == "")):
            return "Empty"
        if (isinstance(val, bool)):
            return "Boolean"
        if (isinstance(val, str)):
            if (val.lower() == "adodb.stream"):
                return "ADODB.Stream"
            return "String"
        if (isinstance(val, int)):
            return "Integer"
        if (isinstance(val, float)):
            return "Double"
        return "NULL"

    def num_args(self):
        return 1

    def return_type(self):
        return "STRING"
    
class VarType(VbaLibraryFunc):
    """Emulate VarType() function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            return 0

        # Return VB type ID.
        val = params[0]
        if ((val == "NULL") or (val == "")):
            return 0
        if (isinstance(val, bool)):
            return 11
        if (isinstance(val, str)):
            return 8
        if (isinstance(val, int)):
            return 2
        if (isinstance(val, float)):
            return 5
        if (isinstance(val, long)):
            return 3
        return 0

    def num_args(self):
        return 1
    
class Mid(VbaLibraryFunc):
    """Emulate Mid / MidB function

    """

    def eval(self, context, params=None):
        if (params is None):
            log.error("Invalid arguments " + utils.safe_str_convert(params) + " to Mid().")
            return ""
        if ((len(params) > 0) and (params[0] == "ActiveDocument")):
            params = params[1:]
        if (params is None):
            log.error("Invalid arguments " + utils.safe_str_convert(params) + " to Mid().")
            return ""
        if (len(params) not in (2,3)):
            log.error("Invalid arguments " + utils.safe_str_convert(params) + " to Mid().")
            return ""
        s = params[0]
        # "If String contains the data value Null, Null is returned."
        if ((s is None) or (s == "NULL")): return "\x00"
        # If start is NULL, NULL is also returned.
        if ((params[1] is None) or (params[1] == "NULL")): return "\x00"
        if not isinstance(s, basestring):
            s = vba_conversion.str_convert(s)
        start = 0
        try:
            start = vba_conversion.int_convert(params[1])
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Mid() exception: " + utils.safe_str_convert(e))

        # Convert the string to a VbStr to handle mized ASCII/wide char weirdness.
        vb_s = None
        s_len = len(s)
        if (not context.is_vbscript):
            vb_s = vb_str.VbStr(s, context.is_vbscript)
            s_len = vb_s.len()
        
        # "If Start is greater than the number of characters in String,
        # Mid returns a zero-length string ("")."
        if (start > s_len):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Mid: start>len(s) => return ""')
            return ''

        # What to do when start<=0 is not specified:
        if (start <= 0):
            return "NULL"

        # If length not specified, return up to the end of the string:
        if (len(params) == 2):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Mid: no length specified, return s[%d:]=%r' % (start-1, s[start-1:]))
            return s[start-1:]
        length = 0
        try:
            length = vba_conversion.int_convert(params[2])
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Mid() exception: " + utils.safe_str_convert(e))

        # "If omitted or if there are fewer than Length characters in the text
        # (including the character at start), all characters from the start
        # position to the end of the string are returned."
        if start+length-1 > s_len:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Mid: start+length-1>len(s), return s[%d:]' % (start-1))
            if context.is_vbscript:
                return s[start-1:]
            return vb_s.get_chunk(start - 1, vb_s.len()).to_python_str()

        # What to do when length<=0 is not specified:
        if length <= 0:
            return ''

        # Regular Mid().
        if context.is_vbscript:
            r = s[start - 1:start-1+length]
        else:
            r = vb_s.get_chunk(start - 1, start - 1 + length).to_python_str()

        # Done.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('Mid: return s[%d:%d]=%r' % (start - 1, start-1+length, r))
        return r

    def num_args(self):
        return 2

    def return_type(self):
        return "STRING"
    
class MidB(Mid):
    pass

class Left(VbaLibraryFunc):
    """Emulate Left() function.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) < 2)):
            return "NULL"
        if (len(params) > 2):
            params = params[-2:]
        s = params[0]
        if s is None: return None

        # Arg should be a string.
        s = utils.safe_str_convert(s)
            
        # Don't modify the "**MATCH ANY**" special value.
        if (s.strip() == "**MATCH ANY**"):
            return s
        
        # "If String contains the data value Null, Null is returned."
        start = 0
        try:
            start = vba_conversion.int_convert(params[1])
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Left() exception: " + utils.safe_str_convert(e))

        # Convert the string to a VbStr to handle mized ASCII/wide char weirdness.
        vb_s = vb_str.VbStr(s, context.is_vbscript)
        
        # "If Start is greater than the number of characters in String,
        # Left returns the whole string.
        if (start > vb_s.len()):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Left: start>len(s) => return s')
            return s

        # Return empty string if start <= 0.
        if (start <= 0):
            return ""

        # Return characters from start of string.
        #r = s[:start]
        r = vb_s.get_chunk(0, start).to_python_str()
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('Left: return s[0:%d]=%r' % (start, r))
        return r

    def num_args(self):
        return 1

    def return_type(self):
        return "STRING"
    
class PrivateProfileString(VbaLibraryFunc):
    """Emulate PrivateProfileString method.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        return "**MATCH ANY**"

    def num_args(self):
        return 1

    def return_type(self):
        return "STRING"
    
class EOF(VbaLibraryFunc):
    """Emulate Stubbed EOF() file method.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        return True

    def num_args(self):
        return 1
    
class Error(VbaLibraryFunc):
    """Emulate Stubbed Error() method.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        return "Some error message..."

    def num_args(self):
        return 1

    def return_type(self):
        return "STRING"
    
class Right(VbaLibraryFunc):
    """Emulate Right() function.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) < 2)):
            return "NULL"
        if (len(params) > 2):
            params = params[-2:]
        s = params[0]

        # Don't modify the "**MATCH ANY**" special value.
        if (utils.safe_str_convert(s).strip() == "**MATCH ANY**"):
            return s
        
        # "If String contains the data value Null, Null is returned."
        if s is None: return None
        if not isinstance(s, basestring):
            s = utils.safe_str_convert(s)
        start = 0
        try:
            start = vba_conversion.int_convert(params[1])
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Right() exception: " + utils.safe_str_convert(e))

        # Convert the string to a VbStr to handle mized ASCII/wide char weirdness.
        vb_s = vb_str.VbStr(s, context.is_vbscript)
        
        # "If Start is greater than the number of characters in String,
        # Right returns the whole string.
        if (start > vb_s.len()):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Right: start>len(s) => return s')
            return s

        # Return empty string if start <= 0.
        if (start <= 0):
            return ""

        # Return characters from end of string.
        #r = s[(len(s) - start):]
        r = vb_s.get_chunk(vb_s.len() - start, vb_s.len()).to_python_str()
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('Right: return s[%d:]=%r' % (start, r))
        return r

    def num_args(self):
        return 2

    def return_type(self):
        return "STRING"
    
class BuiltInDocumentProperties(VbaLibraryFunc):
    """Emulate calling
    ActiveDocument.BuiltInDocumentProperties('PROPERTYNAME')

    """

    def eval(self, context, params=None):

        if ((params is None) or (len(params) < 1)):
            return "NULL"

        # Get the property we are looking for.
        prop = utils.safe_str_convert(params[0])
        r = context.read_metadata_item(prop)
        if (r == ""):
            r = "NULL"
        return r

    def num_args(self):
        return 1

    def return_type(self):
        return "STRING"
    
class Item(BuiltInDocumentProperties):
    """Assumes that Item() is only called on BuiltInDocumentProperties.

    """

    def eval(self, context, params=None):

        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            return "NULL"

        # Were we given the dict to work with?
        with_dict = None
        index = None
        if ((len(params) >= 2) and (isinstance(params[0], dict))):

            # Dict is 1st parameter.        
            with_dict = params[0]
            # Item index is 2nd parameter.
            index = vba_conversion.coerce_to_int(params[1])
        
        # Are we reading from a With Scripting.Dictionary?
        elif ((context.with_prefix_raw is not None) and
              (context.contains(utils.safe_str_convert(context.with_prefix_raw)))):

            # Get the item index.
            index = None
            try:
                index = vba_conversion.coerce_to_int(params[0])
            except Exception as e:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Item() exception: " + utils.safe_str_convert(e))
                return "NULL"

            # Is the With variable value a dict?
            with_dict = context.get(utils.safe_str_convert(context.with_prefix_raw))
            if (not isinstance(with_dict, dict)):
                with_dict = None

        # Are we reading from a Scripting.Dictionary?
        if (with_dict is not None):

            # Valid key?
            if (index in with_dict):
                return with_dict[index]
            return "NULL"
            
        # Not a workable Scripting.Dictionary.Item() call. Treat as
        # BuiltInDocumentProperties.Item()
        return super(Item, self).eval(context, params)

class Items(VbaLibraryFunc):
    """Modified version of Scripting.Dictionary.Items() call. ViperMonkey
    modifies these calls to take the underlying dict containing the
    items as the 1st parameter.

    """

    def eval(self, context, params=None):

        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            return "NULL"
        
        # Were we given the dict to work with?
        the_map = None
        index = None
        if ((len(params) >= 2) and (isinstance(params[0], dict))):

            # Dict is 1st parameter.        
            the_map = params[0]
            # Item index is 2nd parameter.
            index = vba_conversion.coerce_to_int(params[1])
            
        # Are we reading from a With Scripting.Dictionary?
        elif ((context.with_prefix_raw is not None) and
              (context.contains(utils.safe_str_convert(context.with_prefix_raw)))):

            # Item index is 1st parameter.
            index = vba_conversion.coerce_to_int(params[0])
            
            # Is the With variable value a dict?
            the_map = context.get(utils.safe_str_convert(context.with_prefix_raw))
            if (not isinstance(the_map, dict)):
                return "NULL"
        else:
            return "NULL"
        
        # Items() handles the added entries in order, so this thing
        # does not act like a standard hash map.
        if ("__ADDED_ITEMS__" not in the_map):
            return "NULL"
        added_items = the_map["__ADDED_ITEMS__"]
        
        # Is the index valid?
        if ((index < 0) or (index >= len(added_items))):
            return "NULL"

        # Return the item by index.
        return added_items[index]
    
class Shell(VbaLibraryFunc):
    """Emulate Function Shell(PathName As Variant, Optional WindowStyle
    As VbAppWinStyle = vbMinimizedFocus) As Double

    Runs an executable program and returns a Double representing the
    implementation-defined program's task ID if successful, otherwise
    it returns the data value 0.

    """

    def eval(self, context, params=None):

        # This might be the string "shell".
        if (params is None):
            return "shell"
        try:
            params.remove('ThisDocument')
            params.remove('BuiltInDocumentProperties')
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Shell() exception: " + utils.safe_str_convert(e))

        # Get the command to run.
        command = params[0]

        # Is the command invalid?
        if (not isinstance(command, str)):

            # No, Shell() will throw an error.
            msg = "Shell(" + utils.safe_str_convert(command) + ") throws an error."
            context.set_error(msg)
            return 0

        # We have a valid shell command. Track it.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Shell command type: " + utils.safe_str_convert(type(command)))
        log.info('Shell(%r)' % command)
        context.report_action('Execute Command', command, 'Shell function', strip_null_bytes=True)
        return 0

    def num_args(self):
        return 1
    
class ExecuteStatement(Shell):
    pass
    
class ShellExecute(Shell):
    """Emulate shell.application.ShellExecute() function.

    """
    
    def eval(self, context, params=None):

        if ((params is None) or (len(params) < 2)):
            return 0
        command = utils.safe_str_convert(params[0])
        args = utils.safe_str_convert(params[1])
        log.info('ShellExecute(%r %r)' % (command, args))
        context.report_action('Execute Command', command + " " + args, 'Shell function', strip_null_bytes=True)
        return 0

class Eval(VbaLibraryFunc):
    """Emulate VBScript expression Eval() function.

    """
    
    def eval(self, context, params=None):

        # Pull out the expression to eval.
        if ((params is None) or (len(params) < 1)):
            return 0
        expr = utils.strip_nonvb_chars(utils.safe_str_convert(params[0]))

        # Save original expression.
        orig_expr = expr
        
        # We are executing a string, so any "" in the string are really '"' when
        # we execute the string. Maybe?
        expr = expr.replace('""', '"')

        # Parse it. Assume this is an expression.
        r = None
        try:    
            obj = expressions.expression.parseString(expr, parseAll=True)[0]
            
            # Evaluate the expression in the current context.
            # TODO: Does this actually get evalled in the current context?
            r = obj

        except ParseException:

            # Maybe replacing the '""' with '"' was a bad idea. Try the original
            # command.
            try:
                log.warning("Parsing failed on modified expression. Trying original expression ...")
                obj = expressions.expression.parseString(orig_expr, parseAll=True)[0]
                r = obj
            except ParseException:
                log.error("Parse error. Cannot evaluate '" + orig_expr + "'")
                return "NULL"

        # Do any final evaulation needed.
        if (isinstance(r, VBA_Object)):
            r = r.eval(context)
        return r

    def return_type(self):
        return "UNKNOWN"
    
class Exists(VbaLibraryFunc):
    """Emulate Document or Scripting.Dictionary Exists() method.

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            return False

        # Scripting.Dictionary Exists()?
        if ((len(params) == 2) and (isinstance(params[0], dict))):
            r = (params[1] in params[0])
            return r

        # Document Exists(). Default to False.
        return False

class Count(VbaLibraryFunc):
    """Emulate Document or Scripting.Dictionary Count() method.

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or
            (len(params) == 0) or
            (not isinstance(params[0], dict))):
            return "NULL"

        # Return the # of Added items.
        # Subtract 1 due to "__ADDED_ITEMS__" entry in dict.
        return (len(params[0]) - 1)


parse_cache = {}
class Execute(VbaLibraryFunc):
    """Emulate WScript Execute() function.

    """

    def eval(self, context, params=None):

        # Sanity check.
        if ((params is None) or
            (len(params) == 0) or
            (isinstance(params[0], (VBA_Object, VbaLibraryFunc)))):
            return "NULL"
        
        # Save the command.
        command = utils.strip_nonvb_chars(utils.safe_str_convert(params[0]))
        context.report_action('Execute Command', command, 'Execute() String', strip_null_bytes=True)
        command += "\n"

        # Fix invalid string assignments.
        command = strip_lines.fix_vba_code(command)

        # Save original command string.
        orig_command = command
        
        # We are executing a string, so any "" in the string are really '"' when
        # we execute the string.
        command = command.replace('""', '"')

        # Have we already parsed this?
        obj = None
        if (orig_command in parse_cache):
            obj = parse_cache[orig_command]

        # We have not parsed this previously.
        else:

            # Parse it.
            try:
                obj = modules.module.parseString(command, parseAll=True)[0]
            except ParseException:
                pass

            # Was is parsed?
            if (obj is None):
                
                # Maybe replacing the '""' with '"' was a bad idea. Try the original
                # command.
                try:
                    log.warning("Parsing failed on modified command. Trying original command ...")
                    obj = modules.module.parseString(orig_command, parseAll=True)[0]
                except ParseException:
                    pass

            # Was is parsed?
            if (obj is None):
                
                # Next attempt. Try cutting off the final line and executing.
                if ("\n" in orig_command.strip()):
                    short_command = orig_command.strip()[:orig_command.strip().rindex("\n")]
                    try:
                        log.warning("Parsing failed on original command. Trying shortened command minus last line ...")
                        obj = modules.module.parseString(short_command, parseAll=True)[0]
                    except ParseException:
                        pass

            # Was is parsed?
            if (obj is None):

                # Try deleteing first non-alphabetic characters and reparsing.
                pos = 0
                ascii_pat = r"[A-Za-z]"
                while (pos < len(orig_command)):
                    if (re.match(ascii_pat, orig_command[pos])):
                        break
                    pos += 1
                short_command = orig_command[pos:].replace("\x1c", "\r").replace("\x1d", "\n")
                try:
                    log.warning("Parsing failed on original command. Trying shortened command up to first alphabetic character ...")
                    obj = modules.module.parseString(short_command, parseAll=True)[0]
                except ParseException:
                    pass

            # Was is parsed?
            if (obj is None):
                
                # Try the original command with ALL code rewriting applied.
                try:
                    log.warning("Parsing failed on shortened command. Trying original command with all code rewriting performed...")
                    command = strip_lines.strip_useless_code(orig_command, set())
                    obj = modules.module.parseString(command, parseAll=True)[0]
                except ParseException:
                    pass
                
            # Cannot ever parse this. Punt.
            if (obj is None):
                if (len(orig_command) > 50):
                    orig_command = orig_command[:50] + " ..."
                log.error("Parse error. Cannot evaluate '" + orig_command + "'")
                return "NULL"

        # Cache the parsed VB.
        parse_cache[orig_command] = obj
                    
        # Are we execing this code inside JIT generated Python code?
        # Note that the dict of local variable values to update when we exec the
        # generated Python code is passed as the 2nd to last argument to Execute().
        if ((params[-1] == "__JIT_EXEC__") and
            (_eval_python(obj, context, add_boilerplate=True, namespace=params[-2]))):
            return "NULL"

        # No JIT. Do regular emulation.

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
    """Emulate WScript ExecuteGlobal() function.

    """
    pass

class AddCode(Execute):
    """Emulate Visual Basic script control AddCode() method.

    """
    pass

class AddFromString(Execute):
    """Emulate Office programmatic macro editing method.

    """
    pass

class IsObject(VbaLibraryFunc):
    """Emulate IsObject() function (stubbed). Currently stubbed to always
    return True.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        # Say everything is an object.
        return True

    def num_args(self):
        return 1

    def return_type(self):
        return "BOOLEAN"
    
class AddItem(VbaLibraryFunc):
    """Emulate ListBox AddItem() VB object method.

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) < 2)):
            return None
        the_list = params[0]
        value = params[1]
        if (not isinstance(the_list, list)):
            return None
        r = list(the_list)
        r.append(value)
        return r
    
class Add(VbaLibraryFunc):
    """Emulate Add() VB object method. Currently only add to
    Scripting.Dictionary objects is supported.

    """

    def eval(self, context, params=None):
        """
        params[0] = object
        params[1] = key
        params[2] = value
        """
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) < 3)):
            return {}

        # Get the object (dict), key, and value.
        obj = params[0]
        key = params[1]
        val = params[2]
        if (not isinstance(obj, dict)):
            return {}

        # Add to the map.
        obj[key] = val
        if ("__ADDED_ITEMS__" not in obj):
            obj["__ADDED_ITEMS__"] = []
        obj["__ADDED_ITEMS__"].append(val)

        # Done.
        return obj

class Array(VbaLibraryFunc):
    """Emulate creating an array with Array() function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        r = []
        if ((len(params) == 1) and (params[0] == "NULL")):
            return []        
        r = list(params)
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Array: return %r" % r)
        return r

class UBound(VbaLibraryFunc):
    """Emulate UBound() array function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
            return "NULL"
        arr = params[0]
        # TODO: Handle multidimensional arrays.
        if ((arr is None) or (not hasattr(arr, '__len__'))):
            log.error("UBound(" + utils.safe_str_convert(arr) + ") cannot be computed.")
            return 0
        r = len(arr) - 1
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("UBound: return %r" % r)
        return r

class LBound(VbaLibraryFunc):
    """Emulate LBound() array function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
            return "NULL"
        # TODO: Handle multidimensional arrays.
        r = 0
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("LBound: return %r" % r)
        return r

class Trim(VbaLibraryFunc):
    """Emulate Trim() string function.

    """

    def eval(self, context, params=None):
        context = context # pylint
        
        # Sanity check arguments.
        if ((params is None) or (len(params) == 0)):
            log.error("Invalid paramater to Trim().")
            return ""

        # Trim the string.
        r = utils.safe_str_convert(params[0]).strip()
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Trim: return %r" % r)
        return r

    def return_type(self):
        return "STRING"
    
class RTrim(VbaLibraryFunc):
    """Emulate RTrim() string function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
            return "NULL"
        r = None
        if (isinstance(params[0], int)):
            r = utils.safe_str_convert(params[0])
        else:
            r = params[0].rstrip()
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("RTrim: return %r" % r)
        return r

    def return_type(self):
        return "STRING"    

class LTrim(VbaLibraryFunc):
    """Emulate LTrim() string function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
            return ""
        r = None
        if (isinstance(params[0], int)):
            r = utils.safe_str_convert(params[0])
        else:
            r = params[0].lstrip()
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("LTrim: return %r" % r)
        return r

    def return_type(self):
        return "STRING"

class AscW(VbaLibraryFunc):
    """Emulate AscW() character function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
            return "NULL"
        c = params[0]
        if (c == "NULL"):
            return 0
        if (isinstance(c, int)):
            r = c
        else:
            c = utils.safe_str_convert(c)
            if (len(c) > 0):
                r = ord(utils.safe_str_convert(c)[0])
            else:
                r = 0
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("AscW: return %r" % r)
        return r

class AscB(AscW):
    pass

class International(VbaLibraryFunc):
    """Emulate application.international() Function.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint
        
        # Match anything compared to this result.
        return "**MATCH ANY**"

class GetLocale(VbaLibraryFunc):
    """Emulate GetLocale() Function.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        # Match anything compared to this result.
        return "**MATCH ANY**"

class StrComp(VbaLibraryFunc):
    """Emulate StrComp() string function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 2)):
            return "NULL"
        s1 = params[0]
        s2 = params[1]
        method = 0
        if (len(params) >= 3):
            try:
                method = vba_conversion.int_convert(params[2])
            except Exception as e:
                log.error("StrComp: Invalid comparison method. " + utils.safe_str_convert(e))
        if (method == 0):
            s1 = s1.lower()
            s2 = s2.lower()
        if (s1 == s2):
            return 0
        if (s1 < s2):
            return -1
        return 1

class StrPtr(VbaLibraryFunc):
    """Emulate External StrPtr() string function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
            return "NULL"

        # Do we have a variable name?
        arg = utils.safe_str_convert(params[0])
        if (arg.startswith("&")):

            # Just return the name of the variable being pointed to by the string pointer.
            return arg[1:]

        # We don't have a variable, so just turn it into a "pointer".
        return ("&" + utils.safe_str_convert(params[0]))

    def return_type(self):
        return "STRING"
    
class StrConv(VbaLibraryFunc):
    """Emulate StrConv() string function.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) == 0)):
            return "NULL"

        # TODO: Actually implement this properly.

        # Get the conversion type to perform.
        conv = None
        if (len(params) > 1):
            conv = vba_conversion.int_convert(eval_arg(params[1], context=context))

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
                    r = utils.safe_str_convert(r)

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
                    except Exception as e:
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug("StrConv() exception: " + utils.safe_str_convert(e))
                r = tmp

            else:
                log.error("StrConv: Unhandled type.")
                r = ''
                        
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("StrConv: return %r" % r)
        return r

    def return_type(self):
        return "STRING"
    
class Assert(VbaLibraryFunc):
    """Emulate Assert() debug function (stubbed). Does nothing.

    """

    def eval(self, context, params=None):
        pass

class Shapes(VbaLibraryFunc):
    """Emulate Shapes() object reference (stubbed).

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Just return the string representation of the access. This is used in
        # vba_object._read_from_object_text()
        if ((params is None) or (len(params) == 0)):
            return ""
        return "Shapes('" + utils.safe_str_convert(params[0]) + "')"

class InlineShapes(VbaLibraryFunc):
    """Emulate InlineShapes() object reference (stubbed).

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Just return the string representation of the access. This is used in
        # vba_object._read_from_object_text()
        if ((params is None) or (len(params) == 0)):
            return ""
        return "InlineShapes('" + utils.safe_str_convert(params[0]) + "')"

class GetCursorPos(VbaLibraryFunc):
    """Emulate GetCursorPos() function (stubbed). Returns random
    location.

    """

    def eval(self, context, params=None):
        params = params # pylint

        if ((var_names is None) or (len(var_names) == 0)):
            return 1

        # Set the given parameter to a random position.
        var_name = utils.safe_str_convert(var_names[0])
        context.set(var_name + ".*", random.randint(100, 10000), force_global=True)
        
        return 0

class VarPtr(VbaLibraryFunc):
    """Emulate VarPtr() function (stubbed). Just reports an action.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) == 0)):
            return

        # Report on the full byte array given to VarPtr().
        val = params[0]
        context.report_action("External Call", "VarPtr(" + utils.safe_str_convert(val) + ")", "VarPtr", strip_null_bytes=True)

class RtlMoveMemory(VbaLibraryFunc):
    """Emulate External RtlMoveMemory() function.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) == 0)):
            return

        # Report the memory move.
        context.report_action("External Call", "RtlMoveMemory(" + utils.safe_str_convert(params) + ")", "RtlMoveMemory", strip_null_bytes=True)

        # Track the shellcode bytes.
        if (len(params) < 3):
            return
        import vba_context
        vba_context.add_shellcode_data(params[0], params[1], params[2])
        
class GetByteCount_2(VbaLibraryFunc):
    """Emulate string encoder object method GetByteCount_2().

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((len(params) == 0) or (not isinstance(params[0], str))):
            return 0
        return len(params[0])

class GetBytes_4(VbaLibraryFunc):
    """Emulate string encoder object method GetByteCount_4().

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((len(params) == 0) or (not isinstance(params[0], str))):
            return []
        r = []
        for c in params[0]:
            r.append(ord(c))
        return r

class TransformFinalBlock(VbaLibraryFunc):
    """Emulate base64 encoder object method TransformFinalBlock().

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((len(params) != 3) or (not isinstance(params[0], list))):
            return "NULL"

        # Pull out the byte values and start/end of the bytes to decode.
        vals = params[0]
        start = 0
        try:
            start = int(params[1])
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("TransformFinalBlock() exception 1: " + utils.safe_str_convert(e))
        end = len(vals) - 1
        try:
            end = int(params[2])
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("TransformFinalBlock() exception 2: " + utils.safe_str_convert(e))
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
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("TransformFinalBlock(): Try base64 decode of '" + base64_str + "'...")
        r = utils.b64_decode(base64_str)
        if (r is None):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("TransformFinalBlock(): Base64 decode fail.")
            r = "NULL"

        # Return the decoded string.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Decoded string: " + r)
        return r

    def return_type(self):
        return "STRING"
    
class Split(VbaLibraryFunc):
    """Emulate Split() string function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
            return "NULL"

        # TODO: Actually implement this properly.
        string = utils.safe_str_convert(params[0])
        sep = " "
        if ((len(params) > 1) and
            (isinstance(params[1], str)) and
            (len(params[1]) > 0)):
            sep = utils.safe_str_convert(params[1])

        # Let's assume that splitting on char 0x00 means break
        # up into individual characters.
        if (sep == chr(0)):
            r = []
            for c in string:
                r.append(c)
            return r
            
        r = string.split(sep)
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Split: return %r" % r)
        #print "SPLIT!!"
        #print r
        return r
    
class Int(VbaLibraryFunc):
    """Emulate Int() function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
            return "NULL"
        # TODO: Actually implement this properly.
        val = params[0]
        try:
            if (isinstance(val, str) and (val.lower().startswith("&h"))):
                val = "0x" + val[2:]
                r = int(val, 16)
            elif (isinstance(val, str) and
                (val.lower().startswith("i")) and
                (len(val) == 3)):
                val = "0x" + val[1:]
                r = int(val, 16)
            elif (isinstance(val, str) and (("e" in val) or ("E" in val))):
                r = int(decimal.Decimal(val))
            else:
                r = vba_conversion.int_convert(val)
            # -32,768 to 32,767
            if ((r > 32767) or (r < -32768)):
                # Overflow. Assume On Error Resume Next.
                r = "NULL"
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Int: return %r" % r)
            return r
        except Exception as e:
            log.error("Int(): Invalid call int(%r) [%s]. Returning ''." % (val, utils.safe_str_convert(e)))
            return ''

class CInt(Int):
    """Emulate Same as Int() for our purposes.

    """
    pass

class Oct(VbaLibraryFunc):
    """Emulate Oct() function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
            return "NULL"
        val = params[0]
        try:
            r = oct(val)
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Oct: return %r" % r)
            return r
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Oct() exception: " + utils.safe_str_convert(e))
            log.error("Oct(): Invalid call oct(%r). Returning ''." % val)
            return ''

class StrReverse(VbaLibraryFunc):
    """Emulate StrReverse() string function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
            return "NULL"
        # TODO: Actually implement this properly.
        string =''
        if ((params[0] is not None) and (len(params) > 0)):
            string = params[0]
            if ((not isinstance(params[0], str)) and
                (not isinstance(params[0], unicode))):
                string = utils.safe_str_convert(params[0])
        r = string[::-1]
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("StrReverse: return %r" % r)
        return r

    def return_type(self):
        return "STRING"
    
class RegWrite(VbaLibraryFunc):
    """Emulate RegWrite() function. Just track registry write.

    """

    def eval(self, context, params=None):
        context.report_action("Registry Write", utils.safe_str_convert(params), "Registry Write", strip_null_bytes=True)
        return "NULL"

class SetStringValue(VbaLibraryFunc):
    """Emulate SetStringValue() function. Just track registry write.

    """

    def eval(self, context, params=None):
        context.report_action("Registry Write", utils.safe_str_convert(params), "Set String Value", strip_null_bytes=True)
        return "NULL"

class GetRef(VbaLibraryFunc):
    """Emulate GetRef() function.

    """

    def eval(self, context, params=None):

        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            return "NULL"

        # Get the function.
        obj_name = utils.safe_str_convert(params[0])
        if (not context.contains(obj_name)):
            return "NULL"
        return context.get(obj_name)
            
class Filter(VbaLibraryFunc):
    """Emulate Filter function. The VBA Filter function returns a subset
    of a supplied string array, based on supplied criteria.

    The syntax of the function is: Filter( SourceArray, Match, [Include], [Compare] )

    The function arguments are:

    SourceArray  -  The original array of Strings, that you want to filter.
    Match  -  The string that you want to search for, within each element of the supplied SourceArray.
    [Include]  -  
    An option boolean argument that specifies whether the returns
    array should consist of elements that include or do not include
    the supplied Match String.

    This can have the value True or False, meaning:

    True  -  Only return elements that include the Match String
    False  -  Only return elements that do not include the Match String
    If the [Include] argument is omitted, it takes on the default value True.

    [Compare]  -  
    An optional argument, specifying the type of String comparison to make.

    This can be any of the following values:

    vbBinaryCompare  -  performs a binary comparison (0)
    vbTextCompare  -  performs a text comparison (1)
    vbDatabaseCompare  -  performs a database comparison (2)
    If omitted, the [Compare] argument takes on the default value vbBinaryCompare.

    """
    
    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) < 2)):
            log.warning("Too few arguments to Filter() call. Returning NULL")
            return "NULL"

        # SourceArray and Match are required.
        source_array = params[0]
        match = params[1]
        if (not isinstance(source_array, list)):
            log.warning("SourceArray argument to Filter() call not an array. Returning NULL")
            return "NULL"
        if (not isinstance(match, str)):
            log.warning("Match argument to Filter() call not a string. Returning NULL")
            return "NULL"

        # Include/exclude argument is optional.
        include = True
        if (len(params) >=3):
            include = params[2]
            if (not isinstance(match, str)):
                log.warning("Include/exclude argument to Filter() call not a boolean. Returning NULL")
                return "NULL"

        # Compare argument is optional.
        compare = 0
        if (len(params) >=4):
            compare = params[3]
            if (not isinstance(compare, int)):
                log.warning("Compare argument to Filter() call not an int. Returning NULL")
                return "NULL"

        # Currently only handling vbBinaryCompare.
        if (compare != 0):
            log.warning("Only handling Compare == vbBinaryCompare in Filter() call. Returning NULL")
            return "NULL"

        # Find the items to return.
        r = []
        for s in source_array:
            found_match = (match in s)
            if (not include):
                found_match = not found_match
            if found_match:
                r.append(s)

        # Done.
        return r
            
class Replace(VbaLibraryFunc):
    """Emulate Replace() string function.

    The Replace function syntax has these named arguments:

    * expression - Required. String expression containing substring to
      replace.
    * find - Required. Substring being searched for.
    * replace - Required. Replacement substring.
    * start - Optional. Start position for the substring of expression
      to be searched and returned. If omitted, 1 is assumed.
    * count - Optional. Number of substring substitutions to
      perform. If omitted, the default value is -1, which means, make
      all possible substitutions.
    * compare - Optional. Numeric value indicating the kind of
      comparison to use when evaluating substrings. See Settings
      section for values.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if (params is None):
            return ""
        if (len(params) < 3):
            if (len(params) > 0):
                return params[0]
            return ""
        # TODO: Handle start, count, and compare parameters.
        string = params[0]
        # Handle Excel cells.
        if (isinstance(string, dict) and ("value" in string)):
            string = utils.safe_str_convert(string["value"])
        if (string is None):
            string = ''
        string = utils.safe_str_convert(string)
        pat = utils.safe_str_convert(params[1])
        if ((pat is None) or (pat == '')):
            return string
        rep = utils.safe_str_convert(params[2])
        if ((rep is None) or (rep == 0) or (rep == "NULL")):
            rep = ''

        # Wide string to change and not wide char pattern/replacement?
        if (vb_str.is_wide_str(string) and
            ((not vb_str.is_wide_str(pat)) or (not vb_str.is_wide_str(rep)))):

            # Convert the string to change to ASCII.
            log.warning("Replace() called on wide string w. ASCII pattern and replacement. Converting to ASCII ...")
            string = vb_str.convert_wide_to_ascii(string)

        # regex replacement?
        if (params[-1] == "<-- USE REGEX -->"):
            
            # Don't do a regex replacement of everything.
            if (pat.strip() != "."):
                try:
                    pat1 = pat.replace("$", "\\$").replace("-", "\\-")
                    fix_dash_pat = r"(\[.\w+)\\\-(\w+\])"
                    pat1 = re.sub(fix_dash_pat, r"\1-\2", pat1)
                    fix_dash_pat1 = r"\((\w+)\\\-(\w+)\)"
                    pat1 = re.sub(fix_dash_pat1, r"[\1-\2]", pat1)
                    rep = re.sub(r"\$(\d)", r"\\\1", rep)
                    r = re.sub(pat1, rep, string)
                except Exception as e:
                    log.error("Regex replace " + utils.safe_str_convert(params) + " failed. " + utils.safe_str_convert(e))
                    r = string

        # Regular string replacement?
        else:
            r = string.replace(pat, rep)

        # Done.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Replace: return %r" % r)
        return r

    def return_type(self):
        return "STRING"
    
class RunShell(VbaLibraryFunc):
    """Emulate WScript.Shell Run() method (stubbed).

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) == 0)):
            return
        context.report_action('Execute Command', utils.safe_str_convert(params[0]), 'WScript.Shell.Run()', strip_null_bytes=True)
    
class SaveToFile(VbaLibraryFunc):
    """Emulate SaveToFile() ADODB.Stream method.

    """

    def eval(self, context, params=None):

        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            return ""

        # Save that we are saving a file.
        fname = utils.safe_str_convert(params[0])
        context.report_action('Write File', fname, 'SaveToFile', strip_null_bytes=True)
        
        # Just return the file name. This is used in
        # expressions.MemberAccessExpression._handle_savetofile().        
        context.last_saved_file = fname
        return fname

    def return_type(self):
        return "STRING"    

class Paragraphs(VbaLibraryFunc):
    """Emulate Paragraphs() function. Get a specific paragraph.

    """

    def eval(self, context, params=None):

        # Get the paragraphs.
        paragraphs = None
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Handling Paragraphs(" + utils.safe_str_convert(params) + ") ...")
        try:
            paragraphs = context.get("ActiveDocument.Paragraphs".lower())
        except KeyError:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("No paragraphs loaded.")
            return "NULL"
        
        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            log.error("Paragraphs() called with no arguments. Returning all paragraphs.")
            return paragraphs

        # Get the paragraph index.
        index = None
        try:
            # Looks like this is 1 based indexing in VBA??
            index = vba_conversion.coerce_to_int(params[0]) - 1
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Paragraphs() exception: " + utils.safe_str_convert(e))
            log.error("%r is not a valid index value. Returning NULL." % params[0])
            return "NULL"

        # Do we have a paragraph at this index?
        if (index >= len(paragraphs)):
            log.error("Paragraphs(" + utils.safe_str_convert(index) + ") out of range. Returning NULL.")
            return "NULL"

        # Return the paragraph.
        r = paragraphs[index]
        return r
    
class SaveAs(VbaLibraryFunc):
    """Emulate ActiveDocument.SaveAs() method.

    """

    def eval(self, context, params=None):

        # Sanity check.
        if ((params is None) or (len(params) < 2)):
            return 0

        # Pull out the name of the file to save to and the format
        # for saving.
        new_fname = utils.safe_str_convert(params[0])
        fmt = params[1]
        for param in params:
            if (isinstance(param, expressions.NamedArgument)):
                if (param.name == "FileName"):
                    new_fname = param.value
                if (param.name == "FileFormat"):
                    fmt = param.value
                    
        # Save the current doc to a file.

        # Handle saving as text.
        # wdFormatText = 2
        if (fmt != 2):
            return 0

        # Get the doc text.
        doc_text = None
        try:
            paragraphs = context.get("ActiveDocument.Paragraphs".lower())
            doc_text = ""
            for p in paragraphs:
                doc_text += p + "\n"
        except KeyError:
            return 0

        # Open the saveas file.
        opener = CreateTextFile()
        opener.eval(context, [new_fname])

        # Write the data.
        writer = WriteLine()
        writer.eval(context, [doc_text])

        # Close the file.
        closer = Close()
        closer.eval(context, [])

        # Done.
        return 1

class SaveAs2(SaveAs):
    pass
    
class LoadXML(VbaLibraryFunc):
    """Emulate LoadXML() MSXML2.DOMDocument.3.0 method.

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            return ""

        # Get the XML.
        xml = utils.safe_str_convert(params[0]).strip()

        # Is this some base64?
        if (xml.startswith("<B64DECODE")):

            # Yes it is. Pull it out.
            start = xml.index(">") + 1
            end = xml.rindex("<")
            xml = xml[start:end].strip()

            # It looks like maybe this magically does base64 decode? Try that.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("LoadXML(): Try base64 decode of '" + xml + "'...")
            decoded = utils.b64_decode(xml)
            if (decoded is not None):
                xml = decoded.replace(chr(0), "")
            else:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("LoadXML(): Base64 decode fail.")

        # Return the XML or base64 string.
        return xml

class RegRead(VbaLibraryFunc):
    """Emulate RegRead() function (stubbed). Some registry key values
    are faked, most are not ("" is returned).

    """

    def eval(self, context, params=None):

        # Sanity check.
        if ((params is None) or (len(params) < 1)):
            return ""

        # Fake some registry reads.
        key = utils.safe_str_convert(params[0])
        context.report_action('Read Registry', key, 'RegRead', strip_null_bytes=True)
        if (key == 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\\PROCESSOR_ARCHITECTURE'):
            return "x86"

        # Not faked.
        return ""
    
class Join(VbaLibraryFunc):
    """Emulate Join() string function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
            return "NULL"
        strings = params[0]
        sep = " "
        if (len(params) > 1):
            sep = utils.safe_str_convert(params[1])
        if (sep == "NULL"):
            sep = ""
        r = ""
        if (isinstance(strings, list)):
            first = True
            for s in strings:
                if (not first):
                    r += sep
                first = False
                tmp_s = utils.safe_str_convert(s)
                r += tmp_s
        else:
            r = utils.safe_str_convert(strings)
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Join: return %r" % r)
        return r

    def return_type(self):
        return "STRING"
    
class InStr(VbaLibraryFunc):
    """Emulate InStr() string function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 2)):
            return "NULL"

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

        # Always say we found the substring if the string in which we
        # are searching is the special wildcard string.
        if (s1 == "**MATCH ANY**"):
            return 1
        
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
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("InStr: %r returns %r" % (self, r))
        return r

class CVar(VbaLibraryFunc):
    """Emulate CVar() type conversion function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"

        # We are not tracking variant types, so work as a pass-through.
        return params[0]

class IsNumeric(VbaLibraryFunc):
    """Emulate IsNumeric() function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"

        arg = utils.safe_str_convert(params[0])
        try:
            _ = float(arg)
            return True
        except ValueError:
            return False
    
class InStrRev(VbaLibraryFunc):
    """Emulate InStrRev() string function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 2)):
            return "NULL"

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
        s1 = utils.safe_str_convert(s1)
        s2 = utils.safe_str_convert(s2)
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
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("InStr: %r returns %r" % (self, r))
        return r

    
class Sgn(VbaLibraryFunc):
    """Emulate Sgn() math function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        num = params[0]
        r = "NULL"
        try:
            n = vba_conversion.int_convert(num)
            if n == 0:
                r = 0
            else:
                r = int(math.copysign(1, n))
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Sgn exception: " + utils.safe_str_convert(e))
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Sgn: %r returns %r" % (self, r))
        return r
        
class Sqr(VbaLibraryFunc):
    """Emulate Sqr() math function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        r = ''
        try:
            num = vba_conversion.int_convert(params[0]) + 0.0
            r = math.sqrt(num)
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Sqr exception: " + utils.safe_str_convert(e))
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Sqr: %r returns %r" % (self, r))
        return r

class Abs(VbaLibraryFunc):
    """Emulate Abs() math function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        r = ''
        try:
            num = vba_conversion.int_convert(params[0])
            r = abs(num)
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Abs exception: " + utils.safe_str_convert(e))
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Abs: %r returns %r" % (self, r))
        return r

class Fix(VbaLibraryFunc):
    """Emulate Fix() math function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        r = ''
        try:
            num = float(params[0])
            r = math.floor(num)
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Fix exception: " + utils.safe_str_convert(e))
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Fix: %r returns %r" % (self, r))
        return r

class Round(VbaLibraryFunc):
    """Emulate Round() math function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        r = ''
        try:
            num = float(params[0])
            sig = 0
            if (len(params) == 2):
                sig = vba_conversion.int_convert(params(1))                
            r = round(num, sig)
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Round exception: " + utils.safe_str_convert(e))
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Round: %r returns %r" % (self, r))
        return r

class Hour(VbaLibraryFunc):
    """Emulate Hour() time function (stubbed).

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        return 13
    
class Hex(VbaLibraryFunc):
    """Emulate Hex() math function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        r = ''
        try:
            num = vba_conversion.int_convert(params[0])
            # Number treated as an unsigned int by VBA.
            if (num < 0):
                num += (1 << 32)
            r = hex(num).replace("0x","").upper()
            # VBA chops FFs from the start of the string down to 1 FF.
            if (r.startswith("FF")):
                r = "FF" + r[r.rindex("FF") + len("FF"):]
                if ((len(r) % 2) != 0):
                    r = "F" + r
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Hex exception: " + utils.safe_str_convert(e))
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Hex: %r returns %r" % (self, r))
        return r

class CByte(VbaLibraryFunc):
    """Emulate CByte() math function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        r = ''
        try:
            tmp = utils.safe_str_convert(params[0]).upper()
            if (tmp.lower().startswith("&h")):
                tmp = tmp.lower().replace("&h", "0x")
                tmp = int(tmp, 16)
            num = int(round(float(tmp)))
            r = num
            if (r > 255):
                r = 255
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("CByte exception: " + utils.safe_str_convert(e))
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("CByte: %r returns %r" % (self, r))
        return r

class CLng(VbaLibraryFunc):
    """
    CLng() math function.
    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"

        # Handle abstracted pointers to memory.
        val = params[0]
        if (isinstance(val, str) and
            (not val.lower().startswith("&h")) and
            (val.startswith("&"))):
            return val

        # Actually try to convert to a number.
        r = ''
        try:
            tmp = val
            if (isinstance(tmp, str)):
                tmp = val.upper()
                if (tmp.lower().startswith("&h")):
                    tmp = tmp.lower().replace("&h", "0x")
                    tmp = int(tmp, 16)
                elif (len(tmp) == 1):
                    tmp = ord(tmp)
            r = round(vba_conversion.coerce_to_num(tmp))
            if ((r > 2147483647) or (r < -2147483647)):
                # Overflow. Assume On Error Resume Next.
                r = "NULL"
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("CLng exception: " + utils.safe_str_convert(e))
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("CLng: %r returns %r" % (self, r))
        return r
    
class CBool(VbaLibraryFunc):
    """Emulate CBool() type conversion function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        val = params[0]
        r = 0
        # We actually want to explicitly check for True.
        # pylint: disable=singleton-comparison
        if ((val is True) or (val == 1)):
            r = 1
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("CBool: %r returns %r" % (self, r))
        return r

class CDate(VbaLibraryFunc):
    """Emulate CDate() type conversion function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        # TODO: For now this is stubbed out. Handling dates correctly is hard.
        r = 12345
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("CDate: %r returns %r" % (self, r))
        return r

class CStr(VbaLibraryFunc):
    """Emulate CStr() type conversion function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        val = params[0]
        r = utils.safe_str_convert(val)
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("CStr: %r returns %r" % (self, r))
        return r

    def return_type(self):
        return "STRING"
    
class CSng(VbaLibraryFunc):
    """Emulate CSng() type conversion function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        r = ''
        try:
            tmp = params[0].upper()
            if (tmp.lower().startswith("&h")):
                tmp = tmp.lower().replace("&h", "0x")
                tmp = int(tmp, 16)
            r = float(tmp)
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("CSng exception: " + utils.safe_str_convert(e))
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("CSng: CSng(%r) returns %r" % (params[0], r))
        return r
    
class Atn(VbaLibraryFunc):
    """Emulate Atn() math function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        r = ''
        try:
            num = float(params[0])
            r = math.atan(num)
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Atn exception: " + utils.safe_str_convert(e))
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Atn: %r returns %r" % (self, r))
        return r

class Tan(VbaLibraryFunc):
    """Emulate Tan() math function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        r = ''
        try:
            num = float(params[0])
            r = math.tan(num)
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Tan exception: " + utils.safe_str_convert(e))
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Tan: %r returns %r" % (self, r))
        return r
        
class Cos(VbaLibraryFunc):
    """Emulate Cos() math function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        r = ''
        try:
            num = float(params[0])
            r = math.cos(num)
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Cos exception: " + utils.safe_str_convert(e))
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Cos: %r returns %r" % (self, r))
        return r
        
class Log(VbaLibraryFunc):
    """Emulate Log() math function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        r = 0.0
        try:
            num = float(params[0])
            r = math.log(num)
        except ValueError as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.error("Log(" + utils.safe_str_convert(params[0]) + ") failed. " + utils.safe_str_convert(e))
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Log: %r returns %r" % (self, r))
        return r
    
class String(VbaLibraryFunc):
    """Emulate String() repeated character string creation function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 2)):
            return "NULL"
        r = ''
        try:
            num = vba_conversion.int_convert(params[0])
            char = params[1]
            r = char * num
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("String exception: " + utils.safe_str_convert(e))
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("String: %r returns %r" % (self, r))
        return r

class Dir(VbaLibraryFunc):
    """Emulate Dir() file/directory finding function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            return ""

        # Try not matching everything in the special case where the attribute
        # arg is vbDirectory.
        if ((len(params) >= 2) and (params[1] == 16)):
            return params[0]
        
        # Lets have this match any logic and see what the VB does.
        return "**MATCH ANY**"

    def return_type(self):
        return "STRING"

class SubFolders(VbaLibraryFunc):
    """Fake Subfolders field in directory object.

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) < 1)):
            return []

        # Terminate recursion when exploring a file system.
        dir = params[0]
        if (dir == "**MATCH ANY**"):
            return []
        
        # Lets have this match any logic and see what the VB does.
        return ["**MATCH ANY**"]

class Files(VbaLibraryFunc):
    """Fake Files field in directory object.

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) < 1)):
            return []

        # Terminate recursion when exploring a file system.
        dir = params[0]
        if (dir == "**MATCH ANY**"):
            return []
        
        # Lets have this match any logic and see what the VB does.
        return ["SOME_FILE_NAME"]

class Name(VbaLibraryFunc):
    """Fake Name field in File object.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        # Lets have this match any logic and see what the VB does.
        return "SOME_FILE_NAME"
    
class Choose(VbaLibraryFunc):
    """Emulate Choose() choice function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) < 2)):
            return "NULL"

        # The index of the value to pick should be the 1st
        # argument.
        index = None
        try:
            index = int(params[0])
        except Exception as e:
            log.warning("Invalid index passed to Choice(). Returning NULL. " + utils.safe_str_convert(e))
            return "NULL"

        # Is the desired value in the choice list?
        if (index > (len(params) + 1)):
            log.warning("Invalid index passed to Choice(). Too large.")
            return "NULL"

        # Return the choice value.
        return params[index]
            
class RGB(VbaLibraryFunc):
    """Emulate RGB() color function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 3)):
            return "NULL"
        r = ''
        try:
            red = vba_conversion.int_convert(params[0])
            green = vba_conversion.int_convert(params[1])
            blue = vba_conversion.int_convert(params[2])
            r = red + (green * 256) + (blue * 65536)
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("RGB exception: " + utils.safe_str_convert(e))
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("RGB: %r returns %r" % (self, r))
        return r

class Exp(VbaLibraryFunc):
    """Emulate Exp() math function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        r = params[0]
        try:
            num = float(params[0])
            r = math.exp(num)
        except Exception as e:
            log.error("Exp(" + utils.safe_str_convert(params[0]) + ") failed. " + utils.safe_str_convert(e))
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Exp: %r returns %r" % (self, r))
        return r
            
class Sin(VbaLibraryFunc):
    """Emulate Sin() math function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        r = ''
        try:
            num = float(params[0])
            r = math.sin(num)
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Sin exception: " + utils.safe_str_convert(e))
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Sin: %r returns %r" % (self, r))
        return r
            
class Str(VbaLibraryFunc):
    """Emulate Str() convert number to string function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
            return ""
        r = utils.safe_str_convert(params[0])
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Str: %r returns %r" % (self, r))
        return r

class Val(VbaLibraryFunc):
    """Emulate Val() convert string to number function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        
        # Sanity check.
        if ((params[0] is None) or (not isinstance(params[0], str))):
            r = ''
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Str: %r returns %r" % (self, r))
            return r
        
        # Ignore whitespace.
        tmp = vba_conversion.str_convert(params[0]).strip().replace(" ", "")

        # No nulls.
        tmp = tmp.replace("\x00", "")
        
        # The VB Val() function is ugly. Look for VB hex encoding.
        nums = re.compile(r"&[Hh][0-9A-Fa-f]+")
        matches = nums.search(tmp)
        if (hasattr(matches, "group")):
            tmp = nums.search(tmp).group(0).replace("&H", "0x").replace("&h", "0x")
            r = float(int(tmp, 16))
            if (log.getEffectiveLevel() == logging.DEBUG):
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
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Val: %r returns %r" % (self, r))
            return r

        # Can't find a valid number to convert. This is probably incorrect behavior.
        r = 0
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Val: Invalid Value: %r returns %r" % (self, r))
        return r
    
class Base64Decode(VbaLibraryFunc):
    """Emulate Base64Decode() function used by some malware (Note that
    this is not part of Visual Basic).

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        txt = params[0]
        if (txt is None):
            txt = ''
        r = utils.b64_decode(txt)
        if (r is None):
            r = "NULL"
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Base64Decode: %r returns %r" % (self, r))
        return r

class Base64DecodeString(Base64Decode):
    pass
    
class CleanString(VbaLibraryFunc):
    """Emulate CleanString() function that removes certain characters from the
    character stream, or translates them. See
    https://docs.microsoft.com/en-us/office/vba/api/word.application.cleanstring

    """

    def eval(self,context,params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        txt=params[0]
        if (txt is None):
            txt = ''
        if isinstance(txt,str):
            a = [c for c in txt]
            # Looking at elements pos and pos-1, so leave this as for over range().
            # pylint: disable=consider-using-enumerate
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
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("CleanString: %r returns %r" % (self,r))
        return r

    def return_type(self):
        return "STRING"
    
class Pmt(VbaLibraryFunc):
    """Emulate Pmt() payment computation function.

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
        context = context # pylint

        if ((params is None) or (len(params) < 3)):
            return "NULL"

        r = ''
        try:
            # Pull out the arguments.
            rate = float(params[0])
            nper = vba_conversion.int_convert(params[1]) + 0.0
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
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Pmt exception: " + utils.safe_str_convert(e))
        
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Pmt: %r returns %r" % (self, r))
        return r

class Day(VbaLibraryFunc):
    """Emulate Day() function (stubbed).

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        # This is usually used for gating, so have it match anything.
        return "**MATCH ANY**"

    # Keep this for easy recovery if we want to revisit it.
    # pylint: disable=pointless-string-statement
    """
        if ((params is None) or (len(params) < 1)):
            return "NULL"
        txt = params[0]
        if ((txt is None) or (txt == "NULL")):
            txt = ''
        r = utils.safe_str_convert(txt)

        # It looks like this should pull the day out of a date string. See if we can
        # handle a simple date string.
        f = r.split("/")
        if (len(f) == 3):
            try:
                r = int(f[1])
            except:
                pass

        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Day: %r returns %r" % (self, r))
        return r
    """

class Space(VbaLibraryFunc):
    """Emulate Space() string function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        n = vba_conversion.int_convert(params[0])
        r = " " * n
        return r

    def return_type(self):
        return "STRING"
    
class UCase(VbaLibraryFunc):
    """Emulate UCase() string function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        r = utils.safe_str_convert(params[0]).upper()
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("UCase: %r returns %r" % (self, r))
        return r

    def return_type(self):
        return "STRING"
    
class LCase(VbaLibraryFunc):
    """Emulate LCase() string function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        r = utils.safe_str_convert(params[0]).lower()
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("LCase: %r returns %r" % (self, r))
        return r

    def return_type(self):
        return "STRING"
    
class Randomize(VbaLibraryFunc):
    """Emulate Randomize() RNG function.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Randomize(): Stubbed out as NOP")
        return ''

class Rnd(VbaLibraryFunc):
    """Emulate Rnd() RNG function.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        return random.random()

    def num_args(self):
        return 0

class OnTime(VbaLibraryFunc):
    """Emulate Application.OnTime() (stubbed). Just immediately calls the
    callback function.

    """

    def eval(self, context, params=None):

        # Sanity check.
        if ((params is None) or (len(params) < 2)):
            return "NULL"

        # The name of the callback function should be the 2nd argument.
        callback_name = utils.safe_str_convert(params[1])

        # Is this function defined?
        callback = None
        try:
            callback = context.get(callback_name)
        except KeyError:
            log.warning("OnTime() callback function '" + callback_name + "' not found.")
            return "NULL"
        import procedures
        if (not isinstance(callback, procedures.Function) and
            not isinstance(callback, procedures.Sub)):
            log.warning("OnTime() callback function '" + callback_name + "' found, but not a function.")
            return "NULL"

        # Emulate the callback function.
        log.info("Running OnTime() callback function '" + callback_name + "'.")
        return eval_arg(callback, context=context)
    
class Environ(VbaLibraryFunc):
    """Emulate Environ() function for getting environment variable
    values. Has faked values for many environment variables.

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
        env_vars["PSModulePath".lower()] = 'C:\\Program Files\\WindowsPowerShell\\Modules;' + \
                                           'C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\Modules;' + \
                                           'C:\\Program Files\\Microsoft Message Analyzer\\PowerShell\\'
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

        # Get the environment variable name.
        var_name = utils.safe_str_convert(params[0]).strip('%')

        # Is this an environment variable we know?
        if context.expand_env_vars and var_name.lower() in env_vars:
            r = env_vars[var_name.lower()]
        else:
            r = "%{}%".format(var_name.upper())

        # Done.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Environ: %r returns %r" % (self, r))
        return r

    def return_type(self):
        return "STRING"
    
class ExpandEnvironmentStrings(Environ):
    pass
    
class DriveExists(VbaLibraryFunc):
    """Emulate DriveExists() function for checking to see if a drive
    exists.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        drive = utils.safe_str_convert(params[0]).lower()
        r = False
        # Assume the C: drive is always there.
        if ((drive == 'c') or (drive == 'c:')):
            r = True
        return r

class Navigate(VbaLibraryFunc):
    """Emulate Navigate() function for loading a URL in a web browser.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) < 1)):
            return
        url = utils.safe_str_convert(params[0])
        if (url.startswith("tp://")):
            url = "ht" + url
        context.report_action("GET", url, 'Load in browser', strip_null_bytes=True)

class IsNull(VbaLibraryFunc):
    """Emulate IsNull() function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) == 0)):
            return False
        arg = params[0]
        return ((arg is None) or (arg == "NULL") or (arg == 0) or (arg == ""))

class IIf(VbaLibraryFunc):
    """Emulate IIf() if-like function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 3)):
            return "NULL"
        guard = params[0]
        true_part = params[1]
        false_part = params[2]
        if (guard):
            return true_part
        return false_part

class CVErr(VbaLibraryFunc):
    """Emulate CVErr() Excel error string function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        err = None
        try:
            err = int(params[0])
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("err num str to int exception: " + utils.safe_str_convert(e))
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
    """Emulate CallByName() function.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) < 3)):
            return "NULL"

        # Report interesting external commands run.
        cmd = utils.safe_str_convert(params[1])
        obj = utils.safe_str_convert(params[0])
        args = ''
        if (len(params) >= 4):
            args = params[3]
        if (("run" in cmd.lower()) or ("create" in cmd.lower()) or ("wscript.shell" in obj.lower())):
            context.report_action("Run", args, 'Interesting Function Call', strip_null_bytes=True)
        # Accessing elements at pos and pos+1, so leave this as a for over the range().
        # pylint: disable=consider-using-enumerate
        for pos in range(0, len(params)):
            if ((utils.safe_str_convert(params[pos]).lower() == "wscript") and ((pos + 1) < len(params))):
                context.report_action("Run", params[pos + 1], 'Interesting Function Call', strip_null_bytes=True)
        # CallByName("['WinHttp.WinHttpRequest.5.1', 'Open', 1, 'GET', 'http://deciodc.org/bin/office1...")
        if ((("Open" in cmd) and ("WinHttpRequest" in obj)) or
            ((len(params) > 5) and (utils.safe_str_convert(params[3]).lower() == "get"))):
            url = utils.safe_str_convert(params[4])
            if (url.startswith("tp://")):
                url = "ht" + url
            context.report_action("GET", url, 'Interesting Function Call', strip_null_bytes=True)
        # CallByName(([DoBas, 'Arguments', VbLet, aas], {}))
        if ((cmd == "Arguments") or (cmd == "Path")):
            context.report_action("CallByName", args, 'Possible Scheduled Task Setup', strip_null_bytes=True)
        # CallByName(['shell.application', 'shellexecute', 1, ...
        if (cmd.lower() == "shellexecute"):
            if (len(params) > 4):
                run_cmd = utils.safe_str_convert(params[3]) + " " + utils.safe_str_convert(params[4])
                context.report_action('Execute Command', run_cmd, 'Shell function', strip_null_bytes=True)
            
        # Are we using this to read text from a GUI element?
        if ((cmd == "Tag") or (cmd == "Text")):

            # Looks like it. Lets return the text. This is read from a for variable.
            try:
                return context.get(utils.safe_str_convert(params[0]) + "." + cmd)
            except KeyError:
                pass

        # Opening a file?
        if (cmd.lower() == "createtextfile"):

            # Open the file.
            opener = CreateTextFile()
            opener.eval(context, [args])

        # Writing to a file?
        if (cmd.lower() == "writeline"):

            # Write to the file.
            writer = WriteLine()
            writer.eval(context, [args])

        # Closing a file?
        if (cmd.lower() == "close"):

            # Close the file.
            closer = Close()
            closer.eval(context, [args])
            
        # Do nothing.
        return None

class Raise(VbaLibraryFunc):
    """Emulate Raise() exception/error function.

    """

    def eval(self, context, params=None):
        msg = "Raise exception " + utils.safe_str_convert(params)
        context.set_error(msg)
            
class Close(VbaLibraryFunc):
    """Emulate File Close statement.

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
                file_id = utils.safe_str_convert(params[0])

        # Close() object method call?
        else:

            # TODO: Currently the object on which Close() is being called is not
            # being tracked. We will only handle the Close() if there is only 1
            # current open file.
            if not context.open_files:
                log.warning("Cannot process Close(). No open files.")
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
    """Emulate File Put statement.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) < 2)):
            return
        
        # Get the ID of the file.
        file_id = params[0]

        # TODO: Handle writing at a given file position.

        # Get the data.
        data = params[1]
        if (len(params) == 3):
            data = params[2]

        # Has the file been opened?
        if (not context.file_is_open(file_id)):
            context.open_file(file_id)

        context.write_file(file_id, data)

class WriteByte(VbaLibraryFunc):
    """Emulate MemoryStream WriteByte() method.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) < 1)):
            return
        context.report_action('Write Process Memory', utils.safe_str_convert(params), 'MemoryStream.WriteByte', strip_null_bytes=True)
        
class WriteLine(VbaLibraryFunc):
    """Emulate File WriteLine() method.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) < 1)):
            return

        # Get the data.
        data = params[0]
        if (len(params) == 3):
            data = params[2]
        
        # Save writes that look like they are writing URLs.
        data_str = utils.safe_str_convert(data)
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
            log.warning("Writing to '" + utils.safe_str_convert(file_id) + "' .")
        else:        

            # Get the ID of the file.
            file_id = context.open_files.keys()[0]
        
        # TODO: Handle writing at a given file position.

        context.write_file(file_id, data)
        context.write_file(file_id, b'\n')

class WriteText(VbaLibraryFunc):
    """Emulate File WriteText() method.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) < 1)):
            return

        # Get the data.
        txt = params[0]
        if (len(params) == 3):
            txt = params[2]
        
        # Set the text value of the string as a faux variable. Make this
        # global as a hacky solution to handle fields in user defined objects.
        #
        # We are appending the written data to whatever is already there.

        # Assume we are writing to ADODB.Stream.ReadText
        var_name = "ADODB.Stream.ReadText"
        if (not context.contains(var_name)):
            context.set(var_name, "", force_global=True)
        final_txt = context.get(var_name) + txt
        context.set(var_name, final_txt, force_global=True)
        
class CurDir(VbaLibraryFunc):
    """Emulate CurDir() function (stubbed).

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        return "~"

    def return_type(self):
        return "STRING"
    
class Unprotect(VbaLibraryFunc):
    """Emulate Unprotect() function (stubbed).

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) == 0)):
            return
        passwd = utils.safe_str_convert(params[0])
        context.report_action('Unprotect()', passwd, 'Try Sheet Unprotect Password', strip_null_bytes=True)

class KeyString(VbaLibraryFunc):
    """Emulate KeyString() function.

    """

    def eval(self, context, params=None):
        context = context # pylint

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
            log.error("KeyString: Invalid args " + utils.safe_str_convert(params) + ". " + utils.safe_str_convert(e))
            return ""

        r = ""
        if (v1 in key_vals):
            r += key_vals[v1]
        if (v2 is not None):
            r += ","
            if (v2 in key_vals):
                r += key_vals[v2]

        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("KeyString: args = " + utils.safe_str_convert(params) + ", return " + r)
        return r

    def return_type(self):
        return "STRING"
    
class Run(VbaLibraryFunc):
    """Emulate Application.Run() function.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) == 0)):
            return 0

        # Get the name of the function to call.
        func_name = utils.safe_str_convert(params[0])
        
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
            log.warning("Application.Run() failed. Cannot find function " + utils.safe_str_convert(func_name) + ".")
            return 0

class Arguments(VbaLibraryFunc):
    """Emulate WScriptShell Arguments() method (stubbed).

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            return "NULL"
        return "_COMMAND_LINE_ARG_" + utils.safe_str_convert(params[0])
            
class Exec(VbaLibraryFunc):
    """Emulate Application.Exec() function.

    """

    def eval(self, context, params=None):

        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            return 1

        # Get the command to run.
        cmd = utils.safe_str_convert(params[0])
        context.report_action("Execute Command", cmd, 'Shell function', strip_null_bytes=True)

        # Say it was successful.
        return 0

class ExecQuery(VbaLibraryFunc):
    """Emulate Application.ExecQuery() function.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) < 1)):
            return "NULL"

        # Get the query to run.
        cmd = utils.safe_str_convert(params[0])
        context.report_action("Execute Query", cmd, 'Query', strip_null_bytes=True)

        # Return some data for some queries.
        if (cmd.lower() == "select * from win32_process"):
            return [{"name" : "wscript.exe"},
                    {"name" : "cscript.exe"},
                    {"name" : "word.exe"},
                    {"name" : "excel.exe"},]
        
        # Say it was successful.
        return ["", ""]
        
class WinExec(VbaLibraryFunc):
    """Emulate WinExec() function.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) < 1)):
            return "NULL"

        cmd = params[0]
        context.report_action("Run", cmd, 'Interesting Command Execution', strip_null_bytes=True)
        return ''

class CreateShortcut(VbaLibraryFunc):
    """Emulate CreateShortcut() function.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) == 0)):
            return
        path = params[0]
        context.report_action("Shortcut Creation", path, 'Shortcut Created', strip_null_bytes=True)
    
class CreateObject(VbaLibraryFunc):
    """Emulate CreateObject() function (stubbed).

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) == 0)):
            return ""
        
        # Track contents of data written to 'ADODB.Stream'.
        obj_type = utils.safe_str_convert(params[0]).lower()
        if (obj_type == 'ADODB.Stream'.lower()):
            context.open_file('ADODB.Stream')

        # Handle certain object types.
        if (obj_type == "Scripting.Dictionary".lower()):
            r = {}
            # Track the added items in order as well as by key.
            r["__ADDED_ITEMS__"] = []
            return r
            
        # Just return a string representation of the name of the object
        # being created.
        return utils.safe_str_convert(obj_type)

class GetParentFolderName(VbaLibraryFunc):
    """Emulate GetParentFolderName() method.

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            return "NULL"

        # Pull the parent directory.
        curr_dir = utils.safe_str_convert(params[0])
        if ("\\" in curr_dir):
            r = curr_dir[:curr_dir.rindex("\\")+1]
        else:
            r = "C:\\"
        return r
            
    def num_args(self):
        return 1
        
class ReadText(VbaLibraryFunc):
    """Emulate ReadText() stream method (stubbed).

    """

    def eval(self, context, params=None):
        params = params # pylint

        # Doing base64 conversion with a VBA object?
        with_str = utils.safe_str_convert(context.with_prefix).strip()
        if (with_str.endswith("GetDecodedContentStream")):
            var_name = with_str.replace("GetDecodedContentStream", "GetEncodedContentStream") + ".ReadText"
            if (context.contains(var_name)):
                return context.get(var_name)
            
        # TODO: Currently the stream object on which ReadText() is
        # being called is not being tracked. We will only handle the
        # ReadText() if there is only 1 current open file.
        if not context.open_files:
            log.error("Cannot process ReadText(). No open streams.")
            return "NULL"
        if len(context.open_files) > 1:
            log.error("Cannot process ReadText(). Too many open streams.")
            return "NULL"

        # Simulate the read.

        # Get the ID of the file.
        file_id = context.open_files.keys()[0]

        # TODO: This function takes a parameter that specifies the number of bytes to read!!

        # Get the data to read.
        raw_data = context.open_files[file_id]

        # Return the data.
        return raw_data

    def return_type(self):
        return "STRING"

class CheckSpelling(VbaLibraryFunc):
    """Emulate Application.CheckSpelling() function (stubbed).

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        # TODO: Find and use a Python spell checker to check the spelling
        # of the argument.

        # For now just say everything is correctly spelled.
        return True

class Specialfolders(VbaLibraryFunc):
    """Emulate Excel Specialfolders() function (stubbed).

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        return "%" + utils.safe_str_convert(params[0]) + "%"

class IsArray(VbaLibraryFunc):
    """Emulate IsArray() function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        return isinstance(params[0], list)

class Month(VbaLibraryFunc):
    """Emulate Excel Month() function. Currently stubbed.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
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

        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Month to int exception: " + utils.safe_str_convert(e))

        return 1


ticks = 100000
class GetTickCount(VbaLibraryFunc):
    """Emulate GetTickCount() function. Randomly increments the tick
    count.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        global ticks
        ticks += random.randint(100, 10000)
        return ticks

class Rows(VbaLibraryFunc):
    """This emulates geting the Rows field of an Excel sheet.
    Currently stubbed out to just return a list of dicts with row
    numbers.

    """

    def eval(self, context, params=None):

        # Do we have a loaded Excel file?
        if (context.loaded_excel is None):
            context.increase_general_errors()
            log.warning("Cannot emulate Rows field access. No Excel file loaded.")
            return []

        # Get the sheet name if given.
        sheet_name = "__NO SHEET NAME__"
        if ((params is not None) and (len(params) > 0)):
            sheet_name = utils.safe_str_convert(params[0]).strip()

        # Get the sheet from which to pull rows.
        sheet = None
        if (sheet_name in context.loaded_excel.sheet_names()):
            sheet = context.loaded_excel.sheet_by_name(sheet_name)

        # No sheet name. Just find the sheet with the most rows.
        else:

            # Look through all sheets.
            max_rows = -1
            for sheet_index in range(0, len(context.loaded_excel.sheet_names())):
            
                # Load the current sheet.
                curr_sheet = None
                try:
                    curr_sheet = context.loaded_excel.sheet_by_index(sheet_index)
                except Exception as e:
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Get sheet by index exception: " + utils.safe_str_convert(e))
                    context.increase_general_errors()
                    log.warning("Cannot process Cells() call. No sheets in file.")
                    return "NULL"

                # Does this have the most rows?
                curr_rows = get_num_rows(curr_sheet)
                if (curr_rows > max_rows):
                    max_rows = curr_rows
                    sheet = curr_sheet

        # Return a list of dicts with row info.
        r = []
        num_rows = get_num_rows(sheet)
        for i in range(0, num_rows + 1):
            r.append({ "Row" : i })

        # Return the row info.
        return r

    def num_args(self):
        return 0

def _read_cell(sheet, row, col):
    """
    Read a cell from an Excel sheet.
    
    @param sheet (ExcelSheet object) The sheet from which to read.

    @param row (int) The row index of the cell to read.

    @param col (int) The column index of the cell to read.

    @return (dict) The cell value as a dict of the form { "value" : r,
    "row" : row + 1, "col" : col + 1 } if found, None if not found.
    """
    
    # Read and process the cell.
    try:
        raw_cell = sheet.cell(row, col)
        r = utils.safe_str_convert(raw_cell).replace("text:", "")
        if (r.startswith("u'")):
            r = r[1:]
        if (r.startswith("'") and r.endswith("'") and (len(r) >= 2)):
            r = r[1:-1]
        if (r.startswith('"') and r.endswith('"') and (len(r) >= 2)):
            r = r[1:-1]
        if (r == "empty:u''"):
            r = ""
        if (r.startswith("number:")):
            r = r[len("number:"):]
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Excel Read: Cell(" + utils.safe_str_convert(col) + ", " + utils.safe_str_convert(row) + ") = '" + utils.safe_str_convert(r) + "'")
        r = { "value" : r,
              "row" : row + 1,
              "col" : col + 1 }
        return r

    except Exception as e:
        
        # Failed to read cell.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Failed to read cell exception: " + utils.safe_str_convert(e))
        return None
    
class Cells(VbaLibraryFunc):
    """Emulate Excel Cells() function.  Currently only handles Cells(x,
    y) calls.

    """

    def eval(self, context, params=None):

        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            log.error("Parameters of Cells() call are None or empty.")
            return "NULL"
        
        # Do we have a loaded Excel file?
        if (context.loaded_excel is None):
            context.increase_general_errors()
            log.warning("Cannot process Cells() call. No Excel file loaded.")
            return "NULL"

        # Is this actually the Cells field of a Sheet?
        if ("Sheet" in utils.safe_str_convert(type(params[0]))):

            # Pull out all the cells  in the sheet and return that.
            return excel.pull_cells_sheet(params[0])
        
        # The row and column must always be the 1st 2 arguments.
        if (len(params) < 2):
            context.increase_general_errors()
            log.warning("Cells() called with < 2 arguments. Returning NULL.")
            return "NULL"

        # The sheet will be the 3rd argument, if given.
        sheet = None
        if (len(params) >= 3):
            sheet = params[2]
            if (not hasattr(sheet, "cell")):
                log.warning("3rd Cells() argument is not sheet object. Returning NULL.")
                return "NULL"
                
        # Get the indices of the cell.

        # Column.
        tmp = params[1]
        if (isinstance(tmp, dict) and ("value" in tmp)):
            tmp = tmp["value"]
        col = None
        try:
            col = int(tmp) - 1
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Convert col num str to index exception: " + utils.safe_str_convert(e))
            try:
                col = excel.excel_col_letter_to_index(tmp)
            except Exception as e:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Convert col letter to index exception: " + utils.safe_str_convert(e))
                context.increase_general_errors()
                log.warning("Cannot process Cells() call. Column " + utils.safe_str_convert(params[1]) + " invalid.")
                return "NULL"

        # Row.
        tmp = params[0]
        if (isinstance(tmp, dict) and ("value" in tmp)):
            tmp = tmp["value"]
        row = None
        try:
            row = int(tmp) - 1
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Convert row to int exception: " + utils.safe_str_convert(e))
            context.increase_general_errors()
            log.warning("Cannot process Cells() call. Row " + utils.safe_str_convert(params[0]) + " invalid.")
            return "NULL"

        # If we were not given a sheet use the current active sheet (if we know it).
        if ((sheet is None) and
            hasattr(context.loaded_excel, "active_sheet_name")):
            try:
                sheet_name = context.loaded_excel.active_sheet_name
                sheet = context.loaded_excel.sheet_by_name(sheet_name)
            except ValueError as e:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Can't find active sheet. " + utils.safe_str_convert(e))
                    
        # Now try the sheet with the most cells if we still need to guess the sheet.
        if (sheet is None):
            sheet = get_largest_sheet(context.loaded_excel)

        # Punt if we still have no idea what sheet to work with.
        if (sheet is None):
            return "NULL"

        # Return the cell contents.
        cell_val = _read_cell(sheet, row, col)
        if (cell_val is not None):
            return cell_val
        
        # The largest sheet or given sheet did not work. Try each sheet until we read a cell.
        for sheet_index in range(0, len(context.loaded_excel.sheet_names())):
            
            # Load the current sheet.
            sheet = None
            try:
                sheet = context.loaded_excel.sheet_by_index(sheet_index)
            except Exception as e:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Get sheet by index exception: " + utils.safe_str_convert(e))
                context.increase_general_errors()
                log.warning("Cannot process Cells() call. No sheets in file.")
                return "NULL"

            # Return the cell contents.
            cell_val = _read_cell(sheet, row, col)
            if (cell_val is not None):
                return cell_val
            continue

        # Can't read the cell.
        context.increase_general_errors()
        log.warning("Failed to read Cell(" + utils.safe_str_convert(col) + ", " + utils.safe_str_convert(row) + "). (1)")
        return "NULL"

    def return_type(self):
        return "STRING"
    
class Sheets(VbaLibraryFunc):
    """Emulate Excel Sheets() function.

    """
        
    def eval(self, context, params=None):

        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Get sheet Sheets(" + utils.safe_str_convert(params) + ") ...")
        
        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Sheets() params are bad. Returning None")
            return None

        # Do we have a loaded Excel file?
        if (context.loaded_excel is None):
            context.increase_general_errors()
            log.warning("Cannot process Sheets() call. No Excel file loaded.")
            return "NULL"
        
        # Get the sheet with the given identifier.
        sheet_id = utils.safe_str_convert(params[0])

        # First try treating this as a sheet name.
        try:
            curr_sheet = context.loaded_excel.sheet_by_name(utils.safe_str_convert(sheet_id))
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Returning sheet with name '" + utils.safe_str_convert(sheet_id) + "'")
            return curr_sheet
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Get sheet by name exception: " + utils.safe_str_convert(e))

        # Next see if the sheet ID is an index.
        try:
            sheet_id = int(sheet_id) - 1
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Cannot convert sheet ID '" + utils.safe_str_convert(sheet_id) + "' to int. " + utils.safe_str_convert(e))
            return None
        try:
            curr_sheet = context.loaded_excel.sheet_by_index(sheet_id)
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Returning sheet with index " + utils.safe_str_convert(sheet_id))
            return curr_sheet
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Get sheet with index exception: " + utils.safe_str_convert(e))
            log.warning("Did not find sheet with index " + utils.safe_str_convert(sheet_id))
            return None

class Worksheets(Sheets):
    """Emulate Excel Worksheets() function.

    """
    pass

class Value(VbaLibraryFunc):
    """Emulate Excel cell Value() function (actually field).

    """
        
    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            return "NULL"

        # Get the cell value.
        cell = params[0]
        r = cell
        if (isinstance(cell, dict) and ("value" in cell)):
            r = cell["value"]

        # Convert numeric cell values to numbers.
        try:
            r = vba_conversion.coerce_to_num(r)
        except ValueError:
            pass

        # Done.
        #print("CELL VALUE!!")
        #print("'" + utils.safe_str_convert(r) + "'")
        #print(type(r))
        return r

class UsedRange(VbaLibraryFunc):
    """Emulate Excel UsedRange() function.

    """
        
    def eval(self, context, params=None):

        # Try each sheet and return the cells from the sheet with the most cells
        # if no sheet is given.
        sheet = None
        if ((params is not None) and
            (len(params) >= 1) and
            ("Sheet" in utils.safe_str_convert(type(params[0])))):
            sheet = params[0]
        else:
            sheet = get_largest_sheet(context.loaded_excel)
        if (sheet is None):
            return []

        # Return all of the defined cells. Each cell is represented as a dict
        # with keys 'value', 'row', and 'col'.
        r = pull_cells_sheet(sheet)
        return r

    def num_args(self):
        return 0
    
class Range(VbaLibraryFunc):
    """Emulate Excel Range() function.

    """

    def _get_row_and_column(self, cell_str):
        """Get a numeric row and column from a "i93" style Excel cell
        reference.

        @param cell_str (str) The cell reference in the "ALPHABETIC
        COLUMN INTEGER ROW" format.
        
        @return (tuple) A 2 element tuple (row, col) where row and col
        are integers.
        """

        # Pull out the cell index.
        cell_index = utils.safe_str_convert(cell_str).replace('"', "").replace("'", "")

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
        col = excel.excel_col_letter_to_index(col)

        # Done.
        return (row, col)
        
    def _read_cell_list(self, sheet, cell_str, return_dict):
        """Read multiple cells specified by a "i93:i424" cell string.

        @param sheet (ExcelSheet object) The sheet from which to read.
        
        @param cell_str The cell range string.

        @param return_dict (boolean) If True represent each cell value
        as a { "value" : r, "row" : row + 1, "col" : col + 1 } dict,
        if False just return the original cell values.
        
        @return (list) A list of cell values, where the cell value
        representation is dicttated by the return_dict parameter. 
        """

        # Get the start and end cell.
        fields = cell_str.split(":")
        if (len(fields) != 2):
            log.warning("Improper cell range " + cell_str + " specified. Range() is returning NULL.")
            return "NULL"
        start = fields[0]
        end = fields[1]

        # Get start and end rows and columns.
        start_row, start_col = self._get_row_and_column(start)
        end_row, end_col = self._get_row_and_column(end)
        
        # Read all the cells, in row by row order.
        r = []
        row_incr = 0
        if ((end_row - start_row) != 0):
            row_incr = (end_row - start_row)/abs(end_row - start_row)
        col_incr = 0
        if ((end_col - start_col) != 0):
            col_incr = (end_col - start_col)/abs(end_col - start_col)
        curr_row = start_row
        #print "=========== READ CELLS!!! ================"
        while True:
            curr_col = start_col
            while True:
                val = None
                try:
                    if return_dict:
                        # Return actual dict, not str.
                        val = sheet.cell_dict(curr_row, curr_col)
                    else:       
                        val = utils.safe_str_convert(sheet.cell_value(curr_row, curr_col))
                except Exception as e:
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("get cell val " + utils.safe_str_convert((curr_row, curr_col)) + " error. " + utils.safe_str_convert(e))
                if (val is not None):
                    #print "(" + utils.safe_str_convert(curr_row) + ", " + utils.safe_str_convert(curr_col) + ")"
                    #print "'" + utils.safe_str_convert(val) + "'"
                    r.append(val)
                if (curr_col == end_col):
                    break
                curr_col += col_incr
            if (curr_row == end_row):
                break
            curr_row += row_incr

        # Return the cell values.
        #print "=========== CELLS!!! ================"
        #print cell_str
        #print r
        #sys.exit(0)
        return r
    
    def eval(self, context, params=None):

        # TODO: Need to track the index of each cell for full
        # emulation of a range. Probably need a Range object
        # implementation.

        # Sanity check.
        if (params is None):
            log.warning("Range() called with no parameters.")
            return "NULL"

        # Do we have a loaded Excel file?
        if (context.loaded_excel is None):

            # It can be the case that we have Range object in Word macro 
            if len(params) == 2 and isinstance(params[0], int) and isinstance(params[1], int):
                return context.globals["activedocument.content.text"][params[0]:params[1]]

            # No Range object in Word sample and no loaded Excel file. Bomb out.
            context.increase_general_errors()
            log.warning("Cannot process Range() call. No Excel file loaded.")
            return "NULL"

        # Were we given an Excel sheet object?
        sheet = None
        for p in params:
            if ("Sheet" in utils.safe_str_convert(type(p))):
                sheet = p
                break
            
        # Return a cell dict rather than the cell value?
        return_dict = False
        # We actually want to explicitly check for True.
        # pylint: disable=singleton-comparison
        if ((len(params) >= 2) and (params[1] is True)):
            return_dict = True
            
        # Currently only handles Range(x) calls.
        if ((len(params) != 1) and (not return_dict) and (sheet is None)):
            context.increase_general_errors()
            log.warning("Only 1 argument Range() calls supported. Returning NULL.")
            return "NULL"
            
        # Was Range() called on a single, already read cell?
        if (isinstance(params[0], dict)):

            # This is an indirect cell read. The cell address should be in the
            # value of the current cell.
            the_cell = params[0]
            if ("value" in the_cell):
                next_index = the_cell["value"]
                new_params = [next_index]
                for p in params[1:]:
                    new_params.append(p)
                return self.eval(context, new_params)

            # Unexpected. This is not a proper read cell dict.
            log.warning("Unexpected cell dict " + utils.safe_str_convert(the_cell) + ". Range() returning NULL.")
            return "NULL"

        # If we were given a sheet, only look there for the cell. Otherwise
        # look at all sheets.
        sheets = None
        if (sheet is not None):
            sheets = [sheet]
        else:
            sheets = []
            for sheet_index in range(0, len(context.loaded_excel.sheet_names())):
                sheet = None
                try:
                    sheet = context.loaded_excel.sheet_by_index(sheet_index)
                    sheets.append(sheet)
                except Exception as e:
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("context.loaded_excel.sheet_by_index(" + utils.safe_str_convert(sheet_index) + ") error. " + utils.safe_str_convert(e))
                    context.increase_general_errors()
                    log.warning("Cannot process Range() call. No sheets in file.")
                    return "NULL"

        # Try the given sheets until we read a cell.                
        col = None
        for sheet in sheets:

            # Multiple cells?
            range_index = utils.safe_str_convert(params[0])
            if (":" in range_index):
                try:
                    return self._read_cell_list(sheet, range_index, return_dict)
                except Exception as e:
                    # Try the next sheet.
                    continue
        
            # Get the cell contents.
            try:

                # Pull out the cell value.
                row, col = self._get_row_and_column(params[0])
                if return_dict:
                    # Return actual dict, not str.
                    val = sheet.cell_dict(row, col)
                else:
                    val = utils.safe_str_convert(sheet.cell_value(row, col))
            
                # Return the cell value.
                sheet_name = ""
                if (hasattr(sheet, "name")):
                    sheet_name = sheet.name
                log.info("Read cell (" + range_index + ") from sheet " + utils.safe_str_convert(sheet_name) + " = '" + utils.safe_str_convert(val) +"'")

                # Regular direct read of range of cells.
                return val            

            except Exception as e:
                # Try the next sheet.
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Cell read failed. " + utils.safe_str_convert(e))
                continue

        # We did not get the cell.
        row = "??"
        col = "??"
        try:
            row, col = self._get_row_and_column(params[0])
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("self._get_row_and_column(" + utils.safe_str_convert(params[0]) + ") error. " + utils.safe_str_convert(e))
        #print sheet
        log.warning("Failed to read cell (" + utils.safe_str_convert(row) + ", " + utils.safe_str_convert(col) + ") [" + utils.safe_str_convert(params[0]) + "] (2)")
        context.increase_general_errors()
        return "NULL"
        
class CountA(VbaLibraryFunc):
    """Emulate Excel CountA() function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            log.warning("No arguments passed to CountA(). Returning NULL")
            return "NULL"
        if (not isinstance(params[0], list)):
            log.warning("CountA() needs list argument, not " + utils.safe_str_convert(type(params[0])) + ". Returning NULL")
            return "NULL"

        # Return a count of all the non-empty cells.
        r = len(params[0])
        return r

class SpecialCells(VbaLibraryFunc):
    """Emulate Excel SpecialCells() method. Not directly used.

    """

    def eval(self, context, params=None):
        context = context # pylint

        # 1st arg should be a list of cell values, 2nd arg the type of cell to include.
        if ((params is None) or (len(params) < 2)):
            log.warning("Not enough arguments passed to SpecialCells(). Returning NULL")
            return "NULL"

        # Sometimes the args are swapped. Handle that.
        cells = None
        if (isinstance(params[0], list) and isinstance(params[1], int)):
            cells = params[0]
        if (isinstance(params[1], list) and isinstance(params[0], int)):
            cells = params[1]
        if (cells is None):
            log.warning("Incorrect argument types passed to SpecialCells(). Returning NULL")
            return "NULL"
            
        # Currently only handling cell type xlCellTypeConstants. This assumes that is what is
        # wanted.
        r = []
        for cell in cells:
            cell_value = utils.safe_str_convert(cell)
            if (isinstance(cell, dict)):
                cell_value = utils.safe_str_convert(cell["value"])
            if (len(cell_value) == 0):
                continue
            if (not cell_value.startswith("=")):
                r.append(cell)

        # Done.
        return r

class RandBetween(VbaLibraryFunc):
    """Emulate Excel RANDBETWEEN() function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        # Sanity check.
        if ((params is None) or (len(params) < 2)):
            return "NULL"
        lower = vba_conversion.coerce_to_int(params[0])
        upper = vba_conversion.coerce_to_int(params[1])
        return random.randint(lower, upper)

    def num_args(self):
        return 2

class DatePart(VbaLibraryFunc):
    """Emulate DatePart() function (stubbed). Currently (very) stubbed to
    just return 3.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        return 3
    
class Date(VbaLibraryFunc):
    """Emulate Date() function (stubbed). Currently stubbed to just return
    the current date as a Python datetime object.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        return date.today()

class DateAdd(VbaLibraryFunc):
    """Emulate DateAdd() function (stubbed). Currently stubbed to just
    return the current date as a Python datetime object.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        return date.today()
    
class Year(VbaLibraryFunc):
    """Emulate Year() function (stubbed).

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        t = params[0]
        r = "**MATCH ANY**"
        if isinstance(t, (date, datetime)):
            r = int(t.year)
        return r

class Minute(VbaLibraryFunc):
    """Emulate Minute() function (stubbed).

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        t = params[0]
        r = 0
        if (isinstance(t, datetime)):
            r = int(t.minute)
        return r

class Second(VbaLibraryFunc):
    """Emulate Second() function (stubbed).

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        t = params[0]
        r = 0
        if (isinstance(t, datetime)):
            r = int(t.second)
        try:
            d = datetime.strptime(t, '%H:%M:%S')
            r = int(d.second)
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Second(" + utils.safe_str_convert(params) + ") error. " + utils.safe_str_convert(e))
        return r

class Variable(VbaLibraryFunc):
    """Get a document variable.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) < 1)):
            return "NULL"
        var = utils.safe_str_convert(params[0]).strip()
        var = var.replace("activedocument.customdocumentproperties(", "").\
              replace(")", "").\
              replace("'","").\
              replace('"',"").\
              replace('.value',"").\
              strip()
        r = context.get_doc_var(var)
        if (r is None):
            r = ""
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("ActiveDocument.Variable(" + var + ") = " + utils.safe_str_convert(r))
        return r

class Variables(Variable):
    pass
    
class CDbl(VbaLibraryFunc):
    """Emulate CDbl() type conversion function.

    """

    def eval(self, context, params=None):
        context = context # pylint

        if ((params is None) or (len(params) < 1)):
            return "NULL"
        try:
            # Handle hex.
            tmp = utils.safe_str_convert(params[0]).upper()
            if (tmp.lower().startswith("&h")):
                tmp = tmp.replace("&h", "0x")
                tmp = int(tmp, 16)

            # VBA rounds the significant digits.
            #return round(float(params[0]), 11)
            return float(tmp)

        except Exception as e:
            log.error("CDbl(" + utils.safe_str_convert(params[0]) + ") failed. " + utils.safe_str_convert(e))
            return 0

class Popup(VbaLibraryFunc):
    """Emulate Popup() function.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) == 0)):
            return
        msg = params[0]
        context.report_action("Popup", utils.safe_str_convert(msg), '')
        
class Print(VbaLibraryFunc):
    """Emulate Debug.Print() function.

    """

    def _handle_file_print(self, context, params):
        """Emulate printing to a file.

        @param context (Context object) The current program
        state. This will be updated with the file update.

        @param params (list) The parameters of the file print call.

        """
        
        # Sanity check.
        if (len(params) != 2):
            log.warning("Wrong # of arguments for Print " + utils.safe_str_convert(params))
            return

        # 1st arg should be file ID.
        fileid = "#" + utils.safe_str_convert(params[0])

        # 2nd arg should be data to write.
        data = utils.safe_str_convert(params[1])

        # Try writing the file.
        context.write_file(fileid, data)
        
    def eval(self, context, params=None):

        # Sanity check.
        if (params is None):
            return

        # Print #NN to a file ID?
        if (len(params) == 2):
            self._handle_file_print(context, params)
            return
        
        # Regular Debug.Print() ?
        if (len(params) != 1):
            log.warning("Wrong # of arguments for Print " + utils.safe_str_convert(params))
            return

        # Save writes that look like they are writing URLs.
        data_str = utils.safe_str_convert(params[0])
        if (("http:" in data_str.lower()) or ("https:" in data_str.lower())):
            context.report_action('Write URL', data_str, 'Debug Print')

        if (params[0] is not None):
            if (not context.throttle_logging):
                data_str = utils.safe_str_convert(data_str).replace("\x00", "")
                context.report_action("Debug Print", data_str, '')

class Debug(Print):
    """Emulate Debug() debugging function.

    """
    pass

class Echo(Print):
    """Emulate WScript.Echo() debugging function.

    """
    pass

class DeleteFile(VbaLibraryFunc):
    """Emulate File delete DeleteFile() call.

    """

    def eval(self, context, params=None):
        if (params is None):
            return
        if (len(params) > 1):
            context.report_action('Delete File', utils.safe_str_convert(params[1]), 'DeleteFile() Call', strip_null_bytes=True)
        if (len(params) == 1):
            context.report_action('Delete File', utils.safe_str_convert(params[0]), 'DeleteFile() Call', strip_null_bytes=True)

class MoveFile(VbaLibraryFunc):
    """Emulate File move MoveFile() call.

    """

    def eval(self, context, params=None):
        if (params is None):
            return
        if (len(params) > 1):
            context.report_action('Move File', "MoveFile(" + utils.safe_str_convert(params[0]) + ", " + utils.safe_str_convert(params[1]) + ")",
                                  'MoveFile() Call', strip_null_bytes=True)

class FollowHyperlink(VbaLibraryFunc):
    """Emulate FollowHyperlink() function.

    """

    def eval(self, context, params=None):
        if (params is None):
            return
        if (len(params) >= 1):
            context.report_action('Download URL', utils.safe_str_convert(params[0]), 'FollowHyperLink', strip_null_bytes=True)

class GetExtensionName(VbaLibraryFunc):
    """Emulate GetExtensionName() function.

    """
    
    def eval(self, context, params=None):
        context = context # pylint

        if (params is None):
            return ""
        r = ""
        if (len(params) >= 1):
            fname = utils.safe_str_convert(params[0])
            if ("." in fname):
                r = fname[fname.rindex("."):]
        return r

class NumPut(VbaLibraryFunc):
    """Emulate DynamicWrapperX.NumPut() method. This simulates the
    NumPut() byte writing actions by writing the byte values to a
    DOM_NumPut.dat file.

    """

    def eval(self, context, params=None):

        if (params is None):
            return
        
        # Do we need to open the simulated file?
        if ("DOM_NumPut.dat" not in context.open_files):
            context.open_file("DOM_NumPut.dat")

        # Get the byte to write.
        if (len(params) < 3):
            return
        val = params[0]

        # Write the byte.
        # TODO: Use the position parameter to write the byte to the proper position.
        #pos = params[2]
        context.write_file("DOM_NumPut.dat", chr(val))
    
class CreateTextFile(VbaLibraryFunc):
    """Emulate CreateTextFile() method.

    """

    def eval(self, context, params=None):

        # Sanity check.
        if ((params is None) or (len(params) == 0) or (params[0] == None)):
            return "NULL"

        # Get the name of the file being opened.
        try:
            fname = context.get(params[0])
        except KeyError:
            fname = utils.safe_str_convert(params[0])
        if (fname is None):
            return "NULL"
        
        # Do we have a numeric file ID?
        file_id = ""
        if (len(params) > 1):
            file_id = params[1]
            
        # Save that the file is opened.
        context.open_file(fname, file_id)
        context.report_action('File Access', fname, "")

        # This could be an external WebDAV access.
        if (fname.startswith("\\\\")):

            # Pull out the mapped drive ID.
            if ("\\" in fname[2:]):
                end = fname[2:].index("\\") + 2
                drive_id = fname[2:end].strip()
                if (re.search(r"[\w_]{1,100}\.\w{2,10}", drive_id) is not None):
                    context.save_intermediate_iocs("http://" + drive_id)

        # How about returning the name of the opened file.
        return fname
    
class Open(CreateTextFile):
    """Emulate Open() file function. Also Open() HTTP function.

    """

    def eval(self, context, params=None):

        # Sanity check.
        if ((params is None) or (len(params) == 0)):
            return
        
        # Is this a HTTP GET or PUT or HEAD?
        action = ""
        if (len(params) >= 2):
            action = utils.safe_str_convert(params[0]).strip().upper()
            http_actions = set(["GET", "PUT", "HEAD"])
            if ((action in http_actions) or
                (utils.safe_str_convert(params[1]).startswith("ftp://")) or
                (utils.safe_str_convert(params[1]).startswith("http://")) or
                (utils.safe_str_convert(params[1]).startswith("https://"))):

                # Fix up the URL if needed.
                url = utils.safe_str_convert(params[1])
                if (url.startswith("tp://")):
                    url = "ht" + url
                # Do we just have a domain?
                domain_pat = r"^[A-Za-z0-9\-_]{1,100}(?:\.[A-Za-z0-9\-_]{1,100}){0,5}\.[A-Za-z0-9\-_]{1,10}$"
                if (re.search(domain_pat, url) is not None):
                    url = "http://" + url

                # Report the HTTP action.
                context.report_action(action, url, 'Interesting Function Call', strip_null_bytes=True)

        # It is a regular file open.
        else:
            super(Open, self).eval(context, params)

class OpenTextFile(CreateTextFile):
    """Emulate OpenTextFile() file function.

    """
    pass
            
class Timer(VbaLibraryFunc):
    """Emulate Timer() method (stubbed).

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        return int(time.mktime(datetime.now().timetuple()))

class Unescape(VbaLibraryFunc):
    """Emulate Unescape() string unescaping method (stubbed).

    """

    def eval(self, context, params=None):
        context = context # pylint
        
        # Get the string to unescape.
        if ((params is None) or (len(params) < 1)):
            return "NULL"
        s = utils.safe_str_convert(params[0])

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

    def return_type(self):
        return "STRING"
    
class InternetGetConnectedState(VbaLibraryFunc):
    """Emulate InternetGetConnectedState() function from wininet.dll
    (stubbed). Always returns True.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        # Always connected.
        return True

class DateDiff(VbaLibraryFunc):
    """Emulate Stubbed DateDiff() function. Returns a random plausible
    epoch integer.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint
        
        return 15904387438 + (5000 - random.randint(100, 10000))
    
class Not(VbaLibraryFunc):
    """Emulate Boolean Not() called as a function.

    """

    def eval(self, context, params=None):
        context = context # pylint
        
        if ((len(params) == 0) or (not isinstance(params[0], bool))):
            log.warning("Cannot compute Not(" + utils.safe_str_convert(params) + ").")
            return "NULL"
        return (not params[0])
                
class InternetOpenA(VbaLibraryFunc):
    """Emulate InternetOpenA() function from wininet.dll
    (stubbed). Always returns True.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint
        
        # Always succeeds.
        return True

class FreeFile(VbaLibraryFunc):
    """Emulate FreeFile() function.

    """

    def eval(self, context, params=None):
        params = params # pylint        

        # Return index of next open file.
        r = utils.safe_str_convert(len(context.open_files) + 1)
        return r

class CreateElement(VbaLibraryFunc):
    """Faked emulation of things like
    'CreateObject("Microsoft.XMLDOM").createElement("tmp")'.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint

        # Assume that this is something like 'CreateObject("Microsoft.XMLDOM").createElement("tmp")'.
        return "Microsoft.XMLDOM"

class Send(VbaLibraryFunc):
    """Faked emulation of HTTP send(). Always returns 200.

    """

    def eval(self, context, params=None):
        context = context # pylint
        params = params # pylint
        return 200

class SetTimeouts(VbaLibraryFunc):
    """Emulate ServerXMLHTTP SetTimeouts() method (stubbed).

    """

    def eval(self, context, params=None):
        pass

class SetOption(VbaLibraryFunc):
    """Emulate ServerXMLHTTP SetOption() method (stubbed).

    """

    def eval(self, context, params=None):
        pass
    
class SetRequestHeader(VbaLibraryFunc):
    """Emulate ServerXMLHTTP SetRequestHeader() method.

    """

    def eval(self, context, params=None):

        # Sanity check.
        if ((params is None) or (len(params) < 2)):
            return

        # Field is 1st arg.
        field = utils.safe_str_convert(params[0])

        # Value is 2nd arg.
        val = utils.safe_str_convert(params[1])

        # Save the header value.
        info = "'" + field + "' ==> '" + val + "'"
        context.report_action('Set HTTP Header', info, "ServerXMLHTTP::SetRequestHeader()")
    
class WriteProcessMemory(VbaLibraryFunc):
    """Emulate WriteProcessMemory() external method.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) < 1)):
            return
        context.report_action('Write Process Memory',
                              utils.safe_str_convert(params),
                              'External Function: kernel32.dll / WriteProcessMemory',
                              strip_null_bytes=True)

        # Track the shellcode bytes.
        if (len(params) < 4):
            return
        import vba_context
        vba_context.add_shellcode_data(params[1], params[2], params[3])
        
class Write(VbaLibraryFunc):
    """Emulate Write() method.

    """

    def eval(self, context, params=None):
        if ((params is None) or (len(params) < 1)):
            return

        # Get the data.
        data = utils.safe_str_convert(params[0])

        # Save writes that look like they are writing URLs.
        if (("http:" in data) or ("https:" in data)):
            context.report_action('Write URL', data, 'File Write', strip_null_bytes=True)

        # TODO: Currently the object on which Write() is being called is not
        # being tracked. We will only handle the Write() if there is only 1
        # obvious open file.
        if not context.open_files:
            log.error("Cannot process Write(). No open files.")
            return
        files = context.open_files.keys()
        if len(files) > 1:
            # Skip ADODB.Stream when guessing what file to write to.
            tmp_files = []
            for f in files:
                if (f.strip() == "ADODB.Stream"):
                    continue
                tmp_files.append(f)
            files = tmp_files
            if len(files) > 1:
                log.error("Cannot process Write(). Too many open files.")
                return

        # Simulate the write.

        # Get the ID of the file.
        file_id = files[0]
        log.info("Writing data to " + utils.safe_str_convert(file_id) + " .")

        context.write_file(file_id, data)

class DefaultFilePath(VbaLibraryFunc):
    """Emulate Options.DefaultFilePath() property. Stubbed.

    """

    def eval(self, context, params=None):

        # Sanity check.
        if ((params is None) or (len(params) < 1)):
            return ""

        # Get the sort of directory to return.
        dir_type = None
        try:
            dir_type = int(params[0])
        except ValueError:
            log.error("Bad param '" + utils.safe_str_convert(params[0]) + "' passed to DefaultFilePath().")
            return ""

        # Return a faked directory of each type.

        # wdAutoRecoverPath
        if (dir_type == 5):
            return "C:\\AutoRecoverPath_WORD\\"
        # wdBorderArtPath
        elif (dir_type == 19):
            return "C:\\BorderArtPath_WORD\\"        
        # wdCurrentFolderPath
        elif (dir_type == 14):
            return "C:\\CurrentFolderPath_WORD\\"        
        # wdDocumentsPath
        elif (dir_type == 0):
            return "C:\\DocumentsPath_WORD\\"        
        # wdGraphicsFiltersPath
        elif (dir_type == 10):
            return "C:\\GraphicsFiltersPath_WORD\\"        
        # wdPicturesPath
        elif (dir_type == 1):
            return "C:\\PicturesPath_WORD\\"        
        # wdProgramPath
        elif (dir_type == 9):
            return "C:\\ProgramPath_WORD\\"        
        # wdProofingToolsPath
        elif (dir_type == 12):
            return "C:\\ProofingToolsPath_WORD\\"        
        # wdStartupPath
        elif (dir_type == 8):
            return "C:\\StartupPath_WORD\\"        
        # wdStyleGalleryPath
        elif (dir_type == 15):
            return "C:\\StyleGalleryPath_WORD\\"        
        # wdTempFilePath
        elif (dir_type == 13):
            return "C:\\TempFilePath_WORD\\"        
        # wdTextConvertersPath
        elif (dir_type == 11):
            return "C:\\TextConvertersPath_WORD\\"        
        # wdToolsPath
        elif (dir_type == 6):
            return "C:\\ToolsPath_WORD\\"        
        # wdTutorialPath
        elif (dir_type == 7):
            return "C:\\TutorialPath_WORD\\"        
        # wdUserOptionsPath
        elif (dir_type == 4):
            return "C:\\UserOptionsPath_WORD\\"        
        # wdUserTemplatesPath
        elif (dir_type == 2):
            return "C:\\UserTemplatesPath_WORD\\"        
        # wdWorkgroupTemplatesPath
        elif (dir_type == 3):
            return "C:\\wdWorkgroupTemplatesPath_WORD\\"        

        # Unknown
        return "C:\\UNKOWN_DEFAULTFILEPATH_DIR\\"        
        
        
# Save classes emulating various VB functions for later lookup.
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
               AddFromString, Not, PrivateProfileString, GetCursorPos, CreateElement,
               IsObject, NumPut, GetLocale, URLDownloadToFile, URLDownloadToFileA,
               URLDownloadToFileW, SaveAs, Quit, Exists, RegRead, Kill, RmDir, EOF,
               MonthName, GetSpecialFolder, IsEmpty, Date, DeleteFile, MoveFile, DateAdd,
               Error, LanguageID, MultiByteToWideChar, IsNull, SetStringValue, TypeName,
               VarType, Send, CreateShortcut, Popup, MakeSureDirectoryPathExists,
               GetSaveAsFilename, ChDir, ExecuteExcel4Macro, VarPtr, WriteText, FileCopy,
               WriteProcessMemory, RunShell, CopyHere, GetFolder, Hour, _Chr, SaveAs2,
               Chr, CopyFile, GetFile, Paragraphs, UsedRange, CountA, SpecialCells,
               RandBetween, Items, Count, GetParentFolderName, WriteByte, ChrB, ChrW,
               RtlMoveMemory, OnTime, AddItem, Rows, DatePart, FileLen, Sheets, Choose,
               Worksheets, Value, IsObject, Filter, GetRef, BuildPath, CreateFolder,
               Arguments, DateDiff, SetRequestHeader, SetOption, SetTimeouts, DefaultFilePath,
               SubFolders, Files, Name):
    name = _class.__name__.lower()
    VBA_LIBRARY[name] = _class()

if (log.getEffectiveLevel() == logging.DEBUG):
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
        # From OleVBA the EOL character is just '\n'.
        ('vbCrLf', '\r\n'),
        #('vbCrLf', '\n'),
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
