#!/usr/bin/env python
"""
ViperMonkey: Execution context for global and local variables

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

__version__ = '0.08'

# --- IMPORTS ------------------------------------------------------------------

import logging
import os
from hashlib import sha256
from datetime import datetime
from logger import log
import base64
import re
import random
import string
import codecs
import copy
import struct

from curses_ascii import isascii

def to_hex(s):
    """
    Convert a string to a VBA hex string.
    """

    r = ""
    for c in str(s):
        r += hex(ord(c)).replace("0x", "")
    return r

def is_procedure(vba_object):
    """
    Check if a VBA object is a procedure, e.g. a Sub or a Function.
    This is implemented by checking if the object has a statements
    attribute
    :param vba_object: VBA_Object to be checked
    :return: True if vba_object is a procedure, False otherwise
    """
    if hasattr(vba_object, 'statements'):
        return True
    else:
        return False

def add_shellcode_data(index, value, num_bytes):
    """
    Save injected shellcode data.
    """

    # Sanity check.
    if ((not isinstance(index, int)) or
        (not isinstance(value, int)) or
        (not isinstance(num_bytes, int))):
        log.warning("Improperly typed argument passed to add_shellcode_data(). Skipping.")
        return

    # Currently only handling single byte values.
    if (num_bytes > 1):
        log.warning("Only handling single byte values in add_shellcode_data(). Skipping.")
        return
    
    # Track the written byte.
    shellcode[index] = value

def get_shellcode_data():
    """
    Get written shellcode bytes as a list.
    """

    # Punt if there is no shellcode data.
    if (len(shellcode) == 0):
        return []

    # Get the shellcode bytes in order. Assume any missing
    # bytes are x86 NOOP instructions.
    indices = shellcode.keys()
    indices.sort()
    last_i = None
    r = []
    for i in indices:

        # Need to fill in missing bytes?
        if ((last_i is not None) and (last_i + 1 != i)):
            last_i += 1
            while (last_i != i):
                r.append(0x90)
                last_i += 1

        # Only want unsigned integers for byte values.
        curr_val = shellcode[i]
        if (curr_val < 0):
            curr_val += 2**8
                    
        # Add in the current shellcode byte.
        r.append(curr_val)
        last_i = i

    # Return shellcode bytes, in order.
    return r
    
# === VBA CLASSES =====================================================================================================

# global dictionary of constants, functions and subs for the VBA library
VBA_LIBRARY = {}

# Output directory to save dropped artifacts.
out_dir = None  # type: str

# Track intermediate IOC values stored in variables during emulation.
intermediate_iocs = set()

# Track the # of base64 IOCs.
num_b64_iocs = 0

# Track any injected shellcode bytes written by the VBA.
# Dict mapping index to a byte.
shellcode = {}

class Context(object):
    """
    a Context object contains the global and local named objects (variables, subs, functions)
    used to evaluate VBA statements.
    """

    def __init__(self,
                 _globals=None,
                 _locals=None,
                 context=None,
                 engine=None,
                 doc_vars=None,
                 loaded_excel=None,
                 filename=None,
                 copy_globals=False,
                 log_funcs=None,
                 expand_env_vars=True,
                 metadata=None):

        # Track the names of VB constants.
        self.vb_constants = set()
        
        # Track canonical names of variables.
        self.name_cache = {}

        # Track the name of the current function being emulated.
        self.curr_func_name = None
        
        # Track the name of the last saved file.
        self.last_saved_file = None
        
        # Track whether we are handling a non-boolean (bitwise) expression.
        self.in_bitwise_expression = False
        
        # Track whether emulation actions have been reported.
        self.got_actions = False
        
        # Track all external functions called by the program.
        self.external_funcs = []

        # Track a quick lookup of variables that have change handling functions.
        self.has_change_handler = {}
        
        # Track the current call stack. This is used to detect simple cases of
        # infinite recursion.
        self.call_stack = []
        
        # Track the maximum number of iterations to emulate in a while loop before
        # breaking out (infinite loop) due to no vars in the loop guard being
        # modified.
        self.max_static_iters = 2

        # Track whether VBScript or VBA is being analyzed.
        self.is_vbscript = False

        # JIT loop emulation?
        self.do_jit = False

        # Track whether logging should be throttled.
        self.throttle_logging = False
        
        # Allow user to provide extra function names to be reported on.
        if log_funcs:
            self._log_funcs = [func_name.lower() for func_name in log_funcs]
        else:
            self._log_funcs = []

        # Allow user to determine whether to expand environment variables.
        self.expand_env_vars = expand_env_vars
        
        # Track callback functions that should not be called. This is to handle
        # recusive change handler calls caused by modifying the element handled
        # by the change handler inside the handler.
        self.skip_handlers = set()
        
        # Track the file being analyze.
        self.filename = filename
        
        # Track whether an error was raised in an emulated statement.
        self.got_error = False

        # Track the error handler to execute when an error is raised.
        self.error_handler = None

        # Track the numebr of reported general errors.
        self.num_general_errors = 0
        
        # Track mapping from bogus alias name of DLL imported functions to
        # real names.
        self.dll_func_true_names = {}
        
        # Track a dict mapping the labels of code blocks labeled with the LABEL:
        # construct to code blocks. This will be used to evaluate GOTO statements
        # when emulating.
        self.tagged_blocks = {}

        # Track the in-memory loaded Excel workbook (xlrd workbook object).
        self.loaded_excel = loaded_excel
        
        # Track open files.
        self.open_files = {}
        self.file_id_map = {}

        # Track the final contents of written files.
        self.closed_files = {}

        # Track document metadata.
        self.metadata = metadata
        
        # Track whether variables by default should go in the global scope.
        self.global_scope = False

        # Track if this is the context of a function/sub.
        self.in_procedure = False

        # Track whether we have emulated a goto.
        self.goto_executed = False

        # Track variable types, if known.
        self.types = {}

        # Track the current with prefix for with statements. This has been evaluated
        self.with_prefix = ""
        # Track the current with prefix for with statements. This has not been evaluated
        self.with_prefix_raw = None
        
        # globals should be a pointer to the globals dict from the core VBA engine (ViperMonkey)
        # because each statement should be able to change global variables
        if _globals is not None:
            if (copy_globals):
                self.globals = copy.deepcopy(_globals)
            else:
                self.globals = _globals

            # Save intermediate IOCs if any appear.
            for var in _globals.keys():
                self.save_intermediate_iocs(_globals[var])
                
        elif context is not None:
            if (copy_globals):
                self.globals = copy.deepcopy(context.globals)
            else:
                self.globals = context.globals
            self.in_bitwise_expression = context.in_bitwise_expression
            self.vb_constants = context.vb_constants
            self.last_saved_file = context.last_saved_file
            self.curr_func_name = context.curr_func_name
            self.do_jit = context.do_jit
            self.has_change_handler = context.has_change_handler
            self.throttle_logging = context.throttle_logging
            self.is_vbscript = context.is_vbscript
            self.doc_vars = context.doc_vars
            self.types = context.types
            self.open_files = context.open_files
            self.file_id_map = context.file_id_map
            self.closed_files = context.closed_files
            self.loaded_excel = context.loaded_excel
            self.dll_func_true_names = context.dll_func_true_names
            self.filename = context.filename
            self.skip_handlers = context.skip_handlers
            self.call_stack = context.call_stack
            self.expand_env_vars = context.expand_env_vars
            self.metadata = context.metadata
            self.external_funcs = context.external_funcs
            self.num_general_errors = context.num_general_errors
            self.with_prefix = context.with_prefix
            self.with_prefix_raw = context.with_prefix_raw
        else:
            self.globals = {}
        # on the other hand, each Context should have its own private copy of locals
        if _locals is not None:
            # However, if locals is explicitly provided, we use a copy of it:
            self.locals = dict(_locals)
        else:
            self.locals = {}
        # engine should be a pointer to the ViperMonkey engine, to provide callback features
        if engine is not None:
            self.engine = engine
        elif context is not None:
            self.engine = context.engine
        else:
            self.engine = None

        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Have xlrd loaded Excel file = " + str(self.loaded_excel is not None))
            
        # Track data saved in document variables.
        if doc_vars is not None:

            # direct copy of the pointer to globals:
            self.doc_vars = doc_vars

            # Save intermediate IOCs if any appear.
            for var in doc_vars.keys():
                self.save_intermediate_iocs(doc_vars[var])

        elif context is not None:
            self.doc_vars = context.doc_vars
        else:
            self.doc_vars = {}
            
        # Track whether nested loops are running with a stack of flags. If a loop is
        # running its flag will be True.
        self.loop_stack = []

        # Track the actual nested loops that are running on a stack. This is used to
        # handle GOTOs that jump out of the current loop body.
        self.loop_object_stack = []
        
        # Track whether we have exited from the current function.
        self.exit_func = False
        
        # Add in a global for the current time.
        self.globals["Now".lower()] = datetime.now()
        self.vb_constants.add("Now".lower())

        # Fake up a user name.
        rand_name = ''.join(random.choice(string.ascii_uppercase + string.digits + " ") for _ in range(random.randint(10, 50)))
        self.globals["Application.UserName".lower()] = rand_name
        self.vb_constants.add("Application.UserName".lower())

        # Fake a location for the template folder.
        self.globals["ActiveDocument.AttachedTemplate.Path".lower()] = "C:\\Users\\" + rand_name + "\\AppData\\Roaming\\Microsoft\\Templates"
        self.globals["ThisDocument.AttachedTemplate.Path".lower()] = "C:\\Users\\" + rand_name + "\\AppData\\Roaming\\Microsoft\\Templates"
        
        # region Add some attributes we are handling as global variables.

        # Keyboard keys and things in the key namespaces
        self.add_key_macro("vbDirectory","vbDirectory")
        self.add_key_macro("vbKeyLButton",1)
        self.add_key_macro("vbKeyRButton",2)
        self.add_key_macro("vbKeyCancel",3)
        self.add_key_macro("vbKeyMButton",4)
        self.add_key_macro("vbKeyBack",8)
        self.add_key_macro("vbKeyTab",9)
        self.add_key_macro("vbKeyClear",12)
        self.add_key_macro("vbKeyReturn",13)
        self.add_key_macro("vbKeyShift",16)
        self.add_key_macro("vbKeyControl",17)
        self.add_key_macro("vbKeyMenu",18)
        self.add_key_macro("vbKeyPause",19)
        self.add_key_macro("vbKeyCapital",20)
        self.add_key_macro("vbKeyEscape",27)
        self.add_key_macro("vbKeySpace",32)
        self.add_key_macro("vbKeyPageUp",33)
        self.add_key_macro("vbKeyPageDown",34)
        self.add_key_macro("vbKeyEnd",35)
        self.add_key_macro("vbKeyHome",36)
        self.add_key_macro("vbKeyLeft",37)
        self.add_key_macro("vbKeyUp",38)
        self.add_key_macro("vbKeyRight",39)
        self.add_key_macro("vbKeyDown",40)
        self.add_key_macro("vbKeySelect",41)
        self.add_key_macro("vbKeyPrint",42)
        self.add_key_macro("vbKeyExecute",43)
        self.add_key_macro("vbKeySnapshot",44)
        self.add_key_macro("vbKeyInsert",45)
        self.add_key_macro("vbKeyDelete",46)
        self.add_key_macro("vbKeyHelp",47)
        self.add_key_macro("vbKeyNumlock",144)
        self.add_key_macro("vbKeyA",65)
        self.add_key_macro("vbKeyB",66)
        self.add_key_macro("vbKeyC",67)
        self.add_key_macro("vbKeyD",68)
        self.add_key_macro("vbKeyE",69)
        self.add_key_macro("vbKeyF",70)
        self.add_key_macro("vbKeyG",71)
        self.add_key_macro("vbKeyH",72)
        self.add_key_macro("vbKeyI",73)
        self.add_key_macro("vbKeyJ",74)
        self.add_key_macro("vbKeyK",75)
        self.add_key_macro("vbKeyL",76)
        self.add_key_macro("vbKeyM",77)
        self.add_key_macro("vbKeyN",78)
        self.add_key_macro("vbKeyO",79)
        self.add_key_macro("vbKeyP",80)
        self.add_key_macro("vbKeyQ",81)
        self.add_key_macro("vbKeyR",82)
        self.add_key_macro("vbKeyS",83)
        self.add_key_macro("vbKeyT",84)
        self.add_key_macro("vbKeyU",85)
        self.add_key_macro("vbKeyV",86)
        self.add_key_macro("vbKeyW",87)
        self.add_key_macro("vbKeyX",88)
        self.add_key_macro("vbKeyY",89)
        self.add_key_macro("vbKeyZ",90)
        self.add_key_macro("vbKey0",48)
        self.add_key_macro("vbKey1",49)
        self.add_key_macro("vbKey2",50)
        self.add_key_macro("vbKey3",51)
        self.add_key_macro("vbKey4",52)
        self.add_key_macro("vbKey5",53)
        self.add_key_macro("vbKey6",54)
        self.add_key_macro("vbKey7",55)
        self.add_key_macro("vbKey8",56)
        self.add_key_macro("vbKey9",57)
        self.add_key_macro("vbKeyNumpad0",96)
        self.add_key_macro("vbKeyNumpad1",97)
        self.add_key_macro("vbKeyNumpad2",98)
        self.add_key_macro("vbKeyNumpad3",99)
        self.add_key_macro("vbKeyNumpad4",100)
        self.add_key_macro("vbKeyNumpad5",101)
        self.add_key_macro("vbKeyNumpad6",102)
        self.add_key_macro("vbKeyNumpad7",103)
        self.add_key_macro("vbKeyNumpad8",104)
        self.add_key_macro("vbKeyNumpad9",105)
        self.add_key_macro("vbKeyMultiply",106)
        self.add_key_macro("vbKeyAdd",107)
        self.add_key_macro("vbKeySeparator",108)
        self.add_key_macro("vbKeySubtract",109)
        self.add_key_macro("vbKeyDecimal",110)
        self.add_key_macro("vbKeyDivide",111)
        self.add_key_macro("vbKeyF1",112)
        self.add_key_macro("vbKeyF2",113)
        self.add_key_macro("vbKeyF3",114)
        self.add_key_macro("vbKeyF4",115)
        self.add_key_macro("vbKeyF5",116)
        self.add_key_macro("vbKeyF6",117)
        self.add_key_macro("vbKeyF7",118)
        self.add_key_macro("vbKeyF8",119)
        self.add_key_macro("vbKeyF9",120)
        self.add_key_macro("vbKeyF10",121)
        self.add_key_macro("vbKeyF11",122)
        self.add_key_macro("vbKeyF12",123)
        self.add_key_macro("vbKeyF13",124)
        self.add_key_macro("vbKeyF14",125)
        self.add_key_macro("vbKeyF15",126)
        self.add_key_macro("vbKeyF16",127)
        self.add_key_macro("vbNullString",'')
        self.add_key_macro("vbNullChar",'\0')
        self.add_key_macro("vbUpperCase",1)
        self.add_key_macro("vbLowerCase",2)
        self.add_key_macro("vbProperCase",3)
        self.add_key_macro("vbWide",4)
        self.add_key_macro("vbNarrow",8)
        self.add_key_macro("vbKatakana",16)
        self.add_key_macro("vbHiragana",32)
        self.add_key_macro("vbUnicode",64)
        self.add_key_macro("vbFromUnicode",128)

        # other global variables 
        self.globals["xlOuterCenterPoint".lower()] = 2.0
        self.vb_constants.add("xlOuterCenterPoint".lower())
        self.globals["xlPivotLineBlank".lower()] = 2
        self.vb_constants.add("xlPivotLineBlank".lower())
        self.globals["rgbMaroon".lower()] = 128
        self.vb_constants.add("rgbMaroon".lower())
        self.globals["NoLineBreakAfter".lower()] = ""
        self.vb_constants.add("NoLineBreakAfter".lower())
        
        # vba color constants
        self.add_color_constant_macro("vbBlack",0)
        self.add_color_constant_macro("vbBlue",16711680)
        self.add_color_constant_macro("vbCyan",16776960)
        self.add_color_constant_macro("vbGreen",65280)
        self.add_color_constant_macro("vbMagenta",16711935)
        self.add_color_constant_macro("vbRed",225)
        self.add_color_constant_macro("vbWhite",167772115)
        self.add_color_constant_macro("vbYellow",65535)
        self.add_color_constant_macro("vb3DDKShadow",-2147483627) 
        self.add_color_constant_macro("vb3DFace",-2147483633) 
        self.add_color_constant_macro("vb3DHighlight",-2147483628) 
        self.add_color_constant_macro("vb3DLight",-2147483626) 
        self.add_color_constant_macro("vb3DShadow",-2147483632) 
        self.add_color_constant_macro("vbActiveBorder",-2147483638) 
        self.add_color_constant_macro("vbActiveTitleBar",-2147483646) 
        self.add_color_constant_macro("vbApplicationWorkspace",-2147483636) 
        self.add_color_constant_macro("vbButtonFace",-2147483633) 
        self.add_color_constant_macro("vbButtonShadow",-2147483632) 
        self.add_color_constant_macro("vbButtonText",-2147483630) 
        self.add_color_constant_macro("vbDesktop",-2147483647) 
        self.add_color_constant_macro("vbGrayText",-2147483631) 
        self.add_color_constant_macro("vbHighlight",-2147483635) 
        self.add_color_constant_macro("vbHighlightText",-2147483634) 
        self.add_color_constant_macro("vbInactiveBorder",-2147483637) 
        self.add_color_constant_macro("vbInactiveCaptionText",-2147483629) 
        self.add_color_constant_macro("vbInactiveTitleBar",-2147483645) 
        self.add_color_constant_macro("vbInfoBackground",-2147483624) 
        self.add_color_constant_macro("vbInfoText",-2147483625) 
        self.add_color_constant_macro("vbMenuBar",-2147483644) 
        self.add_color_constant_macro("vbMenuText",-2147483641) 
        self.add_color_constant_macro("vbMsgBox",-2147483625) 
        self.add_color_constant_macro("vbMsgBoxText",-2147483624) 
        self.add_color_constant_macro("vbScrollBars",-2147483648) 
        self.add_color_constant_macro("vbTitleBarText",-2147483639) 
        self.add_color_constant_macro("vbWindowBackground",-2147483643) 
        self.add_color_constant_macro("vbWindowFrame",-2147483642) 
        self.add_color_constant_macro("vbWindowText",-2147483640) 

        self.add_multiple_macro(["","VBA.FormShowConstants"],"vbModal", 1)
        self.add_multiple_macro(["","VBA.FormShowConstants"],"vbModeless", 0)

        self.add_multiple_macro(["","VBA.vbCompareMethod"],"vbBinaryCompare", 0)
        self.add_multiple_macro(["","VBA.vbCompareMethod"],"vbDatabaseCompare", 2)
        self.add_multiple_macro(["","VBA.vbCompareMethod"],"vbTextCompare", 1)

        self.add_multiple_macro(["","VBA.vbDateTimeFormat"],"vbGeneralDate", 0)
        self.add_multiple_macro(["","VBA.vbDateTimeFormat"],"vbLongDate", 1)
        self.add_multiple_macro(["","VBA.vbDateTimeFormat"],"vbLongTime", 3)
        self.add_multiple_macro(["","VBA.vbDateTimeFormat"],"vbShortDate", 2)
        self.add_multiple_macro(["","VBA.vbDateTimeFormat"],"vbShortTime", 4)

        self.add_multiple_macro(["","VBA.vbDayOfWeek"],"vbFriday", 6)
        self.add_multiple_macro(["","VBA.vbDayOfWeek"],"vbMonday", 2)
        self.add_multiple_macro(["","VBA.vbDayOfWeek"],"vbSaturday", 7)
        self.add_multiple_macro(["","VBA.vbDayOfWeek"],"vbSunday", 1)
        self.add_multiple_macro(["","VBA.vbDayOfWeek"],"vbThursday", 5)
        self.add_multiple_macro(["","VBA.vbDayOfWeek"],"vbTuesday", 3)
        self.add_multiple_macro(["","VBA.vbDayOfWeek"],"vbUseSystemDayOfWeek", 0)
        self.add_multiple_macro(["","VBA.vbDayOfWeek"],"vbWednesday", 4)

        self.add_multiple_macro(["","VBA.vbFirstWeekOfYear"],"vbFirstFourDays", 2)
        self.add_multiple_macro(["","VBA.vbFirstWeekOfYear"],"vbFirstFullWeek", 3)
        self.add_multiple_macro(["","VBA.vbFirstWeekOfYear"],"vbFirstJan1", 1)
        self.add_multiple_macro(["","VBA.vbFirstWeekOfYear"],"vbUseSystem", 0)

        self.add_multiple_macro(["","VBA.vbFileAttribute"],"vbAlias", 64)
        self.add_multiple_macro(["","VBA.vbFileAttribute"],"vbArchive", 32)
        self.add_multiple_macro(["","VBA.vbFileAttribute"],"vbDirectory", 16)
        self.add_multiple_macro(["","VBA.vbFileAttribute"],"vbHidden", 2)
        self.add_multiple_macro(["","VBA.vbFileAttribute"],"vbNormal", 0)
        self.add_multiple_macro(["","VBA.vbFileAttribute"],"vbReadOnly", 1)
        self.add_multiple_macro(["","VBA.vbFileAttribute"],"vbSystem", 4)
        self.add_multiple_macro(["","VBA.vbFileAttribute"],"vbVolume", 8)

        self.add_multiple_macro(["","VBA.vbMsgBoxResult"],"vbAbort", 3)
        self.add_multiple_macro(["","VBA.vbMsgBoxResult"],"vbCancel", 2)
        self.add_multiple_macro(["","VBA.vbMsgBoxResult"],"vbIgnore", 5)
        self.add_multiple_macro(["","VBA.vbMsgBoxResult"],"vbNo", 7)
        self.add_multiple_macro(["","VBA.vbMsgBoxResult"],"vbOK", 1)
        self.add_multiple_macro(["","VBA.vbMsgBoxResult"],"vbRetry", 4)
        self.add_multiple_macro(["","VBA.vbMsgBoxResult"],"vbYes", 6)

        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbAbortRetryIgnore", 2)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbApplicationModal", 0)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbCritical", 16)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbDefaultButton1", 0)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbDefaultButton2", 256)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbDefaultButton3", 512)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbDefaultButton4", 768)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbExclamation", 48)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbInformation", 64)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbMsgBoxHelpButton", 16384)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbMsgBoxRight", 524288)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbMsgBoxRtlReading", 1048576)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbMsgBoxSetForeground", 65536)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbOKCancel", 1)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbOKOnly", 0)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbQuestion", 32)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbRetyrCancel", 5)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbSystemModal", 4096)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbYesNo", 4)
        self.add_multiple_macro(["","VBA.vbMsgBoxStyle"],"vbYesNoCancel", 3)

        self.add_multiple_macro(["","VBA.vbQueryClose"],"vbAppTaskManager", 3)
        self.add_multiple_macro(["","VBA.vbQueryClose"],"vbAppWindows", 2)
        self.add_multiple_macro(["","VBA.vbQueryClose"],"vbFormCode", 1)
        self.add_multiple_macro(["","VBA.vbQueryClose"],"vbFormControlMenu", 0)
        self.add_multiple_macro(["","VBA.vbQueryClose"],"vbFormMDIForm", 4)

        self.add_multiple_macro(["","VBA.vbTriState"],"vbFalse", 0)
        self.add_multiple_macro(["","VBA.vbTriState"],"vbTrue", -1)
        self.add_multiple_macro(["","VBA.vbTriState"],"vbUseDefault", -2)

        self.add_multiple_macro(["","VBA.vbVarType"],"vbArray", 8192)
        self.add_multiple_macro(["","VBA.vbVarType"],"vbBoolean", 11)
        self.add_multiple_macro(["","VBA.vbVarType"],"vbByte", 17)
        self.add_multiple_macro(["","VBA.vbVarType"],"vbCurrency", 6)
        self.add_multiple_macro(["","VBA.vbVarType"],"vbDataObject", 13)
        self.add_multiple_macro(["","VBA.vbVarType"],"vbDate", 7)
        self.add_multiple_macro(["","VBA.vbVarType"],"vbDecimal", 14)
        self.add_multiple_macro(["","VBA.vbVarType"],"vbDouble", 5)
        self.add_multiple_macro(["","VBA.vbVarType"],"vbEmpty", 0)
        self.add_multiple_macro(["","VBA.vbVarType"],"vbError", 10)
        self.add_multiple_macro(["","VBA.vbVarType"],"vbInteger", 2)
        self.add_multiple_macro(["","VBA.vbVarType"],"vbLong", 3)
        self.add_multiple_macro(["","VBA.vbVarType"],"vbNull", 1)
        self.add_multiple_macro(["","VBA.vbVarType"],"vbObject", 9)
        self.add_multiple_macro(["","VBA.vbVarType"],"vbSingle", 4)
        self.add_multiple_macro(["","VBA.vbVarType"],"vbString", 8)
        self.add_multiple_macro(["","VBA.vbVarType"],"vbUserDefinedType", 36)
        self.add_multiple_macro(["","VBA.vbVarType"],"vbVariant", 12)

        self.add_multiple_macro(["","VBA.vbAppWinStyle"],"vbHide", 0)
        self.add_multiple_macro(["","VBA.vbAppWinStyle"],"vbMaximizedFocus", 3)
        self.add_multiple_macro(["","VBA.vbAppWinStyle"],"vbMinimizedFocus", 2)
        self.add_multiple_macro(["","VBA.vbAppWinStyle"],"vbMinimizedNoFocus", 6)
        self.add_multiple_macro(["","VBA.vbAppWinStyle"],"vbNormalFocus", 1)
        self.add_multiple_macro(["","VBA.vbAppWinStyle"],"vbNormalNoFocus", 4)

        self.add_multiple_macro(["","VBA.vbCalendar"],"vbCalGreg", 0)
        self.add_multiple_macro(["","VBA.vbCalendar"],"vbCalHijri", 1)

        self.add_multiple_macro(["","VBA.vbCallType"],"vbGet", 2)
        self.add_multiple_macro(["","VBA.vbCallType"],"vbLet", 4)
        self.add_multiple_macro(["","VBA.vbCallType"],"vbMethod", 1)
        self.add_multiple_macro(["","VBA.vbCallType"],"vbSet", 8)

        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEAlphaDbl", 7)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEAlphaSng", 8)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEDisable", 3)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEHiragana", 4)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEKatakanaDbl", 5)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEKatakanaSng", 6)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEModeAlpha", 8)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEModeAlphaFull", 7)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEModeDisable", 3)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEModeHangul", 10)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEModeHangulFull", 9)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEModeHiragana", 4)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEModeKatakana", 5)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEModeKatakanaHalf", 6)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEModeNoControl", 0)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEModeOff", 2)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEModeOn", 1)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMENoOp", 0)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEOff", 2)
        self.add_multiple_macro(["","VBA.vbIMEStatus"],"vbIMEOn", 1)

        self.globals["Null".lower()] = None
        self.vb_constants.add("Null".lower())

        # WdDisableFeaturesIntroducedAfter enumeration (Word)
        #   
        # Specifies the version of Microsoft Word for which to disable all features introduced after that version.
        
        # Specifies Word for Windows 95, versions 7.0 and 7.0a.
        self.globals["wd70".lower()] = 0
        self.vb_constants.add("wd70".lower())
        # Specifies Word for Windows 95, versions 7.0 and 7.0a, Asian edition.
        self.globals["wd70FE".lower()] = 1
        self.vb_constants.add("wd70FE".lower())
        # Specifies Word 97 for Windows. Default.
        self.globals["wd80".lower()] = 2
        self.vb_constants.add("wd80".lower())
        
        # WdEmphasisMark enumeration (Word)
        #   
        # Specifies the type of emphasis mark to use for a character or designated character string.
        
        # No emphasis mark.
        self.globals["wdEmphasisMarkNone".lower()] = 0
        self.vb_constants.add("wdEmphasisMarkNone".lower())
        # A comma.
        self.globals["wdEmphasisMarkOverComma".lower()] = 2
        self.vb_constants.add("wdEmphasisMarkOverComma".lower())
        # A solid black circle.
        self.globals["wdEmphasisMarkOverSolidCircle".lower()] = 1
        self.vb_constants.add("wdEmphasisMarkOverSolidCircle".lower())
        # An empty white circle.
        self.globals["wdEmphasisMarkOverWhiteCircle".lower()] = 3
        self.vb_constants.add("wdEmphasisMarkOverWhiteCircle".lower())
        # A solid black circle.
        self.globals["wdEmphasisMarkUnderSolidCircle".lower()] = 4
        self.vb_constants.add("wdEmphasisMarkUnderSolidCircle".lower())
        
        # WdUseFormattingFrom enumeration (Word)
        #   
        # Specifies a source to copy formatting from.
        
        # Copy source formatting from the current item.
        self.globals["wdFormattingFromCurrent".lower()] = 0
        self.vb_constants.add("wdFormattingFromCurrent".lower())
        # Prompt the user for formatting to use.
        self.globals["wdFormattingFromPrompt".lower()] = 2
        self.vb_constants.add("wdFormattingFromPrompt".lower())
        # Copy source formatting from the current selection.
        self.globals["wdFormattingFromSelected".lower()] = 1
        self.vb_constants.add("wdFormattingFromSelected".lower())
        
        # WdLigatures enumeration (Word)
        #   
        # Specifies the type of ligatures applied to a font.
        
        # Applies all types of ligatures to the font.
        self.globals["wdLigaturesAll".lower()] = 15
        self.vb_constants.add("wdLigaturesAll".lower())
        # Applies contextual ligatures to the font. Contextual ligatures are often designed to enhance readability, but may also be solely ornamental. Contextual ligatures may also be contextual alternates.
        self.globals["wdLigaturesContextual".lower()] = 2
        self.vb_constants.add("wdLigaturesContextual".lower())
        # Applies contextual and discretional ligatures to the font.
        self.globals["wdLigaturesContextualDiscretional".lower()] = 10
        self.vb_constants.add("wdLigaturesContextualDiscretional".lower())
        # Applies contextual and historical ligatures to the font.
        self.globals["wdLigaturesContextualHistorical".lower()] = 6
        self.vb_constants.add("wdLigaturesContextualHistorical".lower())
        # Applies contextual, historical, and discretional ligatures to a font.
        self.globals["wdLigaturesContextualHistoricalDiscretional".lower()] = 14
        self.vb_constants.add("wdLigaturesContextualHistoricalDiscretional".lower())
        # Applies discretional ligatures to the font. Discretional ligatures are most often designed to be ornamental at the discretion of the type developer.
        self.globals["wdLigaturesDiscretional".lower()] = 8
        self.vb_constants.add("wdLigaturesDiscretional".lower())
        # Applies historical ligatures to the font. Historical ligatures are similar to standard ligatures in that they were originally intended to improve the readability of the font, but may look archaic to the modern reader.
        self.globals["wdLigaturesHistorical".lower()] = 4
        self.vb_constants.add("wdLigaturesHistorical".lower())
        # Applies historical and discretional ligatures to the font.
        self.globals["wdLigaturesHistoricalDiscretional".lower()] = 12
        self.vb_constants.add("wdLigaturesHistoricalDiscretional".lower())
        # Does not apply any ligatures to the font.
        self.globals["wdLigaturesNone".lower()] = 0
        self.vb_constants.add("wdLigaturesNone".lower())
        # Applies standard ligatures to the font. Standard ligatures are designed to enhance readability. Standard ligatures in Latin languages include "fi", "fl", and "ff", for example.
        self.globals["wdLigaturesStandard".lower()] = 1
        self.vb_constants.add("wdLigaturesStandard".lower())
        # Applies standard and contextual ligatures to the font.
        self.globals["wdLigaturesStandardContextual".lower()] = 3
        self.vb_constants.add("wdLigaturesStandardContextual".lower())
        # Applies standard, contextual and discretional ligatures to the font.
        self.globals["wdLigaturesStandardContextualDiscretional".lower()] = 11
        self.vb_constants.add("wdLigaturesStandardContextualDiscretional".lower())
        # Applies standard, contextual, and historical ligatures to the font.
        self.globals["wdLigaturesStandardContextualHistorical".lower()] = 7
        self.vb_constants.add("wdLigaturesStandardContextualHistorical".lower())
        # Applies standard and discretional ligatures to the font.
        self.globals["wdLigaturesStandardDiscretional".lower()] = 9
        self.vb_constants.add("wdLigaturesStandardDiscretional".lower())
        # Applies standard and historical ligatures to the font.
        self.globals["wdLigaturesStandardHistorical".lower()] = 5
        self.vb_constants.add("wdLigaturesStandardHistorical".lower())
        # Applies standard historical and discretional ligatures to the font.
        self.globals["wdLigaturesStandardHistoricalDiscretional".lower()] = 13
        self.vb_constants.add("wdLigaturesStandardHistoricalDiscretional".lower())
        
        # WdListType enumeration (Word)
        #   
        # Specifies a type of list.
        
        # Bulleted list.
        self.globals["wdListBullet".lower()] = 2
        self.vb_constants.add("wdListBullet".lower())
        # ListNum fields that can be used in the body of a paragraph.
        self.globals["wdListListNumOnly".lower()] = 1
        self.vb_constants.add("wdListListNumOnly".lower())
        # Mixed numeric list.
        self.globals["wdListMixedNumbering".lower()] = 5
        self.vb_constants.add("wdListMixedNumbering".lower())
        # List with no bullets, numbering, or outlining.
        self.globals["wdListNoNumbering".lower()] = 0
        self.vb_constants.add("wdListNoNumbering".lower())
        # Outlined list.
        self.globals["wdListOutlineNumbering".lower()] = 4
        self.vb_constants.add("wdListOutlineNumbering".lower())
        # Picture bulleted list.
        self.globals["wdListPictureBullet".lower()] = 6
        self.vb_constants.add("wdListPictureBullet".lower())
        # Simple numeric list.
        self.globals["wdListSimpleNumbering".lower()] = 3
        self.vb_constants.add("wdListSimpleNumbering".lower())
        
        # WdTemplateType enumeration (Word)
        #   
        # Specifies the type of template.
        
        # An attached template.
        self.globals["wdAttachedTemplate".lower()] = 2
        self.vb_constants.add("wdAttachedTemplate".lower())
        # A global template.
        self.globals["wdGlobalTemplate".lower()] = 1
        self.vb_constants.add("wdGlobalTemplate".lower())
        # The normal default template.
        self.globals["wdNormalTemplate".lower()] = 0
        self.vb_constants.add("wdNormalTemplate".lower())
        
        # WdViewType enumeration (Word)
        #   
        # Specifies the view type.
        
        # A master view.
        self.globals["wdMasterView".lower()] = 5
        self.vb_constants.add("wdMasterView".lower())
        # A normal view.
        self.globals["wdNormalView".lower()] = 1
        self.vb_constants.add("wdNormalView".lower())
        # An outline view.
        self.globals["wdOutlineView".lower()] = 2
        self.vb_constants.add("wdOutlineView".lower())
        # A print preview view.
        self.globals["wdPrintPreview".lower()] = 4
        self.vb_constants.add("wdPrintPreview".lower())
        # A print view.
        self.globals["wdPrintView".lower()] = 3
        self.vb_constants.add("wdPrintView".lower())
        # A reading view.
        self.globals["wdReadingView".lower()] = 7
        self.vb_constants.add("wdReadingView".lower())
        # A Web view.
        self.globals["wdWebView".lower()] = 6
        self.vb_constants.add("wdWebView".lower())
        
        # WdNumberForm enumeration (Word)
        #
        # Specifies the number form setting for an OpenType font.
        
        # Applies the default number form for the font.
        self.globals["wdNumberFormDefault".lower()] = 0
        self.vb_constants.add("wdNumberFormDefault".lower())
        # Applies the lining number form to the font.
        self.globals["wdNumberFormLining".lower()] = 1
        self.vb_constants.add("wdNumberFormLining".lower())
        # Applies the "old-style" number form to the font.
        self.globals["wdNumberFormOldstyle".lower()] = 2
        self.vb_constants.add("wdNumberFormOldstyle".lower())
        
        # WdOMathFunctionType enumeration (Word)
        #   
        # Specifies the type of equation function.
        
        # Equation accent mark.
        self.globals["wdOMathFunctionAcc".lower()] = 1
        self.vb_constants.add("wdOMathFunctionAcc".lower())
        # Equation fraction bar.
        self.globals["wdOMathFunctionBar".lower()] = 2
        self.vb_constants.add("wdOMathFunctionBar".lower())
        # Border box.
        self.globals["wdOMathFunctionBorderBox".lower()] = 4
        self.vb_constants.add("wdOMathFunctionBorderBox".lower())
        # Box.
        self.globals["wdOMathFunctionBox".lower()] = 3
        self.vb_constants.add("wdOMathFunctionBox".lower())
        # Equation delimiters.
        self.globals["wdOMathFunctionDelim".lower()] = 5
        self.vb_constants.add("wdOMathFunctionDelim".lower())
        # Equation array.
        self.globals["wdOMathFunctionEqArray".lower()] = 6
        self.vb_constants.add("wdOMathFunctionEqArray".lower())
        # Equation fraction.
        self.globals["wdOMathFunctionFrac".lower()] = 7
        self.vb_constants.add("wdOMathFunctionFrac".lower())
        # Equation function.
        self.globals["wdOMathFunctionFunc".lower()] = 8
        self.vb_constants.add("wdOMathFunctionFunc".lower())
        # Group character.
        self.globals["wdOMathFunctionGroupChar".lower()] = 9
        self.vb_constants.add("wdOMathFunctionGroupChar".lower())
        # Equation lower limit.
        self.globals["wdOMathFunctionLimLow".lower()] = 10
        self.vb_constants.add("wdOMathFunctionLimLow".lower())
        # Equation upper limit.
        self.globals["wdOMathFunctionLimUpp".lower()] = 11
        self.vb_constants.add("wdOMathFunctionLimUpp".lower())
        # Equation matrix.
        self.globals["wdOMathFunctionMat".lower()] = 12
        self.vb_constants.add("wdOMathFunctionMat".lower())
        # Equation N-ary operator.
        self.globals["wdOMathFunctionNary".lower()] = 13
        self.vb_constants.add("wdOMathFunctionNary".lower())
        # Equation normal text.
        self.globals["wdOMathFunctionNormalText".lower()] = 21
        self.vb_constants.add("wdOMathFunctionNormalText".lower())
        # Equation phantom.
        self.globals["wdOMathFunctionPhantom".lower()] = 14
        self.vb_constants.add("wdOMathFunctionPhantom".lower())
        # Equation base expression.
        self.globals["wdOMathFunctionRad".lower()] = 16
        self.vb_constants.add("wdOMathFunctionRad".lower())
        # Scr pre.
        self.globals["wdOMathFunctionScrPre".lower()] = 15
        self.vb_constants.add("wdOMathFunctionScrPre".lower())
        # Scr. sub.
        self.globals["wdOMathFunctionScrSub".lower()] = 17
        self.vb_constants.add("wdOMathFunctionScrSub".lower())
        # Scr. sub sup.
        self.globals["wdOMathFunctionScrSubSup".lower()] = 18
        self.vb_constants.add("wdOMathFunctionScrSubSup".lower())
        # Scr sup.
        self.globals["wdOMathFunctionScrSup".lower()] = 19
        self.vb_constants.add("wdOMathFunctionScrSup".lower())
        # Equation text.
        self.globals["wdOMathFunctionText".lower()] = 20
        self.vb_constants.add("wdOMathFunctionText".lower())
        
        # WdOMathHorizAlignType enumeration (Word)
        #   
        # Specifies the horizontal alignment for an equation.
        
        # Centered.
        self.globals["wdOMathHorizAlignCenter".lower()] = 0
        self.vb_constants.add("wdOMathHorizAlignCenter".lower())
        # Left alignment.
        self.globals["wdOMathHorizAlignLeft".lower()] = 1
        self.vb_constants.add("wdOMathHorizAlignLeft".lower())
        # Right alignment.
        self.globals["wdOMathHorizAlignRight".lower()] = 2
        self.vb_constants.add("wdOMathHorizAlignRight".lower())
        
        # WdOpenFormat enumeration (Word)
        #   
        # Specifies the format to use when opening a document.
        
        # A Microsoft Word format that is backward compatible with earlier versions of Word.
        self.globals["wdOpenFormatAllWord".lower()] = 6
        self.vb_constants.add("wdOpenFormatAllWord".lower())
        # The existing format.
        self.globals["wdOpenFormatAuto".lower()] = 0
        self.vb_constants.add("wdOpenFormatAuto".lower())
        # Word format.
        self.globals["wdOpenFormatDocument".lower()] = 1
        self.vb_constants.add("wdOpenFormatDocument".lower())
        # Encoded text format.
        self.globals["wdOpenFormatEncodedText".lower()] = 5
        self.vb_constants.add("wdOpenFormatEncodedText".lower())
        # Rich text format (RTF).
        self.globals["wdOpenFormatRTF".lower()] = 3
        self.vb_constants.add("wdOpenFormatRTF".lower())
        # As a Word template.
        self.globals["wdOpenFormatTemplate".lower()] = 2
        self.vb_constants.add("wdOpenFormatTemplate".lower())
        # Unencoded text format.
        self.globals["wdOpenFormatText".lower()] = 4
        self.vb_constants.add("wdOpenFormatText".lower())
        # (&H12)	OpenDocument Text format.
        self.globals["wdOpenFormatOpenDocumentText".lower()] = 18
        self.vb_constants.add("wdOpenFormatOpenDocumentText".lower())
        # Unicode text format.
        self.globals["wdOpenFormatUnicodeText".lower()] = 5
        self.vb_constants.add("wdOpenFormatUnicodeText".lower())
        # HTML format.
        self.globals["wdOpenFormatWebPages".lower()] = 7
        self.vb_constants.add("wdOpenFormatWebPages".lower())
        # XML format.
        self.globals["wdOpenFormatXML".lower()] = 8
        self.vb_constants.add("wdOpenFormatXML".lower())
        # Word template format.
        self.globals["wdOpenFormatAllWordTemplates".lower()] = 13
        self.vb_constants.add("wdOpenFormatAllWordTemplates".lower())
        # Microsoft Word 97 document format.
        self.globals["wdOpenFormatDocument97".lower()] = 1
        self.vb_constants.add("wdOpenFormatDocument97".lower())
        # Word 97 template format.
        self.globals["wdOpenFormatTemplate97".lower()] = 2
        self.vb_constants.add("wdOpenFormatTemplate97".lower())
        # XML document format.
        self.globals["wdOpenFormatXMLDocument".lower()] = 9
        self.vb_constants.add("wdOpenFormatXMLDocument".lower())
        # Open XML file format saved as a single XML file.
        self.globals["wdOpenFormatXMLDocumentSerialized".lower()] = 14
        self.vb_constants.add("wdOpenFormatXMLDocumentSerialized".lower())
        # XML document format with macros enabled.
        self.globals["wdOpenFormatXMLDocumentMacroEnabled".lower()] = 10
        self.vb_constants.add("wdOpenFormatXMLDocumentMacroEnabled".lower())
        # Open XML file format with macros enabled saved as a single XML file.
        self.globals["wdOpenFormatXMLDocumentMacroEnabledSerialized".lower()] = 15
        self.vb_constants.add("wdOpenFormatXMLDocumentMacroEnabledSerialized".lower())
        # XML template format.
        self.globals["wdOpenFormatXMLTemplate".lower()] = 11
        self.vb_constants.add("wdOpenFormatXMLTemplate".lower())
        # (&H10)	Open XML template format saved as a XML single file.
        self.globals["wdOpenFormatXMLTemplateSerialized".lower()] = 16
        self.vb_constants.add("wdOpenFormatXMLTemplateSerialized".lower())
        # XML template format with macros enabled.
        self.globals["wdOpenFormatXMLTemplateMacroEnabled".lower()] = 12
        self.vb_constants.add("wdOpenFormatXMLTemplateMacroEnabled".lower())
        # (&H11)	Open XML template format with macros enabled saved as a single XML file.
        self.globals["wdOpenFormatXMLTemplateMacroEnabledSerialized".lower()] = 17
        self.vb_constants.add("wdOpenFormatXMLTemplateMacroEnabledSerialized".lower())
        
        # WdPaperSize enumeration (Word)
        #   
        # Specifies a paper size.
        
        # 10 inches wide, 14 inches long.
        self.globals["wdPaper10x14".lower()] = 0
        self.vb_constants.add("wdPaper10x14".lower())
        # Legal 11 inches wide, 17 inches long.
        self.globals["wdPaper11x17".lower()] = 1
        self.vb_constants.add("wdPaper11x17".lower())
        # A3 dimensions.
        self.globals["wdPaperA3".lower()] = 6
        self.vb_constants.add("wdPaperA3".lower())
        # A4 dimensions.
        self.globals["wdPaperA4".lower()] = 7
        self.vb_constants.add("wdPaperA4".lower())
        # Small A4 dimensions.
        self.globals["wdPaperA4Small".lower()] = 8
        self.vb_constants.add("wdPaperA4Small".lower())
        # A5 dimensions.
        self.globals["wdPaperA5".lower()] = 9
        self.vb_constants.add("wdPaperA5".lower())
        # B4 dimensions.
        self.globals["wdPaperB4".lower()] = 10
        self.vb_constants.add("wdPaperB4".lower())
        # B5 dimensions.
        self.globals["wdPaperB5".lower()] = 11
        self.vb_constants.add("wdPaperB5".lower())
        # C sheet dimensions.
        self.globals["wdPaperCSheet".lower()] = 12
        self.vb_constants.add("wdPaperCSheet".lower())
        # Custom paper size.
        self.globals["wdPaperCustom".lower()] = 41
        self.vb_constants.add("wdPaperCustom".lower())
        # D sheet dimensions.
        self.globals["wdPaperDSheet".lower()] = 13
        self.vb_constants.add("wdPaperDSheet".lower())
        # Legal envelope, size 10.
        self.globals["wdPaperEnvelope10".lower()] = 25
        self.vb_constants.add("wdPaperEnvelope10".lower())
        # Envelope, size 11.
        self.globals["wdPaperEnvelope11".lower()] = 26
        self.vb_constants.add("wdPaperEnvelope11".lower())
        # Envelope, size 12.
        self.globals["wdPaperEnvelope12".lower()] = 27
        self.vb_constants.add("wdPaperEnvelope12".lower())
        # Envelope, size 14.
        self.globals["wdPaperEnvelope14".lower()] = 28
        self.vb_constants.add("wdPaperEnvelope14".lower())
        # Envelope, size 9.
        self.globals["wdPaperEnvelope9".lower()] = 24
        self.vb_constants.add("wdPaperEnvelope9".lower())
        # B4 envelope.
        self.globals["wdPaperEnvelopeB4".lower()] = 29
        self.vb_constants.add("wdPaperEnvelopeB4".lower())
        # B5 envelope.
        self.globals["wdPaperEnvelopeB5".lower()] = 30
        self.vb_constants.add("wdPaperEnvelopeB5".lower())
        # B6 envelope.
        self.globals["wdPaperEnvelopeB6".lower()] = 31
        self.vb_constants.add("wdPaperEnvelopeB6".lower())
        # C3 envelope.
        self.globals["wdPaperEnvelopeC3".lower()] = 32
        self.vb_constants.add("wdPaperEnvelopeC3".lower())
        # C4 envelope.
        self.globals["wdPaperEnvelopeC4".lower()] = 33
        self.vb_constants.add("wdPaperEnvelopeC4".lower())
        # C5 envelope.
        self.globals["wdPaperEnvelopeC5".lower()] = 34
        self.vb_constants.add("wdPaperEnvelopeC5".lower())
        # C6 envelope.
        self.globals["wdPaperEnvelopeC6".lower()] = 35
        self.vb_constants.add("wdPaperEnvelopeC6".lower())
        # C65 envelope.
        self.globals["wdPaperEnvelopeC65".lower()] = 36
        self.vb_constants.add("wdPaperEnvelopeC65".lower())
        # DL envelope.
        self.globals["wdPaperEnvelopeDL".lower()] = 37
        self.vb_constants.add("wdPaperEnvelopeDL".lower())
        # Italian envelope.
        self.globals["wdPaperEnvelopeItaly".lower()] = 38
        self.vb_constants.add("wdPaperEnvelopeItaly".lower())
        # Monarch envelope.
        self.globals["wdPaperEnvelopeMonarch".lower()] = 39
        self.vb_constants.add("wdPaperEnvelopeMonarch".lower())
        # Personal envelope.
        self.globals["wdPaperEnvelopePersonal".lower()] = 40
        self.vb_constants.add("wdPaperEnvelopePersonal".lower())
        # E sheet dimensions.
        self.globals["wdPaperESheet".lower()] = 14
        self.vb_constants.add("wdPaperESheet".lower())
        # Executive dimensions.
        self.globals["wdPaperExecutive".lower()] = 5
        self.vb_constants.add("wdPaperExecutive".lower())
        # German legal fanfold dimensions.
        self.globals["wdPaperFanfoldLegalGerman".lower()] = 15
        self.vb_constants.add("wdPaperFanfoldLegalGerman".lower())
        # German standard fanfold dimensions.
        self.globals["wdPaperFanfoldStdGerman".lower()] = 16
        self.vb_constants.add("wdPaperFanfoldStdGerman".lower())
        # United States fanfold dimensions.
        self.globals["wdPaperFanfoldUS".lower()] = 17
        self.vb_constants.add("wdPaperFanfoldUS".lower())
        # Folio dimensions.
        self.globals["wdPaperFolio".lower()] = 18
        self.vb_constants.add("wdPaperFolio".lower())
        # Ledger dimensions.
        self.globals["wdPaperLedger".lower()] = 19
        self.vb_constants.add("wdPaperLedger".lower())
        # Legal dimensions.
        self.globals["wdPaperLegal".lower()] = 4
        self.vb_constants.add("wdPaperLegal".lower())
        # Letter dimensions.
        self.globals["wdPaperLetter".lower()] = 2
        self.vb_constants.add("wdPaperLetter".lower())
        # Small letter dimensions.
        self.globals["wdPaperLetterSmall".lower()] = 3
        self.vb_constants.add("wdPaperLetterSmall".lower())
        # Note dimensions.
        self.globals["wdPaperNote".lower()] = 20
        self.vb_constants.add("wdPaperNote".lower())
        # Quarto dimensions.
        self.globals["wdPaperQuarto".lower()] = 21
        self.vb_constants.add("wdPaperQuarto".lower())
        # Statement dimensions.
        self.globals["wdPaperStatement".lower()] = 22
        self.vb_constants.add("wdPaperStatement".lower())
        # Tabloid dimensions.
        self.globals["wdPaperTabloid".lower()] = 23
        self.vb_constants.add("wdPaperTabloid".lower())
        
        # WdRevisionType enumeration (Word)
        #   
        # Specifies the type of a change that is marked with a revision mark.
        
        # No revision.
        self.globals["wdNoRevision".lower()] = 0
        self.vb_constants.add("wdNoRevision".lower())
        # Table cell deleted.
        self.globals["wdRevisionCellDeletion".lower()] = 17
        self.vb_constants.add("wdRevisionCellDeletion".lower())
        # Table cell inserted.
        self.globals["wdRevisionCellInsertion".lower()] = 16
        self.vb_constants.add("wdRevisionCellInsertion".lower())
        # Table cells merged.
        self.globals["wdRevisionCellMerge".lower()] = 18
        self.vb_constants.add("wdRevisionCellMerge".lower())
        # This object, member, or enumeration is deprecated and is not intended to be used in your code.
        self.globals["wdRevisionCellSplit".lower()] = 19
        self.vb_constants.add("wdRevisionCellSplit".lower())
        # Revision marked as a conflict.
        self.globals["wdRevisionConflict".lower()] = 7
        self.vb_constants.add("wdRevisionConflict".lower())
        # Deletion revision conflict in a coauthored document.
        self.globals["wdRevisionConflictDelete".lower()] = 21
        self.vb_constants.add("wdRevisionConflictDelete".lower())
        # Insertion revision conflict in a coauthored document
        self.globals["wdRevisionConflictInsert".lower()] = 20
        self.vb_constants.add("wdRevisionConflictInsert".lower())
        # Deletion.
        self.globals["wdRevisionDelete".lower()] = 2
        self.vb_constants.add("wdRevisionDelete".lower())
        # Field display changed.
        self.globals["wdRevisionDisplayField".lower()] = 5
        self.vb_constants.add("wdRevisionDisplayField".lower())
        # Insertion.
        self.globals["wdRevisionInsert".lower()] = 1
        self.vb_constants.add("wdRevisionInsert".lower())
        # Content moved from.
        self.globals["wdRevisionMovedFrom".lower()] = 14
        self.vb_constants.add("wdRevisionMovedFrom".lower())
        # Content moved to.
        self.globals["wdRevisionMovedTo".lower()] = 15
        self.vb_constants.add("wdRevisionMovedTo".lower())
        # Paragraph number changed.
        self.globals["wdRevisionParagraphNumber".lower()] = 4
        self.vb_constants.add("wdRevisionParagraphNumber".lower())
        # Paragraph property changed.
        self.globals["wdRevisionParagraphProperty".lower()] = 10
        self.vb_constants.add("wdRevisionParagraphProperty".lower())
        # Property changed.
        self.globals["wdRevisionProperty".lower()] = 3
        self.vb_constants.add("wdRevisionProperty".lower())
        # Revision marked as reconciled conflict.
        self.globals["wdRevisionReconcile".lower()] = 6
        self.vb_constants.add("wdRevisionReconcile".lower())
        # Replaced.
        self.globals["wdRevisionReplace".lower()] = 9
        self.vb_constants.add("wdRevisionReplace".lower())
        # Section property changed.
        self.globals["wdRevisionSectionProperty".lower()] = 12
        self.vb_constants.add("wdRevisionSectionProperty".lower())
        # Style changed.
        self.globals["wdRevisionStyle".lower()] = 8
        self.vb_constants.add("wdRevisionStyle".lower())
        # Style definition changed.
        self.globals["wdRevisionStyleDefinition".lower()] = 13
        self.vb_constants.add("wdRevisionStyleDefinition".lower())
        # Table property changed.
        self.globals["wdRevisionTableProperty".lower()] = 11
        self.vb_constants.add("wdRevisionTableProperty".lower())
        
        # WdBreakType enumeration (Word)
        #   
        # Specifies type of break.
        
        # Column break at the insertion point.
        self.globals["wdColumnBreak".lower()] = 8
        self.vb_constants.add("wdColumnBreak".lower())
        # Line break.
        self.globals["wdLineBreak".lower()] = 6
        self.vb_constants.add("wdLineBreak".lower())
        # Line break.
        self.globals["wdLineBreakClearLeft".lower()] = 9
        self.vb_constants.add("wdLineBreakClearLeft".lower())
        # Line break.
        self.globals["wdLineBreakClearRight".lower()] = 10
        self.vb_constants.add("wdLineBreakClearRight".lower())
        # Page break at the insertion point.
        self.globals["wdPageBreak".lower()] = 7
        self.vb_constants.add("wdPageBreak".lower())
        # New section without a corresponding page break.
        self.globals["wdSectionBreakContinuous".lower()] = 3
        self.vb_constants.add("wdSectionBreakContinuous".lower())
        # Section break with the next section beginning on the next even-numbered page. If the section break falls on an even-numbered page, Word leaves the next odd-numbered page blank.
        self.globals["wdSectionBreakEvenPage".lower()] = 4
        self.vb_constants.add("wdSectionBreakEvenPage".lower())
        # Section break on next page.
        self.globals["wdSectionBreakNextPage".lower()] = 2
        self.vb_constants.add("wdSectionBreakNextPage".lower())
        # Section break with the next section beginning on the next odd-numbered page. If the section break falls on an odd-numbered page, Word leaves the next even-numbered page blank.
        self.globals["wdSectionBreakOddPage".lower()] = 5
        self.vb_constants.add("wdSectionBreakOddPage".lower())
        # Ends the current line and forces the text to continue below a picture, table, or other item. The text continues on the next blank line that does not contain a table aligned with the left or right margin.
        self.globals["wdTextWrappingBreak".lower()] = 11
        self.vb_constants.add("wdTextWrappingBreak".lower())
        
        # WdDocumentType enumeration
        #   
        # Specifies a document type.
        
        # Document.
        self.globals["wdTypeDocument".lower()] = 0
        self.vb_constants.add("wdTypeDocument".lower())
        # Frameset.
        self.globals["wdTypeFrameset".lower()] = 2
        self.vb_constants.add("wdTypeFrameset".lower())
        # Template.
        self.globals["wdTypeTemplate".lower()] = 1
        self.vb_constants.add("wdTypeTemplate".lower())
        
        # WdWrapSideType enumeration (Word)
        #
        # Specifies whether the document text should wrap on both sides of the specified shape, on either the left or right side only, or on the side of the shape that is farthest from the page margin.
        
        # Both sides of the specified shape.
        self.globals["wdWrapBoth".lower()] = 0
        self.vb_constants.add("wdWrapBoth".lower())
        # Side of the shape that is farthest from the page margin.
        self.globals["wdWrapLargest".lower()] = 3
        self.vb_constants.add("wdWrapLargest".lower())
        # Left side of shape only.
        self.globals["wdWrapLeft".lower()] = 1
        self.vb_constants.add("wdWrapLeft".lower())
        # Right side of shape only.
        self.globals["wdWrapRight".lower()] = 2
        self.vb_constants.add("wdWrapRight".lower())
        
        # WdRecoveryType enumeration (Word)
        #
        # Specifies the formatting to use when pasting the selected table cells.
        
        # Pastes a Microsoft Office Excel chart as an embedded OLE object.
        self.globals["wdChart".lower()] = 14
        self.vb_constants.add("wdChart".lower())
        # Pastes an Excel chart and links it to the original Excel spreadsheet.
        self.globals["wdChartLinked".lower()] = 15
        self.vb_constants.add("wdChartLinked".lower())
        # Pastes an Excel chart as a picture.
        self.globals["wdChartPicture".lower()] = 13
        self.vb_constants.add("wdChartPicture".lower())
        # Preserves original formatting of the pasted material.
        self.globals["wdFormatOriginalFormatting".lower()] = 16
        self.vb_constants.add("wdFormatOriginalFormatting".lower())
        # Pastes as plain, unformatted text.
        self.globals["wdFormatPlainText".lower()] = 22
        self.vb_constants.add("wdFormatPlainText".lower())
        # Matches the formatting of the pasted text to the formatting of surrounding text.
        self.globals["wdFormatSurroundingFormattingWithEmphasis".lower()] = 20
        self.vb_constants.add("wdFormatSurroundingFormattingWithEmphasis".lower())
        # Merges a pasted list with neighboring lists.
        self.globals["wdListCombineWithExistingList".lower()] = 24
        self.vb_constants.add("wdListCombineWithExistingList".lower())
        # Continues numbering of a pasted list from the list in the document.
        self.globals["wdListContinueNumbering".lower()] = 7
        self.vb_constants.add("wdListContinueNumbering".lower())
        # Not supported.
        self.globals["wdListDontMerge".lower()] = 25
        self.vb_constants.add("wdListDontMerge".lower())
        # Restarts numbering of a pasted list.
        self.globals["wdListRestartNumbering".lower()] = 8
        self.vb_constants.add("wdListRestartNumbering".lower())
        # Not supported.
        self.globals["wdPasteDefault".lower()] = 0
        self.vb_constants.add("wdPasteDefault".lower())
        # Pastes a single cell table as a separate table.
        self.globals["wdSingleCellTable".lower()] = 6
        self.vb_constants.add("wdSingleCellTable".lower())
        # Pastes a single cell as text.
        self.globals["wdSingleCellText".lower()] = 5
        self.vb_constants.add("wdSingleCellText".lower())
        # Merges pasted cells into an existing table by inserting the pasted rows between the selected rows.
        self.globals["wdTableAppendTable".lower()] = 10
        self.vb_constants.add("wdTableAppendTable".lower())
        # Inserts a pasted table as rows between two rows in the target table.
        self.globals["wdTableInsertAsRows".lower()] = 11
        self.vb_constants.add("wdTableInsertAsRows".lower())
        # Pastes an appended table without merging table styles.
        self.globals["wdTableOriginalFormatting".lower()] = 12
        self.vb_constants.add("wdTableOriginalFormatting".lower())
        # Pastes table cells and overwrites existing table cells.
        self.globals["wdTableOverwriteCells".lower()] = 23
        self.vb_constants.add("wdTableOverwriteCells".lower())
        # Uses the styles that are in use in the destination document.
        self.globals["wdUseDestinationStylesRecovery".lower()] = 19
        self.vb_constants.add("wdUseDestinationStylesRecovery".lower())
        
        # Excel error codes.
        self.globals["xlErrDiv0".lower()] = 2007  #DIV/0!
        self.vb_constants.add("xlErrDiv0".lower())
        self.globals["xlErrNA".lower()] = 2042    #N/A
        self.vb_constants.add("xlErrNA".lower())
        self.globals["xlErrName".lower()] = 2029  #NAME?
        self.vb_constants.add("xlErrName".lower())
        self.globals["xlErrNull".lower()] = 2000  #NULL!
        self.vb_constants.add("xlErrNull".lower())
        self.globals["xlErrNum".lower()] = 2036   #NUM!
        self.vb_constants.add("xlErrNum".lower())
        self.globals["xlErrRef".lower()] = 2023   #REF!
        self.vb_constants.add("xlErrRef".lower())
        self.globals["xlErrValue".lower()] = 2015 #VALUE!
        self.vb_constants.add("xlErrValue".lower())

        # System info.
        self.globals["System.OperatingSystem".lower()] = "Windows NT"
        self.vb_constants.add("System.OperatingSystem".lower())
        self.globals[".DNSHostName".lower()] = "acomputer.acompany.com"
        self.vb_constants.add("".lower())
        self.globals[".Domain".lower()] = "acompany.com"
        self.vb_constants.add(".Domain".lower())
        self.globals["wscript.network.UserName".lower()] = "humungulous"
        self.vb_constants.add("wscript.network.UserName".lower())

        # WdCaptionNumberStyle enumeration (Word)
        #    
        # Specifies the number style to be used with the CaptionLabel object.
        
        #  Arabic style.
        self.globals["wdCaptionNumberStyleArabic".lower()] = 0
        self.vb_constants.add("wdCaptionNumberStyleArabic".lower())
        #  Full-width Arabic style.
        self.globals["wdCaptionNumberStyleArabicFullWidth".lower()] = 14
        self.vb_constants.add("wdCaptionNumberStyleArabicFullWidth".lower())
        #  Arabic letter style 1.
        self.globals["wdCaptionNumberStyleArabicLetter1".lower()] = 46
        self.vb_constants.add("wdCaptionNumberStyleArabicLetter1".lower())
        #  Arabic letter style 2.
        self.globals["wdCaptionNumberStyleArabicLetter2".lower()] = 48
        self.vb_constants.add("wdCaptionNumberStyleArabicLetter2".lower())
        #  Chosung style.
        self.globals["wdCaptionNumberStyleChosung".lower()] = 25
        self.vb_constants.add("wdCaptionNumberStyleChosung".lower())
        #  Ganada style.
        self.globals["wdCaptionNumberStyleGanada".lower()] = 24
        self.vb_constants.add("wdCaptionNumberStyleGanada".lower())
        #  Hanja read style.
        self.globals["wdCaptionNumberStyleHanjaRead".lower()] = 41
        self.vb_constants.add("wdCaptionNumberStyleHanjaRead".lower())
        #  Hanja read digit style.
        self.globals["wdCaptionNumberStyleHanjaReadDigit".lower()] = 42
        self.vb_constants.add("wdCaptionNumberStyleHanjaReadDigit".lower())
        #  Hebrew letter style 1.
        self.globals["wdCaptionNumberStyleHebrewLetter1".lower()] = 45
        self.vb_constants.add("wdCaptionNumberStyleHebrewLetter1".lower())
        #  Hebrew letter style 2.
        self.globals["wdCaptionNumberStyleHebrewLetter2".lower()] = 47
        self.vb_constants.add("wdCaptionNumberStyleHebrewLetter2".lower())
        #  Hindi Arabic style.
        self.globals["wdCaptionNumberStyleHindiArabic".lower()] = 51
        self.vb_constants.add("wdCaptionNumberStyleHindiArabic".lower())
        #  Hindi cardinal style.
        self.globals["wdCaptionNumberStyleHindiCardinalText".lower()] = 52
        self.vb_constants.add("wdCaptionNumberStyleHindiCardinalText".lower())
        #  Hindi letter style 1.
        self.globals["wdCaptionNumberStyleHindiLetter1".lower()] = 49
        self.vb_constants.add("wdCaptionNumberStyleHindiLetter1".lower())
        #  Hindi letter style 2.
        self.globals["wdCaptionNumberStyleHindiLetter2".lower()] = 50
        self.vb_constants.add("wdCaptionNumberStyleHindiLetter2".lower())
        #  Kanji style.
        self.globals["wdCaptionNumberStyleKanji".lower()] = 10
        self.vb_constants.add("wdCaptionNumberStyleKanji".lower())
        #  Kanji digit style.
        self.globals["wdCaptionNumberStyleKanjiDigit".lower()] = 11
        self.vb_constants.add("wdCaptionNumberStyleKanjiDigit".lower())
        #  Kanji traditional style.
        self.globals["wdCaptionNumberStyleKanjiTraditional".lower()] = 16
        self.vb_constants.add("wdCaptionNumberStyleKanjiTraditional".lower())
        #  Lowercase letter style.
        self.globals["wdCaptionNumberStyleLowercaseLetter".lower()] = 4
        self.vb_constants.add("wdCaptionNumberStyleLowercaseLetter".lower())
        #  Lowercase roman style.
        self.globals["wdCaptionNumberStyleLowercaseRoman".lower()] = 2
        self.vb_constants.add("wdCaptionNumberStyleLowercaseRoman".lower())
        #  Number in circle style.
        self.globals["wdCaptionNumberStyleNumberInCircle".lower()] = 18
        self.vb_constants.add("wdCaptionNumberStyleNumberInCircle".lower())
        #  Simplified Chinese number style 2.
        self.globals["wdCaptionNumberStyleSimpChinNum2".lower()] = 38
        self.vb_constants.add("wdCaptionNumberStyleSimpChinNum2".lower())
        #  Simplified Chinese number style 3.
        self.globals["wdCaptionNumberStyleSimpChinNum3".lower()] = 39
        self.vb_constants.add("wdCaptionNumberStyleSimpChinNum3".lower())
        #  Thai Arabic style.
        self.globals["wdCaptionNumberStyleThaiArabic".lower()] = 54
        self.vb_constants.add("wdCaptionNumberStyleThaiArabic".lower())
        #  Thai cardinal text style.
        self.globals["wdCaptionNumberStyleThaiCardinalText".lower()] = 55
        self.vb_constants.add("wdCaptionNumberStyleThaiCardinalText".lower())
        #  Thai letter style.
        self.globals["wdCaptionNumberStyleThaiLetter".lower()] = 53
        self.vb_constants.add("wdCaptionNumberStyleThaiLetter".lower())
        #  Traditional Chinese number style 2.
        self.globals["wdCaptionNumberStyleTradChinNum2".lower()] = 34
        self.vb_constants.add("wdCaptionNumberStyleTradChinNum2".lower())
        #  Traditional Chinese number style 3.
        self.globals["wdCaptionNumberStyleTradChinNum3".lower()] = 35
        self.vb_constants.add("wdCaptionNumberStyleTradChinNum3".lower())
        #  Uppercase letter style.
        self.globals["wdCaptionNumberStyleUppercaseLetter".lower()] = 3
        self.vb_constants.add("wdCaptionNumberStyleUppercaseLetter".lower())
        #  Uppercase roman style.
        self.globals["wdCaptionNumberStyleUppercaseRoman".lower()] = 1
        self.vb_constants.add("wdCaptionNumberStyleUppercaseRoman".lower())
        #  Vietnamese cardinal text style.
        self.globals["wdCaptionNumberStyleVietCardinalText".lower()] = 56
        self.vb_constants.add("wdCaptionNumberStyleVietCardinalText".lower())
        #  Zodiac style 1.
        self.globals["wdCaptionNumberStyleZodiac1".lower()] = 30
        self.vb_constants.add("wdCaptionNumberStyleZodiac1".lower())
        #  Zodiac style 2.
        self.globals["wdCaptionNumberStyleZodiac2".lower()] = 31
        self.vb_constants.add("wdCaptionNumberStyleZodiac2".lower())
        
        # WdPartOfSpeech enumeration (Word)
        #   
        # Specifies the part of speech that a word represents when returned by the Word thesaurus service.
        
        #  An adjective.
        self.globals["wdAdjective".lower()] = 0
        self.vb_constants.add("wdAdjective".lower())
        #  An adverb.
        self.globals["wdAdverb".lower()] = 2
        self.vb_constants.add("wdAdverb".lower())
        #  A conjunction.
        self.globals["wdConjunction".lower()] = 5
        self.vb_constants.add("wdConjunction".lower())
        #  An idiom.
        self.globals["wdIdiom".lower()] = 8
        self.vb_constants.add("wdIdiom".lower())
        #  An interjection.
        self.globals["wdInterjection".lower()] = 7
        self.vb_constants.add("wdInterjection".lower())
        #  A noun.
        self.globals["wdNoun".lower()] = 1
        self.vb_constants.add("wdNoun".lower())
        #  Some other part of speech.
        self.globals["wdOther".lower()] = 9
        self.vb_constants.add("wdOther".lower())
        #  A preposition.
        self.globals["wdPreposition".lower()] = 6
        self.vb_constants.add("wdPreposition".lower())
        #  A pronoun.
        self.globals["wdPronoun".lower()] = 4
        self.vb_constants.add("wdPronoun".lower())
        #  A verb.
        self.globals["wdVerb".lower()] = 3
        self.vb_constants.add("wdVerb".lower())
        
        # WdCursorType enumeration (Word)
        #   
        # Specifies the state (shape) of the cursor.
        
        #  I-beam cursor shape.
        self.globals["wdCursorIBeam".lower()] = 1
        self.vb_constants.add("wdCursorIBeam".lower())
        #  Normal cursor shape. Default; cursor takes shape designated by Windows or the application.
        self.globals["wdCursorNormal".lower()] = 2
        self.types["wdCursorNormal".lower()] = "Integer"
        self.vb_constants.add("wdCursorNormal".lower())
        #  Diagonal cursor shape starting at upper-left corner.
        self.globals["wdCursorNorthwestArrow".lower()] = 3
        self.vb_constants.add("wdCursorNorthwestArrow".lower())
        #  Hourglass cursor shape.
        self.globals["wdCursorWait".lower()] = 0
        self.vb_constants.add("wdCursorWait".lower())
        
        # WdConstants enumeration (Word)
        #    
        # This enumeration groups together constants used with various Microsoft Word methods.
        
        #  Represents the Auto value for the specified setting.
        self.globals["wdAutoPosition".lower()] = 0
        self.vb_constants.add("wdAutoPosition".lower())
        #  Indicates that selection will be extended backward using the MoveStartUntil or MoveStartWhile method of the Range or Selection object.
        self.globals["wdBackward".lower()] = -1073741823
        self.vb_constants.add("wdBackward".lower())
        #  Represents the creator code for objects created by Microsoft Word.
        self.globals["wdCreatorCode".lower()] = 1297307460
        self.vb_constants.add("wdCreatorCode".lower())
        #  Represents the first item in a collection.
        self.globals["wdFirst".lower()] = 1
        self.vb_constants.add("wdFirst".lower())
        #  Indicates that selection will be extended forward using the MoveStartUntil or MoveStartWhile method of the Range or Selection object.
        self.globals["wdForward".lower()] = 1073741823
        self.vb_constants.add("wdForward".lower())
        #  Toggles a property's value.
        self.globals["wdToggle".lower()] = 9999998
        self.vb_constants.add("wdToggle".lower())
        #  Represents an undefined value.
        self.globals["wdUndefined".lower()] = 9999999
        self.vb_constants.add("wdUndefined".lower())
        
        # WdFramesetNewFrameLocation enumeration (Word)
        #   
        # Specifies the position of a new frame in relation to an existing frame.
        
        #  Above existing frame.
        self.globals["wdFramesetNewFrameAbove".lower()] = 0
        self.vb_constants.add("wdFramesetNewFrameAbove".lower())
        #  Below existing frame.
        self.globals["wdFramesetNewFrameBelow".lower()] = 1
        self.vb_constants.add("wdFramesetNewFrameBelow".lower())
        #  To the left of existing frame.
        self.globals["wdFramesetNewFrameLeft".lower()] = 3
        self.vb_constants.add("wdFramesetNewFrameLeft".lower())
        #  To the right of existing frame.
        self.globals["wdFramesetNewFrameRight".lower()] = 2
        self.vb_constants.add("wdFramesetNewFrameRight".lower())
        
        # WdIndexSortBy enumeration (Word)
        #
        # Specifies the criteria by which Word sorts the specified index.
        
        #  Sort by the number of strokes in a character.
        self.globals["wdIndexSortByStroke".lower()] = 0
        self.vb_constants.add("wdIndexSortByStroke".lower())
        #  Sort phonetically.
        self.globals["wdIndexSortBySyllable".lower()] = 1
        self.vb_constants.add("wdIndexSortBySyllable".lower())
        
        # WdIndexFormat enumeration (Word)
        #   
        # Specifies the formatting for indexes in a document.
        
        #  Bulleted.
        self.globals["wdIndexBulleted".lower()] = 4
        self.vb_constants.add("wdIndexBulleted".lower())
        #  Classic.
        self.globals["wdIndexClassic".lower()] = 1
        self.vb_constants.add("wdIndexClassic".lower())
        #  Fancy.
        self.globals["wdIndexFancy".lower()] = 2
        self.vb_constants.add("wdIndexFancy".lower())
        #  Formal.
        self.globals["wdIndexFormal".lower()] = 5
        self.vb_constants.add("wdIndexFormal".lower())
        #  Modern.
        self.globals["wdIndexModern".lower()] = 3
        self.vb_constants.add("wdIndexModern".lower())
        #  Simple.
        self.globals["wdIndexSimple".lower()] = 6
        self.vb_constants.add("wdIndexSimple".lower())
        #  From template.
        self.globals["wdIndexTemplate".lower()] = 0
        self.vb_constants.add("wdIndexTemplate".lower())
        
        # WdOLEPlacement enumeration (Word)
        #   
        # Specifies the placement for an OLE object.
        
        #  Float over text.
        self.globals["wdFloatOverText".lower()] = 1
        self.vb_constants.add("wdFloatOverText".lower())
        #  In line with text.
        self.globals["wdInLine".lower()] = 0
        self.vb_constants.add("wdInLine".lower())
        
        # WdPasteOptions enumeration (Word)
        #   
        # Indicates how to paste copied text.
        
        #  Keeps formatting from the source document.
        self.globals["wdKeepSourceFormatting".lower()] = 0
        self.vb_constants.add("wdKeepSourceFormatting".lower())
        #  Keeps text only, without formatting.
        self.globals["wdKeepTextOnly".lower()] = 2
        self.vb_constants.add("wdKeepTextOnly".lower())
        #  Matches formatting to the destination document.
        self.globals["wdMatchDestinationFormatting".lower()] = 1
        self.vb_constants.add("wdMatchDestinationFormatting".lower())
        #  Matches formatting to the destination document using styles for formatting.
        self.globals["wdUseDestinationStyles".lower()] = 3
        self.vb_constants.add("wdUseDestinationStyles".lower())
        
        # WdSpecialPane enumeration (Word)
        #   
        # Specifies an item to display in the active window pane.
        
        #  Selected comments.
        self.globals["wdPaneComments".lower()] = 15
        self.vb_constants.add("wdPaneComments".lower())
        #  The page footer.
        self.globals["wdPaneCurrentPageFooter".lower()] = 17
        self.vb_constants.add("wdPaneCurrentPageFooter".lower())
        #  The page header.
        self.globals["wdPaneCurrentPageHeader".lower()] = 16
        self.vb_constants.add("wdPaneCurrentPageHeader".lower())
        #  The endnote continuation notice.
        self.globals["wdPaneEndnoteContinuationNotice".lower()] = 12
        self.vb_constants.add("wdPaneEndnoteContinuationNotice".lower())
        #  The endnote continuation separator.
        self.globals["wdPaneEndnoteContinuationSeparator".lower()] = 13
        self.vb_constants.add("wdPaneEndnoteContinuationSeparator".lower())
        #  Endnotes.
        self.globals["wdPaneEndnotes".lower()] = 8
        self.vb_constants.add("wdPaneEndnotes".lower())
        #  The endnote separator.
        self.globals["wdPaneEndnoteSeparator".lower()] = 14
        self.vb_constants.add("wdPaneEndnoteSeparator".lower())
        #  The even pages footer.
        self.globals["wdPaneEvenPagesFooter".lower()] = 6
        self.vb_constants.add("wdPaneEvenPagesFooter".lower())
        #  The even pages header.
        self.globals["wdPaneEvenPagesHeader".lower()] = 3
        self.vb_constants.add("wdPaneEvenPagesHeader".lower())
        #  The first page footer.
        self.globals["wdPaneFirstPageFooter".lower()] = 5
        self.vb_constants.add("wdPaneFirstPageFooter".lower())
        #  The first page header.
        self.globals["wdPaneFirstPageHeader".lower()] = 2
        self.vb_constants.add("wdPaneFirstPageHeader".lower())
        #  The footnote continuation notice.
        self.globals["wdPaneFootnoteContinuationNotice".lower()] = 9
        self.vb_constants.add("wdPaneFootnoteContinuationNotice".lower())
        #  The footnote continuation separator.
        self.globals["wdPaneFootnoteContinuationSeparator".lower()] = 10
        self.vb_constants.add("wdPaneFootnoteContinuationSeparator".lower())
        #  Footnotes.
        self.globals["wdPaneFootnotes".lower()] = 7
        self.vb_constants.add("wdPaneFootnotes".lower())
        #  The footnote separator.
        self.globals["wdPaneFootnoteSeparator".lower()] = 11
        self.vb_constants.add("wdPaneFootnoteSeparator".lower())
        #  No display.
        self.globals["wdPaneNone".lower()] = 0
        self.vb_constants.add("wdPaneNone".lower())
        #  The primary footer pane.
        self.globals["wdPanePrimaryFooter".lower()] = 4
        self.vb_constants.add("wdPanePrimaryFooter".lower())
        #  The primary header pane.
        self.globals["wdPanePrimaryHeader".lower()] = 1
        self.vb_constants.add("wdPanePrimaryHeader".lower())
        #  The revisions pane.
        self.globals["wdPaneRevisions".lower()] = 18
        self.vb_constants.add("wdPaneRevisions".lower())
        #  The revisions pane displays along the bottom of the document window.
        self.globals["wdPaneRevisionsHoriz".lower()] = 19
        self.vb_constants.add("wdPaneRevisionsHoriz".lower())
        #  The revisions pane displays along the left side of the document window.
        self.globals["wdPaneRevisionsVert".lower()] = 20
        self.vb_constants.add("wdPaneRevisionsVert".lower())
        
        # WdBuiltInProperty enumeration (Word)
        #   
        # Specifies a built-in document property.
        
        #  Name of application.
        self.globals["wdPropertyAppName".lower()] = 9
        self.vb_constants.add("wdPropertyAppName".lower())
        #  Author.
        self.globals["wdPropertyAuthor".lower()] = 3
        self.vb_constants.add("wdPropertyAuthor".lower())
        #  Byte count.
        self.globals["wdPropertyBytes".lower()] = 22
        self.vb_constants.add("wdPropertyBytes".lower())
        #  Category.
        self.globals["wdPropertyCategory".lower()] = 18
        self.vb_constants.add("wdPropertyCategory".lower())
        #  Character count.
        self.globals["wdPropertyCharacters".lower()] = 16
        self.vb_constants.add("wdPropertyCharacters".lower())
        #  Character count with spaces.
        self.globals["wdPropertyCharsWSpaces".lower()] = 30
        self.vb_constants.add("wdPropertyCharsWSpaces".lower())
        #  Comments.
        self.globals["wdPropertyComments".lower()] = 5
        self.vb_constants.add("wdPropertyComments".lower())
        #  Company.
        self.globals["wdPropertyCompany".lower()] = 21
        self.vb_constants.add("wdPropertyCompany".lower())
        #  Not supported.
        self.globals["wdPropertyFormat".lower()] = 19
        self.vb_constants.add("wdPropertyFormat".lower())
        #  Not supported.
        self.globals["wdPropertyHiddenSlides".lower()] = 27
        self.vb_constants.add("wdPropertyHiddenSlides".lower())
        #  Not supported.
        self.globals["wdPropertyHyperlinkBase".lower()] = 29
        self.vb_constants.add("wdPropertyHyperlinkBase".lower())
        #  Keywords.
        self.globals["wdPropertyKeywords".lower()] = 4
        self.vb_constants.add("wdPropertyKeywords".lower())
        #  Last author.
        self.globals["wdPropertyLastAuthor".lower()] = 7
        self.vb_constants.add("wdPropertyLastAuthor".lower())
        #  Line count.
        self.globals["wdPropertyLines".lower()] = 23
        self.vb_constants.add("wdPropertyLines".lower())
        #  Manager.
        self.globals["wdPropertyManager".lower()] = 20
        self.vb_constants.add("wdPropertyManager".lower())
        #  Not supported.
        self.globals["wdPropertyMMClips".lower()] = 28
        self.vb_constants.add("wdPropertyMMClips".lower())
        #  Notes.
        self.globals["wdPropertyNotes".lower()] = 26
        self.vb_constants.add("wdPropertyNotes".lower())
        #  Page count.
        self.globals["wdPropertyPages".lower()] = 14
        self.vb_constants.add("wdPropertyPages".lower())
        #  Paragraph count.
        self.globals["wdPropertyParas".lower()] = 24
        self.vb_constants.add("wdPropertyParas".lower())
        #  Revision number.
        self.globals["wdPropertyRevision".lower()] = 8
        self.vb_constants.add("wdPropertyRevision".lower())
        #  Security setting.
        self.globals["wdPropertySecurity".lower()] = 17
        self.vb_constants.add("wdPropertySecurity".lower())
        #  Not supported.
        self.globals["wdPropertySlides".lower()] = 25
        self.vb_constants.add("wdPropertySlides".lower())
        #  Subject.
        self.globals["wdPropertySubject".lower()] = 2
        self.vb_constants.add("wdPropertySubject".lower())
        #  Template name.
        self.globals["wdPropertyTemplate".lower()] = 6
        self.vb_constants.add("wdPropertyTemplate".lower())
        #  Time created.
        self.globals["wdPropertyTimeCreated".lower()] = 11
        self.vb_constants.add("wdPropertyTimeCreated".lower())
        #  Time last printed.
        self.globals["wdPropertyTimeLastPrinted".lower()] = 10
        self.vb_constants.add("wdPropertyTimeLastPrinted".lower())
        #  Time last saved.
        self.globals["wdPropertyTimeLastSaved".lower()] = 12
        self.vb_constants.add("wdPropertyTimeLastSaved".lower())
        #  Title.
        self.globals["wdPropertyTitle".lower()] = 1
        self.vb_constants.add("wdPropertyTitle".lower())
        #  Number of edits to VBA project.
        self.globals["wdPropertyVBATotalEdit".lower()] = 13
        self.vb_constants.add("wdPropertyVBATotalEdit".lower())
        #  Word count.
        self.globals["wdPropertyWords".lower()] = 15
        self.vb_constants.add("wdPropertyWords".lower())
        
        # WdRelativeHorizontalSize enumeration (Word)
        #    
        # Specifies the relative width of a shape using the value specified in the WidthRelative property for a Shape or ShapeRange object.
        
        #  Width is relative to the size of the inside margin; to the size of the left margin for odd pages, and to the size of the right margin for even pages.
        self.globals["wdRelativeHorizontalSizeInnerMarginArea".lower()] = 4
        self.vb_constants.add("wdRelativeHorizontalSizeInnerMarginArea".lower())
        #  Width is relative to the size of the left margin.
        self.globals["wdRelativeHorizontalSizeLeftMarginArea".lower()] = 2
        self.vb_constants.add("wdRelativeHorizontalSizeLeftMarginArea".lower())
        #  Width is relative to the space between the left margin and the right margin.
        self.globals["wdRelativeHorizontalSizeMargin".lower()] = 0
        self.vb_constants.add("wdRelativeHorizontalSizeMargin".lower())
        #  Width is relative to the size of the outside margin; to the size of the right margin for odd pages, and to the size of the left margin for even pages.
        self.globals["wdRelativeHorizontalSizeOuterMarginArea".lower()] = 5
        self.vb_constants.add("wdRelativeHorizontalSizeOuterMarginArea".lower())
        #  Width is relative to the width of the page.
        self.globals["wdRelativeHorizontalSizePage".lower()] = 1
        self.vb_constants.add("wdRelativeHorizontalSizePage".lower())
        #  Width is relative to the width of the right margin.
        self.globals["wdRelativeHorizontalSizeRightMarginArea".lower()] = 3
        self.vb_constants.add("wdRelativeHorizontalSizeRightMarginArea".lower())
        
        # WdReplace enumeration (Word)
        #   
        # Specifies the number of replacements to be made when find and replace is used.
        
        #  Replace all occurrences.
        self.globals["wdReplaceAll".lower()] = 2
        self.vb_constants.add("wdReplaceAll".lower())
        #  Replace no occurrences.
        self.globals["wdReplaceNone".lower()] = 0
        self.vb_constants.add("wdReplaceNone".lower())
        #  Replace the first occurrence encountered.
        self.globals["wdReplaceOne".lower()] = 1
        self.vb_constants.add("wdReplaceOne".lower())
        
        # WdSeekView enumeration (Word)
        #   
        # Specifies the document element to display in the print layout view.
        
        #  The current page footer.
        self.globals["wdSeekCurrentPageFooter".lower()] = 10
        self.vb_constants.add("wdSeekCurrentPageFooter".lower())
        #  The current page header.
        self.globals["wdSeekCurrentPageHeader".lower()] = 9
        self.vb_constants.add("wdSeekCurrentPageHeader".lower())
        #  Endnotes.
        self.globals["wdSeekEndnotes".lower()] = 8
        self.vb_constants.add("wdSeekEndnotes".lower())
        #  The even pages footer.
        self.globals["wdSeekEvenPagesFooter".lower()] = 6
        self.vb_constants.add("wdSeekEvenPagesFooter".lower())
        #  The even pages header.
        self.globals["wdSeekEvenPagesHeader".lower()] = 3
        self.vb_constants.add("wdSeekEvenPagesHeader".lower())
        #  The first page footer.
        self.globals["wdSeekFirstPageFooter".lower()] = 5
        self.vb_constants.add("wdSeekFirstPageFooter".lower())
        #  The first page header.
        self.globals["wdSeekFirstPageHeader".lower()] = 2
        self.vb_constants.add("wdSeekFirstPageHeader".lower())
        #  Footnotes.
        self.globals["wdSeekFootnotes".lower()] = 7
        self.vb_constants.add("wdSeekFootnotes".lower())
        #  The main document.
        self.globals["wdSeekMainDocument".lower()] = 0
        self.vb_constants.add("wdSeekMainDocument".lower())
        #  The primary footer.
        self.globals["wdSeekPrimaryFooter".lower()] = 4
        self.vb_constants.add("wdSeekPrimaryFooter".lower())
        #  The primary header.
        self.globals["wdSeekPrimaryHeader".lower()] = 1
        self.vb_constants.add("wdSeekPrimaryHeader".lower())
        
        # WdMailMergeDestination enumeration (Word)
        #   
        # Specifies a destination for mail merge results.
        
        #  Send results to email recipient.
        self.globals["wdSendToEmail".lower()] = 2
        self.vb_constants.add("wdSendToEmail".lower())
        #  Send results to fax recipient.
        self.globals["wdSendToFax".lower()] = 3
        self.vb_constants.add("wdSendToFax".lower())
        #  Send results to a new Word document.
        self.globals["wdSendToNewDocument".lower()] = 0
        self.vb_constants.add("wdSendToNewDocument".lower())
        #  Send results to a printer.
        self.globals["wdSendToPrinter".lower()] = 1
        self.vb_constants.add("wdSendToPrinter".lower())
        
        # WdBuildingBlockTypes enumeration (Word)
        #    
        # Specifies the type of building block.
        
        #  Autotext building block.
        self.globals["wdTypeAutoText".lower()] = 9
        self.vb_constants.add("wdTypeAutoText".lower())
        #  Bibliography building block.
        self.globals["wdTypeBibliography".lower()] = 34
        self.vb_constants.add("wdTypeBibliography".lower())
        #  Cover page building block.
        self.globals["wdTypeCoverPage".lower()] = 2
        self.vb_constants.add("wdTypeCoverPage".lower())
        #  Custom building block.
        self.globals["wdTypeCustom1".lower()] = 29
        self.vb_constants.add("wdTypeCustom1".lower())
        #  Custom building block.
        self.globals["wdTypeCustom2".lower()] = 30
        self.vb_constants.add("wdTypeCustom2".lower())
        #  Custom building block.
        self.globals["wdTypeCustom3".lower()] = 31
        self.vb_constants.add("wdTypeCustom3".lower())
        #  Custom building block.
        self.globals["wdTypeCustom4".lower()] = 32
        self.vb_constants.add("wdTypeCustom4".lower())
        #  Custom building block.
        self.globals["wdTypeCustom5".lower()] = 33
        self.vb_constants.add("wdTypeCustom5".lower())
        #  Custom autotext building block.
        self.globals["wdTypeCustomAutoText".lower()] = 23
        self.vb_constants.add("wdTypeCustomAutoText".lower())
        #  Custom bibliography building block.
        self.globals["wdTypeCustomBibliography".lower()] = 35
        self.vb_constants.add("wdTypeCustomBibliography".lower())
        #  Custom cover page building block.
        self.globals["wdTypeCustomCoverPage".lower()] = 16
        self.vb_constants.add("wdTypeCustomCoverPage".lower())
        #  Custom equations building block.
        self.globals["wdTypeCustomEquations".lower()] = 17
        self.vb_constants.add("wdTypeCustomEquations".lower())
        #  Custom footers building block.
        self.globals["wdTypeCustomFooters".lower()] = 18
        self.vb_constants.add("wdTypeCustomFooters".lower())
        #  Custom headers building block.
        self.globals["wdTypeCustomHeaders".lower()] = 19
        self.vb_constants.add("wdTypeCustomHeaders".lower())
        #  Custom page numbering building block.
        self.globals["wdTypeCustomPageNumber".lower()] = 20
        self.vb_constants.add("wdTypeCustomPageNumber".lower())
        #  Building block for custom page numbering on the bottom of the page.
        self.globals["wdTypeCustomPageNumberBottom".lower()] = 26
        self.vb_constants.add("wdTypeCustomPageNumberBottom".lower())
        #  Custom page numbering building block.
        self.globals["wdTypeCustomPageNumberPage".lower()] = 27
        self.vb_constants.add("wdTypeCustomPageNumberPage".lower())
        #  Building block for custom page numbering on the top of the page.
        self.globals["wdTypeCustomPageNumberTop".lower()] = 25
        self.vb_constants.add("wdTypeCustomPageNumberTop".lower())
        #  Custom quick parts building block.
        self.globals["wdTypeCustomQuickParts".lower()] = 15
        self.vb_constants.add("wdTypeCustomQuickParts".lower())
        #  Custom table of contents building block.
        self.globals["wdTypeCustomTableOfContents".lower()] = 28
        self.vb_constants.add("wdTypeCustomTableOfContents".lower())
        #  Custom table building block.
        self.globals["wdTypeCustomTables".lower()] = 21
        self.vb_constants.add("wdTypeCustomTables".lower())
        #  Custom text box building block.
        self.globals["wdTypeCustomTextBox".lower()] = 24
        self.vb_constants.add("wdTypeCustomTextBox".lower())
        #  Custom watermark building block.
        self.globals["wdTypeCustomWatermarks".lower()] = 22
        self.vb_constants.add("wdTypeCustomWatermarks".lower())
        #  Equation building block.
        self.globals["wdTypeEquations".lower()] = 3
        self.vb_constants.add("wdTypeEquations".lower())
        #  Footer building block.
        self.globals["wdTypeFooters".lower()] = 4
        self.vb_constants.add("wdTypeFooters".lower())
        #  Header building block.
        self.globals["wdTypeHeaders".lower()] = 5
        self.vb_constants.add("wdTypeHeaders".lower())
        #  Page numbering building block.
        self.globals["wdTypePageNumber".lower()] = 6
        self.vb_constants.add("wdTypePageNumber".lower())
        #  Building block for page numbering on the bottom of the page.
        self.globals["wdTypePageNumberBottom".lower()] = 12
        self.vb_constants.add("wdTypePageNumberBottom".lower())
        #  Page numbering building block.
        self.globals["wdTypePageNumberPage".lower()] = 13
        self.vb_constants.add("wdTypePageNumberPage".lower())
        #  Building block for page numbering on the top of the page.
        self.globals["wdTypePageNumberTop".lower()] = 11
        self.vb_constants.add("wdTypePageNumberTop".lower())
        #  Quick parts building block.
        self.globals["wdTypeQuickParts".lower()] = 1
        self.vb_constants.add("wdTypeQuickParts".lower())
        #  Table of contents building block.
        self.globals["wdTypeTableOfContents".lower()] = 14
        self.vb_constants.add("wdTypeTableOfContents".lower())
        #  Table building block.
        self.globals["wdTypeTables".lower()] = 7
        self.vb_constants.add("wdTypeTables".lower())
        #  Text box building block.
        self.globals["wdTypeTextBox".lower()] = 10
        self.vb_constants.add("wdTypeTextBox".lower())
        #  Watermark building block.
        self.globals["wdTypeWatermarks".lower()] = 8
        self.vb_constants.add("wdTypeWatermarks".lower())
        
        # WdBuiltinStyle Enum
        #
        # Specifies a built-in Microsoft Word style.
        
        # Bibliography.
        self.globals["wdStyleBibliography".lower()] = -266
        self.vb_constants.add("wdStyleBibliography".lower())
        # Block Quotation.
        self.globals["wdStyleBlockQuotation".lower()] = -85
        self.vb_constants.add("wdStyleBlockQuotation".lower())
        # Body Text.
        self.globals["wdStyleBodyText".lower()] = -67
        self.vb_constants.add("wdStyleBodyText".lower())
        # Body Text 2.
        self.globals["wdStyleBodyText2".lower()] = -81
        self.vb_constants.add("wdStyleBodyText2".lower())
        # Body Text 3.
        self.globals["wdStyleBodyText3".lower()] = -82
        self.vb_constants.add("wdStyleBodyText3".lower())
        # Body Text First Indent.
        self.globals["wdStyleBodyTextFirstIndent".lower()] = -78
        self.vb_constants.add("wdStyleBodyTextFirstIndent".lower())
        # Body Text First Indent 2.
        self.globals["wdStyleBodyTextFirstIndent2".lower()] = -79
        self.vb_constants.add("wdStyleBodyTextFirstIndent2".lower())
        # Body Text Indent.
        self.globals["wdStyleBodyTextIndent".lower()] = -68
        self.vb_constants.add("wdStyleBodyTextIndent".lower())
        # Body Text Indent 2.
        self.globals["wdStyleBodyTextIndent2".lower()] = -83
        self.vb_constants.add("wdStyleBodyTextIndent2".lower())
        # Body Text Indent 3.
        self.globals["wdStyleBodyTextIndent3".lower()] = -84
        self.vb_constants.add("wdStyleBodyTextIndent3".lower())
        # Book title.
        self.globals["wdStyleBookTitle".lower()] = -265
        self.vb_constants.add("wdStyleBookTitle".lower())
        # Caption.
        self.globals["wdStyleCaption".lower()] = -35
        self.vb_constants.add("wdStyleCaption".lower())
        # Closing.
        self.globals["wdStyleClosing".lower()] = -64
        self.vb_constants.add("wdStyleClosing".lower())
        # Comment Reference.
        self.globals["wdStyleCommentReference".lower()] = -40
        self.vb_constants.add("wdStyleCommentReference".lower())
        # Comment Text.
        self.globals["wdStyleCommentText".lower()] = -31
        self.vb_constants.add("wdStyleCommentText".lower())
        # Date.
        self.globals["wdStyleDate".lower()] = -77
        self.vb_constants.add("wdStyleDate".lower())
        # Default Paragraph Font.
        self.globals["wdStyleDefaultParagraphFont".lower()] = -66
        self.vb_constants.add("wdStyleDefaultParagraphFont".lower())
        # Emphasis.
        self.globals["wdStyleEmphasis".lower()] = -89
        self.vb_constants.add("wdStyleEmphasis".lower())
        # Endnote Reference.
        self.globals["wdStyleEndnoteReference".lower()] = -43
        self.vb_constants.add("wdStyleEndnoteReference".lower())
        # Endnote Text.
        self.globals["wdStyleEndnoteText".lower()] = -44
        self.vb_constants.add("wdStyleEndnoteText".lower())
        # Envelope Address.
        self.globals["wdStyleEnvelopeAddress".lower()] = -37
        self.vb_constants.add("wdStyleEnvelopeAddress".lower())
        # Envelope Return.
        self.globals["wdStyleEnvelopeReturn".lower()] = -38
        self.vb_constants.add("wdStyleEnvelopeReturn".lower())
        # Footer.
        self.globals["wdStyleFooter".lower()] = -33
        self.vb_constants.add("wdStyleFooter".lower())
        # Footnote Reference.
        self.globals["wdStyleFootnoteReference".lower()] = -39
        self.vb_constants.add("wdStyleFootnoteReference".lower())
        # Footnote Text.
        self.globals["wdStyleFootnoteText".lower()] = -30
        self.vb_constants.add("wdStyleFootnoteText".lower())
        # Header.
        self.globals["wdStyleHeader".lower()] = -32
        self.vb_constants.add("wdStyleHeader".lower())
        # Heading 1.
        self.globals["wdStyleHeading1".lower()] = -2
        self.vb_constants.add("wdStyleHeading1".lower())
        # Heading 2.
        self.globals["wdStyleHeading2".lower()] = -3
        self.vb_constants.add("wdStyleHeading2".lower())
        # Heading 3.
        self.globals["wdStyleHeading3".lower()] = -4
        self.vb_constants.add("wdStyleHeading3".lower())
        # Heading 4.
        self.globals["wdStyleHeading4".lower()] = -5
        self.vb_constants.add("wdStyleHeading4".lower())
        # Heading 5.
        self.globals["wdStyleHeading5".lower()] = -6
        self.vb_constants.add("wdStyleHeading5".lower())
        # Heading 6.
        self.globals["wdStyleHeading6".lower()] = -7
        self.vb_constants.add("wdStyleHeading6".lower())
        # Heading 7.
        self.globals["wdStyleHeading7".lower()] = -8
        self.vb_constants.add("wdStyleHeading7".lower())
        # Heading 8.
        self.globals["wdStyleHeading8".lower()] = -9
        self.vb_constants.add("wdStyleHeading8".lower())
        # Heading 9.
        self.globals["wdStyleHeading9".lower()] = -10
        self.vb_constants.add("wdStyleHeading9".lower())
        # HTML Acronym.
        self.globals["wdStyleHtmlAcronym".lower()] = -96
        self.vb_constants.add("wdStyleHtmlAcronym".lower())
        # HTML Address.
        self.globals["wdStyleHtmlAddress".lower()] = -97
        self.vb_constants.add("wdStyleHtmlAddress".lower())
        # HTML City.
        self.globals["wdStyleHtmlCite".lower()] = -98
        self.vb_constants.add("wdStyleHtmlCite".lower())
        # HTML Code.
        self.globals["wdStyleHtmlCode".lower()] = -99
        self.vb_constants.add("wdStyleHtmlCode".lower())
        # HTML Definition.
        self.globals["wdStyleHtmlDfn".lower()] = -100
        self.vb_constants.add("wdStyleHtmlDfn".lower())
        # HTML Keyboard.
        self.globals["wdStyleHtmlKbd".lower()] = -101
        self.vb_constants.add("wdStyleHtmlKbd".lower())
        # Normal (Web).
        self.globals["wdStyleHtmlNormal".lower()] = -95
        self.vb_constants.add("wdStyleHtmlNormal".lower())
        # HTML Preformatted.
        self.globals["wdStyleHtmlPre".lower()] = -102
        self.vb_constants.add("wdStyleHtmlPre".lower())
        # HTML Sample.
        self.globals["wdStyleHtmlSamp".lower()] = -103
        self.vb_constants.add("wdStyleHtmlSamp".lower())
        # HTML Typewriter.
        self.globals["wdStyleHtmlTt".lower()] = -104
        self.vb_constants.add("wdStyleHtmlTt".lower())
        # HTML Variable.
        self.globals["wdStyleHtmlVar".lower()] = -105
        self.vb_constants.add("wdStyleHtmlVar".lower())
        # Hyperlink.
        self.globals["wdStyleHyperlink".lower()] = -86
        self.vb_constants.add("wdStyleHyperlink".lower())
        # Followed Hyperlink.
        self.globals["wdStyleHyperlinkFollowed".lower()] = -87
        self.vb_constants.add("wdStyleHyperlinkFollowed".lower())
        # Index 1.
        self.globals["wdStyleIndex1".lower()] = -11
        self.vb_constants.add("wdStyleIndex1".lower())
        # Index 2.
        self.globals["wdStyleIndex2".lower()] = -12
        self.vb_constants.add("wdStyleIndex2".lower())
        # Index 3.
        self.globals["wdStyleIndex3".lower()] = -13
        self.vb_constants.add("wdStyleIndex3".lower())
        # Index 4.
        self.globals["wdStyleIndex4".lower()] = -14
        self.vb_constants.add("wdStyleIndex4".lower())
        # Index 5.
        self.globals["wdStyleIndex5".lower()] = -15
        self.vb_constants.add("wdStyleIndex5".lower())
        # Index 6.
        self.globals["wdStyleIndex6".lower()] = -16
        self.vb_constants.add("wdStyleIndex6".lower())
        # Index 7.
        self.globals["wdStyleIndex7".lower()] = -17
        self.vb_constants.add("wdStyleIndex7".lower())
        # Index8.
        self.globals["wdStyleIndex8".lower()] = -18
        self.vb_constants.add("wdStyleIndex8".lower())
        # Index 9.
        self.globals["wdStyleIndex9".lower()] = -19
        self.vb_constants.add("wdStyleIndex9".lower())
        # Index Heading
        self.globals["wdStyleIndexHeading".lower()] = -34
        self.vb_constants.add("wdStyleIndexHeading".lower())
        # Intense Emphasis.
        self.globals["wdStyleIntenseEmphasis".lower()] = -262
        self.vb_constants.add("wdStyleIntenseEmphasis".lower())
        # Intense Quote.
        self.globals["wdStyleIntenseQuote".lower()] = -182
        self.vb_constants.add("wdStyleIntenseQuote".lower())
        # Intense Reference.
        self.globals["wdStyleIntenseReference".lower()] = -264
        self.vb_constants.add("wdStyleIntenseReference".lower())
        # Line Number.
        self.globals["wdStyleLineNumber".lower()] = -41
        self.vb_constants.add("wdStyleLineNumber".lower())
        # List.
        self.globals["wdStyleList".lower()] = -48
        self.vb_constants.add("wdStyleList".lower())
        # List 2.
        self.globals["wdStyleList2".lower()] = -51
        self.vb_constants.add("wdStyleList2".lower())
        # List 3.
        self.globals["wdStyleList3".lower()] = -52
        self.vb_constants.add("wdStyleList3".lower())
        # List 4.
        self.globals["wdStyleList4".lower()] = -53
        self.vb_constants.add("wdStyleList4".lower())
        # List 5.
        self.globals["wdStyleList5".lower()] = -54
        self.vb_constants.add("wdStyleList5".lower())
        # List Bullet.
        self.globals["wdStyleListBullet".lower()] = -49
        self.vb_constants.add("wdStyleListBullet".lower())
        # List Bullet 2.
        self.globals["wdStyleListBullet2".lower()] = -55
        self.vb_constants.add("wdStyleListBullet2".lower())
        # List Bullet 3.
        self.globals["wdStyleListBullet3".lower()] = -56
        self.vb_constants.add("wdStyleListBullet3".lower())
        # List Bullet 4.
        self.globals["wdStyleListBullet4".lower()] = -57
        self.vb_constants.add("wdStyleListBullet4".lower())
        # List Bullet 5.
        self.globals["wdStyleListBullet5".lower()] = -58
        self.vb_constants.add("wdStyleListBullet5".lower())
        # List Continue.
        self.globals["wdStyleListContinue".lower()] = -69
        self.vb_constants.add("wdStyleListContinue".lower())
        # List Continue 2.
        self.globals["wdStyleListContinue2".lower()] = -70
        self.vb_constants.add("wdStyleListContinue2".lower())
        # List Continue 3.
        self.globals["wdStyleListContinue3".lower()] = -71
        self.vb_constants.add("wdStyleListContinue3".lower())
        # List Continue 4.
        self.globals["wdStyleListContinue4".lower()] = -72
        self.vb_constants.add("wdStyleListContinue4".lower())
        # List Continue 5.
        self.globals["wdStyleListContinue5".lower()] = -73
        self.vb_constants.add("wdStyleListContinue5".lower())
        # List Number.
        self.globals["wdStyleListNumber".lower()] = -50
        self.vb_constants.add("wdStyleListNumber".lower())
        # List Number 2.
        self.globals["wdStyleListNumber2".lower()] = -59
        self.vb_constants.add("wdStyleListNumber2".lower())
        # List Number 3.
        self.globals["wdStyleListNumber3".lower()] = -60
        self.vb_constants.add("wdStyleListNumber3".lower())
        # List Number 4.
        self.globals["wdStyleListNumber4".lower()] = -61
        self.vb_constants.add("wdStyleListNumber4".lower())
        # List Number 5.
        self.globals["wdStyleListNumber5".lower()] = -62
        self.vb_constants.add("wdStyleListNumber5".lower())
        # List Paragraph.
        self.globals["wdStyleListParagraph".lower()] = -180
        self.vb_constants.add("wdStyleListParagraph".lower())
        # Macro Text.
        self.globals["wdStyleMacroText".lower()] = -46
        self.vb_constants.add("wdStyleMacroText".lower())
        # Message Header.
        self.globals["wdStyleMessageHeader".lower()] = -74
        self.vb_constants.add("wdStyleMessageHeader".lower())
        # Document Map.
        self.globals["wdStyleNavPane".lower()] = -90
        self.vb_constants.add("wdStyleNavPane".lower())
        # Normal.
        self.globals["wdStyleNormal".lower()] = -1
        self.vb_constants.add("wdStyleNormal".lower())
        # Normal Indent.
        self.globals["wdStyleNormalIndent".lower()] = -29
        self.vb_constants.add("wdStyleNormalIndent".lower())
        # Normal (applied to an object).
        self.globals["wdStyleNormalObject".lower()] = -158
        self.vb_constants.add("wdStyleNormalObject".lower())
        # Normal (applied within a table).
        self.globals["wdStyleNormalTable".lower()] = -106
        self.vb_constants.add("wdStyleNormalTable".lower())
        # Note Heading.
        self.globals["wdStyleNoteHeading".lower()] = -80
        self.vb_constants.add("wdStyleNoteHeading".lower())
        # Page Number.
        self.globals["wdStylePageNumber".lower()] = -42
        self.vb_constants.add("wdStylePageNumber".lower())
        # Plain Text.
        self.globals["wdStylePlainText".lower()] = -91
        self.vb_constants.add("wdStylePlainText".lower())
        # Quote.
        self.globals["wdStyleQuote".lower()] = -181
        self.vb_constants.add("wdStyleQuote".lower())
        # Salutation.
        self.globals["wdStyleSalutation".lower()] = -76
        self.vb_constants.add("wdStyleSalutation".lower())
        # Signature.
        self.globals["wdStyleSignature".lower()] = -65
        self.vb_constants.add("wdStyleSignature".lower())
        # Strong.
        self.globals["wdStyleStrong".lower()] = -88
        self.vb_constants.add("wdStyleStrong".lower())
        # Subtitle.
        self.globals["wdStyleSubtitle".lower()] = -75
        self.vb_constants.add("wdStyleSubtitle".lower())
        # Subtle Emphasis.
        self.globals["wdStyleSubtleEmphasis".lower()] = -261
        self.vb_constants.add("wdStyleSubtleEmphasis".lower())
        # Subtle Reference.
        self.globals["wdStyleSubtleReference".lower()] = -263
        self.vb_constants.add("wdStyleSubtleReference".lower())
        # Colorful Grid.
        self.globals["wdStyleTableColorfulGrid".lower()] = -172
        self.vb_constants.add("wdStyleTableColorfulGrid".lower())
        # Colorful List.
        self.globals["wdStyleTableColorfulList".lower()] = -171
        self.vb_constants.add("wdStyleTableColorfulList".lower())
        # Colorful Shading.
        self.globals["wdStyleTableColorfulShading".lower()] = -170
        self.vb_constants.add("wdStyleTableColorfulShading".lower())
        # Dark List.
        self.globals["wdStyleTableDarkList".lower()] = -169
        self.vb_constants.add("wdStyleTableDarkList".lower())
        # Light Grid.
        self.globals["wdStyleTableLightGrid".lower()] = -161
        self.vb_constants.add("wdStyleTableLightGrid".lower())
        # Light Grid Accent 1.
        self.globals["wdStyleTableLightGridAccent1".lower()] = -175
        self.vb_constants.add("wdStyleTableLightGridAccent1".lower())
        # Light List.
        self.globals["wdStyleTableLightList".lower()] = -160
        self.vb_constants.add("wdStyleTableLightList".lower())
        # Light List Accent 1.
        self.globals["wdStyleTableLightListAccent1".lower()] = -174
        self.vb_constants.add("wdStyleTableLightListAccent1".lower())
        # Light Shading.
        self.globals["wdStyleTableLightShading".lower()] = -159
        self.vb_constants.add("wdStyleTableLightShading".lower())
        # Light Shading Accent 1.
        self.globals["wdStyleTableLightShadingAccent1".lower()] = -173
        self.vb_constants.add("wdStyleTableLightShadingAccent1".lower())
        # Medium Grid 1.
        self.globals["wdStyleTableMediumGrid1".lower()] = -166
        self.vb_constants.add("wdStyleTableMediumGrid1".lower())
        # Medium Grid 2.
        self.globals["wdStyleTableMediumGrid2".lower()] = -167
        self.vb_constants.add("wdStyleTableMediumGrid2".lower())
        # Medium Grid 3.
        self.globals["wdStyleTableMediumGrid3".lower()] = -168
        self.vb_constants.add("wdStyleTableMediumGrid3".lower())
        # Medium List 1.
        self.globals["wdStyleTableMediumList1".lower()] = -164
        self.vb_constants.add("wdStyleTableMediumList1".lower())
        # Medium List 1 Accent 1.
        self.globals["wdStyleTableMediumList1Accent1".lower()] = -178
        self.vb_constants.add("wdStyleTableMediumList1Accent1".lower())
        # Medium List 2.
        self.globals["wdStyleTableMediumList2".lower()] = -165
        self.vb_constants.add("wdStyleTableMediumList2".lower())
        # Medium Shading 1.
        self.globals["wdStyleTableMediumShading1".lower()] = -162
        self.vb_constants.add("wdStyleTableMediumShading1".lower())
        # Medium List 1 Accent 1.
        self.globals["wdStyleTableMediumShading1Accent1".lower()] = -176
        self.vb_constants.add("wdStyleTableMediumShading1Accent1".lower())
        # Medium Shading 2.
        self.globals["wdStyleTableMediumShading2".lower()] = -163
        self.vb_constants.add("wdStyleTableMediumShading2".lower())
        # Medium Shading 2 Accent 1.
        self.globals["wdStyleTableMediumShading2Accent1".lower()] = -177
        self.vb_constants.add("wdStyleTableMediumShading2Accent1".lower())
        # Table of Authorities.
        self.globals["wdStyleTableOfAuthorities".lower()] = -45
        self.vb_constants.add("wdStyleTableOfAuthorities".lower())
        # Table of Figures.
        self.globals["wdStyleTableOfFigures".lower()] = -36
        self.vb_constants.add("wdStyleTableOfFigures".lower())
        # Title.
        self.globals["wdStyleTitle".lower()] = -63
        self.vb_constants.add("wdStyleTitle".lower())
        # TOA Heading.
        self.globals["wdStyleTOAHeading".lower()] = -47
        self.vb_constants.add("wdStyleTOAHeading".lower())
        # TOC 1.
        self.globals["wdStyleTOC1".lower()] = -20
        self.vb_constants.add("wdStyleTOC1".lower())
        # TOC 2.
        self.globals["wdStyleTOC2".lower()] = -21
        self.vb_constants.add("wdStyleTOC2".lower())
        # TOC 3.
        self.globals["wdStyleTOC3".lower()] = -22
        self.vb_constants.add("wdStyleTOC3".lower())
        # TOC 4.
        self.globals["wdStyleTOC4".lower()] = -23
        self.vb_constants.add("wdStyleTOC4".lower())
        # TOC 5.
        self.globals["wdStyleTOC5".lower()] = -24
        self.vb_constants.add("wdStyleTOC5".lower())
        # TOC 6.
        self.globals["wdStyleTOC6".lower()] = -25
        self.vb_constants.add("wdStyleTOC6".lower())
        # TOC 7.
        self.globals["wdStyleTOC7".lower()] = -26
        self.vb_constants.add("wdStyleTOC7".lower())
        # TOC 8.
        self.globals["wdStyleTOC8".lower()] = -27
        self.vb_constants.add("wdStyleTOC8".lower())
        # TOC 9.
        self.globals["wdStyleTOC9".lower()] = -28
        self.vb_constants.add("wdStyleTOC9".lower())
        # TOC Heading.
        self.globals["wdStyleTocHeading".lower()] = -267
        self.vb_constants.add("wdStyleTocHeading".lower())        
        
        # Call type constants.
        self.globals["vbGet".lower()] = 2
        self.vb_constants.add("vbGet".lower())
        self.globals["vbLet".lower()] = 4
        self.vb_constants.add("vbLet".lower())
        self.globals["vbMethod".lower()] = 1
        self.vb_constants.add("vbMethod".lower())
        self.globals["vbSet".lower()] = 8
        self.vb_constants.add("vbSet".lower())

        # XlTickMark Enum
        self.globals["xlTickMarkCross".lower()] = 4
        self.vb_constants.add("xlTickMarkCross".lower())
        self.globals["xlTickMarkInside".lower()] = 2
        self.vb_constants.add("xlTickMarkInside".lower())
        self.globals["xlTickMarkNone".lower()] = -4142
        self.vb_constants.add("xlTickMarkNone".lower())
        self.globals["xlTickMarkOutside".lower()] = 3
        self.vb_constants.add("xlTickMarkOutside".lower())

        # XlXmlExportResult Enum
        self.globals["xlXmlExportSuccess".lower()] = 0
        self.vb_constants.add("xlXmlExportSuccess".lower())
        self.globals["xlXmlExportValidationFailed".lower()] = 1
        self.vb_constants.add("xlXmlExportValidationFailed".lower())

        # XLPrintErrors Enum
        self.globals["xlPrintErrorsBlank".lower()] = 1
        self.vb_constants.add("xlPrintErrorsBlank".lower())
        self.globals["xlPrintErrorsDash".lower()] = 2
        self.vb_constants.add("xlPrintErrorsDash".lower())
        self.globals["xlPrintErrorsDisplayed".lower()] = 0
        self.vb_constants.add("xlPrintErrorsDisplayed".lower())
        self.globals["xlPrintErrorsNA".lower()] = 3
        self.vb_constants.add("xlPrintErrorsNA".lower())

        # msoTextCaps Enum
        self.globals["msoAllCaps".lower()] = 2
        self.vb_constants.add("msoAllCaps".lower())
        self.globals["msoCapsMixed".lower()] = -2
        self.vb_constants.add("msoCapsMixed".lower())
        self.globals["msoNoCaps".lower()] = 0
        self.vb_constants.add("msoNoCaps".lower())
        self.globals["msoSmallCaps".lower()] = 1
        self.vb_constants.add("msoSmallCaps".lower())

        # XlApplicationInternational enumeration (Excel)
        self.globals["xl24HourClock".lower()] = 33
        self.vb_constants.add("xl24HourClock".lower())
        self.globals["xl4DigitYears".lower()] = 43
        self.vb_constants.add("xl4DigitYears".lower())
        self.globals["xlAlternateArraySeparator".lower()] = 16
        self.vb_constants.add("xlAlternateArraySeparator".lower())
        self.globals["xlColumnSeparator".lower()] = 14
        self.vb_constants.add("xlColumnSeparator".lower())
        self.globals["xlCountryCode".lower()] = 1
        self.vb_constants.add("xlCountryCode".lower())
        self.globals["xlCountrySetting".lower()] = 2
        self.vb_constants.add("xlCountrySetting".lower())
        self.globals["xlCurrencyBefore".lower()] = 37
        self.vb_constants.add("xlCurrencyBefore".lower())
        self.globals["xlCurrencyCode".lower()] = 25
        self.vb_constants.add("xlCurrencyCode".lower())
        self.globals["xlCurrencyDigits".lower()] = 27
        self.vb_constants.add("xlCurrencyDigits".lower())
        self.globals["xlCurrencyLeadingZeros".lower()] = 40
        self.vb_constants.add("xlCurrencyLeadingZeros".lower())
        self.globals["xlCurrencyMinusSign".lower()] = 38
        self.vb_constants.add("xlCurrencyMinusSign".lower())
        self.globals["xlCurrencyNegative".lower()] = 28
        self.vb_constants.add("xlCurrencyNegative".lower())
        self.globals["xlCurrencySpaceBefore".lower()] = 36
        self.vb_constants.add("xlCurrencySpaceBefore".lower())
        self.globals["xlCurrencyTrailingZeros".lower()] = 39
        self.vb_constants.add("xlCurrencyTrailingZeros".lower())
        self.globals["xlDateOrder".lower()] = 32
        self.vb_constants.add("xlDateOrder".lower())
        self.globals["xlDateSeparator".lower()] = 17
        self.vb_constants.add("xlDateSeparator".lower())
        self.globals["xlDayCode".lower()] = 21
        self.vb_constants.add("xlDayCode".lower())
        self.globals["xlDayLeadingZero".lower()] = 42
        self.vb_constants.add("xlDayLeadingZero".lower())
        self.globals["xlDecimalSeparator".lower()] = 3
        self.vb_constants.add("xlDecimalSeparator".lower())
        self.globals["xlGeneralFormatName".lower()] = 26
        self.vb_constants.add("xlGeneralFormatName".lower())
        self.globals["xlHourCode".lower()] = 22
        self.vb_constants.add("xlHourCode".lower())
        self.globals["xlLeftBrace".lower()] = 12
        self.vb_constants.add("xlLeftBrace".lower())
        self.globals["xlLeftBracket".lower()] = 10
        self.vb_constants.add("xlLeftBracket".lower())
        self.globals["xlListSeparator".lower()] = 5
        self.vb_constants.add("xlListSeparator".lower())
        self.globals["xlLowerCaseColumnLetter".lower()] = 9
        self.vb_constants.add("xlLowerCaseColumnLetter".lower())
        self.globals["xlLowerCaseRowLetter".lower()] = 8
        self.vb_constants.add("xlLowerCaseRowLetter".lower())
        self.globals["xlMDY".lower()] = 44
        self.vb_constants.add("xlMDY".lower())
        self.globals["xlMetric".lower()] = 35
        self.vb_constants.add("xlMetric".lower())
        self.globals["xlMinuteCode".lower()] = 23
        self.vb_constants.add("xlMinuteCode".lower())
        self.globals["xlMonthCode".lower()] = 20
        self.vb_constants.add("xlMonthCode".lower())
        self.globals["xlMonthLeadingZero".lower()] = 41
        self.vb_constants.add("xlMonthLeadingZero".lower())
        self.globals["xlMonthNameChars".lower()] = 30
        self.vb_constants.add("xlMonthNameChars".lower())
        self.globals["xlNoncurrencyDigits".lower()] = 29
        self.vb_constants.add("xlNoncurrencyDigits".lower())
        self.globals["xlNonEnglishFunctions".lower()] = 34
        self.vb_constants.add("xlNonEnglishFunctions".lower())
        self.globals["xlRightBrace".lower()] = 13
        self.vb_constants.add("xlRightBrace".lower())
        self.globals["xlRightBracket".lower()] = 11
        self.vb_constants.add("xlRightBracket".lower())
        self.globals["xlRowSeparator".lower()] = 15
        self.vb_constants.add("xlRowSeparator".lower())
        self.globals["xlSecondCode".lower()] = 24
        self.vb_constants.add("xlSecondCode".lower())
        self.globals["xlThousandsSeparator".lower()] = 4
        self.vb_constants.add("xlThousandsSeparator".lower())
        self.globals["xlTimeLeadingZero".lower()] = 45
        self.vb_constants.add("xlTimeLeadingZero".lower())
        self.globals["xlTimeSeparator".lower()] = 18
        self.vb_constants.add("xlTimeSeparator".lower())
        self.globals["xlUpperCaseColumnLetter".lower()] = 7
        self.vb_constants.add("xlUpperCaseColumnLetter".lower())
        self.globals["xlUpperCaseRowLetter".lower()] = 6
        self.vb_constants.add("xlUpperCaseRowLetter".lower())
        self.globals["xlWeekdayNameChars".lower()] = 31
        self.vb_constants.add("xlWeekdayNameChars".lower())
        self.globals["xlYearCode".lower()] = 19
        self.vb_constants.add("xlYearCode".lower())

        # WdMailMergeActiveRecord enumeration (Word)
        #
        # Specifies the active record in a mail merge result set.
        
        # The first record in the data source.
        self.globals["wdFirstDataSourceRecord".lower()] = -6
        self.vb_constants.add("wdFirstDataSourceRecord".lower())
        # The first record in the result set.
        self.globals["wdFirstRecord".lower()] = -4
        self.vb_constants.add("wdFirstRecord".lower())
        # The last record in the data source.
        self.globals["wdLastDataSourceRecord".lower()] = -7
        self.vb_constants.add("wdLastDataSourceRecord".lower())
        # The last record in the result set.
        self.globals["wdLastRecord".lower()] = -5
        self.vb_constants.add("wdLastRecord".lower())
        # The next record in the data source.
        self.globals["wdNextDataSourceRecord".lower()] = -8
        self.vb_constants.add("wdNextDataSourceRecord".lower())
        # The next record in the result set.
        self.globals["wdNextRecord".lower()] = -2
        self.vb_constants.add("wdNextRecord".lower())
        # No active record.
        self.globals["wdNoActiveRecord".lower()] = -1
        self.vb_constants.add("wdNoActiveRecord".lower())
        # The previous record in the data source.
        self.globals["wdPreviousDataSourceRecord".lower()] = -9
        self.vb_constants.add("wdPreviousDataSourceRecord".lower())
        # The previous record in the result set.
        self.globals["wdPreviousRecord".lower()] = -3
        self.vb_constants.add("wdPreviousRecord".lower())

        # WdAlignmentTabAlignment enumeration (Word)
        #   
        # Specifies tab alignment.
        
        # Centered tab.
        self.globals["wdCenter".lower()] = 1
        self.vb_constants.add("wdCenter".lower())
        # Left-aligned tab.
        self.globals["wdLeft".lower()] = 0
        self.vb_constants.add("wdLeft".lower())
        # Right-aligned tab.
        self.globals["wdRight".lower()] = 2
        self.vb_constants.add("wdRight".lower())

        # WdUnits enumeration (Word)
        #   
        # Specifies a unit of measure to use.
        
        # A cell.
        self.globals["wdCell".lower()] = 12
        self.vb_constants.add("wdCell".lower())
        # A character.
        self.globals["wdCharacter".lower()] = 1
        self.vb_constants.add("wdCharacter".lower())
        # Character formatting.
        self.globals["wdCharacterFormatting".lower()] = 13
        self.vb_constants.add("wdCharacterFormatting".lower())
        # A column.
        self.globals["wdColumn".lower()] = 9
        self.vb_constants.add("wdColumn".lower())
        # The selected item.
        self.globals["wdItem".lower()] = 16
        self.vb_constants.add("wdItem".lower())
        # A line.
        self.globals["wdLine".lower()] = 5
        self.vb_constants.add("wdLine".lower())
        # A paragraph.
        self.globals["wdParagraph".lower()] = 4
        self.vb_constants.add("wdParagraph".lower())
        # Paragraph formatting.
        self.globals["wdParagraphFormatting".lower()] = 14
        self.vb_constants.add("wdParagraphFormatting".lower())
        # A row.
        self.globals["wdRow".lower()] = 10
        self.vb_constants.add("wdRow".lower())
        # The screen dimensions.
        self.globals["wdScreen".lower()] = 7
        self.vb_constants.add("wdScreen".lower())
        # A section.
        self.globals["wdSection".lower()] = 8
        self.vb_constants.add("wdSection".lower())
        # A sentence.
        self.globals["wdSentence".lower()] = 3
        self.vb_constants.add("wdSentence".lower())
        # A story.
        self.globals["wdStory".lower()] = 6
        self.vb_constants.add("wdStory".lower())
        # A table.
        self.globals["wdTable".lower()] = 15
        self.vb_constants.add("wdTable".lower())
        # A window.
        self.globals["wdWindow".lower()] = 11
        self.vb_constants.add("wdWindow".lower())
        # A word.
        self.globals["wdWord".lower()] = 2
        self.vb_constants.add("wdWord".lower())

        # WdPageBorderArt enumeration (Word)
        #
        # Specifies the graphical page border setting of a page.
        
        #  An apple border.
        self.globals["wdArtApples".lower()] = 1
        self.vb_constants.add("wdArtApples".lower())
        #  An arched scalloped border.
        self.globals["wdArtArchedScallops".lower()] = 97
        self.vb_constants.add("wdArtArchedScallops".lower())
        #  A baby pacifier border.
        self.globals["wdArtBabyPacifier".lower()] = 70
        self.vb_constants.add("wdArtBabyPacifier".lower())
        #  A baby rattle border.
        self.globals["wdArtBabyRattle".lower()] = 71
        self.vb_constants.add("wdArtBabyRattle".lower())
        #  Balloons in three colors as the border.
        self.globals["wdArtBalloons3Colors".lower()] = 11
        self.vb_constants.add("wdArtBalloons3Colors".lower())
        #  A hot air balloon border.
        self.globals["wdArtBalloonsHotAir".lower()] = 12
        self.vb_constants.add("wdArtBalloonsHotAir".lower())
        #  A basic black-dashed border.
        self.globals["wdArtBasicBlackDashes".lower()] = 155
        self.vb_constants.add("wdArtBasicBlackDashes".lower())
        #  A basic black-dotted border.
        self.globals["wdArtBasicBlackDots".lower()] = 156
        self.vb_constants.add("wdArtBasicBlackDots".lower())
        #  A basic black squares border.
        self.globals["wdArtBasicBlackSquares".lower()] = 154
        self.vb_constants.add("wdArtBasicBlackSquares".lower())
        #  A basic thin-lines border.
        self.globals["wdArtBasicThinLines".lower()] = 151
        self.vb_constants.add("wdArtBasicThinLines".lower())
        #  A basic white-dashed border.
        self.globals["wdArtBasicWhiteDashes".lower()] = 152
        self.vb_constants.add("wdArtBasicWhiteDashes".lower())
        #  A basic white-dotted border.
        self.globals["wdArtBasicWhiteDots".lower()] = 147
        self.vb_constants.add("wdArtBasicWhiteDots".lower())
        #  A basic white squares border.
        self.globals["wdArtBasicWhiteSquares".lower()] = 153
        self.vb_constants.add("wdArtBasicWhiteSquares".lower())
        #  A basic wide inline border.
        self.globals["wdArtBasicWideInline".lower()] = 150
        self.vb_constants.add("wdArtBasicWideInline".lower())
        #  A basic wide midline border.
        self.globals["wdArtBasicWideMidline".lower()] = 148
        self.vb_constants.add("wdArtBasicWideMidline".lower())
        #  A basic wide outline border.
        self.globals["wdArtBasicWideOutline".lower()] = 149
        self.vb_constants.add("wdArtBasicWideOutline".lower())
        #  A bats border.
        self.globals["wdArtBats".lower()] = 37
        self.vb_constants.add("wdArtBats".lower())
        #  A birds border.
        self.globals["wdArtBirds".lower()] = 102
        self.vb_constants.add("wdArtBirds".lower())
        #  A birds-in-flight border.
        self.globals["wdArtBirdsFlight".lower()] = 35
        self.vb_constants.add("wdArtBirdsFlight".lower())
        #  A cabins border.
        self.globals["wdArtCabins".lower()] = 72
        self.vb_constants.add("wdArtCabins".lower())
        #  A cake slice border.
        self.globals["wdArtCakeSlice".lower()] = 3
        self.vb_constants.add("wdArtCakeSlice".lower())
        #  A candy corn border.
        self.globals["wdArtCandyCorn".lower()] = 4
        self.vb_constants.add("wdArtCandyCorn".lower())
        #  A Celtic knotwork border.
        self.globals["wdArtCelticKnotwork".lower()] = 99
        self.vb_constants.add("wdArtCelticKnotwork".lower())
        #  A certificate banner border.
        self.globals["wdArtCertificateBanner".lower()] = 158
        self.vb_constants.add("wdArtCertificateBanner".lower())
        #  A chain-link border.
        self.globals["wdArtChainLink".lower()] = 128
        self.vb_constants.add("wdArtChainLink".lower())
        #  A champagne bottle border.
        self.globals["wdArtChampagneBottle".lower()] = 6
        self.vb_constants.add("wdArtChampagneBottle".lower())
        #  A checked-bar black border.
        self.globals["wdArtCheckedBarBlack".lower()] = 145
        self.vb_constants.add("wdArtCheckedBarBlack".lower())
        #  A checked-bar colored border.
        self.globals["wdArtCheckedBarColor".lower()] = 61
        self.vb_constants.add("wdArtCheckedBarColor".lower())
        #  A checkered border.
        self.globals["wdArtCheckered".lower()] = 144
        self.vb_constants.add("wdArtCheckered".lower())
        #  A Christmas tree border.
        self.globals["wdArtChristmasTree".lower()] = 8
        self.vb_constants.add("wdArtChristmasTree".lower())
        #  A circles-and-lines border.
        self.globals["wdArtCirclesLines".lower()] = 91
        self.vb_constants.add("wdArtCirclesLines".lower())
        #  A circles-and-rectangles border.
        self.globals["wdArtCirclesRectangles".lower()] = 140
        self.vb_constants.add("wdArtCirclesRectangles".lower())
        #  A classical wave border.
        self.globals["wdArtClassicalWave".lower()] = 56
        self.vb_constants.add("wdArtClassicalWave".lower())
        #  A clocks border.
        self.globals["wdArtClocks".lower()] = 27
        self.vb_constants.add("wdArtClocks".lower())
        #  A compass border.
        self.globals["wdArtCompass".lower()] = 54
        self.vb_constants.add("wdArtCompass".lower())
        #  A confetti border.
        self.globals["wdArtConfetti".lower()] = 31
        self.vb_constants.add("wdArtConfetti".lower())
        #  A confetti border using shades of gray.
        self.globals["wdArtConfettiGrays".lower()] = 115
        self.vb_constants.add("wdArtConfettiGrays".lower())
        #  A confetti outline border.
        self.globals["wdArtConfettiOutline".lower()] = 116
        self.vb_constants.add("wdArtConfettiOutline".lower())
        #  A confetti streamers border.
        self.globals["wdArtConfettiStreamers".lower()] = 14
        self.vb_constants.add("wdArtConfettiStreamers".lower())
        #  A confetti white border.
        self.globals["wdArtConfettiWhite".lower()] = 117
        self.vb_constants.add("wdArtConfettiWhite".lower())
        #  A triangles border.
        self.globals["wdArtCornerTriangles".lower()] = 141
        self.vb_constants.add("wdArtCornerTriangles".lower())
        #  A coupon-cut-out dashes border.
        self.globals["wdArtCouponCutoutDashes".lower()] = 163
        self.vb_constants.add("wdArtCouponCutoutDashes".lower())
        #  A coupon-cut-out dots border.
        self.globals["wdArtCouponCutoutDots".lower()] = 164
        self.vb_constants.add("wdArtCouponCutoutDots".lower())
        #  A crazy maze border.
        self.globals["wdArtCrazyMaze".lower()] = 100
        self.vb_constants.add("wdArtCrazyMaze".lower())
        #  A butterfly border.
        self.globals["wdArtCreaturesButterfly".lower()] = 32
        self.vb_constants.add("wdArtCreaturesButterfly".lower())
        #  A fish border.
        self.globals["wdArtCreaturesFish".lower()] = 34
        self.vb_constants.add("wdArtCreaturesFish".lower())
        #  An insect border.
        self.globals["wdArtCreaturesInsects".lower()] = 142
        self.vb_constants.add("wdArtCreaturesInsects".lower())
        #  A ladybug border.
        self.globals["wdArtCreaturesLadyBug".lower()] = 33
        self.vb_constants.add("wdArtCreaturesLadyBug".lower())
        #  A cross-stitch border.
        self.globals["wdArtCrossStitch".lower()] = 138
        self.vb_constants.add("wdArtCrossStitch".lower())
        #  A cup border.
        self.globals["wdArtCup".lower()] = 67
        self.vb_constants.add("wdArtCup".lower())
        #  A deco arch border.
        self.globals["wdArtDecoArch".lower()] = 89
        self.vb_constants.add("wdArtDecoArch".lower())
        #  A deco arch colored border.
        self.globals["wdArtDecoArchColor".lower()] = 50
        self.vb_constants.add("wdArtDecoArchColor".lower())
        #  A deco blocks border.
        self.globals["wdArtDecoBlocks".lower()] = 90
        self.vb_constants.add("wdArtDecoBlocks".lower())
        #  A diamond border using shades of gray.
        self.globals["wdArtDiamondsGray".lower()] = 88
        self.vb_constants.add("wdArtDiamondsGray".lower())
        #  A double-D border.
        self.globals["wdArtDoubleD".lower()] = 55
        self.vb_constants.add("wdArtDoubleD".lower())
        #  A double-diamonds border.
        self.globals["wdArtDoubleDiamonds".lower()] = 127
        self.vb_constants.add("wdArtDoubleDiamonds".lower())
        #  An earth number 1 border.
        self.globals["wdArtEarth1".lower()] = 22
        self.vb_constants.add("wdArtEarth1".lower())
        #  An earth number 2 border.
        self.globals["wdArtEarth2".lower()] = 21
        self.vb_constants.add("wdArtEarth2".lower())
        #  An eclipsing squares number 1 border.
        self.globals["wdArtEclipsingSquares1".lower()] = 101
        self.vb_constants.add("wdArtEclipsingSquares1".lower())
        #  An eclipsing squares number 2 border.
        self.globals["wdArtEclipsingSquares2".lower()] = 86
        self.vb_constants.add("wdArtEclipsingSquares2".lower())
        #  A black eggs border.
        self.globals["wdArtEggsBlack".lower()] = 66
        self.vb_constants.add("wdArtEggsBlack".lower())
        #  A fans border.
        self.globals["wdArtFans".lower()] = 51
        self.vb_constants.add("wdArtFans".lower())
        #  A film border.
        self.globals["wdArtFilm".lower()] = 52
        self.vb_constants.add("wdArtFilm".lower())
        #  A fire crackers border.
        self.globals["wdArtFirecrackers".lower()] = 28
        self.vb_constants.add("wdArtFirecrackers".lower())
        #  A block flowers print border.
        self.globals["wdArtFlowersBlockPrint".lower()] = 49
        self.vb_constants.add("wdArtFlowersBlockPrint".lower())
        #  A daisies border.
        self.globals["wdArtFlowersDaisies".lower()] = 48
        self.vb_constants.add("wdArtFlowersDaisies".lower())
        #  A modern flowers number 1 border.
        self.globals["wdArtFlowersModern1".lower()] = 45
        self.vb_constants.add("wdArtFlowersModern1".lower())
        #  A modern flowers number 2 border.
        self.globals["wdArtFlowersModern2".lower()] = 44
        self.vb_constants.add("wdArtFlowersModern2".lower())
        #  A pansy border.
        self.globals["wdArtFlowersPansy".lower()] = 43
        self.vb_constants.add("wdArtFlowersPansy".lower())
        #  A red rose border.
        self.globals["wdArtFlowersRedRose".lower()] = 39
        self.vb_constants.add("wdArtFlowersRedRose".lower())
        #  A rose border.
        self.globals["wdArtFlowersRoses".lower()] = 38
        self.vb_constants.add("wdArtFlowersRoses".lower())
        #  A teacup border.
        self.globals["wdArtFlowersTeacup".lower()] = 103
        self.vb_constants.add("wdArtFlowersTeacup".lower())
        #  A tiny flower border.
        self.globals["wdArtFlowersTiny".lower()] = 42
        self.vb_constants.add("wdArtFlowersTiny".lower())
        #  A gems border.
        self.globals["wdArtGems".lower()] = 139
        self.vb_constants.add("wdArtGems".lower())
        #  A gingerbread man border.
        self.globals["wdArtGingerbreadMan".lower()] = 69
        self.vb_constants.add("wdArtGingerbreadMan".lower())
        #  A gradient border.
        self.globals["wdArtGradient".lower()] = 122
        self.vb_constants.add("wdArtGradient".lower())
        #  A handmade number 1 border.
        self.globals["wdArtHandmade1".lower()] = 159
        self.vb_constants.add("wdArtHandmade1".lower())
        #  A handmade number 2 border.
        self.globals["wdArtHandmade2".lower()] = 160
        self.vb_constants.add("wdArtHandmade2".lower())
        #  A heart-balloon border.
        self.globals["wdArtHeartBalloon".lower()] = 16
        self.vb_constants.add("wdArtHeartBalloon".lower())
        #  A heart border in shades of gray.
        self.globals["wdArtHeartGray".lower()] = 68
        self.vb_constants.add("wdArtHeartGray".lower())
        #  A hearts border.
        self.globals["wdArtHearts".lower()] = 15
        self.vb_constants.add("wdArtHearts".lower())
        #  A heebie-jeebies border.
        self.globals["wdArtHeebieJeebies".lower()] = 120
        self.vb_constants.add("wdArtHeebieJeebies".lower())
        #  A holly border.
        self.globals["wdArtHolly".lower()] = 41
        self.vb_constants.add("wdArtHolly".lower())
        #  A funky house border.
        self.globals["wdArtHouseFunky".lower()] = 73
        self.vb_constants.add("wdArtHouseFunky".lower())
        #  An hypnotic border.
        self.globals["wdArtHypnotic".lower()] = 87
        self.vb_constants.add("wdArtHypnotic".lower())
        #  An ice cream cones border.
        self.globals["wdArtIceCreamCones".lower()] = 5
        self.vb_constants.add("wdArtIceCreamCones".lower())
        #  A light bulb border.
        self.globals["wdArtLightBulb".lower()] = 121
        self.vb_constants.add("wdArtLightBulb".lower())
        #  A lightning number 1 border.
        self.globals["wdArtLightning1".lower()] = 53
        self.vb_constants.add("wdArtLightning1".lower())
        #  A lightning number 2 border.
        self.globals["wdArtLightning2".lower()] = 119
        self.vb_constants.add("wdArtLightning2".lower())
        #  A maple leaf border.
        self.globals["wdArtMapleLeaf".lower()] = 81
        self.vb_constants.add("wdArtMapleLeaf".lower())
        #  A maple muffins border.
        self.globals["wdArtMapleMuffins".lower()] = 2
        self.vb_constants.add("wdArtMapleMuffins".lower())
        #  A map pins border.
        self.globals["wdArtMapPins".lower()] = 30
        self.vb_constants.add("wdArtMapPins".lower())
        #  A marquee border.
        self.globals["wdArtMarquee".lower()] = 146
        self.vb_constants.add("wdArtMarquee".lower())
        #  A marquee toothed border.
        self.globals["wdArtMarqueeToothed".lower()] = 131
        self.vb_constants.add("wdArtMarqueeToothed".lower())
        #  A moons border.
        self.globals["wdArtMoons".lower()] = 125
        self.vb_constants.add("wdArtMoons".lower())
        #  A mosaic border.
        self.globals["wdArtMosaic".lower()] = 118
        self.vb_constants.add("wdArtMosaic".lower())
        #  A music notes border.
        self.globals["wdArtMusicNotes".lower()] = 79
        self.vb_constants.add("wdArtMusicNotes".lower())
        #  A northwest border.
        self.globals["wdArtNorthwest".lower()] = 104
        self.vb_constants.add("wdArtNorthwest".lower())
        #  An ovals border.
        self.globals["wdArtOvals".lower()] = 126
        self.vb_constants.add("wdArtOvals".lower())
        #  A packages border.
        self.globals["wdArtPackages".lower()] = 26
        self.vb_constants.add("wdArtPackages".lower())
        #  A black palms border.
        self.globals["wdArtPalmsBlack".lower()] = 80
        self.vb_constants.add("wdArtPalmsBlack".lower())
        #  A colored palms border.
        self.globals["wdArtPalmsColor".lower()] = 10
        self.vb_constants.add("wdArtPalmsColor".lower())
        #  A paper clips border.
        self.globals["wdArtPaperClips".lower()] = 82
        self.vb_constants.add("wdArtPaperClips".lower())
        #  A papyrus border.
        self.globals["wdArtPapyrus".lower()] = 92
        self.vb_constants.add("wdArtPapyrus".lower())
        #  A party favor border.
        self.globals["wdArtPartyFavor".lower()] = 13
        self.vb_constants.add("wdArtPartyFavor".lower())
        #  A party glass border.
        self.globals["wdArtPartyGlass".lower()] = 7
        self.vb_constants.add("wdArtPartyGlass".lower())
        #  A pencils border.
        self.globals["wdArtPencils".lower()] = 25
        self.vb_constants.add("wdArtPencils".lower())
        #  A people border.
        self.globals["wdArtPeople".lower()] = 84
        self.vb_constants.add("wdArtPeople".lower())
        #  A people-wearing-hats border.
        self.globals["wdArtPeopleHats".lower()] = 23
        self.vb_constants.add("wdArtPeopleHats".lower())
        #  A people-waving border.
        self.globals["wdArtPeopleWaving".lower()] = 85
        self.vb_constants.add("wdArtPeopleWaving".lower())
        #  A poinsettias border.
        self.globals["wdArtPoinsettias".lower()] = 40
        self.vb_constants.add("wdArtPoinsettias".lower())
        #  A postage stamp border.
        self.globals["wdArtPostageStamp".lower()] = 135
        self.vb_constants.add("wdArtPostageStamp".lower())
        #  A pumpkin number 1 border.
        self.globals["wdArtPumpkin1".lower()] = 65
        self.vb_constants.add("wdArtPumpkin1".lower())
        #  A pushpin note number 1 border.
        self.globals["wdArtPushPinNote1".lower()] = 63
        self.vb_constants.add("wdArtPushPinNote1".lower())
        #  A pushpin note number 2 border.
        self.globals["wdArtPushPinNote2".lower()] = 64
        self.vb_constants.add("wdArtPushPinNote2".lower())
        #  A pyramids border.
        self.globals["wdArtPyramids".lower()] = 113
        self.vb_constants.add("wdArtPyramids".lower())
        #  An external pyramids border.
        self.globals["wdArtPyramidsAbove".lower()] = 114
        self.vb_constants.add("wdArtPyramidsAbove".lower())
        #  A quadrants border.
        self.globals["wdArtQuadrants".lower()] = 60
        self.vb_constants.add("wdArtQuadrants".lower())
        #  A rings border.
        self.globals["wdArtRings".lower()] = 29
        self.vb_constants.add("wdArtRings".lower())
        #  A safari border.
        self.globals["wdArtSafari".lower()] = 98
        self.vb_constants.add("wdArtSafari".lower())
        #  A saw-tooth border.
        self.globals["wdArtSawtooth".lower()] = 133
        self.vb_constants.add("wdArtSawtooth".lower())
        #  A saw-tooth border using shades of gray.
        self.globals["wdArtSawtoothGray".lower()] = 134
        self.vb_constants.add("wdArtSawtoothGray".lower())
        #  A scared cat border.
        self.globals["wdArtScaredCat".lower()] = 36
        self.vb_constants.add("wdArtScaredCat".lower())
        #  A Seattle border.
        self.globals["wdArtSeattle".lower()] = 78
        self.vb_constants.add("wdArtSeattle".lower())
        #  A shadowed squared border.
        self.globals["wdArtShadowedSquares".lower()] = 57
        self.vb_constants.add("wdArtShadowedSquares".lower())
        #  A shark-tooth border.
        self.globals["wdArtSharksTeeth".lower()] = 132
        self.vb_constants.add("wdArtSharksTeeth".lower())
        #  A shorebird tracks border.
        self.globals["wdArtShorebirdTracks".lower()] = 83
        self.vb_constants.add("wdArtShorebirdTracks".lower())
        #  A sky rocket border.
        self.globals["wdArtSkyrocket".lower()] = 77
        self.vb_constants.add("wdArtSkyrocket".lower())
        #  A fancy snowflake border.
        self.globals["wdArtSnowflakeFancy".lower()] = 76
        self.vb_constants.add("wdArtSnowflakeFancy".lower())
        #  A snowflake border.
        self.globals["wdArtSnowflakes".lower()] = 75
        self.vb_constants.add("wdArtSnowflakes".lower())
        #  A sombrero border.
        self.globals["wdArtSombrero".lower()] = 24
        self.vb_constants.add("wdArtSombrero".lower())
        #  A southwest border.
        self.globals["wdArtSouthwest".lower()] = 105
        self.vb_constants.add("wdArtSouthwest".lower())
        #  A stars border.
        self.globals["wdArtStars".lower()] = 19
        self.vb_constants.add("wdArtStars".lower())
        #  A 3D stars border.
        self.globals["wdArtStars3D".lower()] = 17
        self.vb_constants.add("wdArtStars3D".lower())
        #  A black stars border.
        self.globals["wdArtStarsBlack".lower()] = 74
        self.vb_constants.add("wdArtStarsBlack".lower())
        #  A shadowed stars border.
        self.globals["wdArtStarsShadowed".lower()] = 18
        self.vb_constants.add("wdArtStarsShadowed".lower())
        #  A stars-on-top border.
        self.globals["wdArtStarsTop".lower()] = 157
        self.vb_constants.add("wdArtStarsTop".lower())
        #  A sun border.
        self.globals["wdArtSun".lower()] = 20
        self.vb_constants.add("wdArtSun".lower())
        #  A swirling border.
        self.globals["wdArtSwirligig".lower()] = 62
        self.vb_constants.add("wdArtSwirligig".lower())
        #  A torn-paper border.
        self.globals["wdArtTornPaper".lower()] = 161
        self.vb_constants.add("wdArtTornPaper".lower())
        #  A black torn-paper border.
        self.globals["wdArtTornPaperBlack".lower()] = 162
        self.vb_constants.add("wdArtTornPaperBlack".lower())
        #  A trees border.
        self.globals["wdArtTrees".lower()] = 9
        self.vb_constants.add("wdArtTrees".lower())
        #  A triangle party border.
        self.globals["wdArtTriangleParty".lower()] = 123
        self.vb_constants.add("wdArtTriangleParty".lower())
        #  A triangles border.
        self.globals["wdArtTriangles".lower()] = 129
        self.vb_constants.add("wdArtTriangles".lower())
        #  A tribal number 1 border.
        self.globals["wdArtTribal1".lower()] = 130
        self.vb_constants.add("wdArtTribal1".lower())
        #  A tribal number 2 border.
        self.globals["wdArtTribal2".lower()] = 109
        self.vb_constants.add("wdArtTribal2".lower())
        #  A tribal number 3 border.
        self.globals["wdArtTribal3".lower()] = 108
        self.vb_constants.add("wdArtTribal3".lower())
        #  A tribal number 4 border.
        self.globals["wdArtTribal4".lower()] = 107
        self.vb_constants.add("wdArtTribal4".lower())
        #  A tribal number 5 border.
        self.globals["wdArtTribal5".lower()] = 110
        self.vb_constants.add("wdArtTribal5".lower())
        #  A tribal number 6 border.
        self.globals["wdArtTribal6".lower()] = 106
        self.vb_constants.add("wdArtTribal6".lower())
        #  A twisted lines number 1 border.
        self.globals["wdArtTwistedLines1".lower()] = 58
        self.vb_constants.add("wdArtTwistedLines1".lower())
        #  A twisted lines number 2 border.
        self.globals["wdArtTwistedLines2".lower()] = 124
        self.vb_constants.add("wdArtTwistedLines2".lower())
        #  A vine border.
        self.globals["wdArtVine".lower()] = 47
        self.vb_constants.add("wdArtVine".lower())
        #  A wave-line border.
        self.globals["wdArtWaveline".lower()] = 59
        self.vb_constants.add("wdArtWaveline".lower())
        #  A weaving angle border.
        self.globals["wdArtWeavingAngles".lower()] = 96
        self.vb_constants.add("wdArtWeavingAngles".lower())
        #  A weaving braid border.
        self.globals["wdArtWeavingBraid".lower()] = 94
        self.vb_constants.add("wdArtWeavingBraid".lower())
        #  A weaving ribbon border.
        self.globals["wdArtWeavingRibbon".lower()] = 95
        self.vb_constants.add("wdArtWeavingRibbon".lower())
        #  A weaving strips border.
        self.globals["wdArtWeavingStrips".lower()] = 136
        self.vb_constants.add("wdArtWeavingStrips".lower())
        #  A white flower border.
        self.globals["wdArtWhiteFlowers".lower()] = 46
        self.vb_constants.add("wdArtWhiteFlowers".lower())
        #  A woodwork border.
        self.globals["wdArtWoodwork".lower()] = 93
        self.vb_constants.add("wdArtWoodwork".lower())
        #  An X illusion border.
        self.globals["wdArtXIllusions".lower()] = 111
        self.vb_constants.add("wdArtXIllusions".lower())
        #  A zany triangle border.
        self.globals["wdArtZanyTriangles".lower()] = 112
        self.vb_constants.add("wdArtZanyTriangles".lower())
        #  A zigzag border.
        self.globals["wdArtZigZag".lower()] = 137
        self.vb_constants.add("wdArtZigZag".lower())
        #  A zigzag stitch border.
        self.globals["wdArtZigZagStitch".lower()] = 143
        self.vb_constants.add("wdArtZigZagStitch".lower())
        
        # WdColor enumeration (Word)
        #
        # Specifies the 24-bit color to apply.
        
        #  Aqua color
        self.globals["wdColorAqua".lower()] = 13421619
        self.vb_constants.add("wdColorAqua".lower())
        #  Automatic color; default; usually black
        self.globals["wdColorAutomatic".lower()] = -16777216
        self.vb_constants.add("wdColorAutomatic".lower())
        #  Black color
        self.globals["wdColorBlack".lower()] = 0
        self.vb_constants.add("wdColorBlack".lower())
        #  Blue color
        self.globals["wdColorBlue".lower()] = 16711680
        self.vb_constants.add("wdColorBlue".lower())
        #  Blue-gray color
        self.globals["wdColorBlueGray".lower()] = 10053222
        self.vb_constants.add("wdColorBlueGray".lower())
        #  Bright green color
        self.globals["wdColorBrightGreen".lower()] = 65280
        self.vb_constants.add("wdColorBrightGreen".lower())
        #  Brown color
        self.globals["wdColorBrown".lower()] = 13209
        self.vb_constants.add("wdColorBrown".lower())
        #  Dark blue color
        self.globals["wdColorDarkBlue".lower()] = 8388608
        self.vb_constants.add("wdColorDarkBlue".lower())
        #  Dark green color
        self.globals["wdColorDarkGreen".lower()] = 13056
        self.vb_constants.add("wdColorDarkGreen".lower())
        #  Dark red color
        self.globals["wdColorDarkRed".lower()] = 128
        self.vb_constants.add("wdColorDarkRed".lower())
        #  Dark teal color
        self.globals["wdColorDarkTeal".lower()] = 6697728
        self.vb_constants.add("wdColorDarkTeal".lower())
        #  Dark yellow color
        self.globals["wdColorDarkYellow".lower()] = 32896
        self.vb_constants.add("wdColorDarkYellow".lower())
        #  Gold color
        self.globals["wdColorGold".lower()] = 52479
        self.vb_constants.add("wdColorGold".lower())
        #  Shade 05 of gray color
        self.globals["wdColorGray05".lower()] = 15987699
        self.vb_constants.add("wdColorGray05".lower())
        #  Shade 10 of gray color
        self.globals["wdColorGray10".lower()] = 15132390
        self.vb_constants.add("wdColorGray10".lower())
        #  Shade 125 of gray color
        self.globals["wdColorGray125".lower()] = 14737632
        self.vb_constants.add("wdColorGray125".lower())
        #  Shade 15 of gray color
        self.globals["wdColorGray15".lower()] = 14277081
        self.vb_constants.add("wdColorGray15".lower())
        #  Shade 20 of gray color
        self.globals["wdColorGray20".lower()] = 13421772
        self.vb_constants.add("wdColorGray20".lower())
        #  Shade 25 of gray color
        self.globals["wdColorGray25".lower()] = 12632256
        self.vb_constants.add("wdColorGray25".lower())
        #  Shade 30 of gray color
        self.globals["wdColorGray30".lower()] = 11776947
        self.vb_constants.add("wdColorGray30".lower())
        #  Shade 35 of gray color
        self.globals["wdColorGray35".lower()] = 10921638
        self.vb_constants.add("wdColorGray35".lower())
        #  Shade 375 of gray color
        self.globals["wdColorGray375".lower()] = 10526880
        self.vb_constants.add("wdColorGray375".lower())
        #  Shade 40 of gray color
        self.globals["wdColorGray40".lower()] = 10066329
        self.vb_constants.add("wdColorGray40".lower())
        #  Shade 45 of gray color
        self.globals["wdColorGray45".lower()] = 9211020
        self.vb_constants.add("wdColorGray45".lower())
        #  Shade 50 of gray color
        self.globals["wdColorGray50".lower()] = 8421504
        self.vb_constants.add("wdColorGray50".lower())
        #  Shade 55 of gray color
        self.globals["wdColorGray55".lower()] = 7566195
        self.vb_constants.add("wdColorGray55".lower())
        #  Shade 60 of gray color
        self.globals["wdColorGray60".lower()] = 6710886
        self.vb_constants.add("wdColorGray60".lower())
        #  Shade 625 of gray color
        self.globals["wdColorGray625".lower()] = 6316128
        self.vb_constants.add("wdColorGray625".lower())
        #  Shade 65 of gray color
        self.globals["wdColorGray65".lower()] = 5855577
        self.vb_constants.add("wdColorGray65".lower())
        #  Shade 70 of gray color
        self.globals["wdColorGray70".lower()] = 5000268
        self.vb_constants.add("wdColorGray70".lower())
        #  Shade 75 of gray color
        self.globals["wdColorGray75".lower()] = 4210752
        self.vb_constants.add("wdColorGray75".lower())
        #  Shade 80 of gray color
        self.globals["wdColorGray80".lower()] = 3355443
        self.vb_constants.add("wdColorGray80".lower())
        #  Shade 85 of gray color
        self.globals["wdColorGray85".lower()] = 2500134
        self.vb_constants.add("wdColorGray85".lower())
        #  Shade 875 of gray color
        self.globals["wdColorGray875".lower()] = 2105376
        self.vb_constants.add("wdColorGray875".lower())
        #  Shade 90 of gray color
        self.globals["wdColorGray90".lower()] = 1644825
        self.vb_constants.add("wdColorGray90".lower())
        #  Shade 95 of gray color
        self.globals["wdColorGray95".lower()] = 789516
        self.vb_constants.add("wdColorGray95".lower())
        #  Green color
        self.globals["wdColorGreen".lower()] = 32768
        self.vb_constants.add("wdColorGreen".lower())
        #  Indigo color
        self.globals["wdColorIndigo".lower()] = 10040115
        self.vb_constants.add("wdColorIndigo".lower())
        #  Lavender color
        self.globals["wdColorLavender".lower()] = 16751052
        self.vb_constants.add("wdColorLavender".lower())
        #  Light blue color
        self.globals["wdColorLightBlue".lower()] = 16737843
        self.vb_constants.add("wdColorLightBlue".lower())
        #  Light green color
        self.globals["wdColorLightGreen".lower()] = 13434828
        self.vb_constants.add("wdColorLightGreen".lower())
        #  Light orange color
        self.globals["wdColorLightOrange".lower()] = 39423
        self.vb_constants.add("wdColorLightOrange".lower())
        #  Light turquoise color
        self.globals["wdColorLightTurquoise".lower()] = 16777164
        self.vb_constants.add("wdColorLightTurquoise".lower())
        #  Light yellow color
        self.globals["wdColorLightYellow".lower()] = 10092543
        self.vb_constants.add("wdColorLightYellow".lower())
        #  Lime color
        self.globals["wdColorLime".lower()] = 52377
        self.vb_constants.add("wdColorLime".lower())
        #  Olive green color
        self.globals["wdColorOliveGreen".lower()] = 13107
        self.vb_constants.add("wdColorOliveGreen".lower())
        #  Orange color
        self.globals["wdColorOrange".lower()] = 26367
        self.vb_constants.add("wdColorOrange".lower())
        #  Pale blue color
        self.globals["wdColorPaleBlue".lower()] = 16764057
        self.vb_constants.add("wdColorPaleBlue".lower())
        #  Pink color
        self.globals["wdColorPink".lower()] = 16711935
        self.vb_constants.add("wdColorPink".lower())
        #  Plum color
        self.globals["wdColorPlum".lower()] = 6697881
        self.vb_constants.add("wdColorPlum".lower())
        #  Red color
        self.globals["wdColorRed".lower()] = 255
        self.vb_constants.add("wdColorRed".lower())
        #  Rose color
        self.globals["wdColorRose".lower()] = 13408767
        self.vb_constants.add("wdColorRose".lower())
        #  Sea green color
        self.globals["wdColorSeaGreen".lower()] = 6723891
        self.vb_constants.add("wdColorSeaGreen".lower())
        #  Sky blue color
        self.globals["wdColorSkyBlue".lower()] = 16763904
        self.vb_constants.add("wdColorSkyBlue".lower())
        #  Tan color
        self.globals["wdColorTan".lower()] = 10079487
        self.vb_constants.add("wdColorTan".lower())
        #  Teal color
        self.globals["wdColorTeal".lower()] = 8421376
        self.vb_constants.add("wdColorTeal".lower())
        #  Turquoise color
        self.globals["wdColorTurquoise".lower()] = 16776960
        self.vb_constants.add("wdColorTurquoise".lower())
        #  Violet color
        self.globals["wdColorViolet".lower()] = 8388736
        self.vb_constants.add("wdColorViolet".lower())
        #  White color
        self.globals["wdColorWhite".lower()] = 16777215
        self.vb_constants.add("wdColorWhite".lower())
        #  Yellow color
        self.globals["wdColorYellow".lower()] = 65535
        self.vb_constants.add("wdColorYellow".lower())
        
        # WdCompareTarget Enum
        #
        # Specifies the target document for displaying document comparison differences.
        
        #  Places comparison differences in the current document. Default.
        self.globals["wdCompareTargetCurrent".lower()] = 1
        self.vb_constants.add("wdCompareTargetCurrent".lower())
        #  Places comparison differences in a new document.
        self.globals["wdCompareTargetNew".lower()] = 2
        self.vb_constants.add("wdCompareTargetNew".lower())
        #  Places comparison differences in the target document.
        self.globals["wdCompareTargetSelected".lower()] = 0
        self.vb_constants.add("wdCompareTargetSelected".lower())
        
        # WdSmartTagControlType enumeration (Word)
        #   
        # Specifies the type of control associated with a SmartTagAction object.
        
        #  ActiveX control.
        self.globals["wdControlActiveX".lower()] = 13
        self.vb_constants.add("wdControlActiveX".lower())
        #  Button.
        self.globals["wdControlButton".lower()] = 6
        self.vb_constants.add("wdControlButton".lower())
        #  Check box.
        self.globals["wdControlCheckbox".lower()] = 9
        self.vb_constants.add("wdControlCheckbox".lower())
        #  Combo box.
        self.globals["wdControlCombo".lower()] = 12
        self.vb_constants.add("wdControlCombo".lower())
        #  Document fragment.
        self.globals["wdControlDocumentFragment".lower()] = 14
        self.vb_constants.add("wdControlDocumentFragment".lower())
        #  Document fragment URL.
        self.globals["wdControlDocumentFragmentURL".lower()] = 15
        self.vb_constants.add("wdControlDocumentFragmentURL".lower())
        #  Help.
        self.globals["wdControlHelp".lower()] = 3
        self.vb_constants.add("wdControlHelp".lower())
        #  Help URL.
        self.globals["wdControlHelpURL".lower()] = 4
        self.vb_constants.add("wdControlHelpURL".lower())
        #  Image.
        self.globals["wdControlImage".lower()] = 8
        self.vb_constants.add("wdControlImage".lower())
        #  Label.
        self.globals["wdControlLabel".lower()] = 7
        self.vb_constants.add("wdControlLabel".lower())
        #  Link.
        self.globals["wdControlLink".lower()] = 2
        self.vb_constants.add("wdControlLink".lower())
        #  List box.
        self.globals["wdControlListbox".lower()] = 11
        self.vb_constants.add("wdControlListbox".lower())
        #  Radio group.
        self.globals["wdControlRadioGroup".lower()] = 16
        self.vb_constants.add("wdControlRadioGroup".lower())
        #  Separator.
        self.globals["wdControlSeparator".lower()] = 5
        self.vb_constants.add("wdControlSeparator".lower())
        #  Smart tag.
        self.globals["wdControlSmartTag".lower()] = 1
        self.vb_constants.add("wdControlSmartTag".lower())
        #  Text box.
        self.globals["wdControlTextbox".lower()] = 10
        self.vb_constants.add("wdControlTextbox".lower())
        
        # WdDeletedTextMark enumeration (Word)
        #   
        # Specifies the formatting of text that is deleted while change tracking is enabled.
        
        #  Deleted text is displayed in bold.
        self.globals["wdDeletedTextMarkBold".lower()] = 5
        self.vb_constants.add("wdDeletedTextMarkBold".lower())
        #  Deleted text is marked up by using caret characters.
        self.globals["wdDeletedTextMarkCaret".lower()] = 2
        self.vb_constants.add("wdDeletedTextMarkCaret".lower())
        #  Deleted text is displayed in a specified color (default is red).
        self.globals["wdDeletedTextMarkColorOnly".lower()] = 9
        self.vb_constants.add("wdDeletedTextMarkColorOnly".lower())
        #  Deleted text is marked up by using double-underline characters.
        self.globals["wdDeletedTextMarkDoubleUnderline".lower()] = 8
        self.vb_constants.add("wdDeletedTextMarkDoubleUnderline".lower())
        #  Deleted text is hidden.
        self.globals["wdDeletedTextMarkHidden".lower()] = 0
        self.vb_constants.add("wdDeletedTextMarkHidden".lower())
        #  Deleted text is displayed in italic.
        self.globals["wdDeletedTextMarkItalic".lower()] = 6
        self.vb_constants.add("wdDeletedTextMarkItalic".lower())
        #  Deleted text is not marked up.
        self.globals["wdDeletedTextMarkNone".lower()] = 4
        self.vb_constants.add("wdDeletedTextMarkNone".lower())
        #  Deleted text is marked up by using pound characters.
        self.globals["wdDeletedTextMarkPound".lower()] = 3
        self.vb_constants.add("wdDeletedTextMarkPound".lower())
        #  Deleted text is marked up by using strikethrough characters.
        self.globals["wdDeletedTextMarkStrikeThrough".lower()] = 1
        self.vb_constants.add("wdDeletedTextMarkStrikeThrough".lower())
        #  Deleted text is underlined.
        self.globals["wdDeletedTextMarkUnderline".lower()] = 7
        self.vb_constants.add("wdDeletedTextMarkUnderline".lower())
        #  Deleted text is marked up by using double-strikethrough characters.
        self.globals["wdDeletedTextMarkDoubleStrikeThrough".lower()] = 10
        self.vb_constants.add("wdDeletedTextMarkDoubleStrikeThrough".lower())
        
        # WdDiacriticColor enumeration (Word)
        #   
        # Specifies whether to apply a different color to diacritics in bi-directional or Latin style languages.
        
        #  Bi-directional language (Arabic, Hebrew, and so forth).
        self.globals["wdDiacriticColorBidi".lower()] = 0
        self.vb_constants.add("wdDiacriticColorBidi".lower())
        #  Latin style languages.
        self.globals["wdDiacriticColorLatin".lower()] = 1
        self.vb_constants.add("wdDiacriticColorLatin".lower())
        
        # WdWordDialog enumeration (Word)
        #   
        # Indicates the Microsoft Word dialog boxes with which you can work and specifies arguments, if applicable, that you can use to get or set values in a dialog box.
        
        #  (none)
        self.globals["wdDialogBuildingBlockOrganizer".lower()] = 2067
        self.vb_constants.add("wdDialogBuildingBlockOrganizer".lower())
        #  Drive, Path, Password
        self.globals["wdDialogConnect".lower()] = 420
        self.vb_constants.add("wdDialogConnect".lower())
        #  (none)
        self.globals["wdDialogConsistencyChecker".lower()] = 1121
        self.vb_constants.add("wdDialogConsistencyChecker".lower())
        #  (none)
        self.globals["wdDialogContentControlProperties".lower()] = 2394
        self.vb_constants.add("wdDialogContentControlProperties".lower())
        #  Application
        self.globals["wdDialogControlRun".lower()] = 235
        self.vb_constants.add("wdDialogControlRun".lower())
        #  IconNumber, ActivateAs, IconFileName, Caption, Class, DisplayIcon, Floating
        self.globals["wdDialogConvertObject".lower()] = 392
        self.vb_constants.add("wdDialogConvertObject".lower())
        #  FileName, Directory
        self.globals["wdDialogCopyFile".lower()] = 300
        self.vb_constants.add("wdDialogCopyFile".lower())
        #  (none)
        self.globals["wdDialogCreateAutoText".lower()] = 872
        self.vb_constants.add("wdDialogCreateAutoText".lower())
        #  (none)
        self.globals["wdDialogCreateSource".lower()] = 1922
        self.vb_constants.add("wdDialogCreateSource".lower())
        #  LinkStyles
        self.globals["wdDialogCSSLinks".lower()] = 1261
        self.vb_constants.add("wdDialogCSSLinks".lower())
        #  (none)
        self.globals["wdDialogDocumentInspector".lower()] = 1482
        self.vb_constants.add("wdDialogDocumentInspector".lower())
        #  FileName, Directory, Template, Title, Created, LastSaved, LastSavedBy, Revision, Time, Printed, Pages, Words, Characters, Paragraphs, Lines, FileSize
        self.globals["wdDialogDocumentStatistics".lower()] = 78
        self.vb_constants.add("wdDialogDocumentStatistics".lower())
        #  Horizontal, Vertical, RelativeTo
        self.globals["wdDialogDrawAlign".lower()] = 634
        self.vb_constants.add("wdDialogDrawAlign".lower())
        #  SnapToGrid, XGrid, YGrid, XOrigin, YOrigin, SnapToShapes, XGridDisplay, YGridDisplay, FollowMargins, ViewGridLines, DefineLineBasedOnGrid
        self.globals["wdDialogDrawSnapToGrid".lower()] = 633
        self.vb_constants.add("wdDialogDrawSnapToGrid".lower())
        #  Name, Context, InsertAs, Insert, Add, Define, InsertAsText, Delete, CompleteAT
        self.globals["wdDialogEditAutoText".lower()] = 985
        self.vb_constants.add("wdDialogEditAutoText".lower())
        #  Macintosh-only. For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdDialogEditCreatePublisher".lower()] = 732
        self.vb_constants.add("wdDialogEditCreatePublisher".lower())
        #  Find, Replace, Direction, MatchCase, WholeWord, PatternMatch, SoundsLike, FindNext, ReplaceOne, ReplaceAll, Format, Wrap, FindAllWordForms, MatchByte, FuzzyFind, Destination, CorrectEnd, MatchKashida, MatchDiacritics, MatchAlefHamza, MatchControl
        self.globals["wdDialogEditFind".lower()] = 112
        self.vb_constants.add("wdDialogEditFind".lower())
        #  Wrap, WidthRule, FixedWidth, HeightRule, FixedHeight, PositionHorz, PositionHorzRel, DistFromText, PositionVert, PositionVertRel, DistVertFromText, MoveWithText, LockAnchor, RemoveFrame
        self.globals["wdDialogEditFrame".lower()] = 458
        self.vb_constants.add("wdDialogEditFrame".lower())
        #  Find, Replace, Direction, MatchCase, WholeWord, PatternMatch, SoundsLike, FindNext, ReplaceOne, ReplaceAll, Format, Wrap, FindAllWordForms, MatchByte, FuzzyFind, Destination, CorrectEnd, MatchKashida, MatchDiacritics, MatchAlefHamza, MatchControl
        self.globals["wdDialogEditGoTo".lower()] = 896
        self.vb_constants.add("wdDialogEditGoTo".lower())
        #  (none)
        self.globals["wdDialogEditGoToOld".lower()] = 811
        self.vb_constants.add("wdDialogEditGoToOld".lower())
        #  UpdateMode, Locked, SavePictureInDoc, UpdateNow, OpenSource, KillLink, Link, Application, Item, FileName, PreserveFormatLinkUpdate
        self.globals["wdDialogEditLinks".lower()] = 124
        self.vb_constants.add("wdDialogEditLinks".lower())
        #  Verb
        self.globals["wdDialogEditObject".lower()] = 125
        self.vb_constants.add("wdDialogEditObject".lower())
        #  IconNumber, Link, DisplayIcon, Class, DataType, IconFileName, Caption, Floating
        self.globals["wdDialogEditPasteSpecial".lower()] = 111
        self.vb_constants.add("wdDialogEditPasteSpecial".lower())
        #  Macintosh-only. For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdDialogEditPublishOptions".lower()] = 735
        self.vb_constants.add("wdDialogEditPublishOptions".lower())
        #  Find, Replace, Direction, MatchCase, WholeWord, PatternMatch, SoundsLike, FindNext, ReplaceOne, ReplaceAll, Format, Wrap, FindAllWordForms, MatchByte, FuzzyFind, Destination, CorrectEnd, MatchKashida, MatchDiacritics, MatchAlefHamza, MatchControl
        self.globals["wdDialogEditReplace".lower()] = 117
        self.vb_constants.add("wdDialogEditReplace".lower())
        #  (none)
        self.globals["wdDialogEditStyle".lower()] = 120
        self.vb_constants.add("wdDialogEditStyle".lower())
        #  Macintosh-only. For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdDialogEditSubscribeOptions".lower()] = 736
        self.vb_constants.add("wdDialogEditSubscribeOptions".lower())
        #  Macintosh-only. For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdDialogEditSubscribeTo".lower()] = 733
        self.vb_constants.add("wdDialogEditSubscribeTo".lower())
        #  Category, CategoryName
        self.globals["wdDialogEditTOACategory".lower()] = 625
        self.vb_constants.add("wdDialogEditTOACategory".lower())
        #  (none)
        self.globals["wdDialogEmailOptions".lower()] = 863
        self.vb_constants.add("wdDialogEmailOptions".lower())
        #  Tab, PaperSize, TopMargin, BottomMargin, LeftMargin, RightMargin, Gutter, PageWidth, PageHeight, Orientation, FirstPage, OtherPages, VertAlign, ApplyPropsTo, Default, FacingPages, HeaderDistance, FooterDistance, SectionStart, OddAndEvenPages, DifferentFirstPage, Endnotes, LineNum, StartingNum, FromText, CountBy, NumMode, TwoOnOne, GutterPosition, LayoutMode, CharsLine, LinesPage, CharPitch, LinePitch, DocFontName, DocFontSize, PageColumns, TextFlow, FirstPageOnLeft, SectionType, RTLAlignment
        self.globals["wdDialogFileDocumentLayout".lower()] = 178
        self.vb_constants.add("wdDialogFileDocumentLayout".lower())
        #  SearchName, SearchPath, Name, SubDir, Title, Author, Keywords, Subject, Options, MatchCase, Text, PatternMatch, DateSavedFrom, DateSavedTo, SavedBy, DateCreatedFrom, DateCreatedTo, View, SortBy, ListBy, SelectedFile, Add, Delete, ShowFolders, MatchByte
        self.globals["wdDialogFileFind".lower()] = 99
        self.vb_constants.add("wdDialogFileFind".lower())
        #  Macintosh-only. For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdDialogFileMacCustomPageSetupGX".lower()] = 737
        self.vb_constants.add("wdDialogFileMacCustomPageSetupGX".lower())
        #  Macintosh-only. For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdDialogFileMacPageSetup".lower()] = 685
        self.vb_constants.add("wdDialogFileMacPageSetup".lower())
        #  Macintosh-only. For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdDialogFileMacPageSetupGX".lower()] = 444
        self.vb_constants.add("wdDialogFileMacPageSetupGX".lower())
        #  Template, NewTemplate, DocumentType, Visible
        self.globals["wdDialogFileNew".lower()] = 79
        self.vb_constants.add("wdDialogFileNew".lower())
        #  Name, ConfirmConversions, ReadOnly, LinkToSource, AddToMru, PasswordDoc, PasswordDot, Revert, WritePasswordDoc, WritePasswordDot, Connection, SQLStatement, SQLStatement1, Format, Encoding, Visible, OpenExclusive, OpenAndRepair, SubType, DocumentDirection, NoEncodingDialog, XMLTransform
        self.globals["wdDialogFileOpen".lower()] = 80
        self.vb_constants.add("wdDialogFileOpen".lower())
        #  Tab, PaperSize, TopMargin, BottomMargin, LeftMargin, RightMargin, Gutter, PageWidth, PageHeight, Orientation, FirstPage, OtherPages, VertAlign, ApplyPropsTo, Default, FacingPages, HeaderDistance, FooterDistance, SectionStart, OddAndEvenPages, DifferentFirstPage, Endnotes, LineNum, StartingNum, FromText, CountBy, NumMode, TwoOnOne, GutterPosition, LayoutMode, CharsLine, LinesPage, CharPitch, LinePitch, DocFontName, DocFontSize, PageColumns, TextFlow, FirstPageOnLeft, SectionType, RTLAlignment, FolioPrint
        self.globals["wdDialogFilePageSetup".lower()] = 178
        self.vb_constants.add("wdDialogFilePageSetup".lower())
        #  Background, AppendPrFile, Range, PrToFileName, From, To, Type, NumCopies, Pages, Order, PrintToFile, Collate, FileName, Printer, OutputPrinter, DuplexPrint, PrintZoomColumn, PrintZoomRow, PrintZoomPaperWidth, PrintZoomPaperHeight, ZoomPaper
        self.globals["wdDialogFilePrint".lower()] = 88
        self.vb_constants.add("wdDialogFilePrint".lower())
        #  Macintosh-only. For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdDialogFilePrintOneCopy".lower()] = 445
        self.vb_constants.add("wdDialogFilePrintOneCopy".lower())
        #  Printer, Options, Network, DoNotSetAsSysDefault
        self.globals["wdDialogFilePrintSetup".lower()] = 97
        self.vb_constants.add("wdDialogFilePrintSetup".lower())
        #  Subject, Message, AllAtOnce, ReturnWhenDone, TrackStatus, Protect, AddSlip, RouteDocument, AddRecipient, OldRecipient, ResetSlip, ClearSlip, ClearRecipients, Address
        self.globals["wdDialogFileRoutingSlip".lower()] = 624
        self.vb_constants.add("wdDialogFileRoutingSlip".lower())
        #  Name, Format, LockAnnot, Password, AddToMru, WritePassword, RecommendReadOnly, EmbedFonts, NativePictureFormat, FormsData, SaveAsAOCELetter, WriteVersion, VersionDesc, InsertLineBreaks, AllowSubstitutions, LineEnding, AddBiDiMarks
        self.globals["wdDialogFileSaveAs".lower()] = 84
        self.vb_constants.add("wdDialogFileSaveAs".lower())
        #  (none)
        self.globals["wdDialogFileSaveVersion".lower()] = 1007
        self.vb_constants.add("wdDialogFileSaveVersion".lower())
        #  Title, Subject, Author, Keywords, Comments, FileName, Directory, Template, CreateDate, LastSavedDate, LastSavedBy, RevisionNumber, EditTime, LastPrintedDate, NumPages, NumWords, NumChars, NumParas, NumLines, Update, FileSize
        self.globals["wdDialogFileSummaryInfo".lower()] = 86
        self.vb_constants.add("wdDialogFileSummaryInfo".lower())
        #  AutoVersion, VersionDesc
        self.globals["wdDialogFileVersions".lower()] = 945
        self.vb_constants.add("wdDialogFileVersions".lower())
        #  FitTextWidth
        self.globals["wdDialogFitText".lower()] = 983
        self.vb_constants.add("wdDialogFitText".lower())
        #  UnavailableFont, SubstituteFont
        self.globals["wdDialogFontSubstitution".lower()] = 581
        self.vb_constants.add("wdDialogFontSubstitution".lower())
        #  Points, Underline, Color, StrikeThrough, Superscript, Subscript, Hidden, SmallCaps, AllCaps, Spacing, Position, Kerning, KerningMin, Default, Tab, Font, Bold, Italic, DoubleStrikeThrough, Shadow, Outline, Emboss, Engrave, Scale, Animations, CharAccent, FontMajor, FontLowAnsi, FontHighAnsi, CharacterWidthGrid, ColorRGB, UnderlineColor, PointsBi, ColorBi, FontNameBi, BoldBi, ItalicBi, DiacColor
        self.globals["wdDialogFormatAddrFonts".lower()] = 103
        self.vb_constants.add("wdDialogFormatAddrFonts".lower())
        #  ApplyTo, Shadow, TopBorder, LeftBorder, BottomBorder, RightBorder, HorizBorder, VertBorder, TopColor, LeftColor, BottomColor, RightColor, HorizColor, VertColor, FromText, Shading, Foreground, Background, Tab, FineShading, TopStyle, LeftStyle, BottomStyle, RightStyle, HorizStyle, VertStyle, TopWeight, LeftWeight, BottomWeight, RightWeight, HorizWeight, VertWeight, BorderObjectType, BorderArtWeight, BorderArt, FromTextTop, FromTextBottom, FromTextLeft, FromTextRight, OffsetFrom, InFront, SurroundHeader, SurroundFooter, JoinBorder, LineColor, WhichPages, TL2BRBorder, TR2BLBorder, TL2BRColor, TR2BLColor, TL2BRStyle, TR2BLStyle, TL2BRWeight, TR2BLWeight, ForegroundRGB, BackgroundRGB, TopColorRGB, LeftColorRGB, BottomColorRGB, RightColorRGB, HorizColorRGB, VertColorRGB, TL2BRColorRGB, TR2BLColorRGB, LineColorRGB
        self.globals["wdDialogFormatBordersAndShading".lower()] = 189
        self.vb_constants.add("wdDialogFormatBordersAndShading".lower())
        #  (none)
        self.globals["wdDialogFormatBulletsAndNumbering".lower()] = 824
        self.vb_constants.add("wdDialogFormatBulletsAndNumbering".lower())
        #  Type, Gap, Angle, Drop, Length, Border, AutoAttach, Accent
        self.globals["wdDialogFormatCallout".lower()] = 610
        self.vb_constants.add("wdDialogFormatCallout".lower())
        #  Type
        self.globals["wdDialogFormatChangeCase".lower()] = 322
        self.vb_constants.add("wdDialogFormatChangeCase".lower())
        #  Columns, ColumnNo, ColumnWidth, ColumnSpacing, EvenlySpaced, ApplyColsTo, ColLine, StartNewCol, FlowColumnsRtl
        self.globals["wdDialogFormatColumns".lower()] = 177
        self.vb_constants.add("wdDialogFormatColumns".lower())
        #  ApplyTo, Shadow, TopBorder, LeftBorder, BottomBorder, RightBorder, HorizBorder, VertBorder, TopColor, LeftColor, BottomColor, RightColor, HorizColor, VertColor, FromText, Shading, Foreground, Background, Tab, FineShading, TopStyle, LeftStyle, BottomStyle, RightStyle, HorizStyle, VertStyle, TopWeight, LeftWeight, BottomWeight, RightWeight, HorizWeight, VertWeight, BorderObjectType, BorderArtWeight, BorderArt, FromTextTop, FromTextBottom, FromTextLeft, FromTextRight, OffsetFrom, InFront, SurroundHeader, SurroundFooter, JoinBorder, LineColor, WhichPages, TL2BRBorder, TR2BLBorder, TL2BRColor, TR2BLColor, TL2BRStyle, TR2BLStyle, TL2BRWeight, TR2BLWeight, ForegroundRGB, BackgroundRGB, TopColorRGB, LeftColorRGB, BottomColorRGB, RightColorRGB, HorizColorRGB, VertColorRGB, TL2BRColorRGB, TR2BLColorRGB, LineColorRGB
        self.globals["wdDialogFormatDefineStyleBorders".lower()] = 185
        self.vb_constants.add("wdDialogFormatDefineStyleBorders".lower())
        #  Points, Underline, Color, StrikeThrough, Superscript, Subscript, Hidden, SmallCaps, AllCaps, Spacing, Position, Kerning, KerningMin, Default, Tab, Font, Bold, Italic, DoubleStrikeThrough, Shadow, Outline, Emboss, Engrave, Scale, Animations, CharAccent, FontMajor, FontLowAnsi, FontHighAnsi, CharacterWidthGrid, ColorRGB, UnderlineColor, PointsBi, ColorBi, FontNameBi, BoldBi, ItalicBi, DiacColor
        self.globals["wdDialogFormatDefineStyleFont".lower()] = 181
        self.vb_constants.add("wdDialogFormatDefineStyleFont".lower())
        #  Wrap, WidthRule, FixedWidth, HeightRule, FixedHeight, PositionHorz, PositionHorzRel, DistFromText, PositionVert, PositionVertRel, DistVertFromText, MoveWithText, LockAnchor, RemoveFrame
        self.globals["wdDialogFormatDefineStyleFrame".lower()] = 184
        self.vb_constants.add("wdDialogFormatDefineStyleFrame".lower())
        #  Language, CheckLanguage, Default, NoProof
        self.globals["wdDialogFormatDefineStyleLang".lower()] = 186
        self.vb_constants.add("wdDialogFormatDefineStyleLang".lower())
        #  LeftIndent, RightIndent, Before, After, LineSpacingRule, LineSpacing, Alignment, WidowControl, KeepWithNext, KeepTogether, PageBreak, NoLineNum, DontHyphen, Tab, FirstIndent, OutlineLevel, Kinsoku, WordWrap, OverflowPunct, TopLinePunct, AutoSpaceDE, LineHeightGrid, AutoSpaceDN, CharAlign, CharacterUnitLeftIndent, AdjustRight, CharacterUnitFirstIndent, CharacterUnitRightIndent, LineUnitBefore, LineUnitAfter, NoSpaceBetweenParagraphsOfSameStyle, OrientationBi
        self.globals["wdDialogFormatDefineStylePara".lower()] = 182
        self.vb_constants.add("wdDialogFormatDefineStylePara".lower())
        #  Position, DefTabs, Align, Leader, Set, Clear, ClearAll
        self.globals["wdDialogFormatDefineStyleTabs".lower()] = 183
        self.vb_constants.add("wdDialogFormatDefineStyleTabs".lower())
        #  Left, PositionHorzRel, Top, PositionVertRel, LockAnchor, FloatOverText, LayoutInCell, WrapSide, TopDistanceFromText, BottomDistanceFromText, LeftDistanceFromText, RightDistanceFromText, Wrap, WordWrap, AutoSize, HRWidthType, HRHeight, HRNoshade, HRAlign, Text, AllowOverlap, HorizRule
        self.globals["wdDialogFormatDrawingObject".lower()] = 960
        self.vb_constants.add("wdDialogFormatDrawingObject".lower())
        #  Position, Font, DropHeight, DistFromText
        self.globals["wdDialogFormatDropCap".lower()] = 488
        self.vb_constants.add("wdDialogFormatDropCap".lower())
        #  Style, Text, Enclosure
        self.globals["wdDialogFormatEncloseCharacters".lower()] = 1162
        self.vb_constants.add("wdDialogFormatEncloseCharacters".lower())
        #  Points, Underline, Color, StrikeThrough, Superscript, Subscript, Hidden, SmallCaps, AllCaps, Spacing, Position, Kerning, KerningMin, Default, Tab, Font, Bold, Italic, DoubleStrikeThrough, Shadow, Outline, Emboss, Engrave, Scale, Animations, CharAccent, FontMajor, FontLowAnsi, FontHighAnsi, CharacterWidthGrid, ColorRGB, UnderlineColor, PointsBi, ColorBi, FontNameBi, BoldBi, ItalicBi, DiacColor
        self.globals["wdDialogFormatFont".lower()] = 174
        self.vb_constants.add("wdDialogFormatFont".lower())
        #  Wrap, WidthRule, FixedWidth, HeightRule, FixedHeight, PositionHorz, PositionHorzRel, DistFromText, PositionVert, PositionVertRel, DistVertFromText, MoveWithText, LockAnchor, RemoveFrame
        self.globals["wdDialogFormatFrame".lower()] = 190
        self.vb_constants.add("wdDialogFormatFrame".lower())
        #  ChapterNumber, NumRestart, NumFormat, StartingNum, Level, Separator, DoubleQuote, PgNumberingStyle
        self.globals["wdDialogFormatPageNumber".lower()] = 298
        self.vb_constants.add("wdDialogFormatPageNumber".lower())
        #  LeftIndent, RightIndent, Before, After, LineSpacingRule, LineSpacing, Alignment, WidowControl, KeepWithNext, KeepTogether, PageBreak, NoLineNum, DontHyphen, Tab, FirstIndent, OutlineLevel, Kinsoku, WordWrap, OverflowPunct, TopLinePunct, AutoSpaceDE, LineHeightGrid, AutoSpaceDN, CharAlign, CharacterUnitLeftIndent, AdjustRight, CharacterUnitFirstIndent, CharacterUnitRightIndent, LineUnitBefore, LineUnitAfter, NoSpaceBetweenParagraphsOfSameStyle, OrientationBi
        self.globals["wdDialogFormatParagraph".lower()] = 175
        self.vb_constants.add("wdDialogFormatParagraph".lower())
        #  SetSize, CropLeft, CropRight, CropTop, CropBottom, ScaleX, ScaleY, SizeX, SizeY
        self.globals["wdDialogFormatPicture".lower()] = 187
        self.vb_constants.add("wdDialogFormatPicture".lower())
        #  Points, Underline, Color, StrikeThrough, Superscript, Subscript, Hidden, SmallCaps, AllCaps, Spacing, Position, Kerning, KerningMin, Default, Tab, Font, Bold, Italic, DoubleStrikeThrough, Shadow, Outline, Emboss, Engrave, Scale, Animations, CharAccent, FontMajor, FontLowAnsi, FontHighAnsi, CharacterWidthGrid, ColorRGB, UnderlineColor, PointsBi, ColorBi, FontNameBi, BoldBi, ItalicBi, DiacColor
        self.globals["wdDialogFormatRetAddrFonts".lower()] = 221
        self.vb_constants.add("wdDialogFormatRetAddrFonts".lower())
        #  SectionStart, VertAlign, Endnotes, LineNum, StartingNum, FromText, CountBy, NumMode, SectionType
        self.globals["wdDialogFormatSectionLayout".lower()] = 176
        self.vb_constants.add("wdDialogFormatSectionLayout".lower())
        #  Name, Delete, Merge, NewName, BasedOn, NextStyle, Type, FileName, Source, AddToTemplate, Define, Rename, Apply, New, Link
        self.globals["wdDialogFormatStyle".lower()] = 180
        self.vb_constants.add("wdDialogFormatStyle".lower())
        #  Template, Preview
        self.globals["wdDialogFormatStyleGallery".lower()] = 505
        self.vb_constants.add("wdDialogFormatStyleGallery".lower())
        #  (none)
        self.globals["wdDialogFormatStylesCustom".lower()] = 1248
        self.vb_constants.add("wdDialogFormatStylesCustom".lower())
        #  Position, DefTabs, Align, Leader, Set, Clear, ClearAll
        self.globals["wdDialogFormatTabs".lower()] = 179
        self.vb_constants.add("wdDialogFormatTabs".lower())
        #  (none)
        self.globals["wdDialogFormatTheme".lower()] = 855
        self.vb_constants.add("wdDialogFormatTheme".lower())
        #  (none)
        self.globals["wdDialogFormattingRestrictions".lower()] = 1427
        self.vb_constants.add("wdDialogFormattingRestrictions".lower())
        #  (none)
        self.globals["wdDialogFormFieldHelp".lower()] = 361
        self.vb_constants.add("wdDialogFormFieldHelp".lower())
        #  Entry, Exit, Name, Enable, TextType, TextWidth, TextDefault, TextFormat, CheckSize, CheckWidth, CheckDefault, Type, OwnHelp, HelpText, OwnStat, StatText, Calculate
        self.globals["wdDialogFormFieldOptions".lower()] = 353
        self.vb_constants.add("wdDialogFormFieldOptions".lower())
        #  (none)
        self.globals["wdDialogFrameSetProperties".lower()] = 1074
        self.vb_constants.add("wdDialogFrameSetProperties".lower())
        #  APPNAME, APPCOPYRIGHT, APPUSERNAME, APPORGANIZATION, APPSERIALNUMBER
        self.globals["wdDialogHelpAbout".lower()] = 9
        self.vb_constants.add("wdDialogHelpAbout".lower())
        #  WPCommand, HelpText, DemoGuidance
        self.globals["wdDialogHelpWordPerfectHelp".lower()] = 10
        self.vb_constants.add("wdDialogHelpWordPerfectHelp".lower())
        #  CommandKeyHelp, DocNavKeys, MouseSimulation, DemoGuidance, DemoSpeed, HelpType
        self.globals["wdDialogHelpWordPerfectHelpOptions".lower()] = 511
        self.vb_constants.add("wdDialogHelpWordPerfectHelpOptions".lower())
        #  (none)
        self.globals["wdDialogHorizontalInVertical".lower()] = 1160
        self.vb_constants.add("wdDialogHorizontalInVertical".lower())
        #  (none)
        self.globals["wdDialogIMESetDefault".lower()] = 1094
        self.vb_constants.add("wdDialogIMESetDefault".lower())
        #  Name
        self.globals["wdDialogInsertAddCaption".lower()] = 402
        self.vb_constants.add("wdDialogInsertAddCaption".lower())
        #  Clear, ClearAll, Object, Label, Position
        self.globals["wdDialogInsertAutoCaption".lower()] = 359
        self.vb_constants.add("wdDialogInsertAutoCaption".lower())
        #  Name, SortBy, Add, Delete, Goto, Hidden
        self.globals["wdDialogInsertBookmark".lower()] = 168
        self.vb_constants.add("wdDialogInsertBookmark".lower())
        #  Type
        self.globals["wdDialogInsertBreak".lower()] = 159
        self.vb_constants.add("wdDialogInsertBreak".lower())
        #  Label, TitleAutoText, Title, Delete, Position, AutoCaption, ExcludeLabel
        self.globals["wdDialogInsertCaption".lower()] = 357
        self.vb_constants.add("wdDialogInsertCaption".lower())
        #  Label, FormatNumber, ChapterNumber, Level, Separator, CapNumberingStyle
        self.globals["wdDialogInsertCaptionNumbering".lower()] = 358
        self.vb_constants.add("wdDialogInsertCaptionNumbering".lower())
        #  ReferenceType, ReferenceKind, ReferenceItem, InsertAsHyperLink, InsertPosition, SeparateNumbers, SeparatorCharacters
        self.globals["wdDialogInsertCrossReference".lower()] = 367
        self.vb_constants.add("wdDialogInsertCrossReference".lower())
        #  Format, Style, LinkToSource, Connection, SQLStatement, SQLStatement1, PasswordDoc, PasswordDot, DataSource, From, To, IncludeFields, WritePasswordDoc, WritePasswordDot
        self.globals["wdDialogInsertDatabase".lower()] = 341
        self.vb_constants.add("wdDialogInsertDatabase".lower())
        #  DateTimePic, InsertAsField, DbCharField, DateLanguage, CalendarType
        self.globals["wdDialogInsertDateTime".lower()] = 165
        self.vb_constants.add("wdDialogInsertDateTime".lower())
        #  Field
        self.globals["wdDialogInsertField".lower()] = 166
        self.vb_constants.add("wdDialogInsertField".lower())
        #  Name, Range, ConfirmConversions, Link, Attachment
        self.globals["wdDialogInsertFile".lower()] = 164
        self.vb_constants.add("wdDialogInsertFile".lower())
        #  Reference, NoteType, Symbol, FootNumberAs, EndNumberAs, FootnotesAt, EndnotesAt, FootNumberingStyle, EndNumberingStyle, FootStartingNum, FootRestartNum, EndStartingNum, EndRestartNum, ApplyPropsTo
        self.globals["wdDialogInsertFootnote".lower()] = 370
        self.vb_constants.add("wdDialogInsertFootnote".lower())
        #  Entry, Exit, Name, Enable, TextType, TextWidth, TextDefault, TextFormat, CheckSize, CheckWidth, CheckDefault, Type, OwnHelp, HelpText, OwnStat, StatText, Calculate
        self.globals["wdDialogInsertFormField".lower()] = 483
        self.vb_constants.add("wdDialogInsertFormField".lower())
        #  (none)
        self.globals["wdDialogInsertHyperlink".lower()] = 925
        self.vb_constants.add("wdDialogInsertHyperlink".lower())
        #  Outline, Fields, From, To, TableId, AddedStyles, Caption, HeadingSeparator, Replace, MarkEntry, AutoMark, MarkCitation, Type, RightAlignPageNumbers, Passim, KeepFormatting, Columns, Category, Label, ShowPageNumbers, AccentedLetters, Filter, SortBy, Leader, TOCUseHyperlinks, TOCHidePageNumInWeb, IndexLanguage, UseOutlineLevel
        self.globals["wdDialogInsertIndex".lower()] = 170
        self.vb_constants.add("wdDialogInsertIndex".lower())
        #  Outline, Fields, From, To, TableId, AddedStyles, Caption, HeadingSeparator, Replace, MarkEntry, AutoMark, MarkCitation, Type, RightAlignPageNumbers, Passim, KeepFormatting, Columns, Category, Label, ShowPageNumbers, AccentedLetters, Filter, SortBy, Leader, TOCUseHyperlinks, TOCHidePageNumInWeb, IndexLanguage, UseOutlineLevel
        self.globals["wdDialogInsertIndexAndTables".lower()] = 473
        self.vb_constants.add("wdDialogInsertIndexAndTables".lower())
        #  MergeField, WordField
        self.globals["wdDialogInsertMergeField".lower()] = 167
        self.vb_constants.add("wdDialogInsertMergeField".lower())
        #  NumPic
        self.globals["wdDialogInsertNumber".lower()] = 812
        self.vb_constants.add("wdDialogInsertNumber".lower())
        #  IconNumber, FileName, Link, DisplayIcon, Tab, Class, IconFileName, Caption, Floating
        self.globals["wdDialogInsertObject".lower()] = 172
        self.vb_constants.add("wdDialogInsertObject".lower())
        #  Type, Position, FirstPage
        self.globals["wdDialogInsertPageNumbers".lower()] = 294
        self.vb_constants.add("wdDialogInsertPageNumbers".lower())
        #  Name, LinkToFile, New, FloatOverText
        self.globals["wdDialogInsertPicture".lower()] = 163
        self.vb_constants.add("wdDialogInsertPicture".lower())
        #  (none)
        self.globals["wdDialogInsertPlaceholder".lower()] = 2348
        self.vb_constants.add("wdDialogInsertPlaceholder".lower())
        #  (none)
        self.globals["wdDialogInsertSource".lower()] = 2120
        self.vb_constants.add("wdDialogInsertSource".lower())
        #  Name, ConfirmConversions, ReadOnly, LinkToSource, AddToMru, PasswordDoc, PasswordDot, Revert, WritePasswordDoc, WritePasswordDot, Connection, SQLStatement, SQLStatement1, Format, Encoding, Visible, OpenExclusive, OpenAndRepair, SubType, DocumentDirection, NoEncodingDialog, XMLTransform
        self.globals["wdDialogInsertSubdocument".lower()] = 583
        self.vb_constants.add("wdDialogInsertSubdocument".lower())
        #  Font, Tab, CharNum, CharNumLow, Unicode, Hint
        self.globals["wdDialogInsertSymbol".lower()] = 162
        self.vb_constants.add("wdDialogInsertSymbol".lower())
        #  Outline, Fields, From, To, TableId, AddedStyles, Caption, HeadingSeparator, Replace, MarkEntry, AutoMark, MarkCitation, Type, RightAlignPageNumbers, Passim, KeepFormatting, Columns, Category, Label, ShowPageNumbers, AccentedLetters, Filter, SortBy, Leader, TOCUseHyperlinks, TOCHidePageNumInWeb, IndexLanguage, UseOutlineLevel
        self.globals["wdDialogInsertTableOfAuthorities".lower()] = 471
        self.vb_constants.add("wdDialogInsertTableOfAuthorities".lower())
        #  Outline, Fields, From, To, TableId, AddedStyles, Caption, HeadingSeparator, Replace, MarkEntry, AutoMark, MarkCitation, Type, RightAlignPageNumbers, Passim, KeepFormatting, Columns, Category, Label, ShowPageNumbers, AccentedLetters, Filter, SortBy, Leader, TOCUseHyperlinks, TOCHidePageNumInWeb, IndexLanguage, UseOutlineLevel
        self.globals["wdDialogInsertTableOfContents".lower()] = 171
        self.vb_constants.add("wdDialogInsertTableOfContents".lower())
        #  Outline, Fields, From, To, TableId, AddedStyles, Caption, HeadingSeparator, Replace, MarkEntry, AutoMark, MarkCitation, Type, RightAlignPageNumbers, Passim, KeepFormatting, Columns, Category, Label, ShowPageNumbers, AccentedLetters, Filter, SortBy, Leader, TOCUseHyperlinks, TOCHidePageNumInWeb, IndexLanguage, UseOutlineLevel
        self.globals["wdDialogInsertTableOfFigures".lower()] = 472
        self.vb_constants.add("wdDialogInsertTableOfFigures".lower())
        #  IconNumber, FileName, Link, DisplayIcon, Tab, Class, IconFileName, Caption, Floating
        self.globals["wdDialogInsertWebComponent".lower()] = 1324
        self.vb_constants.add("wdDialogInsertWebComponent".lower())
        #  (none)
        self.globals["wdDialogLabelOptions".lower()] = 1367
        self.vb_constants.add("wdDialogLabelOptions".lower())
        #  SenderCity, DateFormat, IncludeHeaderFooter, LetterStyle, Letterhead, LetterheadLocation, LetterheadSize, RecipientName, RecipientAddress, Salutation, SalutationType, RecipientGender, RecipientReference, MailingInstructions, AttentionLine, LetterSubject, CCList, SenderName, ReturnAddress, Closing, SenderJobTitle, SenderCompany, SenderInitials, EnclosureNumber, PageDesign, InfoBlock, SenderGender, ReturnAddressSF, RecipientCode, SenderCode, SenderReference
        self.globals["wdDialogLetterWizard".lower()] = 821
        self.vb_constants.add("wdDialogLetterWizard".lower())
        #  ListType
        self.globals["wdDialogListCommands".lower()] = 723
        self.vb_constants.add("wdDialogListCommands".lower())
        #  CheckErrors, Destination, MergeRecords, From, To, Suppression, MailMerge, QueryOptions, MailSubject, MailAsAttachment, MailAddress
        self.globals["wdDialogMailMerge".lower()] = 676
        self.vb_constants.add("wdDialogMailMerge".lower())
        #  CheckErrors
        self.globals["wdDialogMailMergeCheck".lower()] = 677
        self.vb_constants.add("wdDialogMailMergeCheck".lower())
        #  FileName, PasswordDoc, PasswordDot, HeaderRecord, MSQuery, SQLStatement, SQLStatement1, Connection, LinkToSource, WritePasswordDoc
        self.globals["wdDialogMailMergeCreateDataSource".lower()] = 642
        self.vb_constants.add("wdDialogMailMergeCreateDataSource".lower())
        #  FileName, PasswordDoc, PasswordDot, HeaderRecord, MSQuery, SQLStatement, SQLStatement1, Connection, LinkToSource, WritePasswordDoc
        self.globals["wdDialogMailMergeCreateHeaderSource".lower()] = 643
        self.vb_constants.add("wdDialogMailMergeCreateHeaderSource".lower())
        #  (none)
        self.globals["wdDialogMailMergeFieldMapping".lower()] = 1304
        self.vb_constants.add("wdDialogMailMergeFieldMapping".lower())
        #  (none)
        self.globals["wdDialogMailMergeFindRecipient".lower()] = 1326
        self.vb_constants.add("wdDialogMailMergeFindRecipient".lower())
        #  (none)
        self.globals["wdDialogMailMergeFindRecord".lower()] = 569
        self.vb_constants.add("wdDialogMailMergeFindRecord".lower())
        #  (none)
        self.globals["wdDialogMailMergeHelper".lower()] = 680
        self.vb_constants.add("wdDialogMailMergeHelper".lower())
        #  (none)
        self.globals["wdDialogMailMergeInsertAddressBlock".lower()] = 1305
        self.vb_constants.add("wdDialogMailMergeInsertAddressBlock".lower())
        #  (none)
        self.globals["wdDialogMailMergeInsertAsk".lower()] = 4047
        self.vb_constants.add("wdDialogMailMergeInsertAsk".lower())
        #  (none)
        self.globals["wdDialogMailMergeInsertFields".lower()] = 1307
        self.vb_constants.add("wdDialogMailMergeInsertFields".lower())
        #  (none)
        self.globals["wdDialogMailMergeInsertFillIn".lower()] = 4048
        self.vb_constants.add("wdDialogMailMergeInsertFillIn".lower())
        #  (none)
        self.globals["wdDialogMailMergeInsertGreetingLine".lower()] = 1306
        self.vb_constants.add("wdDialogMailMergeInsertGreetingLine".lower())
        #  (none)
        self.globals["wdDialogMailMergeInsertIf".lower()] = 4049
        self.vb_constants.add("wdDialogMailMergeInsertIf".lower())
        #  (none)
        self.globals["wdDialogMailMergeInsertNextIf".lower()] = 4053
        self.vb_constants.add("wdDialogMailMergeInsertNextIf".lower())
        #  (none)
        self.globals["wdDialogMailMergeInsertSet".lower()] = 4054
        self.vb_constants.add("wdDialogMailMergeInsertSet".lower())
        #  (none)
        self.globals["wdDialogMailMergeInsertSkipIf".lower()] = 4055
        self.vb_constants.add("wdDialogMailMergeInsertSkipIf".lower())
        #  (none)
        self.globals["wdDialogMailMergeOpenDataSource".lower()] = 81
        self.vb_constants.add("wdDialogMailMergeOpenDataSource".lower())
        #  (none)
        self.globals["wdDialogMailMergeOpenHeaderSource".lower()] = 82
        self.vb_constants.add("wdDialogMailMergeOpenHeaderSource".lower())
        #  (none)
        self.globals["wdDialogMailMergeQueryOptions".lower()] = 681
        self.vb_constants.add("wdDialogMailMergeQueryOptions".lower())
        #  (none)
        self.globals["wdDialogMailMergeRecipients".lower()] = 1308
        self.vb_constants.add("wdDialogMailMergeRecipients".lower())
        #  (none)
        self.globals["wdDialogMailMergeSetDocumentType".lower()] = 1339
        self.vb_constants.add("wdDialogMailMergeSetDocumentType".lower())
        #  (none)
        self.globals["wdDialogMailMergeUseAddressBook".lower()] = 779
        self.vb_constants.add("wdDialogMailMergeUseAddressBook".lower())
        #  (none)
        self.globals["wdDialogMarkCitation".lower()] = 463
        self.vb_constants.add("wdDialogMarkCitation".lower())
        #  (none)
        self.globals["wdDialogMarkIndexEntry".lower()] = 169
        self.vb_constants.add("wdDialogMarkIndexEntry".lower())
        #  (none)
        self.globals["wdDialogMarkTableOfContentsEntry".lower()] = 442
        self.vb_constants.add("wdDialogMarkTableOfContentsEntry".lower())
        #  (none)
        self.globals["wdDialogMyPermission".lower()] = 1437
        self.vb_constants.add("wdDialogMyPermission".lower())
        #  (none)
        self.globals["wdDialogNewToolbar".lower()] = 586
        self.vb_constants.add("wdDialogNewToolbar".lower())
        #  (none)
        self.globals["wdDialogNoteOptions".lower()] = 373
        self.vb_constants.add("wdDialogNoteOptions".lower())
        #  (none)
        self.globals["wdDialogOMathRecognizedFunctions".lower()] = 2165
        self.vb_constants.add("wdDialogOMathRecognizedFunctions".lower())
        #  (none)
        self.globals["wdDialogOrganizer".lower()] = 222
        self.vb_constants.add("wdDialogOrganizer".lower())
        #  (none)
        self.globals["wdDialogPermission".lower()] = 1469
        self.vb_constants.add("wdDialogPermission".lower())
        #  (none)
        self.globals["wdDialogPhoneticGuide".lower()] = 986
        self.vb_constants.add("wdDialogPhoneticGuide".lower())
        #  (none)
        self.globals["wdDialogReviewAfmtRevisions".lower()] = 570
        self.vb_constants.add("wdDialogReviewAfmtRevisions".lower())
        #  (none)
        self.globals["wdDialogSchemaLibrary".lower()] = 1417
        self.vb_constants.add("wdDialogSchemaLibrary".lower())
        #  (none)
        self.globals["wdDialogSearch".lower()] = 1363
        self.vb_constants.add("wdDialogSearch".lower())
        #  (none)
        self.globals["wdDialogShowRepairs".lower()] = 1381
        self.vb_constants.add("wdDialogShowRepairs".lower())
        #  (none)
        self.globals["wdDialogSourceManager".lower()] = 1920
        self.vb_constants.add("wdDialogSourceManager".lower())
        #  (none)
        self.globals["wdDialogStyleManagement".lower()] = 1948
        self.vb_constants.add("wdDialogStyleManagement".lower())
        #  (none)
        self.globals["wdDialogTableAutoFormat".lower()] = 563
        self.vb_constants.add("wdDialogTableAutoFormat".lower())
        #  (none)
        self.globals["wdDialogTableCellOptions".lower()] = 1081
        self.vb_constants.add("wdDialogTableCellOptions".lower())
        #  (none)
        self.globals["wdDialogTableColumnWidth".lower()] = 143
        self.vb_constants.add("wdDialogTableColumnWidth".lower())
        #  (none)
        self.globals["wdDialogTableDeleteCells".lower()] = 133
        self.vb_constants.add("wdDialogTableDeleteCells".lower())
        #  (none)
        self.globals["wdDialogTableFormatCell".lower()] = 612
        self.vb_constants.add("wdDialogTableFormatCell".lower())
        #  (none)
        self.globals["wdDialogTableFormula".lower()] = 348
        self.vb_constants.add("wdDialogTableFormula".lower())
        #  (none)
        self.globals["wdDialogTableInsertCells".lower()] = 130
        self.vb_constants.add("wdDialogTableInsertCells".lower())
        #  (none)
        self.globals["wdDialogTableInsertRow".lower()] = 131
        self.vb_constants.add("wdDialogTableInsertRow".lower())
        #  (none)
        self.globals["wdDialogTableInsertTable".lower()] = 129
        self.vb_constants.add("wdDialogTableInsertTable".lower())
        #  (none)
        self.globals["wdDialogTableOfCaptionsOptions".lower()] = 551
        self.vb_constants.add("wdDialogTableOfCaptionsOptions".lower())
        #  (none)
        self.globals["wdDialogTableOfContentsOptions".lower()] = 470
        self.vb_constants.add("wdDialogTableOfContentsOptions".lower())
        #  (none)
        self.globals["wdDialogTableProperties".lower()] = 861
        self.vb_constants.add("wdDialogTableProperties".lower())
        #  (none)
        self.globals["wdDialogTableRowHeight".lower()] = 142
        self.vb_constants.add("wdDialogTableRowHeight".lower())
        #  (none)
        self.globals["wdDialogTableSort".lower()] = 199
        self.vb_constants.add("wdDialogTableSort".lower())
        #  (none)
        self.globals["wdDialogTableSplitCells".lower()] = 137
        self.vb_constants.add("wdDialogTableSplitCells".lower())
        #  (none)
        self.globals["wdDialogTableTableOptions".lower()] = 1080
        self.vb_constants.add("wdDialogTableTableOptions".lower())
        #  (none)
        self.globals["wdDialogTableToText".lower()] = 128
        self.vb_constants.add("wdDialogTableToText".lower())
        #  (none)
        self.globals["wdDialogTableWrapping".lower()] = 854
        self.vb_constants.add("wdDialogTableWrapping".lower())
        #  (none)
        self.globals["wdDialogTCSCTranslator".lower()] = 1156
        self.vb_constants.add("wdDialogTCSCTranslator".lower())
        #  (none)
        self.globals["wdDialogTextToTable".lower()] = 127
        self.vb_constants.add("wdDialogTextToTable".lower())
        #  (none)
        self.globals["wdDialogToolsAcceptRejectChanges".lower()] = 506
        self.vb_constants.add("wdDialogToolsAcceptRejectChanges".lower())
        #  (none)
        self.globals["wdDialogToolsAdvancedSettings".lower()] = 206
        self.vb_constants.add("wdDialogToolsAdvancedSettings".lower())
        #  (none)
        self.globals["wdDialogToolsAutoCorrect".lower()] = 378
        self.vb_constants.add("wdDialogToolsAutoCorrect".lower())
        #  (none)
        self.globals["wdDialogToolsAutoCorrectExceptions".lower()] = 762
        self.vb_constants.add("wdDialogToolsAutoCorrectExceptions".lower())
        #  (none)
        self.globals["wdDialogToolsAutoManager".lower()] = 915
        self.vb_constants.add("wdDialogToolsAutoManager".lower())
        #  (none)
        self.globals["wdDialogToolsAutoSummarize".lower()] = 874
        self.vb_constants.add("wdDialogToolsAutoSummarize".lower())
        #  (none)
        self.globals["wdDialogToolsBulletsNumbers".lower()] = 196
        self.vb_constants.add("wdDialogToolsBulletsNumbers".lower())
        #  (none)
        self.globals["wdDialogToolsCompareDocuments".lower()] = 198
        self.vb_constants.add("wdDialogToolsCompareDocuments".lower())
        #  (none)
        self.globals["wdDialogToolsCreateDirectory".lower()] = 833
        self.vb_constants.add("wdDialogToolsCreateDirectory".lower())
        #  (none)
        self.globals["wdDialogToolsCreateEnvelope".lower()] = 173
        self.vb_constants.add("wdDialogToolsCreateEnvelope".lower())
        #  (none)
        self.globals["wdDialogToolsCreateLabels".lower()] = 489
        self.vb_constants.add("wdDialogToolsCreateLabels".lower())
        #  (none)
        self.globals["wdDialogToolsCustomize".lower()] = 152
        self.vb_constants.add("wdDialogToolsCustomize".lower())
        #  (none)
        self.globals["wdDialogToolsCustomizeKeyboard".lower()] = 432
        self.vb_constants.add("wdDialogToolsCustomizeKeyboard".lower())
        #  (none)
        self.globals["wdDialogToolsCustomizeMenuBar".lower()] = 615
        self.vb_constants.add("wdDialogToolsCustomizeMenuBar".lower())
        #  (none)
        self.globals["wdDialogToolsCustomizeMenus".lower()] = 433
        self.vb_constants.add("wdDialogToolsCustomizeMenus".lower())
        #  (none)
        self.globals["wdDialogToolsDictionary".lower()] = 989
        self.vb_constants.add("wdDialogToolsDictionary".lower())
        #  (none)
        self.globals["wdDialogToolsEnvelopesAndLabels".lower()] = 607
        self.vb_constants.add("wdDialogToolsEnvelopesAndLabels".lower())
        #  (none)
        self.globals["wdDialogToolsGrammarSettings".lower()] = 885
        self.vb_constants.add("wdDialogToolsGrammarSettings".lower())
        #  (none)
        self.globals["wdDialogToolsHangulHanjaConversion".lower()] = 784
        self.vb_constants.add("wdDialogToolsHangulHanjaConversion".lower())
        #  (none)
        self.globals["wdDialogToolsHighlightChanges".lower()] = 197
        self.vb_constants.add("wdDialogToolsHighlightChanges".lower())
        #  (none)
        self.globals["wdDialogToolsHyphenation".lower()] = 195
        self.vb_constants.add("wdDialogToolsHyphenation".lower())
        #  (none)
        self.globals["wdDialogToolsLanguage".lower()] = 188
        self.vb_constants.add("wdDialogToolsLanguage".lower())
        #  (none)
        self.globals["wdDialogToolsMacro".lower()] = 215
        self.vb_constants.add("wdDialogToolsMacro".lower())
        #  (none)
        self.globals["wdDialogToolsMacroRecord".lower()] = 214
        self.vb_constants.add("wdDialogToolsMacroRecord".lower())
        #  (none)
        self.globals["wdDialogToolsManageFields".lower()] = 631
        self.vb_constants.add("wdDialogToolsManageFields".lower())
        #  (none)
        self.globals["wdDialogToolsMergeDocuments".lower()] = 435
        self.vb_constants.add("wdDialogToolsMergeDocuments".lower())
        #  (none)
        self.globals["wdDialogToolsOptions".lower()] = 974
        self.vb_constants.add("wdDialogToolsOptions".lower())
        #  (none)
        self.globals["wdDialogToolsOptionsAutoFormat".lower()] = 959
        self.vb_constants.add("wdDialogToolsOptionsAutoFormat".lower())
        #  (none)
        self.globals["wdDialogToolsOptionsAutoFormatAsYouType".lower()] = 778
        self.vb_constants.add("wdDialogToolsOptionsAutoFormatAsYouType".lower())
        #  (none)
        self.globals["wdDialogToolsOptionsBidi".lower()] = 1029
        self.vb_constants.add("wdDialogToolsOptionsBidi".lower())
        #  (none)
        self.globals["wdDialogToolsOptionsCompatibility".lower()] = 525
        self.vb_constants.add("wdDialogToolsOptionsCompatibility".lower())
        #  (none)
        self.globals["wdDialogToolsOptionsEdit".lower()] = 224
        self.vb_constants.add("wdDialogToolsOptionsEdit".lower())
        #  (none)
        self.globals["wdDialogToolsOptionsEditCopyPaste".lower()] = 1356
        self.vb_constants.add("wdDialogToolsOptionsEditCopyPaste".lower())
        #  (none)
        self.globals["wdDialogToolsOptionsFileLocations".lower()] = 225
        self.vb_constants.add("wdDialogToolsOptionsFileLocations".lower())
        #  (none)
        self.globals["wdDialogToolsOptionsFuzzy".lower()] = 790
        self.vb_constants.add("wdDialogToolsOptionsFuzzy".lower())
        #  (none)
        self.globals["wdDialogToolsOptionsGeneral".lower()] = 203
        self.vb_constants.add("wdDialogToolsOptionsGeneral".lower())
        #  (none)
        self.globals["wdDialogToolsOptionsPrint".lower()] = 208
        self.vb_constants.add("wdDialogToolsOptionsPrint".lower())
        #  (none)
        self.globals["wdDialogToolsOptionsSave".lower()] = 209
        self.vb_constants.add("wdDialogToolsOptionsSave".lower())
        #  (none)
        self.globals["wdDialogToolsOptionsSecurity".lower()] = 1361
        self.vb_constants.add("wdDialogToolsOptionsSecurity".lower())
        #  (none)
        self.globals["wdDialogToolsOptionsSmartTag".lower()] = 1395
        self.vb_constants.add("wdDialogToolsOptionsSmartTag".lower())
        #  (none)
        self.globals["wdDialogToolsOptionsSpellingAndGrammar".lower()] = 211
        self.vb_constants.add("wdDialogToolsOptionsSpellingAndGrammar".lower())
        #  (none)
        self.globals["wdDialogToolsOptionsTrackChanges".lower()] = 386
        self.vb_constants.add("wdDialogToolsOptionsTrackChanges".lower())
        #  (none)
        self.globals["wdDialogToolsOptionsTypography".lower()] = 739
        self.vb_constants.add("wdDialogToolsOptionsTypography".lower())
        #  (none)
        self.globals["wdDialogToolsOptionsUserInfo".lower()] = 213
        self.vb_constants.add("wdDialogToolsOptionsUserInfo".lower())
        #  (none)
        self.globals["wdDialogToolsOptionsView".lower()] = 204
        self.vb_constants.add("wdDialogToolsOptionsView".lower())
        #  (none)
        self.globals["wdDialogToolsProtectDocument".lower()] = 503
        self.vb_constants.add("wdDialogToolsProtectDocument".lower())
        #  (none)
        self.globals["wdDialogToolsProtectSection".lower()] = 578
        self.vb_constants.add("wdDialogToolsProtectSection".lower())
        #  (none)
        self.globals["wdDialogToolsRevisions".lower()] = 197
        self.vb_constants.add("wdDialogToolsRevisions".lower())
        #  (none)
        self.globals["wdDialogToolsSpellingAndGrammar".lower()] = 828
        self.vb_constants.add("wdDialogToolsSpellingAndGrammar".lower())
        #  (none)
        self.globals["wdDialogToolsTemplates".lower()] = 87
        self.vb_constants.add("wdDialogToolsTemplates".lower())
        #  (none)
        self.globals["wdDialogToolsThesaurus".lower()] = 194
        self.vb_constants.add("wdDialogToolsThesaurus".lower())
        #  (none)
        self.globals["wdDialogToolsUnprotectDocument".lower()] = 521
        self.vb_constants.add("wdDialogToolsUnprotectDocument".lower())
        #  (none)
        self.globals["wdDialogToolsWordCount".lower()] = 228
        self.vb_constants.add("wdDialogToolsWordCount".lower())
        #  (none)
        self.globals["wdDialogTwoLinesInOne".lower()] = 1161
        self.vb_constants.add("wdDialogTwoLinesInOne".lower())
        #  (none)
        self.globals["wdDialogUpdateTOC".lower()] = 331
        self.vb_constants.add("wdDialogUpdateTOC".lower())
        #  (none)
        self.globals["wdDialogViewZoom".lower()] = 577
        self.vb_constants.add("wdDialogViewZoom".lower())
        #  (none)
        self.globals["wdDialogWebOptions".lower()] = 898
        self.vb_constants.add("wdDialogWebOptions".lower())
        #  (none)
        self.globals["wdDialogWindowActivate".lower()] = 220
        self.vb_constants.add("wdDialogWindowActivate".lower())
        #  (none)
        self.globals["wdDialogXMLElementAttributes".lower()] = 1460
        self.vb_constants.add("wdDialogXMLElementAttributes".lower())
        #  (none)
        self.globals["wdDialogXMLOptions".lower()] = 1425
        self.vb_constants.add("wdDialogXMLOptions".lower())
        
        # WdWordDialogTab enumeration (Word)
        #   
        # Specifies the active tab when the specified dialog box is displayed.
        
        #  General tab of the Email Options dialog box.
        self.globals["wdDialogEmailOptionsTabQuoting".lower()] = 1900002
        self.vb_constants.add("wdDialogEmailOptionsTabQuoting".lower())
        #  Email Signature tab of the Email Options dialog box.
        self.globals["wdDialogEmailOptionsTabSignature".lower()] = 1900000
        self.vb_constants.add("wdDialogEmailOptionsTabSignature".lower())
        #  Personal Stationary tab of the Email Options dialog box.
        self.globals["wdDialogEmailOptionsTabStationary".lower()] = 1900001
        self.vb_constants.add("wdDialogEmailOptionsTabStationary".lower())
        #  Margins tab of the Page Setup dialog box, with Apply To drop-down list active.
        self.globals["wdDialogFilePageSetupTabCharsLines".lower()] = 150004
        self.vb_constants.add("wdDialogFilePageSetupTabCharsLines".lower())
        #  Layout tab of the Page Setup dialog box.
        self.globals["wdDialogFilePageSetupTabLayout".lower()] = 150003
        self.vb_constants.add("wdDialogFilePageSetupTabLayout".lower())
        #  Margins tab of the Page Setup dialog box.
        self.globals["wdDialogFilePageSetupTabMargins".lower()] = 150000
        self.vb_constants.add("wdDialogFilePageSetupTabMargins".lower())
        #  Paper tab of the Page Setup dialog box.
        self.globals["wdDialogFilePageSetupTabPaper".lower()] = 150001
        self.vb_constants.add("wdDialogFilePageSetupTabPaper".lower())
        #  Borders tab of the Borders dialog box.
        self.globals["wdDialogFormatBordersAndShadingTabBorders".lower()] = 700000
        self.vb_constants.add("wdDialogFormatBordersAndShadingTabBorders".lower())
        #  Page Border tab of the Borders dialog box.
        self.globals["wdDialogFormatBordersAndShadingTabPageBorder".lower()] = 700001
        self.vb_constants.add("wdDialogFormatBordersAndShadingTabPageBorder".lower())
        #  Shading tab of the Borders dialog box.
        self.globals["wdDialogFormatBordersAndShadingTabShading".lower()] = 700002
        self.vb_constants.add("wdDialogFormatBordersAndShadingTabShading".lower())
        #  Bulleted tab of the Bullets and Numbering dialog box.
        self.globals["wdDialogFormatBulletsAndNumberingTabBulleted".lower()] = 1500000
        self.vb_constants.add("wdDialogFormatBulletsAndNumberingTabBulleted".lower())
        #  Numbered tab of the Bullets and Numbering dialog box.
        self.globals["wdDialogFormatBulletsAndNumberingTabNumbered".lower()] = 1500001
        self.vb_constants.add("wdDialogFormatBulletsAndNumberingTabNumbered".lower())
        #  Outline Numbered tab of the Bullets and Numbering dialog box.
        self.globals["wdDialogFormatBulletsAndNumberingTabOutlineNumbered".lower()] = 1500002
        self.vb_constants.add("wdDialogFormatBulletsAndNumberingTabOutlineNumbered".lower())
        #  Colors and Lines tab of the Format Drawing Object dialog box.
        self.globals["wdDialogFormatDrawingObjectTabColorsAndLines".lower()] = 1200000
        self.vb_constants.add("wdDialogFormatDrawingObjectTabColorsAndLines".lower())
        #  Colors and Lines tab of the Format Drawing Object dialog box.
        self.globals["wdDialogFormatDrawingObjectTabHR".lower()] = 1200007
        self.vb_constants.add("wdDialogFormatDrawingObjectTabHR".lower())
        #  Picture tab of the Format Drawing Object dialog box.
        self.globals["wdDialogFormatDrawingObjectTabPicture".lower()] = 1200004
        self.vb_constants.add("wdDialogFormatDrawingObjectTabPicture".lower())
        #  Position tab of the Format Drawing Object dialog box.
        self.globals["wdDialogFormatDrawingObjectTabPosition".lower()] = 1200002
        self.vb_constants.add("wdDialogFormatDrawingObjectTabPosition".lower())
        #  Size tab of the Format Drawing Object dialog box.
        self.globals["wdDialogFormatDrawingObjectTabSize".lower()] = 1200001
        self.vb_constants.add("wdDialogFormatDrawingObjectTabSize".lower())
        #  Textbox tab of the Format Drawing Object dialog box.
        self.globals["wdDialogFormatDrawingObjectTabTextbox".lower()] = 1200005
        self.vb_constants.add("wdDialogFormatDrawingObjectTabTextbox".lower())
        #  Web tab of the Format Drawing Object dialog box.
        self.globals["wdDialogFormatDrawingObjectTabWeb".lower()] = 1200006
        self.vb_constants.add("wdDialogFormatDrawingObjectTabWeb".lower())
        #  Wrapping tab of the Format Drawing Object dialog box.
        self.globals["wdDialogFormatDrawingObjectTabWrapping".lower()] = 1200003
        self.vb_constants.add("wdDialogFormatDrawingObjectTabWrapping".lower())
        #  Animation tab of the Font dialog box.
        self.globals["wdDialogFormatFontTabAnimation".lower()] = 600002
        self.vb_constants.add("wdDialogFormatFontTabAnimation".lower())
        #  Character Spacing tab of the Font dialog box.
        self.globals["wdDialogFormatFontTabCharacterSpacing".lower()] = 600001
        self.vb_constants.add("wdDialogFormatFontTabCharacterSpacing".lower())
        #  Font tab of the Font dialog box.
        self.globals["wdDialogFormatFontTabFont".lower()] = 600000
        self.vb_constants.add("wdDialogFormatFontTabFont".lower())
        #  Indents and Spacing tab of the Paragraph dialog box.
        self.globals["wdDialogFormatParagraphTabIndentsAndSpacing".lower()] = 1000000
        self.vb_constants.add("wdDialogFormatParagraphTabIndentsAndSpacing".lower())
        #  Line and Page Breaks tab of the Paragraph dialog box, with choices appropriate for Asian text.
        self.globals["wdDialogFormatParagraphTabTeisai".lower()] = 1000002
        self.vb_constants.add("wdDialogFormatParagraphTabTeisai".lower())
        #  Line and Page Breaks tab of the Paragraph dialog box.
        self.globals["wdDialogFormatParagraphTabTextFlow".lower()] = 1000001
        self.vb_constants.add("wdDialogFormatParagraphTabTextFlow".lower())
        #  Index tab of the Index and Tables dialog box.
        self.globals["wdDialogInsertIndexAndTablesTabIndex".lower()] = 400000
        self.vb_constants.add("wdDialogInsertIndexAndTablesTabIndex".lower())
        #  Table of Authorities tab of the Index and Tables dialog box.
        self.globals["wdDialogInsertIndexAndTablesTabTableOfAuthorities".lower()] = 400003
        self.vb_constants.add("wdDialogInsertIndexAndTablesTabTableOfAuthorities".lower())
        #  Table of Contents tab of the Index and Tables dialog box.
        self.globals["wdDialogInsertIndexAndTablesTabTableOfContents".lower()] = 400001
        self.vb_constants.add("wdDialogInsertIndexAndTablesTabTableOfContents".lower())
        #  Table of Figures tab of the Index and Tables dialog box.
        self.globals["wdDialogInsertIndexAndTablesTabTableOfFigures".lower()] = 400002
        self.vb_constants.add("wdDialogInsertIndexAndTablesTabTableOfFigures".lower())
        #  Special Characters tab of the Symbol dialog box.
        self.globals["wdDialogInsertSymbolTabSpecialCharacters".lower()] = 200001
        self.vb_constants.add("wdDialogInsertSymbolTabSpecialCharacters".lower())
        #  Symbols tab of the Symbol dialog box.
        self.globals["wdDialogInsertSymbolTabSymbols".lower()] = 200000
        self.vb_constants.add("wdDialogInsertSymbolTabSymbols".lower())
        #  Letter Format tab of the Letter Wizard dialog box.
        self.globals["wdDialogLetterWizardTabLetterFormat".lower()] = 1600000
        self.vb_constants.add("wdDialogLetterWizardTabLetterFormat".lower())
        #  Other Elements tab of the Letter Wizard dialog box.
        self.globals["wdDialogLetterWizardTabOtherElements".lower()] = 1600002
        self.vb_constants.add("wdDialogLetterWizardTabOtherElements".lower())
        #  Recipient Info tab of the Letter Wizard dialog box.
        self.globals["wdDialogLetterWizardTabRecipientInfo".lower()] = 1600001
        self.vb_constants.add("wdDialogLetterWizardTabRecipientInfo".lower())
        #  Sender Info tab of the Letter Wizard dialog box.
        self.globals["wdDialogLetterWizardTabSenderInfo".lower()] = 1600003
        self.vb_constants.add("wdDialogLetterWizardTabSenderInfo".lower())
        #  All Endnotes tab of the Note Options dialog box.
        self.globals["wdDialogNoteOptionsTabAllEndnotes".lower()] = 300001
        self.vb_constants.add("wdDialogNoteOptionsTabAllEndnotes".lower())
        #  All Footnotes tab of the Note Options dialog box.
        self.globals["wdDialogNoteOptionsTabAllFootnotes".lower()] = 300000
        self.vb_constants.add("wdDialogNoteOptionsTabAllFootnotes".lower())
        #  AutoText tab of the Organizer dialog box.
        self.globals["wdDialogOrganizerTabAutoText".lower()] = 500001
        self.vb_constants.add("wdDialogOrganizerTabAutoText".lower())
        #  Command Bars tab of the Organizer dialog box.
        self.globals["wdDialogOrganizerTabCommandBars".lower()] = 500002
        self.vb_constants.add("wdDialogOrganizerTabCommandBars".lower())
        #  Macros tab of the Organizer dialog box.
        self.globals["wdDialogOrganizerTabMacros".lower()] = 500003
        self.vb_constants.add("wdDialogOrganizerTabMacros".lower())
        #  Styles tab of the Organizer dialog box.
        self.globals["wdDialogOrganizerTabStyles".lower()] = 500000
        self.vb_constants.add("wdDialogOrganizerTabStyles".lower())
        #  Cell tab of the Table Properties dialog box.
        self.globals["wdDialogTablePropertiesTabCell".lower()] = 1800003
        self.vb_constants.add("wdDialogTablePropertiesTabCell".lower())
        #  Column tab of the Table Properties dialog box.
        self.globals["wdDialogTablePropertiesTabColumn".lower()] = 1800002
        self.vb_constants.add("wdDialogTablePropertiesTabColumn".lower())
        #  Row tab of the Table Properties dialog box.
        self.globals["wdDialogTablePropertiesTabRow".lower()] = 1800001
        self.vb_constants.add("wdDialogTablePropertiesTabRow".lower())
        #  Table tab of the Table Properties dialog box.
        self.globals["wdDialogTablePropertiesTabTable".lower()] = 1800000
        self.vb_constants.add("wdDialogTablePropertiesTabTable".lower())
        #  Templates tab of the Templates and Add-ins dialog box.
        self.globals["wdDialogTemplates".lower()] = 2100000
        self.vb_constants.add("wdDialogTemplates".lower())
        #  Linked CSS tab of the Templates and Add-ins dialog box.
        self.globals["wdDialogTemplatesLinkedCSS".lower()] = 2100003
        self.vb_constants.add("wdDialogTemplatesLinkedCSS".lower())
        #  XML Expansion Packs tab of the Templates and Add-ins dialog box.
        self.globals["wdDialogTemplatesXMLExpansionPacks".lower()] = 2100002
        self.vb_constants.add("wdDialogTemplatesXMLExpansionPacks".lower())
        #  XML Schema tab of the Templates and Add-ins dialog box.
        self.globals["wdDialogTemplatesXMLSchema".lower()] = 2100001
        self.vb_constants.add("wdDialogTemplatesXMLSchema".lower())
        #  First Letter tab of the AutoCorrect Exceptions dialog box.
        self.globals["wdDialogToolsAutoCorrectExceptionsTabFirstLetter".lower()] = 1400000
        self.vb_constants.add("wdDialogToolsAutoCorrectExceptionsTabFirstLetter".lower())
        #  Hangul and Alphabet tab of the AutoCorrect Exceptions dialog box. Available only in multi-language versions.
        self.globals["wdDialogToolsAutoCorrectExceptionsTabHangulAndAlphabet".lower()] = 1400002
        self.vb_constants.add("wdDialogToolsAutoCorrectExceptionsTabHangulAndAlphabet".lower())
        #  Other Corrections tab of the AutoCorrect Exceptions dialog box.
        self.globals["wdDialogToolsAutoCorrectExceptionsTabIac".lower()] = 1400003
        self.vb_constants.add("wdDialogToolsAutoCorrectExceptionsTabIac".lower())
        #  Initial Caps tab of the AutoCorrect Exceptions dialog box.
        self.globals["wdDialogToolsAutoCorrectExceptionsTabInitialCaps".lower()] = 1400001
        self.vb_constants.add("wdDialogToolsAutoCorrectExceptionsTabInitialCaps".lower())
        #  AutoCorrect tab of the AutoCorrect dialog box.
        self.globals["wdDialogToolsAutoManagerTabAutoCorrect".lower()] = 1700000
        self.vb_constants.add("wdDialogToolsAutoManagerTabAutoCorrect".lower())
        #  AutoFormat tab of the AutoCorrect dialog box.
        self.globals["wdDialogToolsAutoManagerTabAutoFormat".lower()] = 1700003
        self.vb_constants.add("wdDialogToolsAutoManagerTabAutoFormat".lower())
        #  Format As You Type tab of the AutoCorrect dialog box.
        self.globals["wdDialogToolsAutoManagerTabAutoFormatAsYouType".lower()] = 1700001
        self.vb_constants.add("wdDialogToolsAutoManagerTabAutoFormatAsYouType".lower())
        #  AutoText tab of the AutoCorrect dialog box.
        self.globals["wdDialogToolsAutoManagerTabAutoText".lower()] = 1700002
        self.vb_constants.add("wdDialogToolsAutoManagerTabAutoText".lower())
        #  Smart Tags tab of the AutoCorrect dialog box.
        self.globals["wdDialogToolsAutoManagerTabSmartTags".lower()] = 1700004
        self.vb_constants.add("wdDialogToolsAutoManagerTabSmartTags".lower())
        #  Envelopes tab of the Envelopes and Labels dialog box.
        self.globals["wdDialogToolsEnvelopesAndLabelsTabEnvelopes".lower()] = 800000
        self.vb_constants.add("wdDialogToolsEnvelopesAndLabelsTabEnvelopes".lower())
        #  Labels tab of the Envelopes and Labels dialog box.
        self.globals["wdDialogToolsEnvelopesAndLabelsTabLabels".lower()] = 800001
        self.vb_constants.add("wdDialogToolsEnvelopesAndLabelsTabLabels".lower())
        #  Not supported.
        self.globals["wdDialogToolsOptionsTabAcetate".lower()] = 1266
        self.vb_constants.add("wdDialogToolsOptionsTabAcetate".lower())
        #  Complex Scripts tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabBidi".lower()] = 1029
        self.vb_constants.add("wdDialogToolsOptionsTabBidi".lower())
        #  Compatibility tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabCompatibility".lower()] = 525
        self.vb_constants.add("wdDialogToolsOptionsTabCompatibility".lower())
        #  Edit tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabEdit".lower()] = 224
        self.vb_constants.add("wdDialogToolsOptionsTabEdit".lower())
        #  File Locations tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabFileLocations".lower()] = 225
        self.vb_constants.add("wdDialogToolsOptionsTabFileLocations".lower())
        #  Not supported.
        self.globals["wdDialogToolsOptionsTabFuzzy".lower()] = 790
        self.vb_constants.add("wdDialogToolsOptionsTabFuzzy".lower())
        #  General tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabGeneral".lower()] = 203
        self.vb_constants.add("wdDialogToolsOptionsTabGeneral".lower())
        #  Hangul Hanja Conversion tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabHangulHanjaConversion".lower()] = 786
        self.vb_constants.add("wdDialogToolsOptionsTabHangulHanjaConversion".lower())
        #  Print tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabPrint".lower()] = 208
        self.vb_constants.add("wdDialogToolsOptionsTabPrint".lower())
        #  Spelling and Grammar tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabProofread".lower()] = 211
        self.vb_constants.add("wdDialogToolsOptionsTabProofread".lower())
        #  Save tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabSave".lower()] = 209
        self.vb_constants.add("wdDialogToolsOptionsTabSave".lower())
        #  Security tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabSecurity".lower()] = 1361
        self.vb_constants.add("wdDialogToolsOptionsTabSecurity".lower())
        #  Track Changes tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabTrackChanges".lower()] = 386
        self.vb_constants.add("wdDialogToolsOptionsTabTrackChanges".lower())
        #  Asian Typography tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabTypography".lower()] = 739
        self.vb_constants.add("wdDialogToolsOptionsTabTypography".lower())
        #  User Information tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabUserInfo".lower()] = 213
        self.vb_constants.add("wdDialogToolsOptionsTabUserInfo".lower())
        #  View tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabView".lower()] = 204
        self.vb_constants.add("wdDialogToolsOptionsTabView".lower())
        #  Browsers tab of the Web Options dialog box.
        self.globals["wdDialogWebOptionsBrowsers".lower()] = 2000000
        self.vb_constants.add("wdDialogWebOptionsBrowsers".lower())
        #  Encoding tab of the Web Options dialog box.
        self.globals["wdDialogWebOptionsEncoding".lower()] = 2000003
        self.vb_constants.add("wdDialogWebOptionsEncoding".lower())
        #  Files tab of the Web Options dialog box.
        self.globals["wdDialogWebOptionsFiles".lower()] = 2000001
        self.vb_constants.add("wdDialogWebOptionsFiles".lower())
        #  Fonts tab of the Web Options dialog box.
        self.globals["wdDialogWebOptionsFonts".lower()] = 2000004
        self.vb_constants.add("wdDialogWebOptionsFonts".lower())
        #  General tab of the Web Options dialog box.
        self.globals["wdDialogWebOptionsGeneral".lower()] = 2000000
        self.vb_constants.add("wdDialogWebOptionsGeneral".lower())
        #  Pictures tab of the Web Options dialog box.
        self.globals["wdDialogWebOptionsPictures".lower()] = 2000002
        self.vb_constants.add("wdDialogWebOptionsPictures".lower())
        #  Edit tab of the Style Management dialog box.
        self.globals["wdDialogStyleManagementTabEdit".lower()] = 2200000
        self.vb_constants.add("wdDialogStyleManagementTabEdit".lower())
        #  Recommend tab of the Style Management dialog box.
        self.globals["wdDialogStyleManagementTabRecommend".lower()] = 2200001
        self.vb_constants.add("wdDialogStyleManagementTabRecommend".lower())
        #  Restrict tab of the Style Management dialog box.
        self.globals["wdDialogStyleManagementTabRestrict".lower()] = 2200002
        self.vb_constants.add("wdDialogStyleManagementTabRestrict".lower())
        
        # WdFarEastLineBreakLevel enumeration (Word)
        #
        # Specifies the line break control level for the specified document.
        
        #  Custom line break control.
        self.globals["wdFarEastLineBreakLevelCustom".lower()] = 2
        self.vb_constants.add("wdFarEastLineBreakLevelCustom".lower())
        #  Normal line break control.
        self.globals["wdFarEastLineBreakLevelNormal".lower()] = 0
        self.vb_constants.add("wdFarEastLineBreakLevelNormal".lower())
        #  Strict line break control.
        self.globals["wdFarEastLineBreakLevelStrict".lower()] = 1
        self.vb_constants.add("wdFarEastLineBreakLevelStrict".lower())
        
        # WdFieldType enumeration (Word)
        #    
        # Specifies a Microsoft Word field. Unless otherwise specified, the field types described in this enumeration can be added interactively to a Word document by using the Field dialog box. See the Word Help for more information about specific field codes.
        
        #  Add-in field. Not available through the Field dialog box. Used to store data that is hidden from the user interface.
        self.globals["wdFieldAddin".lower()] = 81
        self.vb_constants.add("wdFieldAddin".lower())
        #  AddressBlock field.
        self.globals["wdFieldAddressBlock".lower()] = 93
        self.vb_constants.add("wdFieldAddressBlock".lower())
        #  Advance field.
        self.globals["wdFieldAdvance".lower()] = 84
        self.vb_constants.add("wdFieldAdvance".lower())
        #  Ask field.
        self.globals["wdFieldAsk".lower()] = 38
        self.vb_constants.add("wdFieldAsk".lower())
        #  Author field.
        self.globals["wdFieldAuthor".lower()] = 17
        self.vb_constants.add("wdFieldAuthor".lower())
        #  AutoNum field.
        self.globals["wdFieldAutoNum".lower()] = 54
        self.vb_constants.add("wdFieldAutoNum".lower())
        #  AutoNumLgl field.
        self.globals["wdFieldAutoNumLegal".lower()] = 53
        self.vb_constants.add("wdFieldAutoNumLegal".lower())
        #  AutoNumOut field.
        self.globals["wdFieldAutoNumOutline".lower()] = 52
        self.vb_constants.add("wdFieldAutoNumOutline".lower())
        #  AutoText field.
        self.globals["wdFieldAutoText".lower()] = 79
        self.vb_constants.add("wdFieldAutoText".lower())
        #  AutoTextList field.
        self.globals["wdFieldAutoTextList".lower()] = 89
        self.vb_constants.add("wdFieldAutoTextList".lower())
        #  BarCode field.
        self.globals["wdFieldBarCode".lower()] = 63
        self.vb_constants.add("wdFieldBarCode".lower())
        #  BidiOutline field.
        self.globals["wdFieldBidiOutline".lower()] = 92
        self.vb_constants.add("wdFieldBidiOutline".lower())
        #  Comments field.
        self.globals["wdFieldComments".lower()] = 19
        self.vb_constants.add("wdFieldComments".lower())
        #  Compare field.
        self.globals["wdFieldCompare".lower()] = 80
        self.vb_constants.add("wdFieldCompare".lower())
        #  CreateDate field.
        self.globals["wdFieldCreateDate".lower()] = 21
        self.vb_constants.add("wdFieldCreateDate".lower())
        #  Data field.
        self.globals["wdFieldData".lower()] = 40
        self.vb_constants.add("wdFieldData".lower())
        #  Database field.
        self.globals["wdFieldDatabase".lower()] = 78
        self.vb_constants.add("wdFieldDatabase".lower())
        #  Date field.
        self.globals["wdFieldDate".lower()] = 31
        self.vb_constants.add("wdFieldDate".lower())
        #  DDE field. No longer available through the Field dialog box, but supported for documents created in earlier versions of Word.
        self.globals["wdFieldDDE".lower()] = 45
        self.vb_constants.add("wdFieldDDE".lower())
        #  DDEAuto field. No longer available through the Field dialog box, but supported for documents created in earlier versions of Word.
        self.globals["wdFieldDDEAuto".lower()] = 46
        self.vb_constants.add("wdFieldDDEAuto".lower())
        #  DisplayBarcode field.
        self.globals["wdFieldDisplayBarcode".lower()] = 99
        self.vb_constants.add("wdFieldDisplayBarcode".lower())
        #  DocProperty field.
        self.globals["wdFieldDocProperty".lower()] = 85
        self.vb_constants.add("wdFieldDocProperty".lower())
        #  DocVariable field.
        self.globals["wdFieldDocVariable".lower()] = 64
        self.vb_constants.add("wdFieldDocVariable".lower())
        #  EditTime field.
        self.globals["wdFieldEditTime".lower()] = 25
        self.vb_constants.add("wdFieldEditTime".lower())
        #  Embedded field.
        self.globals["wdFieldEmbed".lower()] = 58
        self.vb_constants.add("wdFieldEmbed".lower())
        #  Empty field. Acts as a placeholder for field content that has not yet been added. A field added by pressing Ctrl+F9 in the user interface is an Empty field.
        self.globals["wdFieldEmpty".lower()] = -1
        self.vb_constants.add("wdFieldEmpty".lower())
        #  = (Formula) field.
        self.globals["wdFieldExpression".lower()] = 34
        self.vb_constants.add("wdFieldExpression".lower())
        #  FileName field.
        self.globals["wdFieldFileName".lower()] = 29
        self.vb_constants.add("wdFieldFileName".lower())
        #  FileSize field.
        self.globals["wdFieldFileSize".lower()] = 69
        self.vb_constants.add("wdFieldFileSize".lower())
        #  Fill-In field.
        self.globals["wdFieldFillIn".lower()] = 39
        self.vb_constants.add("wdFieldFillIn".lower())
        #  FootnoteRef field. Not available through the Field dialog box. Inserted programmatically or interactively.
        self.globals["wdFieldFootnoteRef".lower()] = 5
        self.vb_constants.add("wdFieldFootnoteRef".lower())
        #  FormCheckBox field.
        self.globals["wdFieldFormCheckBox".lower()] = 71
        self.vb_constants.add("wdFieldFormCheckBox".lower())
        #  FormDropDown field.
        self.globals["wdFieldFormDropDown".lower()] = 83
        self.vb_constants.add("wdFieldFormDropDown".lower())
        #  FormText field.
        self.globals["wdFieldFormTextInput".lower()] = 70
        self.vb_constants.add("wdFieldFormTextInput".lower())
        #  EQ (Equation) field.
        self.globals["wdFieldFormula".lower()] = 49
        self.vb_constants.add("wdFieldFormula".lower())
        #  Glossary field. No longer supported in Word.
        self.globals["wdFieldGlossary".lower()] = 47
        self.vb_constants.add("wdFieldGlossary".lower())
        #  GoToButton field.
        self.globals["wdFieldGoToButton".lower()] = 50
        self.vb_constants.add("wdFieldGoToButton".lower())
        #  GreetingLine field.
        self.globals["wdFieldGreetingLine".lower()] = 94
        self.vb_constants.add("wdFieldGreetingLine".lower())
        #  HTMLActiveX field. Not currently supported.
        self.globals["wdFieldHTMLActiveX".lower()] = 91
        self.vb_constants.add("wdFieldHTMLActiveX".lower())
        #  Hyperlink field.
        self.globals["wdFieldHyperlink".lower()] = 88
        self.vb_constants.add("wdFieldHyperlink".lower())
        #  If field.
        self.globals["wdFieldIf".lower()] = 7
        self.vb_constants.add("wdFieldIf".lower())
        #  Import field. Cannot be added through the Field dialog box, but can be added interactively or through code.
        self.globals["wdFieldImport".lower()] = 55
        self.vb_constants.add("wdFieldImport".lower())
        #  Include field. Cannot be added through the Field dialog box, but can be added interactively or through code.
        self.globals["wdFieldInclude".lower()] = 36
        self.vb_constants.add("wdFieldInclude".lower())
        #  IncludePicture field.
        self.globals["wdFieldIncludePicture".lower()] = 67
        self.vb_constants.add("wdFieldIncludePicture".lower())
        #  IncludeText field.
        self.globals["wdFieldIncludeText".lower()] = 68
        self.vb_constants.add("wdFieldIncludeText".lower())
        #  Index field.
        self.globals["wdFieldIndex".lower()] = 8
        self.vb_constants.add("wdFieldIndex".lower())
        #  XE (Index Entry) field.
        self.globals["wdFieldIndexEntry".lower()] = 4
        self.vb_constants.add("wdFieldIndexEntry".lower())
        #  Info field.
        self.globals["wdFieldInfo".lower()] = 14
        self.vb_constants.add("wdFieldInfo".lower())
        #  Keywords field.
        self.globals["wdFieldKeyWord".lower()] = 18
        self.vb_constants.add("wdFieldKeyWord".lower())
        #  LastSavedBy field.
        self.globals["wdFieldLastSavedBy".lower()] = 20
        self.vb_constants.add("wdFieldLastSavedBy".lower())
        #  Link field.
        self.globals["wdFieldLink".lower()] = 56
        self.vb_constants.add("wdFieldLink".lower())
        #  ListNum field.
        self.globals["wdFieldListNum".lower()] = 90
        self.vb_constants.add("wdFieldListNum".lower())
        #  MacroButton field.
        self.globals["wdFieldMacroButton".lower()] = 51
        self.vb_constants.add("wdFieldMacroButton".lower())
        #  MergeBarcode field.
        self.globals["wdFieldMergeBarcode".lower()] = 98
        self.vb_constants.add("wdFieldMergeBarcode".lower())
        #  MergeField field.
        self.globals["wdFieldMergeField".lower()] = 59
        self.vb_constants.add("wdFieldMergeField".lower())
        #  MergeRec field.
        self.globals["wdFieldMergeRec".lower()] = 44
        self.vb_constants.add("wdFieldMergeRec".lower())
        #  MergeSeq field.
        self.globals["wdFieldMergeSeq".lower()] = 75
        self.vb_constants.add("wdFieldMergeSeq".lower())
        #  Next field.
        self.globals["wdFieldNext".lower()] = 41
        self.vb_constants.add("wdFieldNext".lower())
        #  NextIf field.
        self.globals["wdFieldNextIf".lower()] = 42
        self.vb_constants.add("wdFieldNextIf".lower())
        #  NoteRef field.
        self.globals["wdFieldNoteRef".lower()] = 72
        self.vb_constants.add("wdFieldNoteRef".lower())
        #  NumChars field.
        self.globals["wdFieldNumChars".lower()] = 28
        self.vb_constants.add("wdFieldNumChars".lower())
        #  NumPages field.
        self.globals["wdFieldNumPages".lower()] = 26
        self.vb_constants.add("wdFieldNumPages".lower())
        #  NumWords field.
        self.globals["wdFieldNumWords".lower()] = 27
        self.vb_constants.add("wdFieldNumWords".lower())
        #  OCX field. Cannot be added through the Field dialog box, but can be added through code by using the AddOLEControl method of the Shapes collection or of the InlineShapes collection.
        self.globals["wdFieldOCX".lower()] = 87
        self.vb_constants.add("wdFieldOCX".lower())
        #  Page field.
        self.globals["wdFieldPage".lower()] = 33
        self.vb_constants.add("wdFieldPage".lower())
        #  PageRef field.
        self.globals["wdFieldPageRef".lower()] = 37
        self.vb_constants.add("wdFieldPageRef".lower())
        #  Print field.
        self.globals["wdFieldPrint".lower()] = 48
        self.vb_constants.add("wdFieldPrint".lower())
        #  PrintDate field.
        self.globals["wdFieldPrintDate".lower()] = 23
        self.vb_constants.add("wdFieldPrintDate".lower())
        #  Private field.
        self.globals["wdFieldPrivate".lower()] = 77
        self.vb_constants.add("wdFieldPrivate".lower())
        #  Quote field.
        self.globals["wdFieldQuote".lower()] = 35
        self.vb_constants.add("wdFieldQuote".lower())
        #  Ref field.
        self.globals["wdFieldRef".lower()] = 3
        self.vb_constants.add("wdFieldRef".lower())
        #  RD (Reference Document) field.
        self.globals["wdFieldRefDoc".lower()] = 11
        self.vb_constants.add("wdFieldRefDoc".lower())
        #  RevNum field.
        self.globals["wdFieldRevisionNum".lower()] = 24
        self.vb_constants.add("wdFieldRevisionNum".lower())
        #  SaveDate field.
        self.globals["wdFieldSaveDate".lower()] = 22
        self.vb_constants.add("wdFieldSaveDate".lower())
        #  Section field.
        self.globals["wdFieldSection".lower()] = 65
        self.vb_constants.add("wdFieldSection".lower())
        #  SectionPages field.
        self.globals["wdFieldSectionPages".lower()] = 66
        self.vb_constants.add("wdFieldSectionPages".lower())
        #  Seq (Sequence) field.
        self.globals["wdFieldSequence".lower()] = 12
        self.vb_constants.add("wdFieldSequence".lower())
        #  Set field.
        self.globals["wdFieldSet".lower()] = 6
        self.vb_constants.add("wdFieldSet".lower())
        #  Shape field. Automatically created for any drawn picture.
        self.globals["wdFieldShape".lower()] = 95
        self.vb_constants.add("wdFieldShape".lower())
        #  SkipIf field.
        self.globals["wdFieldSkipIf".lower()] = 43
        self.vb_constants.add("wdFieldSkipIf".lower())
        #  StyleRef field.
        self.globals["wdFieldStyleRef".lower()] = 10
        self.vb_constants.add("wdFieldStyleRef".lower())
        #  Subject field.
        self.globals["wdFieldSubject".lower()] = 16
        self.vb_constants.add("wdFieldSubject".lower())
        #  Macintosh only. For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdFieldSubscriber".lower()] = 82
        self.vb_constants.add("wdFieldSubscriber".lower())
        #  Symbol field.
        self.globals["wdFieldSymbol".lower()] = 57
        self.vb_constants.add("wdFieldSymbol".lower())
        #  Template field.
        self.globals["wdFieldTemplate".lower()] = 30
        self.vb_constants.add("wdFieldTemplate".lower())
        #  Time field.
        self.globals["wdFieldTime".lower()] = 32
        self.vb_constants.add("wdFieldTime".lower())
        #  Title field.
        self.globals["wdFieldTitle".lower()] = 15
        self.vb_constants.add("wdFieldTitle".lower())
        #  TOA (Table of Authorities) field.
        self.globals["wdFieldTOA".lower()] = 73
        self.vb_constants.add("wdFieldTOA".lower())
        #  TOA (Table of Authorities Entry) field.
        self.globals["wdFieldTOAEntry".lower()] = 74
        self.vb_constants.add("wdFieldTOAEntry".lower())
        #  TOC (Table of Contents) field.
        self.globals["wdFieldTOC".lower()] = 13
        self.vb_constants.add("wdFieldTOC".lower())
        #  TOC (Table of Contents Entry) field.
        self.globals["wdFieldTOCEntry".lower()] = 9
        self.vb_constants.add("wdFieldTOCEntry".lower())
        #  UserAddress field.
        self.globals["wdFieldUserAddress".lower()] = 62
        self.vb_constants.add("wdFieldUserAddress".lower())
        #  UserInitials field.
        self.globals["wdFieldUserInitials".lower()] = 61
        self.vb_constants.add("wdFieldUserInitials".lower())
        #  UserName field.
        self.globals["wdFieldUserName".lower()] = 60
        self.vb_constants.add("wdFieldUserName".lower())
        #  Bibliography field.
        self.globals["wdFieldBibliography".lower()] = 97
        self.vb_constants.add("wdFieldBibliography".lower())
        #  Citation field.
        self.globals["wdFieldCitation".lower()] = 96
        self.vb_constants.add("wdFieldCitation".lower())
        
        # WdInformation enumeration (Word)
        #
        # Specifies the type of information returned about a specified selection or range.
        
        #  Returns the number of the page that contains the active end of the specified selection or range. If you set a starting page number or make other manual adjustments, returns the adjusted page number (unlike wdActiveEndPageNumber).
        self.globals["wdActiveEndAdjustedPageNumber".lower()] = 1
        self.vb_constants.add("wdActiveEndAdjustedPageNumber".lower())
        #  Returns the number of the page that contains the active end of the specified selection or range, counting from the beginning of the document. Any manual adjustments to page numbering are disregarded (unlike wdActiveEndAdjustedPageNumber).
        self.globals["wdActiveEndPageNumber".lower()] = 3
        self.vb_constants.add("wdActiveEndPageNumber".lower())
        #  Returns the number of the section that contains the active end of the specified selection or range.
        self.globals["wdActiveEndSectionNumber".lower()] = 2
        self.vb_constants.add("wdActiveEndSectionNumber".lower())
        #  Returns True if the specified selection or range is at the end-of-row mark in a table.
        self.globals["wdAtEndOfRowMarker".lower()] = 31
        self.vb_constants.add("wdAtEndOfRowMarker".lower())
        #  Returns True if Caps Lock is in effect.
        self.globals["wdCapsLock".lower()] = 21
        self.vb_constants.add("wdCapsLock".lower())
        #  Returns the table column number that contains the end of the specified selection or range.
        self.globals["wdEndOfRangeColumnNumber".lower()] = 17
        self.vb_constants.add("wdEndOfRangeColumnNumber".lower())
        #  Returns the table row number that contains the end of the specified selection or range.
        self.globals["wdEndOfRangeRowNumber".lower()] = 14
        self.vb_constants.add("wdEndOfRangeRowNumber".lower())
        #  Returns the character position of the first character in the specified selection or range. If the selection or range is collapsed, the character number immediately to the right of the range or selection is returned (this is the same as the character column number displayed in the status bar after "Col").
        self.globals["wdFirstCharacterColumnNumber".lower()] = 9
        self.vb_constants.add("wdFirstCharacterColumnNumber".lower())
        #  Returns the character position of the first character in the specified selection or range. If the selection or range is collapsed, the character number immediately to the right of the range or selection is returned (this is the same as the character line number displayed in the status bar after "Ln").
        self.globals["wdFirstCharacterLineNumber".lower()] = 10
        self.vb_constants.add("wdFirstCharacterLineNumber".lower())
        #  Returns True if the selection or range is an entire frame or text box.
        self.globals["wdFrameIsSelected".lower()] = 11
        self.vb_constants.add("wdFrameIsSelected".lower())
        #  Returns a value that indicates the type of header or footer that contains the specified selection or range. See the table in the remarks section for additional information.
        self.globals["wdHeaderFooterType".lower()] = 33
        self.vb_constants.add("wdHeaderFooterType".lower())
        #  Returns the horizontal position of the specified selection or range; this is the distance from the left edge of the selection or range to the left edge of the page measured in points (1 point = 20 twips, 72 points = 1 inch). If the selection or range isn't within the screen area, returns -1.
        self.globals["wdHorizontalPositionRelativeToPage".lower()] = 5
        self.vb_constants.add("wdHorizontalPositionRelativeToPage".lower())
        #  Returns the horizontal position of the specified selection or range relative to the left edge of the nearest text boundary enclosing it, in points (1 point = 20 twips, 72 points = 1 inch). If the selection or range isn't within the screen area, returns -1.
        self.globals["wdHorizontalPositionRelativeToTextBoundary".lower()] = 7
        self.vb_constants.add("wdHorizontalPositionRelativeToTextBoundary".lower())
        #  Returns True if the specified selection or range is in a bibliography.
        self.globals["wdInBibliography".lower()] = 42
        self.vb_constants.add("wdInBibliography".lower())
        #  Returns True if the specified selection or range is in a citation.
        self.globals["wdInCitation".lower()] = 43
        self.vb_constants.add("wdInCitation".lower())
        #  For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdInClipboard".lower()] = 38
        self.vb_constants.add("wdInClipboard".lower())
        #  Returns True if the specified selection or range is in a comment pane.
        self.globals["wdInCommentPane".lower()] = 26
        self.vb_constants.add("wdInCommentPane".lower())
        #  Returns True if the specified selection or range is in a content control.
        self.globals["wdInContentControl".lower()] = 46
        self.vb_constants.add("wdInContentControl".lower())
        #  Returns True if the specified selection or range is in a cover page.
        self.globals["wdInCoverPage".lower()] = 41
        self.vb_constants.add("wdInCoverPage".lower())
        #  Returns True if the specified selection or range is in an endnote area in print layout view or in the endnote pane in normal view.
        self.globals["wdInEndnote".lower()] = 36
        self.vb_constants.add("wdInEndnote".lower())
        #  Returns True if the specified selection or range is in a field code.
        self.globals["wdInFieldCode".lower()] = 44
        self.vb_constants.add("wdInFieldCode".lower())
        #  Returns True if the specified selection or range is in a field result.
        self.globals["wdInFieldResult".lower()] = 45
        self.vb_constants.add("wdInFieldResult".lower())
        #  Returns True if the specified selection or range is in a footnote area in print layout view or in the footnote pane in normal view.
        self.globals["wdInFootnote".lower()] = 35
        self.vb_constants.add("wdInFootnote".lower())
        #  Returns True if the specified selection or range is in the footnote or endnote pane in normal view or in a footnote or endnote area in print layout view. For more information, see the descriptions of wdInFootnote and wdInEndnote in the preceding paragraphs.
        self.globals["wdInFootnoteEndnotePane".lower()] = 25
        self.vb_constants.add("wdInFootnoteEndnotePane".lower())
        #  Returns True if the selection or range is in the header or footer pane or in a header or footer in print layout view.
        self.globals["wdInHeaderFooter".lower()] = 28
        self.vb_constants.add("wdInHeaderFooter".lower())
        #  Returns True if the selection or range is in a master document (that is, a document that contains at least one subdocument).
        self.globals["wdInMasterDocument".lower()] = 34
        self.vb_constants.add("wdInMasterDocument".lower())
        #  Returns True if the selection or range is in the header or footer pane or in a header or footer in print layout view.
        self.globals["wdInWordMail".lower()] = 37
        self.vb_constants.add("wdInWordMail".lower())
        #  Returns the greatest number of table columns within any row in the selection or range.
        self.globals["wdMaximumNumberOfColumns".lower()] = 18
        self.vb_constants.add("wdMaximumNumberOfColumns".lower())
        #  Returns the greatest number of table rows within the table in the specified selection or range.
        self.globals["wdMaximumNumberOfRows".lower()] = 15
        self.vb_constants.add("wdMaximumNumberOfRows".lower())
        #  Returns the number of pages in the document associated with the selection or range.
        self.globals["wdNumberOfPagesInDocument".lower()] = 4
        self.vb_constants.add("wdNumberOfPagesInDocument".lower())
        #  Returns True if Num Lock is in effect.
        self.globals["wdNumLock".lower()] = 22
        self.vb_constants.add("wdNumLock".lower())
        #  Returns True if Overtype mode is in effect. The Overtype property can be used to change the state of the Overtype mode.
        self.globals["wdOverType".lower()] = 23
        self.vb_constants.add("wdOverType".lower())
        #  Returns a value that indicates where the selection is in relation to a footnote, endnote, or comment reference, as shown in the table in the remarks section.
        self.globals["wdReferenceOfType".lower()] = 32
        self.vb_constants.add("wdReferenceOfType".lower())
        #  Returns True if change tracking is in effect.
        self.globals["wdRevisionMarking".lower()] = 24
        self.vb_constants.add("wdRevisionMarking".lower())
        #  Returns a value that indicates the current selection mode, as shown in the following table.
        self.globals["wdSelectionMode".lower()] = 20
        self.vb_constants.add("wdSelectionMode".lower())
        #  Returns the table column number that contains the beginning of the selection or range.
        self.globals["wdStartOfRangeColumnNumber".lower()] = 16
        self.vb_constants.add("wdStartOfRangeColumnNumber".lower())
        #  Returns the table row number that contains the beginning of the selection or range.
        self.globals["wdStartOfRangeRowNumber".lower()] = 13
        self.vb_constants.add("wdStartOfRangeRowNumber".lower())
        #  Returns the vertical position of the selection or range; this is the distance from the top edge of the selection to the top edge of the page measured in points (1 point = 20 twips, 72 points = 1 inch). If the selection isn't visible in the document window, returns -1.
        self.globals["wdVerticalPositionRelativeToPage".lower()] = 6
        self.vb_constants.add("wdVerticalPositionRelativeToPage".lower())
        #  Returns the vertical position of the selection or range relative to the top edge of the nearest text boundary enclosing it, in points (1 point = 20 twips, 72 points = 1 inch). This is useful for determining the position of the insertion point within a frame or table cell. If the selection isn't visible, returns -1.
        self.globals["wdVerticalPositionRelativeToTextBoundary".lower()] = 8
        self.vb_constants.add("wdVerticalPositionRelativeToTextBoundary".lower())
        #  Returns True if the selection is in a table.
        self.globals["wdWithInTable".lower()] = 12
        self.vb_constants.add("wdWithInTable".lower())
        #  Returns the current percentage of magnification as set by the Percentage property.
        self.globals["wdZoomPercentage".lower()] = 19
        self.vb_constants.add("wdZoomPercentage".lower())
        
        # WdColorIndex enumeration (Word)
        #   
        # Specifies the color to apply.
        
        #  Automatic color. Default; usually black.
        self.globals["wdAuto".lower()] = 0
        self.vb_constants.add("wdAuto".lower())
        #  Black color.
        self.globals["wdBlack".lower()] = 1
        self.vb_constants.add("wdBlack".lower())
        #  Blue color.
        self.globals["wdBlue".lower()] = 2
        self.vb_constants.add("wdBlue".lower())
        #  Bright green color.
        self.globals["wdBrightGreen".lower()] = 4
        self.vb_constants.add("wdBrightGreen".lower())
        #  Color defined by document author.
        self.globals["wdByAuthor".lower()] = -1
        self.vb_constants.add("wdByAuthor".lower())
        #  Dark blue color.
        self.globals["wdDarkBlue".lower()] = 9
        self.vb_constants.add("wdDarkBlue".lower())
        #  Dark red color.
        self.globals["wdDarkRed".lower()] = 13
        self.vb_constants.add("wdDarkRed".lower())
        #  Dark yellow color.
        self.globals["wdDarkYellow".lower()] = 14
        self.vb_constants.add("wdDarkYellow".lower())
        #  Shade 25 of gray color.
        self.globals["wdGray25".lower()] = 16
        self.vb_constants.add("wdGray25".lower())
        #  Shade 50 of gray color.
        self.globals["wdGray50".lower()] = 15
        self.vb_constants.add("wdGray50".lower())
        #  Green color.
        self.globals["wdGreen".lower()] = 11
        self.vb_constants.add("wdGreen".lower())
        #  Removes highlighting that has been applied.
        self.globals["wdNoHighlight".lower()] = 0
        self.vb_constants.add("wdNoHighlight".lower())
        #  Pink color.
        self.globals["wdPink".lower()] = 5
        self.vb_constants.add("wdPink".lower())
        #  Red color.
        self.globals["wdRed".lower()] = 6
        self.vb_constants.add("wdRed".lower())
        #  Teal color.
        self.globals["wdTeal".lower()] = 10
        self.vb_constants.add("wdTeal".lower())
        #  Turquoise color.
        self.globals["wdTurquoise".lower()] = 3
        self.vb_constants.add("wdTurquoise".lower())
        #  Violet color.
        self.globals["wdViolet".lower()] = 12
        self.vb_constants.add("wdViolet".lower())
        #  White color.
        self.globals["wdWhite".lower()] = 8
        self.vb_constants.add("wdWhite".lower())
        #  Yellow color.
        self.globals["wdYellow".lower()] = 7
        self.vb_constants.add("wdYellow".lower())
        
        # WdHorizontalLineWidthType enumeration (Word)
        #    
        # Specifies how Word interprets the width (length) of the specified horizontal line.
        
        #  Microsoft Word interprets the width (length) of the specified horizontal line as a fixed value (in points). This is the default value for horizontal lines added with the AddHorizontalLine method. Setting the Width property for the InlineShape object associated with a horizontal line sets the WidthType property to this value.
        self.globals["wdHorizontalLineFixedWidth".lower()] = -2
        self.vb_constants.add("wdHorizontalLineFixedWidth".lower())
        #  Word interprets the width (length) of the specified horizontal line as a percentage of the screen width. This is the default value for horizontal lines added with the AddHorizontalLineStandard method. Setting the PercentWidth property on a horizontal line sets the WidthType property to this value.
        self.globals["wdHorizontalLinePercentWidth".lower()] = -1
        self.vb_constants.add("wdHorizontalLinePercentWidth".lower())
        
        # WdLanguageID enumeration
        #   
        # Specifies the language to use.
        
        #  African language.
        self.globals["wdAfrikaans".lower()] = 1078
        self.vb_constants.add("wdAfrikaans".lower())
        #  Albanian language.
        self.globals["wdAlbanian".lower()] = 1052
        self.vb_constants.add("wdAlbanian".lower())
        #  Amharic language.
        self.globals["wdAmharic".lower()] = 1118
        self.vb_constants.add("wdAmharic".lower())
        #  Arabic language.
        self.globals["wdArabic".lower()] = 1025
        self.vb_constants.add("wdArabic".lower())
        #  Arabic Algerian language.
        self.globals["wdArabicAlgeria".lower()] = 5121
        self.vb_constants.add("wdArabicAlgeria".lower())
        #  Arabic Bahraini language.
        self.globals["wdArabicBahrain".lower()] = 15361
        self.vb_constants.add("wdArabicBahrain".lower())
        #  Arabic Egyptian language.
        self.globals["wdArabicEgypt".lower()] = 3073
        self.vb_constants.add("wdArabicEgypt".lower())
        #  Arabic Iraqi language.
        self.globals["wdArabicIraq".lower()] = 2049
        self.vb_constants.add("wdArabicIraq".lower())
        #  Arabic Jordanian language.
        self.globals["wdArabicJordan".lower()] = 11265
        self.vb_constants.add("wdArabicJordan".lower())
        #  Arabic Kuwaiti language.
        self.globals["wdArabicKuwait".lower()] = 13313
        self.vb_constants.add("wdArabicKuwait".lower())
        #  Arabic Lebanese language.
        self.globals["wdArabicLebanon".lower()] = 12289
        self.vb_constants.add("wdArabicLebanon".lower())
        #  Arabic Libyan language.
        self.globals["wdArabicLibya".lower()] = 4097
        self.vb_constants.add("wdArabicLibya".lower())
        #  Arabic Moroccan language.
        self.globals["wdArabicMorocco".lower()] = 6145
        self.vb_constants.add("wdArabicMorocco".lower())
        #  Arabic Omani language.
        self.globals["wdArabicOman".lower()] = 8193
        self.vb_constants.add("wdArabicOman".lower())
        #  Arabic Qatari language.
        self.globals["wdArabicQatar".lower()] = 16385
        self.vb_constants.add("wdArabicQatar".lower())
        #  Arabic Syrian language.
        self.globals["wdArabicSyria".lower()] = 10241
        self.vb_constants.add("wdArabicSyria".lower())
        #  Arabic Tunisian language.
        self.globals["wdArabicTunisia".lower()] = 7169
        self.vb_constants.add("wdArabicTunisia".lower())
        #  Arabic United Arab Emirates language.
        self.globals["wdArabicUAE".lower()] = 14337
        self.vb_constants.add("wdArabicUAE".lower())
        #  Arabic Yemeni language.
        self.globals["wdArabicYemen".lower()] = 9217
        self.vb_constants.add("wdArabicYemen".lower())
        #  Armenian language.
        self.globals["wdArmenian".lower()] = 1067
        self.vb_constants.add("wdArmenian".lower())
        #  Assamese language.
        self.globals["wdAssamese".lower()] = 1101
        self.vb_constants.add("wdAssamese".lower())
        #  Azeri Cyrillic language.
        self.globals["wdAzeriCyrillic".lower()] = 2092
        self.vb_constants.add("wdAzeriCyrillic".lower())
        #  Azeri Latin language.
        self.globals["wdAzeriLatin".lower()] = 1068
        self.vb_constants.add("wdAzeriLatin".lower())
        #  Basque (Basque).
        self.globals["wdBasque".lower()] = 1069
        self.vb_constants.add("wdBasque".lower())
        #  Belgian Dutch language.
        self.globals["wdBelgianDutch".lower()] = 2067
        self.vb_constants.add("wdBelgianDutch".lower())
        #  Belgian French language.
        self.globals["wdBelgianFrench".lower()] = 2060
        self.vb_constants.add("wdBelgianFrench".lower())
        #  Bengali language.
        self.globals["wdBengali".lower()] = 1093
        self.vb_constants.add("wdBengali".lower())
        #  Bulgarian language.
        self.globals["wdBulgarian".lower()] = 1026
        self.vb_constants.add("wdBulgarian".lower())
        #  Burmese language.
        self.globals["wdBurmese".lower()] = 1109
        self.vb_constants.add("wdBurmese".lower())
        #  Belarusian language.
        self.globals["wdByelorussian".lower()] = 1059
        self.vb_constants.add("wdByelorussian".lower())
        #  Catalan language.
        self.globals["wdCatalan".lower()] = 1027
        self.vb_constants.add("wdCatalan".lower())
        #  Cherokee language.
        self.globals["wdCherokee".lower()] = 1116
        self.vb_constants.add("wdCherokee".lower())
        #  Chinese Hong Kong SAR language.
        self.globals["wdChineseHongKongSAR".lower()] = 3076
        self.vb_constants.add("wdChineseHongKongSAR".lower())
        #  Chinese Macao SAR language.
        self.globals["wdChineseMacaoSAR".lower()] = 5124
        self.vb_constants.add("wdChineseMacaoSAR".lower())
        #  Chinese Singapore language.
        self.globals["wdChineseSingapore".lower()] = 4100
        self.vb_constants.add("wdChineseSingapore".lower())
        #  Croatian language.
        self.globals["wdCroatian".lower()] = 1050
        self.vb_constants.add("wdCroatian".lower())
        #  Czech language.
        self.globals["wdCzech".lower()] = 1029
        self.vb_constants.add("wdCzech".lower())
        #  Danish language.
        self.globals["wdDanish".lower()] = 1030
        self.vb_constants.add("wdDanish".lower())
        #  Divehi language.
        self.globals["wdDivehi".lower()] = 1125
        self.vb_constants.add("wdDivehi".lower())
        #  Dutch language.
        self.globals["wdDutch".lower()] = 1043
        self.vb_constants.add("wdDutch".lower())
        #  Edo language.
        self.globals["wdEdo".lower()] = 1126
        self.vb_constants.add("wdEdo".lower())
        #  Australian English language.
        self.globals["wdEnglishAUS".lower()] = 3081
        self.vb_constants.add("wdEnglishAUS".lower())
        #  Belize English language.
        self.globals["wdEnglishBelize".lower()] = 10249
        self.vb_constants.add("wdEnglishBelize".lower())
        #  Canadian English language.
        self.globals["wdEnglishCanadian".lower()] = 4105
        self.vb_constants.add("wdEnglishCanadian".lower())
        #  Caribbean English language.
        self.globals["wdEnglishCaribbean".lower()] = 9225
        self.vb_constants.add("wdEnglishCaribbean".lower())
        #  Indonesian English language.
        self.globals["wdEnglishIndonesia".lower()] = 14345
        self.vb_constants.add("wdEnglishIndonesia".lower())
        #  Irish English language.
        self.globals["wdEnglishIreland".lower()] = 6153
        self.vb_constants.add("wdEnglishIreland".lower())
        #  Jamaican English language.
        self.globals["wdEnglishJamaica".lower()] = 8201
        self.vb_constants.add("wdEnglishJamaica".lower())
        #  New Zealand English language.
        self.globals["wdEnglishNewZealand".lower()] = 5129
        self.vb_constants.add("wdEnglishNewZealand".lower())
        #  Filipino English language.
        self.globals["wdEnglishPhilippines".lower()] = 13321
        self.vb_constants.add("wdEnglishPhilippines".lower())
        #  South African English language.
        self.globals["wdEnglishSouthAfrica".lower()] = 7177
        self.vb_constants.add("wdEnglishSouthAfrica".lower())
        #  Tobago Trinidad English language.
        self.globals["wdEnglishTrinidadTobago".lower()] = 11273
        self.vb_constants.add("wdEnglishTrinidadTobago".lower())
        #  United Kingdom English language.
        self.globals["wdEnglishUK".lower()] = 2057
        self.vb_constants.add("wdEnglishUK".lower())
        #  United States English language.
        self.globals["wdEnglishUS".lower()] = 1033
        self.vb_constants.add("wdEnglishUS".lower())
        #  Zimbabwe English language.
        self.globals["wdEnglishZimbabwe".lower()] = 12297
        self.vb_constants.add("wdEnglishZimbabwe".lower())
        #  Estonian language.
        self.globals["wdEstonian".lower()] = 1061
        self.vb_constants.add("wdEstonian".lower())
        #  Faeroese language.
        self.globals["wdFaeroese".lower()] = 1080
        self.vb_constants.add("wdFaeroese".lower())
        #  Filipino language.
        self.globals["wdFilipino".lower()] = 1124
        self.vb_constants.add("wdFilipino".lower())
        #  Finnish language.
        self.globals["wdFinnish".lower()] = 1035
        self.vb_constants.add("wdFinnish".lower())
        #  French language.
        self.globals["wdFrench".lower()] = 1036
        self.vb_constants.add("wdFrench".lower())
        #  French Cameroon language.
        self.globals["wdFrenchCameroon".lower()] = 11276
        self.vb_constants.add("wdFrenchCameroon".lower())
        #  French Canadian language.
        self.globals["wdFrenchCanadian".lower()] = 3084
        self.vb_constants.add("wdFrenchCanadian".lower())
        #  French (Congo (DRC)) language.
        self.globals["wdFrenchCongoDRC".lower()] = 9228
        self.vb_constants.add("wdFrenchCongoDRC".lower())
        #  French Cote d'Ivoire language.
        self.globals["wdFrenchCotedIvoire".lower()] = 12300
        self.vb_constants.add("wdFrenchCotedIvoire".lower())
        #  French Haiti language.
        self.globals["wdFrenchHaiti".lower()] = 15372
        self.vb_constants.add("wdFrenchHaiti".lower())
        #  French Luxembourg language.
        self.globals["wdFrenchLuxembourg".lower()] = 5132
        self.vb_constants.add("wdFrenchLuxembourg".lower())
        #  French Mali language.
        self.globals["wdFrenchMali".lower()] = 13324
        self.vb_constants.add("wdFrenchMali".lower())
        #  French Monaco language.
        self.globals["wdFrenchMonaco".lower()] = 6156
        self.vb_constants.add("wdFrenchMonaco".lower())
        #  French Morocco language.
        self.globals["wdFrenchMorocco".lower()] = 14348
        self.vb_constants.add("wdFrenchMorocco".lower())
        #  French Reunion language.
        self.globals["wdFrenchReunion".lower()] = 8204
        self.vb_constants.add("wdFrenchReunion".lower())
        #  French Senegal language.
        self.globals["wdFrenchSenegal".lower()] = 10252
        self.vb_constants.add("wdFrenchSenegal".lower())
        #  French West Indies language.
        self.globals["wdFrenchWestIndies".lower()] = 7180
        self.vb_constants.add("wdFrenchWestIndies".lower())
        #  Frisian Netherlands language.
        self.globals["wdFrisianNetherlands".lower()] = 1122
        self.vb_constants.add("wdFrisianNetherlands".lower())
        #  Fulfulde language.
        self.globals["wdFulfulde".lower()] = 1127
        self.vb_constants.add("wdFulfulde".lower())
        #  Irish (Irish) language.
        self.globals["wdGaelicIreland".lower()] = 2108
        self.vb_constants.add("wdGaelicIreland".lower())
        #  Scottish Gaelic language.
        self.globals["wdGaelicScotland".lower()] = 1084
        self.vb_constants.add("wdGaelicScotland".lower())
        #  Galician language.
        self.globals["wdGalician".lower()] = 1110
        self.vb_constants.add("wdGalician".lower())
        #  Georgian language.
        self.globals["wdGeorgian".lower()] = 1079
        self.vb_constants.add("wdGeorgian".lower())
        #  German language.
        self.globals["wdGerman".lower()] = 1031
        self.vb_constants.add("wdGerman".lower())
        #  German Austrian language.
        self.globals["wdGermanAustria".lower()] = 3079
        self.vb_constants.add("wdGermanAustria".lower())
        #  German Liechtenstein language.
        self.globals["wdGermanLiechtenstein".lower()] = 5127
        self.vb_constants.add("wdGermanLiechtenstein".lower())
        #  German Luxembourg language.
        self.globals["wdGermanLuxembourg".lower()] = 4103
        self.vb_constants.add("wdGermanLuxembourg".lower())
        #  Greek language.
        self.globals["wdGreek".lower()] = 1032
        self.vb_constants.add("wdGreek".lower())
        #  Guarani language.
        self.globals["wdGuarani".lower()] = 1140
        self.vb_constants.add("wdGuarani".lower())
        #  Gujarati language.
        self.globals["wdGujarati".lower()] = 1095
        self.vb_constants.add("wdGujarati".lower())
        #  Hausa language.
        self.globals["wdHausa".lower()] = 1128
        self.vb_constants.add("wdHausa".lower())
        #  Hawaiian language.
        self.globals["wdHawaiian".lower()] = 1141
        self.vb_constants.add("wdHawaiian".lower())
        #  Hebrew language.
        self.globals["wdHebrew".lower()] = 1037
        self.vb_constants.add("wdHebrew".lower())
        #  Hindi language.
        self.globals["wdHindi".lower()] = 1081
        self.vb_constants.add("wdHindi".lower())
        #  Hungarian language.
        self.globals["wdHungarian".lower()] = 1038
        self.vb_constants.add("wdHungarian".lower())
        #  Ibibio language.
        self.globals["wdIbibio".lower()] = 1129
        self.vb_constants.add("wdIbibio".lower())
        #  Icelandic language.
        self.globals["wdIcelandic".lower()] = 1039
        self.vb_constants.add("wdIcelandic".lower())
        #  Igbo language.
        self.globals["wdIgbo".lower()] = 1136
        self.vb_constants.add("wdIgbo".lower())
        #  Indonesian language.
        self.globals["wdIndonesian".lower()] = 1057
        self.vb_constants.add("wdIndonesian".lower())
        #  Inuktitut language.
        self.globals["wdInuktitut".lower()] = 1117
        self.vb_constants.add("wdInuktitut".lower())
        #  Italian language.
        self.globals["wdItalian".lower()] = 1040
        self.vb_constants.add("wdItalian".lower())
        #  Japanese language.
        self.globals["wdJapanese".lower()] = 1041
        self.vb_constants.add("wdJapanese".lower())
        #  Kannada language.
        self.globals["wdKannada".lower()] = 1099
        self.vb_constants.add("wdKannada".lower())
        #  Kanuri language.
        self.globals["wdKanuri".lower()] = 1137
        self.vb_constants.add("wdKanuri".lower())
        #  Kashmiri language.
        self.globals["wdKashmiri".lower()] = 1120
        self.vb_constants.add("wdKashmiri".lower())
        #  Kazakh language.
        self.globals["wdKazakh".lower()] = 1087
        self.vb_constants.add("wdKazakh".lower())
        #  Khmer language.
        self.globals["wdKhmer".lower()] = 1107
        self.vb_constants.add("wdKhmer".lower())
        #  Kirghiz language.
        self.globals["wdKirghiz".lower()] = 1088
        self.vb_constants.add("wdKirghiz".lower())
        #  Konkani language.
        self.globals["wdKonkani".lower()] = 1111
        self.vb_constants.add("wdKonkani".lower())
        #  Korean language.
        self.globals["wdKorean".lower()] = 1042
        self.vb_constants.add("wdKorean".lower())
        #  Kyrgyz language.
        self.globals["wdKyrgyz".lower()] = 1088
        self.vb_constants.add("wdKyrgyz".lower())
        #  No specified language.
        self.globals["wdLanguageNone".lower()] = 0
        self.vb_constants.add("wdLanguageNone".lower())
        #  Lao language.
        self.globals["wdLao".lower()] = 1108
        self.vb_constants.add("wdLao".lower())
        #  Latin language.
        self.globals["wdLatin".lower()] = 1142
        self.vb_constants.add("wdLatin".lower())
        #  Latvian language.
        self.globals["wdLatvian".lower()] = 1062
        self.vb_constants.add("wdLatvian".lower())
        #  Lithuanian language.
        self.globals["wdLithuanian".lower()] = 1063
        self.vb_constants.add("wdLithuanian".lower())
        #  Macedonian (FYROM) language.
        self.globals["wdMacedonianFYROM".lower()] = 1071
        self.vb_constants.add("wdMacedonianFYROM".lower())
        #  Malayalam language.
        self.globals["wdMalayalam".lower()] = 1100
        self.vb_constants.add("wdMalayalam".lower())
        #  Malay Brunei Darussalam language.
        self.globals["wdMalayBruneiDarussalam".lower()] = 2110
        self.vb_constants.add("wdMalayBruneiDarussalam".lower())
        #  Malaysian language.
        self.globals["wdMalaysian".lower()] = 1086
        self.vb_constants.add("wdMalaysian".lower())
        #  Maltese language.
        self.globals["wdMaltese".lower()] = 1082
        self.vb_constants.add("wdMaltese".lower())
        #  Manipuri language.
        self.globals["wdManipuri".lower()] = 1112
        self.vb_constants.add("wdManipuri".lower())
        #  Marathi language.
        self.globals["wdMarathi".lower()] = 1102
        self.vb_constants.add("wdMarathi".lower())
        #  Mexican Spanish language.
        self.globals["wdMexicanSpanish".lower()] = 2058
        self.vb_constants.add("wdMexicanSpanish".lower())
        #  Mongolian language.
        self.globals["wdMongolian".lower()] = 1104
        self.vb_constants.add("wdMongolian".lower())
        #  Nepali language.
        self.globals["wdNepali".lower()] = 1121
        self.vb_constants.add("wdNepali".lower())
        #  Disables proofing if the language ID identifies a language in which an object is grammatically validated using the Microsoft Word proofing tools.
        self.globals["wdNoProofing".lower()] = 1024
        self.vb_constants.add("wdNoProofing".lower())
        #  Norwegian Bokmol language.
        self.globals["wdNorwegianBokmol".lower()] = 1044
        self.vb_constants.add("wdNorwegianBokmol".lower())
        #  Norwegian Nynorsk language.
        self.globals["wdNorwegianNynorsk".lower()] = 2068
        self.vb_constants.add("wdNorwegianNynorsk".lower())
        #  Oriya language.
        self.globals["wdOriya".lower()] = 1096
        self.vb_constants.add("wdOriya".lower())
        #  Oromo language.
        self.globals["wdOromo".lower()] = 1138
        self.vb_constants.add("wdOromo".lower())
        #  Pashto language.
        self.globals["wdPashto".lower()] = 1123
        self.vb_constants.add("wdPashto".lower())
        #  Persian language.
        self.globals["wdPersian".lower()] = 1065
        self.vb_constants.add("wdPersian".lower())
        #  Polish language.
        self.globals["wdPolish".lower()] = 1045
        self.vb_constants.add("wdPolish".lower())
        #  Portuguese language.
        self.globals["wdPortuguese".lower()] = 2070
        self.vb_constants.add("wdPortuguese".lower())
        #  Portuguese (Brazil) language.
        self.globals["wdPortugueseBrazil".lower()] = 1046
        self.vb_constants.add("wdPortugueseBrazil".lower())
        #  Punjabi language.
        self.globals["wdPunjabi".lower()] = 1094
        self.vb_constants.add("wdPunjabi".lower())
        #  Rhaeto Romanic language.
        self.globals["wdRhaetoRomanic".lower()] = 1047
        self.vb_constants.add("wdRhaetoRomanic".lower())
        #  Romanian language.
        self.globals["wdRomanian".lower()] = 1048
        self.vb_constants.add("wdRomanian".lower())
        #  Romanian Moldova language.
        self.globals["wdRomanianMoldova".lower()] = 2072
        self.vb_constants.add("wdRomanianMoldova".lower())
        #  Russian language.
        self.globals["wdRussian".lower()] = 1049
        self.vb_constants.add("wdRussian".lower())
        #  Russian Moldova language.
        self.globals["wdRussianMoldova".lower()] = 2073
        self.vb_constants.add("wdRussianMoldova".lower())
        #  Sami Lappish language.
        self.globals["wdSamiLappish".lower()] = 1083
        self.vb_constants.add("wdSamiLappish".lower())
        #  Sanskrit language.
        self.globals["wdSanskrit".lower()] = 1103
        self.vb_constants.add("wdSanskrit".lower())
        #  Serbian Cyrillic language.
        self.globals["wdSerbianCyrillic".lower()] = 3098
        self.vb_constants.add("wdSerbianCyrillic".lower())
        #  Serbian Latin language.
        self.globals["wdSerbianLatin".lower()] = 2074
        self.vb_constants.add("wdSerbianLatin".lower())
        #  Sesotho language.
        self.globals["wdSesotho".lower()] = 1072
        self.vb_constants.add("wdSesotho".lower())
        #  Simplified Chinese language.
        self.globals["wdSimplifiedChinese".lower()] = 2052
        self.vb_constants.add("wdSimplifiedChinese".lower())
        #  Sindhi language.
        self.globals["wdSindhi".lower()] = 1113
        self.vb_constants.add("wdSindhi".lower())
        #  Sindhi (Pakistan) language.
        self.globals["wdSindhiPakistan".lower()] = 2137
        self.vb_constants.add("wdSindhiPakistan".lower())
        #  Sinhalese language.
        self.globals["wdSinhalese".lower()] = 1115
        self.vb_constants.add("wdSinhalese".lower())
        #  Slovakian language.
        self.globals["wdSlovak".lower()] = 1051
        self.vb_constants.add("wdSlovak".lower())
        #  Slovenian language.
        self.globals["wdSlovenian".lower()] = 1060
        self.vb_constants.add("wdSlovenian".lower())
        #  Somali language.
        self.globals["wdSomali".lower()] = 1143
        self.vb_constants.add("wdSomali".lower())
        #  Sorbian language.
        self.globals["wdSorbian".lower()] = 1070
        self.vb_constants.add("wdSorbian".lower())
        #  Spanish language.
        self.globals["wdSpanish".lower()] = 1034
        self.vb_constants.add("wdSpanish".lower())
        #  Spanish Argentina language.
        self.globals["wdSpanishArgentina".lower()] = 11274
        self.vb_constants.add("wdSpanishArgentina".lower())
        #  Spanish Bolivian language.
        self.globals["wdSpanishBolivia".lower()] = 16394
        self.vb_constants.add("wdSpanishBolivia".lower())
        #  Spanish Chilean language.
        self.globals["wdSpanishChile".lower()] = 13322
        self.vb_constants.add("wdSpanishChile".lower())
        #  Spanish Colombian language.
        self.globals["wdSpanishColombia".lower()] = 9226
        self.vb_constants.add("wdSpanishColombia".lower())
        #  Spanish Costa Rican language.
        self.globals["wdSpanishCostaRica".lower()] = 5130
        self.vb_constants.add("wdSpanishCostaRica".lower())
        #  Spanish Dominican Republic language.
        self.globals["wdSpanishDominicanRepublic".lower()] = 7178
        self.vb_constants.add("wdSpanishDominicanRepublic".lower())
        #  Spanish Ecuadorian language.
        self.globals["wdSpanishEcuador".lower()] = 12298
        self.vb_constants.add("wdSpanishEcuador".lower())
        #  Spanish El Salvadorian language.
        self.globals["wdSpanishElSalvador".lower()] = 17418
        self.vb_constants.add("wdSpanishElSalvador".lower())
        #  Spanish Guatemala language.
        self.globals["wdSpanishGuatemala".lower()] = 4106
        self.vb_constants.add("wdSpanishGuatemala".lower())
        #  Spanish Honduran language.
        self.globals["wdSpanishHonduras".lower()] = 18442
        self.vb_constants.add("wdSpanishHonduras".lower())
        #  Spanish Modern Sort language.
        self.globals["wdSpanishModernSort".lower()] = 3082
        self.vb_constants.add("wdSpanishModernSort".lower())
        #  Spanish Nicaraguan language.
        self.globals["wdSpanishNicaragua".lower()] = 19466
        self.vb_constants.add("wdSpanishNicaragua".lower())
        #  Spanish Panamanian language.
        self.globals["wdSpanishPanama".lower()] = 6154
        self.vb_constants.add("wdSpanishPanama".lower())
        #  Spanish Paraguayan language.
        self.globals["wdSpanishParaguay".lower()] = 15370
        self.vb_constants.add("wdSpanishParaguay".lower())
        #  Spanish Peruvian language.
        self.globals["wdSpanishPeru".lower()] = 10250
        self.vb_constants.add("wdSpanishPeru".lower())
        #  Spanish Puerto Rican language.
        self.globals["wdSpanishPuertoRico".lower()] = 20490
        self.vb_constants.add("wdSpanishPuertoRico".lower())
        #  Spanish Uruguayan language.
        self.globals["wdSpanishUruguay".lower()] = 14346
        self.vb_constants.add("wdSpanishUruguay".lower())
        #  Spanish Venezuelan language.
        self.globals["wdSpanishVenezuela".lower()] = 8202
        self.vb_constants.add("wdSpanishVenezuela".lower())
        #  Sutu language.
        self.globals["wdSutu".lower()] = 1072
        self.vb_constants.add("wdSutu".lower())
        #  Swahili language.
        self.globals["wdSwahili".lower()] = 1089
        self.vb_constants.add("wdSwahili".lower())
        #  Swedish language.
        self.globals["wdSwedish".lower()] = 1053
        self.vb_constants.add("wdSwedish".lower())
        #  Swedish Finnish language.
        self.globals["wdSwedishFinland".lower()] = 2077
        self.vb_constants.add("wdSwedishFinland".lower())
        #  Swiss French language.
        self.globals["wdSwissFrench".lower()] = 4108
        self.vb_constants.add("wdSwissFrench".lower())
        #  Swiss German language.
        self.globals["wdSwissGerman".lower()] = 2055
        self.vb_constants.add("wdSwissGerman".lower())
        #  Swiss Italian language.
        self.globals["wdSwissItalian".lower()] = 2064
        self.vb_constants.add("wdSwissItalian".lower())
        #  Syriac language.
        self.globals["wdSyriac".lower()] = 1114
        self.vb_constants.add("wdSyriac".lower())
        #  Tajik language.
        self.globals["wdTajik".lower()] = 1064
        self.vb_constants.add("wdTajik".lower())
        #  Tamazight language.
        self.globals["wdTamazight".lower()] = 1119
        self.vb_constants.add("wdTamazight".lower())
        #  Tamazight Latin language.
        self.globals["wdTamazightLatin".lower()] = 2143
        self.vb_constants.add("wdTamazightLatin".lower())
        #  Tamil language.
        self.globals["wdTamil".lower()] = 1097
        self.vb_constants.add("wdTamil".lower())
        #  Tatar language.
        self.globals["wdTatar".lower()] = 1092
        self.vb_constants.add("wdTatar".lower())
        #  Telugu language.
        self.globals["wdTelugu".lower()] = 1098
        self.vb_constants.add("wdTelugu".lower())
        #  Thai language.
        self.globals["wdThai".lower()] = 1054
        self.vb_constants.add("wdThai".lower())
        #  Tibetan language.
        self.globals["wdTibetan".lower()] = 1105
        self.vb_constants.add("wdTibetan".lower())
        #  Tigrigna Eritrea language.
        self.globals["wdTigrignaEritrea".lower()] = 2163
        self.vb_constants.add("wdTigrignaEritrea".lower())
        #  Tigrigna Ethiopic language.
        self.globals["wdTigrignaEthiopic".lower()] = 1139
        self.vb_constants.add("wdTigrignaEthiopic".lower())
        #  Traditional Chinese language.
        self.globals["wdTraditionalChinese".lower()] = 1028
        self.vb_constants.add("wdTraditionalChinese".lower())
        #  Tsonga language.
        self.globals["wdTsonga".lower()] = 1073
        self.vb_constants.add("wdTsonga".lower())
        #  Tswana language.
        self.globals["wdTswana".lower()] = 1074
        self.vb_constants.add("wdTswana".lower())
        #  Turkish language.
        self.globals["wdTurkish".lower()] = 1055
        self.vb_constants.add("wdTurkish".lower())
        #  Turkmen language.
        self.globals["wdTurkmen".lower()] = 1090
        self.vb_constants.add("wdTurkmen".lower())
        #  Ukrainian language.
        self.globals["wdUkrainian".lower()] = 1058
        self.vb_constants.add("wdUkrainian".lower())
        #  Urdu language.
        self.globals["wdUrdu".lower()] = 1056
        self.vb_constants.add("wdUrdu".lower())
        #  Uzbek Cyrillic language.
        self.globals["wdUzbekCyrillic".lower()] = 2115
        self.vb_constants.add("wdUzbekCyrillic".lower())
        #  Uzbek Latin language.
        self.globals["wdUzbekLatin".lower()] = 1091
        self.vb_constants.add("wdUzbekLatin".lower())
        #  Venda language.
        self.globals["wdVenda".lower()] = 1075
        self.vb_constants.add("wdVenda".lower())
        #  Vietnamese language.
        self.globals["wdVietnamese".lower()] = 1066
        self.vb_constants.add("wdVietnamese".lower())
        #  Welsh language.
        self.globals["wdWelsh".lower()] = 1106
        self.vb_constants.add("wdWelsh".lower())
        #  Xhosa language.
        self.globals["wdXhosa".lower()] = 1076
        self.vb_constants.add("wdXhosa".lower())
        #  Yi language.
        self.globals["wdYi".lower()] = 1144
        self.vb_constants.add("wdYi".lower())
        #  Yiddish language.
        self.globals["wdYiddish".lower()] = 1085
        self.vb_constants.add("wdYiddish".lower())
        #  Yoruba language.
        self.globals["wdYoruba".lower()] = 1130
        self.vb_constants.add("wdYoruba".lower())
        #  Zulu language.
        self.globals["wdZulu".lower()] = 1077
        self.vb_constants.add("wdZulu".lower())
        
        # WdKeyCategory enumeration (Word)
        #   
        # Specifies the type of item assigned to the key binding.
        
        #  Key is assigned to autotext.
        self.globals["wdKeyCategoryAutoText".lower()] = 4
        self.vb_constants.add("wdKeyCategoryAutoText".lower())
        #  Key is assigned to a command.
        self.globals["wdKeyCategoryCommand".lower()] = 1
        self.vb_constants.add("wdKeyCategoryCommand".lower())
        #  Key is disabled.
        self.globals["wdKeyCategoryDisable".lower()] = 0
        self.vb_constants.add("wdKeyCategoryDisable".lower())
        #  Key is assigned to a font.
        self.globals["wdKeyCategoryFont".lower()] = 3
        self.vb_constants.add("wdKeyCategoryFont".lower())
        #  Key is assigned to a macro.
        self.globals["wdKeyCategoryMacro".lower()] = 2
        self.vb_constants.add("wdKeyCategoryMacro".lower())
        #  Key is not assigned.
        self.globals["wdKeyCategoryNil".lower()] = -1
        self.vb_constants.add("wdKeyCategoryNil".lower())
        #  Key is assigned to a prefix.
        self.globals["wdKeyCategoryPrefix".lower()] = 7
        self.vb_constants.add("wdKeyCategoryPrefix".lower())
        #  Key is assigned to a style.
        self.globals["wdKeyCategoryStyle".lower()] = 5
        self.vb_constants.add("wdKeyCategoryStyle".lower())
        #  Key is assigned to a symbol.
        self.globals["wdKeyCategorySymbol".lower()] = 6
        self.vb_constants.add("wdKeyCategorySymbol".lower())
        
        # WdKey enumeration (Word)
        #   
        # Specifies a keyboard character. Although uppercase and lowercase characters are designated by using different values in a character encoding map, they share a single constant in this enumeration.
        
        #  The 0 key.
        self.globals["wdKey0".lower()] = 48
        self.vb_constants.add("wdKey0".lower())
        #  The 1 key.
        self.globals["wdKey1".lower()] = 49
        self.vb_constants.add("wdKey1".lower())
        #  The 2 key.
        self.globals["wdKey2".lower()] = 50
        self.vb_constants.add("wdKey2".lower())
        #  The 3 key.
        self.globals["wdKey3".lower()] = 51
        self.vb_constants.add("wdKey3".lower())
        #  The 4 key.
        self.globals["wdKey4".lower()] = 52
        self.vb_constants.add("wdKey4".lower())
        #  The 5 key.
        self.globals["wdKey5".lower()] = 53
        self.vb_constants.add("wdKey5".lower())
        #  The 6 key.
        self.globals["wdKey6".lower()] = 54
        self.vb_constants.add("wdKey6".lower())
        #  The 7 key.
        self.globals["wdKey7".lower()] = 55
        self.vb_constants.add("wdKey7".lower())
        #  The 8 key.
        self.globals["wdKey8".lower()] = 56
        self.vb_constants.add("wdKey8".lower())
        #  The 9 key.
        self.globals["wdKey9".lower()] = 57
        self.vb_constants.add("wdKey9".lower())
        #  The A key.
        self.globals["wdKeyA".lower()] = 65
        self.vb_constants.add("wdKeyA".lower())
        #  The ALT key.
        self.globals["wdKeyAlt".lower()] = 1024
        self.vb_constants.add("wdKeyAlt".lower())
        #  The B key.
        self.globals["wdKeyB".lower()] = 66
        self.vb_constants.add("wdKeyB".lower())
        #  The ` key.
        self.globals["wdKeyBackSingleQuote".lower()] = 192
        self.vb_constants.add("wdKeyBackSingleQuote".lower())
        #  The \ key.
        self.globals["wdKeyBackSlash".lower()] = 220
        self.vb_constants.add("wdKeyBackSlash".lower())
        #  The BACKSPACE key.
        self.globals["wdKeyBackspace".lower()] = 8
        self.vb_constants.add("wdKeyBackspace".lower())
        #  The C key.
        self.globals["wdKeyC".lower()] = 67
        self.vb_constants.add("wdKeyC".lower())
        #  The ] key.
        self.globals["wdKeyCloseSquareBrace".lower()] = 221
        self.vb_constants.add("wdKeyCloseSquareBrace".lower())
        #  The , key.
        self.globals["wdKeyComma".lower()] = 188
        self.vb_constants.add("wdKeyComma".lower())
        #  The Windows command key or Macintosh COMMAND key.
        self.globals["wdKeyCommand".lower()] = 512
        self.vb_constants.add("wdKeyCommand".lower())
        #  The CTRL key.
        self.globals["wdKeyControl".lower()] = 512
        self.vb_constants.add("wdKeyControl".lower())
        #  The D key.
        self.globals["wdKeyD".lower()] = 68
        self.vb_constants.add("wdKeyD".lower())
        #  The DELETE key.
        self.globals["wdKeyDelete".lower()] = 46
        self.vb_constants.add("wdKeyDelete".lower())
        #  The E key.
        self.globals["wdKeyE".lower()] = 69
        self.vb_constants.add("wdKeyE".lower())
        #  The END key.
        self.globals["wdKeyEnd".lower()] = 35
        self.vb_constants.add("wdKeyEnd".lower())
        #  The = key.
        self.globals["wdKeyEquals".lower()] = 187
        self.vb_constants.add("wdKeyEquals".lower())
        #  The ESC key.
        self.globals["wdKeyEsc".lower()] = 27
        self.vb_constants.add("wdKeyEsc".lower())
        #  The F key.
        self.globals["wdKeyF".lower()] = 70
        self.vb_constants.add("wdKeyF".lower())
        #  The F1 key.
        self.globals["wdKeyF1".lower()] = 112
        self.vb_constants.add("wdKeyF1".lower())
        #  The F10 key.
        self.globals["wdKeyF10".lower()] = 121
        self.vb_constants.add("wdKeyF10".lower())
        #  The F11 key.
        self.globals["wdKeyF11".lower()] = 122
        self.vb_constants.add("wdKeyF11".lower())
        #  The F12 key.
        self.globals["wdKeyF12".lower()] = 123
        self.vb_constants.add("wdKeyF12".lower())
        #  The F13 key.
        self.globals["wdKeyF13".lower()] = 124
        self.vb_constants.add("wdKeyF13".lower())
        #  The F14 key.
        self.globals["wdKeyF14".lower()] = 125
        self.vb_constants.add("wdKeyF14".lower())
        #  The F15 key.
        self.globals["wdKeyF15".lower()] = 126
        self.vb_constants.add("wdKeyF15".lower())
        #  The F16 key.
        self.globals["wdKeyF16".lower()] = 127
        self.vb_constants.add("wdKeyF16".lower())
        #  The F2 key.
        self.globals["wdKeyF2".lower()] = 113
        self.vb_constants.add("wdKeyF2".lower())
        #  The F3 key.
        self.globals["wdKeyF3".lower()] = 114
        self.vb_constants.add("wdKeyF3".lower())
        #  The F4 key.
        self.globals["wdKeyF4".lower()] = 115
        self.vb_constants.add("wdKeyF4".lower())
        #  The F5 key.
        self.globals["wdKeyF5".lower()] = 116
        self.vb_constants.add("wdKeyF5".lower())
        #  The F6 key.
        self.globals["wdKeyF6".lower()] = 117
        self.vb_constants.add("wdKeyF6".lower())
        #  The F7 key.
        self.globals["wdKeyF7".lower()] = 118
        self.vb_constants.add("wdKeyF7".lower())
        #  The F8 key.
        self.globals["wdKeyF8".lower()] = 119
        self.vb_constants.add("wdKeyF8".lower())
        #  The F9 key.
        self.globals["wdKeyF9".lower()] = 120
        self.vb_constants.add("wdKeyF9".lower())
        #  The G key.
        self.globals["wdKeyG".lower()] = 71
        self.vb_constants.add("wdKeyG".lower())
        #  The H key.
        self.globals["wdKeyH".lower()] = 72
        self.vb_constants.add("wdKeyH".lower())
        #  The HOME key.
        self.globals["wdKeyHome".lower()] = 36
        self.vb_constants.add("wdKeyHome".lower())
        #  The - key.
        self.globals["wdKeyHyphen".lower()] = 189
        self.vb_constants.add("wdKeyHyphen".lower())
        #  The I key.
        self.globals["wdKeyI".lower()] = 73
        self.vb_constants.add("wdKeyI".lower())
        #  The INSERT key.
        self.globals["wdKeyInsert".lower()] = 45
        self.vb_constants.add("wdKeyInsert".lower())
        #  The J key.
        self.globals["wdKeyJ".lower()] = 74
        self.vb_constants.add("wdKeyJ".lower())
        #  The K key.
        self.globals["wdKeyK".lower()] = 75
        self.vb_constants.add("wdKeyK".lower())
        #  The L key.
        self.globals["wdKeyL".lower()] = 76
        self.vb_constants.add("wdKeyL".lower())
        #  The M key.
        self.globals["wdKeyM".lower()] = 77
        self.vb_constants.add("wdKeyM".lower())
        #  The N key.
        self.globals["wdKeyN".lower()] = 78
        self.vb_constants.add("wdKeyN".lower())
        #  The 0 key.
        self.globals["wdKeyNumeric0".lower()] = 96
        self.vb_constants.add("wdKeyNumeric0".lower())
        #  The 1 key.
        self.globals["wdKeyNumeric1".lower()] = 97
        self.vb_constants.add("wdKeyNumeric1".lower())
        #  The 2 key.
        self.globals["wdKeyNumeric2".lower()] = 98
        self.vb_constants.add("wdKeyNumeric2".lower())
        #  The 3 key.
        self.globals["wdKeyNumeric3".lower()] = 99
        self.vb_constants.add("wdKeyNumeric3".lower())
        #  The 4 key.
        self.globals["wdKeyNumeric4".lower()] = 100
        self.vb_constants.add("wdKeyNumeric4".lower())
        #  The 5 key.
        self.globals["wdKeyNumeric5".lower()] = 101
        self.vb_constants.add("wdKeyNumeric5".lower())
        #  .
        self.globals["wdKeyNumeric5Special".lower()] = 12
        self.vb_constants.add("wdKeyNumeric5Special".lower())
        #  The 6 key.
        self.globals["wdKeyNumeric6".lower()] = 102
        self.vb_constants.add("wdKeyNumeric6".lower())
        #  The 7 key.
        self.globals["wdKeyNumeric7".lower()] = 103
        self.vb_constants.add("wdKeyNumeric7".lower())
        #  The 8 key.
        self.globals["wdKeyNumeric8".lower()] = 104
        self.vb_constants.add("wdKeyNumeric8".lower())
        #  The 9 key.
        self.globals["wdKeyNumeric9".lower()] = 105
        self.vb_constants.add("wdKeyNumeric9".lower())
        #  The + key on the numeric keypad.
        self.globals["wdKeyNumericAdd".lower()] = 107
        self.vb_constants.add("wdKeyNumericAdd".lower())
        #  The . key on the numeric keypad.
        self.globals["wdKeyNumericDecimal".lower()] = 110
        self.vb_constants.add("wdKeyNumericDecimal".lower())
        #  The / key on the numeric keypad.
        self.globals["wdKeyNumericDivide".lower()] = 111
        self.vb_constants.add("wdKeyNumericDivide".lower())
        #  The * key on the numeric keypad.
        self.globals["wdKeyNumericMultiply".lower()] = 106
        self.vb_constants.add("wdKeyNumericMultiply".lower())
        #  The - key on the numeric keypad.
        self.globals["wdKeyNumericSubtract".lower()] = 109
        self.vb_constants.add("wdKeyNumericSubtract".lower())
        #  The O key.
        self.globals["wdKeyO".lower()] = 79
        self.vb_constants.add("wdKeyO".lower())
        #  The [ key.
        self.globals["wdKeyOpenSquareBrace".lower()] = 219
        self.vb_constants.add("wdKeyOpenSquareBrace".lower())
        #  The mouse option key or Macintosh OPTION key.
        self.globals["wdKeyOption".lower()] = 1024
        self.vb_constants.add("wdKeyOption".lower())
        #  The P key.
        self.globals["wdKeyP".lower()] = 80
        self.vb_constants.add("wdKeyP".lower())
        #  The PAGE DOWN key.
        self.globals["wdKeyPageDown".lower()] = 34
        self.vb_constants.add("wdKeyPageDown".lower())
        #  The PAGE UP key.
        self.globals["wdKeyPageUp".lower()] = 33
        self.vb_constants.add("wdKeyPageUp".lower())
        #  The PAUSE key.
        self.globals["wdKeyPause".lower()] = 19
        self.vb_constants.add("wdKeyPause".lower())
        #  The . key.
        self.globals["wdKeyPeriod".lower()] = 190
        self.vb_constants.add("wdKeyPeriod".lower())
        #  The Q key.
        self.globals["wdKeyQ".lower()] = 81
        self.vb_constants.add("wdKeyQ".lower())
        #  The R key.
        self.globals["wdKeyR".lower()] = 82
        self.vb_constants.add("wdKeyR".lower())
        #  The ENTER or RETURN key.
        self.globals["wdKeyReturn".lower()] = 13
        self.vb_constants.add("wdKeyReturn".lower())
        #  The S key.
        self.globals["wdKeyS".lower()] = 83
        self.vb_constants.add("wdKeyS".lower())
        #  The SCROLL LOCK key.
        self.globals["wdKeyScrollLock".lower()] = 145
        self.vb_constants.add("wdKeyScrollLock".lower())
        #  The ; key.
        self.globals["wdKeySemiColon".lower()] = 186
        self.vb_constants.add("wdKeySemiColon".lower())
        #  The SHIFT key.
        self.globals["wdKeyShift".lower()] = 256
        self.vb_constants.add("wdKeyShift".lower())
        #  The ' key.
        self.globals["wdKeySingleQuote".lower()] = 222
        self.vb_constants.add("wdKeySingleQuote".lower())
        #  The / key.
        self.globals["wdKeySlash".lower()] = 191
        self.vb_constants.add("wdKeySlash".lower())
        #  The SPACEBAR key.
        self.globals["wdKeySpacebar".lower()] = 32
        self.vb_constants.add("wdKeySpacebar".lower())
        #  The T key.
        self.globals["wdKeyT".lower()] = 84
        self.vb_constants.add("wdKeyT".lower())
        #  The TAB key.
        self.globals["wdKeyTab".lower()] = 9
        self.vb_constants.add("wdKeyTab".lower())
        #  The U key.
        self.globals["wdKeyU".lower()] = 85
        self.vb_constants.add("wdKeyU".lower())
        #  The V key.
        self.globals["wdKeyV".lower()] = 86
        self.vb_constants.add("wdKeyV".lower())
        #  The W key.
        self.globals["wdKeyW".lower()] = 87
        self.vb_constants.add("wdKeyW".lower())
        #  The X key.
        self.globals["wdKeyX".lower()] = 88
        self.vb_constants.add("wdKeyX".lower())
        #  The Y key.
        self.globals["wdKeyY".lower()] = 89
        self.vb_constants.add("wdKeyY".lower())
        #  The Z key.
        self.globals["wdKeyZ".lower()] = 90
        self.vb_constants.add("wdKeyZ".lower())
        #  No key.
        self.globals["wdNoKey".lower()] = 255
        self.vb_constants.add("wdNoKey".lower())
        
        # WdCompatibility enumeration (Word)
        # 
        # Specifies a compatibility option.
        
        #  Align table rows independently.
        self.globals["wdAlignTablesRowByRow".lower()] = 39
        self.vb_constants.add("wdAlignTablesRowByRow".lower())
        #  Use line-breaking rules.
        self.globals["wdApplyBreakingRules".lower()] = 46
        self.vb_constants.add("wdApplyBreakingRules".lower())
        #  Autospace like Microsoft Word 95.
        self.globals["wdAutospaceLikeWW7".lower()] = 38
        self.vb_constants.add("wdAutospaceLikeWW7".lower())
        #  Treat " as "" in mail merge data sources.
        self.globals["wdConvMailMergeEsc".lower()] = 6
        self.vb_constants.add("wdConvMailMergeEsc".lower())
        #  Adjust line height to grid height in the table.
        self.globals["wdDontAdjustLineHeightInTable".lower()] = 36
        self.vb_constants.add("wdDontAdjustLineHeightInTable".lower())
        #  Balance SBCS characters and DBCS characters.
        self.globals["wdDontBalanceSingleByteDoubleByteWidth".lower()] = 16
        self.vb_constants.add("wdDontBalanceSingleByteDoubleByteWidth".lower())
        #  Do not break wrapped tables across pages.
        self.globals["wdDontBreakWrappedTables".lower()] = 43
        self.vb_constants.add("wdDontBreakWrappedTables".lower())
        #  Do not snap text to grid inside table with inline objects.
        self.globals["wdDontSnapTextToGridInTableWithObjects".lower()] = 44
        self.vb_constants.add("wdDontSnapTextToGridInTableWithObjects".lower())
        #  Draw underline on trailing spaces.
        self.globals["wdDontULTrailSpace".lower()] = 15
        self.vb_constants.add("wdDontULTrailSpace".lower())
        #  Do not use Asian rules for line breaks with character grid.
        self.globals["wdDontUseAsianBreakRulesInGrid".lower()] = 48
        self.vb_constants.add("wdDontUseAsianBreakRulesInGrid".lower())
        #  Do not use HTML paragraph auto spacing.
        self.globals["wdDontUseHTMLParagraphAutoSpacing".lower()] = 35
        self.vb_constants.add("wdDontUseHTMLParagraphAutoSpacing".lower())
        #  Do not allow hanging punctuation with character grid.
        self.globals["wdDontWrapTextWithPunctuation".lower()] = 47
        self.vb_constants.add("wdDontWrapTextWithPunctuation".lower())
        #  Do not center "exact line height" lines.
        self.globals["wdExactOnTop".lower()] = 28
        self.vb_constants.add("wdExactOnTop".lower())
        #  Do not expand character spaces on the line ending Shift+Return.
        self.globals["wdExpandShiftReturn".lower()] = 14
        self.vb_constants.add("wdExpandShiftReturn".lower())
        #  Lay out footnotes like Word 6.x/95/97.
        self.globals["wdFootnoteLayoutLikeWW8".lower()] = 34
        self.vb_constants.add("wdFootnoteLayoutLikeWW8".lower())
        #  Forget last tab alignment.
        self.globals["wdForgetLastTabAlignment".lower()] = 37
        self.vb_constants.add("wdForgetLastTabAlignment".lower())
        #  Allow tables to extend into margins.
        self.globals["wdGrowAutofit".lower()] = 50
        self.vb_constants.add("wdGrowAutofit".lower())
        #  Lay out tables with raw width.
        self.globals["wdLayoutRawTableWidth".lower()] = 40
        self.vb_constants.add("wdLayoutRawTableWidth".lower())
        #  Allow table rows to lay out apart.
        self.globals["wdLayoutTableRowsApart".lower()] = 41
        self.vb_constants.add("wdLayoutTableRowsApart".lower())
        #  Convert backslash characters into yen signs.
        self.globals["wdLeaveBackslashAlone".lower()] = 13
        self.vb_constants.add("wdLeaveBackslashAlone".lower())
        #  Line wrap like Word 6.0.
        self.globals["wdLineWrapLikeWord6".lower()] = 32
        self.vb_constants.add("wdLineWrapLikeWord6".lower())
        #  Use larger small caps like Word 5.x for the Macintosh.
        self.globals["wdMWSmallCaps".lower()] = 22
        self.vb_constants.add("wdMWSmallCaps".lower())
        #  Do not balance columns for continuous section starts.
        self.globals["wdNoColumnBalance".lower()] = 5
        self.vb_constants.add("wdNoColumnBalance".lower())
        #  Suppress extra line spacing like WordPerfect 5.x.
        self.globals["wdNoExtraLineSpacing".lower()] = 23
        self.vb_constants.add("wdNoExtraLineSpacing".lower())
        #  Do not add leading (extra space) between rows of text.
        self.globals["wdNoLeading".lower()] = 20
        self.vb_constants.add("wdNoLeading".lower())
        #  Add space for underline.
        self.globals["wdNoSpaceForUL".lower()] = 21
        self.vb_constants.add("wdNoSpaceForUL".lower())
        #  Do not add extra space for raised/lowered characters.
        self.globals["wdNoSpaceRaiseLower".lower()] = 2
        self.vb_constants.add("wdNoSpaceRaiseLower".lower())
        #  Do not add automatic tab stop for hanging indent.
        self.globals["wdNoTabHangIndent".lower()] = 1
        self.vb_constants.add("wdNoTabHangIndent".lower())
        #  Combine table borders like Word 5.x for the Macintosh.
        self.globals["wdOrigWordTableRules".lower()] = 9
        self.vb_constants.add("wdOrigWordTableRules".lower())
        #  Print body text before header/footer.
        self.globals["wdPrintBodyTextBeforeHeader".lower()] = 19
        self.vb_constants.add("wdPrintBodyTextBeforeHeader".lower())
        #  Print colors as black on noncolor printers.
        self.globals["wdPrintColBlack".lower()] = 3
        self.vb_constants.add("wdPrintColBlack".lower())
        #  Select entire field with first or last character.
        self.globals["wdSelectFieldWithFirstOrLastCharacter".lower()] = 45
        self.vb_constants.add("wdSelectFieldWithFirstOrLastCharacter".lower())
        #  Lay out autoshapes like Word 97.
        self.globals["wdShapeLayoutLikeWW8".lower()] = 33
        self.vb_constants.add("wdShapeLayoutLikeWW8".lower())
        #  Show hard page or column breaks in frames.
        self.globals["wdShowBreaksInFrames".lower()] = 11
        self.vb_constants.add("wdShowBreaksInFrames".lower())
        #  Expand/condense by whole number of points.
        self.globals["wdSpacingInWholePoints".lower()] = 18
        self.vb_constants.add("wdSpacingInWholePoints".lower())
        #  Substitute fonts based on font size.
        self.globals["wdSubFontBySize".lower()] = 25
        self.vb_constants.add("wdSubFontBySize".lower())
        #  Suppress extra line spacing at bottom of page.
        self.globals["wdSuppressBottomSpacing".lower()] = 29
        self.vb_constants.add("wdSuppressBottomSpacing".lower())
        #  Suppress Space Before after a hard page or column break.
        self.globals["wdSuppressSpBfAfterPgBrk".lower()] = 7
        self.vb_constants.add("wdSuppressSpBfAfterPgBrk".lower())
        #  Suppress extra line spacing at top of page.
        self.globals["wdSuppressTopSpacing".lower()] = 8
        self.vb_constants.add("wdSuppressTopSpacing".lower())
        #  Suppress extra line spacing at top of page like Word 5.x for the Macintosh.
        self.globals["wdSuppressTopSpacingMac5".lower()] = 17
        self.vb_constants.add("wdSuppressTopSpacingMac5".lower())
        #  Swap left and right borders on odd facing pages.
        self.globals["wdSwapBordersFacingPages".lower()] = 12
        self.vb_constants.add("wdSwapBordersFacingPages".lower())
        #  Do not blank the area behind metafile pictures.
        self.globals["wdTransparentMetafiles".lower()] = 10
        self.vb_constants.add("wdTransparentMetafiles".lower())
        #  Truncate font height.
        self.globals["wdTruncateFontHeight".lower()] = 24
        self.vb_constants.add("wdTruncateFontHeight".lower())
        #  Use printer metrics to lay out document.
        self.globals["wdUsePrinterMetrics".lower()] = 26
        self.vb_constants.add("wdUsePrinterMetrics".lower())
        #  Use Microsoft Word 2002 table style rules.
        self.globals["wdUseWord2002TableStyleRules".lower()] = 49
        self.vb_constants.add("wdUseWord2002TableStyleRules".lower())
        #  Use Microsoft Word 2010 table style rules.
        self.globals["wdUseWord2010TableStyleRules".lower()] = 69
        self.vb_constants.add("wdUseWord2010TableStyleRules".lower())
        #  Use Microsoft Word 97 line breaking rules for Asian text.
        self.globals["wdUseWord97LineBreakingRules".lower()] = 42
        self.vb_constants.add("wdUseWord97LineBreakingRules".lower())
        #  Do full justification like WordPerfect 6.x for Windows.
        self.globals["wdWPJustification".lower()] = 31
        self.vb_constants.add("wdWPJustification".lower())
        #  Set the width of a space like WordPerfect 5.x.
        self.globals["wdWPSpaceWidth".lower()] = 30
        self.vb_constants.add("wdWPSpaceWidth".lower())
        #  Wrap trailing spaces to next line.
        self.globals["wdWrapTrailSpaces".lower()] = 4
        self.vb_constants.add("wdWrapTrailSpaces".lower())
        #  Use Word 6.x/95 border rules.
        self.globals["wdWW6BorderRules".lower()] = 27
        self.vb_constants.add("wdWW6BorderRules".lower())
        #  Allow space between paragraphs of the same style in a table.
        self.globals["wdAllowSpaceOfSameStyleInTable".lower()] = 54
        self.vb_constants.add("wdAllowSpaceOfSameStyleInTable".lower())
        #  Use Microsoft Word 2003 table autofit rules.
        self.globals["wdAutofitLikeWW11".lower()] = 57
        self.vb_constants.add("wdAutofitLikeWW11".lower())
        #  Do not autofit tables next to wrapped objects.
        self.globals["wdDontAutofitConstrainedTables".lower()] = 56
        self.vb_constants.add("wdDontAutofitConstrainedTables".lower())
        #  Do not use hanging indent as tab stop for bullets and numbering.
        self.globals["wdDontUseIndentAsNumberingTabStop".lower()] = 52
        self.vb_constants.add("wdDontUseIndentAsNumberingTabStop".lower())
        #  Use Word 2003 hanging-punctuation rules in Asian languages.
        self.globals["wdFELineBreak11".lower()] = 53
        self.vb_constants.add("wdFELineBreak11".lower())
        #  Do not use proportional width for Korean characters.
        self.globals["wdHangulWidthLikeWW11".lower()] = 59
        self.vb_constants.add("wdHangulWidthLikeWW11".lower())
        #  Split apart page break and paragraph mark.
        self.globals["wdSplitPgBreakAndParaMark".lower()] = 60
        self.vb_constants.add("wdSplitPgBreakAndParaMark".lower())
        #  Underline the tab character between the number and the text in numbered lists.
        self.globals["wdUnderlineTabInNumList".lower()] = 58
        self.vb_constants.add("wdUnderlineTabInNumList".lower())
        #  Use the Normal style instead of the List Paragraph style for bulleted or numbered lists.
        self.globals["wdUseNormalStyleForList".lower()] = 51
        self.vb_constants.add("wdUseNormalStyleForList".lower())
        #  Use Word 2003 indent rules for text next to wrapped objects.
        self.globals["wdWW11IndentRules".lower()] = 55
        self.vb_constants.add("wdWW11IndentRules".lower())
        
        # WdLineStyle enumeration (Word)
        #   
        # Specifies the border style for an object.
        
        #  A dash followed by a dot.
        self.globals["wdLineStyleDashDot".lower()] = 5
        self.vb_constants.add("wdLineStyleDashDot".lower())
        #  A dash followed by two dots.
        self.globals["wdLineStyleDashDotDot".lower()] = 6
        self.vb_constants.add("wdLineStyleDashDotDot".lower())
        #  A dash followed by a dot stroke, thus rendering a border similar to a barber pole.
        self.globals["wdLineStyleDashDotStroked".lower()] = 20
        self.vb_constants.add("wdLineStyleDashDotStroked".lower())
        #  A dash followed by a large gap.
        self.globals["wdLineStyleDashLargeGap".lower()] = 4
        self.vb_constants.add("wdLineStyleDashLargeGap".lower())
        #  A dash followed by a small gap.
        self.globals["wdLineStyleDashSmallGap".lower()] = 3
        self.vb_constants.add("wdLineStyleDashSmallGap".lower())
        #  Dots.
        self.globals["wdLineStyleDot".lower()] = 2
        self.vb_constants.add("wdLineStyleDot".lower())
        #  Double solid lines.
        self.globals["wdLineStyleDouble".lower()] = 7
        self.vb_constants.add("wdLineStyleDouble".lower())
        #  Double wavy solid lines.
        self.globals["wdLineStyleDoubleWavy".lower()] = 19
        self.vb_constants.add("wdLineStyleDoubleWavy".lower())
        #  The border appears to have a 3D embossed look.
        self.globals["wdLineStyleEmboss3D".lower()] = 21
        self.vb_constants.add("wdLineStyleEmboss3D".lower())
        #  The border appears to have a 3D engraved look.
        self.globals["wdLineStyleEngrave3D".lower()] = 22
        self.vb_constants.add("wdLineStyleEngrave3D".lower())
        #  The border appears to be inset.
        self.globals["wdLineStyleInset".lower()] = 24
        self.vb_constants.add("wdLineStyleInset".lower())
        #  No border.
        self.globals["wdLineStyleNone".lower()] = 0
        self.vb_constants.add("wdLineStyleNone".lower())
        #  The border appears to be outset.
        self.globals["wdLineStyleOutset".lower()] = 23
        self.vb_constants.add("wdLineStyleOutset".lower())
        #  A single solid line.
        self.globals["wdLineStyleSingle".lower()] = 1
        self.vb_constants.add("wdLineStyleSingle".lower())
        #  A single wavy solid line.
        self.globals["wdLineStyleSingleWavy".lower()] = 18
        self.vb_constants.add("wdLineStyleSingleWavy".lower())
        #  An internal single thick solid line surrounded by a single thin solid line with a large gap between them.
        self.globals["wdLineStyleThickThinLargeGap".lower()] = 16
        self.vb_constants.add("wdLineStyleThickThinLargeGap".lower())
        #  An internal single thick solid line surrounded by a single thin solid line with a medium gap between them.
        self.globals["wdLineStyleThickThinMedGap".lower()] = 13
        self.vb_constants.add("wdLineStyleThickThinMedGap".lower())
        #  An internal single thick solid line surrounded by a single thin solid line with a small gap between them.
        self.globals["wdLineStyleThickThinSmallGap".lower()] = 10
        self.vb_constants.add("wdLineStyleThickThinSmallGap".lower())
        #  An internal single thin solid line surrounded by a single thick solid line with a large gap between them.
        self.globals["wdLineStyleThinThickLargeGap".lower()] = 15
        self.vb_constants.add("wdLineStyleThinThickLargeGap".lower())
        #  An internal single thin solid line surrounded by a single thick solid line with a medium gap between them.
        self.globals["wdLineStyleThinThickMedGap".lower()] = 12
        self.vb_constants.add("wdLineStyleThinThickMedGap".lower())
        #  An internal single thin solid line surrounded by a single thick solid line with a small gap between them.
        self.globals["wdLineStyleThinThickSmallGap".lower()] = 9
        self.vb_constants.add("wdLineStyleThinThickSmallGap".lower())
        #  An internal single thin solid line surrounded by a single thick solid line surrounded by a single thin solid line with a large gap between all lines.
        self.globals["wdLineStyleThinThickThinLargeGap".lower()] = 17
        self.vb_constants.add("wdLineStyleThinThickThinLargeGap".lower())
        #  An internal single thin solid line surrounded by a single thick solid line surrounded by a single thin solid line with a medium gap between all lines.
        self.globals["wdLineStyleThinThickThinMedGap".lower()] = 14
        self.vb_constants.add("wdLineStyleThinThickThinMedGap".lower())
        #  An internal single thin solid line surrounded by a single thick solid line surrounded by a single thin solid line with a small gap between all lines.
        self.globals["wdLineStyleThinThickThinSmallGap".lower()] = 11
        self.vb_constants.add("wdLineStyleThinThickThinSmallGap".lower())
        #  Three solid thin lines.
        self.globals["wdLineStyleTriple".lower()] = 8
        self.vb_constants.add("wdLineStyleTriple".lower())
        
        # WdListNumberStyle enumeration (Word)
        #   
        # Specifies the numeric style to apply to a list.
        
        #  Aiueo numeric style.
        self.globals["wdListNumberStyleAiueo".lower()] = 20
        self.vb_constants.add("wdListNumberStyleAiueo".lower())
        #  Aiueo half-width numeric style.
        self.globals["wdListNumberStyleAiueoHalfWidth".lower()] = 12
        self.vb_constants.add("wdListNumberStyleAiueoHalfWidth".lower())
        #  Arabic numeric style.
        self.globals["wdListNumberStyleArabic".lower()] = 0
        self.vb_constants.add("wdListNumberStyleArabic".lower())
        #  Arabic 1 numeric style.
        self.globals["wdListNumberStyleArabic1".lower()] = 46
        self.vb_constants.add("wdListNumberStyleArabic1".lower())
        #  Arabic 2 numeric style.
        self.globals["wdListNumberStyleArabic2".lower()] = 48
        self.vb_constants.add("wdListNumberStyleArabic2".lower())
        #  Arabic full-width numeric style.
        self.globals["wdListNumberStyleArabicFullWidth".lower()] = 14
        self.vb_constants.add("wdListNumberStyleArabicFullWidth".lower())
        #  Arabic LZ numeric style.
        self.globals["wdListNumberStyleArabicLZ".lower()] = 22
        self.vb_constants.add("wdListNumberStyleArabicLZ".lower())
        #  Arabic LZ2 numeric style.
        self.globals["wdListNumberStyleArabicLZ2".lower()] = 62
        self.vb_constants.add("wdListNumberStyleArabicLZ2".lower())
        #  Arabic LZ3 numeric style.
        self.globals["wdListNumberStyleArabicLZ3".lower()] = 63
        self.vb_constants.add("wdListNumberStyleArabicLZ3".lower())
        #  Arabic LZ4 numeric style.
        self.globals["wdListNumberStyleArabicLZ4".lower()] = 64
        self.vb_constants.add("wdListNumberStyleArabicLZ4".lower())
        #  Bullet style.
        self.globals["wdListNumberStyleBullet".lower()] = 23
        self.vb_constants.add("wdListNumberStyleBullet".lower())
        #  Cardinal text style.
        self.globals["wdListNumberStyleCardinalText".lower()] = 6
        self.vb_constants.add("wdListNumberStyleCardinalText".lower())
        #  Chosung style.
        self.globals["wdListNumberStyleChosung".lower()] = 25
        self.vb_constants.add("wdListNumberStyleChosung".lower())
        #  Ganada style.
        self.globals["wdListNumberStyleGanada".lower()] = 24
        self.vb_constants.add("wdListNumberStyleGanada".lower())
        #  GB numeric 1 style.
        self.globals["wdListNumberStyleGBNum1".lower()] = 26
        self.vb_constants.add("wdListNumberStyleGBNum1".lower())
        #  GB numeric 2 style.
        self.globals["wdListNumberStyleGBNum2".lower()] = 27
        self.vb_constants.add("wdListNumberStyleGBNum2".lower())
        #  GB numeric 3 style.
        self.globals["wdListNumberStyleGBNum3".lower()] = 28
        self.vb_constants.add("wdListNumberStyleGBNum3".lower())
        #  GB numeric 4 style.
        self.globals["wdListNumberStyleGBNum4".lower()] = 29
        self.vb_constants.add("wdListNumberStyleGBNum4".lower())
        #  Hanqul style.
        self.globals["wdListNumberStyleHangul".lower()] = 43
        self.vb_constants.add("wdListNumberStyleHangul".lower())
        #  Hanja style.
        self.globals["wdListNumberStyleHanja".lower()] = 44
        self.vb_constants.add("wdListNumberStyleHanja".lower())
        #  Hanja Read style.
        self.globals["wdListNumberStyleHanjaRead".lower()] = 41
        self.vb_constants.add("wdListNumberStyleHanjaRead".lower())
        #  Hanja Read Digit style.
        self.globals["wdListNumberStyleHanjaReadDigit".lower()] = 42
        self.vb_constants.add("wdListNumberStyleHanjaReadDigit".lower())
        #  Hebrew 1 style.
        self.globals["wdListNumberStyleHebrew1".lower()] = 45
        self.vb_constants.add("wdListNumberStyleHebrew1".lower())
        #  Hebrew 2 style.
        self.globals["wdListNumberStyleHebrew2".lower()] = 47
        self.vb_constants.add("wdListNumberStyleHebrew2".lower())
        #  Hindi Arabic style.
        self.globals["wdListNumberStyleHindiArabic".lower()] = 51
        self.vb_constants.add("wdListNumberStyleHindiArabic".lower())
        #  Hindi Cardinal text style.
        self.globals["wdListNumberStyleHindiCardinalText".lower()] = 52
        self.vb_constants.add("wdListNumberStyleHindiCardinalText".lower())
        #  Hindi letter 1 style.
        self.globals["wdListNumberStyleHindiLetter1".lower()] = 49
        self.vb_constants.add("wdListNumberStyleHindiLetter1".lower())
        #  Hindi letter 2 style.
        self.globals["wdListNumberStyleHindiLetter2".lower()] = 50
        self.vb_constants.add("wdListNumberStyleHindiLetter2".lower())
        #  Iroha style.
        self.globals["wdListNumberStyleIroha".lower()] = 21
        self.vb_constants.add("wdListNumberStyleIroha".lower())
        #  Iroha half width style.
        self.globals["wdListNumberStyleIrohaHalfWidth".lower()] = 13
        self.vb_constants.add("wdListNumberStyleIrohaHalfWidth".lower())
        #  Kanji style.
        self.globals["wdListNumberStyleKanji".lower()] = 10
        self.vb_constants.add("wdListNumberStyleKanji".lower())
        #  Kanji Digit style.
        self.globals["wdListNumberStyleKanjiDigit".lower()] = 11
        self.vb_constants.add("wdListNumberStyleKanjiDigit".lower())
        #  Kanji traditional style.
        self.globals["wdListNumberStyleKanjiTraditional".lower()] = 16
        self.vb_constants.add("wdListNumberStyleKanjiTraditional".lower())
        #  Kanji traditional 2 style.
        self.globals["wdListNumberStyleKanjiTraditional2".lower()] = 17
        self.vb_constants.add("wdListNumberStyleKanjiTraditional2".lower())
        #  Legal style.
        self.globals["wdListNumberStyleLegal".lower()] = 253
        self.vb_constants.add("wdListNumberStyleLegal".lower())
        #  Legal LZ style.
        self.globals["wdListNumberStyleLegalLZ".lower()] = 254
        self.vb_constants.add("wdListNumberStyleLegalLZ".lower())
        #  Lowercase Bulgarian style.
        self.globals["wdListNumberStyleLowercaseBulgarian".lower()] = 67
        self.vb_constants.add("wdListNumberStyleLowercaseBulgarian".lower())
        #  Lowercase Greek style.
        self.globals["wdListNumberStyleLowercaseGreek".lower()] = 60
        self.vb_constants.add("wdListNumberStyleLowercaseGreek".lower())
        #  Lowercase letter style.
        self.globals["wdListNumberStyleLowercaseLetter".lower()] = 4
        self.vb_constants.add("wdListNumberStyleLowercaseLetter".lower())
        #  Lowercase Roman style.
        self.globals["wdListNumberStyleLowercaseRoman".lower()] = 2
        self.vb_constants.add("wdListNumberStyleLowercaseRoman".lower())
        #  Lowercase Russian style.
        self.globals["wdListNumberStyleLowercaseRussian".lower()] = 58
        self.vb_constants.add("wdListNumberStyleLowercaseRussian".lower())
        #  Lowercase Turkish style.
        self.globals["wdListNumberStyleLowercaseTurkish".lower()] = 65
        self.vb_constants.add("wdListNumberStyleLowercaseTurkish".lower())
        #  No style applied.
        self.globals["wdListNumberStyleNone".lower()] = 255
        self.vb_constants.add("wdListNumberStyleNone".lower())
        #  Number in circle style.
        self.globals["wdListNumberStyleNumberInCircle".lower()] = 18
        self.vb_constants.add("wdListNumberStyleNumberInCircle".lower())
        #  Ordinal style.
        self.globals["wdListNumberStyleOrdinal".lower()] = 5
        self.vb_constants.add("wdListNumberStyleOrdinal".lower())
        #  Ordinal text style.
        self.globals["wdListNumberStyleOrdinalText".lower()] = 7
        self.vb_constants.add("wdListNumberStyleOrdinalText".lower())
        #  Picture bullet style.
        self.globals["wdListNumberStylePictureBullet".lower()] = 249
        self.vb_constants.add("wdListNumberStylePictureBullet".lower())
        #  Simplified Chinese numeric 1 style.
        self.globals["wdListNumberStyleSimpChinNum1".lower()] = 37
        self.vb_constants.add("wdListNumberStyleSimpChinNum1".lower())
        #  Simplified Chinese numeric 2 style.
        self.globals["wdListNumberStyleSimpChinNum2".lower()] = 38
        self.vb_constants.add("wdListNumberStyleSimpChinNum2".lower())
        #  Simplified Chinese numeric 3 style.
        self.globals["wdListNumberStyleSimpChinNum3".lower()] = 39
        self.vb_constants.add("wdListNumberStyleSimpChinNum3".lower())
        #  Simplified Chinese numeric 4 style.
        self.globals["wdListNumberStyleSimpChinNum4".lower()] = 40
        self.vb_constants.add("wdListNumberStyleSimpChinNum4".lower())
        #  Thai Arabic style.
        self.globals["wdListNumberStyleThaiArabic".lower()] = 54
        self.vb_constants.add("wdListNumberStyleThaiArabic".lower())
        #  Thai Cardinal text style.
        self.globals["wdListNumberStyleThaiCardinalText".lower()] = 55
        self.vb_constants.add("wdListNumberStyleThaiCardinalText".lower())
        #  Thai letter style.
        self.globals["wdListNumberStyleThaiLetter".lower()] = 53
        self.vb_constants.add("wdListNumberStyleThaiLetter".lower())
        #  Traditional Chinese numeric 1 style.
        self.globals["wdListNumberStyleTradChinNum1".lower()] = 33
        self.vb_constants.add("wdListNumberStyleTradChinNum1".lower())
        #  Traditional Chinese numeric 2 style.
        self.globals["wdListNumberStyleTradChinNum2".lower()] = 34
        self.vb_constants.add("wdListNumberStyleTradChinNum2".lower())
        #  Traditional Chinese numeric 3 style.
        self.globals["wdListNumberStyleTradChinNum3".lower()] = 35
        self.vb_constants.add("wdListNumberStyleTradChinNum3".lower())
        #  Traditional Chinese numeric 4 style.
        self.globals["wdListNumberStyleTradChinNum4".lower()] = 36
        self.vb_constants.add("wdListNumberStyleTradChinNum4".lower())
        #  Uppercase Bulgarian style.
        self.globals["wdListNumberStyleUppercaseBulgarian".lower()] = 68
        self.vb_constants.add("wdListNumberStyleUppercaseBulgarian".lower())
        #  Uppercase Greek style.
        self.globals["wdListNumberStyleUppercaseGreek".lower()] = 61
        self.vb_constants.add("wdListNumberStyleUppercaseGreek".lower())
        #  Uppercase letter style.
        self.globals["wdListNumberStyleUppercaseLetter".lower()] = 3
        self.vb_constants.add("wdListNumberStyleUppercaseLetter".lower())
        #  Uppercase Roman style.
        self.globals["wdListNumberStyleUppercaseRoman".lower()] = 1
        self.vb_constants.add("wdListNumberStyleUppercaseRoman".lower())
        #  Uppercase Russian style.
        self.globals["wdListNumberStyleUppercaseRussian".lower()] = 59
        self.vb_constants.add("wdListNumberStyleUppercaseRussian".lower())
        #  Uppercase Turkish style.
        self.globals["wdListNumberStyleUppercaseTurkish".lower()] = 66
        self.vb_constants.add("wdListNumberStyleUppercaseTurkish".lower())
        #  Vietnamese Cardinal text style.
        self.globals["wdListNumberStyleVietCardinalText".lower()] = 56
        self.vb_constants.add("wdListNumberStyleVietCardinalText".lower())
        #  Zodiac 1 style.
        self.globals["wdListNumberStyleZodiac1".lower()] = 30
        self.vb_constants.add("wdListNumberStyleZodiac1".lower())
        #  Zodiac 2 style.
        self.globals["wdListNumberStyleZodiac2".lower()] = 31
        self.vb_constants.add("wdListNumberStyleZodiac2".lower())
        #  Zodiac 3 style.
        self.globals["wdListNumberStyleZodiac3".lower()] = 32
        self.vb_constants.add("wdListNumberStyleZodiac3".lower())
        
        # WdMoveToTextMark enumeration (Word)
        #    
        # Marks the moved-to text when text in a document with tracked changes is moved from one place to another.
        
        #  Marks moved text with bold formatting.
        self.globals["wdMoveToTextMarkBold".lower()] = 1
        self.vb_constants.add("wdMoveToTextMarkBold".lower())
        #  Marks moved text with color only. Use the MoveToTextColor property to set the color of moved text.
        self.globals["wdMoveToTextMarkColorOnly".lower()] = 5
        self.vb_constants.add("wdMoveToTextMarkColorOnly".lower())
        #  Moved text is marked with a double strikethrough.
        self.globals["wdMoveToTextMarkDoubleStrikeThrough".lower()] = 7
        self.vb_constants.add("wdMoveToTextMarkDoubleStrikeThrough".lower())
        #  Moved text is marked with a double underline.
        self.globals["wdMoveToTextMarkDoubleUnderline".lower()] = 4
        self.vb_constants.add("wdMoveToTextMarkDoubleUnderline".lower())
        #  Marks moved text with italic formatting.
        self.globals["wdMoveToTextMarkItalic".lower()] = 2
        self.vb_constants.add("wdMoveToTextMarkItalic".lower())
        #  No special formatting for moved text.
        self.globals["wdMoveToTextMarkNone".lower()] = 0
        self.vb_constants.add("wdMoveToTextMarkNone".lower())
        #  Moved text is marked with a strikethrough.
        self.globals["wdMoveToTextMarkStrikeThrough".lower()] = 6
        self.vb_constants.add("wdMoveToTextMarkStrikeThrough".lower())
        #  Underlines moved text.
        self.globals["wdMoveToTextMarkUnderline".lower()] = 3
        self.vb_constants.add("wdMoveToTextMarkUnderline".lower())
        
        # WdNumberSpacing enumeration (Word)
        #   
        # Specifies the number spacing setting for an OpenType font.
        
        #  Applies the default number spacing for the font.
        self.globals["wdNumberSpacingDefault".lower()] = 0
        self.vb_constants.add("wdNumberSpacingDefault".lower())
        #  Applies proportional number spacing to the font.
        self.globals["wdNumberSpacingProportional".lower()] = 1
        self.vb_constants.add("wdNumberSpacingProportional".lower())
        #  Applies tabular number spacing to the font.
        self.globals["wdNumberSpacingTabular".lower()] = 2
        self.vb_constants.add("wdNumberSpacingTabular".lower())
        
        # WdPageNumberStyle enumeration (Word)
        #   
        # Specifies the style to apply to page numbers.
        
        #  Arabic style.
        self.globals["wdPageNumberStyleArabic".lower()] = 0
        self.vb_constants.add("wdPageNumberStyleArabic".lower())
        #  Arabic full width style.
        self.globals["wdPageNumberStyleArabicFullWidth".lower()] = 14
        self.vb_constants.add("wdPageNumberStyleArabicFullWidth".lower())
        #  Arabic letter 1 style.
        self.globals["wdPageNumberStyleArabicLetter1".lower()] = 46
        self.vb_constants.add("wdPageNumberStyleArabicLetter1".lower())
        #  Arabic letter 2 style.
        self.globals["wdPageNumberStyleArabicLetter2".lower()] = 48
        self.vb_constants.add("wdPageNumberStyleArabicLetter2".lower())
        #  Hanja Read style.
        self.globals["wdPageNumberStyleHanjaRead".lower()] = 41
        self.vb_constants.add("wdPageNumberStyleHanjaRead".lower())
        #  Hanja Read Digit style.
        self.globals["wdPageNumberStyleHanjaReadDigit".lower()] = 42
        self.vb_constants.add("wdPageNumberStyleHanjaReadDigit".lower())
        #  Hebrew letter 1 style.
        self.globals["wdPageNumberStyleHebrewLetter1".lower()] = 45
        self.vb_constants.add("wdPageNumberStyleHebrewLetter1".lower())
        #  Hebrew letter 2 style.
        self.globals["wdPageNumberStyleHebrewLetter2".lower()] = 47
        self.vb_constants.add("wdPageNumberStyleHebrewLetter2".lower())
        #  Hindi Arabic style.
        self.globals["wdPageNumberStyleHindiArabic".lower()] = 51
        self.vb_constants.add("wdPageNumberStyleHindiArabic".lower())
        #  Hindi Cardinal text style.
        self.globals["wdPageNumberStyleHindiCardinalText".lower()] = 52
        self.vb_constants.add("wdPageNumberStyleHindiCardinalText".lower())
        #  Hindi letter 1 style.
        self.globals["wdPageNumberStyleHindiLetter1".lower()] = 49
        self.vb_constants.add("wdPageNumberStyleHindiLetter1".lower())
        #  Hindi letter 2 style.
        self.globals["wdPageNumberStyleHindiLetter2".lower()] = 50
        self.vb_constants.add("wdPageNumberStyleHindiLetter2".lower())
        #  Kanji style.
        self.globals["wdPageNumberStyleKanji".lower()] = 10
        self.vb_constants.add("wdPageNumberStyleKanji".lower())
        #  Kanji Digit style.
        self.globals["wdPageNumberStyleKanjiDigit".lower()] = 11
        self.vb_constants.add("wdPageNumberStyleKanjiDigit".lower())
        #  Kanji traditional style.
        self.globals["wdPageNumberStyleKanjiTraditional".lower()] = 16
        self.vb_constants.add("wdPageNumberStyleKanjiTraditional".lower())
        #  Lowercase letter style.
        self.globals["wdPageNumberStyleLowercaseLetter".lower()] = 4
        self.vb_constants.add("wdPageNumberStyleLowercaseLetter".lower())
        #  Lowercase Roman style.
        self.globals["wdPageNumberStyleLowercaseRoman".lower()] = 2
        self.vb_constants.add("wdPageNumberStyleLowercaseRoman".lower())
        #  Number in circle style.
        self.globals["wdPageNumberStyleNumberInCircle".lower()] = 18
        self.vb_constants.add("wdPageNumberStyleNumberInCircle".lower())
        #  Number in dash style.
        self.globals["wdPageNumberStyleNumberInDash".lower()] = 57
        self.vb_constants.add("wdPageNumberStyleNumberInDash".lower())
        #  Simplified Chinese number 1 style.
        self.globals["wdPageNumberStyleSimpChinNum1".lower()] = 37
        self.vb_constants.add("wdPageNumberStyleSimpChinNum1".lower())
        #  Simplified Chinese number 2 style.
        self.globals["wdPageNumberStyleSimpChinNum2".lower()] = 38
        self.vb_constants.add("wdPageNumberStyleSimpChinNum2".lower())
        #  Thai Arabic style.
        self.globals["wdPageNumberStyleThaiArabic".lower()] = 54
        self.vb_constants.add("wdPageNumberStyleThaiArabic".lower())
        #  Thai Cardinal Text style.
        self.globals["wdPageNumberStyleThaiCardinalText".lower()] = 55
        self.vb_constants.add("wdPageNumberStyleThaiCardinalText".lower())
        #  Thai letter style.
        self.globals["wdPageNumberStyleThaiLetter".lower()] = 53
        self.vb_constants.add("wdPageNumberStyleThaiLetter".lower())
        #  Traditional Chinese number 1 style.
        self.globals["wdPageNumberStyleTradChinNum1".lower()] = 33
        self.vb_constants.add("wdPageNumberStyleTradChinNum1".lower())
        #  Traditional Chinese number 2 style.
        self.globals["wdPageNumberStyleTradChinNum2".lower()] = 34
        self.vb_constants.add("wdPageNumberStyleTradChinNum2".lower())
        #  Uppercase letter style.
        self.globals["wdPageNumberStyleUppercaseLetter".lower()] = 3
        self.vb_constants.add("wdPageNumberStyleUppercaseLetter".lower())
        #  Uppercase Roman style.
        self.globals["wdPageNumberStyleUppercaseRoman".lower()] = 1
        self.vb_constants.add("wdPageNumberStyleUppercaseRoman".lower())
        #  Vietnamese Cardinal text style.
        self.globals["wdPageNumberStyleVietCardinalText".lower()] = 56
        self.vb_constants.add("wdPageNumberStyleVietCardinalText".lower())
        
        # WdEnvelopeOrientation enumeration (Word)
        #   
        # Specifies the orientation of envelopes.
        
        #  Center clockwise orientation.
        self.globals["wdCenterClockwise".lower()] = 7
        self.vb_constants.add("wdCenterClockwise".lower())
        #  Center landscape orientation.
        self.globals["wdCenterLandscape".lower()] = 4
        self.vb_constants.add("wdCenterLandscape".lower())
        #  Center portrait orientation.
        self.globals["wdCenterPortrait".lower()] = 1
        self.vb_constants.add("wdCenterPortrait".lower())
        #  Left clockwise orientation.
        self.globals["wdLeftClockwise".lower()] = 6
        self.vb_constants.add("wdLeftClockwise".lower())
        #  Left landscape orientation.
        self.globals["wdLeftLandscape".lower()] = 3
        self.vb_constants.add("wdLeftLandscape".lower())
        #  Left portrait orientation.
        self.globals["wdLeftPortrait".lower()] = 0
        self.vb_constants.add("wdLeftPortrait".lower())
        #  Right clockwise orientation.
        self.globals["wdRightClockwise".lower()] = 8
        self.vb_constants.add("wdRightClockwise".lower())
        #  Right landscape orientation.
        self.globals["wdRightLandscape".lower()] = 5
        self.vb_constants.add("wdRightLandscape".lower())
        #  Right portrait orientation.
        self.globals["wdRightPortrait".lower()] = 2
        self.vb_constants.add("wdRightPortrait".lower())
        
        # WdSelectionFlags enumeration (Word)
        #   
        # Specifies the properties of the selection.
        
        #  The selection is the active selection.
        self.globals["wdSelActive".lower()] = 8
        self.vb_constants.add("wdSelActive".lower())
        #  The selection is at the end of the letter.
        self.globals["wdSelAtEOL".lower()] = 2
        self.vb_constants.add("wdSelAtEOL".lower())
        #  The selection was overtyped.
        self.globals["wdSelOvertype".lower()] = 4
        self.vb_constants.add("wdSelOvertype".lower())
        #  The selection was replaced.
        self.globals["wdSelReplace".lower()] = 16
        self.vb_constants.add("wdSelReplace".lower())
        #  The selection is at the start of the active document.
        self.globals["wdSelStartActive".lower()] = 1
        self.vb_constants.add("wdSelStartActive".lower())
        
        # WdSortFieldType enumeration (Word)
        #   
        # Specifies the sort type to apply when sorting a column.
        
        #  Alphanumeric order.
        self.globals["wdSortFieldAlphanumeric".lower()] = 0
        self.vb_constants.add("wdSortFieldAlphanumeric".lower())
        #  Date order.
        self.globals["wdSortFieldDate".lower()] = 2
        self.vb_constants.add("wdSortFieldDate".lower())
        #  Japanese JIS order.
        self.globals["wdSortFieldJapanJIS".lower()] = 4
        self.vb_constants.add("wdSortFieldJapanJIS".lower())
        #  Korean KS order.
        self.globals["wdSortFieldKoreaKS".lower()] = 6
        self.vb_constants.add("wdSortFieldKoreaKS".lower())
        #  Numeric order.
        self.globals["wdSortFieldNumeric".lower()] = 1
        self.vb_constants.add("wdSortFieldNumeric".lower())
        #  Stroke order.
        self.globals["wdSortFieldStroke".lower()] = 5
        self.vb_constants.add("wdSortFieldStroke".lower())
        #  Syllable order.
        self.globals["wdSortFieldSyllable".lower()] = 3
        self.vb_constants.add("wdSortFieldSyllable".lower())
        
        # WdSortSeparator enumeration (Word)
        #
        # Specifies the type of field separator.
        
        #  Comma.
        self.globals["wdSortSeparateByCommas".lower()] = 1
        self.vb_constants.add("wdSortSeparateByCommas".lower())
        #  Default table separator.
        self.globals["wdSortSeparateByDefaultTableSeparator".lower()] = 2
        self.vb_constants.add("wdSortSeparateByDefaultTableSeparator".lower())
        #  Tab.
        self.globals["wdSortSeparateByTabs".lower()] = 0
        self.vb_constants.add("wdSortSeparateByTabs".lower())
        
        # WdTableFormatApply enumeration (Word)
        #
        # Specifies how table formatting should be applied.
        
        #  AutoFit.
        self.globals["wdTableFormatApplyAutoFit".lower()] = 16
        self.vb_constants.add("wdTableFormatApplyAutoFit".lower())
        #  Borders.
        self.globals["wdTableFormatApplyBorders".lower()] = 1
        self.vb_constants.add("wdTableFormatApplyBorders".lower())
        #  Color.
        self.globals["wdTableFormatApplyColor".lower()] = 8
        self.vb_constants.add("wdTableFormatApplyColor".lower())
        #  Apply AutoFormat to first column.
        self.globals["wdTableFormatApplyFirstColumn".lower()] = 128
        self.vb_constants.add("wdTableFormatApplyFirstColumn".lower())
        #  Font.
        self.globals["wdTableFormatApplyFont".lower()] = 4
        self.vb_constants.add("wdTableFormatApplyFont".lower())
        #  Apply AutoFormat to heading rows.
        self.globals["wdTableFormatApplyHeadingRows".lower()] = 32
        self.vb_constants.add("wdTableFormatApplyHeadingRows".lower())
        #  Apply AutoFormat to last column.
        self.globals["wdTableFormatApplyLastColumn".lower()] = 256
        self.vb_constants.add("wdTableFormatApplyLastColumn".lower())
        #  Apply AutoFormat to last row.
        self.globals["wdTableFormatApplyLastRow".lower()] = 64
        self.vb_constants.add("wdTableFormatApplyLastRow".lower())
        #  Shading.
        self.globals["wdTableFormatApplyShading".lower()] = 2
        self.vb_constants.add("wdTableFormatApplyShading".lower())
        
        # WdTableFormat enumeration (Word)
        #   
        # Specifies the predefined format to apply to a table.
        
        #  3D effects format number 1.
        self.globals["wdTableFormat3DEffects1".lower()] = 32
        self.vb_constants.add("wdTableFormat3DEffects1".lower())
        #  3D effects format number 2.
        self.globals["wdTableFormat3DEffects2".lower()] = 33
        self.vb_constants.add("wdTableFormat3DEffects2".lower())
        #  3D effects format number 3.
        self.globals["wdTableFormat3DEffects3".lower()] = 34
        self.vb_constants.add("wdTableFormat3DEffects3".lower())
        #  Classic format number 1.
        self.globals["wdTableFormatClassic1".lower()] = 4
        self.vb_constants.add("wdTableFormatClassic1".lower())
        #  Classic format number 2.
        self.globals["wdTableFormatClassic2".lower()] = 5
        self.vb_constants.add("wdTableFormatClassic2".lower())
        #  Classic format number 3.
        self.globals["wdTableFormatClassic3".lower()] = 6
        self.vb_constants.add("wdTableFormatClassic3".lower())
        #  Classic format number 4.
        self.globals["wdTableFormatClassic4".lower()] = 7
        self.vb_constants.add("wdTableFormatClassic4".lower())
        #  Colorful format number 1.
        self.globals["wdTableFormatColorful1".lower()] = 8
        self.vb_constants.add("wdTableFormatColorful1".lower())
        #  Colorful format number 2.
        self.globals["wdTableFormatColorful2".lower()] = 9
        self.vb_constants.add("wdTableFormatColorful2".lower())
        #  Colorful format number 3.
        self.globals["wdTableFormatColorful3".lower()] = 10
        self.vb_constants.add("wdTableFormatColorful3".lower())
        #  Columns format number 1.
        self.globals["wdTableFormatColumns1".lower()] = 11
        self.vb_constants.add("wdTableFormatColumns1".lower())
        #  Columns format number 2.
        self.globals["wdTableFormatColumns2".lower()] = 12
        self.vb_constants.add("wdTableFormatColumns2".lower())
        #  Columns format number 3.
        self.globals["wdTableFormatColumns3".lower()] = 13
        self.vb_constants.add("wdTableFormatColumns3".lower())
        #  Columns format number 4.
        self.globals["wdTableFormatColumns4".lower()] = 14
        self.vb_constants.add("wdTableFormatColumns4".lower())
        #  Columns format number 5.
        self.globals["wdTableFormatColumns5".lower()] = 15
        self.vb_constants.add("wdTableFormatColumns5".lower())
        #  Contemporary format.
        self.globals["wdTableFormatContemporary".lower()] = 35
        self.vb_constants.add("wdTableFormatContemporary".lower())
        #  Elegant format.
        self.globals["wdTableFormatElegant".lower()] = 36
        self.vb_constants.add("wdTableFormatElegant".lower())
        #  Grid format number 1.
        self.globals["wdTableFormatGrid1".lower()] = 16
        self.vb_constants.add("wdTableFormatGrid1".lower())
        #  Grid format number 2.
        self.globals["wdTableFormatGrid2".lower()] = 17
        self.vb_constants.add("wdTableFormatGrid2".lower())
        #  Grid format number 3.
        self.globals["wdTableFormatGrid3".lower()] = 18
        self.vb_constants.add("wdTableFormatGrid3".lower())
        #  Grid format number 4.
        self.globals["wdTableFormatGrid4".lower()] = 19
        self.vb_constants.add("wdTableFormatGrid4".lower())
        #  Grid format number 5.
        self.globals["wdTableFormatGrid5".lower()] = 20
        self.vb_constants.add("wdTableFormatGrid5".lower())
        #  Grid format number 6.
        self.globals["wdTableFormatGrid6".lower()] = 21
        self.vb_constants.add("wdTableFormatGrid6".lower())
        #  Grid format number 7.
        self.globals["wdTableFormatGrid7".lower()] = 22
        self.vb_constants.add("wdTableFormatGrid7".lower())
        #  Grid format number 8.
        self.globals["wdTableFormatGrid8".lower()] = 23
        self.vb_constants.add("wdTableFormatGrid8".lower())
        #  List format number 1.
        self.globals["wdTableFormatList1".lower()] = 24
        self.vb_constants.add("wdTableFormatList1".lower())
        #  List format number 2.
        self.globals["wdTableFormatList2".lower()] = 25
        self.vb_constants.add("wdTableFormatList2".lower())
        #  List format number 3.
        self.globals["wdTableFormatList3".lower()] = 26
        self.vb_constants.add("wdTableFormatList3".lower())
        #  List format number 4.
        self.globals["wdTableFormatList4".lower()] = 27
        self.vb_constants.add("wdTableFormatList4".lower())
        #  List format number 5.
        self.globals["wdTableFormatList5".lower()] = 28
        self.vb_constants.add("wdTableFormatList5".lower())
        #  List format number 6.
        self.globals["wdTableFormatList6".lower()] = 29
        self.vb_constants.add("wdTableFormatList6".lower())
        #  List format number 7.
        self.globals["wdTableFormatList7".lower()] = 30
        self.vb_constants.add("wdTableFormatList7".lower())
        #  List format number 8.
        self.globals["wdTableFormatList8".lower()] = 31
        self.vb_constants.add("wdTableFormatList8".lower())
        #  No formatting.
        self.globals["wdTableFormatNone".lower()] = 0
        self.vb_constants.add("wdTableFormatNone".lower())
        #  Professional format.
        self.globals["wdTableFormatProfessional".lower()] = 37
        self.vb_constants.add("wdTableFormatProfessional".lower())
        #  Simple format number 1.
        self.globals["wdTableFormatSimple1".lower()] = 1
        self.vb_constants.add("wdTableFormatSimple1".lower())
        #  Simple format number 2.
        self.globals["wdTableFormatSimple2".lower()] = 2
        self.vb_constants.add("wdTableFormatSimple2".lower())
        #  Simple format number 3.
        self.globals["wdTableFormatSimple3".lower()] = 3
        self.vb_constants.add("wdTableFormatSimple3".lower())
        #  Subtle format number 1.
        self.globals["wdTableFormatSubtle1".lower()] = 38
        self.vb_constants.add("wdTableFormatSubtle1".lower())
        #  Subtle format number 2.
        self.globals["wdTableFormatSubtle2".lower()] = 39
        self.vb_constants.add("wdTableFormatSubtle2".lower())
        #  Web format number 1.
        self.globals["wdTableFormatWeb1".lower()] = 40
        self.vb_constants.add("wdTableFormatWeb1".lower())
        #  Web format number 2.
        self.globals["wdTableFormatWeb2".lower()] = 41
        self.vb_constants.add("wdTableFormatWeb2".lower())
        #  Web format number 3.
        self.globals["wdTableFormatWeb3".lower()] = 42
        self.vb_constants.add("wdTableFormatWeb3".lower())
        
        # WdLineType enumeration (Word)
        #   
        # Specifies whether a line is a line of text or a table row.
        
        #  A table row.
        self.globals["wdTableRow".lower()] = 1
        self.vb_constants.add("wdTableRow".lower())
        #  A line of text in the body of the document.
        self.globals["wdTextLine".lower()] = 0
        self.vb_constants.add("wdTextLine".lower())
        
        # WdTextureIndex enumeration (Word)
        #   
        # Specifies the shading texture to use for a selected item.
        
        #  10 percent shading.
        self.globals["wdTexture10Percent".lower()] = 100
        self.vb_constants.add("wdTexture10Percent".lower())
        #  12.5 percent shading.
        self.globals["wdTexture12Pt5Percent".lower()] = 125
        self.vb_constants.add("wdTexture12Pt5Percent".lower())
        #  15 percent shading.
        self.globals["wdTexture15Percent".lower()] = 150
        self.vb_constants.add("wdTexture15Percent".lower())
        #  17.5 percent shading.
        self.globals["wdTexture17Pt5Percent".lower()] = 175
        self.vb_constants.add("wdTexture17Pt5Percent".lower())
        #  20 percent shading.
        self.globals["wdTexture20Percent".lower()] = 200
        self.vb_constants.add("wdTexture20Percent".lower())
        #  22.5 percent shading.
        self.globals["wdTexture22Pt5Percent".lower()] = 225
        self.vb_constants.add("wdTexture22Pt5Percent".lower())
        #  25 percent shading.
        self.globals["wdTexture25Percent".lower()] = 250
        self.vb_constants.add("wdTexture25Percent".lower())
        #  27.5 percent shading.
        self.globals["wdTexture27Pt5Percent".lower()] = 275
        self.vb_constants.add("wdTexture27Pt5Percent".lower())
        #  2.5 percent shading.
        self.globals["wdTexture2Pt5Percent".lower()] = 25
        self.vb_constants.add("wdTexture2Pt5Percent".lower())
        #  30 percent shading.
        self.globals["wdTexture30Percent".lower()] = 300
        self.vb_constants.add("wdTexture30Percent".lower())
        #  32.5 percent shading.
        self.globals["wdTexture32Pt5Percent".lower()] = 325
        self.vb_constants.add("wdTexture32Pt5Percent".lower())
        #  35 percent shading.
        self.globals["wdTexture35Percent".lower()] = 350
        self.vb_constants.add("wdTexture35Percent".lower())
        #  37.5 percent shading.
        self.globals["wdTexture37Pt5Percent".lower()] = 375
        self.vb_constants.add("wdTexture37Pt5Percent".lower())
        #  40 percent shading.
        self.globals["wdTexture40Percent".lower()] = 400
        self.vb_constants.add("wdTexture40Percent".lower())
        #  42.5 percent shading.
        self.globals["wdTexture42Pt5Percent".lower()] = 425
        self.vb_constants.add("wdTexture42Pt5Percent".lower())
        #  45 percent shading.
        self.globals["wdTexture45Percent".lower()] = 450
        self.vb_constants.add("wdTexture45Percent".lower())
        #  47.5 percent shading.
        self.globals["wdTexture47Pt5Percent".lower()] = 475
        self.vb_constants.add("wdTexture47Pt5Percent".lower())
        #  50 percent shading.
        self.globals["wdTexture50Percent".lower()] = 500
        self.vb_constants.add("wdTexture50Percent".lower())
        #  52.5 percent shading.
        self.globals["wdTexture52Pt5Percent".lower()] = 525
        self.vb_constants.add("wdTexture52Pt5Percent".lower())
        #  55 percent shading.
        self.globals["wdTexture55Percent".lower()] = 550
        self.vb_constants.add("wdTexture55Percent".lower())
        #  57.5 percent shading.
        self.globals["wdTexture57Pt5Percent".lower()] = 575
        self.vb_constants.add("wdTexture57Pt5Percent".lower())
        #  5 percent shading.
        self.globals["wdTexture5Percent".lower()] = 50
        self.vb_constants.add("wdTexture5Percent".lower())
        #  60 percent shading.
        self.globals["wdTexture60Percent".lower()] = 600
        self.vb_constants.add("wdTexture60Percent".lower())
        #  62.5 percent shading.
        self.globals["wdTexture62Pt5Percent".lower()] = 625
        self.vb_constants.add("wdTexture62Pt5Percent".lower())
        #  65 percent shading.
        self.globals["wdTexture65Percent".lower()] = 650
        self.vb_constants.add("wdTexture65Percent".lower())
        #  67.5 percent shading.
        self.globals["wdTexture67Pt5Percent".lower()] = 675
        self.vb_constants.add("wdTexture67Pt5Percent".lower())
        #  70 percent shading.
        self.globals["wdTexture70Percent".lower()] = 700
        self.vb_constants.add("wdTexture70Percent".lower())
        #  72.5 percent shading.
        self.globals["wdTexture72Pt5Percent".lower()] = 725
        self.vb_constants.add("wdTexture72Pt5Percent".lower())
        #  75 percent shading.
        self.globals["wdTexture75Percent".lower()] = 750
        self.vb_constants.add("wdTexture75Percent".lower())
        #  77.5 percent shading.
        self.globals["wdTexture77Pt5Percent".lower()] = 775
        self.vb_constants.add("wdTexture77Pt5Percent".lower())
        #  7.5 percent shading.
        self.globals["wdTexture7Pt5Percent".lower()] = 75
        self.vb_constants.add("wdTexture7Pt5Percent".lower())
        #  80 percent shading.
        self.globals["wdTexture80Percent".lower()] = 800
        self.vb_constants.add("wdTexture80Percent".lower())
        #  82.5 percent shading.
        self.globals["wdTexture82Pt5Percent".lower()] = 825
        self.vb_constants.add("wdTexture82Pt5Percent".lower())
        #  85 percent shading.
        self.globals["wdTexture85Percent".lower()] = 850
        self.vb_constants.add("wdTexture85Percent".lower())
        #  87.5 percent shading.
        self.globals["wdTexture87Pt5Percent".lower()] = 875
        self.vb_constants.add("wdTexture87Pt5Percent".lower())
        #  90 percent shading.
        self.globals["wdTexture90Percent".lower()] = 900
        self.vb_constants.add("wdTexture90Percent".lower())
        #  92.5 percent shading.
        self.globals["wdTexture92Pt5Percent".lower()] = 925
        self.vb_constants.add("wdTexture92Pt5Percent".lower())
        #  95 percent shading.
        self.globals["wdTexture95Percent".lower()] = 950
        self.vb_constants.add("wdTexture95Percent".lower())
        #  97.5 percent shading.
        self.globals["wdTexture97Pt5Percent".lower()] = 975
        self.vb_constants.add("wdTexture97Pt5Percent".lower())
        #  Horizontal cross shading.
        self.globals["wdTextureCross".lower()] = -11
        self.vb_constants.add("wdTextureCross".lower())
        #  Dark horizontal cross shading.
        self.globals["wdTextureDarkCross".lower()] = -5
        self.vb_constants.add("wdTextureDarkCross".lower())
        #  Dark diagonal cross shading.
        self.globals["wdTextureDarkDiagonalCross".lower()] = -6
        self.vb_constants.add("wdTextureDarkDiagonalCross".lower())
        #  Dark diagonal down shading.
        self.globals["wdTextureDarkDiagonalDown".lower()] = -3
        self.vb_constants.add("wdTextureDarkDiagonalDown".lower())
        #  Dark diagonal up shading.
        self.globals["wdTextureDarkDiagonalUp".lower()] = -4
        self.vb_constants.add("wdTextureDarkDiagonalUp".lower())
        #  Dark horizontal shading.
        self.globals["wdTextureDarkHorizontal".lower()] = -1
        self.vb_constants.add("wdTextureDarkHorizontal".lower())
        #  Dark vertical shading.
        self.globals["wdTextureDarkVertical".lower()] = -2
        self.vb_constants.add("wdTextureDarkVertical".lower())
        #  Diagonal cross shading.
        self.globals["wdTextureDiagonalCross".lower()] = -12
        self.vb_constants.add("wdTextureDiagonalCross".lower())
        #  Diagonal down shading.
        self.globals["wdTextureDiagonalDown".lower()] = -9
        self.vb_constants.add("wdTextureDiagonalDown".lower())
        #  Diagonal up shading.
        self.globals["wdTextureDiagonalUp".lower()] = -10
        self.vb_constants.add("wdTextureDiagonalUp".lower())
        #  Horizontal shading.
        self.globals["wdTextureHorizontal".lower()] = -7
        self.vb_constants.add("wdTextureHorizontal".lower())
        #  No shading.
        self.globals["wdTextureNone".lower()] = 0
        self.vb_constants.add("wdTextureNone".lower())
        #  Solid shading.
        self.globals["wdTextureSolid".lower()] = 1000
        self.vb_constants.add("wdTextureSolid".lower())
        #  Vertical shading.
        self.globals["wdTextureVertical".lower()] = -8
        self.vb_constants.add("wdTextureVertical".lower())
        
        # WdTofFormat enumeration (Word)
        #   
        # Specifies the type of formatting to apply to the table of figures in the active document.
        
        #  Centered formatting.
        self.globals["wdTOFCentered".lower()] = 3
        self.vb_constants.add("wdTOFCentered".lower())
        #  Classic formatting.
        self.globals["wdTOFClassic".lower()] = 1
        self.vb_constants.add("wdTOFClassic".lower())
        #  Distinctive formatting.
        self.globals["wdTOFDistinctive".lower()] = 2
        self.vb_constants.add("wdTOFDistinctive".lower())
        #  Formal formatting.
        self.globals["wdTOFFormal".lower()] = 4
        self.vb_constants.add("wdTOFFormal".lower())
        #  Simple formatting.
        self.globals["wdTOFSimple".lower()] = 5
        self.vb_constants.add("wdTOFSimple".lower())
        #  Template formatting.
        self.globals["wdTOFTemplate".lower()] = 0
        self.vb_constants.add("wdTOFTemplate".lower())
        
        # WdTwoLinesInOneType enumeration (Word)
        #   
        # Specifies the character to use to enclose two lines being written into one.
        
        #  Enclose the lines using angle brackets.
        self.globals["wdTwoLinesInOneAngleBrackets".lower()] = 4
        self.vb_constants.add("wdTwoLinesInOneAngleBrackets".lower())
        #  Enclose the lines using curly brackets.
        self.globals["wdTwoLinesInOneCurlyBrackets".lower()] = 5
        self.vb_constants.add("wdTwoLinesInOneCurlyBrackets".lower())
        #  Use no enclosing character.
        self.globals["wdTwoLinesInOneNoBrackets".lower()] = 1
        self.vb_constants.add("wdTwoLinesInOneNoBrackets".lower())
        #  Restore the two lines of text written into one to two separate lines.
        self.globals["wdTwoLinesInOneNone".lower()] = 0
        self.vb_constants.add("wdTwoLinesInOneNone".lower())
        #  Enclose the lines using parentheses.
        self.globals["wdTwoLinesInOneParentheses".lower()] = 2
        self.vb_constants.add("wdTwoLinesInOneParentheses".lower())
        #  Enclose the lines using square brackets.
        self.globals["wdTwoLinesInOneSquareBrackets".lower()] = 3
        self.vb_constants.add("wdTwoLinesInOneSquareBrackets".lower())
        
        # WdCountry enumeration (Word)
        #   
        # Specifies the country/region setting of the current system.
        
        #  Argentina
        self.globals["wdArgentina".lower()] = 54
        self.vb_constants.add("wdArgentina".lower())
        #  Brazil
        self.globals["wdBrazil".lower()] = 55
        self.vb_constants.add("wdBrazil".lower())
        #  Canada
        self.globals["wdCanada".lower()] = 2
        self.vb_constants.add("wdCanada".lower())
        #  Chile
        self.globals["wdChile".lower()] = 56
        self.vb_constants.add("wdChile".lower())
        #  China
        self.globals["wdChina".lower()] = 86
        self.vb_constants.add("wdChina".lower())
        #  Denmark
        self.globals["wdDenmark".lower()] = 45
        self.vb_constants.add("wdDenmark".lower())
        #  Finland
        self.globals["wdFinland".lower()] = 358
        self.vb_constants.add("wdFinland".lower())
        #  France
        self.globals["wdFrance".lower()] = 33
        self.vb_constants.add("wdFrance".lower())
        #  Germany
        self.globals["wdGermany".lower()] = 49
        self.vb_constants.add("wdGermany".lower())
        #  Iceland
        self.globals["wdIceland".lower()] = 354
        self.vb_constants.add("wdIceland".lower())
        #  Italy
        self.globals["wdItaly".lower()] = 39
        self.vb_constants.add("wdItaly".lower())
        #  Japan
        self.globals["wdJapan".lower()] = 81
        self.vb_constants.add("wdJapan".lower())
        #  Korea
        self.globals["wdKorea".lower()] = 82
        self.vb_constants.add("wdKorea".lower())
        #  Latin America
        self.globals["wdLatinAmerica".lower()] = 3
        self.vb_constants.add("wdLatinAmerica".lower())
        #  Mexico
        self.globals["wdMexico".lower()] = 52
        self.vb_constants.add("wdMexico".lower())
        #  Netherlands
        self.globals["wdNetherlands".lower()] = 31
        self.vb_constants.add("wdNetherlands".lower())
        #  Norway
        self.globals["wdNorway".lower()] = 47
        self.vb_constants.add("wdNorway".lower())
        #  Peru
        self.globals["wdPeru".lower()] = 51
        self.vb_constants.add("wdPeru".lower())
        #  Spain
        self.globals["wdSpain".lower()] = 34
        self.vb_constants.add("wdSpain".lower())
        #  Sweden
        self.globals["wdSweden".lower()] = 46
        self.vb_constants.add("wdSweden".lower())
        #  Taiwan
        self.globals["wdTaiwan".lower()] = 886
        self.vb_constants.add("wdTaiwan".lower())
        #  United Kingdom
        self.globals["wdUK".lower()] = 44
        self.vb_constants.add("wdUK".lower())
        #  United States
        self.globals["wdUS".lower()] = 1
        self.vb_constants.add("wdUS".lower())
        #  Venezuela
        self.globals["wdVenezuela".lower()] = 58
        self.vb_constants.add("wdVenezuela".lower())
        
        # XlBinsType enumeration (Word)
        self.globals["xlBinsTypeAutomatic".lower()] = 0
        self.vb_constants.add("xlBinsTypeAutomatic".lower())
        self.globals["xlBinsTypeCategorical".lower()] = 1
        self.vb_constants.add("xlBinsTypeCategorical".lower())
        self.globals["xlBinsTypeManual".lower()] = 2
        self.vb_constants.add("xlBinsTypeManual".lower())
        self.globals["xlBinsTypeBinSize".lower()] = 3
        self.vb_constants.add("xlBinsTypeBinSize".lower())
        self.globals["xlBinsTypeBinCount".lower()] = 4
        self.vb_constants.add("xlBinsTypeBinCount".lower())

        # XlPieSliceIndex Enum
        self.globals["xlCenterPoint".lower()] = 5
        self.vb_constants.add("xlCenterPoint".lower())
        self.globals["xlInnerCenterPoint".lower()] = 8
        self.vb_constants.add("xlInnerCenterPoint".lower())
        self.globals["xlInnerClockwisePoint".lower()] = 7
        self.vb_constants.add("xlInnerClockwisePoint".lower())
        self.globals["xlInnerCounterClockwisePoint".lower()] = 9
        self.vb_constants.add("xlInnerCounterClockwisePoint".lower())
        self.globals["xlMidClockwiseRadiusPoint".lower()] = 4
        self.vb_constants.add("xlMidClockwiseRadiusPoint".lower())
        self.globals["xlMidCounterClockwiseRadiusPoint".lower()] = 6
        self.vb_constants.add("xlMidCounterClockwiseRadiusPoint".lower())
        self.globals["xlOuterCenterPoint".lower()] = 2
        self.vb_constants.add("xlOuterCenterPoint".lower())
        self.globals["xlOuterClockwisePoint".lower()] = 3
        self.vb_constants.add("xlOuterClockwisePoint".lower())
        self.globals["xlOuterCounterClockwisePoint".lower()] = 1
        self.vb_constants.add("xlOuterCounterClockwisePoint".lower())

        # XlUnderlineStyle Enum
        self.globals["xlUnderlineStyleDouble".lower()] = -4119
        self.vb_constants.add("xlUnderlineStyleDouble".lower())
        self.globals["xlUnderlineStyleDoubleAccounting".lower()] = 5
        self.vb_constants.add("xlUnderlineStyleDoubleAccounting".lower())
        self.globals["xlUnderlineStyleNone".lower()] = -4142
        self.vb_constants.add("xlUnderlineStyleNone".lower())
        self.globals["xlUnderlineStyleSingle".lower()] = 2
        self.vb_constants.add("xlUnderlineStyleSingle".lower())
        self.globals["xlUnderlineStyleSingleAccounting".lower()] = 4
        self.vb_constants.add("xlUnderlineStyleSingleAccounting".lower())

        # XlTimeUnit enumeration
        self.globals["xlDays".lower()] = 0
        self.vb_constants.add("xlDays".lower())
        self.globals["xlMonths".lower()] = 1
        self.vb_constants.add("xlMonths".lower())
        self.globals["xlYears".lower()] = 2
        self.vb_constants.add("xlYears".lower())

        # WdOrientation enumeration (Word)
        self.globals["wdOrientLandscape".lower()] = 1
        self.vb_constants.add("wdOrientLandscape".lower())
        self.globals["wdOrientPortrait".lower()] = 0
        self.vb_constants.add("wdOrientPortrait".lower())
        
        # Misc.
        self.globals["ActiveDocument.PageSetup.PageWidth".lower()] = 10
        self.vb_constants.add("ActiveDocument.PageSetup.PageWidth".lower())
        self.globals["ThisDocument.PageSetup.PageWidth".lower()] = 10
        self.vb_constants.add("ThisDocument.PageSetup.PageWidth".lower())
        self.globals["ActiveDocument.PageSetup.Orientation".lower()] = 1
        self.vb_constants.add("ActiveDocument.PageSetup.Orientation".lower())
        self.globals["ThisDocument.PageSetup.Orientation".lower()] = 1
        self.vb_constants.add("ThisDocument.PageSetup.Orientation".lower())
        self.globals["ActiveDocument.Scripts.Count".lower()] = 0
        self.vb_constants.add("ActiveDocument.Scripts.Count".lower())
        self.globals["ThisDocument.Scripts.Count".lower()] = 0
        self.vb_constants.add("ThisDocument.Scripts.Count".lower())
        self.globals["ActiveDocument.FullName".lower()] = "C:\\CURRENT_FILE_NAME.docm"
        self.vb_constants.add("ActiveDocument.FullName".lower())
        self.globals["ThisDocument.FullName".lower()] = "C:\\CURRENT_FILE_NAME.docm"
        self.vb_constants.add("ThisDocument.FullName".lower())
        self.globals["ActiveDocument.Name".lower()] = "CURRENT_FILE_NAME.docm"
        self.vb_constants.add("ActiveDocument.Name".lower())
        self.globals["ThisDocument.Name".lower()] = "CURRENT_FILE_NAME.docm"
        self.vb_constants.add("ThisDocument.Name".lower())
        self.globals["TotalPhysicalMemory".lower()] = 2097741824
        self.vb_constants.add("TotalPhysicalMemory".lower())
        if self.filename:
            self.globals["WSCRIPT.SCRIPTFULLNAME".lower()] = "C:\\" + self.filename
            self.vb_constants.add("WSCRIPT.SCRIPTFULLNAME".lower())
            self.globals["['WSCRIPT'].SCRIPTFULLNAME".lower()] = "C:\\" + self.filename
        self.globals["OSlanguage".lower()] = "**MATCH ANY**"
        self.vb_constants.add("OSlanguage".lower())
        self.globals["Err.Number".lower()] = "**MATCH ANY**"
        self.vb_constants.add("Err.Number".lower())
        self.globals["Selection".lower()] = "**SELECTED TEXT IN DOC**"
        self.vb_constants.add("Selection".lower())
        self.globals["msoFontAlignTop".lower()] = 1
        self.vb_constants.add("msoFontAlignTop".lower())
        self.globals["msoTextBox".lower()] = "**MATCH ANY**"
        self.vb_constants.add("msoTextBox".lower())
        self.globals["Application.MouseAvailable".lower()] = True
        self.vb_constants.add("Application.MouseAvailable".lower())
        self.globals["Application.PathSeparator".lower()] = "\\"
        self.vb_constants.add("Application.PathSeparator".lower())
        self.globals["RecentFiles.Count".lower()] = 4 + random.randint(1, 10)
        self.vb_constants.add("RecentFiles.Count".lower())
        self.globals["ActiveDocument.Revisions.Count".lower()] = 1 + random.randint(1, 3)
        self.vb_constants.add("ActiveDocument.Revisions.Count".lower())
        self.globals["ThisDocument.Revisions.Count".lower()] = 1 + random.randint(1, 3)
        self.vb_constants.add("ThisDocument.Revisions.Count".lower())
        self.globals["Revisions.Count".lower()] = 1 + random.randint(1, 3)
        self.vb_constants.add("Revisions.Count".lower())
        self.globals["ReadyState".lower()] = "**MATCH ANY**"
        self.vb_constants.add("ReadyState".lower())
        self.globals["Application.Caption".lower()] = "**MATCH ANY**"
        self.vb_constants.add("Application.Caption".lower())
        self.globals["Application.System.Version".lower()] = "**MATCH ANY**"
        self.vb_constants.add("Application.System.Version".lower())
        self.globals["BackStyle".lower()] = "**MATCH ANY**"
        self.vb_constants.add("BackStyle".lower())
        self.globals["responseText".lower()] = ""
        self.vb_constants.add("responseText".lower())
        self.globals["NumberOfLogicalProcessors".lower()] = 4
        self.vb_constants.add("NumberOfLogicalProcessors".lower())
        self.globals[".NumberOfLogicalProcessors".lower()] = 4
        self.vb_constants.add(".NumberOfLogicalProcessors".lower())
        self.globals["ActiveWorkbook.Name".lower()] = "**MATCH ANY**"
        self.vb_constants.add("ActiveWorkbook.Name".lower())
        self.globals["me.Status".lower()] = 200
        self.vb_constants.add("me.Status".lower())
        self.globals["BackColor".lower()] = "**MATCH ANY**"
        self.vb_constants.add("BackColor".lower())
        self.globals["me.BackColor".lower()] = "**MATCH ANY**"
        self.vb_constants.add("me.BackColor".lower())
        self.globals["Empty".lower()] = "NULL"
        self.vb_constants.add("Empty".lower())
        self.globals["Scripting.FileSystemObject.Drives.DriveLetter".lower()] = "B"
        self.vb_constants.add("Scripting.FileSystemObject.Drives.DriveLetter".lower())
        self.globals["Wscript.ScriptName".lower()] = "__CURRENT_SCRIPT_NAME__"
        self.vb_constants.add("Wscript.ScriptName".lower())
        
        # List of _all_ Excel constants taken from https://www.autohotkey.com/boards/viewtopic.php?t=60538&p=255925 .
        self.globals["_xlDialogChartSourceData".lower()] = 541
        self.vb_constants.add("_xlDialogChartSourceData".lower())
        self.globals["_xlDialogPhonetic".lower()] = 538
        self.vb_constants.add("_xlDialogPhonetic".lower())
        self.globals["msoLimited".lower()] = 1
        self.vb_constants.add("msoLimited".lower())
        self.globals["msoNoOverwrite".lower()] = 3
        self.vb_constants.add("msoNoOverwrite".lower())
        self.globals["msoOrganization".lower()] = 2
        self.vb_constants.add("msoOrganization".lower())
        self.globals["msoPBIAbort".lower()] = 1
        self.vb_constants.add("msoPBIAbort".lower())
        self.globals["msoPBIExport".lower()] = 0
        self.vb_constants.add("msoPBIExport".lower())
        self.globals["msoPBIIgnore".lower()] = 0
        self.vb_constants.add("msoPBIIgnore".lower())
        self.globals["msoPBIOverwrite".lower()] = 2
        self.vb_constants.add("msoPBIOverwrite".lower())
        self.globals["msoPBIUpload".lower()] = 1
        self.vb_constants.add("msoPBIUpload".lower())
        self.globals["msoPublic".lower()] = 0
        self.vb_constants.add("msoPublic".lower())
        self.globals["rgbAliceBlue".lower()] = 16775408
        self.vb_constants.add("rgbAliceBlue".lower())
        self.globals["rgbAntiqueWhite".lower()] = 14150650
        self.vb_constants.add("rgbAntiqueWhite".lower())
        self.globals["rgbAqua".lower()] = 16776960
        self.vb_constants.add("rgbAqua".lower())
        self.globals["rgbAquamarine".lower()] = 13959039
        self.vb_constants.add("rgbAquamarine".lower())
        self.globals["rgbAzure".lower()] = 16777200
        self.vb_constants.add("rgbAzure".lower())
        self.globals["rgbBeige".lower()] = 14480885
        self.vb_constants.add("rgbBeige".lower())
        self.globals["rgbBisque".lower()] = 12903679
        self.vb_constants.add("rgbBisque".lower())
        self.globals["rgbBlack".lower()] = 0
        self.vb_constants.add("rgbBlack".lower())
        self.globals["rgbBlanchedAlmond".lower()] = 13495295
        self.vb_constants.add("rgbBlanchedAlmond".lower())
        self.globals["rgbBlue".lower()] = 16711680
        self.vb_constants.add("rgbBlue".lower())
        self.globals["rgbBlueViolet".lower()] = 14822282
        self.vb_constants.add("rgbBlueViolet".lower())
        self.globals["rgbBrown".lower()] = 2763429
        self.vb_constants.add("rgbBrown".lower())
        self.globals["rgbBurlyWood".lower()] = 8894686
        self.vb_constants.add("rgbBurlyWood".lower())
        self.globals["rgbCadetBlue".lower()] = 10526303
        self.vb_constants.add("rgbCadetBlue".lower())
        self.globals["rgbChartreuse".lower()] = 65407
        self.vb_constants.add("rgbChartreuse".lower())
        self.globals["rgbCoral".lower()] = 5275647
        self.vb_constants.add("rgbCoral".lower())
        self.globals["rgbCornflowerBlue".lower()] = 15570276
        self.vb_constants.add("rgbCornflowerBlue".lower())
        self.globals["rgbCornsilk".lower()] = 14481663
        self.vb_constants.add("rgbCornsilk".lower())
        self.globals["rgbCrimson".lower()] = 3937500
        self.vb_constants.add("rgbCrimson".lower())
        self.globals["rgbDarkBlue".lower()] = 9109504
        self.vb_constants.add("rgbDarkBlue".lower())
        self.globals["rgbDarkCyan".lower()] = 9145088
        self.vb_constants.add("rgbDarkCyan".lower())
        self.globals["rgbDarkGoldenrod".lower()] = 755384
        self.vb_constants.add("rgbDarkGoldenrod".lower())
        self.globals["rgbDarkGray".lower()] = 11119017
        self.vb_constants.add("rgbDarkGray".lower())
        self.globals["rgbDarkGreen".lower()] = 25600
        self.vb_constants.add("rgbDarkGreen".lower())
        self.globals["rgbDarkGrey".lower()] = 11119017
        self.vb_constants.add("rgbDarkGrey".lower())
        self.globals["rgbDarkKhaki".lower()] = 7059389
        self.vb_constants.add("rgbDarkKhaki".lower())
        self.globals["rgbDarkMagenta".lower()] = 9109643
        self.vb_constants.add("rgbDarkMagenta".lower())
        self.globals["rgbDarkOliveGreen".lower()] = 3107669
        self.vb_constants.add("rgbDarkOliveGreen".lower())
        self.globals["rgbDarkOrange".lower()] = 36095
        self.vb_constants.add("rgbDarkOrange".lower())
        self.globals["rgbDarkOrchid".lower()] = 13382297
        self.vb_constants.add("rgbDarkOrchid".lower())
        self.globals["rgbDarkRed".lower()] = 139
        self.vb_constants.add("rgbDarkRed".lower())
        self.globals["rgbDarkSalmon".lower()] = 8034025
        self.vb_constants.add("rgbDarkSalmon".lower())
        self.globals["rgbDarkSeaGreen".lower()] = 9419919
        self.vb_constants.add("rgbDarkSeaGreen".lower())
        self.globals["rgbDarkSlateBlue".lower()] = 9125192
        self.vb_constants.add("rgbDarkSlateBlue".lower())
        self.globals["rgbDarkSlateGray".lower()] = 5197615
        self.vb_constants.add("rgbDarkSlateGray".lower())
        self.globals["rgbDarkSlateGrey".lower()] = 5197615
        self.vb_constants.add("rgbDarkSlateGrey".lower())
        self.globals["rgbDarkTurquoise".lower()] = 13749760
        self.vb_constants.add("rgbDarkTurquoise".lower())
        self.globals["rgbDarkViolet".lower()] = 13828244
        self.vb_constants.add("rgbDarkViolet".lower())
        self.globals["rgbDeepPink".lower()] = 9639167
        self.vb_constants.add("rgbDeepPink".lower())
        self.globals["rgbDeepSkyBlue".lower()] = 16760576
        self.vb_constants.add("rgbDeepSkyBlue".lower())
        self.globals["rgbDimGray".lower()] = 6908265
        self.vb_constants.add("rgbDimGray".lower())
        self.globals["rgbDimGrey".lower()] = 6908265
        self.vb_constants.add("rgbDimGrey".lower())
        self.globals["rgbDodgerBlue".lower()] = 16748574
        self.vb_constants.add("rgbDodgerBlue".lower())
        self.globals["rgbFireBrick".lower()] = 2237106
        self.vb_constants.add("rgbFireBrick".lower())
        self.globals["rgbFloralWhite".lower()] = 15792895
        self.vb_constants.add("rgbFloralWhite".lower())
        self.globals["rgbForestGreen".lower()] = 2263842
        self.vb_constants.add("rgbForestGreen".lower())
        self.globals["rgbFuchsia".lower()] = 16711935
        self.vb_constants.add("rgbFuchsia".lower())
        self.globals["rgbGainsboro".lower()] = 14474460
        self.vb_constants.add("rgbGainsboro".lower())
        self.globals["rgbGhostWhite".lower()] = 16775416
        self.vb_constants.add("rgbGhostWhite".lower())
        self.globals["rgbGold".lower()] = 55295
        self.vb_constants.add("rgbGold".lower())
        self.globals["rgbGoldenrod".lower()] = 2139610
        self.vb_constants.add("rgbGoldenrod".lower())
        self.globals["rgbGray".lower()] = 8421504
        self.vb_constants.add("rgbGray".lower())
        self.globals["rgbGreen".lower()] = 32768
        self.vb_constants.add("rgbGreen".lower())
        self.globals["rgbGreenYellow".lower()] = 3145645
        self.vb_constants.add("rgbGreenYellow".lower())
        self.globals["rgbGrey".lower()] = 8421504
        self.vb_constants.add("rgbGrey".lower())
        self.globals["rgbHoneydew".lower()] = 15794160
        self.vb_constants.add("rgbHoneydew".lower())
        self.globals["rgbHotPink".lower()] = 11823615
        self.vb_constants.add("rgbHotPink".lower())
        self.globals["rgbIndianRed".lower()] = 6053069
        self.vb_constants.add("rgbIndianRed".lower())
        self.globals["rgbIndigo".lower()] = 8519755
        self.vb_constants.add("rgbIndigo".lower())
        self.globals["rgbIvory".lower()] = 15794175
        self.vb_constants.add("rgbIvory".lower())
        self.globals["rgbKhaki".lower()] = 9234160
        self.vb_constants.add("rgbKhaki".lower())
        self.globals["rgbLavender".lower()] = 16443110
        self.vb_constants.add("rgbLavender".lower())
        self.globals["rgbLavenderBlush".lower()] = 16118015
        self.vb_constants.add("rgbLavenderBlush".lower())
        self.globals["rgbLawnGreen".lower()] = 64636
        self.vb_constants.add("rgbLawnGreen".lower())
        self.globals["rgbLemonChiffon".lower()] = 13499135
        self.vb_constants.add("rgbLemonChiffon".lower())
        self.globals["rgbLightBlue".lower()] = 15128749
        self.vb_constants.add("rgbLightBlue".lower())
        self.globals["rgbLightCoral".lower()] = 8421616
        self.vb_constants.add("rgbLightCoral".lower())
        self.globals["rgbLightCyan".lower()] = 9145088
        self.vb_constants.add("rgbLightCyan".lower())
        self.globals["rgbLightGoldenrodYellow".lower()] = 13826810
        self.vb_constants.add("rgbLightGoldenrodYellow".lower())
        self.globals["rgbLightGray".lower()] = 13882323
        self.vb_constants.add("rgbLightGray".lower())
        self.globals["rgbLightGreen".lower()] = 9498256
        self.vb_constants.add("rgbLightGreen".lower())
        self.globals["rgbLightGrey".lower()] = 13882323
        self.vb_constants.add("rgbLightGrey".lower())
        self.globals["rgbLightPink".lower()] = 12695295
        self.vb_constants.add("rgbLightPink".lower())
        self.globals["rgbLightSalmon".lower()] = 8036607
        self.vb_constants.add("rgbLightSalmon".lower())
        self.globals["rgbLightSeaGreen".lower()] = 11186720
        self.vb_constants.add("rgbLightSeaGreen".lower())
        self.globals["rgbLightSkyBlue".lower()] = 16436871
        self.vb_constants.add("rgbLightSkyBlue".lower())
        self.globals["rgbLightSlateGray".lower()] = 10061943
        self.vb_constants.add("rgbLightSlateGray".lower())
        self.globals["rgbLightSlateGrey".lower()] = 10061943
        self.vb_constants.add("rgbLightSlateGrey".lower())
        self.globals["rgbLightSteelBlue".lower()] = 14599344
        self.vb_constants.add("rgbLightSteelBlue".lower())
        self.globals["rgbLightYellow".lower()] = 14745599
        self.vb_constants.add("rgbLightYellow".lower())
        self.globals["rgbLime".lower()] = 65280
        self.vb_constants.add("rgbLime".lower())
        self.globals["rgbLimeGreen".lower()] = 3329330
        self.vb_constants.add("rgbLimeGreen".lower())
        self.globals["rgbLinen".lower()] = 15134970
        self.vb_constants.add("rgbLinen".lower())
        self.globals["rgbMaroon".lower()] = 128
        self.vb_constants.add("rgbMaroon".lower())
        self.globals["rgbMediumAquamarine".lower()] = 11206502
        self.vb_constants.add("rgbMediumAquamarine".lower())
        self.globals["rgbMediumBlue".lower()] = 13434880
        self.vb_constants.add("rgbMediumBlue".lower())
        self.globals["rgbMediumOrchid".lower()] = 13850042
        self.vb_constants.add("rgbMediumOrchid".lower())
        self.globals["rgbMediumPurple".lower()] = 14381203
        self.vb_constants.add("rgbMediumPurple".lower())
        self.globals["rgbMediumSeaGreen".lower()] = 7451452
        self.vb_constants.add("rgbMediumSeaGreen".lower())
        self.globals["rgbMediumSlateBlue".lower()] = 15624315
        self.vb_constants.add("rgbMediumSlateBlue".lower())
        self.globals["rgbMediumSpringGreen".lower()] = 10156544
        self.vb_constants.add("rgbMediumSpringGreen".lower())
        self.globals["rgbMediumTurquoise".lower()] = 13422920
        self.vb_constants.add("rgbMediumTurquoise".lower())
        self.globals["rgbMediumVioletRed".lower()] = 8721863
        self.vb_constants.add("rgbMediumVioletRed".lower())
        self.globals["rgbMidnightBlue".lower()] = 7346457
        self.vb_constants.add("rgbMidnightBlue".lower())
        self.globals["rgbMintCream".lower()] = 16449525
        self.vb_constants.add("rgbMintCream".lower())
        self.globals["rgbMistyRose".lower()] = 14804223
        self.vb_constants.add("rgbMistyRose".lower())
        self.globals["rgbMoccasin".lower()] = 11920639
        self.vb_constants.add("rgbMoccasin".lower())
        self.globals["rgbNavajoWhite".lower()] = 11394815
        self.vb_constants.add("rgbNavajoWhite".lower())
        self.globals["rgbNavy".lower()] = 8388608
        self.vb_constants.add("rgbNavy".lower())
        self.globals["rgbNavyBlue".lower()] = 8388608
        self.vb_constants.add("rgbNavyBlue".lower())
        self.globals["rgbOldLace".lower()] = 15136253
        self.vb_constants.add("rgbOldLace".lower())
        self.globals["rgbOlive".lower()] = 32896
        self.vb_constants.add("rgbOlive".lower())
        self.globals["rgbOliveDrab".lower()] = 2330219
        self.vb_constants.add("rgbOliveDrab".lower())
        self.globals["rgbOrange".lower()] = 42495
        self.vb_constants.add("rgbOrange".lower())
        self.globals["rgbOrangeRed".lower()] = 17919
        self.vb_constants.add("rgbOrangeRed".lower())
        self.globals["rgbOrchid".lower()] = 14053594
        self.vb_constants.add("rgbOrchid".lower())
        self.globals["rgbPaleGoldenrod".lower()] = 7071982
        self.vb_constants.add("rgbPaleGoldenrod".lower())
        self.globals["rgbPaleGreen".lower()] = 10025880
        self.vb_constants.add("rgbPaleGreen".lower())
        self.globals["rgbPaleTurquoise".lower()] = 15658671
        self.vb_constants.add("rgbPaleTurquoise".lower())
        self.globals["rgbPaleVioletRed".lower()] = 9662683
        self.vb_constants.add("rgbPaleVioletRed".lower())
        self.globals["rgbPapayaWhip".lower()] = 14020607
        self.vb_constants.add("rgbPapayaWhip".lower())
        self.globals["rgbPeachPuff".lower()] = 12180223
        self.vb_constants.add("rgbPeachPuff".lower())
        self.globals["rgbPeru".lower()] = 4163021
        self.vb_constants.add("rgbPeru".lower())
        self.globals["rgbPink".lower()] = 13353215
        self.vb_constants.add("rgbPink".lower())
        self.globals["rgbPlum".lower()] = 14524637
        self.vb_constants.add("rgbPlum".lower())
        self.globals["rgbPowderBlue".lower()] = 15130800
        self.vb_constants.add("rgbPowderBlue".lower())
        self.globals["rgbPurple".lower()] = 8388736
        self.vb_constants.add("rgbPurple".lower())
        self.globals["rgbRed".lower()] = 255
        self.vb_constants.add("rgbRed".lower())
        self.globals["rgbRosyBrown".lower()] = 9408444
        self.vb_constants.add("rgbRosyBrown".lower())
        self.globals["rgbRoyalBlue".lower()] = 14772545
        self.vb_constants.add("rgbRoyalBlue".lower())
        self.globals["rgbSalmon".lower()] = 7504122
        self.vb_constants.add("rgbSalmon".lower())
        self.globals["rgbSandyBrown".lower()] = 6333684
        self.vb_constants.add("rgbSandyBrown".lower())
        self.globals["rgbSeaGreen".lower()] = 5737262
        self.vb_constants.add("rgbSeaGreen".lower())
        self.globals["rgbSeashell".lower()] = 15660543
        self.vb_constants.add("rgbSeashell".lower())
        self.globals["rgbSienna".lower()] = 2970272
        self.vb_constants.add("rgbSienna".lower())
        self.globals["rgbSilver".lower()] = 12632256
        self.vb_constants.add("rgbSilver".lower())
        self.globals["rgbSkyBlue".lower()] = 15453831
        self.vb_constants.add("rgbSkyBlue".lower())
        self.globals["rgbSlateBlue".lower()] = 13458026
        self.vb_constants.add("rgbSlateBlue".lower())
        self.globals["rgbSlateGray".lower()] = 9470064
        self.vb_constants.add("rgbSlateGray".lower())
        self.globals["rgbSlateGrey".lower()] = 9470064
        self.vb_constants.add("rgbSlateGrey".lower())
        self.globals["rgbSnow".lower()] = 16448255
        self.vb_constants.add("rgbSnow".lower())
        self.globals["rgbSpringGreen".lower()] = 8388352
        self.vb_constants.add("rgbSpringGreen".lower())
        self.globals["rgbSteelBlue".lower()] = 11829830
        self.vb_constants.add("rgbSteelBlue".lower())
        self.globals["rgbTan".lower()] = 9221330
        self.vb_constants.add("rgbTan".lower())
        self.globals["rgbTeal".lower()] = 8421376
        self.vb_constants.add("rgbTeal".lower())
        self.globals["rgbThistle".lower()] = 14204888
        self.vb_constants.add("rgbThistle".lower())
        self.globals["rgbTomato".lower()] = 4678655
        self.vb_constants.add("rgbTomato".lower())
        self.globals["rgbTurquoise".lower()] = 13688896
        self.vb_constants.add("rgbTurquoise".lower())
        self.globals["rgbViolet".lower()] = 15631086
        self.vb_constants.add("rgbViolet".lower())
        self.globals["rgbWheat".lower()] = 11788021
        self.vb_constants.add("rgbWheat".lower())
        self.globals["rgbWhite".lower()] = 16777215
        self.vb_constants.add("rgbWhite".lower())
        self.globals["rgbWhiteSmoke".lower()] = 16119285
        self.vb_constants.add("rgbWhiteSmoke".lower())
        self.globals["rgbYellow".lower()] = 65535
        self.vb_constants.add("rgbYellow".lower())
        self.globals["rgbYellowGreen".lower()] = 3329434
        self.vb_constants.add("rgbYellowGreen".lower())
        self.globals["xl24HourClock".lower()] = 33
        self.vb_constants.add("xl24HourClock".lower())
        self.globals["xl3Arrows".lower()] = 1
        self.vb_constants.add("xl3Arrows".lower())
        self.globals["xl3ArrowsGray".lower()] = 2
        self.vb_constants.add("xl3ArrowsGray".lower())
        self.globals["xl3DArea".lower()] = 4098
        self.vb_constants.add("xl3DArea".lower())
        self.globals["xl3DAreaStacked".lower()] = 78
        self.vb_constants.add("xl3DAreaStacked".lower())
        self.globals["xl3DAreaStacked100".lower()] = 79
        self.vb_constants.add("xl3DAreaStacked100".lower())
        self.globals["xl3DBar".lower()] = 4099
        self.vb_constants.add("xl3DBar".lower())
        self.globals["xl3DBarClustered".lower()] = 60
        self.vb_constants.add("xl3DBarClustered".lower())
        self.globals["xl3DBarStacked".lower()] = 61
        self.vb_constants.add("xl3DBarStacked".lower())
        self.globals["xl3DBarStacked100".lower()] = 62
        self.vb_constants.add("xl3DBarStacked100".lower())
        self.globals["xl3DColumn".lower()] = 4100
        self.vb_constants.add("xl3DColumn".lower())
        self.globals["xl3DColumnClustered".lower()] = 54
        self.vb_constants.add("xl3DColumnClustered".lower())
        self.globals["xl3DColumnStacked".lower()] = 55
        self.vb_constants.add("xl3DColumnStacked".lower())
        self.globals["xl3DColumnStacked100".lower()] = 56
        self.vb_constants.add("xl3DColumnStacked100".lower())
        self.globals["xl3DEffects1".lower()] = 13
        self.vb_constants.add("xl3DEffects1".lower())
        self.globals["xl3DEffects2".lower()] = 14
        self.vb_constants.add("xl3DEffects2".lower())
        self.globals["xl3DLine".lower()] = 4101
        self.vb_constants.add("xl3DLine".lower())
        self.globals["xl3DPie".lower()] = 4102
        self.vb_constants.add("xl3DPie".lower())
        self.globals["xl3DPieExploded".lower()] = 70
        self.vb_constants.add("xl3DPieExploded".lower())
        self.globals["xl3DSurface".lower()] = 4103
        self.vb_constants.add("xl3DSurface".lower())
        self.globals["xl3Flags".lower()] = 3
        self.vb_constants.add("xl3Flags".lower())
        self.globals["xl3Signs".lower()] = 6
        self.vb_constants.add("xl3Signs".lower())
        self.globals["xl3Stars".lower()] = 18
        self.vb_constants.add("xl3Stars".lower())
        self.globals["xl3Symbols".lower()] = 7
        self.vb_constants.add("xl3Symbols".lower())
        self.globals["xl3Symbols2".lower()] = 8
        self.vb_constants.add("xl3Symbols2".lower())
        self.globals["xl3TrafficLights1".lower()] = 4
        self.vb_constants.add("xl3TrafficLights1".lower())
        self.globals["xl3TrafficLights2".lower()] = 5
        self.vb_constants.add("xl3TrafficLights2".lower())
        self.globals["xl3Triangles".lower()] = 19
        self.vb_constants.add("xl3Triangles".lower())
        self.globals["xl4Arrows".lower()] = 9
        self.vb_constants.add("xl4Arrows".lower())
        self.globals["xl4ArrowsGray".lower()] = 10
        self.vb_constants.add("xl4ArrowsGray".lower())
        self.globals["xl4CRV".lower()] = 12
        self.vb_constants.add("xl4CRV".lower())
        self.globals["xl4DigitYears".lower()] = 43
        self.vb_constants.add("xl4DigitYears".lower())
        self.globals["xl4RedToBlack".lower()] = 11
        self.vb_constants.add("xl4RedToBlack".lower())
        self.globals["xl4TrafficLights".lower()] = 13
        self.vb_constants.add("xl4TrafficLights".lower())
        self.globals["xl5Arrows".lower()] = 14
        self.vb_constants.add("xl5Arrows".lower())
        self.globals["xl5ArrowsGray".lower()] = 15
        self.vb_constants.add("xl5ArrowsGray".lower())
        self.globals["xl5Boxes".lower()] = 20
        self.vb_constants.add("xl5Boxes".lower())
        self.globals["xl5CRV".lower()] = 16
        self.vb_constants.add("xl5CRV".lower())
        self.globals["xl5Quarters".lower()] = 17
        self.vb_constants.add("xl5Quarters".lower())
        self.globals["xlA1".lower()] = 1
        self.vb_constants.add("xlA1".lower())
        self.globals["xlAbove".lower()] = 0
        self.vb_constants.add("xlAbove".lower())
        self.globals["xlAboveAverage".lower()] = 0
        self.vb_constants.add("xlAboveAverage".lower())
        self.globals["xlAboveAverageCondition".lower()] = 12
        self.vb_constants.add("xlAboveAverageCondition".lower())
        self.globals["xlAboveStdDev".lower()] = 4
        self.vb_constants.add("xlAboveStdDev".lower())
        self.globals["xlAbsolute".lower()] = 1
        self.vb_constants.add("xlAbsolute".lower())
        self.globals["xlAbsRowRelColumn".lower()] = 2
        self.vb_constants.add("xlAbsRowRelColumn".lower())
        self.globals["xlAccounting1".lower()] = 4
        self.vb_constants.add("xlAccounting1".lower())
        self.globals["xlAccounting2".lower()] = 5
        self.vb_constants.add("xlAccounting2".lower())
        self.globals["xlAccounting3".lower()] = 6
        self.vb_constants.add("xlAccounting3".lower())
        self.globals["xlAccounting4".lower()] = 17
        self.vb_constants.add("xlAccounting4".lower())
        self.globals["xlActionTypeDrillthrough".lower()] = 256
        self.vb_constants.add("xlActionTypeDrillthrough".lower())
        self.globals["xlActionTypeReport".lower()] = 128
        self.vb_constants.add("xlActionTypeReport".lower())
        self.globals["xlActionTypeRowset".lower()] = 16
        self.vb_constants.add("xlActionTypeRowset".lower())
        self.globals["xlActionTypeUrl".lower()] = 1
        self.vb_constants.add("xlActionTypeUrl".lower())
        self.globals["xlAdd".lower()] = 2
        self.vb_constants.add("xlAdd".lower())
        self.globals["xlAddIn".lower()] = 18
        self.vb_constants.add("xlAddIn".lower())
        self.globals["xlAddIn8".lower()] = 18
        self.vb_constants.add("xlAddIn8".lower())
        self.globals["xlADORecordset".lower()] = 7
        self.vb_constants.add("xlADORecordset".lower())
        self.globals["xlAfter".lower()] = 33
        self.vb_constants.add("xlAfter".lower())
        self.globals["xlAfterOrEqualTo".lower()] = 34
        self.vb_constants.add("xlAfterOrEqualTo".lower())
        self.globals["xlAll".lower()] = 4104
        self.vb_constants.add("xlAll".lower())
        self.globals["xlAllAtOnce".lower()] = 2
        self.vb_constants.add("xlAllAtOnce".lower())
        self.globals["xlAllChanges".lower()] = 2
        self.vb_constants.add("xlAllChanges".lower())
        self.globals["xlAllDatesInPeriodApril".lower()] = 60
        self.vb_constants.add("xlAllDatesInPeriodApril".lower())
        self.globals["xlAllDatesInPeriodAugust".lower()] = 64
        self.vb_constants.add("xlAllDatesInPeriodAugust".lower())
        self.globals["xlAllDatesInPeriodDecember".lower()] = 68
        self.vb_constants.add("xlAllDatesInPeriodDecember".lower())
        self.globals["xlAllDatesInPeriodFebruary".lower()] = 58
        self.vb_constants.add("xlAllDatesInPeriodFebruary".lower())
        self.globals["xlAllDatesInPeriodJanuary".lower()] = 57
        self.vb_constants.add("xlAllDatesInPeriodJanuary".lower())
        self.globals["xlAllDatesInPeriodJuly".lower()] = 63
        self.vb_constants.add("xlAllDatesInPeriodJuly".lower())
        self.globals["xlAllDatesInPeriodJune".lower()] = 62
        self.vb_constants.add("xlAllDatesInPeriodJune".lower())
        self.globals["xlAllDatesInPeriodMarch".lower()] = 59
        self.vb_constants.add("xlAllDatesInPeriodMarch".lower())
        self.globals["xlAllDatesInPeriodMay".lower()] = 61
        self.vb_constants.add("xlAllDatesInPeriodMay".lower())
        self.globals["xlAllDatesInPeriodNovember".lower()] = 67
        self.vb_constants.add("xlAllDatesInPeriodNovember".lower())
        self.globals["xlAllDatesInPeriodOctober".lower()] = 66
        self.vb_constants.add("xlAllDatesInPeriodOctober".lower())
        self.globals["xlAllDatesInPeriodQuarter1".lower()] = 53
        self.vb_constants.add("xlAllDatesInPeriodQuarter1".lower())
        self.globals["xlAllDatesInPeriodQuarter2".lower()] = 54
        self.vb_constants.add("xlAllDatesInPeriodQuarter2".lower())
        self.globals["xlAllDatesInPeriodQuarter3".lower()] = 55
        self.vb_constants.add("xlAllDatesInPeriodQuarter3".lower())
        self.globals["xlAllDatesInPeriodQuarter4".lower()] = 56
        self.vb_constants.add("xlAllDatesInPeriodQuarter4".lower())
        self.globals["xlAllDatesInPeriodSeptember".lower()] = 65
        self.vb_constants.add("xlAllDatesInPeriodSeptember".lower())
        self.globals["xlAllExceptBorders".lower()] = 7
        self.vb_constants.add("xlAllExceptBorders".lower())
        self.globals["xlAllFaces".lower()] = 7
        self.vb_constants.add("xlAllFaces".lower())
        self.globals["xlAllocateIncrement".lower()] = 2
        self.vb_constants.add("xlAllocateIncrement".lower())
        self.globals["xlAllocateValue".lower()] = 1
        self.vb_constants.add("xlAllocateValue".lower())
        self.globals["xlAllTables".lower()] = 2
        self.vb_constants.add("xlAllTables".lower())
        self.globals["xlAllValues".lower()] = 0
        self.vb_constants.add("xlAllValues".lower())
        self.globals["xlAlternateArraySeparator".lower()] = 16
        self.vb_constants.add("xlAlternateArraySeparator".lower())
        self.globals["xlAlways".lower()] = 1
        self.vb_constants.add("xlAlways".lower())
        self.globals["xlAnd".lower()] = 1
        self.vb_constants.add("xlAnd".lower())
        self.globals["xlAnyGallery".lower()] = 23
        self.vb_constants.add("xlAnyGallery".lower())
        self.globals["xlAnyKey".lower()] = 2
        self.vb_constants.add("xlAnyKey".lower())
        self.globals["xlArabicBothStrict".lower()] = 3
        self.vb_constants.add("xlArabicBothStrict".lower())
        self.globals["xlArabicNone".lower()] = 0
        self.vb_constants.add("xlArabicNone".lower())
        self.globals["xlArabicStrictAlefHamza".lower()] = 1
        self.vb_constants.add("xlArabicStrictAlefHamza".lower())
        self.globals["xlArabicStrictFinalYaa".lower()] = 2
        self.vb_constants.add("xlArabicStrictFinalYaa".lower())
        self.globals["xlArea".lower()] = 1
        self.vb_constants.add("xlArea".lower())
        self.globals["xlAreaStacked".lower()] = 76
        self.vb_constants.add("xlAreaStacked".lower())
        self.globals["xlAreaStacked100".lower()] = 77
        self.vb_constants.add("xlAreaStacked100".lower())
        self.globals["xlArrangeStyleCascade".lower()] = 7
        self.vb_constants.add("xlArrangeStyleCascade".lower())
        self.globals["xlArrangeStyleHorizontal".lower()] = 4128
        self.vb_constants.add("xlArrangeStyleHorizontal".lower())
        self.globals["xlArrangeStyleTiled".lower()] = 1
        self.vb_constants.add("xlArrangeStyleTiled".lower())
        self.globals["xlArrangeStyleVertical".lower()] = 4166
        self.vb_constants.add("xlArrangeStyleVertical".lower())
        self.globals["xlArrowHeadLengthLong".lower()] = 3
        self.vb_constants.add("xlArrowHeadLengthLong".lower())
        self.globals["xlArrowHeadLengthMedium".lower()] = 4138
        self.vb_constants.add("xlArrowHeadLengthMedium".lower())
        self.globals["xlArrowHeadLengthShort".lower()] = 1
        self.vb_constants.add("xlArrowHeadLengthShort".lower())
        self.globals["xlArrowHeadStyleClosed".lower()] = 3
        self.vb_constants.add("xlArrowHeadStyleClosed".lower())
        self.globals["xlArrowHeadStyleDoubleClosed".lower()] = 5
        self.vb_constants.add("xlArrowHeadStyleDoubleClosed".lower())
        self.globals["xlArrowHeadStyleDoubleOpen".lower()] = 4
        self.vb_constants.add("xlArrowHeadStyleDoubleOpen".lower())
        self.globals["xlArrowHeadStyleNone".lower()] = 4142
        self.vb_constants.add("xlArrowHeadStyleNone".lower())
        self.globals["xlArrowHeadStyleOpen".lower()] = 2
        self.vb_constants.add("xlArrowHeadStyleOpen".lower())
        self.globals["xlArrowHeadWidthMedium".lower()] = 4138
        self.vb_constants.add("xlArrowHeadWidthMedium".lower())
        self.globals["xlArrowHeadWidthNarrow".lower()] = 1
        self.vb_constants.add("xlArrowHeadWidthNarrow".lower())
        self.globals["xlArrowHeadWidthWide".lower()] = 3
        self.vb_constants.add("xlArrowHeadWidthWide".lower())
        self.globals["xlAscending".lower()] = 1
        self.vb_constants.add("xlAscending".lower())
        self.globals["xlAsRequired".lower()] = 0
        self.vb_constants.add("xlAsRequired".lower())
        self.globals["xlAtBottom".lower()] = 2
        self.vb_constants.add("xlAtBottom".lower())
        self.globals["xlAtTop".lower()] = 1
        self.vb_constants.add("xlAtTop".lower())
        self.globals["xlAutoActivate".lower()] = 3
        self.vb_constants.add("xlAutoActivate".lower())
        self.globals["xlAutoClose".lower()] = 2
        self.vb_constants.add("xlAutoClose".lower())
        self.globals["xlAutoDeactivate".lower()] = 4
        self.vb_constants.add("xlAutoDeactivate".lower())
        self.globals["xlAutoFill".lower()] = 4
        self.vb_constants.add("xlAutoFill".lower())
        self.globals["xlAutomatic".lower()] = 4105
        self.vb_constants.add("xlAutomatic".lower())
        self.globals["xlAutomaticAllocation".lower()] = 2
        self.vb_constants.add("xlAutomaticAllocation".lower())
        self.globals["xlAutomaticScale".lower()] = 4105
        self.vb_constants.add("xlAutomaticScale".lower())
        self.globals["xlAutomaticUpdate".lower()] = 4
        self.vb_constants.add("xlAutomaticUpdate".lower())
        self.globals["xlAutoOpen".lower()] = 1
        self.vb_constants.add("xlAutoOpen".lower())
        self.globals["xlAverage".lower()] = 4106
        self.vb_constants.add("xlAverage".lower())
        self.globals["xlAxis".lower()] = 21
        self.vb_constants.add("xlAxis".lower())
        self.globals["xlAxisCrossesAutomatic".lower()] = 4105
        self.vb_constants.add("xlAxisCrossesAutomatic".lower())
        self.globals["xlAxisCrossesCustom".lower()] = 4114
        self.vb_constants.add("xlAxisCrossesCustom".lower())
        self.globals["xlAxisCrossesMaximum".lower()] = 2
        self.vb_constants.add("xlAxisCrossesMaximum".lower())
        self.globals["xlAxisCrossesMinimum".lower()] = 4
        self.vb_constants.add("xlAxisCrossesMinimum".lower())
        self.globals["xlAxisTitle".lower()] = 17
        self.vb_constants.add("xlAxisTitle".lower())
        self.globals["xlBackgroundAutomatic".lower()] = 4105
        self.vb_constants.add("xlBackgroundAutomatic".lower())
        self.globals["xlBackgroundOpaque".lower()] = 3
        self.vb_constants.add("xlBackgroundOpaque".lower())
        self.globals["xlBackgroundTransparent".lower()] = 2
        self.vb_constants.add("xlBackgroundTransparent".lower())
        self.globals["xlBar".lower()] = 2
        self.vb_constants.add("xlBar".lower())
        self.globals["xlBarClustered".lower()] = 57
        self.vb_constants.add("xlBarClustered".lower())
        self.globals["xlBarOfPie".lower()] = 71
        self.vb_constants.add("xlBarOfPie".lower())
        self.globals["xlBarStacked".lower()] = 58
        self.vb_constants.add("xlBarStacked".lower())
        self.globals["xlBarStacked100".lower()] = 59
        self.vb_constants.add("xlBarStacked100".lower())
        self.globals["xlBefore".lower()] = 31
        self.vb_constants.add("xlBefore".lower())
        self.globals["xlBeforeOrEqualTo".lower()] = 32
        self.vb_constants.add("xlBeforeOrEqualTo".lower())
        self.globals["xlBeginsWith".lower()] = 2
        self.vb_constants.add("xlBeginsWith".lower())
        self.globals["xlBelow".lower()] = 1
        self.vb_constants.add("xlBelow".lower())
        self.globals["xlBelowAverage".lower()] = 1
        self.vb_constants.add("xlBelowAverage".lower())
        self.globals["xlBelowStdDev".lower()] = 5
        self.vb_constants.add("xlBelowStdDev".lower())
        self.globals["xlBetween".lower()] = 1
        self.vb_constants.add("xlBetween".lower())
        self.globals["xlBidi".lower()] = 5000
        self.vb_constants.add("xlBidi".lower())
        self.globals["xlBidiCalendar".lower()] = 3
        self.vb_constants.add("xlBidiCalendar".lower())
        self.globals["xlBIFF".lower()] = 2
        self.vb_constants.add("xlBIFF".lower())
        self.globals["xlBinsTypeAutomatic".lower()] = 0
        self.vb_constants.add("xlBinsTypeAutomatic".lower())
        self.globals["xlBinsTypeBinCount".lower()] = 4
        self.vb_constants.add("xlBinsTypeBinCount".lower())
        self.globals["xlBinsTypeBinSize".lower()] = 3
        self.vb_constants.add("xlBinsTypeBinSize".lower())
        self.globals["xlBinsTypeCategorical".lower()] = 1
        self.vb_constants.add("xlBinsTypeCategorical".lower())
        self.globals["xlBinsTypeManual".lower()] = 2
        self.vb_constants.add("xlBinsTypeManual".lower())
        self.globals["xlBitmap".lower()] = 2
        self.vb_constants.add("xlBitmap".lower())
        self.globals["xlBlankRow".lower()] = 19
        self.vb_constants.add("xlBlankRow".lower())
        self.globals["xlBlanks".lower()] = 4
        self.vb_constants.add("xlBlanks".lower())
        self.globals["xlBlanksCondition".lower()] = 10
        self.vb_constants.add("xlBlanksCondition".lower())
        self.globals["xlBMP".lower()] = 1
        self.vb_constants.add("xlBMP".lower())
        self.globals["xlBoth".lower()] = 1
        self.vb_constants.add("xlBoth".lower())
        self.globals["xlBottom".lower()] = 4107
        self.vb_constants.add("xlBottom".lower())
        self.globals["xlBottom10Items".lower()] = 4
        self.vb_constants.add("xlBottom10Items".lower())
        self.globals["xlBottom10Percent".lower()] = 6
        self.vb_constants.add("xlBottom10Percent".lower())
        self.globals["xlBottomCount".lower()] = 2
        self.vb_constants.add("xlBottomCount".lower())
        self.globals["xlBottomPercent".lower()] = 4
        self.vb_constants.add("xlBottomPercent".lower())
        self.globals["xlBottomSum".lower()] = 6
        self.vb_constants.add("xlBottomSum".lower())
        self.globals["xlBox".lower()] = 0
        self.vb_constants.add("xlBox".lower())
        self.globals["xlBoxwhisker".lower()] = 121
        self.vb_constants.add("xlBoxwhisker".lower())
        self.globals["xlBubble".lower()] = 15
        self.vb_constants.add("xlBubble".lower())
        self.globals["xlBubble3DEffect".lower()] = 87
        self.vb_constants.add("xlBubble3DEffect".lower())
        self.globals["xlBuiltIn".lower()] = 21
        self.vb_constants.add("xlBuiltIn".lower())
        self.globals["xlButton".lower()] = 15
        self.vb_constants.add("xlButton".lower())
        self.globals["xlButtonControl".lower()] = 0
        self.vb_constants.add("xlButtonControl".lower())
        self.globals["xlButtonOnly".lower()] = 2
        self.vb_constants.add("xlButtonOnly".lower())
        self.globals["xlByColumns".lower()] = 2
        self.vb_constants.add("xlByColumns".lower())
        self.globals["xlByRows".lower()] = 1
        self.vb_constants.add("xlByRows".lower())
        self.globals["xlCalculatedMeasure".lower()] = 2
        self.vb_constants.add("xlCalculatedMeasure".lower())
        self.globals["xlCalculatedMember".lower()] = 0
        self.vb_constants.add("xlCalculatedMember".lower())
        self.globals["xlCalculatedSet".lower()] = 1
        self.vb_constants.add("xlCalculatedSet".lower())
        self.globals["xlCalculating".lower()] = 1
        self.vb_constants.add("xlCalculating".lower())
        self.globals["xlCalculationAutomatic".lower()] = 4105
        self.vb_constants.add("xlCalculationAutomatic".lower())
        self.globals["xlCalculationManual".lower()] = 4135
        self.vb_constants.add("xlCalculationManual".lower())
        self.globals["xlCalculationSemiautomatic".lower()] = 2
        self.vb_constants.add("xlCalculationSemiautomatic".lower())
        self.globals["xlCancel".lower()] = 1
        self.vb_constants.add("xlCancel".lower())
        self.globals["xlCap".lower()] = 1
        self.vb_constants.add("xlCap".lower())
        self.globals["xlCaptionBeginsWith".lower()] = 17
        self.vb_constants.add("xlCaptionBeginsWith".lower())
        self.globals["xlCaptionContains".lower()] = 21
        self.vb_constants.add("xlCaptionContains".lower())
        self.globals["xlCaptionDoesNotBeginWith".lower()] = 18
        self.vb_constants.add("xlCaptionDoesNotBeginWith".lower())
        self.globals["xlCaptionDoesNotContain".lower()] = 22
        self.vb_constants.add("xlCaptionDoesNotContain".lower())
        self.globals["xlCaptionDoesNotEndWith".lower()] = 20
        self.vb_constants.add("xlCaptionDoesNotEndWith".lower())
        self.globals["xlCaptionDoesNotEqual".lower()] = 16
        self.vb_constants.add("xlCaptionDoesNotEqual".lower())
        self.globals["xlCaptionEndsWith".lower()] = 19
        self.vb_constants.add("xlCaptionEndsWith".lower())
        self.globals["xlCaptionEquals".lower()] = 15
        self.vb_constants.add("xlCaptionEquals".lower())
        self.globals["xlCaptionIsBetween".lower()] = 27
        self.vb_constants.add("xlCaptionIsBetween".lower())
        self.globals["xlCaptionIsGreaterThan".lower()] = 23
        self.vb_constants.add("xlCaptionIsGreaterThan".lower())
        self.globals["xlCaptionIsGreaterThanOrEqualTo".lower()] = 24
        self.vb_constants.add("xlCaptionIsGreaterThanOrEqualTo".lower())
        self.globals["xlCaptionIsLessThan".lower()] = 25
        self.vb_constants.add("xlCaptionIsLessThan".lower())
        self.globals["xlCaptionIsLessThanOrEqualTo".lower()] = 26
        self.vb_constants.add("xlCaptionIsLessThanOrEqualTo".lower())
        self.globals["xlCaptionIsNotBetween".lower()] = 28
        self.vb_constants.add("xlCaptionIsNotBetween".lower())
        self.globals["xlCascade".lower()] = 7
        self.vb_constants.add("xlCascade".lower())
        self.globals["xlCategory".lower()] = 1
        self.vb_constants.add("xlCategory".lower())
        self.globals["xlCategoryAscending".lower()] = 2
        self.vb_constants.add("xlCategoryAscending".lower())
        self.globals["xlCategoryDescending".lower()] = 3
        self.vb_constants.add("xlCategoryDescending".lower())
        self.globals["xlCategoryLabelLevelAll".lower()] = 1
        self.vb_constants.add("xlCategoryLabelLevelAll".lower())
        self.globals["xlCategoryLabelLevelCustom".lower()] = 2
        self.vb_constants.add("xlCategoryLabelLevelCustom".lower())
        self.globals["xlCategoryLabelLevelNone".lower()] = 3
        self.vb_constants.add("xlCategoryLabelLevelNone".lower())
        self.globals["xlCategoryScale".lower()] = 2
        self.vb_constants.add("xlCategoryScale".lower())
        self.globals["xlCellChangeApplied".lower()] = 3
        self.vb_constants.add("xlCellChangeApplied".lower())
        self.globals["xlCellChanged".lower()] = 2
        self.vb_constants.add("xlCellChanged".lower())
        self.globals["xlCellNotChanged".lower()] = 1
        self.vb_constants.add("xlCellNotChanged".lower())
        self.globals["xlCellTypeAllFormatConditions".lower()] = 4172
        self.vb_constants.add("xlCellTypeAllFormatConditions".lower())
        self.globals["xlCellTypeAllValidation".lower()] = 4174
        self.vb_constants.add("xlCellTypeAllValidation".lower())
        self.globals["xlCellTypeBlanks".lower()] = 4
        self.vb_constants.add("xlCellTypeBlanks".lower())
        self.globals["xlCellTypeComments".lower()] = 4144
        self.vb_constants.add("xlCellTypeComments".lower())
        self.globals["xlCellTypeConstants".lower()] = 2
        self.vb_constants.add("xlCellTypeConstants".lower())
        self.globals["xlCellTypeFormulas".lower()] = 4123
        self.vb_constants.add("xlCellTypeFormulas".lower())
        self.globals["xlCellTypeLastCell".lower()] = 11
        self.vb_constants.add("xlCellTypeLastCell".lower())
        self.globals["xlCellTypeSameFormatConditions".lower()] = 4173
        self.vb_constants.add("xlCellTypeSameFormatConditions".lower())
        self.globals["xlCellTypeSameValidation".lower()] = 4175
        self.vb_constants.add("xlCellTypeSameValidation".lower())
        self.globals["xlCellTypeVisible".lower()] = 12
        self.vb_constants.add("xlCellTypeVisible".lower())
        self.globals["xlCellValue".lower()] = 1
        self.vb_constants.add("xlCellValue".lower())
        self.globals["xlCenter".lower()] = 4108
        self.vb_constants.add("xlCenter".lower())
        self.globals["xlCenterAcrossSelection".lower()] = 7
        self.vb_constants.add("xlCenterAcrossSelection".lower())
        self.globals["xlCenterPoint".lower()] = 5
        self.vb_constants.add("xlCenterPoint".lower())
        self.globals["xlCentimeters".lower()] = 1
        self.vb_constants.add("xlCentimeters".lower())
        self.globals["xlCGM".lower()] = 7
        self.vb_constants.add("xlCGM".lower())
        self.globals["xlChangeAttributes".lower()] = 6
        self.vb_constants.add("xlChangeAttributes".lower())
        self.globals["xlChangeByExcel".lower()] = 0
        self.vb_constants.add("xlChangeByExcel".lower())
        self.globals["xlChangeByPowerPivotAddIn".lower()] = 1
        self.vb_constants.add("xlChangeByPowerPivotAddIn".lower())
        self.globals["xlChart".lower()] = 4109
        self.vb_constants.add("xlChart".lower())
        self.globals["xlChart4".lower()] = 2
        self.vb_constants.add("xlChart4".lower())
        self.globals["xlChartArea".lower()] = 2
        self.vb_constants.add("xlChartArea".lower())
        self.globals["xlChartAsWindow".lower()] = 5
        self.vb_constants.add("xlChartAsWindow".lower())
        self.globals["xlChartElementPositionAutomatic".lower()] = 4105
        self.vb_constants.add("xlChartElementPositionAutomatic".lower())
        self.globals["xlChartElementPositionCustom".lower()] = 4114
        self.vb_constants.add("xlChartElementPositionCustom".lower())
        self.globals["xlChartInPlace".lower()] = 4
        self.vb_constants.add("xlChartInPlace".lower())
        self.globals["xlChartSeries".lower()] = 17
        self.vb_constants.add("xlChartSeries".lower())
        self.globals["xlChartShort".lower()] = 6
        self.vb_constants.add("xlChartShort".lower())
        self.globals["xlChartTitle".lower()] = 4
        self.vb_constants.add("xlChartTitle".lower())
        self.globals["xlChartTitles".lower()] = 18
        self.vb_constants.add("xlChartTitles".lower())
        self.globals["xlCheckBox".lower()] = 1
        self.vb_constants.add("xlCheckBox".lower())
        self.globals["xlChecker".lower()] = 9
        self.vb_constants.add("xlChecker".lower())
        self.globals["xlCheckInMajorVersion".lower()] = 1
        self.vb_constants.add("xlCheckInMajorVersion".lower())
        self.globals["xlCheckInMinorVersion".lower()] = 0
        self.vb_constants.add("xlCheckInMinorVersion".lower())
        self.globals["xlCheckInOverwriteVersion".lower()] = 2
        self.vb_constants.add("xlCheckInOverwriteVersion".lower())
        self.globals["xlChronological".lower()] = 3
        self.vb_constants.add("xlChronological".lower())
        self.globals["xlCircle".lower()] = 8
        self.vb_constants.add("xlCircle".lower())
        self.globals["xlClassic1".lower()] = 1
        self.vb_constants.add("xlClassic1".lower())
        self.globals["xlClassic2".lower()] = 2
        self.vb_constants.add("xlClassic2".lower())
        self.globals["xlClassic3".lower()] = 3
        self.vb_constants.add("xlClassic3".lower())
        self.globals["xlClipboard".lower()] = 3
        self.vb_constants.add("xlClipboard".lower())
        self.globals["xlClipboardFormatBIFF".lower()] = 8
        self.vb_constants.add("xlClipboardFormatBIFF".lower())
        self.globals["xlClipboardFormatBIFF12".lower()] = 63
        self.vb_constants.add("xlClipboardFormatBIFF12".lower())
        self.globals["xlClipboardFormatBIFF2".lower()] = 18
        self.vb_constants.add("xlClipboardFormatBIFF2".lower())
        self.globals["xlClipboardFormatBIFF3".lower()] = 20
        self.vb_constants.add("xlClipboardFormatBIFF3".lower())
        self.globals["xlClipboardFormatBIFF4".lower()] = 30
        self.vb_constants.add("xlClipboardFormatBIFF4".lower())
        self.globals["xlClipboardFormatBinary".lower()] = 15
        self.vb_constants.add("xlClipboardFormatBinary".lower())
        self.globals["xlClipboardFormatBitmap".lower()] = 9
        self.vb_constants.add("xlClipboardFormatBitmap".lower())
        self.globals["xlClipboardFormatCGM".lower()] = 13
        self.vb_constants.add("xlClipboardFormatCGM".lower())
        self.globals["xlClipboardFormatCSV".lower()] = 5
        self.vb_constants.add("xlClipboardFormatCSV".lower())
        self.globals["xlClipboardFormatDIF".lower()] = 4
        self.vb_constants.add("xlClipboardFormatDIF".lower())
        self.globals["xlClipboardFormatDspText".lower()] = 12
        self.vb_constants.add("xlClipboardFormatDspText".lower())
        self.globals["xlClipboardFormatEmbeddedObject".lower()] = 21
        self.vb_constants.add("xlClipboardFormatEmbeddedObject".lower())
        self.globals["xlClipboardFormatEmbedSource".lower()] = 22
        self.vb_constants.add("xlClipboardFormatEmbedSource".lower())
        self.globals["xlClipboardFormatLink".lower()] = 11
        self.vb_constants.add("xlClipboardFormatLink".lower())
        self.globals["xlClipboardFormatLinkSource".lower()] = 23
        self.vb_constants.add("xlClipboardFormatLinkSource".lower())
        self.globals["xlClipboardFormatLinkSourceDesc".lower()] = 32
        self.vb_constants.add("xlClipboardFormatLinkSourceDesc".lower())
        self.globals["xlClipboardFormatMovie".lower()] = 24
        self.vb_constants.add("xlClipboardFormatMovie".lower())
        self.globals["xlClipboardFormatNative".lower()] = 14
        self.vb_constants.add("xlClipboardFormatNative".lower())
        self.globals["xlClipboardFormatObjectDesc".lower()] = 31
        self.vb_constants.add("xlClipboardFormatObjectDesc".lower())
        self.globals["xlClipboardFormatObjectLink".lower()] = 19
        self.vb_constants.add("xlClipboardFormatObjectLink".lower())
        self.globals["xlClipboardFormatOwnerLink".lower()] = 17
        self.vb_constants.add("xlClipboardFormatOwnerLink".lower())
        self.globals["xlClipboardFormatPICT".lower()] = 2
        self.vb_constants.add("xlClipboardFormatPICT".lower())
        self.globals["xlClipboardFormatPrintPICT".lower()] = 3
        self.vb_constants.add("xlClipboardFormatPrintPICT".lower())
        self.globals["xlClipboardFormatRTF".lower()] = 7
        self.vb_constants.add("xlClipboardFormatRTF".lower())
        self.globals["xlClipboardFormatScreenPICT".lower()] = 29
        self.vb_constants.add("xlClipboardFormatScreenPICT".lower())
        self.globals["xlClipboardFormatStandardFont".lower()] = 28
        self.vb_constants.add("xlClipboardFormatStandardFont".lower())
        self.globals["xlClipboardFormatStandardScale".lower()] = 27
        self.vb_constants.add("xlClipboardFormatStandardScale".lower())
        self.globals["xlClipboardFormatSYLK".lower()] = 6
        self.vb_constants.add("xlClipboardFormatSYLK".lower())
        self.globals["xlClipboardFormatTable".lower()] = 16
        self.vb_constants.add("xlClipboardFormatTable".lower())
        self.globals["xlClipboardFormatText".lower()] = 0
        self.vb_constants.add("xlClipboardFormatText".lower())
        self.globals["xlClipboardFormatToolFace".lower()] = 25
        self.vb_constants.add("xlClipboardFormatToolFace".lower())
        self.globals["xlClipboardFormatToolFacePICT".lower()] = 26
        self.vb_constants.add("xlClipboardFormatToolFacePICT".lower())
        self.globals["xlClipboardFormatVALU".lower()] = 1
        self.vb_constants.add("xlClipboardFormatVALU".lower())
        self.globals["xlClipboardFormatWK1".lower()] = 10
        self.vb_constants.add("xlClipboardFormatWK1".lower())
        self.globals["xlClosed".lower()] = 3
        self.vb_constants.add("xlClosed".lower())
        self.globals["xlCmdCube".lower()] = 1
        self.vb_constants.add("xlCmdCube".lower())
        self.globals["xlCmdDAX".lower()] = 8
        self.vb_constants.add("xlCmdDAX".lower())
        self.globals["xlCmdDefault".lower()] = 4
        self.vb_constants.add("xlCmdDefault".lower())
        self.globals["xlCmdExcel".lower()] = 7
        self.vb_constants.add("xlCmdExcel".lower())
        self.globals["xlCmdList".lower()] = 5
        self.vb_constants.add("xlCmdList".lower())
        self.globals["xlCmdSql".lower()] = 2
        self.vb_constants.add("xlCmdSql".lower())
        self.globals["xlCmdTable".lower()] = 3
        self.vb_constants.add("xlCmdTable".lower())
        self.globals["xlCmdTableCollection".lower()] = 6
        self.vb_constants.add("xlCmdTableCollection".lower())
        self.globals["xlCodePage".lower()] = 2
        self.vb_constants.add("xlCodePage".lower())
        self.globals["xlColGroups".lower()] = 2
        self.vb_constants.add("xlColGroups".lower())
        self.globals["xlColor1".lower()] = 7
        self.vb_constants.add("xlColor1".lower())
        self.globals["xlColor2".lower()] = 8
        self.vb_constants.add("xlColor2".lower())
        self.globals["xlColor3".lower()] = 9
        self.vb_constants.add("xlColor3".lower())
        self.globals["xlColorIndexAutomatic".lower()] = 4105
        self.vb_constants.add("xlColorIndexAutomatic".lower())
        self.globals["xlColorIndexNone".lower()] = 4142
        self.vb_constants.add("xlColorIndexNone".lower())
        self.globals["xlColorScale".lower()] = 3
        self.vb_constants.add("xlColorScale".lower())
        self.globals["xlColorScaleBlackWhite".lower()] = 3
        self.vb_constants.add("xlColorScaleBlackWhite".lower())
        self.globals["xlColorScaleGYR".lower()] = 2
        self.vb_constants.add("xlColorScaleGYR".lower())
        self.globals["xlColorScaleRYG".lower()] = 1
        self.vb_constants.add("xlColorScaleRYG".lower())
        self.globals["xlColorScaleWhiteBlack".lower()] = 4
        self.vb_constants.add("xlColorScaleWhiteBlack".lower())
        self.globals["xlColumn".lower()] = 3
        self.vb_constants.add("xlColumn".lower())
        self.globals["xlColumnClustered".lower()] = 51
        self.vb_constants.add("xlColumnClustered".lower())
        self.globals["xlColumnField".lower()] = 2
        self.vb_constants.add("xlColumnField".lower())
        self.globals["xlColumnHeader".lower()] = 4110
        self.vb_constants.add("xlColumnHeader".lower())
        self.globals["xlColumnItem".lower()] = 5
        self.vb_constants.add("xlColumnItem".lower())
        self.globals["xlColumnLabels".lower()] = 2
        self.vb_constants.add("xlColumnLabels".lower())
        self.globals["xlColumns".lower()] = 2
        self.vb_constants.add("xlColumns".lower())
        self.globals["xlColumnSeparator".lower()] = 14
        self.vb_constants.add("xlColumnSeparator".lower())
        self.globals["xlColumnStacked".lower()] = 52
        self.vb_constants.add("xlColumnStacked".lower())
        self.globals["xlColumnStacked100".lower()] = 53
        self.vb_constants.add("xlColumnStacked100".lower())
        self.globals["xlColumnStripe1".lower()] = 7
        self.vb_constants.add("xlColumnStripe1".lower())
        self.globals["xlColumnStripe2".lower()] = 8
        self.vb_constants.add("xlColumnStripe2".lower())
        self.globals["xlColumnSubheading1".lower()] = 20
        self.vb_constants.add("xlColumnSubheading1".lower())
        self.globals["xlColumnSubheading2".lower()] = 21
        self.vb_constants.add("xlColumnSubheading2".lower())
        self.globals["xlColumnSubheading3".lower()] = 22
        self.vb_constants.add("xlColumnSubheading3".lower())
        self.globals["xlColumnThenRow".lower()] = 2
        self.vb_constants.add("xlColumnThenRow".lower())
        self.globals["xlCombination".lower()] = 4111
        self.vb_constants.add("xlCombination".lower())
        self.globals["xlCommand".lower()] = 2
        self.vb_constants.add("xlCommand".lower())
        self.globals["xlCommandUnderlinesAutomatic".lower()] = 4105
        self.vb_constants.add("xlCommandUnderlinesAutomatic".lower())
        self.globals["xlCommandUnderlinesOff".lower()] = 4146
        self.vb_constants.add("xlCommandUnderlinesOff".lower())
        self.globals["xlCommandUnderlinesOn".lower()] = 1
        self.vb_constants.add("xlCommandUnderlinesOn".lower())
        self.globals["xlCommentAndIndicator".lower()] = 1
        self.vb_constants.add("xlCommentAndIndicator".lower())
        self.globals["xlCommentIndicatorOnly".lower()] = 1
        self.vb_constants.add("xlCommentIndicatorOnly".lower())
        self.globals["xlComments".lower()] = 4144
        self.vb_constants.add("xlComments".lower())
        self.globals["xlCompactRow".lower()] = 0
        self.vb_constants.add("xlCompactRow".lower())
        self.globals["xlComplete".lower()] = 4
        self.vb_constants.add("xlComplete".lower())
        self.globals["xlConditionValueAutomaticMax".lower()] = 7
        self.vb_constants.add("xlConditionValueAutomaticMax".lower())
        self.globals["xlConditionValueAutomaticMin".lower()] = 6
        self.vb_constants.add("xlConditionValueAutomaticMin".lower())
        self.globals["xlConditionValueFormula".lower()] = 4
        self.vb_constants.add("xlConditionValueFormula".lower())
        self.globals["xlConditionValueHighestValue".lower()] = 2
        self.vb_constants.add("xlConditionValueHighestValue".lower())
        self.globals["xlConditionValueLowestValue".lower()] = 1
        self.vb_constants.add("xlConditionValueLowestValue".lower())
        self.globals["xlConditionValueNone".lower()] = 1
        self.vb_constants.add("xlConditionValueNone".lower())
        self.globals["xlConditionValueNumber".lower()] = 0
        self.vb_constants.add("xlConditionValueNumber".lower())
        self.globals["xlConditionValuePercent".lower()] = 3
        self.vb_constants.add("xlConditionValuePercent".lower())
        self.globals["xlConditionValuePercentile".lower()] = 5
        self.vb_constants.add("xlConditionValuePercentile".lower())
        self.globals["xlConeBarClustered".lower()] = 102
        self.vb_constants.add("xlConeBarClustered".lower())
        self.globals["xlConeBarStacked".lower()] = 103
        self.vb_constants.add("xlConeBarStacked".lower())
        self.globals["xlConeBarStacked100".lower()] = 104
        self.vb_constants.add("xlConeBarStacked100".lower())
        self.globals["xlConeCol".lower()] = 105
        self.vb_constants.add("xlConeCol".lower())
        self.globals["xlConeColClustered".lower()] = 99
        self.vb_constants.add("xlConeColClustered".lower())
        self.globals["xlConeColStacked".lower()] = 100
        self.vb_constants.add("xlConeColStacked".lower())
        self.globals["xlConeColStacked100".lower()] = 101
        self.vb_constants.add("xlConeColStacked100".lower())
        self.globals["xlConeToMax".lower()] = 5
        self.vb_constants.add("xlConeToMax".lower())
        self.globals["xlConeToPoint".lower()] = 4
        self.vb_constants.add("xlConeToPoint".lower())
        self.globals["xlConnectionTypeDATAFEED".lower()] = 6
        self.vb_constants.add("xlConnectionTypeDATAFEED".lower())
        self.globals["xlConnectionTypeMODEL".lower()] = 7
        self.vb_constants.add("xlConnectionTypeMODEL".lower())
        self.globals["xlConnectionTypeNOSOURCE".lower()] = 9
        self.vb_constants.add("xlConnectionTypeNOSOURCE".lower())
        self.globals["xlConnectionTypeODBC".lower()] = 2
        self.vb_constants.add("xlConnectionTypeODBC".lower())
        self.globals["xlConnectionTypeOLEDB".lower()] = 1
        self.vb_constants.add("xlConnectionTypeOLEDB".lower())
        self.globals["xlConnectionTypeTEXT".lower()] = 4
        self.vb_constants.add("xlConnectionTypeTEXT".lower())
        self.globals["xlConnectionTypeWEB".lower()] = 5
        self.vb_constants.add("xlConnectionTypeWEB".lower())
        self.globals["xlConnectionTypeWORKSHEET".lower()] = 8
        self.vb_constants.add("xlConnectionTypeWORKSHEET".lower())
        self.globals["xlConnectionTypeXMLMAP".lower()] = 3
        self.vb_constants.add("xlConnectionTypeXMLMAP".lower())
        self.globals["xlConsolidation".lower()] = 3
        self.vb_constants.add("xlConsolidation".lower())
        self.globals["xlConstant".lower()] = 1
        self.vb_constants.add("xlConstant".lower())
        self.globals["xlConstants".lower()] = 2
        self.vb_constants.add("xlConstants".lower())
        self.globals["xlContains".lower()] = 0
        self.vb_constants.add("xlContains".lower())
        self.globals["xlContents".lower()] = 2
        self.vb_constants.add("xlContents".lower())
        self.globals["xlContext".lower()] = 5002
        self.vb_constants.add("xlContext".lower())
        self.globals["xlContinuous".lower()] = 1
        self.vb_constants.add("xlContinuous".lower())
        self.globals["xlCopy".lower()] = 1
        self.vb_constants.add("xlCopy".lower())
        self.globals["xlCorner".lower()] = 2
        self.vb_constants.add("xlCorner".lower())
        self.globals["xlCorners".lower()] = 6
        self.vb_constants.add("xlCorners".lower())
        self.globals["xlCount".lower()] = 4112
        self.vb_constants.add("xlCount".lower())
        self.globals["xlCountNums".lower()] = 4113
        self.vb_constants.add("xlCountNums".lower())
        self.globals["xlCountryCode".lower()] = 1
        self.vb_constants.add("xlCountryCode".lower())
        self.globals["xlCountrySetting".lower()] = 2
        self.vb_constants.add("xlCountrySetting".lower())
        self.globals["xlCreatorCode".lower()] = 1480803660
        self.vb_constants.add("xlCreatorCode".lower())
        self.globals["xlCredentialsMethodIntegrated".lower()] = 0
        self.vb_constants.add("xlCredentialsMethodIntegrated".lower())
        self.globals["xlCredentialsMethodNone".lower()] = 1
        self.vb_constants.add("xlCredentialsMethodNone".lower())
        self.globals["xlCredentialsMethodStored".lower()] = 2
        self.vb_constants.add("xlCredentialsMethodStored".lower())
        self.globals["xlCrissCross".lower()] = 16
        self.vb_constants.add("xlCrissCross".lower())
        self.globals["xlCross".lower()] = 4
        self.vb_constants.add("xlCross".lower())
        self.globals["xlCSV".lower()] = 6
        self.vb_constants.add("xlCSV".lower())
        self.globals["xlCSVMac".lower()] = 22
        self.vb_constants.add("xlCSVMac".lower())
        self.globals["xlCSVMSDOS".lower()] = 24
        self.vb_constants.add("xlCSVMSDOS".lower())
        self.globals["xlCSVUTF8".lower()] = 62
        self.vb_constants.add("xlCSVUTF8".lower())
        self.globals["xlCSVWindows".lower()] = 23
        self.vb_constants.add("xlCSVWindows".lower())
        self.globals["xlCubeAttribute".lower()] = 4
        self.vb_constants.add("xlCubeAttribute".lower())
        self.globals["xlCubeCalculatedMeasure".lower()] = 5
        self.vb_constants.add("xlCubeCalculatedMeasure".lower())
        self.globals["xlCubeHierarchy".lower()] = 1
        self.vb_constants.add("xlCubeHierarchy".lower())
        self.globals["xlCubeImplicitMeasure".lower()] = 11
        self.vb_constants.add("xlCubeImplicitMeasure".lower())
        self.globals["xlCubeKPIGoal".lower()] = 7
        self.vb_constants.add("xlCubeKPIGoal".lower())
        self.globals["xlCubeKPIStatus".lower()] = 8
        self.vb_constants.add("xlCubeKPIStatus".lower())
        self.globals["xlCubeKPITrend".lower()] = 9
        self.vb_constants.add("xlCubeKPITrend".lower())
        self.globals["xlCubeKPIValue".lower()] = 6
        self.vb_constants.add("xlCubeKPIValue".lower())
        self.globals["xlCubeKPIWeight".lower()] = 10
        self.vb_constants.add("xlCubeKPIWeight".lower())
        self.globals["xlCubeMeasure".lower()] = 2
        self.vb_constants.add("xlCubeMeasure".lower())
        self.globals["xlCubeSet".lower()] = 3
        self.vb_constants.add("xlCubeSet".lower())
        self.globals["xlCurrencyBefore".lower()] = 37
        self.vb_constants.add("xlCurrencyBefore".lower())
        self.globals["xlCurrencyCode".lower()] = 25
        self.vb_constants.add("xlCurrencyCode".lower())
        self.globals["xlCurrencyDigits".lower()] = 27
        self.vb_constants.add("xlCurrencyDigits".lower())
        self.globals["xlCurrencyLeadingZeros".lower()] = 40
        self.vb_constants.add("xlCurrencyLeadingZeros".lower())
        self.globals["xlCurrencyMinusSign".lower()] = 38
        self.vb_constants.add("xlCurrencyMinusSign".lower())
        self.globals["xlCurrencyNegative".lower()] = 28
        self.vb_constants.add("xlCurrencyNegative".lower())
        self.globals["xlCurrencySpaceBefore".lower()] = 36
        self.vb_constants.add("xlCurrencySpaceBefore".lower())
        self.globals["xlCurrencyTrailingZeros".lower()] = 39
        self.vb_constants.add("xlCurrencyTrailingZeros".lower())
        self.globals["xlCurrentPlatformText".lower()] = 4158
        self.vb_constants.add("xlCurrentPlatformText".lower())
        self.globals["xlCustom".lower()] = 4114
        self.vb_constants.add("xlCustom".lower())
        self.globals["xlCustomSet".lower()] = 1
        self.vb_constants.add("xlCustomSet".lower())
        self.globals["xlCut".lower()] = 2
        self.vb_constants.add("xlCut".lower())
        self.globals["xlCylinder".lower()] = 3
        self.vb_constants.add("xlCylinder".lower())
        self.globals["xlCylinderBarClustered".lower()] = 95
        self.vb_constants.add("xlCylinderBarClustered".lower())
        self.globals["xlCylinderBarStacked".lower()] = 96
        self.vb_constants.add("xlCylinderBarStacked".lower())
        self.globals["xlCylinderBarStacked100".lower()] = 97
        self.vb_constants.add("xlCylinderBarStacked100".lower())
        self.globals["xlCylinderCol".lower()] = 98
        self.vb_constants.add("xlCylinderCol".lower())
        self.globals["xlCylinderColClustered".lower()] = 92
        self.vb_constants.add("xlCylinderColClustered".lower())
        self.globals["xlCylinderColStacked".lower()] = 93
        self.vb_constants.add("xlCylinderColStacked".lower())
        self.globals["xlCylinderColStacked100".lower()] = 94
        self.vb_constants.add("xlCylinderColStacked100".lower())
        self.globals["xlDAORecordset".lower()] = 2
        self.vb_constants.add("xlDAORecordset".lower())
        self.globals["xlDash".lower()] = 4115
        self.vb_constants.add("xlDash".lower())
        self.globals["xlDashDot".lower()] = 4
        self.vb_constants.add("xlDashDot".lower())
        self.globals["xlDashDotDot".lower()] = 5
        self.vb_constants.add("xlDashDotDot".lower())
        self.globals["xlDataAndLabel".lower()] = 0
        self.vb_constants.add("xlDataAndLabel".lower())
        self.globals["xlDatabar".lower()] = 4
        self.vb_constants.add("xlDatabar".lower())
        self.globals["xlDataBarAxisAutomatic".lower()] = 0
        self.vb_constants.add("xlDataBarAxisAutomatic".lower())
        self.globals["xlDataBarAxisMidpoint".lower()] = 1
        self.vb_constants.add("xlDataBarAxisMidpoint".lower())
        self.globals["xlDataBarAxisNone".lower()] = 2
        self.vb_constants.add("xlDataBarAxisNone".lower())
        self.globals["xlDataBarBorderNone".lower()] = 0
        self.vb_constants.add("xlDataBarBorderNone".lower())
        self.globals["xlDataBarBorderSolid".lower()] = 1
        self.vb_constants.add("xlDataBarBorderSolid".lower())
        self.globals["xlDataBarColor".lower()] = 0
        self.vb_constants.add("xlDataBarColor".lower())
        self.globals["xlDataBarFillGradient".lower()] = 1
        self.vb_constants.add("xlDataBarFillGradient".lower())
        self.globals["xlDataBarFillSolid".lower()] = 0
        self.vb_constants.add("xlDataBarFillSolid".lower())
        self.globals["xlDataBarSameAsPositive".lower()] = 1
        self.vb_constants.add("xlDataBarSameAsPositive".lower())
        self.globals["xlDatabase".lower()] = 1
        self.vb_constants.add("xlDatabase".lower())
        self.globals["xlDataField".lower()] = 4
        self.vb_constants.add("xlDataField".lower())
        self.globals["xlDataFieldScope".lower()] = 2
        self.vb_constants.add("xlDataFieldScope".lower())
        self.globals["xlDataHeader".lower()] = 3
        self.vb_constants.add("xlDataHeader".lower())
        self.globals["xlDataItem".lower()] = 7
        self.vb_constants.add("xlDataItem".lower())
        self.globals["xlDataLabel".lower()] = 0
        self.vb_constants.add("xlDataLabel".lower())
        self.globals["xlDataLabelSeparatorDefault".lower()] = 1
        self.vb_constants.add("xlDataLabelSeparatorDefault".lower())
        self.globals["xlDataLabelsShowBubbleSizes".lower()] = 6
        self.vb_constants.add("xlDataLabelsShowBubbleSizes".lower())
        self.globals["xlDataLabelsShowLabel".lower()] = 4
        self.vb_constants.add("xlDataLabelsShowLabel".lower())
        self.globals["xlDataLabelsShowLabelAndPercent".lower()] = 5
        self.vb_constants.add("xlDataLabelsShowLabelAndPercent".lower())
        self.globals["xlDataLabelsShowNone".lower()] = 4142
        self.vb_constants.add("xlDataLabelsShowNone".lower())
        self.globals["xlDataLabelsShowPercent".lower()] = 3
        self.vb_constants.add("xlDataLabelsShowPercent".lower())
        self.globals["xlDataLabelsShowValue".lower()] = 2
        self.vb_constants.add("xlDataLabelsShowValue".lower())
        self.globals["xlDataOnly".lower()] = 2
        self.vb_constants.add("xlDataOnly".lower())
        self.globals["xlDataSeriesLinear".lower()] = 4132
        self.vb_constants.add("xlDataSeriesLinear".lower())
        self.globals["xlDataTable".lower()] = 7
        self.vb_constants.add("xlDataTable".lower())
        self.globals["xlDate".lower()] = 2
        self.vb_constants.add("xlDate".lower())
        self.globals["xlDateBetween".lower()] = 35
        self.vb_constants.add("xlDateBetween".lower())
        self.globals["xlDateLastMonth".lower()] = 45
        self.vb_constants.add("xlDateLastMonth".lower())
        self.globals["xlDateLastQuarter".lower()] = 48
        self.vb_constants.add("xlDateLastQuarter".lower())
        self.globals["xlDateLastWeek".lower()] = 42
        self.vb_constants.add("xlDateLastWeek".lower())
        self.globals["xlDateLastYear".lower()] = 51
        self.vb_constants.add("xlDateLastYear".lower())
        self.globals["xlDateNextMonth".lower()] = 43
        self.vb_constants.add("xlDateNextMonth".lower())
        self.globals["xlDateNextQuarter".lower()] = 46
        self.vb_constants.add("xlDateNextQuarter".lower())
        self.globals["xlDateNextWeek".lower()] = 40
        self.vb_constants.add("xlDateNextWeek".lower())
        self.globals["xlDateNextYear".lower()] = 49
        self.vb_constants.add("xlDateNextYear".lower())
        self.globals["xlDateNotBetween".lower()] = 36
        self.vb_constants.add("xlDateNotBetween".lower())
        self.globals["xlDateOrder".lower()] = 32
        self.vb_constants.add("xlDateOrder".lower())
        self.globals["xlDateSeparator".lower()] = 17
        self.vb_constants.add("xlDateSeparator".lower())
        self.globals["xlDateThisMonth".lower()] = 44
        self.vb_constants.add("xlDateThisMonth".lower())
        self.globals["xlDateThisQuarter".lower()] = 47
        self.vb_constants.add("xlDateThisQuarter".lower())
        self.globals["xlDateThisWeek".lower()] = 41
        self.vb_constants.add("xlDateThisWeek".lower())
        self.globals["xlDateThisYear".lower()] = 50
        self.vb_constants.add("xlDateThisYear".lower())
        self.globals["xlDateToday".lower()] = 38
        self.vb_constants.add("xlDateToday".lower())
        self.globals["xlDateTomorrow".lower()] = 37
        self.vb_constants.add("xlDateTomorrow".lower())
        self.globals["xlDateYesterday".lower()] = 39
        self.vb_constants.add("xlDateYesterday".lower())
        self.globals["xlDay".lower()] = 1
        self.vb_constants.add("xlDay".lower())
        self.globals["xlDayCode".lower()] = 21
        self.vb_constants.add("xlDayCode".lower())
        self.globals["xlDayLeadingZero".lower()] = 42
        self.vb_constants.add("xlDayLeadingZero".lower())
        self.globals["xlDays".lower()] = 0
        self.vb_constants.add("xlDays".lower())
        self.globals["xlDBF2".lower()] = 7
        self.vb_constants.add("xlDBF2".lower())
        self.globals["xlDBF3".lower()] = 8
        self.vb_constants.add("xlDBF3".lower())
        self.globals["xlDBF4".lower()] = 11
        self.vb_constants.add("xlDBF4".lower())
        self.globals["xlDebugCodePane".lower()] = 13
        self.vb_constants.add("xlDebugCodePane".lower())
        self.globals["xlDecimalSeparator".lower()] = 3
        self.vb_constants.add("xlDecimalSeparator".lower())
        self.globals["xlDefault".lower()] = 4143
        self.vb_constants.add("xlDefault".lower())
        self.globals["xlDefaultAutoFormat".lower()] = 1
        self.vb_constants.add("xlDefaultAutoFormat".lower())
        self.globals["xlDelimited".lower()] = 1
        self.vb_constants.add("xlDelimited".lower())
        self.globals["xlDescending".lower()] = 2
        self.vb_constants.add("xlDescending".lower())
        self.globals["xlDesktop".lower()] = 9
        self.vb_constants.add("xlDesktop".lower())
        self.globals["xlDiagonalDown".lower()] = 5
        self.vb_constants.add("xlDiagonalDown".lower())
        self.globals["xlDiagonalUp".lower()] = 6
        self.vb_constants.add("xlDiagonalUp".lower())
        self.globals["xlDialogActivate".lower()] = 103
        self.vb_constants.add("xlDialogActivate".lower())
        self.globals["xlDialogActiveCellFont".lower()] = 476
        self.vb_constants.add("xlDialogActiveCellFont".lower())
        self.globals["xlDialogAddChartAutoformat".lower()] = 390
        self.vb_constants.add("xlDialogAddChartAutoformat".lower())
        self.globals["xlDialogAddinManager".lower()] = 321
        self.vb_constants.add("xlDialogAddinManager".lower())
        self.globals["xlDialogAlignment".lower()] = 43
        self.vb_constants.add("xlDialogAlignment".lower())
        self.globals["xlDialogApplyNames".lower()] = 133
        self.vb_constants.add("xlDialogApplyNames".lower())
        self.globals["xlDialogApplyStyle".lower()] = 212
        self.vb_constants.add("xlDialogApplyStyle".lower())
        self.globals["xlDialogAppMove".lower()] = 170
        self.vb_constants.add("xlDialogAppMove".lower())
        self.globals["xlDialogAppSize".lower()] = 171
        self.vb_constants.add("xlDialogAppSize".lower())
        self.globals["xlDialogArrangeAll".lower()] = 12
        self.vb_constants.add("xlDialogArrangeAll".lower())
        self.globals["xlDialogAssignToObject".lower()] = 213
        self.vb_constants.add("xlDialogAssignToObject".lower())
        self.globals["xlDialogAssignToTool".lower()] = 293
        self.vb_constants.add("xlDialogAssignToTool".lower())
        self.globals["xlDialogAttachText".lower()] = 80
        self.vb_constants.add("xlDialogAttachText".lower())
        self.globals["xlDialogAttachToolbars".lower()] = 323
        self.vb_constants.add("xlDialogAttachToolbars".lower())
        self.globals["xlDialogAutoCorrect".lower()] = 485
        self.vb_constants.add("xlDialogAutoCorrect".lower())
        self.globals["xlDialogAxes".lower()] = 78
        self.vb_constants.add("xlDialogAxes".lower())
        self.globals["xlDialogBorder".lower()] = 45
        self.vb_constants.add("xlDialogBorder".lower())
        self.globals["xlDialogCalculation".lower()] = 32
        self.vb_constants.add("xlDialogCalculation".lower())
        self.globals["xlDialogCellProtection".lower()] = 46
        self.vb_constants.add("xlDialogCellProtection".lower())
        self.globals["xlDialogChangeLink".lower()] = 166
        self.vb_constants.add("xlDialogChangeLink".lower())
        self.globals["xlDialogChartAddData".lower()] = 392
        self.vb_constants.add("xlDialogChartAddData".lower())
        self.globals["xlDialogChartLocation".lower()] = 527
        self.vb_constants.add("xlDialogChartLocation".lower())
        self.globals["xlDialogChartOptionsDataLabelMultiple".lower()] = 724
        self.vb_constants.add("xlDialogChartOptionsDataLabelMultiple".lower())
        self.globals["xlDialogChartOptionsDataLabels".lower()] = 505
        self.vb_constants.add("xlDialogChartOptionsDataLabels".lower())
        self.globals["xlDialogChartOptionsDataTable".lower()] = 506
        self.vb_constants.add("xlDialogChartOptionsDataTable".lower())
        self.globals["xlDialogChartSourceData".lower()] = 540
        self.vb_constants.add("xlDialogChartSourceData".lower())
        self.globals["xlDialogChartTrend".lower()] = 350
        self.vb_constants.add("xlDialogChartTrend".lower())
        self.globals["xlDialogChartType".lower()] = 526
        self.vb_constants.add("xlDialogChartType".lower())
        self.globals["xlDialogChartWizard".lower()] = 288
        self.vb_constants.add("xlDialogChartWizard".lower())
        self.globals["xlDialogCheckboxProperties".lower()] = 435
        self.vb_constants.add("xlDialogCheckboxProperties".lower())
        self.globals["xlDialogClear".lower()] = 52
        self.vb_constants.add("xlDialogClear".lower())
        self.globals["xlDialogColorPalette".lower()] = 161
        self.vb_constants.add("xlDialogColorPalette".lower())
        self.globals["xlDialogColumnWidth".lower()] = 47
        self.vb_constants.add("xlDialogColumnWidth".lower())
        self.globals["xlDialogCombination".lower()] = 73
        self.vb_constants.add("xlDialogCombination".lower())
        self.globals["xlDialogConditionalFormatting".lower()] = 583
        self.vb_constants.add("xlDialogConditionalFormatting".lower())
        self.globals["xlDialogConsolidate".lower()] = 191
        self.vb_constants.add("xlDialogConsolidate".lower())
        self.globals["xlDialogCopyChart".lower()] = 147
        self.vb_constants.add("xlDialogCopyChart".lower())
        self.globals["xlDialogCopyPicture".lower()] = 108
        self.vb_constants.add("xlDialogCopyPicture".lower())
        self.globals["xlDialogCreateList".lower()] = 796
        self.vb_constants.add("xlDialogCreateList".lower())
        self.globals["xlDialogCreateNames".lower()] = 62
        self.vb_constants.add("xlDialogCreateNames".lower())
        self.globals["xlDialogCreatePublisher".lower()] = 217
        self.vb_constants.add("xlDialogCreatePublisher".lower())
        self.globals["xlDialogCreateRelationship".lower()] = 1272
        self.vb_constants.add("xlDialogCreateRelationship".lower())
        self.globals["xlDialogCustomizeToolbar".lower()] = 276
        self.vb_constants.add("xlDialogCustomizeToolbar".lower())
        self.globals["xlDialogCustomViews".lower()] = 493
        self.vb_constants.add("xlDialogCustomViews".lower())
        self.globals["xlDialogDataDelete".lower()] = 36
        self.vb_constants.add("xlDialogDataDelete".lower())
        self.globals["xlDialogDataLabel".lower()] = 379
        self.vb_constants.add("xlDialogDataLabel".lower())
        self.globals["xlDialogDataLabelMultiple".lower()] = 723
        self.vb_constants.add("xlDialogDataLabelMultiple".lower())
        self.globals["xlDialogDataSeries".lower()] = 40
        self.vb_constants.add("xlDialogDataSeries".lower())
        self.globals["xlDialogDataValidation".lower()] = 525
        self.vb_constants.add("xlDialogDataValidation".lower())
        self.globals["xlDialogDefineName".lower()] = 61
        self.vb_constants.add("xlDialogDefineName".lower())
        self.globals["xlDialogDefineStyle".lower()] = 229
        self.vb_constants.add("xlDialogDefineStyle".lower())
        self.globals["xlDialogDeleteFormat".lower()] = 111
        self.vb_constants.add("xlDialogDeleteFormat".lower())
        self.globals["xlDialogDeleteName".lower()] = 110
        self.vb_constants.add("xlDialogDeleteName".lower())
        self.globals["xlDialogDemote".lower()] = 203
        self.vb_constants.add("xlDialogDemote".lower())
        self.globals["xlDialogDisplay".lower()] = 27
        self.vb_constants.add("xlDialogDisplay".lower())
        self.globals["xlDialogDocumentInspector".lower()] = 862
        self.vb_constants.add("xlDialogDocumentInspector".lower())
        self.globals["xlDialogEditboxProperties".lower()] = 438
        self.vb_constants.add("xlDialogEditboxProperties".lower())
        self.globals["xlDialogEditColor".lower()] = 223
        self.vb_constants.add("xlDialogEditColor".lower())
        self.globals["xlDialogEditDelete".lower()] = 54
        self.vb_constants.add("xlDialogEditDelete".lower())
        self.globals["xlDialogEditionOptions".lower()] = 251
        self.vb_constants.add("xlDialogEditionOptions".lower())
        self.globals["xlDialogEditSeries".lower()] = 228
        self.vb_constants.add("xlDialogEditSeries".lower())
        self.globals["xlDialogErrorbarX".lower()] = 463
        self.vb_constants.add("xlDialogErrorbarX".lower())
        self.globals["xlDialogErrorbarY".lower()] = 464
        self.vb_constants.add("xlDialogErrorbarY".lower())
        self.globals["xlDialogErrorChecking".lower()] = 732
        self.vb_constants.add("xlDialogErrorChecking".lower())
        self.globals["xlDialogEvaluateFormula".lower()] = 709
        self.vb_constants.add("xlDialogEvaluateFormula".lower())
        self.globals["xlDialogExternalDataProperties".lower()] = 530
        self.vb_constants.add("xlDialogExternalDataProperties".lower())
        self.globals["xlDialogExtract".lower()] = 35
        self.vb_constants.add("xlDialogExtract".lower())
        self.globals["xlDialogFileDelete".lower()] = 6
        self.vb_constants.add("xlDialogFileDelete".lower())
        self.globals["xlDialogFileSharing".lower()] = 481
        self.vb_constants.add("xlDialogFileSharing".lower())
        self.globals["xlDialogFillGroup".lower()] = 200
        self.vb_constants.add("xlDialogFillGroup".lower())
        self.globals["xlDialogFillWorkgroup".lower()] = 301
        self.vb_constants.add("xlDialogFillWorkgroup".lower())
        self.globals["xlDialogFilter".lower()] = 447
        self.vb_constants.add("xlDialogFilter".lower())
        self.globals["xlDialogFilterAdvanced".lower()] = 370
        self.vb_constants.add("xlDialogFilterAdvanced".lower())
        self.globals["xlDialogFindFile".lower()] = 475
        self.vb_constants.add("xlDialogFindFile".lower())
        self.globals["xlDialogFont".lower()] = 26
        self.vb_constants.add("xlDialogFont".lower())
        self.globals["xlDialogFontProperties".lower()] = 381
        self.vb_constants.add("xlDialogFontProperties".lower())
        self.globals["xlDialogForecastETS".lower()] = 1300
        self.vb_constants.add("xlDialogForecastETS".lower())
        self.globals["xlDialogFormatAuto".lower()] = 269
        self.vb_constants.add("xlDialogFormatAuto".lower())
        self.globals["xlDialogFormatChart".lower()] = 465
        self.vb_constants.add("xlDialogFormatChart".lower())
        self.globals["xlDialogFormatCharttype".lower()] = 423
        self.vb_constants.add("xlDialogFormatCharttype".lower())
        self.globals["xlDialogFormatFont".lower()] = 150
        self.vb_constants.add("xlDialogFormatFont".lower())
        self.globals["xlDialogFormatLegend".lower()] = 88
        self.vb_constants.add("xlDialogFormatLegend".lower())
        self.globals["xlDialogFormatMain".lower()] = 225
        self.vb_constants.add("xlDialogFormatMain".lower())
        self.globals["xlDialogFormatMove".lower()] = 128
        self.vb_constants.add("xlDialogFormatMove".lower())
        self.globals["xlDialogFormatNumber".lower()] = 42
        self.vb_constants.add("xlDialogFormatNumber".lower())
        self.globals["xlDialogFormatOverlay".lower()] = 226
        self.vb_constants.add("xlDialogFormatOverlay".lower())
        self.globals["xlDialogFormatSize".lower()] = 129
        self.vb_constants.add("xlDialogFormatSize".lower())
        self.globals["xlDialogFormatText".lower()] = 89
        self.vb_constants.add("xlDialogFormatText".lower())
        self.globals["xlDialogFormulaFind".lower()] = 64
        self.vb_constants.add("xlDialogFormulaFind".lower())
        self.globals["xlDialogFormulaGoto".lower()] = 63
        self.vb_constants.add("xlDialogFormulaGoto".lower())
        self.globals["xlDialogFormulaReplace".lower()] = 130
        self.vb_constants.add("xlDialogFormulaReplace".lower())
        self.globals["xlDialogFunctionWizard".lower()] = 450
        self.vb_constants.add("xlDialogFunctionWizard".lower())
        self.globals["xlDialogGallery3dArea".lower()] = 193
        self.vb_constants.add("xlDialogGallery3dArea".lower())
        self.globals["xlDialogGallery3dBar".lower()] = 272
        self.vb_constants.add("xlDialogGallery3dBar".lower())
        self.globals["xlDialogGallery3dColumn".lower()] = 194
        self.vb_constants.add("xlDialogGallery3dColumn".lower())
        self.globals["xlDialogGallery3dLine".lower()] = 195
        self.vb_constants.add("xlDialogGallery3dLine".lower())
        self.globals["xlDialogGallery3dPie".lower()] = 196
        self.vb_constants.add("xlDialogGallery3dPie".lower())
        self.globals["xlDialogGallery3dSurface".lower()] = 273
        self.vb_constants.add("xlDialogGallery3dSurface".lower())
        self.globals["xlDialogGalleryArea".lower()] = 67
        self.vb_constants.add("xlDialogGalleryArea".lower())
        self.globals["xlDialogGalleryBar".lower()] = 68
        self.vb_constants.add("xlDialogGalleryBar".lower())
        self.globals["xlDialogGalleryColumn".lower()] = 69
        self.vb_constants.add("xlDialogGalleryColumn".lower())
        self.globals["xlDialogGalleryCustom".lower()] = 388
        self.vb_constants.add("xlDialogGalleryCustom".lower())
        self.globals["xlDialogGalleryDoughnut".lower()] = 344
        self.vb_constants.add("xlDialogGalleryDoughnut".lower())
        self.globals["xlDialogGalleryLine".lower()] = 70
        self.vb_constants.add("xlDialogGalleryLine".lower())
        self.globals["xlDialogGalleryPie".lower()] = 71
        self.vb_constants.add("xlDialogGalleryPie".lower())
        self.globals["xlDialogGalleryRadar".lower()] = 249
        self.vb_constants.add("xlDialogGalleryRadar".lower())
        self.globals["xlDialogGalleryScatter".lower()] = 72
        self.vb_constants.add("xlDialogGalleryScatter".lower())
        self.globals["xlDialogGoalSeek".lower()] = 198
        self.vb_constants.add("xlDialogGoalSeek".lower())
        self.globals["xlDialogGridlines".lower()] = 76
        self.vb_constants.add("xlDialogGridlines".lower())
        self.globals["xlDialogImportTextFile".lower()] = 666
        self.vb_constants.add("xlDialogImportTextFile".lower())
        self.globals["xlDialogInsert".lower()] = 55
        self.vb_constants.add("xlDialogInsert".lower())
        self.globals["xlDialogInsertHyperlink".lower()] = 596
        self.vb_constants.add("xlDialogInsertHyperlink".lower())
        self.globals["xlDialogInsertNameLabel".lower()] = 496
        self.vb_constants.add("xlDialogInsertNameLabel".lower())
        self.globals["xlDialogInsertObject".lower()] = 259
        self.vb_constants.add("xlDialogInsertObject".lower())
        self.globals["xlDialogInsertPicture".lower()] = 342
        self.vb_constants.add("xlDialogInsertPicture".lower())
        self.globals["xlDialogInsertTitle".lower()] = 380
        self.vb_constants.add("xlDialogInsertTitle".lower())
        self.globals["xlDialogLabelProperties".lower()] = 436
        self.vb_constants.add("xlDialogLabelProperties".lower())
        self.globals["xlDialogListboxProperties".lower()] = 437
        self.vb_constants.add("xlDialogListboxProperties".lower())
        self.globals["xlDialogMacroOptions".lower()] = 382
        self.vb_constants.add("xlDialogMacroOptions".lower())
        self.globals["xlDialogMailEditMailer".lower()] = 470
        self.vb_constants.add("xlDialogMailEditMailer".lower())
        self.globals["xlDialogMailLogon".lower()] = 339
        self.vb_constants.add("xlDialogMailLogon".lower())
        self.globals["xlDialogMailNextLetter".lower()] = 378
        self.vb_constants.add("xlDialogMailNextLetter".lower())
        self.globals["xlDialogMainChart".lower()] = 85
        self.vb_constants.add("xlDialogMainChart".lower())
        self.globals["xlDialogMainChartType".lower()] = 185
        self.vb_constants.add("xlDialogMainChartType".lower())
        self.globals["xlDialogManageRelationships".lower()] = 1271
        self.vb_constants.add("xlDialogManageRelationships".lower())
        self.globals["xlDialogMenuEditor".lower()] = 322
        self.vb_constants.add("xlDialogMenuEditor".lower())
        self.globals["xlDialogMove".lower()] = 262
        self.vb_constants.add("xlDialogMove".lower())
        self.globals["xlDialogMyPermission".lower()] = 834
        self.vb_constants.add("xlDialogMyPermission".lower())
        self.globals["xlDialogNameManager".lower()] = 977
        self.vb_constants.add("xlDialogNameManager".lower())
        self.globals["xlDialogNew".lower()] = 119
        self.vb_constants.add("xlDialogNew".lower())
        self.globals["xlDialogNewName".lower()] = 978
        self.vb_constants.add("xlDialogNewName".lower())
        self.globals["xlDialogNewWebQuery".lower()] = 667
        self.vb_constants.add("xlDialogNewWebQuery".lower())
        self.globals["xlDialogNote".lower()] = 154
        self.vb_constants.add("xlDialogNote".lower())
        self.globals["xlDialogObjectProperties".lower()] = 207
        self.vb_constants.add("xlDialogObjectProperties".lower())
        self.globals["xlDialogObjectProtection".lower()] = 214
        self.vb_constants.add("xlDialogObjectProtection".lower())
        self.globals["xlDialogOpen".lower()] = 1
        self.vb_constants.add("xlDialogOpen".lower())
        self.globals["xlDialogOpenLinks".lower()] = 2
        self.vb_constants.add("xlDialogOpenLinks".lower())
        self.globals["xlDialogOpenMail".lower()] = 188
        self.vb_constants.add("xlDialogOpenMail".lower())
        self.globals["xlDialogOpenText".lower()] = 441
        self.vb_constants.add("xlDialogOpenText".lower())
        self.globals["xlDialogOptionsCalculation".lower()] = 318
        self.vb_constants.add("xlDialogOptionsCalculation".lower())
        self.globals["xlDialogOptionsChart".lower()] = 325
        self.vb_constants.add("xlDialogOptionsChart".lower())
        self.globals["xlDialogOptionsEdit".lower()] = 319
        self.vb_constants.add("xlDialogOptionsEdit".lower())
        self.globals["xlDialogOptionsGeneral".lower()] = 356
        self.vb_constants.add("xlDialogOptionsGeneral".lower())
        self.globals["xlDialogOptionsListsAdd".lower()] = 458
        self.vb_constants.add("xlDialogOptionsListsAdd".lower())
        self.globals["xlDialogOptionsME".lower()] = 647
        self.vb_constants.add("xlDialogOptionsME".lower())
        self.globals["xlDialogOptionsTransition".lower()] = 355
        self.vb_constants.add("xlDialogOptionsTransition".lower())
        self.globals["xlDialogOptionsView".lower()] = 320
        self.vb_constants.add("xlDialogOptionsView".lower())
        self.globals["xlDialogOutline".lower()] = 142
        self.vb_constants.add("xlDialogOutline".lower())
        self.globals["xlDialogOverlay".lower()] = 86
        self.vb_constants.add("xlDialogOverlay".lower())
        self.globals["xlDialogOverlayChartType".lower()] = 186
        self.vb_constants.add("xlDialogOverlayChartType".lower())
        self.globals["xlDialogPageSetup".lower()] = 7
        self.vb_constants.add("xlDialogPageSetup".lower())
        self.globals["xlDialogParse".lower()] = 91
        self.vb_constants.add("xlDialogParse".lower())
        self.globals["xlDialogPasteNames".lower()] = 58
        self.vb_constants.add("xlDialogPasteNames".lower())
        self.globals["xlDialogPasteSpecial".lower()] = 53
        self.vb_constants.add("xlDialogPasteSpecial".lower())
        self.globals["xlDialogPatterns".lower()] = 84
        self.vb_constants.add("xlDialogPatterns".lower())
        self.globals["xlDialogPermission".lower()] = 832
        self.vb_constants.add("xlDialogPermission".lower())
        self.globals["xlDialogPhonetic".lower()] = 656
        self.vb_constants.add("xlDialogPhonetic".lower())
        self.globals["xlDialogPivotCalculatedField".lower()] = 570
        self.vb_constants.add("xlDialogPivotCalculatedField".lower())
        self.globals["xlDialogPivotCalculatedItem".lower()] = 572
        self.vb_constants.add("xlDialogPivotCalculatedItem".lower())
        self.globals["xlDialogPivotClientServerSet".lower()] = 689
        self.vb_constants.add("xlDialogPivotClientServerSet".lower())
        self.globals["xlDialogPivotDefaultLayout".lower()] = 1360
        self.vb_constants.add("xlDialogPivotDefaultLayout".lower())
        self.globals["xlDialogPivotFieldGroup".lower()] = 433
        self.vb_constants.add("xlDialogPivotFieldGroup".lower())
        self.globals["xlDialogPivotFieldProperties".lower()] = 313
        self.vb_constants.add("xlDialogPivotFieldProperties".lower())
        self.globals["xlDialogPivotFieldUngroup".lower()] = 434
        self.vb_constants.add("xlDialogPivotFieldUngroup".lower())
        self.globals["xlDialogPivotShowPages".lower()] = 421
        self.vb_constants.add("xlDialogPivotShowPages".lower())
        self.globals["xlDialogPivotSolveOrder".lower()] = 568
        self.vb_constants.add("xlDialogPivotSolveOrder".lower())
        self.globals["xlDialogPivotTableOptions".lower()] = 567
        self.vb_constants.add("xlDialogPivotTableOptions".lower())
        self.globals["xlDialogPivotTableSlicerConnections".lower()] = 1183
        self.vb_constants.add("xlDialogPivotTableSlicerConnections".lower())
        self.globals["xlDialogPivotTableWhatIfAnalysisSettings".lower()] = 1153
        self.vb_constants.add("xlDialogPivotTableWhatIfAnalysisSettings".lower())
        self.globals["xlDialogPivotTableWizard".lower()] = 312
        self.vb_constants.add("xlDialogPivotTableWizard".lower())
        self.globals["xlDialogPlacement".lower()] = 300
        self.vb_constants.add("xlDialogPlacement".lower())
        self.globals["xlDialogPrint".lower()] = 8
        self.vb_constants.add("xlDialogPrint".lower())
        self.globals["xlDialogPrinterSetup".lower()] = 9
        self.vb_constants.add("xlDialogPrinterSetup".lower())
        self.globals["xlDialogPrintPreview".lower()] = 222
        self.vb_constants.add("xlDialogPrintPreview".lower())
        self.globals["xlDialogPromote".lower()] = 202
        self.vb_constants.add("xlDialogPromote".lower())
        self.globals["xlDialogProperties".lower()] = 474
        self.vb_constants.add("xlDialogProperties".lower())
        self.globals["xlDialogPropertyFields".lower()] = 754
        self.vb_constants.add("xlDialogPropertyFields".lower())
        self.globals["xlDialogProtectDocument".lower()] = 28
        self.vb_constants.add("xlDialogProtectDocument".lower())
        self.globals["xlDialogProtectSharing".lower()] = 620
        self.vb_constants.add("xlDialogProtectSharing".lower())
        self.globals["xlDialogPublishAsWebPage".lower()] = 653
        self.vb_constants.add("xlDialogPublishAsWebPage".lower())
        self.globals["xlDialogPushbuttonProperties".lower()] = 445
        self.vb_constants.add("xlDialogPushbuttonProperties".lower())
        self.globals["xlDialogRecommendedPivotTables".lower()] = 1258
        self.vb_constants.add("xlDialogRecommendedPivotTables".lower())
        self.globals["xlDialogReplaceFont".lower()] = 134
        self.vb_constants.add("xlDialogReplaceFont".lower())
        self.globals["xlDialogRoutingSlip".lower()] = 336
        self.vb_constants.add("xlDialogRoutingSlip".lower())
        self.globals["xlDialogRowHeight".lower()] = 127
        self.vb_constants.add("xlDialogRowHeight".lower())
        self.globals["xlDialogRun".lower()] = 17
        self.vb_constants.add("xlDialogRun".lower())
        self.globals["xlDialogSaveAs".lower()] = 5
        self.vb_constants.add("xlDialogSaveAs".lower())
        self.globals["xlDialogSaveCopyAs".lower()] = 456
        self.vb_constants.add("xlDialogSaveCopyAs".lower())
        self.globals["xlDialogSaveNewObject".lower()] = 208
        self.vb_constants.add("xlDialogSaveNewObject".lower())
        self.globals["xlDialogSaveWorkbook".lower()] = 145
        self.vb_constants.add("xlDialogSaveWorkbook".lower())
        self.globals["xlDialogSaveWorkspace".lower()] = 285
        self.vb_constants.add("xlDialogSaveWorkspace".lower())
        self.globals["xlDialogScale".lower()] = 87
        self.vb_constants.add("xlDialogScale".lower())
        self.globals["xlDialogScenarioAdd".lower()] = 307
        self.vb_constants.add("xlDialogScenarioAdd".lower())
        self.globals["xlDialogScenarioCells".lower()] = 305
        self.vb_constants.add("xlDialogScenarioCells".lower())
        self.globals["xlDialogScenarioEdit".lower()] = 308
        self.vb_constants.add("xlDialogScenarioEdit".lower())
        self.globals["xlDialogScenarioMerge".lower()] = 473
        self.vb_constants.add("xlDialogScenarioMerge".lower())
        self.globals["xlDialogScenarioSummary".lower()] = 311
        self.vb_constants.add("xlDialogScenarioSummary".lower())
        self.globals["xlDialogScrollbarProperties".lower()] = 420
        self.vb_constants.add("xlDialogScrollbarProperties".lower())
        self.globals["xlDialogSearch".lower()] = 731
        self.vb_constants.add("xlDialogSearch".lower())
        self.globals["xlDialogSelectSpecial".lower()] = 132
        self.vb_constants.add("xlDialogSelectSpecial".lower())
        self.globals["xlDialogSendMail".lower()] = 189
        self.vb_constants.add("xlDialogSendMail".lower())
        self.globals["xlDialogSeriesAxes".lower()] = 460
        self.vb_constants.add("xlDialogSeriesAxes".lower())
        self.globals["xlDialogSeriesOptions".lower()] = 557
        self.vb_constants.add("xlDialogSeriesOptions".lower())
        self.globals["xlDialogSeriesOrder".lower()] = 466
        self.vb_constants.add("xlDialogSeriesOrder".lower())
        self.globals["xlDialogSeriesShape".lower()] = 504
        self.vb_constants.add("xlDialogSeriesShape".lower())
        self.globals["xlDialogSeriesX".lower()] = 461
        self.vb_constants.add("xlDialogSeriesX".lower())
        self.globals["xlDialogSeriesY".lower()] = 462
        self.vb_constants.add("xlDialogSeriesY".lower())
        self.globals["xlDialogSetBackgroundPicture".lower()] = 509
        self.vb_constants.add("xlDialogSetBackgroundPicture".lower())
        self.globals["xlDialogSetManager".lower()] = 1109
        self.vb_constants.add("xlDialogSetManager".lower())
        self.globals["xlDialogSetMDXEditor".lower()] = 1208
        self.vb_constants.add("xlDialogSetMDXEditor".lower())
        self.globals["xlDialogSetPrintTitles".lower()] = 23
        self.vb_constants.add("xlDialogSetPrintTitles".lower())
        self.globals["xlDialogSetTupleEditorOnColumns".lower()] = 1108
        self.vb_constants.add("xlDialogSetTupleEditorOnColumns".lower())
        self.globals["xlDialogSetTupleEditorOnRows".lower()] = 1107
        self.vb_constants.add("xlDialogSetTupleEditorOnRows".lower())
        self.globals["xlDialogSetUpdateStatus".lower()] = 159
        self.vb_constants.add("xlDialogSetUpdateStatus".lower())
        self.globals["xlDialogSheet".lower()] = 4116
        self.vb_constants.add("xlDialogSheet".lower())
        self.globals["xlDialogShowDetail".lower()] = 204
        self.vb_constants.add("xlDialogShowDetail".lower())
        self.globals["xlDialogShowToolbar".lower()] = 220
        self.vb_constants.add("xlDialogShowToolbar".lower())
        self.globals["xlDialogSize".lower()] = 261
        self.vb_constants.add("xlDialogSize".lower())
        self.globals["xlDialogSlicerCreation".lower()] = 1182
        self.vb_constants.add("xlDialogSlicerCreation".lower())
        self.globals["xlDialogSlicerPivotTableConnections".lower()] = 1184
        self.vb_constants.add("xlDialogSlicerPivotTableConnections".lower())
        self.globals["xlDialogSlicerSettings".lower()] = 1179
        self.vb_constants.add("xlDialogSlicerSettings".lower())
        self.globals["xlDialogSort".lower()] = 39
        self.vb_constants.add("xlDialogSort".lower())
        self.globals["xlDialogSortSpecial".lower()] = 192
        self.vb_constants.add("xlDialogSortSpecial".lower())
        self.globals["xlDialogSparklineInsertColumn".lower()] = 1134
        self.vb_constants.add("xlDialogSparklineInsertColumn".lower())
        self.globals["xlDialogSparklineInsertLine".lower()] = 1133
        self.vb_constants.add("xlDialogSparklineInsertLine".lower())
        self.globals["xlDialogSparklineInsertWinLoss".lower()] = 1135
        self.vb_constants.add("xlDialogSparklineInsertWinLoss".lower())
        self.globals["xlDialogSplit".lower()] = 137
        self.vb_constants.add("xlDialogSplit".lower())
        self.globals["xlDialogStandardFont".lower()] = 190
        self.vb_constants.add("xlDialogStandardFont".lower())
        self.globals["xlDialogStandardWidth".lower()] = 472
        self.vb_constants.add("xlDialogStandardWidth".lower())
        self.globals["xlDialogStyle".lower()] = 44
        self.vb_constants.add("xlDialogStyle".lower())
        self.globals["xlDialogSubscribeTo".lower()] = 218
        self.vb_constants.add("xlDialogSubscribeTo".lower())
        self.globals["xlDialogSubtotalCreate".lower()] = 398
        self.vb_constants.add("xlDialogSubtotalCreate".lower())
        self.globals["xlDialogSummaryInfo".lower()] = 474
        self.vb_constants.add("xlDialogSummaryInfo".lower())
        self.globals["xlDialogTable".lower()] = 41
        self.vb_constants.add("xlDialogTable".lower())
        self.globals["xlDialogTabOrder".lower()] = 394
        self.vb_constants.add("xlDialogTabOrder".lower())
        self.globals["xlDialogTextToColumns".lower()] = 422
        self.vb_constants.add("xlDialogTextToColumns".lower())
        self.globals["xlDialogUnhide".lower()] = 94
        self.vb_constants.add("xlDialogUnhide".lower())
        self.globals["xlDialogUpdateLink".lower()] = 201
        self.vb_constants.add("xlDialogUpdateLink".lower())
        self.globals["xlDialogVbaInsertFile".lower()] = 328
        self.vb_constants.add("xlDialogVbaInsertFile".lower())
        self.globals["xlDialogVbaMakeAddin".lower()] = 478
        self.vb_constants.add("xlDialogVbaMakeAddin".lower())
        self.globals["xlDialogVbaProcedureDefinition".lower()] = 330
        self.vb_constants.add("xlDialogVbaProcedureDefinition".lower())
        self.globals["xlDialogView3d".lower()] = 197
        self.vb_constants.add("xlDialogView3d".lower())
        self.globals["xlDialogWebOptionsBrowsers".lower()] = 773
        self.vb_constants.add("xlDialogWebOptionsBrowsers".lower())
        self.globals["xlDialogWebOptionsEncoding".lower()] = 686
        self.vb_constants.add("xlDialogWebOptionsEncoding".lower())
        self.globals["xlDialogWebOptionsFiles".lower()] = 684
        self.vb_constants.add("xlDialogWebOptionsFiles".lower())
        self.globals["xlDialogWebOptionsFonts".lower()] = 687
        self.vb_constants.add("xlDialogWebOptionsFonts".lower())
        self.globals["xlDialogWebOptionsGeneral".lower()] = 683
        self.vb_constants.add("xlDialogWebOptionsGeneral".lower())
        self.globals["xlDialogWebOptionsPictures".lower()] = 685
        self.vb_constants.add("xlDialogWebOptionsPictures".lower())
        self.globals["xlDialogWindowMove".lower()] = 14
        self.vb_constants.add("xlDialogWindowMove".lower())
        self.globals["xlDialogWindowSize".lower()] = 13
        self.vb_constants.add("xlDialogWindowSize".lower())
        self.globals["xlDialogWorkbookAdd".lower()] = 281
        self.vb_constants.add("xlDialogWorkbookAdd".lower())
        self.globals["xlDialogWorkbookCopy".lower()] = 283
        self.vb_constants.add("xlDialogWorkbookCopy".lower())
        self.globals["xlDialogWorkbookInsert".lower()] = 354
        self.vb_constants.add("xlDialogWorkbookInsert".lower())
        self.globals["xlDialogWorkbookMove".lower()] = 282
        self.vb_constants.add("xlDialogWorkbookMove".lower())
        self.globals["xlDialogWorkbookName".lower()] = 386
        self.vb_constants.add("xlDialogWorkbookName".lower())
        self.globals["xlDialogWorkbookNew".lower()] = 302
        self.vb_constants.add("xlDialogWorkbookNew".lower())
        self.globals["xlDialogWorkbookOptions".lower()] = 284
        self.vb_constants.add("xlDialogWorkbookOptions".lower())
        self.globals["xlDialogWorkbookProtect".lower()] = 417
        self.vb_constants.add("xlDialogWorkbookProtect".lower())
        self.globals["xlDialogWorkbookTabSplit".lower()] = 415
        self.vb_constants.add("xlDialogWorkbookTabSplit".lower())
        self.globals["xlDialogWorkbookUnhide".lower()] = 384
        self.vb_constants.add("xlDialogWorkbookUnhide".lower())
        self.globals["xlDialogWorkgroup".lower()] = 199
        self.vb_constants.add("xlDialogWorkgroup".lower())
        self.globals["xlDialogWorkspace".lower()] = 95
        self.vb_constants.add("xlDialogWorkspace".lower())
        self.globals["xlDialogZoom".lower()] = 256
        self.vb_constants.add("xlDialogZoom".lower())
        self.globals["xlDiamond".lower()] = 2
        self.vb_constants.add("xlDiamond".lower())
        self.globals["xlDIF".lower()] = 9
        self.vb_constants.add("xlDIF".lower())
        self.globals["xlDifferenceFrom".lower()] = 2
        self.vb_constants.add("xlDifferenceFrom".lower())
        self.globals["xlDirect".lower()] = 1
        self.vb_constants.add("xlDirect".lower())
        self.globals["xlDisabled".lower()] = 0
        self.vb_constants.add("xlDisabled".lower())
        self.globals["xlDisplayNone".lower()] = 1
        self.vb_constants.add("xlDisplayNone".lower())
        self.globals["xlDisplayPropertyInPivotTable".lower()] = 1
        self.vb_constants.add("xlDisplayPropertyInPivotTable".lower())
        self.globals["xlDisplayPropertyInPivotTableAndTooltip".lower()] = 3
        self.vb_constants.add("xlDisplayPropertyInPivotTableAndTooltip".lower())
        self.globals["xlDisplayPropertyInTooltip".lower()] = 2
        self.vb_constants.add("xlDisplayPropertyInTooltip".lower())
        self.globals["xlDisplayShapes".lower()] = 4104
        self.vb_constants.add("xlDisplayShapes".lower())
        self.globals["xlDisplayUnitLabel".lower()] = 30
        self.vb_constants.add("xlDisplayUnitLabel".lower())
        self.globals["xlDistinctCount".lower()] = 11
        self.vb_constants.add("xlDistinctCount".lower())
        self.globals["xlDistributed".lower()] = 4117
        self.vb_constants.add("xlDistributed".lower())
        self.globals["xlDivide".lower()] = 5
        self.vb_constants.add("xlDivide".lower())
        self.globals["xlDMYFormat".lower()] = 4
        self.vb_constants.add("xlDMYFormat".lower())
        self.globals["xlDoesNotContain".lower()] = 1
        self.vb_constants.add("xlDoesNotContain".lower())
        self.globals["xlDone".lower()] = 0
        self.vb_constants.add("xlDone".lower())
        self.globals["xlDoNotRepeatLabels".lower()] = 1
        self.vb_constants.add("xlDoNotRepeatLabels".lower())
        self.globals["xlDoNotSaveChanges".lower()] = 2
        self.vb_constants.add("xlDoNotSaveChanges".lower())
        self.globals["xlDot".lower()] = 4118
        self.vb_constants.add("xlDot".lower())
        self.globals["xlDouble".lower()] = 4119
        self.vb_constants.add("xlDouble".lower())
        self.globals["xlDoubleAccounting".lower()] = 5
        self.vb_constants.add("xlDoubleAccounting".lower())
        self.globals["xlDoubleClosed".lower()] = 5
        self.vb_constants.add("xlDoubleClosed".lower())
        self.globals["xlDoubleOpen".lower()] = 4
        self.vb_constants.add("xlDoubleOpen".lower())
        self.globals["xlDoubleQuote".lower()] = 1
        self.vb_constants.add("xlDoubleQuote".lower())
        self.globals["xlDoughnut".lower()] = 4120
        self.vb_constants.add("xlDoughnut".lower())
        self.globals["xlDoughnutExploded".lower()] = 80
        self.vb_constants.add("xlDoughnutExploded".lower())
        self.globals["xlDown".lower()] = 4121
        self.vb_constants.add("xlDown".lower())
        self.globals["xlDownBars".lower()] = 20
        self.vb_constants.add("xlDownBars".lower())
        self.globals["xlDownThenOver".lower()] = 1
        self.vb_constants.add("xlDownThenOver".lower())
        self.globals["xlDownward".lower()] = 4170
        self.vb_constants.add("xlDownward".lower())
        self.globals["xlDrawingObject".lower()] = 14
        self.vb_constants.add("xlDrawingObject".lower())
        self.globals["xlDropDown".lower()] = 2
        self.vb_constants.add("xlDropDown".lower())
        self.globals["xlDropLines".lower()] = 26
        self.vb_constants.add("xlDropLines".lower())
        self.globals["xlDRW".lower()] = 4
        self.vb_constants.add("xlDRW".lower())
        self.globals["xlDuplicate".lower()] = 1
        self.vb_constants.add("xlDuplicate".lower())
        self.globals["xlDXF".lower()] = 5
        self.vb_constants.add("xlDXF".lower())
        self.globals["xlDYMFormat".lower()] = 7
        self.vb_constants.add("xlDYMFormat".lower())
        self.globals["xlEdgeBottom".lower()] = 9
        self.vb_constants.add("xlEdgeBottom".lower())
        self.globals["xlEdgeLeft".lower()] = 7
        self.vb_constants.add("xlEdgeLeft".lower())
        self.globals["xlEdgeRight".lower()] = 10
        self.vb_constants.add("xlEdgeRight".lower())
        self.globals["xlEdgeTop".lower()] = 8
        self.vb_constants.add("xlEdgeTop".lower())
        self.globals["xlEditBox".lower()] = 3
        self.vb_constants.add("xlEditBox".lower())
        self.globals["xlEditionDate".lower()] = 2
        self.vb_constants.add("xlEditionDate".lower())
        self.globals["xlEMDFormat".lower()] = 10
        self.vb_constants.add("xlEMDFormat".lower())
        self.globals["xlEmptyCellReferences".lower()] = 7
        self.vb_constants.add("xlEmptyCellReferences".lower())
        self.globals["xlEnd".lower()] = 2
        self.vb_constants.add("xlEnd".lower())
        self.globals["xlEndSides".lower()] = 3
        self.vb_constants.add("xlEndSides".lower())
        self.globals["xlEndsWith".lower()] = 3
        self.vb_constants.add("xlEndsWith".lower())
        self.globals["xlEntireChart".lower()] = 20
        self.vb_constants.add("xlEntireChart".lower())
        self.globals["xlEntirePage".lower()] = 1
        self.vb_constants.add("xlEntirePage".lower())
        self.globals["xlEPS".lower()] = 8
        self.vb_constants.add("xlEPS".lower())
        self.globals["xlEqual".lower()] = 3
        self.vb_constants.add("xlEqual".lower())
        self.globals["xlEqualAboveAverage".lower()] = 2
        self.vb_constants.add("xlEqualAboveAverage".lower())
        self.globals["xlEqualAllocation".lower()] = 1
        self.vb_constants.add("xlEqualAllocation".lower())
        self.globals["xlEqualBelowAverage".lower()] = 3
        self.vb_constants.add("xlEqualBelowAverage".lower())
        self.globals["xlErrBlocked".lower()] = 2047
        self.vb_constants.add("xlErrBlocked".lower())
        self.globals["xlErrCalc".lower()] = 2050
        self.vb_constants.add("xlErrCalc".lower())
        self.globals["xlErrConnect".lower()] = 2046
        self.vb_constants.add("xlErrConnect".lower())
        self.globals["xlErrDiv0".lower()] = 2007
        self.vb_constants.add("xlErrDiv0".lower())
        self.globals["xlErrField".lower()] = 2049
        self.vb_constants.add("xlErrField".lower())
        self.globals["xlErrGettingData".lower()] = 2043
        self.vb_constants.add("xlErrGettingData".lower())
        self.globals["xlErrNA".lower()] = 2042
        self.vb_constants.add("xlErrNA".lower())
        self.globals["xlErrName".lower()] = 2029
        self.vb_constants.add("xlErrName".lower())
        self.globals["xlErrNull".lower()] = 2000
        self.vb_constants.add("xlErrNull".lower())
        self.globals["xlErrNum".lower()] = 2036
        self.vb_constants.add("xlErrNum".lower())
        self.globals["xlErrorBarIncludeBoth".lower()] = 1
        self.vb_constants.add("xlErrorBarIncludeBoth".lower())
        self.globals["xlErrorBarIncludeMinusValues".lower()] = 3
        self.vb_constants.add("xlErrorBarIncludeMinusValues".lower())
        self.globals["xlErrorBarIncludeNone".lower()] = 4142
        self.vb_constants.add("xlErrorBarIncludeNone".lower())
        self.globals["xlErrorBarIncludePlusValues".lower()] = 2
        self.vb_constants.add("xlErrorBarIncludePlusValues".lower())
        self.globals["xlErrorBars".lower()] = 9
        self.vb_constants.add("xlErrorBars".lower())
        self.globals["xlErrorBarTypeCustom".lower()] = 4114
        self.vb_constants.add("xlErrorBarTypeCustom".lower())
        self.globals["xlErrorBarTypeFixedValue".lower()] = 1
        self.vb_constants.add("xlErrorBarTypeFixedValue".lower())
        self.globals["xlErrorBarTypePercent".lower()] = 2
        self.vb_constants.add("xlErrorBarTypePercent".lower())
        self.globals["xlErrorBarTypeStDev".lower()] = 4155
        self.vb_constants.add("xlErrorBarTypeStDev".lower())
        self.globals["xlErrorBarTypeStError".lower()] = 4
        self.vb_constants.add("xlErrorBarTypeStError".lower())
        self.globals["xlErrorHandler".lower()] = 2
        self.vb_constants.add("xlErrorHandler".lower())
        self.globals["xlErrors".lower()] = 16
        self.vb_constants.add("xlErrors".lower())
        self.globals["xlErrorsCondition".lower()] = 16
        self.vb_constants.add("xlErrorsCondition".lower())
        self.globals["xlErrRef".lower()] = 2023
        self.vb_constants.add("xlErrRef".lower())
        self.globals["xlErrSpill".lower()] = 2045
        self.vb_constants.add("xlErrSpill".lower())
        self.globals["xlErrUnknown".lower()] = 2048
        self.vb_constants.add("xlErrUnknown".lower())
        self.globals["xlErrValue".lower()] = 2015
        self.vb_constants.add("xlErrValue".lower())
        self.globals["xlEscKey".lower()] = 1
        self.vb_constants.add("xlEscKey".lower())
        self.globals["xlEvaluateToError".lower()] = 1
        self.vb_constants.add("xlEvaluateToError".lower())
        self.globals["xlExcel12".lower()] = 50
        self.vb_constants.add("xlExcel12".lower())
        self.globals["xlExcel2".lower()] = 16
        self.vb_constants.add("xlExcel2".lower())
        self.globals["xlExcel2FarEast".lower()] = 27
        self.vb_constants.add("xlExcel2FarEast".lower())
        self.globals["xlExcel3".lower()] = 29
        self.vb_constants.add("xlExcel3".lower())
        self.globals["xlExcel4".lower()] = 33
        self.vb_constants.add("xlExcel4".lower())
        self.globals["xlExcel4IntlMacroSheet".lower()] = 4
        self.vb_constants.add("xlExcel4IntlMacroSheet".lower())
        self.globals["xlExcel4MacroSheet".lower()] = 3
        self.vb_constants.add("xlExcel4MacroSheet".lower())
        self.globals["xlExcel4Workbook".lower()] = 35
        self.vb_constants.add("xlExcel4Workbook".lower())
        self.globals["xlExcel5".lower()] = 39
        self.vb_constants.add("xlExcel5".lower())
        self.globals["xlExcel7".lower()] = 39
        self.vb_constants.add("xlExcel7".lower())
        self.globals["xlExcel8".lower()] = 56
        self.vb_constants.add("xlExcel8".lower())
        self.globals["xlExcel9795".lower()] = 43
        self.vb_constants.add("xlExcel9795".lower())
        self.globals["xlExcelLinks".lower()] = 1
        self.vb_constants.add("xlExcelLinks".lower())
        self.globals["xlExcelMenus".lower()] = 1
        self.vb_constants.add("xlExcelMenus".lower())
        self.globals["xlExclusive".lower()] = 3
        self.vb_constants.add("xlExclusive".lower())
        self.globals["xlExponential".lower()] = 5
        self.vb_constants.add("xlExponential".lower())
        self.globals["xlExpression".lower()] = 2
        self.vb_constants.add("xlExpression".lower())
        self.globals["xlExtended".lower()] = 3
        self.vb_constants.add("xlExtended".lower())
        self.globals["xlExternal".lower()] = 2
        self.vb_constants.add("xlExternal".lower())
        self.globals["xlExtractData".lower()] = 2
        self.vb_constants.add("xlExtractData".lower())
        self.globals["xlFieldsScope".lower()] = 1
        self.vb_constants.add("xlFieldsScope".lower())
        self.globals["xlFileValidationPivotDefault".lower()] = 0
        self.vb_constants.add("xlFileValidationPivotDefault".lower())
        self.globals["xlFileValidationPivotRun".lower()] = 1
        self.vb_constants.add("xlFileValidationPivotRun".lower())
        self.globals["xlFileValidationPivotSkip".lower()] = 2
        self.vb_constants.add("xlFileValidationPivotSkip".lower())
        self.globals["xlFill".lower()] = 5
        self.vb_constants.add("xlFill".lower())
        self.globals["xlFillCopy".lower()] = 1
        self.vb_constants.add("xlFillCopy".lower())
        self.globals["xlFillDays".lower()] = 5
        self.vb_constants.add("xlFillDays".lower())
        self.globals["xlFillDefault".lower()] = 0
        self.vb_constants.add("xlFillDefault".lower())
        self.globals["xlFillFormats".lower()] = 3
        self.vb_constants.add("xlFillFormats".lower())
        self.globals["xlFillMonths".lower()] = 7
        self.vb_constants.add("xlFillMonths".lower())
        self.globals["xlFillSeries".lower()] = 2
        self.vb_constants.add("xlFillSeries".lower())
        self.globals["xlFillValues".lower()] = 4
        self.vb_constants.add("xlFillValues".lower())
        self.globals["xlFillWeekdays".lower()] = 6
        self.vb_constants.add("xlFillWeekdays".lower())
        self.globals["xlFillWithAll".lower()] = 4104
        self.vb_constants.add("xlFillWithAll".lower())
        self.globals["xlFillWithContents".lower()] = 2
        self.vb_constants.add("xlFillWithContents".lower())
        self.globals["xlFillWithFormats".lower()] = 4122
        self.vb_constants.add("xlFillWithFormats".lower())
        self.globals["xlFillYears".lower()] = 8
        self.vb_constants.add("xlFillYears".lower())
        self.globals["xlFilterAboveAverage".lower()] = 33
        self.vb_constants.add("xlFilterAboveAverage".lower())
        self.globals["xlFilterAllDatesInPeriodApril".lower()] = 24
        self.vb_constants.add("xlFilterAllDatesInPeriodApril".lower())
        self.globals["xlFilterAllDatesInPeriodAugust".lower()] = 28
        self.vb_constants.add("xlFilterAllDatesInPeriodAugust".lower())
        self.globals["xlFilterAllDatesInPeriodDay".lower()] = 2
        self.vb_constants.add("xlFilterAllDatesInPeriodDay".lower())
        self.globals["xlFilterAllDatesInPeriodDecember".lower()] = 32
        self.vb_constants.add("xlFilterAllDatesInPeriodDecember".lower())
        self.globals["xlFilterAllDatesInPeriodFebruray".lower()] = 22
        self.vb_constants.add("xlFilterAllDatesInPeriodFebruray".lower())
        self.globals["xlFilterAllDatesInPeriodHour".lower()] = 3
        self.vb_constants.add("xlFilterAllDatesInPeriodHour".lower())
        self.globals["xlFilterAllDatesInPeriodJanuary".lower()] = 21
        self.vb_constants.add("xlFilterAllDatesInPeriodJanuary".lower())
        self.globals["xlFilterAllDatesInPeriodJuly".lower()] = 27
        self.vb_constants.add("xlFilterAllDatesInPeriodJuly".lower())
        self.globals["xlFilterAllDatesInPeriodJune".lower()] = 26
        self.vb_constants.add("xlFilterAllDatesInPeriodJune".lower())
        self.globals["xlFilterAllDatesInPeriodMarch".lower()] = 23
        self.vb_constants.add("xlFilterAllDatesInPeriodMarch".lower())
        self.globals["xlFilterAllDatesInPeriodMay".lower()] = 25
        self.vb_constants.add("xlFilterAllDatesInPeriodMay".lower())
        self.globals["xlFilterAllDatesInPeriodMinute".lower()] = 4
        self.vb_constants.add("xlFilterAllDatesInPeriodMinute".lower())
        self.globals["xlFilterAllDatesInPeriodMonth".lower()] = 1
        self.vb_constants.add("xlFilterAllDatesInPeriodMonth".lower())
        self.globals["xlFilterAllDatesInPeriodNovember".lower()] = 31
        self.vb_constants.add("xlFilterAllDatesInPeriodNovember".lower())
        self.globals["xlFilterAllDatesInPeriodOctober".lower()] = 30
        self.vb_constants.add("xlFilterAllDatesInPeriodOctober".lower())
        self.globals["xlFilterAllDatesInPeriodQuarter1".lower()] = 17
        self.vb_constants.add("xlFilterAllDatesInPeriodQuarter1".lower())
        self.globals["xlFilterAllDatesInPeriodQuarter2".lower()] = 18
        self.vb_constants.add("xlFilterAllDatesInPeriodQuarter2".lower())
        self.globals["xlFilterAllDatesInPeriodQuarter3".lower()] = 19
        self.vb_constants.add("xlFilterAllDatesInPeriodQuarter3".lower())
        self.globals["xlFilterAllDatesInPeriodQuarter4".lower()] = 20
        self.vb_constants.add("xlFilterAllDatesInPeriodQuarter4".lower())
        self.globals["xlFilterAllDatesInPeriodSecond".lower()] = 5
        self.vb_constants.add("xlFilterAllDatesInPeriodSecond".lower())
        self.globals["xlFilterAllDatesInPeriodSeptember".lower()] = 29
        self.vb_constants.add("xlFilterAllDatesInPeriodSeptember".lower())
        self.globals["xlFilterAllDatesInPeriodYear".lower()] = 0
        self.vb_constants.add("xlFilterAllDatesInPeriodYear".lower())
        self.globals["xlFilterAutomaticFontColor".lower()] = 13
        self.vb_constants.add("xlFilterAutomaticFontColor".lower())
        self.globals["xlFilterBelowAverage".lower()] = 34
        self.vb_constants.add("xlFilterBelowAverage".lower())
        self.globals["xlFilterBottom".lower()] = 0
        self.vb_constants.add("xlFilterBottom".lower())
        self.globals["xlFilterBottomPercent".lower()] = 2
        self.vb_constants.add("xlFilterBottomPercent".lower())
        self.globals["xlFilterCellColor".lower()] = 8
        self.vb_constants.add("xlFilterCellColor".lower())
        self.globals["xlFilterCopy".lower()] = 2
        self.vb_constants.add("xlFilterCopy".lower())
        self.globals["xlFilterDynamic".lower()] = 11
        self.vb_constants.add("xlFilterDynamic".lower())
        self.globals["xlFilterFontColor".lower()] = 9
        self.vb_constants.add("xlFilterFontColor".lower())
        self.globals["xlFilterIcon".lower()] = 10
        self.vb_constants.add("xlFilterIcon".lower())
        self.globals["xlFilterInPlace".lower()] = 1
        self.vb_constants.add("xlFilterInPlace".lower())
        self.globals["xlFilterLastMonth".lower()] = 8
        self.vb_constants.add("xlFilterLastMonth".lower())
        self.globals["xlFilterLastQuarter".lower()] = 11
        self.vb_constants.add("xlFilterLastQuarter".lower())
        self.globals["xlFilterLastWeek".lower()] = 5
        self.vb_constants.add("xlFilterLastWeek".lower())
        self.globals["xlFilterLastYear".lower()] = 14
        self.vb_constants.add("xlFilterLastYear".lower())
        self.globals["xlFilterNextMonth".lower()] = 9
        self.vb_constants.add("xlFilterNextMonth".lower())
        self.globals["xlFilterNextQuarter".lower()] = 12
        self.vb_constants.add("xlFilterNextQuarter".lower())
        self.globals["xlFilterNextWeek".lower()] = 6
        self.vb_constants.add("xlFilterNextWeek".lower())
        self.globals["xlFilterNextYear".lower()] = 15
        self.vb_constants.add("xlFilterNextYear".lower())
        self.globals["xlFilterNoFill".lower()] = 12
        self.vb_constants.add("xlFilterNoFill".lower())
        self.globals["xlFilterNoIcon".lower()] = 14
        self.vb_constants.add("xlFilterNoIcon".lower())
        self.globals["xlFilterStatusDateHasTime".lower()] = 2
        self.vb_constants.add("xlFilterStatusDateHasTime".lower())
        self.globals["xlFilterStatusDateWrongOrder".lower()] = 1
        self.vb_constants.add("xlFilterStatusDateWrongOrder".lower())
        self.globals["xlFilterStatusInvalidDate".lower()] = 3
        self.vb_constants.add("xlFilterStatusInvalidDate".lower())
        self.globals["xlFilterStatusOK".lower()] = 0
        self.vb_constants.add("xlFilterStatusOK".lower())
        self.globals["xlFilterThisMonth".lower()] = 7
        self.vb_constants.add("xlFilterThisMonth".lower())
        self.globals["xlFilterThisQuarter".lower()] = 10
        self.vb_constants.add("xlFilterThisQuarter".lower())
        self.globals["xlFilterThisWeek".lower()] = 4
        self.vb_constants.add("xlFilterThisWeek".lower())
        self.globals["xlFilterThisYear".lower()] = 13
        self.vb_constants.add("xlFilterThisYear".lower())
        self.globals["xlFilterToday".lower()] = 1
        self.vb_constants.add("xlFilterToday".lower())
        self.globals["xlFilterTomorrow".lower()] = 3
        self.vb_constants.add("xlFilterTomorrow".lower())
        self.globals["xlFilterTop".lower()] = 1
        self.vb_constants.add("xlFilterTop".lower())
        self.globals["xlFilterTopPercent".lower()] = 3
        self.vb_constants.add("xlFilterTopPercent".lower())
        self.globals["xlFilterValues".lower()] = 7
        self.vb_constants.add("xlFilterValues".lower())
        self.globals["xlFilterYearToDate".lower()] = 16
        self.vb_constants.add("xlFilterYearToDate".lower())
        self.globals["xlFilterYesterday".lower()] = 2
        self.vb_constants.add("xlFilterYesterday".lower())
        self.globals["xlFirst".lower()] = 0
        self.vb_constants.add("xlFirst".lower())
        self.globals["xlFirstColumn".lower()] = 3
        self.vb_constants.add("xlFirstColumn".lower())
        self.globals["xlFirstHeaderCell".lower()] = 9
        self.vb_constants.add("xlFirstHeaderCell".lower())
        self.globals["xlFirstRow".lower()] = 256
        self.vb_constants.add("xlFirstRow".lower())
        self.globals["xlFirstTotalCell".lower()] = 11
        self.vb_constants.add("xlFirstTotalCell".lower())
        self.globals["xlFitToPage".lower()] = 2
        self.vb_constants.add("xlFitToPage".lower())
        self.globals["xlFixedValue".lower()] = 1
        self.vb_constants.add("xlFixedValue".lower())
        self.globals["xlFixedWidth".lower()] = 2
        self.vb_constants.add("xlFixedWidth".lower())
        self.globals["xlFlashFill".lower()] = 11
        self.vb_constants.add("xlFlashFill".lower())
        self.globals["xlFloating".lower()] = 5
        self.vb_constants.add("xlFloating".lower())
        self.globals["xlFloor".lower()] = 23
        self.vb_constants.add("xlFloor".lower())
        self.globals["xlForecastAggregationAverage".lower()] = 1
        self.vb_constants.add("xlForecastAggregationAverage".lower())
        self.globals["xlForecastAggregationCount".lower()] = 2
        self.vb_constants.add("xlForecastAggregationCount".lower())
        self.globals["xlForecastAggregationCountA".lower()] = 3
        self.vb_constants.add("xlForecastAggregationCountA".lower())
        self.globals["xlForecastAggregationMax".lower()] = 4
        self.vb_constants.add("xlForecastAggregationMax".lower())
        self.globals["xlForecastAggregationMedian".lower()] = 5
        self.vb_constants.add("xlForecastAggregationMedian".lower())
        self.globals["xlForecastAggregationMin".lower()] = 6
        self.vb_constants.add("xlForecastAggregationMin".lower())
        self.globals["xlForecastAggregationSum".lower()] = 7
        self.vb_constants.add("xlForecastAggregationSum".lower())
        self.globals["xlForecastChartTypeColumn".lower()] = 1
        self.vb_constants.add("xlForecastChartTypeColumn".lower())
        self.globals["xlForecastChartTypeLine".lower()] = 0
        self.vb_constants.add("xlForecastChartTypeLine".lower())
        self.globals["xlForecastDataCompletionInterpolate".lower()] = 1
        self.vb_constants.add("xlForecastDataCompletionInterpolate".lower())
        self.globals["xlForecastDataCompletionZeros".lower()] = 0
        self.vb_constants.add("xlForecastDataCompletionZeros".lower())
        self.globals["xlFormatConditions".lower()] = 1
        self.vb_constants.add("xlFormatConditions".lower())
        self.globals["xlFormatFromLeftOrAbove".lower()] = 0
        self.vb_constants.add("xlFormatFromLeftOrAbove".lower())
        self.globals["xlFormatFromRightOrBelow".lower()] = 1
        self.vb_constants.add("xlFormatFromRightOrBelow".lower())
        self.globals["xlFormats".lower()] = 4122
        self.vb_constants.add("xlFormats".lower())
        self.globals["xlFormula".lower()] = 5
        self.vb_constants.add("xlFormula".lower())
        self.globals["xlFormulas".lower()] = 4123
        self.vb_constants.add("xlFormulas".lower())
        self.globals["xlFreeFloating".lower()] = 3
        self.vb_constants.add("xlFreeFloating".lower())
        self.globals["xlFront".lower()] = 4
        self.vb_constants.add("xlFront".lower())
        self.globals["xlFrontEnd".lower()] = 6
        self.vb_constants.add("xlFrontEnd".lower())
        self.globals["xlFrontSides".lower()] = 5
        self.vb_constants.add("xlFrontSides".lower())
        self.globals["xlFullPage".lower()] = 3
        self.vb_constants.add("xlFullPage".lower())
        self.globals["xlFullScript".lower()] = 1
        self.vb_constants.add("xlFullScript".lower())
        self.globals["xlFunction".lower()] = 1
        self.vb_constants.add("xlFunction".lower())
        self.globals["xlFunnel".lower()] = 123
        self.vb_constants.add("xlFunnel".lower())
        self.globals["xlGeneral".lower()] = 1
        self.vb_constants.add("xlGeneral".lower())
        self.globals["xlGeneralFormat".lower()] = 1
        self.vb_constants.add("xlGeneralFormat".lower())
        self.globals["xlGeneralFormatName".lower()] = 26
        self.vb_constants.add("xlGeneralFormatName".lower())
        self.globals["xlGenerateTableRefA1".lower()] = 0
        self.vb_constants.add("xlGenerateTableRefA1".lower())
        self.globals["xlGenerateTableRefStruct".lower()] = 1
        self.vb_constants.add("xlGenerateTableRefStruct".lower())
        self.globals["xlGeoMappingLevelAutomatic".lower()] = 0
        self.vb_constants.add("xlGeoMappingLevelAutomatic".lower())
        self.globals["xlGeoMappingLevelCountryRegion".lower()] = 5
        self.vb_constants.add("xlGeoMappingLevelCountryRegion".lower())
        self.globals["xlGeoMappingLevelCountryRegionList".lower()] = 6
        self.vb_constants.add("xlGeoMappingLevelCountryRegionList".lower())
        self.globals["xlGeoMappingLevelCounty".lower()] = 3
        self.vb_constants.add("xlGeoMappingLevelCounty".lower())
        self.globals["xlGeoMappingLevelDataOnly".lower()] = 1
        self.vb_constants.add("xlGeoMappingLevelDataOnly".lower())
        self.globals["xlGeoMappingLevelPostalCode".lower()] = 2
        self.vb_constants.add("xlGeoMappingLevelPostalCode".lower())
        self.globals["xlGeoMappingLevelState".lower()] = 4
        self.vb_constants.add("xlGeoMappingLevelState".lower())
        self.globals["xlGeoMappingLevelWorld".lower()] = 7
        self.vb_constants.add("xlGeoMappingLevelWorld".lower())
        self.globals["xlGeoProjectionTypeAlbers".lower()] = 3
        self.vb_constants.add("xlGeoProjectionTypeAlbers".lower())
        self.globals["xlGeoProjectionTypeAutomatic".lower()] = 0
        self.vb_constants.add("xlGeoProjectionTypeAutomatic".lower())
        self.globals["xlGeoProjectionTypeMercator".lower()] = 1
        self.vb_constants.add("xlGeoProjectionTypeMercator".lower())
        self.globals["xlGeoProjectionTypeMiller".lower()] = 2
        self.vb_constants.add("xlGeoProjectionTypeMiller".lower())
        self.globals["xlGeoProjectionTypeRobinson".lower()] = 4
        self.vb_constants.add("xlGeoProjectionTypeRobinson".lower())
        self.globals["xlGradientFillLinear".lower()] = 0
        self.vb_constants.add("xlGradientFillLinear".lower())
        self.globals["xlGradientFillPath".lower()] = 1
        self.vb_constants.add("xlGradientFillPath".lower())
        self.globals["xlGradientStopPositionTypeExtremeValue".lower()] = 0
        self.vb_constants.add("xlGradientStopPositionTypeExtremeValue".lower())
        self.globals["xlGradientStopPositionTypeNumber".lower()] = 1
        self.vb_constants.add("xlGradientStopPositionTypeNumber".lower())
        self.globals["xlGradientStopPositionTypePercent".lower()] = 2
        self.vb_constants.add("xlGradientStopPositionTypePercent".lower())
        self.globals["xlGrandTotalColumn".lower()] = 4
        self.vb_constants.add("xlGrandTotalColumn".lower())
        self.globals["xlGrandTotalRow".lower()] = 2
        self.vb_constants.add("xlGrandTotalRow".lower())
        self.globals["xlGray16".lower()] = 17
        self.vb_constants.add("xlGray16".lower())
        self.globals["xlGray25".lower()] = 4124
        self.vb_constants.add("xlGray25".lower())
        self.globals["xlGray50".lower()] = 4125
        self.vb_constants.add("xlGray50".lower())
        self.globals["xlGray75".lower()] = 4126
        self.vb_constants.add("xlGray75".lower())
        self.globals["xlGray8".lower()] = 18
        self.vb_constants.add("xlGray8".lower())
        self.globals["xlGreater".lower()] = 5
        self.vb_constants.add("xlGreater".lower())
        self.globals["xlGreaterEqual".lower()] = 7
        self.vb_constants.add("xlGreaterEqual".lower())
        self.globals["xlGregorian".lower()] = 2
        self.vb_constants.add("xlGregorian".lower())
        self.globals["xlGrid".lower()] = 15
        self.vb_constants.add("xlGrid".lower())
        self.globals["xlGridline".lower()] = 22
        self.vb_constants.add("xlGridline".lower())
        self.globals["xlGroupBox".lower()] = 4
        self.vb_constants.add("xlGroupBox".lower())
        self.globals["xlGrowth".lower()] = 2
        self.vb_constants.add("xlGrowth".lower())
        self.globals["xlGrowthTrend".lower()] = 10
        self.vb_constants.add("xlGrowthTrend".lower())
        self.globals["xlGuess".lower()] = 0
        self.vb_constants.add("xlGuess".lower())
        self.globals["xlHairline".lower()] = 1
        self.vb_constants.add("xlHairline".lower())
        self.globals["xlHAlignCenter".lower()] = 4108
        self.vb_constants.add("xlHAlignCenter".lower())
        self.globals["xlHAlignCenterAcrossSelection".lower()] = 7
        self.vb_constants.add("xlHAlignCenterAcrossSelection".lower())
        self.globals["xlHAlignDistributed".lower()] = 4117
        self.vb_constants.add("xlHAlignDistributed".lower())
        self.globals["xlHAlignFill".lower()] = 5
        self.vb_constants.add("xlHAlignFill".lower())
        self.globals["xlHAlignGeneral".lower()] = 1
        self.vb_constants.add("xlHAlignGeneral".lower())
        self.globals["xlHAlignJustify".lower()] = 4130
        self.vb_constants.add("xlHAlignJustify".lower())
        self.globals["xlHAlignLeft".lower()] = 4131
        self.vb_constants.add("xlHAlignLeft".lower())
        self.globals["xlHAlignRight".lower()] = 4152
        self.vb_constants.add("xlHAlignRight".lower())
        self.globals["xlHeaderRow".lower()] = 1
        self.vb_constants.add("xlHeaderRow".lower())
        self.globals["xlHebrewFullScript".lower()] = 0
        self.vb_constants.add("xlHebrewFullScript".lower())
        self.globals["xlHebrewMixedAuthorizedScript".lower()] = 3
        self.vb_constants.add("xlHebrewMixedAuthorizedScript".lower())
        self.globals["xlHebrewMixedScript".lower()] = 2
        self.vb_constants.add("xlHebrewMixedScript".lower())
        self.globals["xlHebrewPartialScript".lower()] = 1
        self.vb_constants.add("xlHebrewPartialScript".lower())
        self.globals["xlHGL".lower()] = 6
        self.vb_constants.add("xlHGL".lower())
        self.globals["xlHidden".lower()] = 0
        self.vb_constants.add("xlHidden".lower())
        self.globals["xlHide".lower()] = 3
        self.vb_constants.add("xlHide".lower())
        self.globals["xlHierarchy".lower()] = 1
        self.vb_constants.add("xlHierarchy".lower())
        self.globals["xlHigh".lower()] = 4127
        self.vb_constants.add("xlHigh".lower())
        self.globals["xlHiLoLines".lower()] = 25
        self.vb_constants.add("xlHiLoLines".lower())
        self.globals["xlHindiNumerals".lower()] = 3
        self.vb_constants.add("xlHindiNumerals".lower())
        self.globals["xlHiragana".lower()] = 2
        self.vb_constants.add("xlHiragana".lower())
        self.globals["xlHistogram".lower()] = 118
        self.vb_constants.add("xlHistogram".lower())
        self.globals["xlHorizontal".lower()] = 4128
        self.vb_constants.add("xlHorizontal".lower())
        self.globals["xlHorizontalCoordinate".lower()] = 1
        self.vb_constants.add("xlHorizontalCoordinate".lower())
        self.globals["xlHourCode".lower()] = 22
        self.vb_constants.add("xlHourCode".lower())
        self.globals["xlHtml".lower()] = 44
        self.vb_constants.add("xlHtml".lower())
        self.globals["xlHtmlCalc".lower()] = 1
        self.vb_constants.add("xlHtmlCalc".lower())
        self.globals["xlHtmlChart".lower()] = 3
        self.vb_constants.add("xlHtmlChart".lower())
        self.globals["xlHtmlList".lower()] = 2
        self.vb_constants.add("xlHtmlList".lower())
        self.globals["xlHtmlStatic".lower()] = 0
        self.vb_constants.add("xlHtmlStatic".lower())
        self.globals["xlHundredMillions".lower()] = 8
        self.vb_constants.add("xlHundredMillions".lower())
        self.globals["xlHundreds".lower()] = 2
        self.vb_constants.add("xlHundreds".lower())
        self.globals["xlHundredThousands".lower()] = 5
        self.vb_constants.add("xlHundredThousands".lower())
        self.globals["xlIBeam".lower()] = 3
        self.vb_constants.add("xlIBeam".lower())
        self.globals["xlIcon0Bars".lower()] = 37
        self.vb_constants.add("xlIcon0Bars".lower())
        self.globals["xlIcon0FilledBoxes".lower()] = 52
        self.vb_constants.add("xlIcon0FilledBoxes".lower())
        self.globals["xlIcon1Bar".lower()] = 38
        self.vb_constants.add("xlIcon1Bar".lower())
        self.globals["xlIcon1FilledBox".lower()] = 51
        self.vb_constants.add("xlIcon1FilledBox".lower())
        self.globals["xlIcon2Bars".lower()] = 39
        self.vb_constants.add("xlIcon2Bars".lower())
        self.globals["xlIcon2FilledBoxes".lower()] = 50
        self.vb_constants.add("xlIcon2FilledBoxes".lower())
        self.globals["xlIcon3Bars".lower()] = 40
        self.vb_constants.add("xlIcon3Bars".lower())
        self.globals["xlIcon3FilledBoxes".lower()] = 49
        self.vb_constants.add("xlIcon3FilledBoxes".lower())
        self.globals["xlIcon4Bars".lower()] = 41
        self.vb_constants.add("xlIcon4Bars".lower())
        self.globals["xlIcon4FilledBoxes".lower()] = 48
        self.vb_constants.add("xlIcon4FilledBoxes".lower())
        self.globals["xlIconBlackCircle".lower()] = 32
        self.vb_constants.add("xlIconBlackCircle".lower())
        self.globals["xlIconBlackCircleWithBorder".lower()] = 13
        self.vb_constants.add("xlIconBlackCircleWithBorder".lower())
        self.globals["xlIconCircleWithOneWhiteQuarter".lower()] = 33
        self.vb_constants.add("xlIconCircleWithOneWhiteQuarter".lower())
        self.globals["xlIconCircleWithThreeWhiteQuarters".lower()] = 35
        self.vb_constants.add("xlIconCircleWithThreeWhiteQuarters".lower())
        self.globals["xlIconCircleWithTwoWhiteQuarters".lower()] = 34
        self.vb_constants.add("xlIconCircleWithTwoWhiteQuarters".lower())
        self.globals["xlIconGoldStar".lower()] = 42
        self.vb_constants.add("xlIconGoldStar".lower())
        self.globals["xlIconGrayCircle".lower()] = 31
        self.vb_constants.add("xlIconGrayCircle".lower())
        self.globals["xlIconGrayDownArrow".lower()] = 6
        self.vb_constants.add("xlIconGrayDownArrow".lower())
        self.globals["xlIconGrayDownInclineArrow".lower()] = 28
        self.vb_constants.add("xlIconGrayDownInclineArrow".lower())
        self.globals["xlIconGraySideArrow".lower()] = 5
        self.vb_constants.add("xlIconGraySideArrow".lower())
        self.globals["xlIconGrayUpArrow".lower()] = 4
        self.vb_constants.add("xlIconGrayUpArrow".lower())
        self.globals["xlIconGrayUpInclineArrow".lower()] = 27
        self.vb_constants.add("xlIconGrayUpInclineArrow".lower())
        self.globals["xlIconGreenCheck".lower()] = 22
        self.vb_constants.add("xlIconGreenCheck".lower())
        self.globals["xlIconGreenCheckSymbol".lower()] = 19
        self.vb_constants.add("xlIconGreenCheckSymbol".lower())
        self.globals["xlIconGreenCircle".lower()] = 10
        self.vb_constants.add("xlIconGreenCircle".lower())
        self.globals["xlIconGreenFlag".lower()] = 7
        self.vb_constants.add("xlIconGreenFlag".lower())
        self.globals["xlIconGreenTrafficLight".lower()] = 14
        self.vb_constants.add("xlIconGreenTrafficLight".lower())
        self.globals["xlIconGreenUpArrow".lower()] = 1
        self.vb_constants.add("xlIconGreenUpArrow".lower())
        self.globals["xlIconGreenUpTriangle".lower()] = 45
        self.vb_constants.add("xlIconGreenUpTriangle".lower())
        self.globals["xlIconHalfGoldStar".lower()] = 43
        self.vb_constants.add("xlIconHalfGoldStar".lower())
        self.globals["xlIconNoCellIcon".lower()] = 1
        self.vb_constants.add("xlIconNoCellIcon".lower())
        self.globals["xlIconPinkCircle".lower()] = 30
        self.vb_constants.add("xlIconPinkCircle".lower())
        self.globals["xlIconRedCircle".lower()] = 29
        self.vb_constants.add("xlIconRedCircle".lower())
        self.globals["xlIconRedCircleWithBorder".lower()] = 12
        self.vb_constants.add("xlIconRedCircleWithBorder".lower())
        self.globals["xlIconRedCross".lower()] = 24
        self.vb_constants.add("xlIconRedCross".lower())
        self.globals["xlIconRedCrossSymbol".lower()] = 21
        self.vb_constants.add("xlIconRedCrossSymbol".lower())
        self.globals["xlIconRedDiamond".lower()] = 18
        self.vb_constants.add("xlIconRedDiamond".lower())
        self.globals["xlIconRedDownArrow".lower()] = 3
        self.vb_constants.add("xlIconRedDownArrow".lower())
        self.globals["xlIconRedDownTriangle".lower()] = 47
        self.vb_constants.add("xlIconRedDownTriangle".lower())
        self.globals["xlIconRedFlag".lower()] = 9
        self.vb_constants.add("xlIconRedFlag".lower())
        self.globals["xlIconRedTrafficLight".lower()] = 16
        self.vb_constants.add("xlIconRedTrafficLight".lower())
        self.globals["xlIcons".lower()] = 1
        self.vb_constants.add("xlIcons".lower())
        self.globals["xlIconSets".lower()] = 6
        self.vb_constants.add("xlIconSets".lower())
        self.globals["xlIconSilverStar".lower()] = 44
        self.vb_constants.add("xlIconSilverStar".lower())
        self.globals["xlIconWhiteCircleAllWhiteQuarters".lower()] = 36
        self.vb_constants.add("xlIconWhiteCircleAllWhiteQuarters".lower())
        self.globals["xlIconYellowCircle".lower()] = 11
        self.vb_constants.add("xlIconYellowCircle".lower())
        self.globals["xlIconYellowDash".lower()] = 46
        self.vb_constants.add("xlIconYellowDash".lower())
        self.globals["xlIconYellowDownInclineArrow".lower()] = 26
        self.vb_constants.add("xlIconYellowDownInclineArrow".lower())
        self.globals["xlIconYellowExclamation".lower()] = 23
        self.vb_constants.add("xlIconYellowExclamation".lower())
        self.globals["xlIconYellowExclamationSymbol".lower()] = 20
        self.vb_constants.add("xlIconYellowExclamationSymbol".lower())
        self.globals["xlIconYellowFlag".lower()] = 8
        self.vb_constants.add("xlIconYellowFlag".lower())
        self.globals["xlIconYellowSideArrow".lower()] = 2
        self.vb_constants.add("xlIconYellowSideArrow".lower())
        self.globals["xlIconYellowTrafficLight".lower()] = 15
        self.vb_constants.add("xlIconYellowTrafficLight".lower())
        self.globals["xlIconYellowTriangle".lower()] = 17
        self.vb_constants.add("xlIconYellowTriangle".lower())
        self.globals["xlIconYellowUpInclineArrow".lower()] = 25
        self.vb_constants.add("xlIconYellowUpInclineArrow".lower())
        self.globals["xlIMEModeAlpha".lower()] = 8
        self.vb_constants.add("xlIMEModeAlpha".lower())
        self.globals["xlIMEModeAlphaFull".lower()] = 7
        self.vb_constants.add("xlIMEModeAlphaFull".lower())
        self.globals["xlIMEModeDisable".lower()] = 3
        self.vb_constants.add("xlIMEModeDisable".lower())
        self.globals["xlIMEModeHangul".lower()] = 10
        self.vb_constants.add("xlIMEModeHangul".lower())
        self.globals["xlIMEModeHangulFull".lower()] = 9
        self.vb_constants.add("xlIMEModeHangulFull".lower())
        self.globals["xlIMEModeHiragana".lower()] = 4
        self.vb_constants.add("xlIMEModeHiragana".lower())
        self.globals["xlIMEModeKatakana".lower()] = 5
        self.vb_constants.add("xlIMEModeKatakana".lower())
        self.globals["xlIMEModeKatakanaHalf".lower()] = 6
        self.vb_constants.add("xlIMEModeKatakanaHalf".lower())
        self.globals["xlIMEModeNoControl".lower()] = 0
        self.vb_constants.add("xlIMEModeNoControl".lower())
        self.globals["xlIMEModeOff".lower()] = 2
        self.vb_constants.add("xlIMEModeOff".lower())
        self.globals["xlIMEModeOn".lower()] = 1
        self.vb_constants.add("xlIMEModeOn".lower())
        self.globals["xlImmediatePane".lower()] = 12
        self.vb_constants.add("xlImmediatePane".lower())
        self.globals["xlInches".lower()] = 0
        self.vb_constants.add("xlInches".lower())
        self.globals["xlInconsistentFormula".lower()] = 4
        self.vb_constants.add("xlInconsistentFormula".lower())
        self.globals["xlInconsistentListFormula".lower()] = 9
        self.vb_constants.add("xlInconsistentListFormula".lower())
        self.globals["xlIndex".lower()] = 9
        self.vb_constants.add("xlIndex".lower())
        self.globals["xlIndexAscending".lower()] = 0
        self.vb_constants.add("xlIndexAscending".lower())
        self.globals["xlIndexDescending".lower()] = 1
        self.vb_constants.add("xlIndexDescending".lower())
        self.globals["xlIndicatorAndButton".lower()] = 0
        self.vb_constants.add("xlIndicatorAndButton".lower())
        self.globals["xlInfo".lower()] = 4129
        self.vb_constants.add("xlInfo".lower())
        self.globals["xlInnerCenterPoint".lower()] = 8
        self.vb_constants.add("xlInnerCenterPoint".lower())
        self.globals["xlInnerClockwisePoint".lower()] = 7
        self.vb_constants.add("xlInnerClockwisePoint".lower())
        self.globals["xlInnerCounterClockwisePoint".lower()] = 9
        self.vb_constants.add("xlInnerCounterClockwisePoint".lower())
        self.globals["xlInsertDeleteCells".lower()] = 1
        self.vb_constants.add("xlInsertDeleteCells".lower())
        self.globals["xlInsertEntireRows".lower()] = 2
        self.vb_constants.add("xlInsertEntireRows".lower())
        self.globals["xlInside".lower()] = 2
        self.vb_constants.add("xlInside".lower())
        self.globals["xlInsideHorizontal".lower()] = 12
        self.vb_constants.add("xlInsideHorizontal".lower())
        self.globals["xlInsideVertical".lower()] = 11
        self.vb_constants.add("xlInsideVertical".lower())
        self.globals["xlInteger".lower()] = 2
        self.vb_constants.add("xlInteger".lower())
        self.globals["xlInterpolated".lower()] = 3
        self.vb_constants.add("xlInterpolated".lower())
        self.globals["xlInterrupt".lower()] = 1
        self.vb_constants.add("xlInterrupt".lower())
        self.globals["xlIntlAddIn".lower()] = 26
        self.vb_constants.add("xlIntlAddIn".lower())
        self.globals["xlIntlMacro".lower()] = 25
        self.vb_constants.add("xlIntlMacro".lower())
        self.globals["xlJustify".lower()] = 4130
        self.vb_constants.add("xlJustify".lower())
        self.globals["xlKatakana".lower()] = 1
        self.vb_constants.add("xlKatakana".lower())
        self.globals["xlKatakanaHalf".lower()] = 0
        self.vb_constants.add("xlKatakanaHalf".lower())
        self.globals["xlLabel".lower()] = 5
        self.vb_constants.add("xlLabel".lower())
        self.globals["xlLabelOnly".lower()] = 1
        self.vb_constants.add("xlLabelOnly".lower())
        self.globals["xlLabelPositionAbove".lower()] = 0
        self.vb_constants.add("xlLabelPositionAbove".lower())
        self.globals["xlLabelPositionBelow".lower()] = 1
        self.vb_constants.add("xlLabelPositionBelow".lower())
        self.globals["xlLabelPositionBestFit".lower()] = 5
        self.vb_constants.add("xlLabelPositionBestFit".lower())
        self.globals["xlLabelPositionCenter".lower()] = 4108
        self.vb_constants.add("xlLabelPositionCenter".lower())
        self.globals["xlLabelPositionCustom".lower()] = 7
        self.vb_constants.add("xlLabelPositionCustom".lower())
        self.globals["xlLabelPositionInsideBase".lower()] = 4
        self.vb_constants.add("xlLabelPositionInsideBase".lower())
        self.globals["xlLabelPositionInsideEnd".lower()] = 3
        self.vb_constants.add("xlLabelPositionInsideEnd".lower())
        self.globals["xlLabelPositionLeft".lower()] = 4131
        self.vb_constants.add("xlLabelPositionLeft".lower())
        self.globals["xlLabelPositionMixed".lower()] = 6
        self.vb_constants.add("xlLabelPositionMixed".lower())
        self.globals["xlLabelPositionOutsideEnd".lower()] = 2
        self.vb_constants.add("xlLabelPositionOutsideEnd".lower())
        self.globals["xlLabelPositionRight".lower()] = 4152
        self.vb_constants.add("xlLabelPositionRight".lower())
        self.globals["xlLandscape".lower()] = 2
        self.vb_constants.add("xlLandscape".lower())
        self.globals["xlLast".lower()] = 1
        self.vb_constants.add("xlLast".lower())
        self.globals["xlLast7Days".lower()] = 2
        self.vb_constants.add("xlLast7Days".lower())
        self.globals["xlLastCell".lower()] = 11
        self.vb_constants.add("xlLastCell".lower())
        self.globals["xlLastColumn".lower()] = 4
        self.vb_constants.add("xlLastColumn".lower())
        self.globals["xlLastHeaderCell".lower()] = 10
        self.vb_constants.add("xlLastHeaderCell".lower())
        self.globals["xlLastMonth".lower()] = 5
        self.vb_constants.add("xlLastMonth".lower())
        self.globals["xlLastTotalCell".lower()] = 12
        self.vb_constants.add("xlLastTotalCell".lower())
        self.globals["xlLastWeek".lower()] = 4
        self.vb_constants.add("xlLastWeek".lower())
        self.globals["xlLatin".lower()] = 5001
        self.vb_constants.add("xlLatin".lower())
        self.globals["xlLeaderLines".lower()] = 29
        self.vb_constants.add("xlLeaderLines".lower())
        self.globals["xlLeft".lower()] = 4131
        self.vb_constants.add("xlLeft".lower())
        self.globals["xlLeftBrace".lower()] = 12
        self.vb_constants.add("xlLeftBrace".lower())
        self.globals["xlLeftBracket".lower()] = 10
        self.vb_constants.add("xlLeftBracket".lower())
        self.globals["xlLeftToRight".lower()] = 2
        self.vb_constants.add("xlLeftToRight".lower())
        self.globals["xlLegend".lower()] = 24
        self.vb_constants.add("xlLegend".lower())
        self.globals["xlLegendEntry".lower()] = 12
        self.vb_constants.add("xlLegendEntry".lower())
        self.globals["xlLegendKey".lower()] = 13
        self.vb_constants.add("xlLegendKey".lower())
        self.globals["xlLegendPositionBottom".lower()] = 4107
        self.vb_constants.add("xlLegendPositionBottom".lower())
        self.globals["xlLegendPositionCorner".lower()] = 2
        self.vb_constants.add("xlLegendPositionCorner".lower())
        self.globals["xlLegendPositionCustom".lower()] = 4161
        self.vb_constants.add("xlLegendPositionCustom".lower())
        self.globals["xlLegendPositionLeft".lower()] = 4131
        self.vb_constants.add("xlLegendPositionLeft".lower())
        self.globals["xlLegendPositionRight".lower()] = 4152
        self.vb_constants.add("xlLegendPositionRight".lower())
        self.globals["xlLegendPositionTop".lower()] = 4160
        self.vb_constants.add("xlLegendPositionTop".lower())
        self.globals["xlLensOnly".lower()] = 0
        self.vb_constants.add("xlLensOnly".lower())
        self.globals["xlLess".lower()] = 6
        self.vb_constants.add("xlLess".lower())
        self.globals["xlLessEqual".lower()] = 8
        self.vb_constants.add("xlLessEqual".lower())
        self.globals["xlLightDown".lower()] = 13
        self.vb_constants.add("xlLightDown".lower())
        self.globals["xlLightHorizontal".lower()] = 11
        self.vb_constants.add("xlLightHorizontal".lower())
        self.globals["xlLightUp".lower()] = 14
        self.vb_constants.add("xlLightUp".lower())
        self.globals["xlLightVertical".lower()] = 12
        self.vb_constants.add("xlLightVertical".lower())
        self.globals["xlLine".lower()] = 4
        self.vb_constants.add("xlLine".lower())
        self.globals["xlLinear".lower()] = 4132
        self.vb_constants.add("xlLinear".lower())
        self.globals["xlLinearTrend".lower()] = 9
        self.vb_constants.add("xlLinearTrend".lower())
        self.globals["xlLineMarkers".lower()] = 65
        self.vb_constants.add("xlLineMarkers".lower())
        self.globals["xlLineMarkersStacked".lower()] = 66
        self.vb_constants.add("xlLineMarkersStacked".lower())
        self.globals["xlLineMarkersStacked100".lower()] = 67
        self.vb_constants.add("xlLineMarkersStacked100".lower())
        self.globals["xlLineStacked".lower()] = 63
        self.vb_constants.add("xlLineStacked".lower())
        self.globals["xlLineStacked100".lower()] = 64
        self.vb_constants.add("xlLineStacked100".lower())
        self.globals["xlLineStyleNone".lower()] = 4142
        self.vb_constants.add("xlLineStyleNone".lower())
        self.globals["xlLinkedDataTypeStateBrokenLinkedData".lower()] = 3
        self.vb_constants.add("xlLinkedDataTypeStateBrokenLinkedData".lower())
        self.globals["xlLinkedDataTypeStateDisambiguationNeeded".lower()] = 2
        self.vb_constants.add("xlLinkedDataTypeStateDisambiguationNeeded".lower())
        self.globals["xlLinkedDataTypeStateFetchingData".lower()] = 4
        self.vb_constants.add("xlLinkedDataTypeStateFetchingData".lower())
        self.globals["xlLinkedDataTypeStateNone".lower()] = 0
        self.vb_constants.add("xlLinkedDataTypeStateNone".lower())
        self.globals["xlLinkedDataTypeStateValidLinkedData".lower()] = 1
        self.vb_constants.add("xlLinkedDataTypeStateValidLinkedData".lower())
        self.globals["xlLinkInfoOLELinks".lower()] = 2
        self.vb_constants.add("xlLinkInfoOLELinks".lower())
        self.globals["xlLinkInfoPublishers".lower()] = 5
        self.vb_constants.add("xlLinkInfoPublishers".lower())
        self.globals["xlLinkInfoStatus".lower()] = 3
        self.vb_constants.add("xlLinkInfoStatus".lower())
        self.globals["xlLinkInfoSubscribers".lower()] = 6
        self.vb_constants.add("xlLinkInfoSubscribers".lower())
        self.globals["xlLinkStatusCopiedValues".lower()] = 10
        self.vb_constants.add("xlLinkStatusCopiedValues".lower())
        self.globals["xlLinkStatusIndeterminate".lower()] = 5
        self.vb_constants.add("xlLinkStatusIndeterminate".lower())
        self.globals["xlLinkStatusInvalidName".lower()] = 7
        self.vb_constants.add("xlLinkStatusInvalidName".lower())
        self.globals["xlLinkStatusMissingFile".lower()] = 1
        self.vb_constants.add("xlLinkStatusMissingFile".lower())
        self.globals["xlLinkStatusMissingSheet".lower()] = 2
        self.vb_constants.add("xlLinkStatusMissingSheet".lower())
        self.globals["xlLinkStatusNotStarted".lower()] = 6
        self.vb_constants.add("xlLinkStatusNotStarted".lower())
        self.globals["xlLinkStatusOK".lower()] = 0
        self.vb_constants.add("xlLinkStatusOK".lower())
        self.globals["xlLinkStatusOld".lower()] = 3
        self.vb_constants.add("xlLinkStatusOld".lower())
        self.globals["xlLinkStatusSourceNotCalculated".lower()] = 4
        self.vb_constants.add("xlLinkStatusSourceNotCalculated".lower())
        self.globals["xlLinkStatusSourceNotOpen".lower()] = 8
        self.vb_constants.add("xlLinkStatusSourceNotOpen".lower())
        self.globals["xlLinkStatusSourceOpen".lower()] = 9
        self.vb_constants.add("xlLinkStatusSourceOpen".lower())
        self.globals["xlLinkTypeExcelLinks".lower()] = 1
        self.vb_constants.add("xlLinkTypeExcelLinks".lower())
        self.globals["xlLinkTypeOLELinks".lower()] = 2
        self.vb_constants.add("xlLinkTypeOLELinks".lower())
        self.globals["xlList1".lower()] = 10
        self.vb_constants.add("xlList1".lower())
        self.globals["xlList2".lower()] = 11
        self.vb_constants.add("xlList2".lower())
        self.globals["xlList3".lower()] = 12
        self.vb_constants.add("xlList3".lower())
        self.globals["xlListBox".lower()] = 6
        self.vb_constants.add("xlListBox".lower())
        self.globals["xlListConflictDialog".lower()] = 0
        self.vb_constants.add("xlListConflictDialog".lower())
        self.globals["xlListConflictDiscardAllConflicts".lower()] = 2
        self.vb_constants.add("xlListConflictDiscardAllConflicts".lower())
        self.globals["xlListConflictError".lower()] = 3
        self.vb_constants.add("xlListConflictError".lower())
        self.globals["xlListConflictRetryAllConflicts".lower()] = 1
        self.vb_constants.add("xlListConflictRetryAllConflicts".lower())
        self.globals["xlListDataTypeCheckbox".lower()] = 9
        self.vb_constants.add("xlListDataTypeCheckbox".lower())
        self.globals["xlListDataTypeChoice".lower()] = 6
        self.vb_constants.add("xlListDataTypeChoice".lower())
        self.globals["xlListDataTypeChoiceMulti".lower()] = 7
        self.vb_constants.add("xlListDataTypeChoiceMulti".lower())
        self.globals["xlListDataTypeCounter".lower()] = 11
        self.vb_constants.add("xlListDataTypeCounter".lower())
        self.globals["xlListDataTypeCurrency".lower()] = 4
        self.vb_constants.add("xlListDataTypeCurrency".lower())
        self.globals["xlListDataTypeDateTime".lower()] = 5
        self.vb_constants.add("xlListDataTypeDateTime".lower())
        self.globals["xlListDataTypeHyperLink".lower()] = 10
        self.vb_constants.add("xlListDataTypeHyperLink".lower())
        self.globals["xlListDataTypeListLookup".lower()] = 8
        self.vb_constants.add("xlListDataTypeListLookup".lower())
        self.globals["xlListDataTypeMultiLineRichText".lower()] = 12
        self.vb_constants.add("xlListDataTypeMultiLineRichText".lower())
        self.globals["xlListDataTypeMultiLineText".lower()] = 2
        self.vb_constants.add("xlListDataTypeMultiLineText".lower())
        self.globals["xlListDataTypeNone".lower()] = 0
        self.vb_constants.add("xlListDataTypeNone".lower())
        self.globals["xlListDataTypeNumber".lower()] = 3
        self.vb_constants.add("xlListDataTypeNumber".lower())
        self.globals["xlListDataTypeText".lower()] = 1
        self.vb_constants.add("xlListDataTypeText".lower())
        self.globals["xlListDataValidation".lower()] = 8
        self.vb_constants.add("xlListDataValidation".lower())
        self.globals["xlListSeparator".lower()] = 5
        self.vb_constants.add("xlListSeparator".lower())
        self.globals["xlLocalFormat1".lower()] = 15
        self.vb_constants.add("xlLocalFormat1".lower())
        self.globals["xlLocalFormat2".lower()] = 16
        self.vb_constants.add("xlLocalFormat2".lower())
        self.globals["xlLocalSessionChanges".lower()] = 2
        self.vb_constants.add("xlLocalSessionChanges".lower())
        self.globals["xlLocationAsNewSheet".lower()] = 1
        self.vb_constants.add("xlLocationAsNewSheet".lower())
        self.globals["xlLocationAsObject".lower()] = 2
        self.vb_constants.add("xlLocationAsObject".lower())
        self.globals["xlLocationAutomatic".lower()] = 3
        self.vb_constants.add("xlLocationAutomatic".lower())
        self.globals["xlLogarithmic".lower()] = 4133
        self.vb_constants.add("xlLogarithmic".lower())
        self.globals["xlLogical".lower()] = 4
        self.vb_constants.add("xlLogical".lower())
        self.globals["xlLogicalCursor".lower()] = 1
        self.vb_constants.add("xlLogicalCursor".lower())
        self.globals["xlLong".lower()] = 3
        self.vb_constants.add("xlLong".lower())
        self.globals["xlLookForBlanks".lower()] = 0
        self.vb_constants.add("xlLookForBlanks".lower())
        self.globals["xlLookForErrors".lower()] = 1
        self.vb_constants.add("xlLookForErrors".lower())
        self.globals["xlLookForFormulas".lower()] = 2
        self.vb_constants.add("xlLookForFormulas".lower())
        self.globals["xlLotusHelp".lower()] = 2
        self.vb_constants.add("xlLotusHelp".lower())
        self.globals["xlLow".lower()] = 4134
        self.vb_constants.add("xlLow".lower())
        self.globals["xlLowerCaseColumnLetter".lower()] = 9
        self.vb_constants.add("xlLowerCaseColumnLetter".lower())
        self.globals["xlLowerCaseRowLetter".lower()] = 8
        self.vb_constants.add("xlLowerCaseRowLetter".lower())
        self.globals["xlLTR".lower()] = 5003
        self.vb_constants.add("xlLTR".lower())
        self.globals["xlMacintosh".lower()] = 1
        self.vb_constants.add("xlMacintosh".lower())
        self.globals["xlMacrosheetCell".lower()] = 7
        self.vb_constants.add("xlMacrosheetCell".lower())
        self.globals["xlMajorGridlines".lower()] = 15
        self.vb_constants.add("xlMajorGridlines".lower())
        self.globals["xlManual".lower()] = 4135
        self.vb_constants.add("xlManual".lower())
        self.globals["xlManualAllocation".lower()] = 1
        self.vb_constants.add("xlManualAllocation".lower())
        self.globals["xlManualUpdate".lower()] = 5
        self.vb_constants.add("xlManualUpdate".lower())
        self.globals["xlMAPI".lower()] = 1
        self.vb_constants.add("xlMAPI".lower())
        self.globals["xlMarkerStyleAutomatic".lower()] = 4105
        self.vb_constants.add("xlMarkerStyleAutomatic".lower())
        self.globals["xlMarkerStyleCircle".lower()] = 8
        self.vb_constants.add("xlMarkerStyleCircle".lower())
        self.globals["xlMarkerStyleDash".lower()] = 4115
        self.vb_constants.add("xlMarkerStyleDash".lower())
        self.globals["xlMarkerStyleDiamond".lower()] = 2
        self.vb_constants.add("xlMarkerStyleDiamond".lower())
        self.globals["xlMarkerStyleDot".lower()] = 4118
        self.vb_constants.add("xlMarkerStyleDot".lower())
        self.globals["xlMarkerStyleNone".lower()] = 4142
        self.vb_constants.add("xlMarkerStyleNone".lower())
        self.globals["xlMarkerStylePicture".lower()] = 4147
        self.vb_constants.add("xlMarkerStylePicture".lower())
        self.globals["xlMarkerStylePlus".lower()] = 9
        self.vb_constants.add("xlMarkerStylePlus".lower())
        self.globals["xlMarkerStyleSquare".lower()] = 1
        self.vb_constants.add("xlMarkerStyleSquare".lower())
        self.globals["xlMarkerStyleStar".lower()] = 5
        self.vb_constants.add("xlMarkerStyleStar".lower())
        self.globals["xlMarkerStyleTriangle".lower()] = 3
        self.vb_constants.add("xlMarkerStyleTriangle".lower())
        self.globals["xlMarkerStyleX".lower()] = 4168
        self.vb_constants.add("xlMarkerStyleX".lower())
        self.globals["xlMax".lower()] = 4136
        self.vb_constants.add("xlMax".lower())
        self.globals["xlMaximized".lower()] = 4137
        self.vb_constants.add("xlMaximized".lower())
        self.globals["xlMaximum".lower()] = 2
        self.vb_constants.add("xlMaximum".lower())
        self.globals["xlMDY".lower()] = 44
        self.vb_constants.add("xlMDY".lower())
        self.globals["xlMDYFormat".lower()] = 3
        self.vb_constants.add("xlMDYFormat".lower())
        self.globals["xlMeasure".lower()] = 2
        self.vb_constants.add("xlMeasure".lower())
        self.globals["xlMedium".lower()] = 4138
        self.vb_constants.add("xlMedium".lower())
        self.globals["xlMetric".lower()] = 35
        self.vb_constants.add("xlMetric".lower())
        self.globals["xlMicrosoftAccess".lower()] = 4
        self.vb_constants.add("xlMicrosoftAccess".lower())
        self.globals["xlMicrosoftFoxPro".lower()] = 5
        self.vb_constants.add("xlMicrosoftFoxPro".lower())
        self.globals["xlMicrosoftMail".lower()] = 3
        self.vb_constants.add("xlMicrosoftMail".lower())
        self.globals["xlMicrosoftPowerPoint".lower()] = 2
        self.vb_constants.add("xlMicrosoftPowerPoint".lower())
        self.globals["xlMicrosoftProject".lower()] = 6
        self.vb_constants.add("xlMicrosoftProject".lower())
        self.globals["xlMicrosoftSchedulePlus".lower()] = 7
        self.vb_constants.add("xlMicrosoftSchedulePlus".lower())
        self.globals["xlMicrosoftWord".lower()] = 1
        self.vb_constants.add("xlMicrosoftWord".lower())
        self.globals["xlMidClockwiseRadiusPoint".lower()] = 4
        self.vb_constants.add("xlMidClockwiseRadiusPoint".lower())
        self.globals["xlMidCounterClockwiseRadiusPoint".lower()] = 6
        self.vb_constants.add("xlMidCounterClockwiseRadiusPoint".lower())
        self.globals["xlMillimeters".lower()] = 2
        self.vb_constants.add("xlMillimeters".lower())
        self.globals["xlMillionMillions".lower()] = 10
        self.vb_constants.add("xlMillionMillions".lower())
        self.globals["xlMillions".lower()] = 6
        self.vb_constants.add("xlMillions".lower())
        self.globals["xlMin".lower()] = 4139
        self.vb_constants.add("xlMin".lower())
        self.globals["xlMinimized".lower()] = 4140
        self.vb_constants.add("xlMinimized".lower())
        self.globals["xlMinimum".lower()] = 4
        self.vb_constants.add("xlMinimum".lower())
        self.globals["xlMinorGridlines".lower()] = 16
        self.vb_constants.add("xlMinorGridlines".lower())
        self.globals["xlMinusValues".lower()] = 3
        self.vb_constants.add("xlMinusValues".lower())
        self.globals["xlMinuteCode".lower()] = 23
        self.vb_constants.add("xlMinuteCode".lower())
        self.globals["xlMissingItemsDefault".lower()] = 1
        self.vb_constants.add("xlMissingItemsDefault".lower())
        self.globals["xlMissingItemsMax".lower()] = 32500
        self.vb_constants.add("xlMissingItemsMax".lower())
        self.globals["xlMissingItemsMax2".lower()] = 1048576
        self.vb_constants.add("xlMissingItemsMax2".lower())
        self.globals["xlMissingItemsNone".lower()] = 0
        self.vb_constants.add("xlMissingItemsNone".lower())
        self.globals["xlMixed".lower()] = 2
        self.vb_constants.add("xlMixed".lower())
        self.globals["xlMixedAuthorizedScript".lower()] = 4
        self.vb_constants.add("xlMixedAuthorizedScript".lower())
        self.globals["xlMixedLabels".lower()] = 3
        self.vb_constants.add("xlMixedLabels".lower())
        self.globals["xlMixedScript".lower()] = 3
        self.vb_constants.add("xlMixedScript".lower())
        self.globals["xlModule".lower()] = 4141
        self.vb_constants.add("xlModule".lower())
        self.globals["xlMonth".lower()] = 3
        self.vb_constants.add("xlMonth".lower())
        self.globals["xlMonthCode".lower()] = 20
        self.vb_constants.add("xlMonthCode".lower())
        self.globals["xlMonthLeadingZero".lower()] = 41
        self.vb_constants.add("xlMonthLeadingZero".lower())
        self.globals["xlMonthNameChars".lower()] = 30
        self.vb_constants.add("xlMonthNameChars".lower())
        self.globals["xlMonths".lower()] = 1
        self.vb_constants.add("xlMonths".lower())
        self.globals["xlMove".lower()] = 2
        self.vb_constants.add("xlMove".lower())
        self.globals["xlMoveAndSize".lower()] = 1
        self.vb_constants.add("xlMoveAndSize".lower())
        self.globals["xlMovingAvg".lower()] = 6
        self.vb_constants.add("xlMovingAvg".lower())
        self.globals["xlMSDOS".lower()] = 3
        self.vb_constants.add("xlMSDOS".lower())
        self.globals["xlMultiply".lower()] = 4
        self.vb_constants.add("xlMultiply".lower())
        self.globals["xlMYDFormat".lower()] = 6
        self.vb_constants.add("xlMYDFormat".lower())
        self.globals["xlNarrow".lower()] = 1
        self.vb_constants.add("xlNarrow".lower())
        self.globals["xlNever".lower()] = 2
        self.vb_constants.add("xlNever".lower())
        self.globals["xlNext".lower()] = 1
        self.vb_constants.add("xlNext".lower())
        self.globals["xlNextMonth".lower()] = 8
        self.vb_constants.add("xlNextMonth".lower())
        self.globals["xlNextToAxis".lower()] = 4
        self.vb_constants.add("xlNextToAxis".lower())
        self.globals["xlNextWeek".lower()] = 7
        self.vb_constants.add("xlNextWeek".lower())
        self.globals["xlNo".lower()] = 2
        self.vb_constants.add("xlNo".lower())
        self.globals["xlNoAdditionalCalculation".lower()] = 4143
        self.vb_constants.add("xlNoAdditionalCalculation".lower())
        self.globals["xlNoBlanksCondition".lower()] = 13
        self.vb_constants.add("xlNoBlanksCondition".lower())
        self.globals["xlNoButton".lower()] = 0
        self.vb_constants.add("xlNoButton".lower())
        self.globals["xlNoButtonChanges".lower()] = 1
        self.vb_constants.add("xlNoButtonChanges".lower())
        self.globals["xlNoCap".lower()] = 2
        self.vb_constants.add("xlNoCap".lower())
        self.globals["xlNoChange".lower()] = 1
        self.vb_constants.add("xlNoChange".lower())
        self.globals["xlNoChanges".lower()] = 4
        self.vb_constants.add("xlNoChanges".lower())
        self.globals["xlNoConversion".lower()] = 3
        self.vb_constants.add("xlNoConversion".lower())
        self.globals["xlNoDockingChanges".lower()] = 3
        self.vb_constants.add("xlNoDockingChanges".lower())
        self.globals["xlNoDocuments".lower()] = 3
        self.vb_constants.add("xlNoDocuments".lower())
        self.globals["xlNoErrorsCondition".lower()] = 17
        self.vb_constants.add("xlNoErrorsCondition".lower())
        self.globals["xlNoIndicator".lower()] = 0
        self.vb_constants.add("xlNoIndicator".lower())
        self.globals["xlNoKey".lower()] = 0
        self.vb_constants.add("xlNoKey".lower())
        self.globals["xlNoLabels".lower()] = 4142
        self.vb_constants.add("xlNoLabels".lower())
        self.globals["xlNoMailSystem".lower()] = 0
        self.vb_constants.add("xlNoMailSystem".lower())
        self.globals["xlNoncurrencyDigits".lower()] = 29
        self.vb_constants.add("xlNoncurrencyDigits".lower())
        self.globals["xlNone".lower()] = 4142
        self.vb_constants.add("xlNone".lower())
        self.globals["xlNonEnglishFunctions".lower()] = 34
        self.vb_constants.add("xlNonEnglishFunctions".lower())
        self.globals["xlNoRestrictions".lower()] = 0
        self.vb_constants.add("xlNoRestrictions".lower())
        self.globals["xlNormal".lower()] = 4143
        self.vb_constants.add("xlNormal".lower())
        self.globals["xlNormalLoad".lower()] = 0
        self.vb_constants.add("xlNormalLoad".lower())
        self.globals["xlNormalView".lower()] = 1
        self.vb_constants.add("xlNormalView".lower())
        self.globals["xlNorthwestArrow".lower()] = 1
        self.vb_constants.add("xlNorthwestArrow".lower())
        self.globals["xlNoSelection".lower()] = 4142
        self.vb_constants.add("xlNoSelection".lower())
        self.globals["xlNoShapeChanges".lower()] = 2
        self.vb_constants.add("xlNoShapeChanges".lower())
        self.globals["xlNotBetween".lower()] = 2
        self.vb_constants.add("xlNotBetween".lower())
        self.globals["xlNotEqual".lower()] = 4
        self.vb_constants.add("xlNotEqual".lower())
        self.globals["xlNotes".lower()] = 4144
        self.vb_constants.add("xlNotes".lower())
        self.globals["xlNothing".lower()] = 28
        self.vb_constants.add("xlNothing".lower())
        self.globals["xlNotPlotted".lower()] = 1
        self.vb_constants.add("xlNotPlotted".lower())
        self.globals["xlNotSpecificDate".lower()] = 30
        self.vb_constants.add("xlNotSpecificDate".lower())
        self.globals["xlNotXLM".lower()] = 3
        self.vb_constants.add("xlNotXLM".lower())
        self.globals["xlNotYetReviewed".lower()] = 3
        self.vb_constants.add("xlNotYetReviewed".lower())
        self.globals["xlNotYetRouted".lower()] = 0
        self.vb_constants.add("xlNotYetRouted".lower())
        self.globals["xlNumber".lower()] = 4145
        self.vb_constants.add("xlNumber".lower())
        self.globals["xlNumberAsText".lower()] = 3
        self.vb_constants.add("xlNumberAsText".lower())
        self.globals["xlNumberFormatTypeDefault".lower()] = 0
        self.vb_constants.add("xlNumberFormatTypeDefault".lower())
        self.globals["xlNumberFormatTypeNumber".lower()] = 1
        self.vb_constants.add("xlNumberFormatTypeNumber".lower())
        self.globals["xlNumberFormatTypePercent".lower()] = 2
        self.vb_constants.add("xlNumberFormatTypePercent".lower())
        self.globals["xlNumbers".lower()] = 1
        self.vb_constants.add("xlNumbers".lower())
        self.globals["xlOartHorizontalOverflowClip".lower()] = 1
        self.vb_constants.add("xlOartHorizontalOverflowClip".lower())
        self.globals["xlOartHorizontalOverflowOverflow".lower()] = 0
        self.vb_constants.add("xlOartHorizontalOverflowOverflow".lower())
        self.globals["xlOartVerticalOverflowClip".lower()] = 1
        self.vb_constants.add("xlOartVerticalOverflowClip".lower())
        self.globals["xlOartVerticalOverflowEllipsis".lower()] = 2
        self.vb_constants.add("xlOartVerticalOverflowEllipsis".lower())
        self.globals["xlOartVerticalOverflowOverflow".lower()] = 0
        self.vb_constants.add("xlOartVerticalOverflowOverflow".lower())
        self.globals["xlODBCQuery".lower()] = 1
        self.vb_constants.add("xlODBCQuery".lower())
        self.globals["xlOff".lower()] = 4146
        self.vb_constants.add("xlOff".lower())
        self.globals["xlOLEControl".lower()] = 2
        self.vb_constants.add("xlOLEControl".lower())
        self.globals["xlOLEDBQuery".lower()] = 5
        self.vb_constants.add("xlOLEDBQuery".lower())
        self.globals["xlOLEEmbed".lower()] = 1
        self.vb_constants.add("xlOLEEmbed".lower())
        self.globals["xlOLELink".lower()] = 0
        self.vb_constants.add("xlOLELink".lower())
        self.globals["xlOLELinks".lower()] = 2
        self.vb_constants.add("xlOLELinks".lower())
        self.globals["xlOmittedCells".lower()] = 5
        self.vb_constants.add("xlOmittedCells".lower())
        self.globals["xlOn".lower()] = 1
        self.vb_constants.add("xlOn".lower())
        self.globals["xlOneAfterAnother".lower()] = 1
        self.vb_constants.add("xlOneAfterAnother".lower())
        self.globals["xlOpaque".lower()] = 3
        self.vb_constants.add("xlOpaque".lower())
        self.globals["xlOpen".lower()] = 2
        self.vb_constants.add("xlOpen".lower())
        self.globals["xlOpenDocumentSpreadsheet".lower()] = 60
        self.vb_constants.add("xlOpenDocumentSpreadsheet".lower())
        self.globals["xlOpenSource".lower()] = 3
        self.vb_constants.add("xlOpenSource".lower())
        self.globals["xlOpenXMLAddIn".lower()] = 55
        self.vb_constants.add("xlOpenXMLAddIn".lower())
        self.globals["xlOpenXMLStrictWorkbook".lower()] = 61
        self.vb_constants.add("xlOpenXMLStrictWorkbook".lower())
        self.globals["xlOpenXMLTemplate".lower()] = 54
        self.vb_constants.add("xlOpenXMLTemplate".lower())
        self.globals["xlOpenXMLTemplateMacroEnabled".lower()] = 53
        self.vb_constants.add("xlOpenXMLTemplateMacroEnabled".lower())
        self.globals["xlOpenXMLWorkbook".lower()] = 51
        self.vb_constants.add("xlOpenXMLWorkbook".lower())
        self.globals["xlOpenXMLWorkbookMacroEnabled".lower()] = 52
        self.vb_constants.add("xlOpenXMLWorkbookMacroEnabled".lower())
        self.globals["xlOptionButton".lower()] = 7
        self.vb_constants.add("xlOptionButton".lower())
        self.globals["xlOr".lower()] = 2
        self.vb_constants.add("xlOr".lower())
        self.globals["xlOrigin".lower()] = 3
        self.vb_constants.add("xlOrigin".lower())
        self.globals["xlOtherSessionChanges".lower()] = 3
        self.vb_constants.add("xlOtherSessionChanges".lower())
        self.globals["xlOuterCenterPoint".lower()] = 2
        self.vb_constants.add("xlOuterCenterPoint".lower())
        self.globals["xlOuterClockwisePoint".lower()] = 3
        self.vb_constants.add("xlOuterClockwisePoint".lower())
        self.globals["xlOuterCounterClockwisePoint".lower()] = 1
        self.vb_constants.add("xlOuterCounterClockwisePoint".lower())
        self.globals["xlOutline".lower()] = 1
        self.vb_constants.add("xlOutline".lower())
        self.globals["xlOutlineRow".lower()] = 2
        self.vb_constants.add("xlOutlineRow".lower())
        self.globals["xlOutside".lower()] = 3
        self.vb_constants.add("xlOutside".lower())
        self.globals["xlOverThenDown".lower()] = 2
        self.vb_constants.add("xlOverThenDown".lower())
        self.globals["xlOverwriteCells".lower()] = 0
        self.vb_constants.add("xlOverwriteCells".lower())
        self.globals["xlPageBreakAutomatic".lower()] = 4105
        self.vb_constants.add("xlPageBreakAutomatic".lower())
        self.globals["xlPageBreakFull".lower()] = 1
        self.vb_constants.add("xlPageBreakFull".lower())
        self.globals["xlPageBreakManual".lower()] = 4135
        self.vb_constants.add("xlPageBreakManual".lower())
        self.globals["xlPageBreakNone".lower()] = 4142
        self.vb_constants.add("xlPageBreakNone".lower())
        self.globals["xlPageBreakPartial".lower()] = 2
        self.vb_constants.add("xlPageBreakPartial".lower())
        self.globals["xlPageBreakPreview".lower()] = 2
        self.vb_constants.add("xlPageBreakPreview".lower())
        self.globals["xlPageField".lower()] = 3
        self.vb_constants.add("xlPageField".lower())
        self.globals["xlPageFieldLabels".lower()] = 26
        self.vb_constants.add("xlPageFieldLabels".lower())
        self.globals["xlPageFieldValues".lower()] = 27
        self.vb_constants.add("xlPageFieldValues".lower())
        self.globals["xlPageHeader".lower()] = 2
        self.vb_constants.add("xlPageHeader".lower())
        self.globals["xlPageItem".lower()] = 6
        self.vb_constants.add("xlPageItem".lower())
        self.globals["xlPageLayoutView".lower()] = 3
        self.vb_constants.add("xlPageLayoutView".lower())
        self.globals["xlPaper10x14".lower()] = 16
        self.vb_constants.add("xlPaper10x14".lower())
        self.globals["xlPaper11x17".lower()] = 17
        self.vb_constants.add("xlPaper11x17".lower())
        self.globals["xlPaperA3".lower()] = 8
        self.vb_constants.add("xlPaperA3".lower())
        self.globals["xlPaperA4".lower()] = 9
        self.vb_constants.add("xlPaperA4".lower())
        self.globals["xlPaperA4Small".lower()] = 10
        self.vb_constants.add("xlPaperA4Small".lower())
        self.globals["xlPaperA5".lower()] = 11
        self.vb_constants.add("xlPaperA5".lower())
        self.globals["xlPaperB4".lower()] = 12
        self.vb_constants.add("xlPaperB4".lower())
        self.globals["xlPaperB5".lower()] = 13
        self.vb_constants.add("xlPaperB5".lower())
        self.globals["xlPaperCsheet".lower()] = 24
        self.vb_constants.add("xlPaperCsheet".lower())
        self.globals["xlPaperDsheet".lower()] = 25
        self.vb_constants.add("xlPaperDsheet".lower())
        self.globals["xlPaperEnvelope10".lower()] = 20
        self.vb_constants.add("xlPaperEnvelope10".lower())
        self.globals["xlPaperEnvelope11".lower()] = 21
        self.vb_constants.add("xlPaperEnvelope11".lower())
        self.globals["xlPaperEnvelope12".lower()] = 22
        self.vb_constants.add("xlPaperEnvelope12".lower())
        self.globals["xlPaperEnvelope14".lower()] = 23
        self.vb_constants.add("xlPaperEnvelope14".lower())
        self.globals["xlPaperEnvelope9".lower()] = 19
        self.vb_constants.add("xlPaperEnvelope9".lower())
        self.globals["xlPaperEnvelopeB4".lower()] = 33
        self.vb_constants.add("xlPaperEnvelopeB4".lower())
        self.globals["xlPaperEnvelopeB5".lower()] = 34
        self.vb_constants.add("xlPaperEnvelopeB5".lower())
        self.globals["xlPaperEnvelopeB6".lower()] = 35
        self.vb_constants.add("xlPaperEnvelopeB6".lower())
        self.globals["xlPaperEnvelopeC3".lower()] = 29
        self.vb_constants.add("xlPaperEnvelopeC3".lower())
        self.globals["xlPaperEnvelopeC4".lower()] = 30
        self.vb_constants.add("xlPaperEnvelopeC4".lower())
        self.globals["xlPaperEnvelopeC5".lower()] = 28
        self.vb_constants.add("xlPaperEnvelopeC5".lower())
        self.globals["xlPaperEnvelopeC6".lower()] = 31
        self.vb_constants.add("xlPaperEnvelopeC6".lower())
        self.globals["xlPaperEnvelopeC65".lower()] = 32
        self.vb_constants.add("xlPaperEnvelopeC65".lower())
        self.globals["xlPaperEnvelopeDL".lower()] = 27
        self.vb_constants.add("xlPaperEnvelopeDL".lower())
        self.globals["xlPaperEnvelopeItaly".lower()] = 36
        self.vb_constants.add("xlPaperEnvelopeItaly".lower())
        self.globals["xlPaperEnvelopeMonarch".lower()] = 37
        self.vb_constants.add("xlPaperEnvelopeMonarch".lower())
        self.globals["xlPaperEnvelopePersonal".lower()] = 38
        self.vb_constants.add("xlPaperEnvelopePersonal".lower())
        self.globals["xlPaperEsheet".lower()] = 26
        self.vb_constants.add("xlPaperEsheet".lower())
        self.globals["xlPaperExecutive".lower()] = 7
        self.vb_constants.add("xlPaperExecutive".lower())
        self.globals["xlPaperFanfoldLegalGerman".lower()] = 41
        self.vb_constants.add("xlPaperFanfoldLegalGerman".lower())
        self.globals["xlPaperFanfoldStdGerman".lower()] = 40
        self.vb_constants.add("xlPaperFanfoldStdGerman".lower())
        self.globals["xlPaperFanfoldUS".lower()] = 39
        self.vb_constants.add("xlPaperFanfoldUS".lower())
        self.globals["xlPaperFolio".lower()] = 14
        self.vb_constants.add("xlPaperFolio".lower())
        self.globals["xlPaperLedger".lower()] = 4
        self.vb_constants.add("xlPaperLedger".lower())
        self.globals["xlPaperLegal".lower()] = 5
        self.vb_constants.add("xlPaperLegal".lower())
        self.globals["xlPaperLetter".lower()] = 1
        self.vb_constants.add("xlPaperLetter".lower())
        self.globals["xlPaperLetterSmall".lower()] = 2
        self.vb_constants.add("xlPaperLetterSmall".lower())
        self.globals["xlPaperNote".lower()] = 18
        self.vb_constants.add("xlPaperNote".lower())
        self.globals["xlPaperQuarto".lower()] = 15
        self.vb_constants.add("xlPaperQuarto".lower())
        self.globals["xlPaperStatement".lower()] = 6
        self.vb_constants.add("xlPaperStatement".lower())
        self.globals["xlPaperTabloid".lower()] = 3
        self.vb_constants.add("xlPaperTabloid".lower())
        self.globals["xlPaperUser".lower()] = 256
        self.vb_constants.add("xlPaperUser".lower())
        self.globals["xlParamTypeBigInt".lower()] = 5
        self.vb_constants.add("xlParamTypeBigInt".lower())
        self.globals["xlParamTypeBinary".lower()] = 2
        self.vb_constants.add("xlParamTypeBinary".lower())
        self.globals["xlParamTypeBit".lower()] = 7
        self.vb_constants.add("xlParamTypeBit".lower())
        self.globals["xlParamTypeChar".lower()] = 1
        self.vb_constants.add("xlParamTypeChar".lower())
        self.globals["xlParamTypeDate".lower()] = 9
        self.vb_constants.add("xlParamTypeDate".lower())
        self.globals["xlParamTypeDecimal".lower()] = 3
        self.vb_constants.add("xlParamTypeDecimal".lower())
        self.globals["xlParamTypeDouble".lower()] = 8
        self.vb_constants.add("xlParamTypeDouble".lower())
        self.globals["xlParamTypeFloat".lower()] = 6
        self.vb_constants.add("xlParamTypeFloat".lower())
        self.globals["xlParamTypeInteger".lower()] = 4
        self.vb_constants.add("xlParamTypeInteger".lower())
        self.globals["xlParamTypeLongVarBinary".lower()] = 4
        self.vb_constants.add("xlParamTypeLongVarBinary".lower())
        self.globals["xlParamTypeLongVarChar".lower()] = 1
        self.vb_constants.add("xlParamTypeLongVarChar".lower())
        self.globals["xlParamTypeNumeric".lower()] = 2
        self.vb_constants.add("xlParamTypeNumeric".lower())
        self.globals["xlParamTypeReal".lower()] = 7
        self.vb_constants.add("xlParamTypeReal".lower())
        self.globals["xlParamTypeSmallInt".lower()] = 5
        self.vb_constants.add("xlParamTypeSmallInt".lower())
        self.globals["xlParamTypeTime".lower()] = 10
        self.vb_constants.add("xlParamTypeTime".lower())
        self.globals["xlParamTypeTimestamp".lower()] = 11
        self.vb_constants.add("xlParamTypeTimestamp".lower())
        self.globals["xlParamTypeTinyInt".lower()] = 6
        self.vb_constants.add("xlParamTypeTinyInt".lower())
        self.globals["xlParamTypeUnknown".lower()] = 0
        self.vb_constants.add("xlParamTypeUnknown".lower())
        self.globals["xlParamTypeVarBinary".lower()] = 3
        self.vb_constants.add("xlParamTypeVarBinary".lower())
        self.globals["xlParamTypeVarChar".lower()] = 12
        self.vb_constants.add("xlParamTypeVarChar".lower())
        self.globals["xlParamTypeWChar".lower()] = 8
        self.vb_constants.add("xlParamTypeWChar".lower())
        self.globals["xlParentDataLabelOptionsBanner".lower()] = 1
        self.vb_constants.add("xlParentDataLabelOptionsBanner".lower())
        self.globals["xlParentDataLabelOptionsNone".lower()] = 0
        self.vb_constants.add("xlParentDataLabelOptionsNone".lower())
        self.globals["xlParentDataLabelOptionsOverlapping".lower()] = 2
        self.vb_constants.add("xlParentDataLabelOptionsOverlapping".lower())
        self.globals["xlPareto".lower()] = 122
        self.vb_constants.add("xlPareto".lower())
        self.globals["xlPart".lower()] = 2
        self.vb_constants.add("xlPart".lower())
        self.globals["xlPartial".lower()] = 3
        self.vb_constants.add("xlPartial".lower())
        self.globals["xlPartialScript".lower()] = 2
        self.vb_constants.add("xlPartialScript".lower())
        self.globals["xlPasteAll".lower()] = 4104
        self.vb_constants.add("xlPasteAll".lower())
        self.globals["xlPasteAllExceptBorders".lower()] = 7
        self.vb_constants.add("xlPasteAllExceptBorders".lower())
        self.globals["xlPasteAllMergingConditionalFormats".lower()] = 14
        self.vb_constants.add("xlPasteAllMergingConditionalFormats".lower())
        self.globals["xlPasteAllUsingSourceTheme".lower()] = 13
        self.vb_constants.add("xlPasteAllUsingSourceTheme".lower())
        self.globals["xlPasteColumnWidths".lower()] = 8
        self.vb_constants.add("xlPasteColumnWidths".lower())
        self.globals["xlPasteComments".lower()] = 4144
        self.vb_constants.add("xlPasteComments".lower())
        self.globals["xlPasteFormats".lower()] = 4122
        self.vb_constants.add("xlPasteFormats".lower())
        self.globals["xlPasteFormulas".lower()] = 4123
        self.vb_constants.add("xlPasteFormulas".lower())
        self.globals["xlPasteFormulasAndNumberFormats".lower()] = 11
        self.vb_constants.add("xlPasteFormulasAndNumberFormats".lower())
        self.globals["xlPasteSpecialOperationAdd".lower()] = 2
        self.vb_constants.add("xlPasteSpecialOperationAdd".lower())
        self.globals["xlPasteSpecialOperationDivide".lower()] = 5
        self.vb_constants.add("xlPasteSpecialOperationDivide".lower())
        self.globals["xlPasteSpecialOperationMultiply".lower()] = 4
        self.vb_constants.add("xlPasteSpecialOperationMultiply".lower())
        self.globals["xlPasteSpecialOperationNone".lower()] = 4142
        self.vb_constants.add("xlPasteSpecialOperationNone".lower())
        self.globals["xlPasteSpecialOperationSubtract".lower()] = 3
        self.vb_constants.add("xlPasteSpecialOperationSubtract".lower())
        self.globals["xlPasteValidation".lower()] = 6
        self.vb_constants.add("xlPasteValidation".lower())
        self.globals["xlPasteValues".lower()] = 4163
        self.vb_constants.add("xlPasteValues".lower())
        self.globals["xlPasteValuesAndNumberFormats".lower()] = 12
        self.vb_constants.add("xlPasteValuesAndNumberFormats".lower())
        self.globals["xlPatternAutomatic".lower()] = 4105
        self.vb_constants.add("xlPatternAutomatic".lower())
        self.globals["xlPatternChecker".lower()] = 9
        self.vb_constants.add("xlPatternChecker".lower())
        self.globals["xlPatternCrissCross".lower()] = 16
        self.vb_constants.add("xlPatternCrissCross".lower())
        self.globals["xlPatternDown".lower()] = 4121
        self.vb_constants.add("xlPatternDown".lower())
        self.globals["xlPatternGray16".lower()] = 17
        self.vb_constants.add("xlPatternGray16".lower())
        self.globals["xlPatternGray25".lower()] = 4124
        self.vb_constants.add("xlPatternGray25".lower())
        self.globals["xlPatternGray50".lower()] = 4125
        self.vb_constants.add("xlPatternGray50".lower())
        self.globals["xlPatternGray75".lower()] = 4126
        self.vb_constants.add("xlPatternGray75".lower())
        self.globals["xlPatternGray8".lower()] = 18
        self.vb_constants.add("xlPatternGray8".lower())
        self.globals["xlPatternGrid".lower()] = 15
        self.vb_constants.add("xlPatternGrid".lower())
        self.globals["xlPatternHorizontal".lower()] = 4128
        self.vb_constants.add("xlPatternHorizontal".lower())
        self.globals["xlPatternLightDown".lower()] = 13
        self.vb_constants.add("xlPatternLightDown".lower())
        self.globals["xlPatternLightHorizontal".lower()] = 11
        self.vb_constants.add("xlPatternLightHorizontal".lower())
        self.globals["xlPatternLightUp".lower()] = 14
        self.vb_constants.add("xlPatternLightUp".lower())
        self.globals["xlPatternLightVertical".lower()] = 12
        self.vb_constants.add("xlPatternLightVertical".lower())
        self.globals["xlPatternLinearGradient".lower()] = 4000
        self.vb_constants.add("xlPatternLinearGradient".lower())
        self.globals["xlPatternNone".lower()] = 4142
        self.vb_constants.add("xlPatternNone".lower())
        self.globals["xlPatternRectangularGradient".lower()] = 4001
        self.vb_constants.add("xlPatternRectangularGradient".lower())
        self.globals["xlPatternSemiGray75".lower()] = 10
        self.vb_constants.add("xlPatternSemiGray75".lower())
        self.globals["xlPatternSolid".lower()] = 1
        self.vb_constants.add("xlPatternSolid".lower())
        self.globals["xlPatternUp".lower()] = 4162
        self.vb_constants.add("xlPatternUp".lower())
        self.globals["xlPatternVertical".lower()] = 4166
        self.vb_constants.add("xlPatternVertical".lower())
        self.globals["xlPCT".lower()] = 13
        self.vb_constants.add("xlPCT".lower())
        self.globals["xlPCX".lower()] = 10
        self.vb_constants.add("xlPCX".lower())
        self.globals["xlPending".lower()] = 2
        self.vb_constants.add("xlPending".lower())
        self.globals["xlPercent".lower()] = 2
        self.vb_constants.add("xlPercent".lower())
        self.globals["xlPercentDifferenceFrom".lower()] = 4
        self.vb_constants.add("xlPercentDifferenceFrom".lower())
        self.globals["xlPercentOf".lower()] = 3
        self.vb_constants.add("xlPercentOf".lower())
        self.globals["xlPercentOfColumn".lower()] = 7
        self.vb_constants.add("xlPercentOfColumn".lower())
        self.globals["xlPercentOfParent".lower()] = 12
        self.vb_constants.add("xlPercentOfParent".lower())
        self.globals["xlPercentOfParentColumn".lower()] = 11
        self.vb_constants.add("xlPercentOfParentColumn".lower())
        self.globals["xlPercentOfParentRow".lower()] = 10
        self.vb_constants.add("xlPercentOfParentRow".lower())
        self.globals["xlPercentOfRow".lower()] = 6
        self.vb_constants.add("xlPercentOfRow".lower())
        self.globals["xlPercentOfTotal".lower()] = 8
        self.vb_constants.add("xlPercentOfTotal".lower())
        self.globals["xlPercentRunningTotal".lower()] = 13
        self.vb_constants.add("xlPercentRunningTotal".lower())
        self.globals["xlPhoneticAlignCenter".lower()] = 2
        self.vb_constants.add("xlPhoneticAlignCenter".lower())
        self.globals["xlPhoneticAlignDistributed".lower()] = 3
        self.vb_constants.add("xlPhoneticAlignDistributed".lower())
        self.globals["xlPhoneticAlignLeft".lower()] = 1
        self.vb_constants.add("xlPhoneticAlignLeft".lower())
        self.globals["xlPhoneticAlignNoControl".lower()] = 0
        self.vb_constants.add("xlPhoneticAlignNoControl".lower())
        self.globals["xlPIC".lower()] = 11
        self.vb_constants.add("xlPIC".lower())
        self.globals["xlPICT".lower()] = 1
        self.vb_constants.add("xlPICT".lower())
        self.globals["xlPicture".lower()] = 4147
        self.vb_constants.add("xlPicture".lower())
        self.globals["xlPie".lower()] = 5
        self.vb_constants.add("xlPie".lower())
        self.globals["xlPieExploded".lower()] = 69
        self.vb_constants.add("xlPieExploded".lower())
        self.globals["xlPieOfPie".lower()] = 68
        self.vb_constants.add("xlPieOfPie".lower())
        self.globals["xlPinYin".lower()] = 1
        self.vb_constants.add("xlPinYin".lower())
        self.globals["xlPivotCellBlankCell".lower()] = 9
        self.vb_constants.add("xlPivotCellBlankCell".lower())
        self.globals["xlPivotCellCustomSubtotal".lower()] = 7
        self.vb_constants.add("xlPivotCellCustomSubtotal".lower())
        self.globals["xlPivotCellDataField".lower()] = 4
        self.vb_constants.add("xlPivotCellDataField".lower())
        self.globals["xlPivotCellDataPivotField".lower()] = 8
        self.vb_constants.add("xlPivotCellDataPivotField".lower())
        self.globals["xlPivotCellGrandTotal".lower()] = 3
        self.vb_constants.add("xlPivotCellGrandTotal".lower())
        self.globals["xlPivotCellPageFieldItem".lower()] = 6
        self.vb_constants.add("xlPivotCellPageFieldItem".lower())
        self.globals["xlPivotCellPivotField".lower()] = 5
        self.vb_constants.add("xlPivotCellPivotField".lower())
        self.globals["xlPivotCellPivotItem".lower()] = 1
        self.vb_constants.add("xlPivotCellPivotItem".lower())
        self.globals["xlPivotCellSubtotal".lower()] = 2
        self.vb_constants.add("xlPivotCellSubtotal".lower())
        self.globals["xlPivotCellValue".lower()] = 0
        self.vb_constants.add("xlPivotCellValue".lower())
        self.globals["xlPivotChartCollapseEntireFieldButton".lower()] = 34
        self.vb_constants.add("xlPivotChartCollapseEntireFieldButton".lower())
        self.globals["xlPivotChartDropZone".lower()] = 32
        self.vb_constants.add("xlPivotChartDropZone".lower())
        self.globals["xlPivotChartExpandEntireFieldButton".lower()] = 33
        self.vb_constants.add("xlPivotChartExpandEntireFieldButton".lower())
        self.globals["xlPivotChartFieldButton".lower()] = 31
        self.vb_constants.add("xlPivotChartFieldButton".lower())
        self.globals["xlPivotLineBlank".lower()] = 3
        self.vb_constants.add("xlPivotLineBlank".lower())
        self.globals["xlPivotLineGrandTotal".lower()] = 2
        self.vb_constants.add("xlPivotLineGrandTotal".lower())
        self.globals["xlPivotLineRegular".lower()] = 0
        self.vb_constants.add("xlPivotLineRegular".lower())
        self.globals["xlPivotLineSubtotal".lower()] = 1
        self.vb_constants.add("xlPivotLineSubtotal".lower())
        self.globals["xlPivotTable".lower()] = 4148
        self.vb_constants.add("xlPivotTable".lower())
        self.globals["xlPivotTableReport".lower()] = 1
        self.vb_constants.add("xlPivotTableReport".lower())
        self.globals["xlPivotTableVersion10".lower()] = 1
        self.vb_constants.add("xlPivotTableVersion10".lower())
        self.globals["xlPivotTableVersion11".lower()] = 2
        self.vb_constants.add("xlPivotTableVersion11".lower())
        self.globals["xlPivotTableVersion12".lower()] = 3
        self.vb_constants.add("xlPivotTableVersion12".lower())
        self.globals["xlPivotTableVersion14".lower()] = 4
        self.vb_constants.add("xlPivotTableVersion14".lower())
        self.globals["xlPivotTableVersion15".lower()] = 5
        self.vb_constants.add("xlPivotTableVersion15".lower())
        self.globals["xlPivotTableVersion2000".lower()] = 0
        self.vb_constants.add("xlPivotTableVersion2000".lower())
        self.globals["xlPivotTableVersionCurrent".lower()] = 1
        self.vb_constants.add("xlPivotTableVersionCurrent".lower())
        self.globals["xlPlaceholders".lower()] = 2
        self.vb_constants.add("xlPlaceholders".lower())
        self.globals["xlPlotArea".lower()] = 19
        self.vb_constants.add("xlPlotArea".lower())
        self.globals["xlPLT".lower()] = 12
        self.vb_constants.add("xlPLT".lower())
        self.globals["xlPlus".lower()] = 9
        self.vb_constants.add("xlPlus".lower())
        self.globals["xlPlusValues".lower()] = 2
        self.vb_constants.add("xlPlusValues".lower())
        self.globals["xlPolynomial".lower()] = 3
        self.vb_constants.add("xlPolynomial".lower())
        self.globals["xlPortrait".lower()] = 1
        self.vb_constants.add("xlPortrait".lower())
        self.globals["xlPortugueseBoth".lower()] = 3
        self.vb_constants.add("xlPortugueseBoth".lower())
        self.globals["xlPortuguesePostReform".lower()] = 2
        self.vb_constants.add("xlPortuguesePostReform".lower())
        self.globals["xlPortuguesePreReform".lower()] = 1
        self.vb_constants.add("xlPortuguesePreReform".lower())
        self.globals["xlPower".lower()] = 4
        self.vb_constants.add("xlPower".lower())
        self.globals["xlPowerTalk".lower()] = 2
        self.vb_constants.add("xlPowerTalk".lower())
        self.globals["xlPrevious".lower()] = 2
        self.vb_constants.add("xlPrevious".lower())
        self.globals["xlPrimary".lower()] = 1
        self.vb_constants.add("xlPrimary".lower())
        self.globals["xlPrimaryButton".lower()] = 1
        self.vb_constants.add("xlPrimaryButton".lower())
        self.globals["xlPrinter".lower()] = 2
        self.vb_constants.add("xlPrinter".lower())
        self.globals["xlPrintErrorsBlank".lower()] = 1
        self.vb_constants.add("xlPrintErrorsBlank".lower())
        self.globals["xlPrintErrorsDash".lower()] = 2
        self.vb_constants.add("xlPrintErrorsDash".lower())
        self.globals["xlPrintErrorsDisplayed".lower()] = 0
        self.vb_constants.add("xlPrintErrorsDisplayed".lower())
        self.globals["xlPrintErrorsNA".lower()] = 3
        self.vb_constants.add("xlPrintErrorsNA".lower())
        self.globals["xlPrintInPlace".lower()] = 16
        self.vb_constants.add("xlPrintInPlace".lower())
        self.globals["xlPrintNoComments".lower()] = 4142
        self.vb_constants.add("xlPrintNoComments".lower())
        self.globals["xlPrintSheetEnd".lower()] = 1
        self.vb_constants.add("xlPrintSheetEnd".lower())
        self.globals["xlPriorityHigh".lower()] = 4127
        self.vb_constants.add("xlPriorityHigh".lower())
        self.globals["xlPriorityLow".lower()] = 4134
        self.vb_constants.add("xlPriorityLow".lower())
        self.globals["xlPriorityNormal".lower()] = 4143
        self.vb_constants.add("xlPriorityNormal".lower())
        self.globals["xlProduct".lower()] = 4149
        self.vb_constants.add("xlProduct".lower())
        self.globals["xlPrompt".lower()] = 0
        self.vb_constants.add("xlPrompt".lower())
        self.globals["xlProtectedViewCloseEdit".lower()] = 1
        self.vb_constants.add("xlProtectedViewCloseEdit".lower())
        self.globals["xlProtectedViewCloseForced".lower()] = 2
        self.vb_constants.add("xlProtectedViewCloseForced".lower())
        self.globals["xlProtectedViewCloseNormal".lower()] = 0
        self.vb_constants.add("xlProtectedViewCloseNormal".lower())
        self.globals["xlProtectedViewWindowMaximized".lower()] = 2
        self.vb_constants.add("xlProtectedViewWindowMaximized".lower())
        self.globals["xlProtectedViewWindowMinimized".lower()] = 1
        self.vb_constants.add("xlProtectedViewWindowMinimized".lower())
        self.globals["xlProtectedViewWindowNormal".lower()] = 0
        self.vb_constants.add("xlProtectedViewWindowNormal".lower())
        self.globals["xlPTClassic".lower()] = 20
        self.vb_constants.add("xlPTClassic".lower())
        self.globals["xlPTNone".lower()] = 21
        self.vb_constants.add("xlPTNone".lower())
        self.globals["xlPublisher".lower()] = 1
        self.vb_constants.add("xlPublisher".lower())
        self.globals["xlPublishers".lower()] = 5
        self.vb_constants.add("xlPublishers".lower())
        self.globals["xlPyramidBarClustered".lower()] = 109
        self.vb_constants.add("xlPyramidBarClustered".lower())
        self.globals["xlPyramidBarStacked".lower()] = 110
        self.vb_constants.add("xlPyramidBarStacked".lower())
        self.globals["xlPyramidBarStacked100".lower()] = 111
        self.vb_constants.add("xlPyramidBarStacked100".lower())
        self.globals["xlPyramidCol".lower()] = 112
        self.vb_constants.add("xlPyramidCol".lower())
        self.globals["xlPyramidColClustered".lower()] = 106
        self.vb_constants.add("xlPyramidColClustered".lower())
        self.globals["xlPyramidColStacked".lower()] = 107
        self.vb_constants.add("xlPyramidColStacked".lower())
        self.globals["xlPyramidColStacked100".lower()] = 108
        self.vb_constants.add("xlPyramidColStacked100".lower())
        self.globals["xlPyramidToMax".lower()] = 2
        self.vb_constants.add("xlPyramidToMax".lower())
        self.globals["xlPyramidToPoint".lower()] = 1
        self.vb_constants.add("xlPyramidToPoint".lower())
        self.globals["xlQualityMinimum".lower()] = 1
        self.vb_constants.add("xlQualityMinimum".lower())
        self.globals["xlQualityStandard".lower()] = 0
        self.vb_constants.add("xlQualityStandard".lower())
        self.globals["xlQueryTable".lower()] = 0
        self.vb_constants.add("xlQueryTable".lower())
        self.globals["xlR1C1".lower()] = 4150
        self.vb_constants.add("xlR1C1".lower())
        self.globals["xlRadar".lower()] = 4151
        self.vb_constants.add("xlRadar".lower())
        self.globals["xlRadarAxisLabels".lower()] = 27
        self.vb_constants.add("xlRadarAxisLabels".lower())
        self.globals["xlRadarFilled".lower()] = 82
        self.vb_constants.add("xlRadarFilled".lower())
        self.globals["xlRadarMarkers".lower()] = 81
        self.vb_constants.add("xlRadarMarkers".lower())
        self.globals["xlRange".lower()] = 2
        self.vb_constants.add("xlRange".lower())
        self.globals["xlRangeAutoFormat3DEffects1".lower()] = 13
        self.vb_constants.add("xlRangeAutoFormat3DEffects1".lower())
        self.globals["xlRangeAutoFormat3DEffects2".lower()] = 14
        self.vb_constants.add("xlRangeAutoFormat3DEffects2".lower())
        self.globals["xlRangeAutoFormatAccounting1".lower()] = 4
        self.vb_constants.add("xlRangeAutoFormatAccounting1".lower())
        self.globals["xlRangeAutoFormatAccounting2".lower()] = 5
        self.vb_constants.add("xlRangeAutoFormatAccounting2".lower())
        self.globals["xlRangeAutoFormatAccounting3".lower()] = 6
        self.vb_constants.add("xlRangeAutoFormatAccounting3".lower())
        self.globals["xlRangeAutoFormatAccounting4".lower()] = 17
        self.vb_constants.add("xlRangeAutoFormatAccounting4".lower())
        self.globals["xlRangeAutoFormatClassic1".lower()] = 1
        self.vb_constants.add("xlRangeAutoFormatClassic1".lower())
        self.globals["xlRangeAutoFormatClassic2".lower()] = 2
        self.vb_constants.add("xlRangeAutoFormatClassic2".lower())
        self.globals["xlRangeAutoFormatClassic3".lower()] = 3
        self.vb_constants.add("xlRangeAutoFormatClassic3".lower())
        self.globals["xlRangeAutoFormatClassicPivotTable".lower()] = 31
        self.vb_constants.add("xlRangeAutoFormatClassicPivotTable".lower())
        self.globals["xlRangeAutoFormatColor1".lower()] = 7
        self.vb_constants.add("xlRangeAutoFormatColor1".lower())
        self.globals["xlRangeAutoFormatColor2".lower()] = 8
        self.vb_constants.add("xlRangeAutoFormatColor2".lower())
        self.globals["xlRangeAutoFormatColor3".lower()] = 9
        self.vb_constants.add("xlRangeAutoFormatColor3".lower())
        self.globals["xlRangeAutoFormatList1".lower()] = 10
        self.vb_constants.add("xlRangeAutoFormatList1".lower())
        self.globals["xlRangeAutoFormatList2".lower()] = 11
        self.vb_constants.add("xlRangeAutoFormatList2".lower())
        self.globals["xlRangeAutoFormatList3".lower()] = 12
        self.vb_constants.add("xlRangeAutoFormatList3".lower())
        self.globals["xlRangeAutoFormatLocalFormat1".lower()] = 15
        self.vb_constants.add("xlRangeAutoFormatLocalFormat1".lower())
        self.globals["xlRangeAutoFormatLocalFormat2".lower()] = 16
        self.vb_constants.add("xlRangeAutoFormatLocalFormat2".lower())
        self.globals["xlRangeAutoFormatLocalFormat3".lower()] = 19
        self.vb_constants.add("xlRangeAutoFormatLocalFormat3".lower())
        self.globals["xlRangeAutoFormatLocalFormat4".lower()] = 20
        self.vb_constants.add("xlRangeAutoFormatLocalFormat4".lower())
        self.globals["xlRangeAutoFormatNone".lower()] = 4142
        self.vb_constants.add("xlRangeAutoFormatNone".lower())
        self.globals["xlRangeAutoFormatPTNone".lower()] = 42
        self.vb_constants.add("xlRangeAutoFormatPTNone".lower())
        self.globals["xlRangeAutoFormatReport1".lower()] = 21
        self.vb_constants.add("xlRangeAutoFormatReport1".lower())
        self.globals["xlRangeAutoFormatReport10".lower()] = 30
        self.vb_constants.add("xlRangeAutoFormatReport10".lower())
        self.globals["xlRangeAutoFormatReport2".lower()] = 22
        self.vb_constants.add("xlRangeAutoFormatReport2".lower())
        self.globals["xlRangeAutoFormatReport3".lower()] = 23
        self.vb_constants.add("xlRangeAutoFormatReport3".lower())
        self.globals["xlRangeAutoFormatReport4".lower()] = 24
        self.vb_constants.add("xlRangeAutoFormatReport4".lower())
        self.globals["xlRangeAutoFormatReport5".lower()] = 25
        self.vb_constants.add("xlRangeAutoFormatReport5".lower())
        self.globals["xlRangeAutoFormatReport6".lower()] = 26
        self.vb_constants.add("xlRangeAutoFormatReport6".lower())
        self.globals["xlRangeAutoFormatReport7".lower()] = 27
        self.vb_constants.add("xlRangeAutoFormatReport7".lower())
        self.globals["xlRangeAutoFormatReport8".lower()] = 28
        self.vb_constants.add("xlRangeAutoFormatReport8".lower())
        self.globals["xlRangeAutoFormatReport9".lower()] = 29
        self.vb_constants.add("xlRangeAutoFormatReport9".lower())
        self.globals["xlRangeAutoFormatSimple".lower()] = 4154
        self.vb_constants.add("xlRangeAutoFormatSimple".lower())
        self.globals["xlRangeAutoFormatTable1".lower()] = 32
        self.vb_constants.add("xlRangeAutoFormatTable1".lower())
        self.globals["xlRangeAutoFormatTable10".lower()] = 41
        self.vb_constants.add("xlRangeAutoFormatTable10".lower())
        self.globals["xlRangeAutoFormatTable2".lower()] = 33
        self.vb_constants.add("xlRangeAutoFormatTable2".lower())
        self.globals["xlRangeAutoFormatTable3".lower()] = 34
        self.vb_constants.add("xlRangeAutoFormatTable3".lower())
        self.globals["xlRangeAutoFormatTable4".lower()] = 35
        self.vb_constants.add("xlRangeAutoFormatTable4".lower())
        self.globals["xlRangeAutoFormatTable5".lower()] = 36
        self.vb_constants.add("xlRangeAutoFormatTable5".lower())
        self.globals["xlRangeAutoFormatTable6".lower()] = 37
        self.vb_constants.add("xlRangeAutoFormatTable6".lower())
        self.globals["xlRangeAutoFormatTable7".lower()] = 38
        self.vb_constants.add("xlRangeAutoFormatTable7".lower())
        self.globals["xlRangeAutoFormatTable8".lower()] = 39
        self.vb_constants.add("xlRangeAutoFormatTable8".lower())
        self.globals["xlRangeAutoFormatTable9".lower()] = 40
        self.vb_constants.add("xlRangeAutoFormatTable9".lower())
        self.globals["xlRangeValueDefault".lower()] = 10
        self.vb_constants.add("xlRangeValueDefault".lower())
        self.globals["xlRangeValueMSPersistXML".lower()] = 12
        self.vb_constants.add("xlRangeValueMSPersistXML".lower())
        self.globals["xlRangeValueXMLSpreadsheet".lower()] = 11
        self.vb_constants.add("xlRangeValueXMLSpreadsheet".lower())
        self.globals["xlRankAscending".lower()] = 14
        self.vb_constants.add("xlRankAscending".lower())
        self.globals["xlRankDecending".lower()] = 15
        self.vb_constants.add("xlRankDecending".lower())
        self.globals["xlRDIAll".lower()] = 99
        self.vb_constants.add("xlRDIAll".lower())
        self.globals["xlRDIComments".lower()] = 1
        self.vb_constants.add("xlRDIComments".lower())
        self.globals["xlRDIContentType".lower()] = 16
        self.vb_constants.add("xlRDIContentType".lower())
        self.globals["xlRDIDefinedNameComments".lower()] = 18
        self.vb_constants.add("xlRDIDefinedNameComments".lower())
        self.globals["xlRDIDocumentManagementPolicy".lower()] = 15
        self.vb_constants.add("xlRDIDocumentManagementPolicy".lower())
        self.globals["xlRDIDocumentProperties".lower()] = 8
        self.vb_constants.add("xlRDIDocumentProperties".lower())
        self.globals["xlRDIDocumentServerProperties".lower()] = 14
        self.vb_constants.add("xlRDIDocumentServerProperties".lower())
        self.globals["xlRDIDocumentWorkspace".lower()] = 10
        self.vb_constants.add("xlRDIDocumentWorkspace".lower())
        self.globals["xlRDIEmailHeader".lower()] = 5
        self.vb_constants.add("xlRDIEmailHeader".lower())
        self.globals["xlRDIExcelDataModel".lower()] = 23
        self.vb_constants.add("xlRDIExcelDataModel".lower())
        self.globals["xlRDIInactiveDataConnections".lower()] = 19
        self.vb_constants.add("xlRDIInactiveDataConnections".lower())
        self.globals["xlRDIInkAnnotations".lower()] = 11
        self.vb_constants.add("xlRDIInkAnnotations".lower())
        self.globals["xlRDIInlineWebExtensions".lower()] = 21
        self.vb_constants.add("xlRDIInlineWebExtensions".lower())
        self.globals["xlRDIPrinterPath".lower()] = 20
        self.vb_constants.add("xlRDIPrinterPath".lower())
        self.globals["xlRDIPublishInfo".lower()] = 13
        self.vb_constants.add("xlRDIPublishInfo".lower())
        self.globals["xlRDIRemovePersonalInformation".lower()] = 4
        self.vb_constants.add("xlRDIRemovePersonalInformation".lower())
        self.globals["xlRDIRoutingSlip".lower()] = 6
        self.vb_constants.add("xlRDIRoutingSlip".lower())
        self.globals["xlRDIScenarioComments".lower()] = 12
        self.vb_constants.add("xlRDIScenarioComments".lower())
        self.globals["xlRDISendForReview".lower()] = 7
        self.vb_constants.add("xlRDISendForReview".lower())
        self.globals["xlRDITaskpaneWebExtensions".lower()] = 22
        self.vb_constants.add("xlRDITaskpaneWebExtensions".lower())
        self.globals["xlReadOnly".lower()] = 3
        self.vb_constants.add("xlReadOnly".lower())
        self.globals["xlReadWrite".lower()] = 2
        self.vb_constants.add("xlReadWrite".lower())
        self.globals["xlRecommendedCharts".lower()] = 2
        self.vb_constants.add("xlRecommendedCharts".lower())
        self.globals["xlReference".lower()] = 4
        self.vb_constants.add("xlReference".lower())
        self.globals["xlRegionLabelOptionsBestFitOnly".lower()] = 1
        self.vb_constants.add("xlRegionLabelOptionsBestFitOnly".lower())
        self.globals["xlRegionLabelOptionsNone".lower()] = 0
        self.vb_constants.add("xlRegionLabelOptionsNone".lower())
        self.globals["xlRegionLabelOptionsShowAll".lower()] = 2
        self.vb_constants.add("xlRegionLabelOptionsShowAll".lower())
        self.globals["xlRegionMap".lower()] = 140
        self.vb_constants.add("xlRegionMap".lower())
        self.globals["xlRelative".lower()] = 4
        self.vb_constants.add("xlRelative".lower())
        self.globals["xlRelRowAbsColumn".lower()] = 3
        self.vb_constants.add("xlRelRowAbsColumn".lower())
        self.globals["xlRepairFile".lower()] = 1
        self.vb_constants.add("xlRepairFile".lower())
        self.globals["xlRepeatLabels".lower()] = 2
        self.vb_constants.add("xlRepeatLabels".lower())
        self.globals["xlReport1".lower()] = 0
        self.vb_constants.add("xlReport1".lower())
        self.globals["xlReport10".lower()] = 9
        self.vb_constants.add("xlReport10".lower())
        self.globals["xlReport2".lower()] = 1
        self.vb_constants.add("xlReport2".lower())
        self.globals["xlReport3".lower()] = 2
        self.vb_constants.add("xlReport3".lower())
        self.globals["xlReport4".lower()] = 3
        self.vb_constants.add("xlReport4".lower())
        self.globals["xlReport5".lower()] = 4
        self.vb_constants.add("xlReport5".lower())
        self.globals["xlReport6".lower()] = 5
        self.vb_constants.add("xlReport6".lower())
        self.globals["xlReport7".lower()] = 6
        self.vb_constants.add("xlReport7".lower())
        self.globals["xlReport8".lower()] = 7
        self.vb_constants.add("xlReport8".lower())
        self.globals["xlReport9".lower()] = 8
        self.vb_constants.add("xlReport9".lower())
        self.globals["xlRight".lower()] = 4152
        self.vb_constants.add("xlRight".lower())
        self.globals["xlRightBrace".lower()] = 13
        self.vb_constants.add("xlRightBrace".lower())
        self.globals["xlRightBracket".lower()] = 11
        self.vb_constants.add("xlRightBracket".lower())
        self.globals["xlRoutingComplete".lower()] = 2
        self.vb_constants.add("xlRoutingComplete".lower())
        self.globals["xlRoutingInProgress".lower()] = 1
        self.vb_constants.add("xlRoutingInProgress".lower())
        self.globals["xlRowField".lower()] = 1
        self.vb_constants.add("xlRowField".lower())
        self.globals["xlRowGroups".lower()] = 1
        self.vb_constants.add("xlRowGroups".lower())
        self.globals["xlRowHeader".lower()] = 4153
        self.vb_constants.add("xlRowHeader".lower())
        self.globals["xlRowItem".lower()] = 4
        self.vb_constants.add("xlRowItem".lower())
        self.globals["xlRowLabels".lower()] = 1
        self.vb_constants.add("xlRowLabels".lower())
        self.globals["xlRows".lower()] = 1
        self.vb_constants.add("xlRows".lower())
        self.globals["xlRowSeparator".lower()] = 15
        self.vb_constants.add("xlRowSeparator".lower())
        self.globals["xlRowStripe1".lower()] = 5
        self.vb_constants.add("xlRowStripe1".lower())
        self.globals["xlRowStripe2".lower()] = 6
        self.vb_constants.add("xlRowStripe2".lower())
        self.globals["xlRowSubheading1".lower()] = 23
        self.vb_constants.add("xlRowSubheading1".lower())
        self.globals["xlRowSubheading2".lower()] = 24
        self.vb_constants.add("xlRowSubheading2".lower())
        self.globals["xlRowSubheading3".lower()] = 25
        self.vb_constants.add("xlRowSubheading3".lower())
        self.globals["xlRowThenColumn".lower()] = 1
        self.vb_constants.add("xlRowThenColumn".lower())
        self.globals["xlRTF".lower()] = 4
        self.vb_constants.add("xlRTF".lower())
        self.globals["xlRTL".lower()] = 5004
        self.vb_constants.add("xlRTL".lower())
        self.globals["xlRunningTotal".lower()] = 5
        self.vb_constants.add("xlRunningTotal".lower())
        self.globals["xlSaveChanges".lower()] = 1
        self.vb_constants.add("xlSaveChanges".lower())
        self.globals["xlScale".lower()] = 3
        self.vb_constants.add("xlScale".lower())
        self.globals["xlScaleLinear".lower()] = 4132
        self.vb_constants.add("xlScaleLinear".lower())
        self.globals["xlScaleLogarithmic".lower()] = 4133
        self.vb_constants.add("xlScaleLogarithmic".lower())
        self.globals["xlScenario".lower()] = 4
        self.vb_constants.add("xlScenario".lower())
        self.globals["xlScreen".lower()] = 1
        self.vb_constants.add("xlScreen".lower())
        self.globals["xlScreenSize".lower()] = 1
        self.vb_constants.add("xlScreenSize".lower())
        self.globals["xlScrollBar".lower()] = 8
        self.vb_constants.add("xlScrollBar".lower())
        self.globals["xlSecondary".lower()] = 2
        self.vb_constants.add("xlSecondary".lower())
        self.globals["xlSecondaryButton".lower()] = 2
        self.vb_constants.add("xlSecondaryButton".lower())
        self.globals["xlSecondCode".lower()] = 24
        self.vb_constants.add("xlSecondCode".lower())
        self.globals["xlSelect".lower()] = 3
        self.vb_constants.add("xlSelect".lower())
        self.globals["xlSelectionScope".lower()] = 0
        self.vb_constants.add("xlSelectionScope".lower())
        self.globals["xlSemiautomatic".lower()] = 2
        self.vb_constants.add("xlSemiautomatic".lower())
        self.globals["xlSemiGray75".lower()] = 10
        self.vb_constants.add("xlSemiGray75".lower())
        self.globals["xlSendPublisher".lower()] = 2
        self.vb_constants.add("xlSendPublisher".lower())
        self.globals["xlSeries".lower()] = 3
        self.vb_constants.add("xlSeries".lower())
        self.globals["xlSeriesAxis".lower()] = 3
        self.vb_constants.add("xlSeriesAxis".lower())
        self.globals["xlSeriesColorGradientStyleDiverging".lower()] = 1
        self.vb_constants.add("xlSeriesColorGradientStyleDiverging".lower())
        self.globals["xlSeriesColorGradientStyleSequential".lower()] = 0
        self.vb_constants.add("xlSeriesColorGradientStyleSequential".lower())
        self.globals["xlSeriesLines".lower()] = 22
        self.vb_constants.add("xlSeriesLines".lower())
        self.globals["xlSeriesNameLevelAll".lower()] = 1
        self.vb_constants.add("xlSeriesNameLevelAll".lower())
        self.globals["xlSeriesNameLevelCustom".lower()] = 2
        self.vb_constants.add("xlSeriesNameLevelCustom".lower())
        self.globals["xlSeriesNameLevelNone".lower()] = 3
        self.vb_constants.add("xlSeriesNameLevelNone".lower())
        self.globals["xlSet".lower()] = 3
        self.vb_constants.add("xlSet".lower())
        self.globals["xlShape".lower()] = 14
        self.vb_constants.add("xlShape".lower())
        self.globals["xlShared".lower()] = 2
        self.vb_constants.add("xlShared".lower())
        self.globals["xlSheetHidden".lower()] = 0
        self.vb_constants.add("xlSheetHidden".lower())
        self.globals["xlSheetVeryHidden".lower()] = 2
        self.vb_constants.add("xlSheetVeryHidden".lower())
        self.globals["xlSheetVisible".lower()] = 1
        self.vb_constants.add("xlSheetVisible".lower())
        self.globals["xlShiftDown".lower()] = 4121
        self.vb_constants.add("xlShiftDown".lower())
        self.globals["xlShiftToLeft".lower()] = 4159
        self.vb_constants.add("xlShiftToLeft".lower())
        self.globals["xlShiftToRight".lower()] = 4161
        self.vb_constants.add("xlShiftToRight".lower())
        self.globals["xlShiftUp".lower()] = 4162
        self.vb_constants.add("xlShiftUp".lower())
        self.globals["xlShort".lower()] = 1
        self.vb_constants.add("xlShort".lower())
        self.globals["xlShowLabel".lower()] = 4
        self.vb_constants.add("xlShowLabel".lower())
        self.globals["xlShowLabelAndPercent".lower()] = 5
        self.vb_constants.add("xlShowLabelAndPercent".lower())
        self.globals["xlShowPercent".lower()] = 3
        self.vb_constants.add("xlShowPercent".lower())
        self.globals["xlShowValue".lower()] = 2
        self.vb_constants.add("xlShowValue".lower())
        self.globals["xlSides".lower()] = 1
        self.vb_constants.add("xlSides".lower())
        self.globals["xlSimple".lower()] = 4154
        self.vb_constants.add("xlSimple".lower())
        self.globals["xlSinceMyLastSave".lower()] = 1
        self.vb_constants.add("xlSinceMyLastSave".lower())
        self.globals["xlSingle".lower()] = 2
        self.vb_constants.add("xlSingle".lower())
        self.globals["xlSingleAccounting".lower()] = 4
        self.vb_constants.add("xlSingleAccounting".lower())
        self.globals["xlSingleQuote".lower()] = 2
        self.vb_constants.add("xlSingleQuote".lower())
        self.globals["xlSizeIsArea".lower()] = 1
        self.vb_constants.add("xlSizeIsArea".lower())
        self.globals["xlSizeIsWidth".lower()] = 2
        self.vb_constants.add("xlSizeIsWidth".lower())
        self.globals["xlSkipColumn".lower()] = 9
        self.vb_constants.add("xlSkipColumn".lower())
        self.globals["xlSlantDashDot".lower()] = 13
        self.vb_constants.add("xlSlantDashDot".lower())
        self.globals["xlSlicer".lower()] = 1
        self.vb_constants.add("xlSlicer".lower())
        self.globals["xlSlicerCrossFilterHideButtonsWithNoData".lower()] = 4
        self.vb_constants.add("xlSlicerCrossFilterHideButtonsWithNoData".lower())
        self.globals["xlSlicerCrossFilterShowItemsWithDataAtTop".lower()] = 2
        self.vb_constants.add("xlSlicerCrossFilterShowItemsWithDataAtTop".lower())
        self.globals["xlSlicerCrossFilterShowItemsWithNoData".lower()] = 3
        self.vb_constants.add("xlSlicerCrossFilterShowItemsWithNoData".lower())
        self.globals["xlSlicerHoveredSelectedItemWithData".lower()] = 33
        self.vb_constants.add("xlSlicerHoveredSelectedItemWithData".lower())
        self.globals["xlSlicerHoveredSelectedItemWithNoData".lower()] = 35
        self.vb_constants.add("xlSlicerHoveredSelectedItemWithNoData".lower())
        self.globals["xlSlicerHoveredUnselectedItemWithData".lower()] = 32
        self.vb_constants.add("xlSlicerHoveredUnselectedItemWithData".lower())
        self.globals["xlSlicerHoveredUnselectedItemWithNoData".lower()] = 34
        self.vb_constants.add("xlSlicerHoveredUnselectedItemWithNoData".lower())
        self.globals["xlSlicerNoCrossFilter".lower()] = 1
        self.vb_constants.add("xlSlicerNoCrossFilter".lower())
        self.globals["xlSlicerSelectedItemWithData".lower()] = 30
        self.vb_constants.add("xlSlicerSelectedItemWithData".lower())
        self.globals["xlSlicerSelectedItemWithNoData".lower()] = 31
        self.vb_constants.add("xlSlicerSelectedItemWithNoData".lower())
        self.globals["xlSlicerSortAscending".lower()] = 2
        self.vb_constants.add("xlSlicerSortAscending".lower())
        self.globals["xlSlicerSortDataSourceOrder".lower()] = 1
        self.vb_constants.add("xlSlicerSortDataSourceOrder".lower())
        self.globals["xlSlicerSortDescending".lower()] = 3
        self.vb_constants.add("xlSlicerSortDescending".lower())
        self.globals["xlSlicerUnselectedItemWithData".lower()] = 28
        self.vb_constants.add("xlSlicerUnselectedItemWithData".lower())
        self.globals["xlSlicerUnselectedItemWithNoData".lower()] = 29
        self.vb_constants.add("xlSlicerUnselectedItemWithNoData".lower())
        self.globals["xlSmartTagControlActiveX".lower()] = 13
        self.vb_constants.add("xlSmartTagControlActiveX".lower())
        self.globals["xlSmartTagControlButton".lower()] = 6
        self.vb_constants.add("xlSmartTagControlButton".lower())
        self.globals["xlSmartTagControlCheckbox".lower()] = 9
        self.vb_constants.add("xlSmartTagControlCheckbox".lower())
        self.globals["xlSmartTagControlCombo".lower()] = 12
        self.vb_constants.add("xlSmartTagControlCombo".lower())
        self.globals["xlSmartTagControlHelp".lower()] = 3
        self.vb_constants.add("xlSmartTagControlHelp".lower())
        self.globals["xlSmartTagControlHelpURL".lower()] = 4
        self.vb_constants.add("xlSmartTagControlHelpURL".lower())
        self.globals["xlSmartTagControlImage".lower()] = 8
        self.vb_constants.add("xlSmartTagControlImage".lower())
        self.globals["xlSmartTagControlLabel".lower()] = 7
        self.vb_constants.add("xlSmartTagControlLabel".lower())
        self.globals["xlSmartTagControlLink".lower()] = 2
        self.vb_constants.add("xlSmartTagControlLink".lower())
        self.globals["xlSmartTagControlListbox".lower()] = 11
        self.vb_constants.add("xlSmartTagControlListbox".lower())
        self.globals["xlSmartTagControlRadioGroup".lower()] = 14
        self.vb_constants.add("xlSmartTagControlRadioGroup".lower())
        self.globals["xlSmartTagControlSeparator".lower()] = 5
        self.vb_constants.add("xlSmartTagControlSeparator".lower())
        self.globals["xlSmartTagControlSmartTag".lower()] = 1
        self.vb_constants.add("xlSmartTagControlSmartTag".lower())
        self.globals["xlSmartTagControlTextbox".lower()] = 10
        self.vb_constants.add("xlSmartTagControlTextbox".lower())
        self.globals["xlSolid".lower()] = 1
        self.vb_constants.add("xlSolid".lower())
        self.globals["xlSortColumns".lower()] = 1
        self.vb_constants.add("xlSortColumns".lower())
        self.globals["xlSortLabels".lower()] = 2
        self.vb_constants.add("xlSortLabels".lower())
        self.globals["xlSortNormal".lower()] = 0
        self.vb_constants.add("xlSortNormal".lower())
        self.globals["xlSortOnCellColor".lower()] = 1
        self.vb_constants.add("xlSortOnCellColor".lower())
        self.globals["xlSortOnFontColor".lower()] = 2
        self.vb_constants.add("xlSortOnFontColor".lower())
        self.globals["xlSortOnIcon".lower()] = 3
        self.vb_constants.add("xlSortOnIcon".lower())
        self.globals["xlSortOnValues".lower()] = 0
        self.vb_constants.add("xlSortOnValues".lower())
        self.globals["xlSortRows".lower()] = 2
        self.vb_constants.add("xlSortRows".lower())
        self.globals["xlSortTextAsNumbers".lower()] = 1
        self.vb_constants.add("xlSortTextAsNumbers".lower())
        self.globals["xlSortValues".lower()] = 1
        self.vb_constants.add("xlSortValues".lower())
        self.globals["xlSourceAutoFilter".lower()] = 3
        self.vb_constants.add("xlSourceAutoFilter".lower())
        self.globals["xlSourceChart".lower()] = 5
        self.vb_constants.add("xlSourceChart".lower())
        self.globals["xlSourcePivotTable".lower()] = 6
        self.vb_constants.add("xlSourcePivotTable".lower())
        self.globals["xlSourcePrintArea".lower()] = 2
        self.vb_constants.add("xlSourcePrintArea".lower())
        self.globals["xlSourceQuery".lower()] = 7
        self.vb_constants.add("xlSourceQuery".lower())
        self.globals["xlSourceRange".lower()] = 4
        self.vb_constants.add("xlSourceRange".lower())
        self.globals["xlSourceSheet".lower()] = 1
        self.vb_constants.add("xlSourceSheet".lower())
        self.globals["xlSourceWorkbook".lower()] = 0
        self.vb_constants.add("xlSourceWorkbook".lower())
        self.globals["xlSpanishTuteoAndVoseo".lower()] = 1
        self.vb_constants.add("xlSpanishTuteoAndVoseo".lower())
        self.globals["xlSpanishTuteoOnly".lower()] = 0
        self.vb_constants.add("xlSpanishTuteoOnly".lower())
        self.globals["xlSpanishVoseoOnly".lower()] = 2
        self.vb_constants.add("xlSpanishVoseoOnly".lower())
        self.globals["xlSparkColumn".lower()] = 2
        self.vb_constants.add("xlSparkColumn".lower())
        self.globals["xlSparkColumnStacked100".lower()] = 3
        self.vb_constants.add("xlSparkColumnStacked100".lower())
        self.globals["xlSparkLine".lower()] = 1
        self.vb_constants.add("xlSparkLine".lower())
        self.globals["xlSparklineColumnsSquare".lower()] = 2
        self.vb_constants.add("xlSparklineColumnsSquare".lower())
        self.globals["xlSparklineNonSquare".lower()] = 0
        self.vb_constants.add("xlSparklineNonSquare".lower())
        self.globals["xlSparklineRowsSquare".lower()] = 1
        self.vb_constants.add("xlSparklineRowsSquare".lower())
        self.globals["xlSparklines".lower()] = 5
        self.vb_constants.add("xlSparklines".lower())
        self.globals["xlSparkScaleCustom".lower()] = 3
        self.vb_constants.add("xlSparkScaleCustom".lower())
        self.globals["xlSparkScaleGroup".lower()] = 1
        self.vb_constants.add("xlSparkScaleGroup".lower())
        self.globals["xlSparkScaleSingle".lower()] = 2
        self.vb_constants.add("xlSparkScaleSingle".lower())
        self.globals["xlSpeakByColumns".lower()] = 1
        self.vb_constants.add("xlSpeakByColumns".lower())
        self.globals["xlSpeakByRows".lower()] = 0
        self.vb_constants.add("xlSpeakByRows".lower())
        self.globals["xlSpecificDate".lower()] = 29
        self.vb_constants.add("xlSpecificDate".lower())
        self.globals["xlSpecifiedTables".lower()] = 3
        self.vb_constants.add("xlSpecifiedTables".lower())
        self.globals["xlSpinner".lower()] = 9
        self.vb_constants.add("xlSpinner".lower())
        self.globals["xlSplitByCustomSplit".lower()] = 4
        self.vb_constants.add("xlSplitByCustomSplit".lower())
        self.globals["xlSplitByPercentValue".lower()] = 3
        self.vb_constants.add("xlSplitByPercentValue".lower())
        self.globals["xlSplitByPosition".lower()] = 1
        self.vb_constants.add("xlSplitByPosition".lower())
        self.globals["xlSplitByValue".lower()] = 2
        self.vb_constants.add("xlSplitByValue".lower())
        self.globals["xlSquare".lower()] = 1
        self.vb_constants.add("xlSquare".lower())
        self.globals["xlSrcExternal".lower()] = 0
        self.vb_constants.add("xlSrcExternal".lower())
        self.globals["xlSrcModel".lower()] = 4
        self.vb_constants.add("xlSrcModel".lower())
        self.globals["xlSrcQuery".lower()] = 3
        self.vb_constants.add("xlSrcQuery".lower())
        self.globals["xlSrcRange".lower()] = 1
        self.vb_constants.add("xlSrcRange".lower())
        self.globals["xlSrcXml".lower()] = 2
        self.vb_constants.add("xlSrcXml".lower())
        self.globals["xlStack".lower()] = 2
        self.vb_constants.add("xlStack".lower())
        self.globals["xlStackScale".lower()] = 3
        self.vb_constants.add("xlStackScale".lower())
        self.globals["xlStandardSummary".lower()] = 1
        self.vb_constants.add("xlStandardSummary".lower())
        self.globals["xlStar".lower()] = 5
        self.vb_constants.add("xlStar".lower())
        self.globals["xlStDev".lower()] = 4155
        self.vb_constants.add("xlStDev".lower())
        self.globals["xlStDevP".lower()] = 4156
        self.vb_constants.add("xlStDevP".lower())
        self.globals["xlStError".lower()] = 4
        self.vb_constants.add("xlStError".lower())
        self.globals["xlStockHLC".lower()] = 88
        self.vb_constants.add("xlStockHLC".lower())
        self.globals["xlStockOHLC".lower()] = 89
        self.vb_constants.add("xlStockOHLC".lower())
        self.globals["xlStockVHLC".lower()] = 90
        self.vb_constants.add("xlStockVHLC".lower())
        self.globals["xlStockVOHLC".lower()] = 91
        self.vb_constants.add("xlStockVOHLC".lower())
        self.globals["xlStretch".lower()] = 1
        self.vb_constants.add("xlStretch".lower())
        self.globals["xlStrict".lower()] = 2
        self.vb_constants.add("xlStrict".lower())
        self.globals["xlStroke".lower()] = 2
        self.vb_constants.add("xlStroke".lower())
        self.globals["xlSubscriber".lower()] = 2
        self.vb_constants.add("xlSubscriber".lower())
        self.globals["xlSubscribers".lower()] = 6
        self.vb_constants.add("xlSubscribers".lower())
        self.globals["xlSubscribeToPicture".lower()] = 4147
        self.vb_constants.add("xlSubscribeToPicture".lower())
        self.globals["xlSubscribeToText".lower()] = 4158
        self.vb_constants.add("xlSubscribeToText".lower())
        self.globals["xlSubtotalColumn1".lower()] = 13
        self.vb_constants.add("xlSubtotalColumn1".lower())
        self.globals["xlSubtotalColumn2".lower()] = 14
        self.vb_constants.add("xlSubtotalColumn2".lower())
        self.globals["xlSubtotalColumn3".lower()] = 15
        self.vb_constants.add("xlSubtotalColumn3".lower())
        self.globals["xlSubtotalRow1".lower()] = 16
        self.vb_constants.add("xlSubtotalRow1".lower())
        self.globals["xlSubtotalRow2".lower()] = 17
        self.vb_constants.add("xlSubtotalRow2".lower())
        self.globals["xlSubtotalRow3".lower()] = 18
        self.vb_constants.add("xlSubtotalRow3".lower())
        self.globals["xlSubtract".lower()] = 3
        self.vb_constants.add("xlSubtract".lower())
        self.globals["xlSum".lower()] = 4157
        self.vb_constants.add("xlSum".lower())
        self.globals["xlSummaryAbove".lower()] = 0
        self.vb_constants.add("xlSummaryAbove".lower())
        self.globals["xlSummaryBelow".lower()] = 1
        self.vb_constants.add("xlSummaryBelow".lower())
        self.globals["xlSummaryOnLeft".lower()] = 4131
        self.vb_constants.add("xlSummaryOnLeft".lower())
        self.globals["xlSummaryOnRight".lower()] = 4152
        self.vb_constants.add("xlSummaryOnRight".lower())
        self.globals["xlSummaryPivotTable".lower()] = 4148
        self.vb_constants.add("xlSummaryPivotTable".lower())
        self.globals["xlSunburst".lower()] = 120
        self.vb_constants.add("xlSunburst".lower())
        self.globals["xlSurface".lower()] = 83
        self.vb_constants.add("xlSurface".lower())
        self.globals["xlSurfaceTopView".lower()] = 85
        self.vb_constants.add("xlSurfaceTopView".lower())
        self.globals["xlSurfaceTopViewWireframe".lower()] = 86
        self.vb_constants.add("xlSurfaceTopViewWireframe".lower())
        self.globals["xlSurfaceWireframe".lower()] = 84
        self.vb_constants.add("xlSurfaceWireframe".lower())
        self.globals["xlSYLK".lower()] = 2
        self.vb_constants.add("xlSYLK".lower())
        self.globals["xlSyllabary".lower()] = 1
        self.vb_constants.add("xlSyllabary".lower())
        self.globals["xlSystem".lower()] = 1
        self.vb_constants.add("xlSystem".lower())
        self.globals["xlTable".lower()] = 2
        self.vb_constants.add("xlTable".lower())
        self.globals["xlTable1".lower()] = 10
        self.vb_constants.add("xlTable1".lower())
        self.globals["xlTable10".lower()] = 19
        self.vb_constants.add("xlTable10".lower())
        self.globals["xlTable2".lower()] = 11
        self.vb_constants.add("xlTable2".lower())
        self.globals["xlTable3".lower()] = 12
        self.vb_constants.add("xlTable3".lower())
        self.globals["xlTable4".lower()] = 13
        self.vb_constants.add("xlTable4".lower())
        self.globals["xlTable5".lower()] = 14
        self.vb_constants.add("xlTable5".lower())
        self.globals["xlTable6".lower()] = 15
        self.vb_constants.add("xlTable6".lower())
        self.globals["xlTable7".lower()] = 16
        self.vb_constants.add("xlTable7".lower())
        self.globals["xlTable8".lower()] = 17
        self.vb_constants.add("xlTable8".lower())
        self.globals["xlTable9".lower()] = 18
        self.vb_constants.add("xlTable9".lower())
        self.globals["xlTableBody".lower()] = 8
        self.vb_constants.add("xlTableBody".lower())
        self.globals["xlTables".lower()] = 4
        self.vb_constants.add("xlTables".lower())
        self.globals["xlTabPositionFirst".lower()] = 0
        self.vb_constants.add("xlTabPositionFirst".lower())
        self.globals["xlTabPositionLast".lower()] = 1
        self.vb_constants.add("xlTabPositionLast".lower())
        self.globals["xlTabular".lower()] = 0
        self.vb_constants.add("xlTabular".lower())
        self.globals["xlTabularRow".lower()] = 1
        self.vb_constants.add("xlTabularRow".lower())
        self.globals["xlTemplate".lower()] = 17
        self.vb_constants.add("xlTemplate".lower())
        self.globals["xlTemplate8".lower()] = 17
        self.vb_constants.add("xlTemplate8".lower())
        self.globals["xlTenMillions".lower()] = 7
        self.vb_constants.add("xlTenMillions".lower())
        self.globals["xlTenThousands".lower()] = 4
        self.vb_constants.add("xlTenThousands".lower())
        self.globals["xlText".lower()] = 4158
        self.vb_constants.add("xlText".lower())
        self.globals["xlTextBox".lower()] = 16
        self.vb_constants.add("xlTextBox".lower())
        self.globals["xlTextDate".lower()] = 2
        self.vb_constants.add("xlTextDate".lower())
        self.globals["xlTextFormat".lower()] = 2
        self.vb_constants.add("xlTextFormat".lower())
        self.globals["xlTextImport".lower()] = 6
        self.vb_constants.add("xlTextImport".lower())
        self.globals["xlTextMac".lower()] = 19
        self.vb_constants.add("xlTextMac".lower())
        self.globals["xlTextMSDOS".lower()] = 21
        self.vb_constants.add("xlTextMSDOS".lower())
        self.globals["xlTextPrinter".lower()] = 36
        self.vb_constants.add("xlTextPrinter".lower())
        self.globals["xlTextQualifierDoubleQuote".lower()] = 1
        self.vb_constants.add("xlTextQualifierDoubleQuote".lower())
        self.globals["xlTextQualifierNone".lower()] = 4142
        self.vb_constants.add("xlTextQualifierNone".lower())
        self.globals["xlTextQualifierSingleQuote".lower()] = 2
        self.vb_constants.add("xlTextQualifierSingleQuote".lower())
        self.globals["xlTextString".lower()] = 9
        self.vb_constants.add("xlTextString".lower())
        self.globals["xlTextValues".lower()] = 2
        self.vb_constants.add("xlTextValues".lower())
        self.globals["xlTextVisualLTR".lower()] = 1
        self.vb_constants.add("xlTextVisualLTR".lower())
        self.globals["xlTextVisualRTL".lower()] = 2
        self.vb_constants.add("xlTextVisualRTL".lower())
        self.globals["xlTextWindows".lower()] = 20
        self.vb_constants.add("xlTextWindows".lower())
        self.globals["xlThemeColorAccent1".lower()] = 5
        self.vb_constants.add("xlThemeColorAccent1".lower())
        self.globals["xlThemeColorAccent2".lower()] = 6
        self.vb_constants.add("xlThemeColorAccent2".lower())
        self.globals["xlThemeColorAccent3".lower()] = 7
        self.vb_constants.add("xlThemeColorAccent3".lower())
        self.globals["xlThemeColorAccent4".lower()] = 8
        self.vb_constants.add("xlThemeColorAccent4".lower())
        self.globals["xlThemeColorAccent5".lower()] = 9
        self.vb_constants.add("xlThemeColorAccent5".lower())
        self.globals["xlThemeColorAccent6".lower()] = 10
        self.vb_constants.add("xlThemeColorAccent6".lower())
        self.globals["xlThemeColorDark1".lower()] = 1
        self.vb_constants.add("xlThemeColorDark1".lower())
        self.globals["xlThemeColorDark2".lower()] = 3
        self.vb_constants.add("xlThemeColorDark2".lower())
        self.globals["xlThemeColorFollowedHyperlink".lower()] = 12
        self.vb_constants.add("xlThemeColorFollowedHyperlink".lower())
        self.globals["xlThemeColorHyperlink".lower()] = 11
        self.vb_constants.add("xlThemeColorHyperlink".lower())
        self.globals["xlThemeColorLight1".lower()] = 2
        self.vb_constants.add("xlThemeColorLight1".lower())
        self.globals["xlThemeColorLight2".lower()] = 4
        self.vb_constants.add("xlThemeColorLight2".lower())
        self.globals["xlThemeFontMajor".lower()] = 1
        self.vb_constants.add("xlThemeFontMajor".lower())
        self.globals["xlThemeFontMinor".lower()] = 2
        self.vb_constants.add("xlThemeFontMinor".lower())
        self.globals["xlThemeFontNone".lower()] = 0
        self.vb_constants.add("xlThemeFontNone".lower())
        self.globals["xlThick".lower()] = 4
        self.vb_constants.add("xlThick".lower())
        self.globals["xlThin".lower()] = 2
        self.vb_constants.add("xlThin".lower())
        self.globals["xlThisMonth".lower()] = 9
        self.vb_constants.add("xlThisMonth".lower())
        self.globals["xlThisWeek".lower()] = 3
        self.vb_constants.add("xlThisWeek".lower())
        self.globals["xlThousandMillions".lower()] = 9
        self.vb_constants.add("xlThousandMillions".lower())
        self.globals["xlThousands".lower()] = 3
        self.vb_constants.add("xlThousands".lower())
        self.globals["xlThousandsSeparator".lower()] = 4
        self.vb_constants.add("xlThousandsSeparator".lower())
        self.globals["xlThreadModeAutomatic".lower()] = 0
        self.vb_constants.add("xlThreadModeAutomatic".lower())
        self.globals["xlThreadModeManual".lower()] = 1
        self.vb_constants.add("xlThreadModeManual".lower())
        self.globals["xlTickLabelOrientationAutomatic".lower()] = 4105
        self.vb_constants.add("xlTickLabelOrientationAutomatic".lower())
        self.globals["xlTickLabelOrientationDownward".lower()] = 4170
        self.vb_constants.add("xlTickLabelOrientationDownward".lower())
        self.globals["xlTickLabelOrientationHorizontal".lower()] = 4128
        self.vb_constants.add("xlTickLabelOrientationHorizontal".lower())
        self.globals["xlTickLabelOrientationUpward".lower()] = 4171
        self.vb_constants.add("xlTickLabelOrientationUpward".lower())
        self.globals["xlTickLabelOrientationVertical".lower()] = 4166
        self.vb_constants.add("xlTickLabelOrientationVertical".lower())
        self.globals["xlTickLabelPositionHigh".lower()] = 4127
        self.vb_constants.add("xlTickLabelPositionHigh".lower())
        self.globals["xlTickLabelPositionLow".lower()] = 4134
        self.vb_constants.add("xlTickLabelPositionLow".lower())
        self.globals["xlTickLabelPositionNextToAxis".lower()] = 4
        self.vb_constants.add("xlTickLabelPositionNextToAxis".lower())
        self.globals["xlTickLabelPositionNone".lower()] = 4142
        self.vb_constants.add("xlTickLabelPositionNone".lower())
        self.globals["xlTickMarkCross".lower()] = 4
        self.vb_constants.add("xlTickMarkCross".lower())
        self.globals["xlTickMarkInside".lower()] = 2
        self.vb_constants.add("xlTickMarkInside".lower())
        self.globals["xlTickMarkNone".lower()] = 4142
        self.vb_constants.add("xlTickMarkNone".lower())
        self.globals["xlTickMarkOutside".lower()] = 3
        self.vb_constants.add("xlTickMarkOutside".lower())
        self.globals["xlTIF".lower()] = 9
        self.vb_constants.add("xlTIF".lower())
        self.globals["xlTiled".lower()] = 1
        self.vb_constants.add("xlTiled".lower())
        self.globals["xlTimeLeadingZero".lower()] = 45
        self.vb_constants.add("xlTimeLeadingZero".lower())
        self.globals["xlTimeline".lower()] = 2
        self.vb_constants.add("xlTimeline".lower())
        self.globals["xlTimelineLevelDays".lower()] = 3
        self.vb_constants.add("xlTimelineLevelDays".lower())
        self.globals["xlTimelineLevelMonths".lower()] = 2
        self.vb_constants.add("xlTimelineLevelMonths".lower())
        self.globals["xlTimelineLevelQuarters".lower()] = 1
        self.vb_constants.add("xlTimelineLevelQuarters".lower())
        self.globals["xlTimelineLevelYears".lower()] = 0
        self.vb_constants.add("xlTimelineLevelYears".lower())
        self.globals["xlTimelinePeriodLabels1".lower()] = 38
        self.vb_constants.add("xlTimelinePeriodLabels1".lower())
        self.globals["xlTimelinePeriodLabels2".lower()] = 39
        self.vb_constants.add("xlTimelinePeriodLabels2".lower())
        self.globals["xlTimelineSelectedTimeBlock".lower()] = 40
        self.vb_constants.add("xlTimelineSelectedTimeBlock".lower())
        self.globals["xlTimelineSelectedTimeBlockSpace".lower()] = 42
        self.vb_constants.add("xlTimelineSelectedTimeBlockSpace".lower())
        self.globals["xlTimelineSelectionLabel".lower()] = 36
        self.vb_constants.add("xlTimelineSelectionLabel".lower())
        self.globals["xlTimelineTimeLevel".lower()] = 37
        self.vb_constants.add("xlTimelineTimeLevel".lower())
        self.globals["xlTimelineUnselectedTimeBlock".lower()] = 41
        self.vb_constants.add("xlTimelineUnselectedTimeBlock".lower())
        self.globals["xlTimePeriod".lower()] = 11
        self.vb_constants.add("xlTimePeriod".lower())
        self.globals["xlTimeScale".lower()] = 3
        self.vb_constants.add("xlTimeScale".lower())
        self.globals["xlTimeSeparator".lower()] = 18
        self.vb_constants.add("xlTimeSeparator".lower())
        self.globals["xlTitleBar".lower()] = 8
        self.vb_constants.add("xlTitleBar".lower())
        self.globals["xlToday".lower()] = 0
        self.vb_constants.add("xlToday".lower())
        self.globals["xlToLeft".lower()] = 4159
        self.vb_constants.add("xlToLeft".lower())
        self.globals["xlTomorrow".lower()] = 6
        self.vb_constants.add("xlTomorrow".lower())
        self.globals["xlToolbar".lower()] = 1
        self.vb_constants.add("xlToolbar".lower())
        self.globals["xlToolbarButton".lower()] = 2
        self.vb_constants.add("xlToolbarButton".lower())
        self.globals["xlToolbarProtectionNone".lower()] = 4143
        self.vb_constants.add("xlToolbarProtectionNone".lower())
        self.globals["xlTop".lower()] = 4160
        self.vb_constants.add("xlTop".lower())
        self.globals["xlTop10".lower()] = 5
        self.vb_constants.add("xlTop10".lower())
        self.globals["xlTop10Bottom".lower()] = 0
        self.vb_constants.add("xlTop10Bottom".lower())
        self.globals["xlTop10Items".lower()] = 3
        self.vb_constants.add("xlTop10Items".lower())
        self.globals["xlTop10Percent".lower()] = 5
        self.vb_constants.add("xlTop10Percent".lower())
        self.globals["xlTop10Top".lower()] = 1
        self.vb_constants.add("xlTop10Top".lower())
        self.globals["xlTopCount".lower()] = 1
        self.vb_constants.add("xlTopCount".lower())
        self.globals["xlTopPercent".lower()] = 3
        self.vb_constants.add("xlTopPercent".lower())
        self.globals["xlTopSum".lower()] = 5
        self.vb_constants.add("xlTopSum".lower())
        self.globals["xlTopToBottom".lower()] = 1
        self.vb_constants.add("xlTopToBottom".lower())
        self.globals["xlToRight".lower()] = 4161
        self.vb_constants.add("xlToRight".lower())
        self.globals["xlTotalRow".lower()] = 2
        self.vb_constants.add("xlTotalRow".lower())
        self.globals["xlTotals".lower()] = 3
        self.vb_constants.add("xlTotals".lower())
        self.globals["xlTotalsCalculationAverage".lower()] = 2
        self.vb_constants.add("xlTotalsCalculationAverage".lower())
        self.globals["xlTotalsCalculationCount".lower()] = 3
        self.vb_constants.add("xlTotalsCalculationCount".lower())
        self.globals["xlTotalsCalculationCountNums".lower()] = 4
        self.vb_constants.add("xlTotalsCalculationCountNums".lower())
        self.globals["xlTotalsCalculationCustom".lower()] = 9
        self.vb_constants.add("xlTotalsCalculationCustom".lower())
        self.globals["xlTotalsCalculationMax".lower()] = 6
        self.vb_constants.add("xlTotalsCalculationMax".lower())
        self.globals["xlTotalsCalculationMin".lower()] = 5
        self.vb_constants.add("xlTotalsCalculationMin".lower())
        self.globals["xlTotalsCalculationNone".lower()] = 0
        self.vb_constants.add("xlTotalsCalculationNone".lower())
        self.globals["xlTotalsCalculationStdDev".lower()] = 7
        self.vb_constants.add("xlTotalsCalculationStdDev".lower())
        self.globals["xlTotalsCalculationSum".lower()] = 1
        self.vb_constants.add("xlTotalsCalculationSum".lower())
        self.globals["xlTotalsCalculationVar".lower()] = 8
        self.vb_constants.add("xlTotalsCalculationVar".lower())
        self.globals["xlTransparent".lower()] = 2
        self.vb_constants.add("xlTransparent".lower())
        self.globals["xlTreemap".lower()] = 117
        self.vb_constants.add("xlTreemap".lower())
        self.globals["xlTrendline".lower()] = 8
        self.vb_constants.add("xlTrendline".lower())
        self.globals["xlTriangle".lower()] = 3
        self.vb_constants.add("xlTriangle".lower())
        self.globals["xlTypePDF".lower()] = 0
        self.vb_constants.add("xlTypePDF".lower())
        self.globals["xlTypeXPS".lower()] = 1
        self.vb_constants.add("xlTypeXPS".lower())
        self.globals["xlUICultureTag".lower()] = 46
        self.vb_constants.add("xlUICultureTag".lower())
        self.globals["xlUnderlineStyleDouble".lower()] = 4119
        self.vb_constants.add("xlUnderlineStyleDouble".lower())
        self.globals["xlUnderlineStyleDoubleAccounting".lower()] = 5
        self.vb_constants.add("xlUnderlineStyleDoubleAccounting".lower())
        self.globals["xlUnderlineStyleNone".lower()] = 4142
        self.vb_constants.add("xlUnderlineStyleNone".lower())
        self.globals["xlUnderlineStyleSingle".lower()] = 2
        self.vb_constants.add("xlUnderlineStyleSingle".lower())
        self.globals["xlUnderlineStyleSingleAccounting".lower()] = 4
        self.vb_constants.add("xlUnderlineStyleSingleAccounting".lower())
        self.globals["xlUnicodeText".lower()] = 42
        self.vb_constants.add("xlUnicodeText".lower())
        self.globals["xlUnique".lower()] = 0
        self.vb_constants.add("xlUnique".lower())
        self.globals["xlUniqueValues".lower()] = 8
        self.vb_constants.add("xlUniqueValues".lower())
        self.globals["xlUnknown".lower()] = 1000
        self.vb_constants.add("xlUnknown".lower())
        self.globals["xlUnlockedCells".lower()] = 1
        self.vb_constants.add("xlUnlockedCells".lower())
        self.globals["xlUnlockedFormulaCells".lower()] = 6
        self.vb_constants.add("xlUnlockedFormulaCells".lower())
        self.globals["xlUp".lower()] = 4162
        self.vb_constants.add("xlUp".lower())
        self.globals["xlUpBars".lower()] = 18
        self.vb_constants.add("xlUpBars".lower())
        self.globals["xlUpdateLinksAlways".lower()] = 3
        self.vb_constants.add("xlUpdateLinksAlways".lower())
        self.globals["xlUpdateLinksNever".lower()] = 2
        self.vb_constants.add("xlUpdateLinksNever".lower())
        self.globals["xlUpdateLinksUserSetting".lower()] = 1
        self.vb_constants.add("xlUpdateLinksUserSetting".lower())
        self.globals["xlUpdateState".lower()] = 1
        self.vb_constants.add("xlUpdateState".lower())
        self.globals["xlUpdateSubscriber".lower()] = 2
        self.vb_constants.add("xlUpdateSubscriber".lower())
        self.globals["xlUpperCaseColumnLetter".lower()] = 7
        self.vb_constants.add("xlUpperCaseColumnLetter".lower())
        self.globals["xlUpperCaseRowLetter".lower()] = 6
        self.vb_constants.add("xlUpperCaseRowLetter".lower())
        self.globals["xlUpward".lower()] = 4171
        self.vb_constants.add("xlUpward".lower())
        self.globals["xlUserDefined".lower()] = 22
        self.vb_constants.add("xlUserDefined".lower())
        self.globals["xlUserResolution".lower()] = 1
        self.vb_constants.add("xlUserResolution".lower())
        self.globals["xlValidAlertInformation".lower()] = 3
        self.vb_constants.add("xlValidAlertInformation".lower())
        self.globals["xlValidAlertStop".lower()] = 1
        self.vb_constants.add("xlValidAlertStop".lower())
        self.globals["xlValidAlertWarning".lower()] = 2
        self.vb_constants.add("xlValidAlertWarning".lower())
        self.globals["xlValidateCustom".lower()] = 7
        self.vb_constants.add("xlValidateCustom".lower())
        self.globals["xlValidateDate".lower()] = 4
        self.vb_constants.add("xlValidateDate".lower())
        self.globals["xlValidateDecimal".lower()] = 2
        self.vb_constants.add("xlValidateDecimal".lower())
        self.globals["xlValidateInputOnly".lower()] = 0
        self.vb_constants.add("xlValidateInputOnly".lower())
        self.globals["xlValidateList".lower()] = 3
        self.vb_constants.add("xlValidateList".lower())
        self.globals["xlValidateTextLength".lower()] = 6
        self.vb_constants.add("xlValidateTextLength".lower())
        self.globals["xlValidateTime".lower()] = 5
        self.vb_constants.add("xlValidateTime".lower())
        self.globals["xlValidateWholeNumber".lower()] = 1
        self.vb_constants.add("xlValidateWholeNumber".lower())
        self.globals["xlVAlignBottom".lower()] = 4107
        self.vb_constants.add("xlVAlignBottom".lower())
        self.globals["xlVAlignCenter".lower()] = 4108
        self.vb_constants.add("xlVAlignCenter".lower())
        self.globals["xlVAlignDistributed".lower()] = 4117
        self.vb_constants.add("xlVAlignDistributed".lower())
        self.globals["xlVAlignJustify".lower()] = 4130
        self.vb_constants.add("xlVAlignJustify".lower())
        self.globals["xlVAlignTop".lower()] = 4160
        self.vb_constants.add("xlVAlignTop".lower())
        self.globals["xlVALU".lower()] = 8
        self.vb_constants.add("xlVALU".lower())
        self.globals["xlValue".lower()] = 2
        self.vb_constants.add("xlValue".lower())
        self.globals["xlValueAscending".lower()] = 1
        self.vb_constants.add("xlValueAscending".lower())
        self.globals["xlValueDescending".lower()] = 2
        self.vb_constants.add("xlValueDescending".lower())
        self.globals["xlValueDoesNotEqual".lower()] = 8
        self.vb_constants.add("xlValueDoesNotEqual".lower())
        self.globals["xlValueEquals".lower()] = 7
        self.vb_constants.add("xlValueEquals".lower())
        self.globals["xlValueIsBetween".lower()] = 13
        self.vb_constants.add("xlValueIsBetween".lower())
        self.globals["xlValueIsGreaterThan".lower()] = 9
        self.vb_constants.add("xlValueIsGreaterThan".lower())
        self.globals["xlValueIsGreaterThanOrEqualTo".lower()] = 10
        self.vb_constants.add("xlValueIsGreaterThanOrEqualTo".lower())
        self.globals["xlValueIsLessThan".lower()] = 11
        self.vb_constants.add("xlValueIsLessThan".lower())
        self.globals["xlValueIsLessThanOrEqualTo".lower()] = 12
        self.vb_constants.add("xlValueIsLessThanOrEqualTo".lower())
        self.globals["xlValueIsNotBetween".lower()] = 14
        self.vb_constants.add("xlValueIsNotBetween".lower())
        self.globals["xlValueNone".lower()] = 0
        self.vb_constants.add("xlValueNone".lower())
        self.globals["xlValues".lower()] = 4163
        self.vb_constants.add("xlValues".lower())
        self.globals["xlVar".lower()] = 4164
        self.vb_constants.add("xlVar".lower())
        self.globals["xlVarP".lower()] = 4165
        self.vb_constants.add("xlVarP".lower())
        self.globals["xlVerbOpen".lower()] = 2
        self.vb_constants.add("xlVerbOpen".lower())
        self.globals["xlVerbPrimary".lower()] = 1
        self.vb_constants.add("xlVerbPrimary".lower())
        self.globals["xlVertical".lower()] = 4166
        self.vb_constants.add("xlVertical".lower())
        self.globals["xlVerticalCoordinate".lower()] = 2
        self.vb_constants.add("xlVerticalCoordinate".lower())
        self.globals["xlVeryHidden".lower()] = 2
        self.vb_constants.add("xlVeryHidden".lower())
        self.globals["xlVisible".lower()] = 12
        self.vb_constants.add("xlVisible".lower())
        self.globals["xlVisualCursor".lower()] = 2
        self.vb_constants.add("xlVisualCursor".lower())
        self.globals["xlWait".lower()] = 2
        self.vb_constants.add("xlWait".lower())
        self.globals["xlWalls".lower()] = 5
        self.vb_constants.add("xlWalls".lower())
        self.globals["xlWatchPane".lower()] = 11
        self.vb_constants.add("xlWatchPane".lower())
        self.globals["xlWaterfall".lower()] = 119
        self.vb_constants.add("xlWaterfall".lower())
        self.globals["xlWBATChart".lower()] = 4109
        self.vb_constants.add("xlWBATChart".lower())
        self.globals["xlWBATExcel4IntlMacroSheet".lower()] = 4
        self.vb_constants.add("xlWBATExcel4IntlMacroSheet".lower())
        self.globals["xlWBATExcel4MacroSheet".lower()] = 3
        self.vb_constants.add("xlWBATExcel4MacroSheet".lower())
        self.globals["xlWBATWorksheet".lower()] = 4167
        self.vb_constants.add("xlWBATWorksheet".lower())
        self.globals["xlWebArchive".lower()] = 45
        self.vb_constants.add("xlWebArchive".lower())
        self.globals["xlWebFormattingAll".lower()] = 1
        self.vb_constants.add("xlWebFormattingAll".lower())
        self.globals["xlWebFormattingNone".lower()] = 3
        self.vb_constants.add("xlWebFormattingNone".lower())
        self.globals["xlWebFormattingRTF".lower()] = 2
        self.vb_constants.add("xlWebFormattingRTF".lower())
        self.globals["xlWebQuery".lower()] = 4
        self.vb_constants.add("xlWebQuery".lower())
        self.globals["xlWeekday".lower()] = 2
        self.vb_constants.add("xlWeekday".lower())
        self.globals["xlWeekdayNameChars".lower()] = 31
        self.vb_constants.add("xlWeekdayNameChars".lower())
        self.globals["xlWeightedAllocation".lower()] = 2
        self.vb_constants.add("xlWeightedAllocation".lower())
        self.globals["xlWhole".lower()] = 1
        self.vb_constants.add("xlWhole".lower())
        self.globals["xlWholeTable".lower()] = 0
        self.vb_constants.add("xlWholeTable".lower())
        self.globals["xlWide".lower()] = 3
        self.vb_constants.add("xlWide".lower())
        self.globals["xlWindows".lower()] = 2
        self.vb_constants.add("xlWindows".lower())
        self.globals["xlWithinSheet".lower()] = 1
        self.vb_constants.add("xlWithinSheet".lower())
        self.globals["xlWithinWorkbook".lower()] = 2
        self.vb_constants.add("xlWithinWorkbook".lower())
        self.globals["xlWJ2WD1".lower()] = 14
        self.vb_constants.add("xlWJ2WD1".lower())
        self.globals["xlWJ3".lower()] = 40
        self.vb_constants.add("xlWJ3".lower())
        self.globals["xlWJ3FJ3".lower()] = 41
        self.vb_constants.add("xlWJ3FJ3".lower())
        self.globals["xlWK1".lower()] = 5
        self.vb_constants.add("xlWK1".lower())
        self.globals["xlWK1ALL".lower()] = 31
        self.vb_constants.add("xlWK1ALL".lower())
        self.globals["xlWK1FMT".lower()] = 30
        self.vb_constants.add("xlWK1FMT".lower())
        self.globals["xlWK3".lower()] = 15
        self.vb_constants.add("xlWK3".lower())
        self.globals["xlWK3FM3".lower()] = 32
        self.vb_constants.add("xlWK3FM3".lower())
        self.globals["xlWK4".lower()] = 38
        self.vb_constants.add("xlWK4".lower())
        self.globals["xlWKS".lower()] = 4
        self.vb_constants.add("xlWKS".lower())
        self.globals["xlWMF".lower()] = 2
        self.vb_constants.add("xlWMF".lower())
        self.globals["xlWorkbook".lower()] = 1
        self.vb_constants.add("xlWorkbook".lower())
        self.globals["xlWorkbookDefault".lower()] = 51
        self.vb_constants.add("xlWorkbookDefault".lower())
        self.globals["xlWorkbookNormal".lower()] = 4143
        self.vb_constants.add("xlWorkbookNormal".lower())
        self.globals["xlWorkbookTab".lower()] = 6
        self.vb_constants.add("xlWorkbookTab".lower())
        self.globals["xlWorks2FarEast".lower()] = 28
        self.vb_constants.add("xlWorks2FarEast".lower())
        self.globals["xlWorksheet".lower()] = 4167
        self.vb_constants.add("xlWorksheet".lower())
        self.globals["xlWorksheet4".lower()] = 1
        self.vb_constants.add("xlWorksheet4".lower())
        self.globals["xlWorksheetCell".lower()] = 3
        self.vb_constants.add("xlWorksheetCell".lower())
        self.globals["xlWorksheetShort".lower()] = 5
        self.vb_constants.add("xlWorksheetShort".lower())
        self.globals["xlWPG".lower()] = 3
        self.vb_constants.add("xlWPG".lower())
        self.globals["xlWQ1".lower()] = 34
        self.vb_constants.add("xlWQ1".lower())
        self.globals["xlX".lower()] = 4168
        self.vb_constants.add("xlX".lower())
        self.globals["xlXErrorBars".lower()] = 10
        self.vb_constants.add("xlXErrorBars".lower())
        self.globals["xlXmlExportSuccess".lower()] = 0
        self.vb_constants.add("xlXmlExportSuccess".lower())
        self.globals["xlXmlExportValidationFailed".lower()] = 1
        self.vb_constants.add("xlXmlExportValidationFailed".lower())
        self.globals["xlXmlImportElementsTruncated".lower()] = 1
        self.vb_constants.add("xlXmlImportElementsTruncated".lower())
        self.globals["xlXmlImportSuccess".lower()] = 0
        self.vb_constants.add("xlXmlImportSuccess".lower())
        self.globals["xlXmlImportValidationFailed".lower()] = 2
        self.vb_constants.add("xlXmlImportValidationFailed".lower())
        self.globals["xlXmlLoadImportToList".lower()] = 2
        self.vb_constants.add("xlXmlLoadImportToList".lower())
        self.globals["xlXmlLoadMapXml".lower()] = 3
        self.vb_constants.add("xlXmlLoadMapXml".lower())
        self.globals["xlXmlLoadOpenXml".lower()] = 1
        self.vb_constants.add("xlXmlLoadOpenXml".lower())
        self.globals["xlXmlLoadPromptUser".lower()] = 0
        self.vb_constants.add("xlXmlLoadPromptUser".lower())
        self.globals["xlXMLSpreadsheet".lower()] = 46
        self.vb_constants.add("xlXMLSpreadsheet".lower())
        self.globals["xlXYScatter".lower()] = 4169
        self.vb_constants.add("xlXYScatter".lower())
        self.globals["xlXYScatterLines".lower()] = 74
        self.vb_constants.add("xlXYScatterLines".lower())
        self.globals["xlXYScatterLinesNoMarkers".lower()] = 75
        self.vb_constants.add("xlXYScatterLinesNoMarkers".lower())
        self.globals["xlXYScatterSmooth".lower()] = 72
        self.vb_constants.add("xlXYScatterSmooth".lower())
        self.globals["xlXYScatterSmoothNoMarkers".lower()] = 73
        self.vb_constants.add("xlXYScatterSmoothNoMarkers".lower())
        self.globals["xlY".lower()] = 1
        self.vb_constants.add("xlY".lower())
        self.globals["xlYDMFormat".lower()] = 8
        self.vb_constants.add("xlYDMFormat".lower())
        self.globals["xlYear".lower()] = 4
        self.vb_constants.add("xlYear".lower())
        self.globals["xlYearCode".lower()] = 19
        self.vb_constants.add("xlYearCode".lower())
        self.globals["xlYears".lower()] = 2
        self.vb_constants.add("xlYears".lower())
        self.globals["xlYearToDate".lower()] = 52
        self.vb_constants.add("xlYearToDate".lower())
        self.globals["xlYErrorBars".lower()] = 11
        self.vb_constants.add("xlYErrorBars".lower())
        self.globals["xlYes".lower()] = 1
        self.vb_constants.add("xlYes".lower())
        self.globals["xlYesterday".lower()] = 1
        self.vb_constants.add("xlYesterday".lower())
        self.globals["xlYMDFormat".lower()] = 5
        self.vb_constants.add("xlYMDFormat".lower())
        self.globals["xlZero".lower()] = 2
        self.vb_constants.add("xlZero".lower())

        # WdSaveFormat enumeration (Word)
        self.globals["wdFormatDocument".lower()] = 0
        self.vb_constants.add("wdFormatDocument".lower())
        self.globals["wdFormatDOSText".lower()] = 4
        self.vb_constants.add("wdFormatDOSText".lower())
        self.globals["wdFormatDOSTextLineBreaks".lower()] = 5
        self.vb_constants.add("wdFormatDOSTextLineBreaks".lower())
        self.globals["wdFormatEncodedText".lower()] = 7
        self.vb_constants.add("wdFormatEncodedText".lower())
        self.globals["wdFormatFilteredHTML".lower()] = 10
        self.vb_constants.add("wdFormatFilteredHTML".lower())
        self.globals["wdFormatFlatXML".lower()] = 19
        self.vb_constants.add("wdFormatFlatXML".lower())
        self.globals["wdFormatFlatXMLMacroEnabled".lower()] = 20
        self.vb_constants.add("wdFormatFlatXMLMacroEnabled".lower())
        self.globals["wdFormatFlatXMLTemplate".lower()] = 21
        self.vb_constants.add("wdFormatFlatXMLTemplate".lower())
        self.globals["wdFormatFlatXMLTemplateMacroEnabled".lower()] = 22
        self.vb_constants.add("wdFormatFlatXMLTemplateMacroEnabled".lower())
        self.globals["wdFormatOpenDocumentText".lower()] = 23
        self.vb_constants.add("wdFormatOpenDocumentText".lower())
        self.globals["wdFormatHTML".lower()] = 8
        self.vb_constants.add("wdFormatHTML".lower())
        self.globals["wdFormatRTF".lower()] = 6
        self.vb_constants.add("wdFormatRTF".lower())
        self.globals["wdFormatStrictOpenXMLDocument".lower()] = 24
        self.vb_constants.add("wdFormatStrictOpenXMLDocument".lower())
        self.globals["wdFormatTemplate".lower()] = 1
        self.vb_constants.add("wdFormatTemplate".lower())
        self.globals["wdFormatText".lower()] = 2
        self.vb_constants.add("wdFormatText".lower())
        self.globals["wdFormatTextLineBreaks".lower()] = 3
        self.vb_constants.add("wdFormatTextLineBreaks".lower())
        self.globals["wdFormatUnicodeText".lower()] = 7
        self.vb_constants.add("wdFormatUnicodeText".lower())
        self.globals["wdFormatWebArchive".lower()] = 9
        self.vb_constants.add("wdFormatWebArchive".lower())
        self.globals["wdFormatXML".lower()] = 11
        self.vb_constants.add("wdFormatXML".lower())
        self.globals["wdFormatDocument97".lower()] = 0
        self.vb_constants.add("wdFormatDocument97".lower())
        self.globals["wdFormatDocumentDefault".lower()] = 16
        self.vb_constants.add("wdFormatDocumentDefault".lower())
        self.globals["wdFormatPDF".lower()] = 17
        self.vb_constants.add("wdFormatPDF".lower())
        self.globals["wdFormatTemplate97".lower()] = 1
        self.vb_constants.add("wdFormatTemplate97".lower())
        self.globals["wdFormatXMLDocument".lower()] = 12
        self.vb_constants.add("wdFormatXMLDocument".lower())
        self.globals["wdFormatXMLDocumentMacroEnabled".lower()] = 13
        self.vb_constants.add("wdFormatXMLDocumentMacroEnabled".lower())
        self.globals["wdFormatXMLTemplate".lower()] = 14
        self.vb_constants.add("wdFormatXMLTemplate".lower())
        self.globals["wdFormatXMLTemplateMacroEnabled".lower()] = 15
        self.vb_constants.add("wdFormatXMLTemplateMacroEnabled".lower())
        self.globals["wdFormatXPS".lower()] = 18
        self.vb_constants.add("wdFormatXPS".lower())

        # WdUnderline enumeration (Word)
        #
        # Specifies the type of underline to apply.
        
        #  Dashes.
        self.globals["wdUnderlineDash".lower()] = 7
        self.vb_constants.add("wdUnderlineDash".lower())
        #  Heavy dashes.
        self.globals["wdUnderlineDashHeavy".lower()] = 23
        self.vb_constants.add("wdUnderlineDashHeavy".lower())
        #  Long dashes.
        self.globals["wdUnderlineDashLong".lower()] = 39
        self.vb_constants.add("wdUnderlineDashLong".lower())
        #  Long heavy dashes.
        self.globals["wdUnderlineDashLongHeavy".lower()] = 55
        self.vb_constants.add("wdUnderlineDashLongHeavy".lower())
        #  Alternating dots and dashes.
        self.globals["wdUnderlineDotDash".lower()] = 9
        self.vb_constants.add("wdUnderlineDotDash".lower())
        #  Alternating heavy dots and heavy dashes.
        self.globals["wdUnderlineDotDashHeavy".lower()] = 25
        self.vb_constants.add("wdUnderlineDotDashHeavy".lower())
        #  An alternating dot-dot-dash pattern.
        self.globals["wdUnderlineDotDotDash".lower()] = 10
        self.vb_constants.add("wdUnderlineDotDotDash".lower())
        #  An alternating heavy dot-dot-dash pattern.
        self.globals["wdUnderlineDotDotDashHeavy".lower()] = 26
        self.vb_constants.add("wdUnderlineDotDotDashHeavy".lower())
        #  Dots.
        self.globals["wdUnderlineDotted".lower()] = 4
        self.vb_constants.add("wdUnderlineDotted".lower())
        #  Heavy dots.
        self.globals["wdUnderlineDottedHeavy".lower()] = 20
        self.vb_constants.add("wdUnderlineDottedHeavy".lower())
        #  A double line.
        self.globals["wdUnderlineDouble".lower()] = 3
        self.types["wdUnderlineDouble".lower()] = "Integer"
        self.vb_constants.add("wdUnderlineDouble".lower())
        #  No underline.
        self.globals["wdUnderlineNone".lower()] = 0
        self.vb_constants.add("wdUnderlineNone".lower())
        #  A single line. default.
        self.globals["wdUnderlineSingle".lower()] = 1
        self.vb_constants.add("wdUnderlineSingle".lower())
        #  A single thick line.
        self.globals["wdUnderlineThick".lower()] = 6
        self.vb_constants.add("wdUnderlineThick".lower())
        #  A single wavy line.
        self.globals["wdUnderlineWavy".lower()] = 11
        self.vb_constants.add("wdUnderlineWavy".lower())
        #  A double wavy line.
        self.globals["wdUnderlineWavyDouble".lower()] = 43
        self.vb_constants.add("wdUnderlineWavyDouble".lower())
        #  A heavy wavy line.
        self.globals["wdUnderlineWavyHeavy".lower()] = 27
        self.vb_constants.add("wdUnderlineWavyHeavy".lower())
        #  Underline individual words only.        
        self.globals["wdUnderlineWords".lower()] = 2
        self.vb_constants.add("wdUnderlineWords".lower())
        
        # endregion

    def __repr__(self):
        r = ""
        r += "Locals:\n"
        r += str(self.locals) + "\n\n"
        #r += "Globals:\n"
        #r += str(self.globals) + "\n"
        return r
        
    def __eq__(self, other):
        if isinstance(other, Context):
            globals_eq = (self.globals == other.globals)
            if (not globals_eq):
                s1 = set()
                for i in self.globals.items():
                    s1.add(str(i))
                s2 = set()
                for i in other.globals.items():
                    s2.add(str(i))
                if (str(s1 ^ s2) == "set([])"):
                    globals_eq = True
            return ((self.call_stack == other.call_stack) and
                    globals_eq and
                    (self.locals == other.locals))
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def add_key_macro(self,key,value):
        namespaces = ['', 'VBA', 'KeyCodeConstants', 'VBA.KeyCodeConstants', 'VBA.vbStrConv', 'vbStrConv']
        self.add_multiple_macro(namespaces,key,value)

    def add_color_constant_macro(self,color,value):
        namespaces = ['', 'VBA.ColorConstants', 'VBA.SystemColorConstants']
        self.add_multiple_macro(namespaces,color,value)

    def add_multiple_macro(self,namespaces,key,value):
        for n in namespaces:
            if n != "" and n[-1] != ".":
                namespace = n + "."
            else:
                namespace = n
            glbl = (namespace+key).lower()
            self.globals[ glbl ] = value
            self.vb_constants.add(glbl)
        
    def read_metadata_item(self, var):

        # Make sure we read in the metadata.
        if (self.metadata is None):
            log.error("BuiltInDocumentProperties: Metadata not read.")
            return ""
    
        # Normalize the variable name.
        var = var.lower().replace(" ", "_")
        if ("." in var):
            var = var[:var.index(".")]
    
        # See if we can find the metadata attribute.
        if (not hasattr(self.metadata, var)):
            log.error("BuiltInDocumentProperties: Metadata field '" + var + "' not found.")
            return ""

        # We have the attribute. Return it.
        r = getattr(self.metadata, var)

        # Handle MS encoding of "\r" and "\n".
        r = r.replace("_x000d_.", "\r\n")
        r = r.replace("_x000d_", "\r")
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("BuiltInDocumentProperties: return %r -> %r" % (var, r))

        # Done.
        return r
            
    def get_error_handler(self):
        """
        Get the onerror goto error handler.
        """
        if (hasattr(self, "error_handler")):
            return self.error_handler
        return None

    def do_next_iter_on_error(self):
        """
        See if the error handler just calls Next to advance to next loop iteration.
        """

        # Do we have an error handler?
        handler = self.get_error_handler()
        if (handler is None):
            return False

        # See if the 1st statement in the handler is Next.
        if (len(handler.block) == 0):

            # If it looks like no commands, let's just go to the next loop iteration.
            return True
        first_cmd = str(handler.block[0]).strip()
        return (first_cmd == "Next")
    
    def have_error(self):
        """
        See if Visual Basic threw an error.
        """
        return (hasattr(self, "got_error") and
                self.got_error)

    def clear_error(self):
        """
        Clear out the error flag.
        """
        self.got_error = False
        
    def must_handle_error(self):
        """
        Check to see if there was are error raised during emulation and we have
        an error handler.
        """
        return (self.have_error() and
                hasattr(self, "error_handler") and
                (self.error_handler is not None))

    def handle_error(self, params):
        """
        Run the current error handler (if there is one) if there is an error.
        """

        # Run the error handler if needed.
        if (self.must_handle_error()):
            log.warning("Running On Error error handler...")
            self.got_error = False
            self.error_handler.eval(context=self, params=params)

            # The error has now been cleared. Note that if there is no
            # error handler and there is an error it will remain.
            self.got_error = False

    def set_error(self, reason):
        """
        Set that a VBA error has occurred.
        """

        self.got_error = True
        self.increase_general_errors()
        log.error("A VB error has occurred. Reason: " + str(reason))

    def report_general_error(self, reason):
        """
        Report and track general ViperMonkey errors. Note that these may not just be
        VBA errors.
        """
        self.num_general_errors += 1
        log.error(reason)

    def clear_general_errors(self):
        """
        Clear the count of general errors.
        """
        self.num_general_errors = 0

    def get_general_errors(self):
        """
        Get the number of reported general errors.
        """
        return self.num_general_errors

    def increase_general_errors(self):
        """
        Add one to the number of reported general errors.
        """
        self.num_general_errors += 1
        
    def get_true_name(self, name):
        """
        Get the true name of an aliased function imported from a DLL.
        """
        if (name in self.dll_func_true_names):
            return self.dll_func_true_names[name]
        return None

    def delete(self, name):
        """
        Delete a variable from the context.
        """

        # Punt if we don't have the variable.
        if (not self.contains(name)):
            return self

        # Delete the variable
        if name in self.locals:
            del self.locals[name]
        elif name in self.globals:
            del self.globals[name]

        return self

    def get_interesting_fileid(self):
        """
        Pick an 'interesting' looking open file and return its ID.
        """

        # Look for the longest file name and any files name on the C: drive.
        # Also look for the last saved file.
        longest = ""
        cdrive = None
        for file_id in self.open_files.keys():
            if ((self.last_saved_file is not None) and (str(file_id).lower() == self.last_saved_file.lower())):
                cdrive = file_id
                break
            if (str(file_id).lower().startswith("c:")):
                cdrive = file_id
            if (len(str(file_id)) > len(longest)):
                longest = file_id

        # Favor files on the C: drive.
        if (cdrive is not None):
            return cdrive

        # Fall back to longest.
        if (len(longest) > 0):
            return longest

        # Punt.
        return None

    def file_is_open(self, fname):
        """
        Check to see if a file is already open.
        """
        fname = str(fname)
        fname = fname.replace(".\\", "").replace("\\", "/")

        # Don't reopen already opened files.
        return (fname in self.open_files.keys())
        
    def open_file(self, fname, file_id=""):
        """
        Simulate opening a file.

        fname - The name of the file.
        file_id - The numeric ID of the file.
        """
        # Save that the file is opened.
        fname = str(fname)
        fname = fname.replace(".\\", "").replace("\\", "/")

        # Don't reopen already opened files.
        if (fname in self.open_files.keys()):
            log.warning("File " + str(fname) + " is already open.")
            return

        # Open the simulated file.
        self.open_files[fname] = b''
        if (file_id != ""):
            self.file_id_map[file_id] = fname
        log.info("Opened file " + fname)

    def write_file(self, fname, data):

        # Make sure the "file" exists.
        fname = str(fname)
        fname = fname.replace(".\\", "").replace("\\", "/")
        if fname not in self.open_files:

            # Are we referencing this by numeric ID.
            if (fname in self.file_id_map.keys()):
                fname = self.file_id_map[fname]
            else:
                log.error('File {} not open. Cannot write new data.'.format(fname))
                return False
            
        # Are we writing a string?
        if isinstance(data, str):

            # Hex string?
            if ((len(data.strip()) == 4) and (re.match('&H[0-9A-F]{2}', data, re.IGNORECASE))):
                data = chr(int(data.strip()[-2:], 16))

            self.open_files[fname] += data
            return True

        # Are we writing a list?
        elif isinstance(data, list):
            for d in data:
                if (isinstance(d, int)):
                    self.open_files[fname] += chr(d)
                else:
                    self.open_files[fname] += str(d)
            return True

        # Are we writing a byte?
        elif isinstance(data, int):

            # Convert the int to a series of bytes to write out.
            byte_list = struct.pack('<i', data)
            
            # Skip 0 bytes at the end of the sequence.
            pos = len(byte_list) + 1
            for b in byte_list[::-1]:
                pos -= 1
                if (b != '\x00'):
                    break
            byte_list = byte_list[:pos]

            # Write out each byte.
            for b in byte_list:
                self.open_files[fname] += b
            return True
        
        # Unhandled.
        else:
            log.error("Unhandled data type to write. " + str(type(data)) + ".")
            return False
        
    def dump_all_files(self, autoclose=False):
        for fname in self.open_files.keys():
            self.dump_file(fname, autoclose=autoclose)

    def get_num_open_files(self):
        """
        Get the # of currently open files being tracked.
        """
        return len(self.open_files)
            
    def close_file(self, fname):
        """
        Simulate closing a file.

        fname - The name of the file.

        Returns boolean indicating success.
        """
        global file_count
        
        # Make sure the "file" exists.
        fname = str(fname).replace(".\\", "").replace("\\", "/")
        file_id = None
        if fname not in self.open_files:

            # Are we referencing this by numeric ID.
            if (fname in self.file_id_map.keys()):
                file_id = fname
                fname = self.file_id_map[fname]
            else:
                log.error('File {} not open. Cannot close.'.format(fname))
                return

        log.info("Closing file " + fname)

        # Get the data written to the file and track it.
        data = self.open_files[fname]
        self.closed_files[fname] = data

        # Clear the file out of the open files.
        del self.open_files[fname]
        if (file_id is not None):
            del self.file_id_map[file_id]

        if out_dir:
            self.dump_file(fname)

    # FIXME: This function is too closely coupled to the CLI.
    #   Context should not contain business logic.
    def dump_file(self, fname, autoclose=False):
        """
        Save the contents of a file dumped by the VBA to disk.

        fname - The name of the file.
        """
        if fname not in self.closed_files:
            if (not autoclose):
                log.error('File {} not closed. Cannot save.'.format(fname))
                return
            else:
                log.warning('File {} not closed. Closing file.'.format(fname))
                self.close_file(fname)
                
        # Hash the data to be saved.
        raw_data = self.closed_files[fname]
        file_hash = sha256(raw_data).hexdigest()

        # TODO: Set a flag to control whether to dump file contents.

        # Make the dropped file directory if needed.
        if not os.path.isdir(out_dir):
            os.makedirs(out_dir)

        # Dump the file.
        try:
            # Get a unique name for the file.
            fname = re.sub(r"[^ -~\r\n]", "__", fname)
            if ("/" in fname):
                fname = fname[fname.rindex("/") + 1:]
            if ("\\" in fname):
                fname = fname[fname.rindex("\\") + 1:]
            fname = fname.replace("\x00", "").replace("..", "")
            if (fname.startswith(".")):
                fname = "_dot_" + fname[1:]

            # Handle really huge file names.
            if (len(fname) > 50):
                fname = "REALLY_LONG_NAME_" + str(file_hash) + ".dat"
                log.warning("Filename of dropped file is too long, replacing with " + fname)

            # Make the name truely unique.
            self.report_action("Dropped File Hash", file_hash, 'File Name: ' + fname)
            file_path = os.path.join(out_dir, os.path.basename(fname))
            orig_file_path = file_path
            count = 0
            while os.path.exists(file_path):
                count += 1
                file_path = '{} ({})'.format(orig_file_path, count)

            # Write out the dropped file.
            with open(file_path, 'wb') as f:
                f.write(raw_data)
            log.info("Wrote dumped file (hash {}) to {}.".format(file_hash, file_path))
        except Exception as e:
            log.error("Writing file {} failed with error: {}".format(fname, e))

    def get_lib_func(self, name):

        if (not isinstance(name, basestring)):
            raise KeyError('Object %r not found' % name)
        
        # Search in the global VBA library:
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Looking for library function '" + name + "'...")
        name = name.lower()
        if name in VBA_LIBRARY:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Found %r in VBA Library' % name)
            return VBA_LIBRARY[name]

        # Unknown symbol.
        else:            
            raise KeyError('Library function %r not found' % name)

    def __get(self, name, case_insensitive=True, local_only=False, global_only=False):

        if (not isinstance(name, basestring)):
            raise KeyError('Object %r not found' % name)

        # Flag if this is a change handler lookup.
        is_change_handler = (str(name).strip().lower().endswith("_change"))
        change_name = str(name).strip().lower()
        if is_change_handler: change_name = change_name[:-len("_change")]
        
        # convert to lowercase if needed.
        orig_name = name
        if (case_insensitive):
            name = name.lower()
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Looking for var '" + name + "'...")

        # We will always say that a directory is not accessible.
        if (name.strip().endswith(".subfolders.count")):
            return -1
        
        # First, search in locals. This handles variables whose name overrides
        # a system function.
        if ((not global_only) and (name in self.locals)):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Found %r in locals' % name)
            if is_change_handler: self.has_change_handler[change_name] = True
            self.name_cache[orig_name] = name
            return self.locals[name]
        # second, in globals:
        elif ((not local_only) and (name in self.globals)):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Found %r in globals' % name)
            if is_change_handler: self.has_change_handler[change_name] = True
            self.name_cache[orig_name] = name
            return self.globals[name]
        # next, search in the global VBA library:
        elif ((not local_only) and (name in VBA_LIBRARY)):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Found %r in VBA Library' % name)
            if is_change_handler: self.has_change_handler[change_name] = True
            self.name_cache[orig_name] = name
            return VBA_LIBRARY[name]
        # Is it a doc var?
        elif ((not local_only) and (name in self.doc_vars)):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Found %r in VBA document variables' % name)
            if is_change_handler: self.has_change_handler[change_name] = True
            self.name_cache[orig_name] = name
            return self.doc_vars[name]
        # Unknown symbol.
        else:
            # Not found.
            if is_change_handler: self.has_change_handler[change_name] = False
            raise KeyError('Object %r not found' % name)
            # NOTE: if name is unknown, just raise Python dict's exception
            # TODO: raise a custom VBA exception?

    def _get(self, name, search_wildcard=True, case_insensitive=True, local_only=False, global_only=False):
        
        # See if this is an aliased reference to an objects .Text field.
        name = str(name)
        if (((name.lower() == "nodetypedvalue") or (name.lower() == ".nodetypedvalue")) and
            (not name in self.locals) and
            (".Text".lower() in self.locals)):
            return self.get(".Text")

        # Try to avoid attempting a bunch of variations on the variable name
        # if we already know one that worked earlier.
        if (name in self.name_cache):
            cached_name = self.name_cache[name]
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Cached name of '" + str(name) + "' is '" + str(cached_name) + "'")
            try:
                return self.__get(cached_name,
                                  case_insensitive=case_insensitive,
                                  local_only=local_only,
                                  global_only=global_only)
            except KeyError:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Cached lookup failed.")

        # Use the evaluated With prefix value only when it makes sense.
        with_prefix = self.with_prefix
        if ((self.with_prefix_raw is not None) and
            (str(self.with_prefix_raw).startswith("ActiveDocument"))):
            with_prefix = self.with_prefix_raw
                    
        # Try to get the item using the current with context.
        if (name.startswith(".")):
            
            # Add in the current With context.
            tmp_name = str(with_prefix) + str(name)
            try:
                return self.__get(tmp_name,
                                  case_insensitive=case_insensitive,
                                  local_only=local_only,
                                  global_only=global_only)
            except KeyError:

                # Try with the evaluated with context.
                tmp_name = str(self.with_prefix) + str(name)
                try:
                    return self.__get(tmp_name,
                                      case_insensitive=case_insensitive,
                                      local_only=local_only,
                                      global_only=global_only)
                except KeyError:
                    pass

        # Now try it without the current with context.
        try:
            return self.__get(str(name),
                              case_insensitive=case_insensitive,
                              local_only=local_only,
                              global_only=global_only)
        except KeyError:
            pass

        # Try to get the item using the current with context, again.
        tmp_name = str(with_prefix) + "." + str(name)
        try:
            return self.__get(tmp_name,
                              case_insensitive=case_insensitive,
                              local_only=local_only,
                              global_only=global_only)
        except KeyError:

            # If we are looking for a shapes title we may already have
            # it.
            if (isinstance(self.with_prefix, str) and
                (self.with_prefix_raw is not None) and
                ("Shapes" in str(self.with_prefix_raw)) and
                (str(name) == "Title")):
                return self.with_prefix
        
        # Are we referencing a field in an object?
        if ("." in name):

            # Look for faked object field.
            new_name = "me." + name[name.index(".")+1:]
            try:
                return self.__get(str(new_name),
                                  case_insensitive=case_insensitive,
                                  local_only=local_only,
                                  global_only=global_only)
            except KeyError:
                pass

            # Look for wild carded field value.
            if (search_wildcard):
                new_name = name[:name.index(".")] + ".*"
                try:
                    r = self.__get(str(new_name),
                                   case_insensitive=case_insensitive,
                                   local_only=local_only,
                                   global_only=global_only)
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Found wildcarded field value " + new_name + " = " + str(r))
                    return r
                except KeyError:
                    pass
            
        # See if the variable was initially defined with a trailing '$'.
        return self.__get(str(name) + "$",
                          case_insensitive=case_insensitive,
                          local_only=local_only,
                          global_only=global_only)

    def _get_all_metadata(self, name):
        """
        Return all items in something like ActiveDocument.BuiltInDocumentProperties.
        """

        # Reading all properties?
        if ((name != "ActiveDocument.BuiltInDocumentProperties") and
            (name != "ThisDocument.BuiltInDocumentProperties")):
            return None

        # Get the names of the metadata items.
        meta_names = [a for a in dir(self.metadata) if not a.startswith('__') and not callable(getattr(self.metadata, a))]

        # Add the names and values of the metadata items to the context.
        for meta_name in meta_names:
            self.set(meta_name + ".Name", meta_name, force_global=True)
            self.set(meta_name + ".Value", getattr(self.metadata, meta_name), force_global=True)
            self.save_intermediate_iocs(getattr(self.metadata, meta_name))

        # Chuck the comments in there for good measure.
        meta_names.append("Comments")
        comments = ""
        first = True
        for comment in self.get("ActiveDocument.Comments"):
            if (not first):
                comments += "\n"
            first = False
            comments += comment
        self.set("Comments.Name", "Comments", force_global=True)
        self.set("Comments.Value", comments, force_global=True)
        self.save_intermediate_iocs(comments)
        
        # Return the metadata items as a list of their names. Accesses of their .Name and
        # .Value fields will hit the synthetic variables that were just added to the
        # context.
        return meta_names
    
    def get(self, name, search_wildcard=True, local_only=False, global_only=False):

        # Sanity check.
        if ((name is None) or
            (isinstance(name, str) and (len(name.strip()) == 0))):
            raise KeyError('Object %r not found' % name)
        
        # Short circuit looking for variable change handlers if possible.
        if (str(name).strip().lower().endswith("_change")):

            # Get the original variable name.
            orig_name = str(name).strip().lower()[:-len("_change")]
            if ((orig_name in self.has_change_handler) and (not self.has_change_handler[orig_name])):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Short circuited change handler lookup of " + name)
                raise KeyError('Object %r not found' % name)

        # Reading all of the document metadata items?
        r = self._get_all_metadata(name)
        if (r is not None):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Read all metadata items.")
            return r
            
        # First try a case sensitive search. If that fails try case insensitive.
        r = None
        try:
            r = self._get(name,
                          search_wildcard=search_wildcard,
                          case_insensitive=False,
                          local_only=local_only,
                          global_only=global_only)
        except KeyError:
            r = self._get(name,
                          search_wildcard=search_wildcard,
                          case_insensitive=True,
                          local_only=local_only,
                          global_only=global_only)

        # Did we get something useful?
        if ((r is None) or (r == "NULL")):

            # See if we have a more useful version of this variable stored as an object
            # field.
            tmp_name = "." + str(name)
            if (self.contains(tmp_name)):
                r = self._get(tmp_name)
            
        # Done.
        return r
            
    def contains(self, name, local=False):
        if (local):
            return (str(name).lower() in self.locals)
        try:
            self.get(name)
            return True
        except KeyError:
            return False

    def contains_user_defined(self, name):
        return ((name in self.locals) or (name in self.globals))
        
    def get_type(self, var):
        if (not isinstance(var, basestring)):
            return None
        var = var.lower()
        if (var not in self.types):
            return None
        return self.types[var]

    def get_doc_var(self, var, search_wildcard=True):
        if (not isinstance(var, basestring)):
            return None

        # Normalize the variable name to lower case.
        var = var.lower()
        # strip VBA nonsense
        var = var.replace('!','').\
                    replace('^','').\
                    replace('%','').\
                    replace('&','').\
                    replace('@','').\
                    replace('#','').\
                    replace('$','')
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Looking up doc var " + var)

        # Are we pulling out all the doc vars?
        if (var == "activedocument.variables"):

            # Return these as (name, value) tuples.
            r = []
            for var_name in self.doc_vars.keys():
                r.append((var_name, self.doc_vars[var_name]))                
            return r
        
        if (var not in self.doc_vars):

            # Can't find a doc var with this name. See if we have an internal variable
            # with this name.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("doc var named " + var + " not found.")
            try:
                var_value = self.get(var, search_wildcard=search_wildcard)
                if ((var_value is not None) and
                    (str(var_value).lower() != str(var).lower())):
                    r = self.get_doc_var(var_value)
                    if (r is not None):
                        return r
                    return var_value
            except KeyError:
                pass

            # Can't find it. Do we have a wild card doc var to guess for
            # this value? Only do this if it looks like we have a valid doc var name.
            if ((re.match(r"^[a-zA-Z_][\w\d]*$", str(var)) is not None) and
                ("*" in self.doc_vars)):
                return self.doc_vars["*"]

            # See if this is in the ActiveDocument.
            if ("." in var):

                # Get the new name looking for the var in ActiveDocument.
                var = "activedocument." + var[var.index(".") + 1:]
                if (var in self.doc_vars):

                    # Found it.
                    r = self.doc_vars[var]
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Found doc var " + var + " = " + str(r))
                    return r
                
            # No variable. Return nothing.
            return None

        # Found it.
        r = self.doc_vars[var]
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Found doc var " + var + " = " + str(r))
        return r

    def save_intermediate_iocs(self, value):
        """
        Save variable values that appear to contain base64 encoded or URL IOCs.
        """

        global num_b64_iocs
        
        # Strip NULLs and unprintable characters from the potential IOC.
        from vba_object import strip_nonvb_chars
        value = strip_nonvb_chars(value)
        if (len(re.findall(r"NULL", str(value))) > 20):
            value = str(value).replace("NULL", "")
        
        # Is there a URL in the data?
        got_ioc = False
        URL_REGEX = r'.*([hH][tT][tT][pP][sS]?://(([a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-\.]+(:[0-9]+)?)+(/([/\?&\~=a-zA-Z0-9_\-\.](?!http))+)?)).*'
        try:
            value = str(value).strip()
        except:
            return
        tmp_value = value
        if (len(tmp_value) > 100):
            tmp_value = tmp_value[:100] + " ..."
        if (re.match(URL_REGEX, value) is not None):
            if (value not in intermediate_iocs):
                got_ioc = True
                log.info("Found possible intermediate IOC (URL): '" + tmp_value + "'")

        # Is there base64 in the data? Don't track too many base64 IOCs.
        if (num_b64_iocs < 200):
            B64_REGEX = r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
            b64_strs = re.findall(B64_REGEX, value)
            for curr_value in b64_strs:
                if ((value not in intermediate_iocs) and (len(curr_value) > 200)):
                    got_ioc = True
                    num_b64_iocs += 1
                    log.info("Found possible intermediate IOC (base64): '" + tmp_value + "'")

        # Did we find anything?
        if (not got_ioc):
            return

        # Is this new and interesting?
        iocs_to_delete = set()
        got_ioc = True
        for old_value in intermediate_iocs:
            if (value.startswith(old_value)):
                iocs_to_delete.add(old_value)
            if ((old_value.startswith(value)) and (len(old_value) > len(value))):
                got_ioc = False

        # Add the new IOC if it is interesting.
        if (got_ioc):
            intermediate_iocs.add(value)
            
        # Delete old IOCs if needed.
        for old_ioc in iocs_to_delete:
            intermediate_iocs.remove(old_ioc)
            
    def set(self,
            name,
            value,
            var_type=None,
            do_with_prefix=True,
            force_local=False,
            force_global=False,
            no_conversion=False,
            case_insensitive=True,
            no_overwrite=False):

        # Does the name make sense?
        orig_name = name
        if (not isinstance(name, basestring)):
            log.warning("context.set() " + str(name) + " is improper type. " + str(type(name)))
            name = str(name)

        # Does the value make sense?
        if (value is None):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("context.set() " + str(name) + " failed. Value is None.")
            return

        # More name fixing.
        if (".." in name):
            self.set(name.replace("..", "."), value, var_type, do_with_prefix, force_local, force_global, no_conversion=no_conversion)

        # Skip this if this variable is already set and we are not allowing value overwrites.
        if (no_overwrite and self.contains(name)):
            return
            
        # Save IOCs from intermediate values if needed.
        self.save_intermediate_iocs(value)
        
        # convert to lowercase
        if (case_insensitive):
            tmp_name = name.lower()
            self.set(tmp_name, value, var_type, do_with_prefix, force_local, force_global, no_conversion=no_conversion, case_insensitive=False)

        # Handling of special case where an array access is being stored as a variable.
        name_str = str(name)
        if (("(" in name_str) and (")" in name_str)):

            # See if this is actually referring to a global variable.
            name_str = name_str[:name_str.index("(")].strip()
            if (name_str in self.globals.keys()):
                force_global = True

        # This should be a global variable if we are not in a function.
        if ((not self.in_procedure) and (not force_global) and (not force_local)):
            self.set(name, value, force_global=True, do_with_prefix=do_with_prefix)
            return
                
        # Set the variable

        # Forced save in global context?
        if (force_global):
            try:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Set global var " + str(name) + " = " + str(value))
            except:
                pass
            self.globals[name] = value

        # Forced save in local context?
        elif ((name in self.locals) or force_local):
            try:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Set local var " + str(name) + " = " + str(value))
            except:
                pass
            self.locals[name] = value

        # Check globals, but avoid to overwrite subs and functions:
        elif name in self.globals and not is_procedure(self.globals[name]):
            self.globals[name] = value
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Set global var " + name + " = " + str(value))
            if ("." in name):
                text_name = name + ".text"
                self.globals[text_name] = value
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Set global var " + text_name + " = " + str(value))

        # New name, typically store in local scope.
        else:
            if (not self.global_scope):
                try:
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Set local var " + str(name) + " = " + str(value))
                except:
                    pass
                self.locals[name] = value
            else:
                self.globals[name] = value
                try:
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Set global var " + name + " = " + str(value))
                except:
                    pass
                if ("." in name):
                    text_name = name + ".text"
                    self.globals[text_name] = value
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Set global var " + text_name + " = " + str(value))
                    text_name = name[name.rindex("."):]
                    self.globals[text_name] = value
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Set global var " + text_name + " = " + str(value))
                
        # If we know the type of the variable, save it.
        if (var_type is not None):
            self.types[name] = var_type

        # Also set the variable using the current With name prefix, if
        # we have one.
        if ((do_with_prefix) and (len(self.with_prefix) > 0)):
            tmp_name = str(self.with_prefix) + "." + str(name)
            self.set(tmp_name, value, var_type=var_type, do_with_prefix=False, no_conversion=no_conversion)

        # Skip automatic data conversion if needed.
        if (no_conversion):
            return
            
        # Handle base64 conversion with VBA objects.
        if (name.endswith(".text")):

            # Is this a base64 object?
            do_b64 = False
            node_type = name.replace(".text", ".datatype")
            try:

                # Is the root object something set to the "bin.base64" data type?
                val = str(self.get(node_type)).strip()
                if (val.lower() == "bin.base64"):
                    do_b64 = True

            except KeyError:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Did not find type var " + node_type)

            # Is this a general XML object?
            try:

                # Is this a Microsoft.XMLDOM object?
                import expressions
                import vba_object
                node_type = orig_name
                if (isinstance(orig_name, expressions.MemberAccessExpression)):
                    node_type = orig_name.lhs
                else:
                    node_type = str(node_type).lower().replace(".text", "")
                val = vba_object.eval_arg(node_type, self)
                if (val == "Microsoft.XMLDOM"):
                    do_b64 = True

            except KeyError:
                pass
            
            # Handle doing conversions on the data.
            if (do_b64):

                # Try converting the text from base64.
                try:

                    # Make sure this is a potentially valid base64 string
                    tmp_str = filter(isascii, str(value).strip())
                    tmp_str = tmp_str.replace(" ", "")
                    b64_pat = r"^[A-Za-z0-9+/=]+$"
                    if (re.match(b64_pat, tmp_str) is not None):

                        # Pad out the b64 string if needed.
                        missing_padding = len(tmp_str) % 4
                        if missing_padding:
                            tmp_str += b'='* (4 - missing_padding)
                    
                        # Set the typed value of the node to the decoded value.
                        conv_val = base64.b64decode(tmp_str)
                        val_name = name
                        self.set(val_name, conv_val, no_conversion=True, do_with_prefix=do_with_prefix)
                        val_name = name.replace(".text", ".nodetypedvalue")
                        self.set(val_name, conv_val, no_conversion=True, do_with_prefix=do_with_prefix)
                        
                # Base64 conversion error.
                except Exception as e:
                    log.error("base64 conversion of '" + str(value) + "' failed. " + str(e))

        # Handle hex conversion with VBA objects.
        if (name.lower().endswith(".nodetypedvalue")):

            # Handle doing conversions on the data.
            node_type = name[:name.rindex(".")] + ".datatype"
            try:

                # Something set to type "bin.hex"?
                val = str(self.get(node_type)).strip()
                if (val.lower() == "bin.hex"):

                    # Try converting from hex.
                    try:

                        # Set the typed value of the node to the decoded value.
                        conv_val = codecs.decode(str(value).strip(), "hex")
                        self.set(name, conv_val, no_conversion=True, do_with_prefix=do_with_prefix)
                    except Exception as e:
                        log.warning("hex conversion of '" + str(value) + "' FROM hex failed. Converting TO hex. " + str(e))
                        conv_val = to_hex(str(value).strip())
                        self.set(name, conv_val, no_conversion=True, do_with_prefix=do_with_prefix)
                        
            except KeyError:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Did not find type var " + node_type)

        # Handle after the fact data conversion with VBA objects.
        if (name.endswith(".datatype")):

            # Handle doing conversions on the existing data.
            node_value_name = name.replace(".datatype", ".nodetypedvalue")
            try:

                # Do we have data to convert from type "bin.hex"?
                node_value = self.get(node_value_name)
                if (value.lower() == "bin.hex"):

                    # Try converting from hex.
                    try:

                        # Set the typed value of the node to the decoded value.
                        conv_val = codecs.decode(str(node_value).strip(), "hex")
                        self.set(node_value_name, conv_val, no_conversion=True, do_with_prefix=do_with_prefix)
                    except Exception as e:
                        log.warning("hex conversion of '" + str(node_value) + "' FROM hex failed. Converting TO hex. " + str(e))
                        conv_val = to_hex(str(node_value).strip())
                        self.set(node_value_name, conv_val, no_conversion=True, do_with_prefix=do_with_prefix)

                # Do we have data to convert from type "bin.base64"?
                if (value.lower() == "bin.base64"):

                    # Try converting the text from base64.
                    try:
                    
                        # Set the typed value of the node to the decoded value.
                        tmp_str = filter(isascii, str(node_value).strip())
                        tmp_str = tmp_str.replace(" ", "")
                        missing_padding = len(tmp_str) % 4
                        if missing_padding:
                            tmp_str += b'='* (4 - missing_padding)
                        conv_val = base64.b64decode(tmp_str)
                        self.set(node_value_name, conv_val, no_conversion=True, do_with_prefix=do_with_prefix)
                    except Exception as e:
                        log.error("base64 conversion of '" + str(node_value) + "' failed. " + str(e))
                        
            except KeyError:
                pass
            
    def _strip_null_bytes(self, item):
        r = item
        if (isinstance(item, str)):
            r = item.replace("\x00", "")
        if (isinstance(item, list)):
            r = []
            for s in item:
                if (isinstance(s, str)):
                    r.append(s.replace("\x00", ""))
                else:
                    r.append(s)
        return r
                    
    def report_action(self, action, params=None, description=None, strip_null_bytes=False):

        # Strip out bad characters if needed.
        if (strip_null_bytes):

            # Strip bad characters.
            from vba_object import strip_nonvb_chars

            action = strip_nonvb_chars(action)
            new_params = strip_nonvb_chars(params)
            if (isinstance(params, list)):
                new_params = []
                for p in params:
                    tmp_p = strip_nonvb_chars(p)
                    if (len(re.findall(r"NULL", str(tmp_p))) > 20):
                        tmp_p = str(tmp_p).replace("NULL", "")
                    new_params.append(tmp_p)
            params = new_params
            description = strip_nonvb_chars(description)

            # Strip repeated NULLs in the action.
            if (len(re.findall(r"NULL", action)) > 20):
                action = action.replace("NULL", "")
            
        # Save the action for reporting.
        self.got_actions = True
        self.engine.report_action(action, params, description)

