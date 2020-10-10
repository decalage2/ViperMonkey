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

# === VBA CLASSES =====================================================================================================

# global dictionary of constants, functions and subs for the VBA library
VBA_LIBRARY = {}

# Output directory to save dropped artifacts.
out_dir = None  # type: str

# Track intermediate IOC values stored in variables during emulation.
intermediate_iocs = set()

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
            return ((self.call_stack == other.call_stack) and
                    (self.globals == other.globals) and
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
                
        # Try to get the item using the current with context.
        if (name.startswith(".")):

            # Add in the current With context.
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
        tmp_name = str(self.with_prefix) + "." + str(name)
        try:
            return self.__get(tmp_name,
                              case_insensitive=case_insensitive,
                              local_only=local_only,
                              global_only=global_only)
        except KeyError:
            pass
        
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
            return self.doc_vars.items()
        
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

        # Is there base64 in the data?
        B64_REGEX = r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
        b64_strs = re.findall(B64_REGEX, value)
        for curr_value in b64_strs:
            if ((value not in intermediate_iocs) and (len(curr_value) > 200)):
                got_ioc = True
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

            from vba_object import strip_nonvb_chars

            action = strip_nonvb_chars(action)
            new_params = strip_nonvb_chars(params)
            if (isinstance(params, list)):
                new_params = []
                for p in params:
                    new_params.append(strip_nonvb_chars(p))
            params = new_params
            description = strip_nonvb_chars(description)
            
        # Save the action for reporting.
        self.got_actions = True
        self.engine.report_action(action, params, description)

