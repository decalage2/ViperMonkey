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

import os
from hashlib import sha256
from datetime import datetime
from logger import log
import base64
import re
import random
import string
import codecs
from curses_ascii import isascii

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
                 expand_env_vars=True):

        # Track the current call stack. This is used to detect simple cases of
        # infinite recursion.
        self.call_stack = []
        
        # Track the maximum number of iterations to emulate in a while loop before
        # breaking out (infinite loop) due to no vars in the loop guard being
        # modified.
        self.max_static_iters = 2

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
        got_error = False

        # Track the error handler to execute when an error is raised.
        error_handler = None
        
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

        # Track the final contents of written files.
        self.closed_files = {}

        # Track whether variables by default should go in the global scope.
        self.global_scope = False

        # globals should be a pointer to the globals dict from the core VBA engine (ViperMonkey)
        # because each statement should be able to change global variables
        if _globals is not None:
            if (copy_globals):
                self.globals = dict(_globals)
            else:
                self.globals = _globals
        elif context is not None:
            if (copy_globals):
                self.globals = dict(context.globals)
            else:
                self.globals = context.globals
            self.open_files = context.open_files
            self.closed_files = context.closed_files
            self.loaded_excel = context.loaded_excel
            self.dll_func_true_names = context.dll_func_true_names
            self.filename = context.filename
            self.skip_handlers = context.skip_handlers
            self.call_stack = context.call_stack
            self.expand_env_vars = context.expand_env_vars
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

        log.debug("Have xlrd loaded Excel file = " + str(self.loaded_excel is not None))
            
        # Track data saved in document variables.
        if doc_vars is not None:
            # direct copy of the pointer to globals:
            self.doc_vars = doc_vars
        elif context is not None:
            self.doc_vars = context.doc_vars
        else:
            self.doc_vars = {}
            
        # Track whether nested loops are running with a stack of flags. If a loop is
        # running its flag will be True.
        self.loop_stack = []

        # Track whether we have exited from the current function.
        self.exit_func = False

        # Track variable types, if known.
        self.types = {}

        # Track the current with prefix for with statements.
        self.with_prefix = ""

        # Add in a global for the current time.
        self.globals["Now".lower()] = datetime.now()

        # Fake up a user name.
        rand_name = ''.join(random.choice(string.ascii_uppercase + string.digits + " ") for _ in range(random.randint(10, 50)))
        self.globals["Application.UserName".lower()] = rand_name

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
        self.globals["xlPivotLineBlank".lower()] = 2
        self.globals["rgbMaroon".lower()] = 128

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

        # Excel error codes.
        self.globals["xlErrDiv0".lower()] = 2007  #DIV/0!
        self.globals["xlErrNA".lower()] = 2042    #N/A
        self.globals["xlErrName".lower()] = 2029  #NAME?
        self.globals["xlErrNull".lower()] = 2000  #NULL!
        self.globals["xlErrNum".lower()] = 2036   #NUM!
        self.globals["xlErrRef".lower()] = 2023   #REF!
        self.globals["xlErrValue".lower()] = 2015 #VALUE!

        # System info.
        self.globals["System.OperatingSystem".lower()] = "Windows NT"

        # Call type constants.
        self.globals["vbGet".lower()] = 2
        self.globals["vbLet".lower()] = 4
        self.globals["vbMethod".lower()] = 1
        self.globals["vbSet".lower()] = 8

        # XlTickMark Enum
        self.globals["xlTickMarkCross".lower()] = 4	
        self.globals["xlTickMarkInside".lower()] = 2	
        self.globals["xlTickMarkNone".lower()] = -4142	
        self.globals["xlTickMarkOutside".lower()] = 3	

        # XlXmlExportResult Enum
        self.globals["xlXmlExportSuccess".lower()] = 0	
        self.globals["xlXmlExportValidationFailed".lower()] = 1	

        # XLPrintErrors Enum
        self.globals["xlPrintErrorsBlank".lower()] = 1	
        self.globals["xlPrintErrorsDash".lower()] = 2	
        self.globals["xlPrintErrorsDisplayed".lower()] = 0	
        self.globals["xlPrintErrorsNA".lower()] = 3	

        # msoTextCaps Enum
        self.globals["msoAllCaps".lower()] = 2
        self.globals["msoCapsMixed".lower()] = -2
        self.globals["msoNoCaps".lower()] = 0
        self.globals["msoSmallCaps".lower()] = 1

        # XlApplicationInternational enumeration (Excel)
        self.globals["xl24HourClock".lower()] = 33
        self.globals["xl4DigitYears".lower()] = 43
        self.globals["xlAlternateArraySeparator".lower()] = 16
        self.globals["xlColumnSeparator".lower()] = 14
        self.globals["xlCountryCode".lower()] = 1
        self.globals["xlCountrySetting".lower()] = 2
        self.globals["xlCurrencyBefore".lower()] = 37
        self.globals["xlCurrencyCode".lower()] = 25
        self.globals["xlCurrencyDigits".lower()] = 27
        self.globals["xlCurrencyLeadingZeros".lower()] = 40
        self.globals["xlCurrencyMinusSign".lower()] = 38
        self.globals["xlCurrencyNegative".lower()] = 28
        self.globals["xlCurrencySpaceBefore".lower()] = 36
        self.globals["xlCurrencyTrailingZeros".lower()] = 39
        self.globals["xlDateOrder".lower()] = 32
        self.globals["xlDateSeparator".lower()] = 17
        self.globals["xlDayCode".lower()] = 21
        self.globals["xlDayLeadingZero".lower()] = 42
        self.globals["xlDecimalSeparator".lower()] = 3
        self.globals["xlGeneralFormatName".lower()] = 26
        self.globals["xlHourCode".lower()] = 22
        self.globals["xlLeftBrace".lower()] = 12
        self.globals["xlLeftBracket".lower()] = 10
        self.globals["xlListSeparator".lower()] = 5
        self.globals["xlLowerCaseColumnLetter".lower()] = 9
        self.globals["xlLowerCaseRowLetter".lower()] = 8
        self.globals["xlMDY".lower()] = 44
        self.globals["xlMetric".lower()] = 35
        self.globals["xlMinuteCode".lower()] = 23
        self.globals["xlMonthCode".lower()] = 20
        self.globals["xlMonthLeadingZero".lower()] = 41
        self.globals["xlMonthNameChars".lower()] = 30
        self.globals["xlNoncurrencyDigits".lower()] = 29
        self.globals["xlNonEnglishFunctions".lower()] = 34
        self.globals["xlRightBrace".lower()] = 13
        self.globals["xlRightBracket".lower()] = 11
        self.globals["xlRowSeparator".lower()] = 15
        self.globals["xlSecondCode".lower()] = 24
        self.globals["xlThousandsSeparator".lower()] = 4
        self.globals["xlTimeLeadingZero".lower()] = 45
        self.globals["xlTimeSeparator".lower()] = 18
        self.globals["xlUpperCaseColumnLetter".lower()] = 7
        self.globals["xlUpperCaseRowLetter".lower()] = 6
        self.globals["xlWeekdayNameChars".lower()] = 31
        self.globals["xlYearCode".lower()] = 19

        # XlBinsType enumeration (Word)
        self.globals["xlBinsTypeAutomatic".lower()] = 0
        self.globals["xlBinsTypeCategorical".lower()] = 1
        self.globals["xlBinsTypeManual".lower()] = 2
        self.globals["xlBinsTypeBinSize".lower()] = 3
        self.globals["xlBinsTypeBinCount".lower()] = 4

        # XlPieSliceIndex Enum
        self.globals["xlCenterPoint".lower()] = 5	
        self.globals["xlInnerCenterPoint".lower()] = 8	
        self.globals["xlInnerClockwisePoint".lower()] = 7	
        self.globals["xlInnerCounterClockwisePoint".lower()] = 9	
        self.globals["xlMidClockwiseRadiusPoint".lower()] = 4	
        self.globals["xlMidCounterClockwiseRadiusPoint".lower()] = 6	
        self.globals["xlOuterCenterPoint".lower()] = 2	
        self.globals["xlOuterClockwisePoint".lower()] = 3	
        self.globals["xlOuterCounterClockwisePoint".lower()] = 1	        

        # XlUnderlineStyle Enum
        self.globals["xlUnderlineStyleDouble".lower()] = -4119	
        self.globals["xlUnderlineStyleDoubleAccounting".lower()] = 5	
        self.globals["xlUnderlineStyleNone".lower()] = -4142	
        self.globals["xlUnderlineStyleSingle".lower()] = 2	
        self.globals["xlUnderlineStyleSingleAccounting".lower()] = 4	

        # XlTimeUnit enumeration
        self.globals["xlDays".lower()] = 0
        self.globals["xlMonths".lower()] = 1
        self.globals["xlYears".lower()] = 2
        
        # Misc.
        self.globals["ActiveDocument.Scripts.Count".lower()] = 0
        self.globals["TotalPhysicalMemory".lower()] = 2097741824
        if self.filename:
            self.globals["WSCRIPT.SCRIPTFULLNAME".lower()] = "C:\\" + self.filename
        self.globals["OSlanguage".lower()] = "**MATCH ANY**"
        self.globals["Err.Number".lower()] = "**MATCH ANY**"
        self.globals["Selection".lower()] = "**SELECTED TEXT IN DOC**"

        # List of _all_ Excel constants taken from https://www.autohotkey.com/boards/viewtopic.php?t=60538&p=255925 .
        self.globals["_xlDialogChartSourceData".lower()] = 541
        self.globals["_xlDialogPhonetic".lower()] = 538
        self.globals["msoLimited".lower()] = 1
        self.globals["msoNoOverwrite".lower()] = 3
        self.globals["msoOrganization".lower()] = 2
        self.globals["msoPBIAbort".lower()] = 1
        self.globals["msoPBIExport".lower()] = 0
        self.globals["msoPBIIgnore".lower()] = 0
        self.globals["msoPBIOverwrite".lower()] = 2
        self.globals["msoPBIUpload".lower()] = 1
        self.globals["msoPublic".lower()] = 0
        self.globals["rgbAliceBlue".lower()] = 16775408
        self.globals["rgbAntiqueWhite".lower()] = 14150650
        self.globals["rgbAqua".lower()] = 16776960
        self.globals["rgbAquamarine".lower()] = 13959039
        self.globals["rgbAzure".lower()] = 16777200
        self.globals["rgbBeige".lower()] = 14480885
        self.globals["rgbBisque".lower()] = 12903679
        self.globals["rgbBlack".lower()] = 0
        self.globals["rgbBlanchedAlmond".lower()] = 13495295
        self.globals["rgbBlue".lower()] = 16711680
        self.globals["rgbBlueViolet".lower()] = 14822282
        self.globals["rgbBrown".lower()] = 2763429
        self.globals["rgbBurlyWood".lower()] = 8894686
        self.globals["rgbCadetBlue".lower()] = 10526303
        self.globals["rgbChartreuse".lower()] = 65407
        self.globals["rgbCoral".lower()] = 5275647
        self.globals["rgbCornflowerBlue".lower()] = 15570276
        self.globals["rgbCornsilk".lower()] = 14481663
        self.globals["rgbCrimson".lower()] = 3937500
        self.globals["rgbDarkBlue".lower()] = 9109504
        self.globals["rgbDarkCyan".lower()] = 9145088
        self.globals["rgbDarkGoldenrod".lower()] = 755384
        self.globals["rgbDarkGray".lower()] = 11119017
        self.globals["rgbDarkGreen".lower()] = 25600
        self.globals["rgbDarkGrey".lower()] = 11119017
        self.globals["rgbDarkKhaki".lower()] = 7059389
        self.globals["rgbDarkMagenta".lower()] = 9109643
        self.globals["rgbDarkOliveGreen".lower()] = 3107669
        self.globals["rgbDarkOrange".lower()] = 36095
        self.globals["rgbDarkOrchid".lower()] = 13382297
        self.globals["rgbDarkRed".lower()] = 139
        self.globals["rgbDarkSalmon".lower()] = 8034025
        self.globals["rgbDarkSeaGreen".lower()] = 9419919
        self.globals["rgbDarkSlateBlue".lower()] = 9125192
        self.globals["rgbDarkSlateGray".lower()] = 5197615
        self.globals["rgbDarkSlateGrey".lower()] = 5197615
        self.globals["rgbDarkTurquoise".lower()] = 13749760
        self.globals["rgbDarkViolet".lower()] = 13828244
        self.globals["rgbDeepPink".lower()] = 9639167
        self.globals["rgbDeepSkyBlue".lower()] = 16760576
        self.globals["rgbDimGray".lower()] = 6908265
        self.globals["rgbDimGrey".lower()] = 6908265
        self.globals["rgbDodgerBlue".lower()] = 16748574
        self.globals["rgbFireBrick".lower()] = 2237106
        self.globals["rgbFloralWhite".lower()] = 15792895
        self.globals["rgbForestGreen".lower()] = 2263842
        self.globals["rgbFuchsia".lower()] = 16711935
        self.globals["rgbGainsboro".lower()] = 14474460
        self.globals["rgbGhostWhite".lower()] = 16775416
        self.globals["rgbGold".lower()] = 55295
        self.globals["rgbGoldenrod".lower()] = 2139610
        self.globals["rgbGray".lower()] = 8421504
        self.globals["rgbGreen".lower()] = 32768
        self.globals["rgbGreenYellow".lower()] = 3145645
        self.globals["rgbGrey".lower()] = 8421504
        self.globals["rgbHoneydew".lower()] = 15794160
        self.globals["rgbHotPink".lower()] = 11823615
        self.globals["rgbIndianRed".lower()] = 6053069
        self.globals["rgbIndigo".lower()] = 8519755
        self.globals["rgbIvory".lower()] = 15794175
        self.globals["rgbKhaki".lower()] = 9234160
        self.globals["rgbLavender".lower()] = 16443110
        self.globals["rgbLavenderBlush".lower()] = 16118015
        self.globals["rgbLawnGreen".lower()] = 64636
        self.globals["rgbLemonChiffon".lower()] = 13499135
        self.globals["rgbLightBlue".lower()] = 15128749
        self.globals["rgbLightCoral".lower()] = 8421616
        self.globals["rgbLightCyan".lower()] = 9145088
        self.globals["rgbLightGoldenrodYellow".lower()] = 13826810
        self.globals["rgbLightGray".lower()] = 13882323
        self.globals["rgbLightGreen".lower()] = 9498256
        self.globals["rgbLightGrey".lower()] = 13882323
        self.globals["rgbLightPink".lower()] = 12695295
        self.globals["rgbLightSalmon".lower()] = 8036607
        self.globals["rgbLightSeaGreen".lower()] = 11186720
        self.globals["rgbLightSkyBlue".lower()] = 16436871
        self.globals["rgbLightSlateGray".lower()] = 10061943
        self.globals["rgbLightSlateGrey".lower()] = 10061943
        self.globals["rgbLightSteelBlue".lower()] = 14599344
        self.globals["rgbLightYellow".lower()] = 14745599
        self.globals["rgbLime".lower()] = 65280
        self.globals["rgbLimeGreen".lower()] = 3329330
        self.globals["rgbLinen".lower()] = 15134970
        self.globals["rgbMaroon".lower()] = 128
        self.globals["rgbMediumAquamarine".lower()] = 11206502
        self.globals["rgbMediumBlue".lower()] = 13434880
        self.globals["rgbMediumOrchid".lower()] = 13850042
        self.globals["rgbMediumPurple".lower()] = 14381203
        self.globals["rgbMediumSeaGreen".lower()] = 7451452
        self.globals["rgbMediumSlateBlue".lower()] = 15624315
        self.globals["rgbMediumSpringGreen".lower()] = 10156544
        self.globals["rgbMediumTurquoise".lower()] = 13422920
        self.globals["rgbMediumVioletRed".lower()] = 8721863
        self.globals["rgbMidnightBlue".lower()] = 7346457
        self.globals["rgbMintCream".lower()] = 16449525
        self.globals["rgbMistyRose".lower()] = 14804223
        self.globals["rgbMoccasin".lower()] = 11920639
        self.globals["rgbNavajoWhite".lower()] = 11394815
        self.globals["rgbNavy".lower()] = 8388608
        self.globals["rgbNavyBlue".lower()] = 8388608
        self.globals["rgbOldLace".lower()] = 15136253
        self.globals["rgbOlive".lower()] = 32896
        self.globals["rgbOliveDrab".lower()] = 2330219
        self.globals["rgbOrange".lower()] = 42495
        self.globals["rgbOrangeRed".lower()] = 17919
        self.globals["rgbOrchid".lower()] = 14053594
        self.globals["rgbPaleGoldenrod".lower()] = 7071982
        self.globals["rgbPaleGreen".lower()] = 10025880
        self.globals["rgbPaleTurquoise".lower()] = 15658671
        self.globals["rgbPaleVioletRed".lower()] = 9662683
        self.globals["rgbPapayaWhip".lower()] = 14020607
        self.globals["rgbPeachPuff".lower()] = 12180223
        self.globals["rgbPeru".lower()] = 4163021
        self.globals["rgbPink".lower()] = 13353215
        self.globals["rgbPlum".lower()] = 14524637
        self.globals["rgbPowderBlue".lower()] = 15130800
        self.globals["rgbPurple".lower()] = 8388736
        self.globals["rgbRed".lower()] = 255
        self.globals["rgbRosyBrown".lower()] = 9408444
        self.globals["rgbRoyalBlue".lower()] = 14772545
        self.globals["rgbSalmon".lower()] = 7504122
        self.globals["rgbSandyBrown".lower()] = 6333684
        self.globals["rgbSeaGreen".lower()] = 5737262
        self.globals["rgbSeashell".lower()] = 15660543
        self.globals["rgbSienna".lower()] = 2970272
        self.globals["rgbSilver".lower()] = 12632256
        self.globals["rgbSkyBlue".lower()] = 15453831
        self.globals["rgbSlateBlue".lower()] = 13458026
        self.globals["rgbSlateGray".lower()] = 9470064
        self.globals["rgbSlateGrey".lower()] = 9470064
        self.globals["rgbSnow".lower()] = 16448255
        self.globals["rgbSpringGreen".lower()] = 8388352
        self.globals["rgbSteelBlue".lower()] = 11829830
        self.globals["rgbTan".lower()] = 9221330
        self.globals["rgbTeal".lower()] = 8421376
        self.globals["rgbThistle".lower()] = 14204888
        self.globals["rgbTomato".lower()] = 4678655
        self.globals["rgbTurquoise".lower()] = 13688896
        self.globals["rgbViolet".lower()] = 15631086
        self.globals["rgbWheat".lower()] = 11788021
        self.globals["rgbWhite".lower()] = 16777215
        self.globals["rgbWhiteSmoke".lower()] = 16119285
        self.globals["rgbYellow".lower()] = 65535
        self.globals["rgbYellowGreen".lower()] = 3329434
        self.globals["xl24HourClock".lower()] = 33
        self.globals["xl3Arrows".lower()] = 1
        self.globals["xl3ArrowsGray".lower()] = 2
        self.globals["xl3DArea".lower()] = 4098
        self.globals["xl3DAreaStacked".lower()] = 78
        self.globals["xl3DAreaStacked100".lower()] = 79
        self.globals["xl3DBar".lower()] = 4099
        self.globals["xl3DBarClustered".lower()] = 60
        self.globals["xl3DBarStacked".lower()] = 61
        self.globals["xl3DBarStacked100".lower()] = 62
        self.globals["xl3DColumn".lower()] = 4100
        self.globals["xl3DColumnClustered".lower()] = 54
        self.globals["xl3DColumnStacked".lower()] = 55
        self.globals["xl3DColumnStacked100".lower()] = 56
        self.globals["xl3DEffects1".lower()] = 13
        self.globals["xl3DEffects2".lower()] = 14
        self.globals["xl3DLine".lower()] = 4101
        self.globals["xl3DPie".lower()] = 4102
        self.globals["xl3DPieExploded".lower()] = 70
        self.globals["xl3DSurface".lower()] = 4103
        self.globals["xl3Flags".lower()] = 3
        self.globals["xl3Signs".lower()] = 6
        self.globals["xl3Stars".lower()] = 18
        self.globals["xl3Symbols".lower()] = 7
        self.globals["xl3Symbols2".lower()] = 8
        self.globals["xl3TrafficLights1".lower()] = 4
        self.globals["xl3TrafficLights2".lower()] = 5
        self.globals["xl3Triangles".lower()] = 19
        self.globals["xl4Arrows".lower()] = 9
        self.globals["xl4ArrowsGray".lower()] = 10
        self.globals["xl4CRV".lower()] = 12
        self.globals["xl4DigitYears".lower()] = 43
        self.globals["xl4RedToBlack".lower()] = 11
        self.globals["xl4TrafficLights".lower()] = 13
        self.globals["xl5Arrows".lower()] = 14
        self.globals["xl5ArrowsGray".lower()] = 15
        self.globals["xl5Boxes".lower()] = 20
        self.globals["xl5CRV".lower()] = 16
        self.globals["xl5Quarters".lower()] = 17
        self.globals["xlA1".lower()] = 1
        self.globals["xlAbove".lower()] = 0
        self.globals["xlAboveAverage".lower()] = 0
        self.globals["xlAboveAverageCondition".lower()] = 12
        self.globals["xlAboveStdDev".lower()] = 4
        self.globals["xlAbsolute".lower()] = 1
        self.globals["xlAbsRowRelColumn".lower()] = 2
        self.globals["xlAccounting1".lower()] = 4
        self.globals["xlAccounting2".lower()] = 5
        self.globals["xlAccounting3".lower()] = 6
        self.globals["xlAccounting4".lower()] = 17
        self.globals["xlActionTypeDrillthrough".lower()] = 256
        self.globals["xlActionTypeReport".lower()] = 128
        self.globals["xlActionTypeRowset".lower()] = 16
        self.globals["xlActionTypeUrl".lower()] = 1
        self.globals["xlAdd".lower()] = 2
        self.globals["xlAddIn".lower()] = 18
        self.globals["xlAddIn8".lower()] = 18
        self.globals["xlADORecordset".lower()] = 7
        self.globals["xlAfter".lower()] = 33
        self.globals["xlAfterOrEqualTo".lower()] = 34
        self.globals["xlAll".lower()] = 4104
        self.globals["xlAllAtOnce".lower()] = 2
        self.globals["xlAllChanges".lower()] = 2
        self.globals["xlAllDatesInPeriodApril".lower()] = 60
        self.globals["xlAllDatesInPeriodAugust".lower()] = 64
        self.globals["xlAllDatesInPeriodDecember".lower()] = 68
        self.globals["xlAllDatesInPeriodFebruary".lower()] = 58
        self.globals["xlAllDatesInPeriodJanuary".lower()] = 57
        self.globals["xlAllDatesInPeriodJuly".lower()] = 63
        self.globals["xlAllDatesInPeriodJune".lower()] = 62
        self.globals["xlAllDatesInPeriodMarch".lower()] = 59
        self.globals["xlAllDatesInPeriodMay".lower()] = 61
        self.globals["xlAllDatesInPeriodNovember".lower()] = 67
        self.globals["xlAllDatesInPeriodOctober".lower()] = 66
        self.globals["xlAllDatesInPeriodQuarter1".lower()] = 53
        self.globals["xlAllDatesInPeriodQuarter2".lower()] = 54
        self.globals["xlAllDatesInPeriodQuarter3".lower()] = 55
        self.globals["xlAllDatesInPeriodQuarter4".lower()] = 56
        self.globals["xlAllDatesInPeriodSeptember".lower()] = 65
        self.globals["xlAllExceptBorders".lower()] = 7
        self.globals["xlAllFaces".lower()] = 7
        self.globals["xlAllocateIncrement".lower()] = 2
        self.globals["xlAllocateValue".lower()] = 1
        self.globals["xlAllTables".lower()] = 2
        self.globals["xlAllValues".lower()] = 0
        self.globals["xlAlternateArraySeparator".lower()] = 16
        self.globals["xlAlways".lower()] = 1
        self.globals["xlAnd".lower()] = 1
        self.globals["xlAnyGallery".lower()] = 23
        self.globals["xlAnyKey".lower()] = 2
        self.globals["xlArabicBothStrict".lower()] = 3
        self.globals["xlArabicNone".lower()] = 0
        self.globals["xlArabicStrictAlefHamza".lower()] = 1
        self.globals["xlArabicStrictFinalYaa".lower()] = 2
        self.globals["xlArea".lower()] = 1
        self.globals["xlAreaStacked".lower()] = 76
        self.globals["xlAreaStacked100".lower()] = 77
        self.globals["xlArrangeStyleCascade".lower()] = 7
        self.globals["xlArrangeStyleHorizontal".lower()] = 4128
        self.globals["xlArrangeStyleTiled".lower()] = 1
        self.globals["xlArrangeStyleVertical".lower()] = 4166
        self.globals["xlArrowHeadLengthLong".lower()] = 3
        self.globals["xlArrowHeadLengthMedium".lower()] = 4138
        self.globals["xlArrowHeadLengthShort".lower()] = 1
        self.globals["xlArrowHeadStyleClosed".lower()] = 3
        self.globals["xlArrowHeadStyleDoubleClosed".lower()] = 5
        self.globals["xlArrowHeadStyleDoubleOpen".lower()] = 4
        self.globals["xlArrowHeadStyleNone".lower()] = 4142
        self.globals["xlArrowHeadStyleOpen".lower()] = 2
        self.globals["xlArrowHeadWidthMedium".lower()] = 4138
        self.globals["xlArrowHeadWidthNarrow".lower()] = 1
        self.globals["xlArrowHeadWidthWide".lower()] = 3
        self.globals["xlAscending".lower()] = 1
        self.globals["xlAsRequired".lower()] = 0
        self.globals["xlAtBottom".lower()] = 2
        self.globals["xlAtTop".lower()] = 1
        self.globals["xlAutoActivate".lower()] = 3
        self.globals["xlAutoClose".lower()] = 2
        self.globals["xlAutoDeactivate".lower()] = 4
        self.globals["xlAutoFill".lower()] = 4
        self.globals["xlAutomatic".lower()] = 4105
        self.globals["xlAutomaticAllocation".lower()] = 2
        self.globals["xlAutomaticScale".lower()] = 4105
        self.globals["xlAutomaticUpdate".lower()] = 4
        self.globals["xlAutoOpen".lower()] = 1
        self.globals["xlAverage".lower()] = 4106
        self.globals["xlAxis".lower()] = 21
        self.globals["xlAxisCrossesAutomatic".lower()] = 4105
        self.globals["xlAxisCrossesCustom".lower()] = 4114
        self.globals["xlAxisCrossesMaximum".lower()] = 2
        self.globals["xlAxisCrossesMinimum".lower()] = 4
        self.globals["xlAxisTitle".lower()] = 17
        self.globals["xlBackgroundAutomatic".lower()] = 4105
        self.globals["xlBackgroundOpaque".lower()] = 3
        self.globals["xlBackgroundTransparent".lower()] = 2
        self.globals["xlBar".lower()] = 2
        self.globals["xlBarClustered".lower()] = 57
        self.globals["xlBarOfPie".lower()] = 71
        self.globals["xlBarStacked".lower()] = 58
        self.globals["xlBarStacked100".lower()] = 59
        self.globals["xlBefore".lower()] = 31
        self.globals["xlBeforeOrEqualTo".lower()] = 32
        self.globals["xlBeginsWith".lower()] = 2
        self.globals["xlBelow".lower()] = 1
        self.globals["xlBelowAverage".lower()] = 1
        self.globals["xlBelowStdDev".lower()] = 5
        self.globals["xlBetween".lower()] = 1
        self.globals["xlBidi".lower()] = 5000
        self.globals["xlBidiCalendar".lower()] = 3
        self.globals["xlBIFF".lower()] = 2
        self.globals["xlBinsTypeAutomatic".lower()] = 0
        self.globals["xlBinsTypeBinCount".lower()] = 4
        self.globals["xlBinsTypeBinSize".lower()] = 3
        self.globals["xlBinsTypeCategorical".lower()] = 1
        self.globals["xlBinsTypeManual".lower()] = 2
        self.globals["xlBitmap".lower()] = 2
        self.globals["xlBlankRow".lower()] = 19
        self.globals["xlBlanks".lower()] = 4
        self.globals["xlBlanksCondition".lower()] = 10
        self.globals["xlBMP".lower()] = 1
        self.globals["xlBoth".lower()] = 1
        self.globals["xlBottom".lower()] = 4107
        self.globals["xlBottom10Items".lower()] = 4
        self.globals["xlBottom10Percent".lower()] = 6
        self.globals["xlBottomCount".lower()] = 2
        self.globals["xlBottomPercent".lower()] = 4
        self.globals["xlBottomSum".lower()] = 6
        self.globals["xlBox".lower()] = 0
        self.globals["xlBoxwhisker".lower()] = 121
        self.globals["xlBubble".lower()] = 15
        self.globals["xlBubble3DEffect".lower()] = 87
        self.globals["xlBuiltIn".lower()] = 21
        self.globals["xlButton".lower()] = 15
        self.globals["xlButtonControl".lower()] = 0
        self.globals["xlButtonOnly".lower()] = 2
        self.globals["xlByColumns".lower()] = 2
        self.globals["xlByRows".lower()] = 1
        self.globals["xlCalculatedMeasure".lower()] = 2
        self.globals["xlCalculatedMember".lower()] = 0
        self.globals["xlCalculatedSet".lower()] = 1
        self.globals["xlCalculating".lower()] = 1
        self.globals["xlCalculationAutomatic".lower()] = 4105
        self.globals["xlCalculationManual".lower()] = 4135
        self.globals["xlCalculationSemiautomatic".lower()] = 2
        self.globals["xlCancel".lower()] = 1
        self.globals["xlCap".lower()] = 1
        self.globals["xlCaptionBeginsWith".lower()] = 17
        self.globals["xlCaptionContains".lower()] = 21
        self.globals["xlCaptionDoesNotBeginWith".lower()] = 18
        self.globals["xlCaptionDoesNotContain".lower()] = 22
        self.globals["xlCaptionDoesNotEndWith".lower()] = 20
        self.globals["xlCaptionDoesNotEqual".lower()] = 16
        self.globals["xlCaptionEndsWith".lower()] = 19
        self.globals["xlCaptionEquals".lower()] = 15
        self.globals["xlCaptionIsBetween".lower()] = 27
        self.globals["xlCaptionIsGreaterThan".lower()] = 23
        self.globals["xlCaptionIsGreaterThanOrEqualTo".lower()] = 24
        self.globals["xlCaptionIsLessThan".lower()] = 25
        self.globals["xlCaptionIsLessThanOrEqualTo".lower()] = 26
        self.globals["xlCaptionIsNotBetween".lower()] = 28
        self.globals["xlCascade".lower()] = 7
        self.globals["xlCategory".lower()] = 1
        self.globals["xlCategoryAscending".lower()] = 2
        self.globals["xlCategoryDescending".lower()] = 3
        self.globals["xlCategoryLabelLevelAll".lower()] = 1
        self.globals["xlCategoryLabelLevelCustom".lower()] = 2
        self.globals["xlCategoryLabelLevelNone".lower()] = 3
        self.globals["xlCategoryScale".lower()] = 2
        self.globals["xlCellChangeApplied".lower()] = 3
        self.globals["xlCellChanged".lower()] = 2
        self.globals["xlCellNotChanged".lower()] = 1
        self.globals["xlCellTypeAllFormatConditions".lower()] = 4172
        self.globals["xlCellTypeAllValidation".lower()] = 4174
        self.globals["xlCellTypeBlanks".lower()] = 4
        self.globals["xlCellTypeComments".lower()] = 4144
        self.globals["xlCellTypeConstants".lower()] = 2
        self.globals["xlCellTypeFormulas".lower()] = 4123
        self.globals["xlCellTypeLastCell".lower()] = 11
        self.globals["xlCellTypeSameFormatConditions".lower()] = 4173
        self.globals["xlCellTypeSameValidation".lower()] = 4175
        self.globals["xlCellTypeVisible".lower()] = 12
        self.globals["xlCellValue".lower()] = 1
        self.globals["xlCenter".lower()] = 4108
        self.globals["xlCenterAcrossSelection".lower()] = 7
        self.globals["xlCenterPoint".lower()] = 5
        self.globals["xlCentimeters".lower()] = 1
        self.globals["xlCGM".lower()] = 7
        self.globals["xlChangeAttributes".lower()] = 6
        self.globals["xlChangeByExcel".lower()] = 0
        self.globals["xlChangeByPowerPivotAddIn".lower()] = 1
        self.globals["xlChart".lower()] = 4109
        self.globals["xlChart4".lower()] = 2
        self.globals["xlChartArea".lower()] = 2
        self.globals["xlChartAsWindow".lower()] = 5
        self.globals["xlChartElementPositionAutomatic".lower()] = 4105
        self.globals["xlChartElementPositionCustom".lower()] = 4114
        self.globals["xlChartInPlace".lower()] = 4
        self.globals["xlChartSeries".lower()] = 17
        self.globals["xlChartShort".lower()] = 6
        self.globals["xlChartTitle".lower()] = 4
        self.globals["xlChartTitles".lower()] = 18
        self.globals["xlCheckBox".lower()] = 1
        self.globals["xlChecker".lower()] = 9
        self.globals["xlCheckInMajorVersion".lower()] = 1
        self.globals["xlCheckInMinorVersion".lower()] = 0
        self.globals["xlCheckInOverwriteVersion".lower()] = 2
        self.globals["xlChronological".lower()] = 3
        self.globals["xlCircle".lower()] = 8
        self.globals["xlClassic1".lower()] = 1
        self.globals["xlClassic2".lower()] = 2
        self.globals["xlClassic3".lower()] = 3
        self.globals["xlClipboard".lower()] = 3
        self.globals["xlClipboardFormatBIFF".lower()] = 8
        self.globals["xlClipboardFormatBIFF12".lower()] = 63
        self.globals["xlClipboardFormatBIFF2".lower()] = 18
        self.globals["xlClipboardFormatBIFF3".lower()] = 20
        self.globals["xlClipboardFormatBIFF4".lower()] = 30
        self.globals["xlClipboardFormatBinary".lower()] = 15
        self.globals["xlClipboardFormatBitmap".lower()] = 9
        self.globals["xlClipboardFormatCGM".lower()] = 13
        self.globals["xlClipboardFormatCSV".lower()] = 5
        self.globals["xlClipboardFormatDIF".lower()] = 4
        self.globals["xlClipboardFormatDspText".lower()] = 12
        self.globals["xlClipboardFormatEmbeddedObject".lower()] = 21
        self.globals["xlClipboardFormatEmbedSource".lower()] = 22
        self.globals["xlClipboardFormatLink".lower()] = 11
        self.globals["xlClipboardFormatLinkSource".lower()] = 23
        self.globals["xlClipboardFormatLinkSourceDesc".lower()] = 32
        self.globals["xlClipboardFormatMovie".lower()] = 24
        self.globals["xlClipboardFormatNative".lower()] = 14
        self.globals["xlClipboardFormatObjectDesc".lower()] = 31
        self.globals["xlClipboardFormatObjectLink".lower()] = 19
        self.globals["xlClipboardFormatOwnerLink".lower()] = 17
        self.globals["xlClipboardFormatPICT".lower()] = 2
        self.globals["xlClipboardFormatPrintPICT".lower()] = 3
        self.globals["xlClipboardFormatRTF".lower()] = 7
        self.globals["xlClipboardFormatScreenPICT".lower()] = 29
        self.globals["xlClipboardFormatStandardFont".lower()] = 28
        self.globals["xlClipboardFormatStandardScale".lower()] = 27
        self.globals["xlClipboardFormatSYLK".lower()] = 6
        self.globals["xlClipboardFormatTable".lower()] = 16
        self.globals["xlClipboardFormatText".lower()] = 0
        self.globals["xlClipboardFormatToolFace".lower()] = 25
        self.globals["xlClipboardFormatToolFacePICT".lower()] = 26
        self.globals["xlClipboardFormatVALU".lower()] = 1
        self.globals["xlClipboardFormatWK1".lower()] = 10
        self.globals["xlClosed".lower()] = 3
        self.globals["xlCmdCube".lower()] = 1
        self.globals["xlCmdDAX".lower()] = 8
        self.globals["xlCmdDefault".lower()] = 4
        self.globals["xlCmdExcel".lower()] = 7
        self.globals["xlCmdList".lower()] = 5
        self.globals["xlCmdSql".lower()] = 2
        self.globals["xlCmdTable".lower()] = 3
        self.globals["xlCmdTableCollection".lower()] = 6
        self.globals["xlCodePage".lower()] = 2
        self.globals["xlColGroups".lower()] = 2
        self.globals["xlColor1".lower()] = 7
        self.globals["xlColor2".lower()] = 8
        self.globals["xlColor3".lower()] = 9
        self.globals["xlColorIndexAutomatic".lower()] = 4105
        self.globals["xlColorIndexNone".lower()] = 4142
        self.globals["xlColorScale".lower()] = 3
        self.globals["xlColorScaleBlackWhite".lower()] = 3
        self.globals["xlColorScaleGYR".lower()] = 2
        self.globals["xlColorScaleRYG".lower()] = 1
        self.globals["xlColorScaleWhiteBlack".lower()] = 4
        self.globals["xlColumn".lower()] = 3
        self.globals["xlColumnClustered".lower()] = 51
        self.globals["xlColumnField".lower()] = 2
        self.globals["xlColumnHeader".lower()] = 4110
        self.globals["xlColumnItem".lower()] = 5
        self.globals["xlColumnLabels".lower()] = 2
        self.globals["xlColumns".lower()] = 2
        self.globals["xlColumnSeparator".lower()] = 14
        self.globals["xlColumnStacked".lower()] = 52
        self.globals["xlColumnStacked100".lower()] = 53
        self.globals["xlColumnStripe1".lower()] = 7
        self.globals["xlColumnStripe2".lower()] = 8
        self.globals["xlColumnSubheading1".lower()] = 20
        self.globals["xlColumnSubheading2".lower()] = 21
        self.globals["xlColumnSubheading3".lower()] = 22
        self.globals["xlColumnThenRow".lower()] = 2
        self.globals["xlCombination".lower()] = 4111
        self.globals["xlCommand".lower()] = 2
        self.globals["xlCommandUnderlinesAutomatic".lower()] = 4105
        self.globals["xlCommandUnderlinesOff".lower()] = 4146
        self.globals["xlCommandUnderlinesOn".lower()] = 1
        self.globals["xlCommentAndIndicator".lower()] = 1
        self.globals["xlCommentIndicatorOnly".lower()] = 1
        self.globals["xlComments".lower()] = 4144
        self.globals["xlCompactRow".lower()] = 0
        self.globals["xlComplete".lower()] = 4
        self.globals["xlConditionValueAutomaticMax".lower()] = 7
        self.globals["xlConditionValueAutomaticMin".lower()] = 6
        self.globals["xlConditionValueFormula".lower()] = 4
        self.globals["xlConditionValueHighestValue".lower()] = 2
        self.globals["xlConditionValueLowestValue".lower()] = 1
        self.globals["xlConditionValueNone".lower()] = 1
        self.globals["xlConditionValueNumber".lower()] = 0
        self.globals["xlConditionValuePercent".lower()] = 3
        self.globals["xlConditionValuePercentile".lower()] = 5
        self.globals["xlConeBarClustered".lower()] = 102
        self.globals["xlConeBarStacked".lower()] = 103
        self.globals["xlConeBarStacked100".lower()] = 104
        self.globals["xlConeCol".lower()] = 105
        self.globals["xlConeColClustered".lower()] = 99
        self.globals["xlConeColStacked".lower()] = 100
        self.globals["xlConeColStacked100".lower()] = 101
        self.globals["xlConeToMax".lower()] = 5
        self.globals["xlConeToPoint".lower()] = 4
        self.globals["xlConnectionTypeDATAFEED".lower()] = 6
        self.globals["xlConnectionTypeMODEL".lower()] = 7
        self.globals["xlConnectionTypeNOSOURCE".lower()] = 9
        self.globals["xlConnectionTypeODBC".lower()] = 2
        self.globals["xlConnectionTypeOLEDB".lower()] = 1
        self.globals["xlConnectionTypeTEXT".lower()] = 4
        self.globals["xlConnectionTypeWEB".lower()] = 5
        self.globals["xlConnectionTypeWORKSHEET".lower()] = 8
        self.globals["xlConnectionTypeXMLMAP".lower()] = 3
        self.globals["xlConsolidation".lower()] = 3
        self.globals["xlConstant".lower()] = 1
        self.globals["xlConstants".lower()] = 2
        self.globals["xlContains".lower()] = 0
        self.globals["xlContents".lower()] = 2
        self.globals["xlContext".lower()] = 5002
        self.globals["xlContinuous".lower()] = 1
        self.globals["xlCopy".lower()] = 1
        self.globals["xlCorner".lower()] = 2
        self.globals["xlCorners".lower()] = 6
        self.globals["xlCount".lower()] = 4112
        self.globals["xlCountNums".lower()] = 4113
        self.globals["xlCountryCode".lower()] = 1
        self.globals["xlCountrySetting".lower()] = 2
        self.globals["xlCreatorCode".lower()] = 1480803660
        self.globals["xlCredentialsMethodIntegrated".lower()] = 0
        self.globals["xlCredentialsMethodNone".lower()] = 1
        self.globals["xlCredentialsMethodStored".lower()] = 2
        self.globals["xlCrissCross".lower()] = 16
        self.globals["xlCross".lower()] = 4
        self.globals["xlCSV".lower()] = 6
        self.globals["xlCSVMac".lower()] = 22
        self.globals["xlCSVMSDOS".lower()] = 24
        self.globals["xlCSVUTF8".lower()] = 62
        self.globals["xlCSVWindows".lower()] = 23
        self.globals["xlCubeAttribute".lower()] = 4
        self.globals["xlCubeCalculatedMeasure".lower()] = 5
        self.globals["xlCubeHierarchy".lower()] = 1
        self.globals["xlCubeImplicitMeasure".lower()] = 11
        self.globals["xlCubeKPIGoal".lower()] = 7
        self.globals["xlCubeKPIStatus".lower()] = 8
        self.globals["xlCubeKPITrend".lower()] = 9
        self.globals["xlCubeKPIValue".lower()] = 6
        self.globals["xlCubeKPIWeight".lower()] = 10
        self.globals["xlCubeMeasure".lower()] = 2
        self.globals["xlCubeSet".lower()] = 3
        self.globals["xlCurrencyBefore".lower()] = 37
        self.globals["xlCurrencyCode".lower()] = 25
        self.globals["xlCurrencyDigits".lower()] = 27
        self.globals["xlCurrencyLeadingZeros".lower()] = 40
        self.globals["xlCurrencyMinusSign".lower()] = 38
        self.globals["xlCurrencyNegative".lower()] = 28
        self.globals["xlCurrencySpaceBefore".lower()] = 36
        self.globals["xlCurrencyTrailingZeros".lower()] = 39
        self.globals["xlCurrentPlatformText".lower()] = 4158
        self.globals["xlCustom".lower()] = 4114
        self.globals["xlCustomSet".lower()] = 1
        self.globals["xlCut".lower()] = 2
        self.globals["xlCylinder".lower()] = 3
        self.globals["xlCylinderBarClustered".lower()] = 95
        self.globals["xlCylinderBarStacked".lower()] = 96
        self.globals["xlCylinderBarStacked100".lower()] = 97
        self.globals["xlCylinderCol".lower()] = 98
        self.globals["xlCylinderColClustered".lower()] = 92
        self.globals["xlCylinderColStacked".lower()] = 93
        self.globals["xlCylinderColStacked100".lower()] = 94
        self.globals["xlDAORecordset".lower()] = 2
        self.globals["xlDash".lower()] = 4115
        self.globals["xlDashDot".lower()] = 4
        self.globals["xlDashDotDot".lower()] = 5
        self.globals["xlDataAndLabel".lower()] = 0
        self.globals["xlDatabar".lower()] = 4
        self.globals["xlDataBarAxisAutomatic".lower()] = 0
        self.globals["xlDataBarAxisMidpoint".lower()] = 1
        self.globals["xlDataBarAxisNone".lower()] = 2
        self.globals["xlDataBarBorderNone".lower()] = 0
        self.globals["xlDataBarBorderSolid".lower()] = 1
        self.globals["xlDataBarColor".lower()] = 0
        self.globals["xlDataBarFillGradient".lower()] = 1
        self.globals["xlDataBarFillSolid".lower()] = 0
        self.globals["xlDataBarSameAsPositive".lower()] = 1
        self.globals["xlDatabase".lower()] = 1
        self.globals["xlDataField".lower()] = 4
        self.globals["xlDataFieldScope".lower()] = 2
        self.globals["xlDataHeader".lower()] = 3
        self.globals["xlDataItem".lower()] = 7
        self.globals["xlDataLabel".lower()] = 0
        self.globals["xlDataLabelSeparatorDefault".lower()] = 1
        self.globals["xlDataLabelsShowBubbleSizes".lower()] = 6
        self.globals["xlDataLabelsShowLabel".lower()] = 4
        self.globals["xlDataLabelsShowLabelAndPercent".lower()] = 5
        self.globals["xlDataLabelsShowNone".lower()] = 4142
        self.globals["xlDataLabelsShowPercent".lower()] = 3
        self.globals["xlDataLabelsShowValue".lower()] = 2
        self.globals["xlDataOnly".lower()] = 2
        self.globals["xlDataSeriesLinear".lower()] = 4132
        self.globals["xlDataTable".lower()] = 7
        self.globals["xlDate".lower()] = 2
        self.globals["xlDateBetween".lower()] = 35
        self.globals["xlDateLastMonth".lower()] = 45
        self.globals["xlDateLastQuarter".lower()] = 48
        self.globals["xlDateLastWeek".lower()] = 42
        self.globals["xlDateLastYear".lower()] = 51
        self.globals["xlDateNextMonth".lower()] = 43
        self.globals["xlDateNextQuarter".lower()] = 46
        self.globals["xlDateNextWeek".lower()] = 40
        self.globals["xlDateNextYear".lower()] = 49
        self.globals["xlDateNotBetween".lower()] = 36
        self.globals["xlDateOrder".lower()] = 32
        self.globals["xlDateSeparator".lower()] = 17
        self.globals["xlDateThisMonth".lower()] = 44
        self.globals["xlDateThisQuarter".lower()] = 47
        self.globals["xlDateThisWeek".lower()] = 41
        self.globals["xlDateThisYear".lower()] = 50
        self.globals["xlDateToday".lower()] = 38
        self.globals["xlDateTomorrow".lower()] = 37
        self.globals["xlDateYesterday".lower()] = 39
        self.globals["xlDay".lower()] = 1
        self.globals["xlDayCode".lower()] = 21
        self.globals["xlDayLeadingZero".lower()] = 42
        self.globals["xlDays".lower()] = 0
        self.globals["xlDBF2".lower()] = 7
        self.globals["xlDBF3".lower()] = 8
        self.globals["xlDBF4".lower()] = 11
        self.globals["xlDebugCodePane".lower()] = 13
        self.globals["xlDecimalSeparator".lower()] = 3
        self.globals["xlDefault".lower()] = 4143
        self.globals["xlDefaultAutoFormat".lower()] = 1
        self.globals["xlDelimited".lower()] = 1
        self.globals["xlDescending".lower()] = 2
        self.globals["xlDesktop".lower()] = 9
        self.globals["xlDiagonalDown".lower()] = 5
        self.globals["xlDiagonalUp".lower()] = 6
        self.globals["xlDialogActivate".lower()] = 103
        self.globals["xlDialogActiveCellFont".lower()] = 476
        self.globals["xlDialogAddChartAutoformat".lower()] = 390
        self.globals["xlDialogAddinManager".lower()] = 321
        self.globals["xlDialogAlignment".lower()] = 43
        self.globals["xlDialogApplyNames".lower()] = 133
        self.globals["xlDialogApplyStyle".lower()] = 212
        self.globals["xlDialogAppMove".lower()] = 170
        self.globals["xlDialogAppSize".lower()] = 171
        self.globals["xlDialogArrangeAll".lower()] = 12
        self.globals["xlDialogAssignToObject".lower()] = 213
        self.globals["xlDialogAssignToTool".lower()] = 293
        self.globals["xlDialogAttachText".lower()] = 80
        self.globals["xlDialogAttachToolbars".lower()] = 323
        self.globals["xlDialogAutoCorrect".lower()] = 485
        self.globals["xlDialogAxes".lower()] = 78
        self.globals["xlDialogBorder".lower()] = 45
        self.globals["xlDialogCalculation".lower()] = 32
        self.globals["xlDialogCellProtection".lower()] = 46
        self.globals["xlDialogChangeLink".lower()] = 166
        self.globals["xlDialogChartAddData".lower()] = 392
        self.globals["xlDialogChartLocation".lower()] = 527
        self.globals["xlDialogChartOptionsDataLabelMultiple".lower()] = 724
        self.globals["xlDialogChartOptionsDataLabels".lower()] = 505
        self.globals["xlDialogChartOptionsDataTable".lower()] = 506
        self.globals["xlDialogChartSourceData".lower()] = 540
        self.globals["xlDialogChartTrend".lower()] = 350
        self.globals["xlDialogChartType".lower()] = 526
        self.globals["xlDialogChartWizard".lower()] = 288
        self.globals["xlDialogCheckboxProperties".lower()] = 435
        self.globals["xlDialogClear".lower()] = 52
        self.globals["xlDialogColorPalette".lower()] = 161
        self.globals["xlDialogColumnWidth".lower()] = 47
        self.globals["xlDialogCombination".lower()] = 73
        self.globals["xlDialogConditionalFormatting".lower()] = 583
        self.globals["xlDialogConsolidate".lower()] = 191
        self.globals["xlDialogCopyChart".lower()] = 147
        self.globals["xlDialogCopyPicture".lower()] = 108
        self.globals["xlDialogCreateList".lower()] = 796
        self.globals["xlDialogCreateNames".lower()] = 62
        self.globals["xlDialogCreatePublisher".lower()] = 217
        self.globals["xlDialogCreateRelationship".lower()] = 1272
        self.globals["xlDialogCustomizeToolbar".lower()] = 276
        self.globals["xlDialogCustomViews".lower()] = 493
        self.globals["xlDialogDataDelete".lower()] = 36
        self.globals["xlDialogDataLabel".lower()] = 379
        self.globals["xlDialogDataLabelMultiple".lower()] = 723
        self.globals["xlDialogDataSeries".lower()] = 40
        self.globals["xlDialogDataValidation".lower()] = 525
        self.globals["xlDialogDefineName".lower()] = 61
        self.globals["xlDialogDefineStyle".lower()] = 229
        self.globals["xlDialogDeleteFormat".lower()] = 111
        self.globals["xlDialogDeleteName".lower()] = 110
        self.globals["xlDialogDemote".lower()] = 203
        self.globals["xlDialogDisplay".lower()] = 27
        self.globals["xlDialogDocumentInspector".lower()] = 862
        self.globals["xlDialogEditboxProperties".lower()] = 438
        self.globals["xlDialogEditColor".lower()] = 223
        self.globals["xlDialogEditDelete".lower()] = 54
        self.globals["xlDialogEditionOptions".lower()] = 251
        self.globals["xlDialogEditSeries".lower()] = 228
        self.globals["xlDialogErrorbarX".lower()] = 463
        self.globals["xlDialogErrorbarY".lower()] = 464
        self.globals["xlDialogErrorChecking".lower()] = 732
        self.globals["xlDialogEvaluateFormula".lower()] = 709
        self.globals["xlDialogExternalDataProperties".lower()] = 530
        self.globals["xlDialogExtract".lower()] = 35
        self.globals["xlDialogFileDelete".lower()] = 6
        self.globals["xlDialogFileSharing".lower()] = 481
        self.globals["xlDialogFillGroup".lower()] = 200
        self.globals["xlDialogFillWorkgroup".lower()] = 301
        self.globals["xlDialogFilter".lower()] = 447
        self.globals["xlDialogFilterAdvanced".lower()] = 370
        self.globals["xlDialogFindFile".lower()] = 475
        self.globals["xlDialogFont".lower()] = 26
        self.globals["xlDialogFontProperties".lower()] = 381
        self.globals["xlDialogForecastETS".lower()] = 1300
        self.globals["xlDialogFormatAuto".lower()] = 269
        self.globals["xlDialogFormatChart".lower()] = 465
        self.globals["xlDialogFormatCharttype".lower()] = 423
        self.globals["xlDialogFormatFont".lower()] = 150
        self.globals["xlDialogFormatLegend".lower()] = 88
        self.globals["xlDialogFormatMain".lower()] = 225
        self.globals["xlDialogFormatMove".lower()] = 128
        self.globals["xlDialogFormatNumber".lower()] = 42
        self.globals["xlDialogFormatOverlay".lower()] = 226
        self.globals["xlDialogFormatSize".lower()] = 129
        self.globals["xlDialogFormatText".lower()] = 89
        self.globals["xlDialogFormulaFind".lower()] = 64
        self.globals["xlDialogFormulaGoto".lower()] = 63
        self.globals["xlDialogFormulaReplace".lower()] = 130
        self.globals["xlDialogFunctionWizard".lower()] = 450
        self.globals["xlDialogGallery3dArea".lower()] = 193
        self.globals["xlDialogGallery3dBar".lower()] = 272
        self.globals["xlDialogGallery3dColumn".lower()] = 194
        self.globals["xlDialogGallery3dLine".lower()] = 195
        self.globals["xlDialogGallery3dPie".lower()] = 196
        self.globals["xlDialogGallery3dSurface".lower()] = 273
        self.globals["xlDialogGalleryArea".lower()] = 67
        self.globals["xlDialogGalleryBar".lower()] = 68
        self.globals["xlDialogGalleryColumn".lower()] = 69
        self.globals["xlDialogGalleryCustom".lower()] = 388
        self.globals["xlDialogGalleryDoughnut".lower()] = 344
        self.globals["xlDialogGalleryLine".lower()] = 70
        self.globals["xlDialogGalleryPie".lower()] = 71
        self.globals["xlDialogGalleryRadar".lower()] = 249
        self.globals["xlDialogGalleryScatter".lower()] = 72
        self.globals["xlDialogGoalSeek".lower()] = 198
        self.globals["xlDialogGridlines".lower()] = 76
        self.globals["xlDialogImportTextFile".lower()] = 666
        self.globals["xlDialogInsert".lower()] = 55
        self.globals["xlDialogInsertHyperlink".lower()] = 596
        self.globals["xlDialogInsertNameLabel".lower()] = 496
        self.globals["xlDialogInsertObject".lower()] = 259
        self.globals["xlDialogInsertPicture".lower()] = 342
        self.globals["xlDialogInsertTitle".lower()] = 380
        self.globals["xlDialogLabelProperties".lower()] = 436
        self.globals["xlDialogListboxProperties".lower()] = 437
        self.globals["xlDialogMacroOptions".lower()] = 382
        self.globals["xlDialogMailEditMailer".lower()] = 470
        self.globals["xlDialogMailLogon".lower()] = 339
        self.globals["xlDialogMailNextLetter".lower()] = 378
        self.globals["xlDialogMainChart".lower()] = 85
        self.globals["xlDialogMainChartType".lower()] = 185
        self.globals["xlDialogManageRelationships".lower()] = 1271
        self.globals["xlDialogMenuEditor".lower()] = 322
        self.globals["xlDialogMove".lower()] = 262
        self.globals["xlDialogMyPermission".lower()] = 834
        self.globals["xlDialogNameManager".lower()] = 977
        self.globals["xlDialogNew".lower()] = 119
        self.globals["xlDialogNewName".lower()] = 978
        self.globals["xlDialogNewWebQuery".lower()] = 667
        self.globals["xlDialogNote".lower()] = 154
        self.globals["xlDialogObjectProperties".lower()] = 207
        self.globals["xlDialogObjectProtection".lower()] = 214
        self.globals["xlDialogOpen".lower()] = 1
        self.globals["xlDialogOpenLinks".lower()] = 2
        self.globals["xlDialogOpenMail".lower()] = 188
        self.globals["xlDialogOpenText".lower()] = 441
        self.globals["xlDialogOptionsCalculation".lower()] = 318
        self.globals["xlDialogOptionsChart".lower()] = 325
        self.globals["xlDialogOptionsEdit".lower()] = 319
        self.globals["xlDialogOptionsGeneral".lower()] = 356
        self.globals["xlDialogOptionsListsAdd".lower()] = 458
        self.globals["xlDialogOptionsME".lower()] = 647
        self.globals["xlDialogOptionsTransition".lower()] = 355
        self.globals["xlDialogOptionsView".lower()] = 320
        self.globals["xlDialogOutline".lower()] = 142
        self.globals["xlDialogOverlay".lower()] = 86
        self.globals["xlDialogOverlayChartType".lower()] = 186
        self.globals["xlDialogPageSetup".lower()] = 7
        self.globals["xlDialogParse".lower()] = 91
        self.globals["xlDialogPasteNames".lower()] = 58
        self.globals["xlDialogPasteSpecial".lower()] = 53
        self.globals["xlDialogPatterns".lower()] = 84
        self.globals["xlDialogPermission".lower()] = 832
        self.globals["xlDialogPhonetic".lower()] = 656
        self.globals["xlDialogPivotCalculatedField".lower()] = 570
        self.globals["xlDialogPivotCalculatedItem".lower()] = 572
        self.globals["xlDialogPivotClientServerSet".lower()] = 689
        self.globals["xlDialogPivotDefaultLayout".lower()] = 1360
        self.globals["xlDialogPivotFieldGroup".lower()] = 433
        self.globals["xlDialogPivotFieldProperties".lower()] = 313
        self.globals["xlDialogPivotFieldUngroup".lower()] = 434
        self.globals["xlDialogPivotShowPages".lower()] = 421
        self.globals["xlDialogPivotSolveOrder".lower()] = 568
        self.globals["xlDialogPivotTableOptions".lower()] = 567
        self.globals["xlDialogPivotTableSlicerConnections".lower()] = 1183
        self.globals["xlDialogPivotTableWhatIfAnalysisSettings".lower()] = 1153
        self.globals["xlDialogPivotTableWizard".lower()] = 312
        self.globals["xlDialogPlacement".lower()] = 300
        self.globals["xlDialogPrint".lower()] = 8
        self.globals["xlDialogPrinterSetup".lower()] = 9
        self.globals["xlDialogPrintPreview".lower()] = 222
        self.globals["xlDialogPromote".lower()] = 202
        self.globals["xlDialogProperties".lower()] = 474
        self.globals["xlDialogPropertyFields".lower()] = 754
        self.globals["xlDialogProtectDocument".lower()] = 28
        self.globals["xlDialogProtectSharing".lower()] = 620
        self.globals["xlDialogPublishAsWebPage".lower()] = 653
        self.globals["xlDialogPushbuttonProperties".lower()] = 445
        self.globals["xlDialogRecommendedPivotTables".lower()] = 1258
        self.globals["xlDialogReplaceFont".lower()] = 134
        self.globals["xlDialogRoutingSlip".lower()] = 336
        self.globals["xlDialogRowHeight".lower()] = 127
        self.globals["xlDialogRun".lower()] = 17
        self.globals["xlDialogSaveAs".lower()] = 5
        self.globals["xlDialogSaveCopyAs".lower()] = 456
        self.globals["xlDialogSaveNewObject".lower()] = 208
        self.globals["xlDialogSaveWorkbook".lower()] = 145
        self.globals["xlDialogSaveWorkspace".lower()] = 285
        self.globals["xlDialogScale".lower()] = 87
        self.globals["xlDialogScenarioAdd".lower()] = 307
        self.globals["xlDialogScenarioCells".lower()] = 305
        self.globals["xlDialogScenarioEdit".lower()] = 308
        self.globals["xlDialogScenarioMerge".lower()] = 473
        self.globals["xlDialogScenarioSummary".lower()] = 311
        self.globals["xlDialogScrollbarProperties".lower()] = 420
        self.globals["xlDialogSearch".lower()] = 731
        self.globals["xlDialogSelectSpecial".lower()] = 132
        self.globals["xlDialogSendMail".lower()] = 189
        self.globals["xlDialogSeriesAxes".lower()] = 460
        self.globals["xlDialogSeriesOptions".lower()] = 557
        self.globals["xlDialogSeriesOrder".lower()] = 466
        self.globals["xlDialogSeriesShape".lower()] = 504
        self.globals["xlDialogSeriesX".lower()] = 461
        self.globals["xlDialogSeriesY".lower()] = 462
        self.globals["xlDialogSetBackgroundPicture".lower()] = 509
        self.globals["xlDialogSetManager".lower()] = 1109
        self.globals["xlDialogSetMDXEditor".lower()] = 1208
        self.globals["xlDialogSetPrintTitles".lower()] = 23
        self.globals["xlDialogSetTupleEditorOnColumns".lower()] = 1108
        self.globals["xlDialogSetTupleEditorOnRows".lower()] = 1107
        self.globals["xlDialogSetUpdateStatus".lower()] = 159
        self.globals["xlDialogSheet".lower()] = 4116
        self.globals["xlDialogShowDetail".lower()] = 204
        self.globals["xlDialogShowToolbar".lower()] = 220
        self.globals["xlDialogSize".lower()] = 261
        self.globals["xlDialogSlicerCreation".lower()] = 1182
        self.globals["xlDialogSlicerPivotTableConnections".lower()] = 1184
        self.globals["xlDialogSlicerSettings".lower()] = 1179
        self.globals["xlDialogSort".lower()] = 39
        self.globals["xlDialogSortSpecial".lower()] = 192
        self.globals["xlDialogSparklineInsertColumn".lower()] = 1134
        self.globals["xlDialogSparklineInsertLine".lower()] = 1133
        self.globals["xlDialogSparklineInsertWinLoss".lower()] = 1135
        self.globals["xlDialogSplit".lower()] = 137
        self.globals["xlDialogStandardFont".lower()] = 190
        self.globals["xlDialogStandardWidth".lower()] = 472
        self.globals["xlDialogStyle".lower()] = 44
        self.globals["xlDialogSubscribeTo".lower()] = 218
        self.globals["xlDialogSubtotalCreate".lower()] = 398
        self.globals["xlDialogSummaryInfo".lower()] = 474
        self.globals["xlDialogTable".lower()] = 41
        self.globals["xlDialogTabOrder".lower()] = 394
        self.globals["xlDialogTextToColumns".lower()] = 422
        self.globals["xlDialogUnhide".lower()] = 94
        self.globals["xlDialogUpdateLink".lower()] = 201
        self.globals["xlDialogVbaInsertFile".lower()] = 328
        self.globals["xlDialogVbaMakeAddin".lower()] = 478
        self.globals["xlDialogVbaProcedureDefinition".lower()] = 330
        self.globals["xlDialogView3d".lower()] = 197
        self.globals["xlDialogWebOptionsBrowsers".lower()] = 773
        self.globals["xlDialogWebOptionsEncoding".lower()] = 686
        self.globals["xlDialogWebOptionsFiles".lower()] = 684
        self.globals["xlDialogWebOptionsFonts".lower()] = 687
        self.globals["xlDialogWebOptionsGeneral".lower()] = 683
        self.globals["xlDialogWebOptionsPictures".lower()] = 685
        self.globals["xlDialogWindowMove".lower()] = 14
        self.globals["xlDialogWindowSize".lower()] = 13
        self.globals["xlDialogWorkbookAdd".lower()] = 281
        self.globals["xlDialogWorkbookCopy".lower()] = 283
        self.globals["xlDialogWorkbookInsert".lower()] = 354
        self.globals["xlDialogWorkbookMove".lower()] = 282
        self.globals["xlDialogWorkbookName".lower()] = 386
        self.globals["xlDialogWorkbookNew".lower()] = 302
        self.globals["xlDialogWorkbookOptions".lower()] = 284
        self.globals["xlDialogWorkbookProtect".lower()] = 417
        self.globals["xlDialogWorkbookTabSplit".lower()] = 415
        self.globals["xlDialogWorkbookUnhide".lower()] = 384
        self.globals["xlDialogWorkgroup".lower()] = 199
        self.globals["xlDialogWorkspace".lower()] = 95
        self.globals["xlDialogZoom".lower()] = 256
        self.globals["xlDiamond".lower()] = 2
        self.globals["xlDIF".lower()] = 9
        self.globals["xlDifferenceFrom".lower()] = 2
        self.globals["xlDirect".lower()] = 1
        self.globals["xlDisabled".lower()] = 0
        self.globals["xlDisplayNone".lower()] = 1
        self.globals["xlDisplayPropertyInPivotTable".lower()] = 1
        self.globals["xlDisplayPropertyInPivotTableAndTooltip".lower()] = 3
        self.globals["xlDisplayPropertyInTooltip".lower()] = 2
        self.globals["xlDisplayShapes".lower()] = 4104
        self.globals["xlDisplayUnitLabel".lower()] = 30
        self.globals["xlDistinctCount".lower()] = 11
        self.globals["xlDistributed".lower()] = 4117
        self.globals["xlDivide".lower()] = 5
        self.globals["xlDMYFormat".lower()] = 4
        self.globals["xlDoesNotContain".lower()] = 1
        self.globals["xlDone".lower()] = 0
        self.globals["xlDoNotRepeatLabels".lower()] = 1
        self.globals["xlDoNotSaveChanges".lower()] = 2
        self.globals["xlDot".lower()] = 4118
        self.globals["xlDouble".lower()] = 4119
        self.globals["xlDoubleAccounting".lower()] = 5
        self.globals["xlDoubleClosed".lower()] = 5
        self.globals["xlDoubleOpen".lower()] = 4
        self.globals["xlDoubleQuote".lower()] = 1
        self.globals["xlDoughnut".lower()] = 4120
        self.globals["xlDoughnutExploded".lower()] = 80
        self.globals["xlDown".lower()] = 4121
        self.globals["xlDownBars".lower()] = 20
        self.globals["xlDownThenOver".lower()] = 1
        self.globals["xlDownward".lower()] = 4170
        self.globals["xlDrawingObject".lower()] = 14
        self.globals["xlDropDown".lower()] = 2
        self.globals["xlDropLines".lower()] = 26
        self.globals["xlDRW".lower()] = 4
        self.globals["xlDuplicate".lower()] = 1
        self.globals["xlDXF".lower()] = 5
        self.globals["xlDYMFormat".lower()] = 7
        self.globals["xlEdgeBottom".lower()] = 9
        self.globals["xlEdgeLeft".lower()] = 7
        self.globals["xlEdgeRight".lower()] = 10
        self.globals["xlEdgeTop".lower()] = 8
        self.globals["xlEditBox".lower()] = 3
        self.globals["xlEditionDate".lower()] = 2
        self.globals["xlEMDFormat".lower()] = 10
        self.globals["xlEmptyCellReferences".lower()] = 7
        self.globals["xlEnd".lower()] = 2
        self.globals["xlEndSides".lower()] = 3
        self.globals["xlEndsWith".lower()] = 3
        self.globals["xlEntireChart".lower()] = 20
        self.globals["xlEntirePage".lower()] = 1
        self.globals["xlEPS".lower()] = 8
        self.globals["xlEqual".lower()] = 3
        self.globals["xlEqualAboveAverage".lower()] = 2
        self.globals["xlEqualAllocation".lower()] = 1
        self.globals["xlEqualBelowAverage".lower()] = 3
        self.globals["xlErrBlocked".lower()] = 2047
        self.globals["xlErrCalc".lower()] = 2050
        self.globals["xlErrConnect".lower()] = 2046
        self.globals["xlErrDiv0".lower()] = 2007
        self.globals["xlErrField".lower()] = 2049
        self.globals["xlErrGettingData".lower()] = 2043
        self.globals["xlErrNA".lower()] = 2042
        self.globals["xlErrName".lower()] = 2029
        self.globals["xlErrNull".lower()] = 2000
        self.globals["xlErrNum".lower()] = 2036
        self.globals["xlErrorBarIncludeBoth".lower()] = 1
        self.globals["xlErrorBarIncludeMinusValues".lower()] = 3
        self.globals["xlErrorBarIncludeNone".lower()] = 4142
        self.globals["xlErrorBarIncludePlusValues".lower()] = 2
        self.globals["xlErrorBars".lower()] = 9
        self.globals["xlErrorBarTypeCustom".lower()] = 4114
        self.globals["xlErrorBarTypeFixedValue".lower()] = 1
        self.globals["xlErrorBarTypePercent".lower()] = 2
        self.globals["xlErrorBarTypeStDev".lower()] = 4155
        self.globals["xlErrorBarTypeStError".lower()] = 4
        self.globals["xlErrorHandler".lower()] = 2
        self.globals["xlErrors".lower()] = 16
        self.globals["xlErrorsCondition".lower()] = 16
        self.globals["xlErrRef".lower()] = 2023
        self.globals["xlErrSpill".lower()] = 2045
        self.globals["xlErrUnknown".lower()] = 2048
        self.globals["xlErrValue".lower()] = 2015
        self.globals["xlEscKey".lower()] = 1
        self.globals["xlEvaluateToError".lower()] = 1
        self.globals["xlExcel12".lower()] = 50
        self.globals["xlExcel2".lower()] = 16
        self.globals["xlExcel2FarEast".lower()] = 27
        self.globals["xlExcel3".lower()] = 29
        self.globals["xlExcel4".lower()] = 33
        self.globals["xlExcel4IntlMacroSheet".lower()] = 4
        self.globals["xlExcel4MacroSheet".lower()] = 3
        self.globals["xlExcel4Workbook".lower()] = 35
        self.globals["xlExcel5".lower()] = 39
        self.globals["xlExcel7".lower()] = 39
        self.globals["xlExcel8".lower()] = 56
        self.globals["xlExcel9795".lower()] = 43
        self.globals["xlExcelLinks".lower()] = 1
        self.globals["xlExcelMenus".lower()] = 1
        self.globals["xlExclusive".lower()] = 3
        self.globals["xlExponential".lower()] = 5
        self.globals["xlExpression".lower()] = 2
        self.globals["xlExtended".lower()] = 3
        self.globals["xlExternal".lower()] = 2
        self.globals["xlExtractData".lower()] = 2
        self.globals["xlFieldsScope".lower()] = 1
        self.globals["xlFileValidationPivotDefault".lower()] = 0
        self.globals["xlFileValidationPivotRun".lower()] = 1
        self.globals["xlFileValidationPivotSkip".lower()] = 2
        self.globals["xlFill".lower()] = 5
        self.globals["xlFillCopy".lower()] = 1
        self.globals["xlFillDays".lower()] = 5
        self.globals["xlFillDefault".lower()] = 0
        self.globals["xlFillFormats".lower()] = 3
        self.globals["xlFillMonths".lower()] = 7
        self.globals["xlFillSeries".lower()] = 2
        self.globals["xlFillValues".lower()] = 4
        self.globals["xlFillWeekdays".lower()] = 6
        self.globals["xlFillWithAll".lower()] = 4104
        self.globals["xlFillWithContents".lower()] = 2
        self.globals["xlFillWithFormats".lower()] = 4122
        self.globals["xlFillYears".lower()] = 8
        self.globals["xlFilterAboveAverage".lower()] = 33
        self.globals["xlFilterAllDatesInPeriodApril".lower()] = 24
        self.globals["xlFilterAllDatesInPeriodAugust".lower()] = 28
        self.globals["xlFilterAllDatesInPeriodDay".lower()] = 2
        self.globals["xlFilterAllDatesInPeriodDecember".lower()] = 32
        self.globals["xlFilterAllDatesInPeriodFebruray".lower()] = 22
        self.globals["xlFilterAllDatesInPeriodHour".lower()] = 3
        self.globals["xlFilterAllDatesInPeriodJanuary".lower()] = 21
        self.globals["xlFilterAllDatesInPeriodJuly".lower()] = 27
        self.globals["xlFilterAllDatesInPeriodJune".lower()] = 26
        self.globals["xlFilterAllDatesInPeriodMarch".lower()] = 23
        self.globals["xlFilterAllDatesInPeriodMay".lower()] = 25
        self.globals["xlFilterAllDatesInPeriodMinute".lower()] = 4
        self.globals["xlFilterAllDatesInPeriodMonth".lower()] = 1
        self.globals["xlFilterAllDatesInPeriodNovember".lower()] = 31
        self.globals["xlFilterAllDatesInPeriodOctober".lower()] = 30
        self.globals["xlFilterAllDatesInPeriodQuarter1".lower()] = 17
        self.globals["xlFilterAllDatesInPeriodQuarter2".lower()] = 18
        self.globals["xlFilterAllDatesInPeriodQuarter3".lower()] = 19
        self.globals["xlFilterAllDatesInPeriodQuarter4".lower()] = 20
        self.globals["xlFilterAllDatesInPeriodSecond".lower()] = 5
        self.globals["xlFilterAllDatesInPeriodSeptember".lower()] = 29
        self.globals["xlFilterAllDatesInPeriodYear".lower()] = 0
        self.globals["xlFilterAutomaticFontColor".lower()] = 13
        self.globals["xlFilterBelowAverage".lower()] = 34
        self.globals["xlFilterBottom".lower()] = 0
        self.globals["xlFilterBottomPercent".lower()] = 2
        self.globals["xlFilterCellColor".lower()] = 8
        self.globals["xlFilterCopy".lower()] = 2
        self.globals["xlFilterDynamic".lower()] = 11
        self.globals["xlFilterFontColor".lower()] = 9
        self.globals["xlFilterIcon".lower()] = 10
        self.globals["xlFilterInPlace".lower()] = 1
        self.globals["xlFilterLastMonth".lower()] = 8
        self.globals["xlFilterLastQuarter".lower()] = 11
        self.globals["xlFilterLastWeek".lower()] = 5
        self.globals["xlFilterLastYear".lower()] = 14
        self.globals["xlFilterNextMonth".lower()] = 9
        self.globals["xlFilterNextQuarter".lower()] = 12
        self.globals["xlFilterNextWeek".lower()] = 6
        self.globals["xlFilterNextYear".lower()] = 15
        self.globals["xlFilterNoFill".lower()] = 12
        self.globals["xlFilterNoIcon".lower()] = 14
        self.globals["xlFilterStatusDateHasTime".lower()] = 2
        self.globals["xlFilterStatusDateWrongOrder".lower()] = 1
        self.globals["xlFilterStatusInvalidDate".lower()] = 3
        self.globals["xlFilterStatusOK".lower()] = 0
        self.globals["xlFilterThisMonth".lower()] = 7
        self.globals["xlFilterThisQuarter".lower()] = 10
        self.globals["xlFilterThisWeek".lower()] = 4
        self.globals["xlFilterThisYear".lower()] = 13
        self.globals["xlFilterToday".lower()] = 1
        self.globals["xlFilterTomorrow".lower()] = 3
        self.globals["xlFilterTop".lower()] = 1
        self.globals["xlFilterTopPercent".lower()] = 3
        self.globals["xlFilterValues".lower()] = 7
        self.globals["xlFilterYearToDate".lower()] = 16
        self.globals["xlFilterYesterday".lower()] = 2
        self.globals["xlFirst".lower()] = 0
        self.globals["xlFirstColumn".lower()] = 3
        self.globals["xlFirstHeaderCell".lower()] = 9
        self.globals["xlFirstRow".lower()] = 256
        self.globals["xlFirstTotalCell".lower()] = 11
        self.globals["xlFitToPage".lower()] = 2
        self.globals["xlFixedValue".lower()] = 1
        self.globals["xlFixedWidth".lower()] = 2
        self.globals["xlFlashFill".lower()] = 11
        self.globals["xlFloating".lower()] = 5
        self.globals["xlFloor".lower()] = 23
        self.globals["xlForecastAggregationAverage".lower()] = 1
        self.globals["xlForecastAggregationCount".lower()] = 2
        self.globals["xlForecastAggregationCountA".lower()] = 3
        self.globals["xlForecastAggregationMax".lower()] = 4
        self.globals["xlForecastAggregationMedian".lower()] = 5
        self.globals["xlForecastAggregationMin".lower()] = 6
        self.globals["xlForecastAggregationSum".lower()] = 7
        self.globals["xlForecastChartTypeColumn".lower()] = 1
        self.globals["xlForecastChartTypeLine".lower()] = 0
        self.globals["xlForecastDataCompletionInterpolate".lower()] = 1
        self.globals["xlForecastDataCompletionZeros".lower()] = 0
        self.globals["xlFormatConditions".lower()] = 1
        self.globals["xlFormatFromLeftOrAbove".lower()] = 0
        self.globals["xlFormatFromRightOrBelow".lower()] = 1
        self.globals["xlFormats".lower()] = 4122
        self.globals["xlFormula".lower()] = 5
        self.globals["xlFormulas".lower()] = 4123
        self.globals["xlFreeFloating".lower()] = 3
        self.globals["xlFront".lower()] = 4
        self.globals["xlFrontEnd".lower()] = 6
        self.globals["xlFrontSides".lower()] = 5
        self.globals["xlFullPage".lower()] = 3
        self.globals["xlFullScript".lower()] = 1
        self.globals["xlFunction".lower()] = 1
        self.globals["xlFunnel".lower()] = 123
        self.globals["xlGeneral".lower()] = 1
        self.globals["xlGeneralFormat".lower()] = 1
        self.globals["xlGeneralFormatName".lower()] = 26
        self.globals["xlGenerateTableRefA1".lower()] = 0
        self.globals["xlGenerateTableRefStruct".lower()] = 1
        self.globals["xlGeoMappingLevelAutomatic".lower()] = 0
        self.globals["xlGeoMappingLevelCountryRegion".lower()] = 5
        self.globals["xlGeoMappingLevelCountryRegionList".lower()] = 6
        self.globals["xlGeoMappingLevelCounty".lower()] = 3
        self.globals["xlGeoMappingLevelDataOnly".lower()] = 1
        self.globals["xlGeoMappingLevelPostalCode".lower()] = 2
        self.globals["xlGeoMappingLevelState".lower()] = 4
        self.globals["xlGeoMappingLevelWorld".lower()] = 7
        self.globals["xlGeoProjectionTypeAlbers".lower()] = 3
        self.globals["xlGeoProjectionTypeAutomatic".lower()] = 0
        self.globals["xlGeoProjectionTypeMercator".lower()] = 1
        self.globals["xlGeoProjectionTypeMiller".lower()] = 2
        self.globals["xlGeoProjectionTypeRobinson".lower()] = 4
        self.globals["xlGradientFillLinear".lower()] = 0
        self.globals["xlGradientFillPath".lower()] = 1
        self.globals["xlGradientStopPositionTypeExtremeValue".lower()] = 0
        self.globals["xlGradientStopPositionTypeNumber".lower()] = 1
        self.globals["xlGradientStopPositionTypePercent".lower()] = 2
        self.globals["xlGrandTotalColumn".lower()] = 4
        self.globals["xlGrandTotalRow".lower()] = 2
        self.globals["xlGray16".lower()] = 17
        self.globals["xlGray25".lower()] = 4124
        self.globals["xlGray50".lower()] = 4125
        self.globals["xlGray75".lower()] = 4126
        self.globals["xlGray8".lower()] = 18
        self.globals["xlGreater".lower()] = 5
        self.globals["xlGreaterEqual".lower()] = 7
        self.globals["xlGregorian".lower()] = 2
        self.globals["xlGrid".lower()] = 15
        self.globals["xlGridline".lower()] = 22
        self.globals["xlGroupBox".lower()] = 4
        self.globals["xlGrowth".lower()] = 2
        self.globals["xlGrowthTrend".lower()] = 10
        self.globals["xlGuess".lower()] = 0
        self.globals["xlHairline".lower()] = 1
        self.globals["xlHAlignCenter".lower()] = 4108
        self.globals["xlHAlignCenterAcrossSelection".lower()] = 7
        self.globals["xlHAlignDistributed".lower()] = 4117
        self.globals["xlHAlignFill".lower()] = 5
        self.globals["xlHAlignGeneral".lower()] = 1
        self.globals["xlHAlignJustify".lower()] = 4130
        self.globals["xlHAlignLeft".lower()] = 4131
        self.globals["xlHAlignRight".lower()] = 4152
        self.globals["xlHeaderRow".lower()] = 1
        self.globals["xlHebrewFullScript".lower()] = 0
        self.globals["xlHebrewMixedAuthorizedScript".lower()] = 3
        self.globals["xlHebrewMixedScript".lower()] = 2
        self.globals["xlHebrewPartialScript".lower()] = 1
        self.globals["xlHGL".lower()] = 6
        self.globals["xlHidden".lower()] = 0
        self.globals["xlHide".lower()] = 3
        self.globals["xlHierarchy".lower()] = 1
        self.globals["xlHigh".lower()] = 4127
        self.globals["xlHiLoLines".lower()] = 25
        self.globals["xlHindiNumerals".lower()] = 3
        self.globals["xlHiragana".lower()] = 2
        self.globals["xlHistogram".lower()] = 118
        self.globals["xlHorizontal".lower()] = 4128
        self.globals["xlHorizontalCoordinate".lower()] = 1
        self.globals["xlHourCode".lower()] = 22
        self.globals["xlHtml".lower()] = 44
        self.globals["xlHtmlCalc".lower()] = 1
        self.globals["xlHtmlChart".lower()] = 3
        self.globals["xlHtmlList".lower()] = 2
        self.globals["xlHtmlStatic".lower()] = 0
        self.globals["xlHundredMillions".lower()] = 8
        self.globals["xlHundreds".lower()] = 2
        self.globals["xlHundredThousands".lower()] = 5
        self.globals["xlIBeam".lower()] = 3
        self.globals["xlIcon0Bars".lower()] = 37
        self.globals["xlIcon0FilledBoxes".lower()] = 52
        self.globals["xlIcon1Bar".lower()] = 38
        self.globals["xlIcon1FilledBox".lower()] = 51
        self.globals["xlIcon2Bars".lower()] = 39
        self.globals["xlIcon2FilledBoxes".lower()] = 50
        self.globals["xlIcon3Bars".lower()] = 40
        self.globals["xlIcon3FilledBoxes".lower()] = 49
        self.globals["xlIcon4Bars".lower()] = 41
        self.globals["xlIcon4FilledBoxes".lower()] = 48
        self.globals["xlIconBlackCircle".lower()] = 32
        self.globals["xlIconBlackCircleWithBorder".lower()] = 13
        self.globals["xlIconCircleWithOneWhiteQuarter".lower()] = 33
        self.globals["xlIconCircleWithThreeWhiteQuarters".lower()] = 35
        self.globals["xlIconCircleWithTwoWhiteQuarters".lower()] = 34
        self.globals["xlIconGoldStar".lower()] = 42
        self.globals["xlIconGrayCircle".lower()] = 31
        self.globals["xlIconGrayDownArrow".lower()] = 6
        self.globals["xlIconGrayDownInclineArrow".lower()] = 28
        self.globals["xlIconGraySideArrow".lower()] = 5
        self.globals["xlIconGrayUpArrow".lower()] = 4
        self.globals["xlIconGrayUpInclineArrow".lower()] = 27
        self.globals["xlIconGreenCheck".lower()] = 22
        self.globals["xlIconGreenCheckSymbol".lower()] = 19
        self.globals["xlIconGreenCircle".lower()] = 10
        self.globals["xlIconGreenFlag".lower()] = 7
        self.globals["xlIconGreenTrafficLight".lower()] = 14
        self.globals["xlIconGreenUpArrow".lower()] = 1
        self.globals["xlIconGreenUpTriangle".lower()] = 45
        self.globals["xlIconHalfGoldStar".lower()] = 43
        self.globals["xlIconNoCellIcon".lower()] = 1
        self.globals["xlIconPinkCircle".lower()] = 30
        self.globals["xlIconRedCircle".lower()] = 29
        self.globals["xlIconRedCircleWithBorder".lower()] = 12
        self.globals["xlIconRedCross".lower()] = 24
        self.globals["xlIconRedCrossSymbol".lower()] = 21
        self.globals["xlIconRedDiamond".lower()] = 18
        self.globals["xlIconRedDownArrow".lower()] = 3
        self.globals["xlIconRedDownTriangle".lower()] = 47
        self.globals["xlIconRedFlag".lower()] = 9
        self.globals["xlIconRedTrafficLight".lower()] = 16
        self.globals["xlIcons".lower()] = 1
        self.globals["xlIconSets".lower()] = 6
        self.globals["xlIconSilverStar".lower()] = 44
        self.globals["xlIconWhiteCircleAllWhiteQuarters".lower()] = 36
        self.globals["xlIconYellowCircle".lower()] = 11
        self.globals["xlIconYellowDash".lower()] = 46
        self.globals["xlIconYellowDownInclineArrow".lower()] = 26
        self.globals["xlIconYellowExclamation".lower()] = 23
        self.globals["xlIconYellowExclamationSymbol".lower()] = 20
        self.globals["xlIconYellowFlag".lower()] = 8
        self.globals["xlIconYellowSideArrow".lower()] = 2
        self.globals["xlIconYellowTrafficLight".lower()] = 15
        self.globals["xlIconYellowTriangle".lower()] = 17
        self.globals["xlIconYellowUpInclineArrow".lower()] = 25
        self.globals["xlIMEModeAlpha".lower()] = 8
        self.globals["xlIMEModeAlphaFull".lower()] = 7
        self.globals["xlIMEModeDisable".lower()] = 3
        self.globals["xlIMEModeHangul".lower()] = 10
        self.globals["xlIMEModeHangulFull".lower()] = 9
        self.globals["xlIMEModeHiragana".lower()] = 4
        self.globals["xlIMEModeKatakana".lower()] = 5
        self.globals["xlIMEModeKatakanaHalf".lower()] = 6
        self.globals["xlIMEModeNoControl".lower()] = 0
        self.globals["xlIMEModeOff".lower()] = 2
        self.globals["xlIMEModeOn".lower()] = 1
        self.globals["xlImmediatePane".lower()] = 12
        self.globals["xlInches".lower()] = 0
        self.globals["xlInconsistentFormula".lower()] = 4
        self.globals["xlInconsistentListFormula".lower()] = 9
        self.globals["xlIndex".lower()] = 9
        self.globals["xlIndexAscending".lower()] = 0
        self.globals["xlIndexDescending".lower()] = 1
        self.globals["xlIndicatorAndButton".lower()] = 0
        self.globals["xlInfo".lower()] = 4129
        self.globals["xlInnerCenterPoint".lower()] = 8
        self.globals["xlInnerClockwisePoint".lower()] = 7
        self.globals["xlInnerCounterClockwisePoint".lower()] = 9
        self.globals["xlInsertDeleteCells".lower()] = 1
        self.globals["xlInsertEntireRows".lower()] = 2
        self.globals["xlInside".lower()] = 2
        self.globals["xlInsideHorizontal".lower()] = 12
        self.globals["xlInsideVertical".lower()] = 11
        self.globals["xlInteger".lower()] = 2
        self.globals["xlInterpolated".lower()] = 3
        self.globals["xlInterrupt".lower()] = 1
        self.globals["xlIntlAddIn".lower()] = 26
        self.globals["xlIntlMacro".lower()] = 25
        self.globals["xlJustify".lower()] = 4130
        self.globals["xlKatakana".lower()] = 1
        self.globals["xlKatakanaHalf".lower()] = 0
        self.globals["xlLabel".lower()] = 5
        self.globals["xlLabelOnly".lower()] = 1
        self.globals["xlLabelPositionAbove".lower()] = 0
        self.globals["xlLabelPositionBelow".lower()] = 1
        self.globals["xlLabelPositionBestFit".lower()] = 5
        self.globals["xlLabelPositionCenter".lower()] = 4108
        self.globals["xlLabelPositionCustom".lower()] = 7
        self.globals["xlLabelPositionInsideBase".lower()] = 4
        self.globals["xlLabelPositionInsideEnd".lower()] = 3
        self.globals["xlLabelPositionLeft".lower()] = 4131
        self.globals["xlLabelPositionMixed".lower()] = 6
        self.globals["xlLabelPositionOutsideEnd".lower()] = 2
        self.globals["xlLabelPositionRight".lower()] = 4152
        self.globals["xlLandscape".lower()] = 2
        self.globals["xlLast".lower()] = 1
        self.globals["xlLast7Days".lower()] = 2
        self.globals["xlLastCell".lower()] = 11
        self.globals["xlLastColumn".lower()] = 4
        self.globals["xlLastHeaderCell".lower()] = 10
        self.globals["xlLastMonth".lower()] = 5
        self.globals["xlLastTotalCell".lower()] = 12
        self.globals["xlLastWeek".lower()] = 4
        self.globals["xlLatin".lower()] = 5001
        self.globals["xlLeaderLines".lower()] = 29
        self.globals["xlLeft".lower()] = 4131
        self.globals["xlLeftBrace".lower()] = 12
        self.globals["xlLeftBracket".lower()] = 10
        self.globals["xlLeftToRight".lower()] = 2
        self.globals["xlLegend".lower()] = 24
        self.globals["xlLegendEntry".lower()] = 12
        self.globals["xlLegendKey".lower()] = 13
        self.globals["xlLegendPositionBottom".lower()] = 4107
        self.globals["xlLegendPositionCorner".lower()] = 2
        self.globals["xlLegendPositionCustom".lower()] = 4161
        self.globals["xlLegendPositionLeft".lower()] = 4131
        self.globals["xlLegendPositionRight".lower()] = 4152
        self.globals["xlLegendPositionTop".lower()] = 4160
        self.globals["xlLensOnly".lower()] = 0
        self.globals["xlLess".lower()] = 6
        self.globals["xlLessEqual".lower()] = 8
        self.globals["xlLightDown".lower()] = 13
        self.globals["xlLightHorizontal".lower()] = 11
        self.globals["xlLightUp".lower()] = 14
        self.globals["xlLightVertical".lower()] = 12
        self.globals["xlLine".lower()] = 4
        self.globals["xlLinear".lower()] = 4132
        self.globals["xlLinearTrend".lower()] = 9
        self.globals["xlLineMarkers".lower()] = 65
        self.globals["xlLineMarkersStacked".lower()] = 66
        self.globals["xlLineMarkersStacked100".lower()] = 67
        self.globals["xlLineStacked".lower()] = 63
        self.globals["xlLineStacked100".lower()] = 64
        self.globals["xlLineStyleNone".lower()] = 4142
        self.globals["xlLinkedDataTypeStateBrokenLinkedData".lower()] = 3
        self.globals["xlLinkedDataTypeStateDisambiguationNeeded".lower()] = 2
        self.globals["xlLinkedDataTypeStateFetchingData".lower()] = 4
        self.globals["xlLinkedDataTypeStateNone".lower()] = 0
        self.globals["xlLinkedDataTypeStateValidLinkedData".lower()] = 1
        self.globals["xlLinkInfoOLELinks".lower()] = 2
        self.globals["xlLinkInfoPublishers".lower()] = 5
        self.globals["xlLinkInfoStatus".lower()] = 3
        self.globals["xlLinkInfoSubscribers".lower()] = 6
        self.globals["xlLinkStatusCopiedValues".lower()] = 10
        self.globals["xlLinkStatusIndeterminate".lower()] = 5
        self.globals["xlLinkStatusInvalidName".lower()] = 7
        self.globals["xlLinkStatusMissingFile".lower()] = 1
        self.globals["xlLinkStatusMissingSheet".lower()] = 2
        self.globals["xlLinkStatusNotStarted".lower()] = 6
        self.globals["xlLinkStatusOK".lower()] = 0
        self.globals["xlLinkStatusOld".lower()] = 3
        self.globals["xlLinkStatusSourceNotCalculated".lower()] = 4
        self.globals["xlLinkStatusSourceNotOpen".lower()] = 8
        self.globals["xlLinkStatusSourceOpen".lower()] = 9
        self.globals["xlLinkTypeExcelLinks".lower()] = 1
        self.globals["xlLinkTypeOLELinks".lower()] = 2
        self.globals["xlList1".lower()] = 10
        self.globals["xlList2".lower()] = 11
        self.globals["xlList3".lower()] = 12
        self.globals["xlListBox".lower()] = 6
        self.globals["xlListConflictDialog".lower()] = 0
        self.globals["xlListConflictDiscardAllConflicts".lower()] = 2
        self.globals["xlListConflictError".lower()] = 3
        self.globals["xlListConflictRetryAllConflicts".lower()] = 1
        self.globals["xlListDataTypeCheckbox".lower()] = 9
        self.globals["xlListDataTypeChoice".lower()] = 6
        self.globals["xlListDataTypeChoiceMulti".lower()] = 7
        self.globals["xlListDataTypeCounter".lower()] = 11
        self.globals["xlListDataTypeCurrency".lower()] = 4
        self.globals["xlListDataTypeDateTime".lower()] = 5
        self.globals["xlListDataTypeHyperLink".lower()] = 10
        self.globals["xlListDataTypeListLookup".lower()] = 8
        self.globals["xlListDataTypeMultiLineRichText".lower()] = 12
        self.globals["xlListDataTypeMultiLineText".lower()] = 2
        self.globals["xlListDataTypeNone".lower()] = 0
        self.globals["xlListDataTypeNumber".lower()] = 3
        self.globals["xlListDataTypeText".lower()] = 1
        self.globals["xlListDataValidation".lower()] = 8
        self.globals["xlListSeparator".lower()] = 5
        self.globals["xlLocalFormat1".lower()] = 15
        self.globals["xlLocalFormat2".lower()] = 16
        self.globals["xlLocalSessionChanges".lower()] = 2
        self.globals["xlLocationAsNewSheet".lower()] = 1
        self.globals["xlLocationAsObject".lower()] = 2
        self.globals["xlLocationAutomatic".lower()] = 3
        self.globals["xlLogarithmic".lower()] = 4133
        self.globals["xlLogical".lower()] = 4
        self.globals["xlLogicalCursor".lower()] = 1
        self.globals["xlLong".lower()] = 3
        self.globals["xlLookForBlanks".lower()] = 0
        self.globals["xlLookForErrors".lower()] = 1
        self.globals["xlLookForFormulas".lower()] = 2
        self.globals["xlLotusHelp".lower()] = 2
        self.globals["xlLow".lower()] = 4134
        self.globals["xlLowerCaseColumnLetter".lower()] = 9
        self.globals["xlLowerCaseRowLetter".lower()] = 8
        self.globals["xlLTR".lower()] = 5003
        self.globals["xlMacintosh".lower()] = 1
        self.globals["xlMacrosheetCell".lower()] = 7
        self.globals["xlMajorGridlines".lower()] = 15
        self.globals["xlManual".lower()] = 4135
        self.globals["xlManualAllocation".lower()] = 1
        self.globals["xlManualUpdate".lower()] = 5
        self.globals["xlMAPI".lower()] = 1
        self.globals["xlMarkerStyleAutomatic".lower()] = 4105
        self.globals["xlMarkerStyleCircle".lower()] = 8
        self.globals["xlMarkerStyleDash".lower()] = 4115
        self.globals["xlMarkerStyleDiamond".lower()] = 2
        self.globals["xlMarkerStyleDot".lower()] = 4118
        self.globals["xlMarkerStyleNone".lower()] = 4142
        self.globals["xlMarkerStylePicture".lower()] = 4147
        self.globals["xlMarkerStylePlus".lower()] = 9
        self.globals["xlMarkerStyleSquare".lower()] = 1
        self.globals["xlMarkerStyleStar".lower()] = 5
        self.globals["xlMarkerStyleTriangle".lower()] = 3
        self.globals["xlMarkerStyleX".lower()] = 4168
        self.globals["xlMax".lower()] = 4136
        self.globals["xlMaximized".lower()] = 4137
        self.globals["xlMaximum".lower()] = 2
        self.globals["xlMDY".lower()] = 44
        self.globals["xlMDYFormat".lower()] = 3
        self.globals["xlMeasure".lower()] = 2
        self.globals["xlMedium".lower()] = 4138
        self.globals["xlMetric".lower()] = 35
        self.globals["xlMicrosoftAccess".lower()] = 4
        self.globals["xlMicrosoftFoxPro".lower()] = 5
        self.globals["xlMicrosoftMail".lower()] = 3
        self.globals["xlMicrosoftPowerPoint".lower()] = 2
        self.globals["xlMicrosoftProject".lower()] = 6
        self.globals["xlMicrosoftSchedulePlus".lower()] = 7
        self.globals["xlMicrosoftWord".lower()] = 1
        self.globals["xlMidClockwiseRadiusPoint".lower()] = 4
        self.globals["xlMidCounterClockwiseRadiusPoint".lower()] = 6
        self.globals["xlMillimeters".lower()] = 2
        self.globals["xlMillionMillions".lower()] = 10
        self.globals["xlMillions".lower()] = 6
        self.globals["xlMin".lower()] = 4139
        self.globals["xlMinimized".lower()] = 4140
        self.globals["xlMinimum".lower()] = 4
        self.globals["xlMinorGridlines".lower()] = 16
        self.globals["xlMinusValues".lower()] = 3
        self.globals["xlMinuteCode".lower()] = 23
        self.globals["xlMissingItemsDefault".lower()] = 1
        self.globals["xlMissingItemsMax".lower()] = 32500
        self.globals["xlMissingItemsMax2".lower()] = 1048576
        self.globals["xlMissingItemsNone".lower()] = 0
        self.globals["xlMixed".lower()] = 2
        self.globals["xlMixedAuthorizedScript".lower()] = 4
        self.globals["xlMixedLabels".lower()] = 3
        self.globals["xlMixedScript".lower()] = 3
        self.globals["xlModule".lower()] = 4141
        self.globals["xlMonth".lower()] = 3
        self.globals["xlMonthCode".lower()] = 20
        self.globals["xlMonthLeadingZero".lower()] = 41
        self.globals["xlMonthNameChars".lower()] = 30
        self.globals["xlMonths".lower()] = 1
        self.globals["xlMove".lower()] = 2
        self.globals["xlMoveAndSize".lower()] = 1
        self.globals["xlMovingAvg".lower()] = 6
        self.globals["xlMSDOS".lower()] = 3
        self.globals["xlMultiply".lower()] = 4
        self.globals["xlMYDFormat".lower()] = 6
        self.globals["xlNarrow".lower()] = 1
        self.globals["xlNever".lower()] = 2
        self.globals["xlNext".lower()] = 1
        self.globals["xlNextMonth".lower()] = 8
        self.globals["xlNextToAxis".lower()] = 4
        self.globals["xlNextWeek".lower()] = 7
        self.globals["xlNo".lower()] = 2
        self.globals["xlNoAdditionalCalculation".lower()] = 4143
        self.globals["xlNoBlanksCondition".lower()] = 13
        self.globals["xlNoButton".lower()] = 0
        self.globals["xlNoButtonChanges".lower()] = 1
        self.globals["xlNoCap".lower()] = 2
        self.globals["xlNoChange".lower()] = 1
        self.globals["xlNoChanges".lower()] = 4
        self.globals["xlNoConversion".lower()] = 3
        self.globals["xlNoDockingChanges".lower()] = 3
        self.globals["xlNoDocuments".lower()] = 3
        self.globals["xlNoErrorsCondition".lower()] = 17
        self.globals["xlNoIndicator".lower()] = 0
        self.globals["xlNoKey".lower()] = 0
        self.globals["xlNoLabels".lower()] = 4142
        self.globals["xlNoMailSystem".lower()] = 0
        self.globals["xlNoncurrencyDigits".lower()] = 29
        self.globals["xlNone".lower()] = 4142
        self.globals["xlNonEnglishFunctions".lower()] = 34
        self.globals["xlNoRestrictions".lower()] = 0
        self.globals["xlNormal".lower()] = 4143
        self.globals["xlNormalLoad".lower()] = 0
        self.globals["xlNormalView".lower()] = 1
        self.globals["xlNorthwestArrow".lower()] = 1
        self.globals["xlNoSelection".lower()] = 4142
        self.globals["xlNoShapeChanges".lower()] = 2
        self.globals["xlNotBetween".lower()] = 2
        self.globals["xlNotEqual".lower()] = 4
        self.globals["xlNotes".lower()] = 4144
        self.globals["xlNothing".lower()] = 28
        self.globals["xlNotPlotted".lower()] = 1
        self.globals["xlNotSpecificDate".lower()] = 30
        self.globals["xlNotXLM".lower()] = 3
        self.globals["xlNotYetReviewed".lower()] = 3
        self.globals["xlNotYetRouted".lower()] = 0
        self.globals["xlNumber".lower()] = 4145
        self.globals["xlNumberAsText".lower()] = 3
        self.globals["xlNumberFormatTypeDefault".lower()] = 0
        self.globals["xlNumberFormatTypeNumber".lower()] = 1
        self.globals["xlNumberFormatTypePercent".lower()] = 2
        self.globals["xlNumbers".lower()] = 1
        self.globals["xlOartHorizontalOverflowClip".lower()] = 1
        self.globals["xlOartHorizontalOverflowOverflow".lower()] = 0
        self.globals["xlOartVerticalOverflowClip".lower()] = 1
        self.globals["xlOartVerticalOverflowEllipsis".lower()] = 2
        self.globals["xlOartVerticalOverflowOverflow".lower()] = 0
        self.globals["xlODBCQuery".lower()] = 1
        self.globals["xlOff".lower()] = 4146
        self.globals["xlOLEControl".lower()] = 2
        self.globals["xlOLEDBQuery".lower()] = 5
        self.globals["xlOLEEmbed".lower()] = 1
        self.globals["xlOLELink".lower()] = 0
        self.globals["xlOLELinks".lower()] = 2
        self.globals["xlOmittedCells".lower()] = 5
        self.globals["xlOn".lower()] = 1
        self.globals["xlOneAfterAnother".lower()] = 1
        self.globals["xlOpaque".lower()] = 3
        self.globals["xlOpen".lower()] = 2
        self.globals["xlOpenDocumentSpreadsheet".lower()] = 60
        self.globals["xlOpenSource".lower()] = 3
        self.globals["xlOpenXMLAddIn".lower()] = 55
        self.globals["xlOpenXMLStrictWorkbook".lower()] = 61
        self.globals["xlOpenXMLTemplate".lower()] = 54
        self.globals["xlOpenXMLTemplateMacroEnabled".lower()] = 53
        self.globals["xlOpenXMLWorkbook".lower()] = 51
        self.globals["xlOpenXMLWorkbookMacroEnabled".lower()] = 52
        self.globals["xlOptionButton".lower()] = 7
        self.globals["xlOr".lower()] = 2
        self.globals["xlOrigin".lower()] = 3
        self.globals["xlOtherSessionChanges".lower()] = 3
        self.globals["xlOuterCenterPoint".lower()] = 2
        self.globals["xlOuterClockwisePoint".lower()] = 3
        self.globals["xlOuterCounterClockwisePoint".lower()] = 1
        self.globals["xlOutline".lower()] = 1
        self.globals["xlOutlineRow".lower()] = 2
        self.globals["xlOutside".lower()] = 3
        self.globals["xlOverThenDown".lower()] = 2
        self.globals["xlOverwriteCells".lower()] = 0
        self.globals["xlPageBreakAutomatic".lower()] = 4105
        self.globals["xlPageBreakFull".lower()] = 1
        self.globals["xlPageBreakManual".lower()] = 4135
        self.globals["xlPageBreakNone".lower()] = 4142
        self.globals["xlPageBreakPartial".lower()] = 2
        self.globals["xlPageBreakPreview".lower()] = 2
        self.globals["xlPageField".lower()] = 3
        self.globals["xlPageFieldLabels".lower()] = 26
        self.globals["xlPageFieldValues".lower()] = 27
        self.globals["xlPageHeader".lower()] = 2
        self.globals["xlPageItem".lower()] = 6
        self.globals["xlPageLayoutView".lower()] = 3
        self.globals["xlPaper10x14".lower()] = 16
        self.globals["xlPaper11x17".lower()] = 17
        self.globals["xlPaperA3".lower()] = 8
        self.globals["xlPaperA4".lower()] = 9
        self.globals["xlPaperA4Small".lower()] = 10
        self.globals["xlPaperA5".lower()] = 11
        self.globals["xlPaperB4".lower()] = 12
        self.globals["xlPaperB5".lower()] = 13
        self.globals["xlPaperCsheet".lower()] = 24
        self.globals["xlPaperDsheet".lower()] = 25
        self.globals["xlPaperEnvelope10".lower()] = 20
        self.globals["xlPaperEnvelope11".lower()] = 21
        self.globals["xlPaperEnvelope12".lower()] = 22
        self.globals["xlPaperEnvelope14".lower()] = 23
        self.globals["xlPaperEnvelope9".lower()] = 19
        self.globals["xlPaperEnvelopeB4".lower()] = 33
        self.globals["xlPaperEnvelopeB5".lower()] = 34
        self.globals["xlPaperEnvelopeB6".lower()] = 35
        self.globals["xlPaperEnvelopeC3".lower()] = 29
        self.globals["xlPaperEnvelopeC4".lower()] = 30
        self.globals["xlPaperEnvelopeC5".lower()] = 28
        self.globals["xlPaperEnvelopeC6".lower()] = 31
        self.globals["xlPaperEnvelopeC65".lower()] = 32
        self.globals["xlPaperEnvelopeDL".lower()] = 27
        self.globals["xlPaperEnvelopeItaly".lower()] = 36
        self.globals["xlPaperEnvelopeMonarch".lower()] = 37
        self.globals["xlPaperEnvelopePersonal".lower()] = 38
        self.globals["xlPaperEsheet".lower()] = 26
        self.globals["xlPaperExecutive".lower()] = 7
        self.globals["xlPaperFanfoldLegalGerman".lower()] = 41
        self.globals["xlPaperFanfoldStdGerman".lower()] = 40
        self.globals["xlPaperFanfoldUS".lower()] = 39
        self.globals["xlPaperFolio".lower()] = 14
        self.globals["xlPaperLedger".lower()] = 4
        self.globals["xlPaperLegal".lower()] = 5
        self.globals["xlPaperLetter".lower()] = 1
        self.globals["xlPaperLetterSmall".lower()] = 2
        self.globals["xlPaperNote".lower()] = 18
        self.globals["xlPaperQuarto".lower()] = 15
        self.globals["xlPaperStatement".lower()] = 6
        self.globals["xlPaperTabloid".lower()] = 3
        self.globals["xlPaperUser".lower()] = 256
        self.globals["xlParamTypeBigInt".lower()] = 5
        self.globals["xlParamTypeBinary".lower()] = 2
        self.globals["xlParamTypeBit".lower()] = 7
        self.globals["xlParamTypeChar".lower()] = 1
        self.globals["xlParamTypeDate".lower()] = 9
        self.globals["xlParamTypeDecimal".lower()] = 3
        self.globals["xlParamTypeDouble".lower()] = 8
        self.globals["xlParamTypeFloat".lower()] = 6
        self.globals["xlParamTypeInteger".lower()] = 4
        self.globals["xlParamTypeLongVarBinary".lower()] = 4
        self.globals["xlParamTypeLongVarChar".lower()] = 1
        self.globals["xlParamTypeNumeric".lower()] = 2
        self.globals["xlParamTypeReal".lower()] = 7
        self.globals["xlParamTypeSmallInt".lower()] = 5
        self.globals["xlParamTypeTime".lower()] = 10
        self.globals["xlParamTypeTimestamp".lower()] = 11
        self.globals["xlParamTypeTinyInt".lower()] = 6
        self.globals["xlParamTypeUnknown".lower()] = 0
        self.globals["xlParamTypeVarBinary".lower()] = 3
        self.globals["xlParamTypeVarChar".lower()] = 12
        self.globals["xlParamTypeWChar".lower()] = 8
        self.globals["xlParentDataLabelOptionsBanner".lower()] = 1
        self.globals["xlParentDataLabelOptionsNone".lower()] = 0
        self.globals["xlParentDataLabelOptionsOverlapping".lower()] = 2
        self.globals["xlPareto".lower()] = 122
        self.globals["xlPart".lower()] = 2
        self.globals["xlPartial".lower()] = 3
        self.globals["xlPartialScript".lower()] = 2
        self.globals["xlPasteAll".lower()] = 4104
        self.globals["xlPasteAllExceptBorders".lower()] = 7
        self.globals["xlPasteAllMergingConditionalFormats".lower()] = 14
        self.globals["xlPasteAllUsingSourceTheme".lower()] = 13
        self.globals["xlPasteColumnWidths".lower()] = 8
        self.globals["xlPasteComments".lower()] = 4144
        self.globals["xlPasteFormats".lower()] = 4122
        self.globals["xlPasteFormulas".lower()] = 4123
        self.globals["xlPasteFormulasAndNumberFormats".lower()] = 11
        self.globals["xlPasteSpecialOperationAdd".lower()] = 2
        self.globals["xlPasteSpecialOperationDivide".lower()] = 5
        self.globals["xlPasteSpecialOperationMultiply".lower()] = 4
        self.globals["xlPasteSpecialOperationNone".lower()] = 4142
        self.globals["xlPasteSpecialOperationSubtract".lower()] = 3
        self.globals["xlPasteValidation".lower()] = 6
        self.globals["xlPasteValues".lower()] = 4163
        self.globals["xlPasteValuesAndNumberFormats".lower()] = 12
        self.globals["xlPatternAutomatic".lower()] = 4105
        self.globals["xlPatternChecker".lower()] = 9
        self.globals["xlPatternCrissCross".lower()] = 16
        self.globals["xlPatternDown".lower()] = 4121
        self.globals["xlPatternGray16".lower()] = 17
        self.globals["xlPatternGray25".lower()] = 4124
        self.globals["xlPatternGray50".lower()] = 4125
        self.globals["xlPatternGray75".lower()] = 4126
        self.globals["xlPatternGray8".lower()] = 18
        self.globals["xlPatternGrid".lower()] = 15
        self.globals["xlPatternHorizontal".lower()] = 4128
        self.globals["xlPatternLightDown".lower()] = 13
        self.globals["xlPatternLightHorizontal".lower()] = 11
        self.globals["xlPatternLightUp".lower()] = 14
        self.globals["xlPatternLightVertical".lower()] = 12
        self.globals["xlPatternLinearGradient".lower()] = 4000
        self.globals["xlPatternNone".lower()] = 4142
        self.globals["xlPatternRectangularGradient".lower()] = 4001
        self.globals["xlPatternSemiGray75".lower()] = 10
        self.globals["xlPatternSolid".lower()] = 1
        self.globals["xlPatternUp".lower()] = 4162
        self.globals["xlPatternVertical".lower()] = 4166
        self.globals["xlPCT".lower()] = 13
        self.globals["xlPCX".lower()] = 10
        self.globals["xlPending".lower()] = 2
        self.globals["xlPercent".lower()] = 2
        self.globals["xlPercentDifferenceFrom".lower()] = 4
        self.globals["xlPercentOf".lower()] = 3
        self.globals["xlPercentOfColumn".lower()] = 7
        self.globals["xlPercentOfParent".lower()] = 12
        self.globals["xlPercentOfParentColumn".lower()] = 11
        self.globals["xlPercentOfParentRow".lower()] = 10
        self.globals["xlPercentOfRow".lower()] = 6
        self.globals["xlPercentOfTotal".lower()] = 8
        self.globals["xlPercentRunningTotal".lower()] = 13
        self.globals["xlPhoneticAlignCenter".lower()] = 2
        self.globals["xlPhoneticAlignDistributed".lower()] = 3
        self.globals["xlPhoneticAlignLeft".lower()] = 1
        self.globals["xlPhoneticAlignNoControl".lower()] = 0
        self.globals["xlPIC".lower()] = 11
        self.globals["xlPICT".lower()] = 1
        self.globals["xlPicture".lower()] = 4147
        self.globals["xlPie".lower()] = 5
        self.globals["xlPieExploded".lower()] = 69
        self.globals["xlPieOfPie".lower()] = 68
        self.globals["xlPinYin".lower()] = 1
        self.globals["xlPivotCellBlankCell".lower()] = 9
        self.globals["xlPivotCellCustomSubtotal".lower()] = 7
        self.globals["xlPivotCellDataField".lower()] = 4
        self.globals["xlPivotCellDataPivotField".lower()] = 8
        self.globals["xlPivotCellGrandTotal".lower()] = 3
        self.globals["xlPivotCellPageFieldItem".lower()] = 6
        self.globals["xlPivotCellPivotField".lower()] = 5
        self.globals["xlPivotCellPivotItem".lower()] = 1
        self.globals["xlPivotCellSubtotal".lower()] = 2
        self.globals["xlPivotCellValue".lower()] = 0
        self.globals["xlPivotChartCollapseEntireFieldButton".lower()] = 34
        self.globals["xlPivotChartDropZone".lower()] = 32
        self.globals["xlPivotChartExpandEntireFieldButton".lower()] = 33
        self.globals["xlPivotChartFieldButton".lower()] = 31
        self.globals["xlPivotLineBlank".lower()] = 3
        self.globals["xlPivotLineGrandTotal".lower()] = 2
        self.globals["xlPivotLineRegular".lower()] = 0
        self.globals["xlPivotLineSubtotal".lower()] = 1
        self.globals["xlPivotTable".lower()] = 4148
        self.globals["xlPivotTableReport".lower()] = 1
        self.globals["xlPivotTableVersion10".lower()] = 1
        self.globals["xlPivotTableVersion11".lower()] = 2
        self.globals["xlPivotTableVersion12".lower()] = 3
        self.globals["xlPivotTableVersion14".lower()] = 4
        self.globals["xlPivotTableVersion15".lower()] = 5
        self.globals["xlPivotTableVersion2000".lower()] = 0
        self.globals["xlPivotTableVersionCurrent".lower()] = 1
        self.globals["xlPlaceholders".lower()] = 2
        self.globals["xlPlotArea".lower()] = 19
        self.globals["xlPLT".lower()] = 12
        self.globals["xlPlus".lower()] = 9
        self.globals["xlPlusValues".lower()] = 2
        self.globals["xlPolynomial".lower()] = 3
        self.globals["xlPortrait".lower()] = 1
        self.globals["xlPortugueseBoth".lower()] = 3
        self.globals["xlPortuguesePostReform".lower()] = 2
        self.globals["xlPortuguesePreReform".lower()] = 1
        self.globals["xlPower".lower()] = 4
        self.globals["xlPowerTalk".lower()] = 2
        self.globals["xlPrevious".lower()] = 2
        self.globals["xlPrimary".lower()] = 1
        self.globals["xlPrimaryButton".lower()] = 1
        self.globals["xlPrinter".lower()] = 2
        self.globals["xlPrintErrorsBlank".lower()] = 1
        self.globals["xlPrintErrorsDash".lower()] = 2
        self.globals["xlPrintErrorsDisplayed".lower()] = 0
        self.globals["xlPrintErrorsNA".lower()] = 3
        self.globals["xlPrintInPlace".lower()] = 16
        self.globals["xlPrintNoComments".lower()] = 4142
        self.globals["xlPrintSheetEnd".lower()] = 1
        self.globals["xlPriorityHigh".lower()] = 4127
        self.globals["xlPriorityLow".lower()] = 4134
        self.globals["xlPriorityNormal".lower()] = 4143
        self.globals["xlProduct".lower()] = 4149
        self.globals["xlPrompt".lower()] = 0
        self.globals["xlProtectedViewCloseEdit".lower()] = 1
        self.globals["xlProtectedViewCloseForced".lower()] = 2
        self.globals["xlProtectedViewCloseNormal".lower()] = 0
        self.globals["xlProtectedViewWindowMaximized".lower()] = 2
        self.globals["xlProtectedViewWindowMinimized".lower()] = 1
        self.globals["xlProtectedViewWindowNormal".lower()] = 0
        self.globals["xlPTClassic".lower()] = 20
        self.globals["xlPTNone".lower()] = 21
        self.globals["xlPublisher".lower()] = 1
        self.globals["xlPublishers".lower()] = 5
        self.globals["xlPyramidBarClustered".lower()] = 109
        self.globals["xlPyramidBarStacked".lower()] = 110
        self.globals["xlPyramidBarStacked100".lower()] = 111
        self.globals["xlPyramidCol".lower()] = 112
        self.globals["xlPyramidColClustered".lower()] = 106
        self.globals["xlPyramidColStacked".lower()] = 107
        self.globals["xlPyramidColStacked100".lower()] = 108
        self.globals["xlPyramidToMax".lower()] = 2
        self.globals["xlPyramidToPoint".lower()] = 1
        self.globals["xlQualityMinimum".lower()] = 1
        self.globals["xlQualityStandard".lower()] = 0
        self.globals["xlQueryTable".lower()] = 0
        self.globals["xlR1C1".lower()] = 4150
        self.globals["xlRadar".lower()] = 4151
        self.globals["xlRadarAxisLabels".lower()] = 27
        self.globals["xlRadarFilled".lower()] = 82
        self.globals["xlRadarMarkers".lower()] = 81
        self.globals["xlRange".lower()] = 2
        self.globals["xlRangeAutoFormat3DEffects1".lower()] = 13
        self.globals["xlRangeAutoFormat3DEffects2".lower()] = 14
        self.globals["xlRangeAutoFormatAccounting1".lower()] = 4
        self.globals["xlRangeAutoFormatAccounting2".lower()] = 5
        self.globals["xlRangeAutoFormatAccounting3".lower()] = 6
        self.globals["xlRangeAutoFormatAccounting4".lower()] = 17
        self.globals["xlRangeAutoFormatClassic1".lower()] = 1
        self.globals["xlRangeAutoFormatClassic2".lower()] = 2
        self.globals["xlRangeAutoFormatClassic3".lower()] = 3
        self.globals["xlRangeAutoFormatClassicPivotTable".lower()] = 31
        self.globals["xlRangeAutoFormatColor1".lower()] = 7
        self.globals["xlRangeAutoFormatColor2".lower()] = 8
        self.globals["xlRangeAutoFormatColor3".lower()] = 9
        self.globals["xlRangeAutoFormatList1".lower()] = 10
        self.globals["xlRangeAutoFormatList2".lower()] = 11
        self.globals["xlRangeAutoFormatList3".lower()] = 12
        self.globals["xlRangeAutoFormatLocalFormat1".lower()] = 15
        self.globals["xlRangeAutoFormatLocalFormat2".lower()] = 16
        self.globals["xlRangeAutoFormatLocalFormat3".lower()] = 19
        self.globals["xlRangeAutoFormatLocalFormat4".lower()] = 20
        self.globals["xlRangeAutoFormatNone".lower()] = 4142
        self.globals["xlRangeAutoFormatPTNone".lower()] = 42
        self.globals["xlRangeAutoFormatReport1".lower()] = 21
        self.globals["xlRangeAutoFormatReport10".lower()] = 30
        self.globals["xlRangeAutoFormatReport2".lower()] = 22
        self.globals["xlRangeAutoFormatReport3".lower()] = 23
        self.globals["xlRangeAutoFormatReport4".lower()] = 24
        self.globals["xlRangeAutoFormatReport5".lower()] = 25
        self.globals["xlRangeAutoFormatReport6".lower()] = 26
        self.globals["xlRangeAutoFormatReport7".lower()] = 27
        self.globals["xlRangeAutoFormatReport8".lower()] = 28
        self.globals["xlRangeAutoFormatReport9".lower()] = 29
        self.globals["xlRangeAutoFormatSimple".lower()] = 4154
        self.globals["xlRangeAutoFormatTable1".lower()] = 32
        self.globals["xlRangeAutoFormatTable10".lower()] = 41
        self.globals["xlRangeAutoFormatTable2".lower()] = 33
        self.globals["xlRangeAutoFormatTable3".lower()] = 34
        self.globals["xlRangeAutoFormatTable4".lower()] = 35
        self.globals["xlRangeAutoFormatTable5".lower()] = 36
        self.globals["xlRangeAutoFormatTable6".lower()] = 37
        self.globals["xlRangeAutoFormatTable7".lower()] = 38
        self.globals["xlRangeAutoFormatTable8".lower()] = 39
        self.globals["xlRangeAutoFormatTable9".lower()] = 40
        self.globals["xlRangeValueDefault".lower()] = 10
        self.globals["xlRangeValueMSPersistXML".lower()] = 12
        self.globals["xlRangeValueXMLSpreadsheet".lower()] = 11
        self.globals["xlRankAscending".lower()] = 14
        self.globals["xlRankDecending".lower()] = 15
        self.globals["xlRDIAll".lower()] = 99
        self.globals["xlRDIComments".lower()] = 1
        self.globals["xlRDIContentType".lower()] = 16
        self.globals["xlRDIDefinedNameComments".lower()] = 18
        self.globals["xlRDIDocumentManagementPolicy".lower()] = 15
        self.globals["xlRDIDocumentProperties".lower()] = 8
        self.globals["xlRDIDocumentServerProperties".lower()] = 14
        self.globals["xlRDIDocumentWorkspace".lower()] = 10
        self.globals["xlRDIEmailHeader".lower()] = 5
        self.globals["xlRDIExcelDataModel".lower()] = 23
        self.globals["xlRDIInactiveDataConnections".lower()] = 19
        self.globals["xlRDIInkAnnotations".lower()] = 11
        self.globals["xlRDIInlineWebExtensions".lower()] = 21
        self.globals["xlRDIPrinterPath".lower()] = 20
        self.globals["xlRDIPublishInfo".lower()] = 13
        self.globals["xlRDIRemovePersonalInformation".lower()] = 4
        self.globals["xlRDIRoutingSlip".lower()] = 6
        self.globals["xlRDIScenarioComments".lower()] = 12
        self.globals["xlRDISendForReview".lower()] = 7
        self.globals["xlRDITaskpaneWebExtensions".lower()] = 22
        self.globals["xlReadOnly".lower()] = 3
        self.globals["xlReadWrite".lower()] = 2
        self.globals["xlRecommendedCharts".lower()] = 2
        self.globals["xlReference".lower()] = 4
        self.globals["xlRegionLabelOptionsBestFitOnly".lower()] = 1
        self.globals["xlRegionLabelOptionsNone".lower()] = 0
        self.globals["xlRegionLabelOptionsShowAll".lower()] = 2
        self.globals["xlRegionMap".lower()] = 140
        self.globals["xlRelative".lower()] = 4
        self.globals["xlRelRowAbsColumn".lower()] = 3
        self.globals["xlRepairFile".lower()] = 1
        self.globals["xlRepeatLabels".lower()] = 2
        self.globals["xlReport1".lower()] = 0
        self.globals["xlReport10".lower()] = 9
        self.globals["xlReport2".lower()] = 1
        self.globals["xlReport3".lower()] = 2
        self.globals["xlReport4".lower()] = 3
        self.globals["xlReport5".lower()] = 4
        self.globals["xlReport6".lower()] = 5
        self.globals["xlReport7".lower()] = 6
        self.globals["xlReport8".lower()] = 7
        self.globals["xlReport9".lower()] = 8
        self.globals["xlRight".lower()] = 4152
        self.globals["xlRightBrace".lower()] = 13
        self.globals["xlRightBracket".lower()] = 11
        self.globals["xlRoutingComplete".lower()] = 2
        self.globals["xlRoutingInProgress".lower()] = 1
        self.globals["xlRowField".lower()] = 1
        self.globals["xlRowGroups".lower()] = 1
        self.globals["xlRowHeader".lower()] = 4153
        self.globals["xlRowItem".lower()] = 4
        self.globals["xlRowLabels".lower()] = 1
        self.globals["xlRows".lower()] = 1
        self.globals["xlRowSeparator".lower()] = 15
        self.globals["xlRowStripe1".lower()] = 5
        self.globals["xlRowStripe2".lower()] = 6
        self.globals["xlRowSubheading1".lower()] = 23
        self.globals["xlRowSubheading2".lower()] = 24
        self.globals["xlRowSubheading3".lower()] = 25
        self.globals["xlRowThenColumn".lower()] = 1
        self.globals["xlRTF".lower()] = 4
        self.globals["xlRTL".lower()] = 5004
        self.globals["xlRunningTotal".lower()] = 5
        self.globals["xlSaveChanges".lower()] = 1
        self.globals["xlScale".lower()] = 3
        self.globals["xlScaleLinear".lower()] = 4132
        self.globals["xlScaleLogarithmic".lower()] = 4133
        self.globals["xlScenario".lower()] = 4
        self.globals["xlScreen".lower()] = 1
        self.globals["xlScreenSize".lower()] = 1
        self.globals["xlScrollBar".lower()] = 8
        self.globals["xlSecondary".lower()] = 2
        self.globals["xlSecondaryButton".lower()] = 2
        self.globals["xlSecondCode".lower()] = 24
        self.globals["xlSelect".lower()] = 3
        self.globals["xlSelectionScope".lower()] = 0
        self.globals["xlSemiautomatic".lower()] = 2
        self.globals["xlSemiGray75".lower()] = 10
        self.globals["xlSendPublisher".lower()] = 2
        self.globals["xlSeries".lower()] = 3
        self.globals["xlSeriesAxis".lower()] = 3
        self.globals["xlSeriesColorGradientStyleDiverging".lower()] = 1
        self.globals["xlSeriesColorGradientStyleSequential".lower()] = 0
        self.globals["xlSeriesLines".lower()] = 22
        self.globals["xlSeriesNameLevelAll".lower()] = 1
        self.globals["xlSeriesNameLevelCustom".lower()] = 2
        self.globals["xlSeriesNameLevelNone".lower()] = 3
        self.globals["xlSet".lower()] = 3
        self.globals["xlShape".lower()] = 14
        self.globals["xlShared".lower()] = 2
        self.globals["xlSheetHidden".lower()] = 0
        self.globals["xlSheetVeryHidden".lower()] = 2
        self.globals["xlSheetVisible".lower()] = 1
        self.globals["xlShiftDown".lower()] = 4121
        self.globals["xlShiftToLeft".lower()] = 4159
        self.globals["xlShiftToRight".lower()] = 4161
        self.globals["xlShiftUp".lower()] = 4162
        self.globals["xlShort".lower()] = 1
        self.globals["xlShowLabel".lower()] = 4
        self.globals["xlShowLabelAndPercent".lower()] = 5
        self.globals["xlShowPercent".lower()] = 3
        self.globals["xlShowValue".lower()] = 2
        self.globals["xlSides".lower()] = 1
        self.globals["xlSimple".lower()] = 4154
        self.globals["xlSinceMyLastSave".lower()] = 1
        self.globals["xlSingle".lower()] = 2
        self.globals["xlSingleAccounting".lower()] = 4
        self.globals["xlSingleQuote".lower()] = 2
        self.globals["xlSizeIsArea".lower()] = 1
        self.globals["xlSizeIsWidth".lower()] = 2
        self.globals["xlSkipColumn".lower()] = 9
        self.globals["xlSlantDashDot".lower()] = 13
        self.globals["xlSlicer".lower()] = 1
        self.globals["xlSlicerCrossFilterHideButtonsWithNoData".lower()] = 4
        self.globals["xlSlicerCrossFilterShowItemsWithDataAtTop".lower()] = 2
        self.globals["xlSlicerCrossFilterShowItemsWithNoData".lower()] = 3
        self.globals["xlSlicerHoveredSelectedItemWithData".lower()] = 33
        self.globals["xlSlicerHoveredSelectedItemWithNoData".lower()] = 35
        self.globals["xlSlicerHoveredUnselectedItemWithData".lower()] = 32
        self.globals["xlSlicerHoveredUnselectedItemWithNoData".lower()] = 34
        self.globals["xlSlicerNoCrossFilter".lower()] = 1
        self.globals["xlSlicerSelectedItemWithData".lower()] = 30
        self.globals["xlSlicerSelectedItemWithNoData".lower()] = 31
        self.globals["xlSlicerSortAscending".lower()] = 2
        self.globals["xlSlicerSortDataSourceOrder".lower()] = 1
        self.globals["xlSlicerSortDescending".lower()] = 3
        self.globals["xlSlicerUnselectedItemWithData".lower()] = 28
        self.globals["xlSlicerUnselectedItemWithNoData".lower()] = 29
        self.globals["xlSmartTagControlActiveX".lower()] = 13
        self.globals["xlSmartTagControlButton".lower()] = 6
        self.globals["xlSmartTagControlCheckbox".lower()] = 9
        self.globals["xlSmartTagControlCombo".lower()] = 12
        self.globals["xlSmartTagControlHelp".lower()] = 3
        self.globals["xlSmartTagControlHelpURL".lower()] = 4
        self.globals["xlSmartTagControlImage".lower()] = 8
        self.globals["xlSmartTagControlLabel".lower()] = 7
        self.globals["xlSmartTagControlLink".lower()] = 2
        self.globals["xlSmartTagControlListbox".lower()] = 11
        self.globals["xlSmartTagControlRadioGroup".lower()] = 14
        self.globals["xlSmartTagControlSeparator".lower()] = 5
        self.globals["xlSmartTagControlSmartTag".lower()] = 1
        self.globals["xlSmartTagControlTextbox".lower()] = 10
        self.globals["xlSolid".lower()] = 1
        self.globals["xlSortColumns".lower()] = 1
        self.globals["xlSortLabels".lower()] = 2
        self.globals["xlSortNormal".lower()] = 0
        self.globals["xlSortOnCellColor".lower()] = 1
        self.globals["xlSortOnFontColor".lower()] = 2
        self.globals["xlSortOnIcon".lower()] = 3
        self.globals["xlSortOnValues".lower()] = 0
        self.globals["xlSortRows".lower()] = 2
        self.globals["xlSortTextAsNumbers".lower()] = 1
        self.globals["xlSortValues".lower()] = 1
        self.globals["xlSourceAutoFilter".lower()] = 3
        self.globals["xlSourceChart".lower()] = 5
        self.globals["xlSourcePivotTable".lower()] = 6
        self.globals["xlSourcePrintArea".lower()] = 2
        self.globals["xlSourceQuery".lower()] = 7
        self.globals["xlSourceRange".lower()] = 4
        self.globals["xlSourceSheet".lower()] = 1
        self.globals["xlSourceWorkbook".lower()] = 0
        self.globals["xlSpanishTuteoAndVoseo".lower()] = 1
        self.globals["xlSpanishTuteoOnly".lower()] = 0
        self.globals["xlSpanishVoseoOnly".lower()] = 2
        self.globals["xlSparkColumn".lower()] = 2
        self.globals["xlSparkColumnStacked100".lower()] = 3
        self.globals["xlSparkLine".lower()] = 1
        self.globals["xlSparklineColumnsSquare".lower()] = 2
        self.globals["xlSparklineNonSquare".lower()] = 0
        self.globals["xlSparklineRowsSquare".lower()] = 1
        self.globals["xlSparklines".lower()] = 5
        self.globals["xlSparkScaleCustom".lower()] = 3
        self.globals["xlSparkScaleGroup".lower()] = 1
        self.globals["xlSparkScaleSingle".lower()] = 2
        self.globals["xlSpeakByColumns".lower()] = 1
        self.globals["xlSpeakByRows".lower()] = 0
        self.globals["xlSpecificDate".lower()] = 29
        self.globals["xlSpecifiedTables".lower()] = 3
        self.globals["xlSpinner".lower()] = 9
        self.globals["xlSplitByCustomSplit".lower()] = 4
        self.globals["xlSplitByPercentValue".lower()] = 3
        self.globals["xlSplitByPosition".lower()] = 1
        self.globals["xlSplitByValue".lower()] = 2
        self.globals["xlSquare".lower()] = 1
        self.globals["xlSrcExternal".lower()] = 0
        self.globals["xlSrcModel".lower()] = 4
        self.globals["xlSrcQuery".lower()] = 3
        self.globals["xlSrcRange".lower()] = 1
        self.globals["xlSrcXml".lower()] = 2
        self.globals["xlStack".lower()] = 2
        self.globals["xlStackScale".lower()] = 3
        self.globals["xlStandardSummary".lower()] = 1
        self.globals["xlStar".lower()] = 5
        self.globals["xlStDev".lower()] = 4155
        self.globals["xlStDevP".lower()] = 4156
        self.globals["xlStError".lower()] = 4
        self.globals["xlStockHLC".lower()] = 88
        self.globals["xlStockOHLC".lower()] = 89
        self.globals["xlStockVHLC".lower()] = 90
        self.globals["xlStockVOHLC".lower()] = 91
        self.globals["xlStretch".lower()] = 1
        self.globals["xlStrict".lower()] = 2
        self.globals["xlStroke".lower()] = 2
        self.globals["xlSubscriber".lower()] = 2
        self.globals["xlSubscribers".lower()] = 6
        self.globals["xlSubscribeToPicture".lower()] = 4147
        self.globals["xlSubscribeToText".lower()] = 4158
        self.globals["xlSubtotalColumn1".lower()] = 13
        self.globals["xlSubtotalColumn2".lower()] = 14
        self.globals["xlSubtotalColumn3".lower()] = 15
        self.globals["xlSubtotalRow1".lower()] = 16
        self.globals["xlSubtotalRow2".lower()] = 17
        self.globals["xlSubtotalRow3".lower()] = 18
        self.globals["xlSubtract".lower()] = 3
        self.globals["xlSum".lower()] = 4157
        self.globals["xlSummaryAbove".lower()] = 0
        self.globals["xlSummaryBelow".lower()] = 1
        self.globals["xlSummaryOnLeft".lower()] = 4131
        self.globals["xlSummaryOnRight".lower()] = 4152
        self.globals["xlSummaryPivotTable".lower()] = 4148
        self.globals["xlSunburst".lower()] = 120
        self.globals["xlSurface".lower()] = 83
        self.globals["xlSurfaceTopView".lower()] = 85
        self.globals["xlSurfaceTopViewWireframe".lower()] = 86
        self.globals["xlSurfaceWireframe".lower()] = 84
        self.globals["xlSYLK".lower()] = 2
        self.globals["xlSyllabary".lower()] = 1
        self.globals["xlSystem".lower()] = 1
        self.globals["xlTable".lower()] = 2
        self.globals["xlTable1".lower()] = 10
        self.globals["xlTable10".lower()] = 19
        self.globals["xlTable2".lower()] = 11
        self.globals["xlTable3".lower()] = 12
        self.globals["xlTable4".lower()] = 13
        self.globals["xlTable5".lower()] = 14
        self.globals["xlTable6".lower()] = 15
        self.globals["xlTable7".lower()] = 16
        self.globals["xlTable8".lower()] = 17
        self.globals["xlTable9".lower()] = 18
        self.globals["xlTableBody".lower()] = 8
        self.globals["xlTables".lower()] = 4
        self.globals["xlTabPositionFirst".lower()] = 0
        self.globals["xlTabPositionLast".lower()] = 1
        self.globals["xlTabular".lower()] = 0
        self.globals["xlTabularRow".lower()] = 1
        self.globals["xlTemplate".lower()] = 17
        self.globals["xlTemplate8".lower()] = 17
        self.globals["xlTenMillions".lower()] = 7
        self.globals["xlTenThousands".lower()] = 4
        self.globals["xlText".lower()] = 4158
        self.globals["xlTextBox".lower()] = 16
        self.globals["xlTextDate".lower()] = 2
        self.globals["xlTextFormat".lower()] = 2
        self.globals["xlTextImport".lower()] = 6
        self.globals["xlTextMac".lower()] = 19
        self.globals["xlTextMSDOS".lower()] = 21
        self.globals["xlTextPrinter".lower()] = 36
        self.globals["xlTextQualifierDoubleQuote".lower()] = 1
        self.globals["xlTextQualifierNone".lower()] = 4142
        self.globals["xlTextQualifierSingleQuote".lower()] = 2
        self.globals["xlTextString".lower()] = 9
        self.globals["xlTextValues".lower()] = 2
        self.globals["xlTextVisualLTR".lower()] = 1
        self.globals["xlTextVisualRTL".lower()] = 2
        self.globals["xlTextWindows".lower()] = 20
        self.globals["xlThemeColorAccent1".lower()] = 5
        self.globals["xlThemeColorAccent2".lower()] = 6
        self.globals["xlThemeColorAccent3".lower()] = 7
        self.globals["xlThemeColorAccent4".lower()] = 8
        self.globals["xlThemeColorAccent5".lower()] = 9
        self.globals["xlThemeColorAccent6".lower()] = 10
        self.globals["xlThemeColorDark1".lower()] = 1
        self.globals["xlThemeColorDark2".lower()] = 3
        self.globals["xlThemeColorFollowedHyperlink".lower()] = 12
        self.globals["xlThemeColorHyperlink".lower()] = 11
        self.globals["xlThemeColorLight1".lower()] = 2
        self.globals["xlThemeColorLight2".lower()] = 4
        self.globals["xlThemeFontMajor".lower()] = 1
        self.globals["xlThemeFontMinor".lower()] = 2
        self.globals["xlThemeFontNone".lower()] = 0
        self.globals["xlThick".lower()] = 4
        self.globals["xlThin".lower()] = 2
        self.globals["xlThisMonth".lower()] = 9
        self.globals["xlThisWeek".lower()] = 3
        self.globals["xlThousandMillions".lower()] = 9
        self.globals["xlThousands".lower()] = 3
        self.globals["xlThousandsSeparator".lower()] = 4
        self.globals["xlThreadModeAutomatic".lower()] = 0
        self.globals["xlThreadModeManual".lower()] = 1
        self.globals["xlTickLabelOrientationAutomatic".lower()] = 4105
        self.globals["xlTickLabelOrientationDownward".lower()] = 4170
        self.globals["xlTickLabelOrientationHorizontal".lower()] = 4128
        self.globals["xlTickLabelOrientationUpward".lower()] = 4171
        self.globals["xlTickLabelOrientationVertical".lower()] = 4166
        self.globals["xlTickLabelPositionHigh".lower()] = 4127
        self.globals["xlTickLabelPositionLow".lower()] = 4134
        self.globals["xlTickLabelPositionNextToAxis".lower()] = 4
        self.globals["xlTickLabelPositionNone".lower()] = 4142
        self.globals["xlTickMarkCross".lower()] = 4
        self.globals["xlTickMarkInside".lower()] = 2
        self.globals["xlTickMarkNone".lower()] = 4142
        self.globals["xlTickMarkOutside".lower()] = 3
        self.globals["xlTIF".lower()] = 9
        self.globals["xlTiled".lower()] = 1
        self.globals["xlTimeLeadingZero".lower()] = 45
        self.globals["xlTimeline".lower()] = 2
        self.globals["xlTimelineLevelDays".lower()] = 3
        self.globals["xlTimelineLevelMonths".lower()] = 2
        self.globals["xlTimelineLevelQuarters".lower()] = 1
        self.globals["xlTimelineLevelYears".lower()] = 0
        self.globals["xlTimelinePeriodLabels1".lower()] = 38
        self.globals["xlTimelinePeriodLabels2".lower()] = 39
        self.globals["xlTimelineSelectedTimeBlock".lower()] = 40
        self.globals["xlTimelineSelectedTimeBlockSpace".lower()] = 42
        self.globals["xlTimelineSelectionLabel".lower()] = 36
        self.globals["xlTimelineTimeLevel".lower()] = 37
        self.globals["xlTimelineUnselectedTimeBlock".lower()] = 41
        self.globals["xlTimePeriod".lower()] = 11
        self.globals["xlTimeScale".lower()] = 3
        self.globals["xlTimeSeparator".lower()] = 18
        self.globals["xlTitleBar".lower()] = 8
        self.globals["xlToday".lower()] = 0
        self.globals["xlToLeft".lower()] = 4159
        self.globals["xlTomorrow".lower()] = 6
        self.globals["xlToolbar".lower()] = 1
        self.globals["xlToolbarButton".lower()] = 2
        self.globals["xlToolbarProtectionNone".lower()] = 4143
        self.globals["xlTop".lower()] = 4160
        self.globals["xlTop10".lower()] = 5
        self.globals["xlTop10Bottom".lower()] = 0
        self.globals["xlTop10Items".lower()] = 3
        self.globals["xlTop10Percent".lower()] = 5
        self.globals["xlTop10Top".lower()] = 1
        self.globals["xlTopCount".lower()] = 1
        self.globals["xlTopPercent".lower()] = 3
        self.globals["xlTopSum".lower()] = 5
        self.globals["xlTopToBottom".lower()] = 1
        self.globals["xlToRight".lower()] = 4161
        self.globals["xlTotalRow".lower()] = 2
        self.globals["xlTotals".lower()] = 3
        self.globals["xlTotalsCalculationAverage".lower()] = 2
        self.globals["xlTotalsCalculationCount".lower()] = 3
        self.globals["xlTotalsCalculationCountNums".lower()] = 4
        self.globals["xlTotalsCalculationCustom".lower()] = 9
        self.globals["xlTotalsCalculationMax".lower()] = 6
        self.globals["xlTotalsCalculationMin".lower()] = 5
        self.globals["xlTotalsCalculationNone".lower()] = 0
        self.globals["xlTotalsCalculationStdDev".lower()] = 7
        self.globals["xlTotalsCalculationSum".lower()] = 1
        self.globals["xlTotalsCalculationVar".lower()] = 8
        self.globals["xlTransparent".lower()] = 2
        self.globals["xlTreemap".lower()] = 117
        self.globals["xlTrendline".lower()] = 8
        self.globals["xlTriangle".lower()] = 3
        self.globals["xlTypePDF".lower()] = 0
        self.globals["xlTypeXPS".lower()] = 1
        self.globals["xlUICultureTag".lower()] = 46
        self.globals["xlUnderlineStyleDouble".lower()] = 4119
        self.globals["xlUnderlineStyleDoubleAccounting".lower()] = 5
        self.globals["xlUnderlineStyleNone".lower()] = 4142
        self.globals["xlUnderlineStyleSingle".lower()] = 2
        self.globals["xlUnderlineStyleSingleAccounting".lower()] = 4
        self.globals["xlUnicodeText".lower()] = 42
        self.globals["xlUnique".lower()] = 0
        self.globals["xlUniqueValues".lower()] = 8
        self.globals["xlUnknown".lower()] = 1000
        self.globals["xlUnlockedCells".lower()] = 1
        self.globals["xlUnlockedFormulaCells".lower()] = 6
        self.globals["xlUp".lower()] = 4162
        self.globals["xlUpBars".lower()] = 18
        self.globals["xlUpdateLinksAlways".lower()] = 3
        self.globals["xlUpdateLinksNever".lower()] = 2
        self.globals["xlUpdateLinksUserSetting".lower()] = 1
        self.globals["xlUpdateState".lower()] = 1
        self.globals["xlUpdateSubscriber".lower()] = 2
        self.globals["xlUpperCaseColumnLetter".lower()] = 7
        self.globals["xlUpperCaseRowLetter".lower()] = 6
        self.globals["xlUpward".lower()] = 4171
        self.globals["xlUserDefined".lower()] = 22
        self.globals["xlUserResolution".lower()] = 1
        self.globals["xlValidAlertInformation".lower()] = 3
        self.globals["xlValidAlertStop".lower()] = 1
        self.globals["xlValidAlertWarning".lower()] = 2
        self.globals["xlValidateCustom".lower()] = 7
        self.globals["xlValidateDate".lower()] = 4
        self.globals["xlValidateDecimal".lower()] = 2
        self.globals["xlValidateInputOnly".lower()] = 0
        self.globals["xlValidateList".lower()] = 3
        self.globals["xlValidateTextLength".lower()] = 6
        self.globals["xlValidateTime".lower()] = 5
        self.globals["xlValidateWholeNumber".lower()] = 1
        self.globals["xlVAlignBottom".lower()] = 4107
        self.globals["xlVAlignCenter".lower()] = 4108
        self.globals["xlVAlignDistributed".lower()] = 4117
        self.globals["xlVAlignJustify".lower()] = 4130
        self.globals["xlVAlignTop".lower()] = 4160
        self.globals["xlVALU".lower()] = 8
        self.globals["xlValue".lower()] = 2
        self.globals["xlValueAscending".lower()] = 1
        self.globals["xlValueDescending".lower()] = 2
        self.globals["xlValueDoesNotEqual".lower()] = 8
        self.globals["xlValueEquals".lower()] = 7
        self.globals["xlValueIsBetween".lower()] = 13
        self.globals["xlValueIsGreaterThan".lower()] = 9
        self.globals["xlValueIsGreaterThanOrEqualTo".lower()] = 10
        self.globals["xlValueIsLessThan".lower()] = 11
        self.globals["xlValueIsLessThanOrEqualTo".lower()] = 12
        self.globals["xlValueIsNotBetween".lower()] = 14
        self.globals["xlValueNone".lower()] = 0
        self.globals["xlValues".lower()] = 4163
        self.globals["xlVar".lower()] = 4164
        self.globals["xlVarP".lower()] = 4165
        self.globals["xlVerbOpen".lower()] = 2
        self.globals["xlVerbPrimary".lower()] = 1
        self.globals["xlVertical".lower()] = 4166
        self.globals["xlVerticalCoordinate".lower()] = 2
        self.globals["xlVeryHidden".lower()] = 2
        self.globals["xlVisible".lower()] = 12
        self.globals["xlVisualCursor".lower()] = 2
        self.globals["xlWait".lower()] = 2
        self.globals["xlWalls".lower()] = 5
        self.globals["xlWatchPane".lower()] = 11
        self.globals["xlWaterfall".lower()] = 119
        self.globals["xlWBATChart".lower()] = 4109
        self.globals["xlWBATExcel4IntlMacroSheet".lower()] = 4
        self.globals["xlWBATExcel4MacroSheet".lower()] = 3
        self.globals["xlWBATWorksheet".lower()] = 4167
        self.globals["xlWebArchive".lower()] = 45
        self.globals["xlWebFormattingAll".lower()] = 1
        self.globals["xlWebFormattingNone".lower()] = 3
        self.globals["xlWebFormattingRTF".lower()] = 2
        self.globals["xlWebQuery".lower()] = 4
        self.globals["xlWeekday".lower()] = 2
        self.globals["xlWeekdayNameChars".lower()] = 31
        self.globals["xlWeightedAllocation".lower()] = 2
        self.globals["xlWhole".lower()] = 1
        self.globals["xlWholeTable".lower()] = 0
        self.globals["xlWide".lower()] = 3
        self.globals["xlWindows".lower()] = 2
        self.globals["xlWithinSheet".lower()] = 1
        self.globals["xlWithinWorkbook".lower()] = 2
        self.globals["xlWJ2WD1".lower()] = 14
        self.globals["xlWJ3".lower()] = 40
        self.globals["xlWJ3FJ3".lower()] = 41
        self.globals["xlWK1".lower()] = 5
        self.globals["xlWK1ALL".lower()] = 31
        self.globals["xlWK1FMT".lower()] = 30
        self.globals["xlWK3".lower()] = 15
        self.globals["xlWK3FM3".lower()] = 32
        self.globals["xlWK4".lower()] = 38
        self.globals["xlWKS".lower()] = 4
        self.globals["xlWMF".lower()] = 2
        self.globals["xlWorkbook".lower()] = 1
        self.globals["xlWorkbookDefault".lower()] = 51
        self.globals["xlWorkbookNormal".lower()] = 4143
        self.globals["xlWorkbookTab".lower()] = 6
        self.globals["xlWorks2FarEast".lower()] = 28
        self.globals["xlWorksheet".lower()] = 4167
        self.globals["xlWorksheet4".lower()] = 1
        self.globals["xlWorksheetCell".lower()] = 3
        self.globals["xlWorksheetShort".lower()] = 5
        self.globals["xlWPG".lower()] = 3
        self.globals["xlWQ1".lower()] = 34
        self.globals["xlX".lower()] = 4168
        self.globals["xlXErrorBars".lower()] = 10
        self.globals["xlXmlExportSuccess".lower()] = 0
        self.globals["xlXmlExportValidationFailed".lower()] = 1
        self.globals["xlXmlImportElementsTruncated".lower()] = 1
        self.globals["xlXmlImportSuccess".lower()] = 0
        self.globals["xlXmlImportValidationFailed".lower()] = 2
        self.globals["xlXmlLoadImportToList".lower()] = 2
        self.globals["xlXmlLoadMapXml".lower()] = 3
        self.globals["xlXmlLoadOpenXml".lower()] = 1
        self.globals["xlXmlLoadPromptUser".lower()] = 0
        self.globals["xlXMLSpreadsheet".lower()] = 46
        self.globals["xlXYScatter".lower()] = 4169
        self.globals["xlXYScatterLines".lower()] = 74
        self.globals["xlXYScatterLinesNoMarkers".lower()] = 75
        self.globals["xlXYScatterSmooth".lower()] = 72
        self.globals["xlXYScatterSmoothNoMarkers".lower()] = 73
        self.globals["xlY".lower()] = 1
        self.globals["xlYDMFormat".lower()] = 8
        self.globals["xlYear".lower()] = 4
        self.globals["xlYearCode".lower()] = 19
        self.globals["xlYears".lower()] = 2
        self.globals["xlYearToDate".lower()] = 52
        self.globals["xlYErrorBars".lower()] = 11
        self.globals["xlYes".lower()] = 1
        self.globals["xlYesterday".lower()] = 1
        self.globals["xlYMDFormat".lower()] = 5
        self.globals["xlZero".lower()] = 2

        # endregion
        
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

        # The error has now been cleared.
        self.got_error = False
    
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
        longest = ""
        cdrive = None
        for file_id in self.open_files.keys():
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
        
    def open_file(self, fname):
        """
        Simulate opening a file.

        fname - The name of the file.
        """
        # Save that the file is opened.
        self.open_files[fname] = b''
        log.info("Opened file " + fname)

    def write_file(self, fname, data):
        # Make sure the "file" exists.
        if fname not in self.open_files:
            log.error('File {} not open. Cannot write new data.'.format(fname))
            return False

        # Are we writing a string?
        if isinstance(data, str):

            # Hex string?
            if re.match('&H[0-9A-F]{2}', data, re.IGNORECASE):
                data = chr(int(data[-2:], 16))

            self.open_files[fname] += data
            return True

        # Are we writing a list?
        elif isinstance(data, list):
            self.open_files[fname] += ''.join(map(chr, data))
            return True

        # Unhandled.
        else:
            log.error("Unhandled data type to write. " + str(type(data)) + ".")
            return False

    def dump_all_files(self):
        for fname in self.open_files.keys():
            self.dump_file(fname)

    def close_file(self, fname):
        """
        Simulate closing a file.

        fname - The name of the file.

        Returns boolean indicating success.
        """
        global file_count
        
        # Make sure the "file" exists.
        if fname not in self.open_files:
            log.error('File {} not open. Cannot close.'.format(fname))
            return

        log.info("Closing file " + fname)

        # Get the data written to the file and track it.
        data = self.open_files[fname]
        self.closed_files[fname] = data

        # Clear the file out of the open files.
        del self.open_files[fname]

        if out_dir:
            self.dump_file(fname)

    # FIXME: This function is too closely coupled to the CLI.
    #   Context should not contain business logic.
    def dump_file(self, fname):
        """
        Save the contents of a file dumped by the VBA to disk.

        fname - The name of the file.
        """
        if fname not in self.closed_files:
            log.error('File {} not closed. Cannot save.'.format(fname))
            return

        raw_data = self.closed_files[fname]
        file_hash = sha256(raw_data).hexdigest()
        self.report_action("Dropped File Hash", file_hash, 'File Name: ' + fname)

        # TODO: Set a flag to control whether to dump file contents.

        # Make the dropped file directory if needed.
        if not os.path.isdir(out_dir):
            os.makedirs(out_dir)

        # Dump the file.
        try:
            # Get a unique name for the file.
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
        log.debug("Looking for library function '" + name + "'...")
        if name in VBA_LIBRARY:
            log.debug('Found %r in VBA Library' % name)
            return VBA_LIBRARY[name]

        # Unknown symbol.
        else:            
            raise KeyError('Library function %r not found' % name)

    def _get(self, name):

        if (not isinstance(name, basestring)):
            raise KeyError('Object %r not found' % name)

        # convert to lowercase
        name = name.lower()
        log.debug("Looking for var '" + name + "'...")
        
        # First, search in locals. This handles variables whose name overrides
        # a system function.
        if name in self.locals:
            log.debug('Found %r in locals' % name)
            return self.locals[name]
        # second, in globals:
        elif name in self.globals:
            log.debug('Found %r in globals' % name)
            return self.globals[name]
        # next, search in the global VBA library:
        elif name in VBA_LIBRARY:
            log.debug('Found %r in VBA Library' % name)
            return VBA_LIBRARY[name]
        # Is it a doc var?
        elif name in self.doc_vars:
            return self.doc_vars[name]
        # Unknown symbol.
        else:
            # Not found.
            raise KeyError('Object %r not found' % name)
            # NOTE: if name is unknown, just raise Python dict's exception
            # TODO: raise a custom VBA exception?

    def get(self, name):
        
        # See if this is an aliased reference to an objects .Text field.
        name = str(name)
        if (((name == "NodeTypedValue") or (name == ".NodeTypedValue")) and
            (not name in self.locals) and
            (".Text".lower() in self.locals)):
            return self.get(".Text")
        
        # Try to get the item using the current with context.
        tmp_name = str(self.with_prefix) + "." + str(name)
        try:
            return self._get(tmp_name)
        except KeyError:
            pass

        # Now try it without the current with context.
        try:
            return self._get(str(name))
        except KeyError:
            pass

        # Are we referencing a field in an object?
        if ("." in name):

            # Look for faked object field.
            new_name = "me." + name[name.index(".")+1:]
            try:
                return self._get(str(new_name))
            except KeyError:
                pass

            # Look for wild carded field value.
            new_name = name[:name.index(".")] + ".*"
            try:
                r = self._get(str(new_name))
                log.debug("Found wildcarded field value " + new_name + " = " + str(r))
                return r
            except KeyError:
                pass
            
        # See if the variable was initially defined with a trailing '$'.
        return self._get(str(name) + "$")
        
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

    def get_doc_var(self, var):
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
        log.debug("Looking up doc var " + var)

        # Are we pulling out all the doc vars?
        if (var == "activedocument.variables"):
            return self.doc_vars.items()
        
        if (var not in self.doc_vars):

            # Can't find a doc var with this name. See if we have an internal variable
            # with this name.
            log.debug("doc var named " + var + " not found.")
            try:
                var_value = self.get(var)
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
                    log.debug("Found doc var " + var + " = " + str(r))
                    return r
                
            # No variable. Return nothing.
            return None

        # Found it.
        r = self.doc_vars[var]
        log.debug("Found doc var " + var + " = " + str(r))
        return r
            
    # TODO: set_global?

    def set(self,
            name,
            value,
            var_type=None,
            do_with_prefix=True,
            force_local=False,
            force_global=False):

        # Does the name make sense?
        if (not isinstance(name, basestring)):
            log.warning("context.set() " + str(name) + " is improper type. " + str(type(name)))
            name = str(name)

        # Does the value make sense?
        if (value is None):
            log.debug("context.set() " + str(name) + " failed. Value is None.")
            return
        
        # convert to lowercase
        name = name.lower()

        # Set the variable
        if (force_global):
            try:
                log.debug("Set local var " + str(name) + " = " + str(value))
            except:
                pass
            self.globals[name] = value
        elif ((name in self.locals) or force_local):
            try:
                log.debug("Set local var " + str(name) + " = " + str(value))
            except:
                pass
            self.locals[name] = value
        # check globals, but avoid to overwrite subs and functions:
        elif name in self.globals and not is_procedure(self.globals[name]):
            self.globals[name] = value
            log.debug("Set global var " + name + " = " + str(value))
            if ("." in name):
                text_name = name + ".text"
                self.globals[text_name] = value
                log.debug("Set global var " + text_name + " = " + str(value))
        else:
            # new name, typically store in local scope.
            if (not self.global_scope):
                log.debug("Set local var " + str(name) + " = " + str(value))
                self.locals[name] = value
            else:
                self.globals[name] = value
                try:
                    log.debug("Set global var " + name + " = " + str(value))
                except:
                    pass
                if ("." in name):
                    text_name = name + ".text"
                    self.globals[text_name] = value
                    log.debug("Set global var " + text_name + " = " + str(value))
                
        # If we know the type of the variable, save it.
        if (var_type is not None):
            self.types[name] = var_type

        # Also set the variable using the current With name prefix, if
        # we have one.
        if ((do_with_prefix) and (len(self.with_prefix) > 0)):
            tmp_name = str(self.with_prefix) + "." + str(name)
            self.set(tmp_name, value, var_type=var_type, do_with_prefix=False)

        # Handle base64 conversion with VBA objects.
        if (name.endswith(".text")):

            # Handle doing conversions on the data.
            node_type = name.replace(".text", ".datatype")
            try:

                # Is the root object something set to the "bin.base64" data type?
                val = str(self.get(node_type)).strip()
                if (val == "bin.base64"):

                    # Try converting the text from base64.
                    try:

                        # Set the typed vale of the node to the decoded value.
                        tmp_str = filter(isascii, str(value).strip())
                        missing_padding = len(tmp_str) % 4
                        if missing_padding:
                            tmp_str += b'='* (4 - missing_padding)
                        conv_val = base64.b64decode(tmp_str)
                        val_name = name.replace(".text", ".nodetypedvalue")
                        self.set(val_name, conv_val)
                    except Exception as e:
                        log.error("base64 conversion of '" + str(value) + "' failed. " + str(e))
                        
            except KeyError:
                pass

        # Handle hex conversion with VBA objects.
        if (name.endswith(".nodetypedvalue")):

            # Handle doing conversions on the data.
            node_type = name.replace(".nodetypedvalue", ".datatype")
            try:

                # Something set to type "bin.hex"?
                val = str(self.get(node_type)).strip()
                if (val == "bin.hex"):

                    # Try converting from hex.
                    try:

                        # Set the typed vale of the node to the decoded value.
                        conv_val = codecs.decode(str(value).strip(), "hex")
                        self.set(name, conv_val)
                    except Exception as e:
                        log.error("hex conversion of '" + str(value) + "' failed. " + str(e))
                        
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
        self.engine.report_action(action, params, description)

