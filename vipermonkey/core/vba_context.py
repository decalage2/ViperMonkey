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

import xlrd

import array
import os
from hashlib import sha256
from datetime import datetime
from logger import log
import base64
import re
import random
import string

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
out_dir = None
# Count of files dropped.
file_count = 0

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
                 filename=None):

        # Track the maximum number of iterations to emulate in a while loop before
        # breaking out (infinite loop) due to no vars in the loop guard being
        # modified.
        self.max_static_iters = 2
        
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
            # direct copy of the pointer to globals:
            self.globals = _globals
        elif context is not None:
            self.globals = context.globals
            self.open_files = context.open_files
            self.closed_files = context.closed_files
            self.loaded_excel = context.loaded_excel
            self.dll_func_true_names = context.dll_func_true_names
            self.fileename = context.filename
            self.skip_handlers = context.skip_handlers
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
        
        # Add some attributes we are handling as global variables.

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


        self.globals["vbModal".lower()]= 1 
        self.globals["vbModeless".lower()] = 0
        self.globals["VBA.FormShowConstants.vbModal".lower()]= 1 
        self.globals["VBA.FormShowConstants.vbModeless".lower()] = 0

        self.globals["vbBinaryCompare".lower()] = 0 
        self.globals["vbDatabaseCompare".lower()] = 2 
        self.globals["vbTextCompare".lower()] = 1 
        self.globals["VBA.vbCompareMethod.vbBinaryCompare".lower()] = 0 
        self.globals["VBA.vbCompareMethod.vbDatabaseCompare".lower()] = 2 
        self.globals["VBA.vbCompareMethod.vbTextCompare".lower()] = 1 

        self.globals["vbGeneralDate".lower()] = 0 
        self.globals["vbLongDate".lower()] = 1 
        self.globals["vbLongTime".lower()] = 3 
        self.globals["vbShortDate".lower()] = 2 
        self.globals["vbShortTime".lower()] = 4 
        self.globals["VBA.vbDateTimeFormat.vbGeneralDate".lower()] = 0 
        self.globals["VBA.vbDateTimeFormat.vbLongDate".lower()] = 1 
        self.globals["VBA.vbDateTimeFormat.vbLongTime".lower()] = 3 
        self.globals["VBA.vbDateTimeFormat.vbShortDate".lower()] = 2 
        self.globals["VBA.vbDateTimeFormat.vbShortTime".lower()] = 4 

        self.globals["vbFriday".lower()] = 6 
        self.globals["vbMonday".lower()] = 2 
        self.globals["vbSaturday".lower()] = 7 
        self.globals["vbSunday".lower()] = 1 
        self.globals["vbThursday".lower()] = 5 
        self.globals["vbTuesday".lower()] = 3 
        self.globals["vbUseSystemDayOfWeek".lower()] = 0 
        self.globals["vbWednesday".lower()] = 4 
        self.globals["VBA.vbDayOfWeek.vbFriday".lower()] = 6 
        self.globals["VBA.vbDayOfWeek.vbMonday".lower()] = 2 
        self.globals["VBA.vbDayOfWeek.vbSaturday".lower()] = 7 
        self.globals["VBA.vbDayOfWeek.vbSunday".lower()] = 1 
        self.globals["VBA.vbDayOfWeek.vbThursday".lower()] = 5 
        self.globals["VBA.vbDayOfWeek.vbTuesday".lower()] = 3 
        self.globals["VBA.vbDayOfWeek.vbUseSystemDayOfWeek".lower()] = 0 
        self.globals["VBA.vbDayOfWeek.vbWednesday".lower()] = 4

        self.globals["vbFirstFourDays".lower()] = 2 
        self.globals["vbFirstFullWeek".lower()] = 3 
        self.globals["vbFirstJan1".lower()] = 1 
        self.globals["vbUseSystem".lower()] = 0 
        self.globals["VBA.vbFirstWeekOfYear.vbFirstFourDays".lower()] = 2 
        self.globals["VBA.vbFirstWeekOfYear.vbFirstFullWeek".lower()] = 3 
        self.globals["VBA.vbFirstWeekOfYear.vbFirstJan1".lower()] = 1 
        self.globals["VBA.vbFirstWeekOfYear.vbUseSystem".lower()] = 0 

        self.globals["vbAlias".lower()] = 64 
        self.globals["vbArchive".lower()] = 32 
        self.globals["vbDirectory".lower()] = 16 
        self.globals["vbHidden".lower()] = 2 
        self.globals["vbNormal".lower()] = 0 
        self.globals["vbReadOnly".lower()] = 1 
        self.globals["vbSystem".lower()] = 4 
        self.globals["vbVolume".lower()] = 8 
        self.globals["VBA.vbFileAttribute.vbAlias".lower()] = 64 
        self.globals["VBA.vbFileAttribute.vbArchive".lower()] = 32 
        self.globals["VBA.vbFileAttribute.vbDirectory".lower()] = 16 
        self.globals["VBA.vbFileAttribute.vbHidden".lower()] = 2 
        self.globals["VBA.vbFileAttribute.vbNormal".lower()] = 0 
        self.globals["VBA.vbFileAttribute.vbReadOnly".lower()] = 1 
        self.globals["VBA.vbFileAttribute.vbSystem".lower()] = 4 
        self.globals["VBA.vbFileAttribute.vbVolume".lower()] = 8 

        self.globals["vbAbort".lower()] = 3 
        self.globals["vbCancel".lower()] = 2 
        self.globals["vbIgnore".lower()] = 5 
        self.globals["vbNo".lower()] = 7 
        self.globals["vbOK".lower()] = 1 
        self.globals["vbRetry".lower()] = 4 
        self.globals["vbYes".lower()] = 6 
        self.globals["VBA.vbMsgBoxResult.vbAbort".lower()] = 3 
        self.globals["VBA.vbMsgBoxResult.vbCancel".lower()] = 2 
        self.globals["VBA.vbMsgBoxResult.vbIgnore".lower()] = 5 
        self.globals["VBA.vbMsgBoxResult.vbNo".lower()] = 7 
        self.globals["VBA.vbMsgBoxResult.vbOK".lower()] = 1 
        self.globals["VBA.vbMsgBoxResult.vbRetry".lower()] = 4 
        self.globals["VBA.vbMsgBoxResult.vbYes".lower()] = 6 

        self.globals["vbAbortRetryIgnore".lower()] = 2 
        self.globals["vbApplicationModal".lower()] = 0 
        self.globals["vbCritical".lower()] = 16 
        self.globals["vbDefaultButton1".lower()] = 0 
        self.globals["vbDefaultButton2".lower()] = 256 
        self.globals["vbDefaultButton3".lower()] = 512 
        self.globals["vbDefaultButton4".lower()] = 768 
        self.globals["vbExclamation".lower()] = 48 
        self.globals["vbInformation".lower()] = 64 
        self.globals["vbMsgBoxHelpButton".lower()] = 16384 
        self.globals["vbMsgBoxRight".lower()] = 524288 
        self.globals["vbMsgBoxRtlReading".lower()] = 1048576 
        self.globals["vbMsgBoxSetForeground".lower()] = 65536 
        self.globals["vbOKCancel".lower()] = 1 
        self.globals["vbOKOnly".lower()] = 0 
        self.globals["vbQuestion".lower()] = 32 
        self.globals["vbRetyrCancel".lower()] = 5 
        self.globals["vbSystemModal".lower()] = 4096 
        self.globals["vbYesNo".lower()] = 4 
        self.globals["vbYesNoCancel".lower()] = 3 
        self.globals["VBA.vbMsgBoxStyle.vbAbortRetryIgnore".lower()] = 2 
        self.globals["VBA.vbMsgBoxStyle.vbApplicationModal".lower()] = 0 
        self.globals["VBA.vbMsgBoxStyle.vbCritical".lower()] = 16 
        self.globals["VBA.vbMsgBoxStyle.vbDefaultButton1".lower()] = 0 
        self.globals["VBA.vbMsgBoxStyle.vbDefaultButton2".lower()] = 256 
        self.globals["VBA.vbMsgBoxStyle.vbDefaultButton3".lower()] = 512 
        self.globals["VBA.vbMsgBoxStyle.vbDefaultButton4".lower()] = 768 
        self.globals["VBA.vbMsgBoxStyle.vbExclamation".lower()] = 48 
        self.globals["VBA.vbMsgBoxStyle.vbInformation".lower()] = 64 
        self.globals["VBA.vbMsgBoxStyle.vbMsgBoxHelpButton".lower()] = 16384 
        self.globals["VBA.vbMsgBoxStyle.vbMsgBoxRight".lower()] = 524288 
        self.globals["VBA.vbMsgBoxStyle.vbMsgBoxRtlReading".lower()] = 1048576 
        self.globals["VBA.vbMsgBoxStyle.vbMsgBoxSetForeground".lower()] = 65536 
        self.globals["VBA.vbMsgBoxStyle.vbOKCancel".lower()] = 1 
        self.globals["VBA.vbMsgBoxStyle.vbOKOnly".lower()] = 0 
        self.globals["VBA.vbMsgBoxStyle.vbQuestion".lower()] = 32 
        self.globals["VBA.vbMsgBoxStyle.vbRetyrCancel".lower()] = 5 
        self.globals["VBA.vbMsgBoxStyle.vbSystemModal".lower()] = 4096 
        self.globals["VBA.vbMsgBoxStyle.vbYesNo".lower()] = 4 
        self.globals["VBA.vbMsgBoxStyle.vbYesNoCancel".lower()] = 3 

        self.globals["vbAppTaskManager".lower()] = 3 
        self.globals["vbAppWindows".lower()] = 2 
        self.globals["vbFormCode".lower()] = 1 
        self.globals["vbFormControlMenu".lower()] = 0 
        self.globals["vbFormMDIForm".lower()] = 4 
        self.globals["VBA.vbQueryClose.vbAppTaskManager".lower()] = 3 
        self.globals["VBA.vbQueryClose.vbAppWindows".lower()] = 2 
        self.globals["VBA.vbQueryClose.vbFormCode".lower()] = 1 
        self.globals["VBA.vbQueryClose.vbFormControlMenu".lower()] = 0 
        self.globals["VBA.vbQueryClose.vbFormMDIForm".lower()] = 4

        self.globals["vbFalse".lower()] = 0 
        self.globals["vbTrue".lower()] = -1 
        self.globals["vbUseDefault".lower()] = -2 
        self.globals["VBA.vbTriState.vbFalse".lower()] = 0 
        self.globals["VBA.vbTriState.vbTrue".lower()] = -1 
        self.globals["VBA.vbTriState.vbUseDefault".lower()] = -2 

        self.globals["vbArray".lower()] = 8192 
        self.globals["vbBoolean".lower()] = 11 
        self.globals["vbByte".lower()] = 17 
        self.globals["vbCurrency".lower()] = 6 
        self.globals["vbDataObject".lower()] = 13 
        self.globals["vbDate".lower()] = 7 
        self.globals["vbDecimal".lower()] = 14 
        self.globals["vbDouble".lower()] = 5 
        self.globals["vbEmpty".lower()] = 0 
        self.globals["vbError".lower()] = 10 
        self.globals["vbInteger".lower()] = 2 
        self.globals["vbLong".lower()] = 3 
        self.globals["vbNull".lower()] = 1 
        self.globals["vbObject".lower()] = 9 
        self.globals["vbSingle".lower()] = 4 
        self.globals["vbString".lower()] = 8 
        self.globals["vbUserDefinedType".lower()] = 36 
        self.globals["vbVariant".lower()] = 12 
        self.globals["VBA.vbVarType.vbArray".lower()] = 8192 
        self.globals["VBA.vbVarType.vbBoolean".lower()] = 11 
        self.globals["VBA.vbVarType.vbByte".lower()] = 17 
        self.globals["VBA.vbVarType.vbCurrency".lower()] = 6 
        self.globals["VBA.vbVarType.vbDataObject".lower()] = 13 
        self.globals["VBA.vbVarType.vbDate".lower()] = 7 
        self.globals["VBA.vbVarType.vbDecimal".lower()] = 14 
        self.globals["VBA.vbVarType.vbDouble".lower()] = 5 
        self.globals["VBA.vbVarType.vbEmpty".lower()] = 0 
        self.globals["VBA.vbVarType.vbError".lower()] = 10 
        self.globals["VBA.vbVarType.vbInteger".lower()] = 2 
        self.globals["VBA.vbVarType.vbLong".lower()] = 3 
        self.globals["VBA.vbVarType.vbNull".lower()] = 1 
        self.globals["VBA.vbVarType.vbObject".lower()] = 9 
        self.globals["VBA.vbVarType.vbSingle".lower()] = 4 
        self.globals["VBA.vbVarType.vbString".lower()] = 8 
        self.globals["VBA.vbVarType.vbUserDefinedType".lower()] = 36 
        self.globals["VBA.vbVarType.vbVariant".lower()] = 12 

        self.globals["vbHide".lower()] = 0 
        self.globals["vbMaximizedFocus".lower()] = 3 
        self.globals["vbMinimizedFocus".lower()] = 2 
        self.globals["vbMinimizedNoFocus".lower()] = 6 
        self.globals["vbNormalFocus".lower()] = 1 
        self.globals["vbNormalNoFocus".lower()] = 4
        self.globals["VBA.vbAppWinStyle.vbHide".lower()] = 0 
        self.globals["VBA.vbAppWinStyle.vbMaximizedFocus".lower()] = 3 
        self.globals["VBA.vbAppWinStyle.vbMinimizedFocus".lower()] = 2 
        self.globals["VBA.vbAppWinStyle.vbMinimizedNoFocus".lower()] = 6 
        self.globals["VBA.vbAppWinStyle.vbNormalFocus".lower()] = 1 
        self.globals["VBA.vbAppWinStyle.vbNormalNoFocus".lower()] = 4

        self.globals["vbCalGreg".lower()] = 0 
        self.globals["vbCalHijri".lower()] = 1  
        self.globals["VBA.vbCalendar.vbCalGreg".lower()] = 0 
        self.globals["VBA.vbCalendar.vbCalHijri".lower()] = 1  

        self.globals["vbGet".lower()] = 2 
        self.globals["vbLet".lower()] = 4 
        self.globals["vbMethod".lower()] = 1 
        self.globals["vbSet".lower()] = 8
        self.globals["VBA.vbCallType.vbGet".lower()] = 2 
        self.globals["VBA.vbCallType.vbLet".lower()] = 4 
        self.globals["VBA.vbCallType.vbMethod".lower()] = 1 
        self.globals["VBA.vbCallType.vbSet".lower()] = 8

        self.globals["vbIMEAlphaDbl".lower()] = 7 
        self.globals["vbIMEAlphaSng".lower()] = 8 
        self.globals["vbIMEDisable".lower()] = 3 
        self.globals["vbIMEHiragana".lower()] = 4 
        self.globals["vbIMEKatakanaDbl".lower()] = 5 
        self.globals["vbIMEKatakanaSng".lower()] = 6 
        self.globals["vbIMEModeAlpha".lower()] = 8 
        self.globals["vbIMEModeAlphaFull".lower()] = 7 
        self.globals["vbIMEModeDisable".lower()] = 3 
        self.globals["vbIMEModeHangul".lower()] = 10 
        self.globals["vbIMEModeHangulFull".lower()] = 9 
        self.globals["vbIMEModeHiragana".lower()] = 4 
        self.globals["vbIMEModeKatakana".lower()] = 5 
        self.globals["vbIMEModeKatakanaHalf".lower()] = 6 
        self.globals["vbIMEModeNoControl".lower()] = 0 
        self.globals["vbIMEModeOff".lower()] = 2 
        self.globals["vbIMEModeOn".lower()] = 1 
        self.globals["vbIMENoOp".lower()] = 0 
        self.globals["vbIMEOff".lower()] = 2 
        self.globals["vbIMEOn".lower()] = 1 
        self.globals["VBA.vbIMEStatus.vbIMEAlphaDbl".lower()] = 7 
        self.globals["VBA.vbIMEStatus.vbIMEAlphaSng".lower()] = 8 
        self.globals["VBA.vbIMEStatus.vbIMEDisable".lower()] = 3 
        self.globals["VBA.vbIMEStatus.vbIMEHiragana".lower()] = 4 
        self.globals["VBA.vbIMEStatus.vbIMEKatakanaDbl".lower()] = 5 
        self.globals["VBA.vbIMEStatus.vbIMEKatakanaSng".lower()] = 6 
        self.globals["VBA.vbIMEStatus.vbIMEModeAlpha".lower()] = 8 
        self.globals["VBA.vbIMEStatus.vbIMEModeAlphaFull".lower()] = 7 
        self.globals["VBA.vbIMEStatus.vbIMEModeDisable".lower()] = 3 
        self.globals["VBA.vbIMEStatus.vbIMEModeHangul".lower()] = 10 
        self.globals["VBA.vbIMEStatus.vbIMEModeHangulFull".lower()] = 9 
        self.globals["VBA.vbIMEStatus.vbIMEModeHiragana".lower()] = 4 
        self.globals["VBA.vbIMEStatus.vbIMEModeKatakana".lower()] = 5 
        self.globals["VBA.vbIMEStatus.vbIMEModeKatakanaHalf".lower()] = 6 
        self.globals["VBA.vbIMEStatus.vbIMEModeNoControl".lower()] = 0 
        self.globals["VBA.vbIMEStatus.vbIMEModeOff".lower()] = 2 
        self.globals["VBA.vbIMEStatus.vbIMEModeOn".lower()] = 1 
        self.globals["VBA.vbIMEStatus.vbIMENoOp".lower()] = 0 
        self.globals["VBA.vbIMEStatus.vbIMEOff".lower()] = 2 
        self.globals["VBA.vbIMEStatus.vbIMEOn".lower()] = 1 

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
        
        # Misc.
        self.globals["ActiveDocument.Scripts.Count".lower()] = 0
        self.globals["TotalPhysicalMemory".lower()] = 2097741824
        self.globals["WSCRIPT.SCRIPTFULLNAME".lower()] = self.filename

    def add_key_macro(self,key,value):
        namespaces = ['', 'VBA.', 'KeyCodeConstants.', 'VBA.KeyCodeConstants.', 'VBA.vbStrConv.', 'vbStrConv.']
        self.add_multiple_macro(namespaces,key,value)

    def add_color_constant_macro(self,color,value):
        namespaces = ['', 'VBA.ColorConstants', 'VBA.SystemColorConstants']
        self.add_multiple_macro(namespaces,color,value)

    def add_multiple_macro(self,namespaces,key,value):
        for n in namespaces:
            self.globals[ (n+key).lower() ] = value

    def have_error(self):
        """
        See if Visual Basic threw an error.
        """
        return (hasattr(self, "got_error") and
                self.got_error)
        
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
        if (self.must_handle_error()):
            log.warning("Running On Error error handler...")
            self.error_handler.eval(context=self, params=params)
    
    def get_true_name(self, name):
        """
        Get the true name of an aliased function imported from a DLL.
        """
        if (name in self.dll_func_true_names):
            return self.dll_func_true_names[name]
        return None
        
    def open_file(self, fname):
        """
        Simulate opening a file.

        fname - The name of the file.
        """

        # Save that the file is opened.
        self.open_files[fname] = {}
        self.open_files[fname]["name"] = fname
        self.open_files[fname]["contents"] = []

    def dump_all_files(self):
        for fname in self.open_files.keys():
            self.dump_file(fname)
        
    def dump_file(self, file_id):
        """
        Save the contents of a file dumped by the VBA to disk.

        file_id - The name of the file.
        """

        # Make sure the "file" exists.
        file_id = str(file_id)
        if (file_id not in self.open_files):
            log.error("File " + file_id + " not open. Cannot save.")
            return
        
        # Get the name of the file being closed.
        name = self.open_files[file_id]["name"].replace("#", "")
        log.info("Closing file " + name)
        
        # Get the data written to the file and track it.
        data = self.open_files[file_id]["contents"]
        self.closed_files[name] = data

        # Clear the file out of the open files.
        del self.open_files[file_id]

        # Save the hash of the written file.
        raw_data = array.array('B', data).tostring()
        h = sha256()
        h.update(raw_data)
        file_hash = h.hexdigest()
        self.report_action("Dropped File Hash", file_hash, 'File Name: ' + name)

        # TODO: Set a flag to control whether to dump file contents.

        # Dump out the file.
        if (out_dir is not None):

            # Make the dropped file directory if needed.
            if (not os.path.isdir(out_dir)):
                os.makedirs(out_dir)

            # Dump the file.
            try:

                # Get a unique name for the file.
                short_name = name
                start = 0
                if ('\\' in short_name):
                    start = short_name.rindex('\\') + 1
                if ('/' in short_name):
                    start = short_name.rindex('/') + 1
                short_name = out_dir + short_name[start:].strip()
                try:
                    f = open(short_name, 'r')
                    # Already exists. Get a unique name.
                    f.close()
                    file_count += 1
                    short_name += " (" + str(file_count) + ")"
                except:
                    pass
                    
                # Write out the dropped file.
                f = open(short_name, 'wb')
                f.write(raw_data)
                f.close()
                log.info("Wrote dumped file (hash " + file_hash + ") to " + short_name + " .")
                
            except Exception as e:
                log.error("Writing file " + short_name + " failed. " + str(e))

        else:
            log.warning("File not dumped. Output dir is None.")

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
        # Unknown symbol.
        else:            
            raise KeyError('Object %r not found' % name)
            # NOTE: if name is unknown, just raise Python dict's exception
            # TODO: raise a custom VBA exception?

    def get(self, name):
        
        # See if this is an aliased reference to an objects .Text field.
        if (((name == "NodeTypedValue") or (name == ".NodeTypedValue")) and
            (not name in self.locals) and
            (".Text".lower() in self.locals)):
            return self.get(".Text")
        
        # Try to get the item using the current with context.
        tmp_name = str(self.with_prefix) + str(name)
        try:
            return self._get(tmp_name)
        except KeyError:
            pass

        # Now try it without the current with context.
        try:
            return self._get(str(name))
        except KeyError:
            pass

        # Finally see if the variable was initially defined with a trailing '$'.
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
        log.info("Looking up doc var " + var)

        # Are we pulling out all the doc vars?
        if (var == "activedocument.variables"):
            return self.doc_vars.items()
        
        if (var not in self.doc_vars):

            # Can't find a doc var with this name. See if we have an internal variable
            # with this name.
            log.debug("doc var named " + var + " not found.")
            try:
                var_value = self.get(var)
                if (var_value is not None):
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

    def set(self, name, value, var_type=None, do_with_prefix=True):

        # Does the name make sense?
        if (not isinstance(name, basestring)):
            log.debug("context.set() " + str(name) + " failed. Invalid type for name.")
            return

        # Does the value make sense?
        if (value is None):
            log.debug("context.set() " + str(name) + " failed. Value is None.")
            return
        
        # convert to lowercase
        name = name.lower()
        if name in self.locals:
            log.debug("Set local var " + str(name) + " = " + str(value))
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
                log.debug("Set global var " + name + " = " + str(value))
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
            tmp_name = str(self.with_prefix) + str(name)
            self.set(tmp_name, value, var_type=var_type, do_with_prefix=False)

        # Handle base64 conversion with VBA objects.
        if (name.endswith(".text")):

            # Is the root object something set to the "bin.base64" data type?
            node_type = name.replace(".text", ".datatype")
            try:
                val = str(self.get(node_type)).strip()
                if (val == "bin.base64"):

                    # Try converting the text from base64.
                    try:

                        # Set the typed vale of the node to the decoded value.
                        conv_val = base64.b64decode(str(value).strip())
                        val_name = name.replace(".text", ".nodetypedvalue")
                        self.set(val_name, conv_val)
                    except Exception as e:
                        log.error("base64 conversion of '" + str(value) + "' failed. " + str(e))
                        
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

        # Strip out \x00 characters if needed.
        if (strip_null_bytes):
            action = self._strip_null_bytes(action)
            params = self._strip_null_bytes(params)
            description = self._strip_null_bytes(description)

        # Save the action for reporting.
        self.engine.report_action(action, params, description)

