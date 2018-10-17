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
                 loaded_excel=None):

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
        self.globals["Application.UserName".lower()] = "--"
        
        # Add some attributes we are handling as global variables.
        self.globals["vbDirectory".lower()] = "vbDirectory"
        self.globals["vbKeyLButton".lower()] = 1
        self.globals["vbKeyRButton".lower()] = 2
        self.globals["vbKeyCancel".lower()] = 3
        self.globals["vbKeyMButton".lower()] = 4
        self.globals["vbKeyBack".lower()] = 8
        self.globals["vbKeyTab".lower()] = 9
        self.globals["vbKeyClear".lower()] = 12
        self.globals["vbKeyReturn".lower()] = 13
        self.globals["vbKeyShift".lower()] = 16
        self.globals["vbKeyControl".lower()] = 17
        self.globals["vbKeyMenu".lower()] = 18
        self.globals["vbKeyPause".lower()] = 19
        self.globals["vbKeyCapital".lower()] = 20
        self.globals["vbKeyEscape".lower()] = 27
        self.globals["vbKeySpace".lower()] = 32
        self.globals["vbKeyPageUp".lower()] = 33
        self.globals["vbKeyPageDown".lower()] = 34
        self.globals["vbKeyEnd".lower()] = 35
        self.globals["vbKeyHome".lower()] = 36
        self.globals["vbKeyLeft".lower()] = 37
        self.globals["vbKeyUp".lower()] = 38
        self.globals["vbKeyRight".lower()] = 39
        self.globals["vbKeyDown".lower()] = 40
        self.globals["vbKeySelect".lower()] = 41
        self.globals["vbKeyPrint".lower()] = 42
        self.globals["vbKeyExecute".lower()] = 43
        self.globals["vbKeySnapshot".lower()] = 44
        self.globals["vbKeyInsert".lower()] = 45
        self.globals["vbKeyDelete".lower()] = 46
        self.globals["vbKeyHelp".lower()] = 47
        self.globals["vbKeyNumlock".lower()] = 144        
        self.globals["vbKeyA".lower()] = 65
        self.globals["vbKeyB".lower()] = 66
        self.globals["vbKeyC".lower()] = 67
        self.globals["vbKeyD".lower()] = 68
        self.globals["vbKeyE".lower()] = 69
        self.globals["vbKeyF".lower()] = 70
        self.globals["vbKeyG".lower()] = 71
        self.globals["vbKeyH".lower()] = 72
        self.globals["vbKeyI".lower()] = 73
        self.globals["vbKeyJ".lower()] = 74
        self.globals["vbKeyK".lower()] = 75
        self.globals["vbKeyL".lower()] = 76
        self.globals["vbKeyM".lower()] = 77
        self.globals["vbKeyN".lower()] = 78
        self.globals["vbKeyO".lower()] = 79
        self.globals["vbKeyP".lower()] = 80
        self.globals["vbKeyQ".lower()] = 81
        self.globals["vbKeyR".lower()] = 82
        self.globals["vbKeyS".lower()] = 83
        self.globals["vbKeyT".lower()] = 84
        self.globals["vbKeyU".lower()] = 85
        self.globals["vbKeyV".lower()] = 86
        self.globals["vbKeyW".lower()] = 87
        self.globals["vbKeyX".lower()] = 88
        self.globals["vbKeyY".lower()] = 89
        self.globals["vbKeyZ".lower()] = 90
        self.globals["vbKey0".lower()] = 48
        self.globals["vbKey1".lower()] = 49
        self.globals["vbKey2".lower()] = 50
        self.globals["vbKey3".lower()] = 51
        self.globals["vbKey4".lower()] = 52
        self.globals["vbKey5".lower()] = 53
        self.globals["vbKey6".lower()] = 54
        self.globals["vbKey7".lower()] = 55
        self.globals["vbKey8".lower()] = 56
        self.globals["vbKey9".lower()] = 57
        self.globals["vbKeyNumpad0".lower()] = 96
        self.globals["vbKeyNumpad1".lower()] = 97
        self.globals["vbKeyNumpad2".lower()] = 98
        self.globals["vbKeyNumpad3".lower()] = 99
        self.globals["vbKeyNumpad4".lower()] = 100
        self.globals["vbKeyNumpad5".lower()] = 101
        self.globals["vbKeyNumpad6".lower()] = 102
        self.globals["vbKeyNumpad7".lower()] = 103
        self.globals["vbKeyNumpad8".lower()] = 104
        self.globals["vbKeyNumpad9".lower()] = 105
        self.globals["vbKeyMultiply".lower()] = 106
        self.globals["vbKeyAdd".lower()] = 107
        self.globals["vbKeySeparator".lower()] = 108
        self.globals["vbKeySubtract".lower()] = 109
        self.globals["vbKeyDecimal".lower()] = 110
        self.globals["vbKeyDivide".lower()] = 111
        self.globals["vbKeyF1".lower()] = 112
        self.globals["vbKeyF2".lower()] = 113
        self.globals["vbKeyF3".lower()] = 114
        self.globals["vbKeyF4".lower()] = 115
        self.globals["vbKeyF5".lower()] = 116
        self.globals["vbKeyF6".lower()] = 117
        self.globals["vbKeyF7".lower()] = 118
        self.globals["vbKeyF8".lower()] = 119
        self.globals["vbKeyF9".lower()] = 120
        self.globals["vbKeyF10".lower()] = 121
        self.globals["vbKeyF11".lower()] = 122
        self.globals["vbKeyF12".lower()] = 123
        self.globals["vbKeyF13".lower()] = 124
        self.globals["vbKeyF14".lower()] = 125
        self.globals["vbKeyF15".lower()] = 126
        self.globals["vbKeyF16".lower()] = 127
        self.globals["vbNullString".lower()] = ''
        self.globals["VBA.vbNullString".lower()] = ''
        self.globals["vbNullChar".lower()] = '\0'
        self.globals["VBA.vbNullChar".lower()] = '\0'

        self.globals["vbUpperCase".lower()] = 1
        self.globals["vbLowerCase".lower()] = 2
        self.globals["vbProperCase".lower()] = 3
        self.globals["vbWide".lower()] = 4
        self.globals["vbNarrow".lower()] = 8
        self.globals["vbKatakana".lower()] = 16
        self.globals["vbHiragana".lower()] = 32
        self.globals["vbUnicode".lower()] = 64
        self.globals["vbFromUnicode".lower()] = 128

        self.globals["xlOuterCenterPoint".lower()] = 2.0
        self.globals["xlPivotLineBlank".lower()] = 2
        self.globals["rgbMaroon".lower()] = 128

        self.globals["vbKeyLButton".lower()] = 0x1
        self.globals["vbKeyRButton".lower()] = 0x2
        self.globals["vbKeyCancel".lower()] = 0x3
        self.globals["vbKeyMButton".lower()] = 0x4
        self.globals["vbKeyBack".lower()] = 0x8
        self.globals["vbKeyTab".lower()] = 0x9
        self.globals["vbKeyClear".lower()] = 0xC
        self.globals["vbKeyReturn".lower()] = 0xD
        self.globals["vbKeyShift".lower()] = 0x10
        self.globals["vbKeyControl".lower()] = 0x11
        self.globals["vbKeyMenu".lower()] = 0x12
        self.globals["vbKeyPause".lower()] = 0x13
        self.globals["vbKeyCapital".lower()] = 0x14
        self.globals["vbKeyEscape".lower()] = 0x1B
        self.globals["vbKeySpace".lower()] = 0x20
        self.globals["vbKeyPageUp".lower()] = 0x21
        self.globals["vbKeyPageDown".lower()] = 0x22
        self.globals["vbKeyEnd".lower()] = 0x23
        self.globals["vbKeyHome".lower()] = 0x24
        self.globals["vbKeyLeft".lower()] = 0x25
        self.globals["vbKeyUp".lower()] = 0x26
        self.globals["vbKeyRight".lower()] = 0x27
        self.globals["vbKeyDown".lower()] = 0x28
        self.globals["vbKeySelect".lower()] = 0x29
        self.globals["vbKeyPrint".lower()] = 0x2A
        self.globals["vbKeyExecute".lower()] = 0x2B
        self.globals["vbKeySnapshot".lower()] = 0x2C
        self.globals["vbKeyInsert".lower()] = 0x2D
        self.globals["vbKeyDelete".lower()] = 0x2E
        self.globals["vbKeyHelp".lower()] = 0x2F
        self.globals["vbKeyNumlock".lower()] = 0x90

        self.globals["vbKeyA".lower()] = 65
        self.globals["vbKeyB".lower()] = 66
        self.globals["vbKeyC".lower()] = 67
        self.globals["vbKeyD".lower()] = 68
        self.globals["vbKeyE".lower()] = 69
        self.globals["vbKeyF".lower()] = 70
        self.globals["vbKeyG".lower()] = 71
        self.globals["vbKeyH".lower()] = 72
        self.globals["vbKeyI".lower()] = 73
        self.globals["vbKeyJ".lower()] = 74
        self.globals["vbKeyK".lower()] = 75
        self.globals["vbKeyL".lower()] = 76
        self.globals["vbKeyM".lower()] = 77
        self.globals["vbKeyN".lower()] = 78
        self.globals["vbKeyO".lower()] = 79
        self.globals["vbKeyP".lower()] = 80
        self.globals["vbKeyQ".lower()] = 81
        self.globals["vbKeyR".lower()] = 82
        self.globals["vbKeyS".lower()] = 83
        self.globals["vbKeyT".lower()] = 84
        self.globals["vbKeyU".lower()] = 85
        self.globals["vbKeyV".lower()] = 86
        self.globals["vbKeyW".lower()] = 87
        self.globals["vbKeyX".lower()] = 88
        self.globals["vbKeyY".lower()] = 89
        self.globals["vbKeyZ".lower()] = 90
        
        self.globals["vbKey0".lower()] = 48
        self.globals["vbKey1".lower()] = 49
        self.globals["vbKey2".lower()] = 50
        self.globals["vbKey3".lower()] = 51
        self.globals["vbKey4".lower()] = 52
        self.globals["vbKey5".lower()] = 53
        self.globals["vbKey6".lower()] = 54
        self.globals["vbKey7".lower()] = 55
        self.globals["vbKey8".lower()] = 56
        self.globals["vbKey9".lower()] = 57
        
        self.globals["vbKeyNumpad0".lower()] = 0x60
        self.globals["vbKeyNumpad1".lower()] = 0x61
        self.globals["vbKeyNumpad2".lower()] = 0x62
        self.globals["vbKeyNumpad3".lower()] = 0x63
        self.globals["vbKeyNumpad4".lower()] = 0x64
        self.globals["vbKeyNumpad5".lower()] = 0x65
        self.globals["vbKeyNumpad6".lower()] = 0x66
        self.globals["vbKeyNumpad7".lower()] = 0x67
        self.globals["vbKeyNumpad8".lower()] = 0x68
        self.globals["vbKeyNumpad9".lower()] = 0x69
        self.globals["vbKeyMultiply".lower()] = 0x6A
        self.globals["vbKeyAdd".lower()] = 0x6B
        self.globals["vbKeySeparator".lower()] = 0x6C
        self.globals["vbKeySubtract".lower()] = 0x6D
        self.globals["vbKeyDecimal".lower()] = 0x6E
        self.globals["vbKeyDivide".lower()] = 0x6F
        
        self.globals["vbKeyF1".lower()] = 0x70
        self.globals["vbKeyF2".lower()] = 0x71
        self.globals["vbKeyF3".lower()] = 0x72
        self.globals["vbKeyF4".lower()] = 0x73
        self.globals["vbKeyF5".lower()] = 0x74
        self.globals["vbKeyF6".lower()] = 0x75
        self.globals["vbKeyF7".lower()] = 0x76
        self.globals["vbKeyF8".lower()] = 0x77
        self.globals["vbKeyF9".lower()] = 0x78
        self.globals["vbKeyF10".lower()] = 0x79
        self.globals["vbKeyF11".lower()] = 0x7A
        self.globals["vbKeyF12".lower()] = 0x7B
        self.globals["vbKeyF13".lower()] = 0x7C
        self.globals["vbKeyF14".lower()] = 0x7D
        self.globals["vbKeyF15".lower()] = 0x7E
        self.globals["vbKeyF16".lower()] = 0x7F        

        self.globals["VBA.vbKeyLButton".lower()] = 0x1
        self.globals["VBA.vbKeyRButton".lower()] = 0x2
        self.globals["VBA.vbKeyCancel".lower()] = 0x3
        self.globals["VBA.vbKeyMButton".lower()] = 0x4
        self.globals["VBA.vbKeyBack".lower()] = 0x8
        self.globals["VBA.vbKeyTab".lower()] = 0x9
        self.globals["VBA.vbKeyClear".lower()] = 0xC
        self.globals["VBA.vbKeyReturn".lower()] = 0xD
        self.globals["VBA.vbKeyShift".lower()] = 0x10
        self.globals["VBA.vbKeyControl".lower()] = 0x11
        self.globals["VBA.vbKeyMenu".lower()] = 0x12
        self.globals["VBA.vbKeyPause".lower()] = 0x13
        self.globals["VBA.vbKeyCapital".lower()] = 0x14
        self.globals["VBA.vbKeyEscape".lower()] = 0x1B
        self.globals["VBA.vbKeySpace".lower()] = 0x20
        self.globals["VBA.vbKeyPageUp".lower()] = 0x21
        self.globals["VBA.vbKeyPageDown".lower()] = 0x22
        self.globals["VBA.vbKeyEnd".lower()] = 0x23
        self.globals["VBA.vbKeyHome".lower()] = 0x24
        self.globals["VBA.vbKeyLeft".lower()] = 0x25
        self.globals["VBA.vbKeyUp".lower()] = 0x26
        self.globals["VBA.vbKeyRight".lower()] = 0x27
        self.globals["VBA.vbKeyDown".lower()] = 0x28
        self.globals["VBA.vbKeySelect".lower()] = 0x29
        self.globals["VBA.vbKeyPrint".lower()] = 0x2A
        self.globals["VBA.vbKeyExecute".lower()] = 0x2B
        self.globals["VBA.vbKeySnapshot".lower()] = 0x2C
        self.globals["VBA.vbKeyInsert".lower()] = 0x2D
        self.globals["VBA.vbKeyDelete".lower()] = 0x2E
        self.globals["VBA.vbKeyHelp".lower()] = 0x2F
        self.globals["VBA.vbKeyNumlock".lower()] = 0x90

        self.globals["VBA.vbKeyA".lower()] = 65
        self.globals["VBA.vbKeyB".lower()] = 66
        self.globals["VBA.vbKeyC".lower()] = 67
        self.globals["VBA.vbKeyD".lower()] = 68
        self.globals["VBA.vbKeyE".lower()] = 69
        self.globals["VBA.vbKeyF".lower()] = 70
        self.globals["VBA.vbKeyG".lower()] = 71
        self.globals["VBA.vbKeyH".lower()] = 72
        self.globals["VBA.vbKeyI".lower()] = 73
        self.globals["VBA.vbKeyJ".lower()] = 74
        self.globals["VBA.vbKeyK".lower()] = 75
        self.globals["VBA.vbKeyL".lower()] = 76
        self.globals["VBA.vbKeyM".lower()] = 77
        self.globals["VBA.vbKeyN".lower()] = 78
        self.globals["VBA.vbKeyO".lower()] = 79
        self.globals["VBA.vbKeyP".lower()] = 80
        self.globals["VBA.vbKeyQ".lower()] = 81
        self.globals["VBA.vbKeyR".lower()] = 82
        self.globals["VBA.vbKeyS".lower()] = 83
        self.globals["VBA.vbKeyT".lower()] = 84
        self.globals["VBA.vbKeyU".lower()] = 85
        self.globals["VBA.vbKeyV".lower()] = 86
        self.globals["VBA.vbKeyW".lower()] = 87
        self.globals["VBA.vbKeyX".lower()] = 88
        self.globals["VBA.vbKeyY".lower()] = 89
        self.globals["VBA.vbKeyZ".lower()] = 90
        
        self.globals["VBA.vbKey0".lower()] = 48
        self.globals["VBA.vbKey1".lower()] = 49
        self.globals["VBA.vbKey2".lower()] = 50
        self.globals["VBA.vbKey3".lower()] = 51
        self.globals["VBA.vbKey4".lower()] = 52
        self.globals["VBA.vbKey5".lower()] = 53
        self.globals["VBA.vbKey6".lower()] = 54
        self.globals["VBA.vbKey7".lower()] = 55
        self.globals["VBA.vbKey8".lower()] = 56
        self.globals["VBA.vbKey9".lower()] = 57
        
        self.globals["VBA.vbKeyNumpad0".lower()] = 0x60
        self.globals["VBA.vbKeyNumpad1".lower()] = 0x61
        self.globals["VBA.vbKeyNumpad2".lower()] = 0x62
        self.globals["VBA.vbKeyNumpad3".lower()] = 0x63
        self.globals["VBA.vbKeyNumpad4".lower()] = 0x64
        self.globals["VBA.vbKeyNumpad5".lower()] = 0x65
        self.globals["VBA.vbKeyNumpad6".lower()] = 0x66
        self.globals["VBA.vbKeyNumpad7".lower()] = 0x67
        self.globals["VBA.vbKeyNumpad8".lower()] = 0x68
        self.globals["VBA.vbKeyNumpad9".lower()] = 0x69
        self.globals["VBA.vbKeyMultiply".lower()] = 0x6A
        self.globals["VBA.vbKeyAdd".lower()] = 0x6B
        self.globals["VBA.vbKeySeparator".lower()] = 0x6C
        self.globals["VBA.vbKeySubtract".lower()] = 0x6D
        self.globals["VBA.vbKeyDecimal".lower()] = 0x6E
        self.globals["VBA.vbKeyDivide".lower()] = 0x6F
        
        self.globals["VBA.vbKeyF1".lower()] = 0x70
        self.globals["VBA.vbKeyF2".lower()] = 0x71
        self.globals["VBA.vbKeyF3".lower()] = 0x72
        self.globals["VBA.vbKeyF4".lower()] = 0x73
        self.globals["VBA.vbKeyF5".lower()] = 0x74
        self.globals["VBA.vbKeyF6".lower()] = 0x75
        self.globals["VBA.vbKeyF7".lower()] = 0x76
        self.globals["VBA.vbKeyF8".lower()] = 0x77
        self.globals["VBA.vbKeyF9".lower()] = 0x78
        self.globals["VBA.vbKeyF10".lower()] = 0x79
        self.globals["VBA.vbKeyF11".lower()] = 0x7A
        self.globals["VBA.vbKeyF12".lower()] = 0x7B
        self.globals["VBA.vbKeyF13".lower()] = 0x7C
        self.globals["VBA.vbKeyF14".lower()] = 0x7D
        self.globals["VBA.vbKeyF15".lower()] = 0x7E
        self.globals["VBA.vbKeyF16".lower()] = 0x7F        

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
        
    def open_file(self, fname):
        """
        Simulate opening a file.

        fname - The name of the file.
        """

        # Save that the file is opened.
        self.open_files[fname] = {}
        self.open_files[fname]["name"] = fname
        self.open_files[fname]["contents"] = []
        
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
        name = self.open_files[file_id]["name"]
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
        # finally, search in the global VBA library:
        elif name in VBA_LIBRARY:
            log.debug('Found %r in VBA Library' % name)
            return VBA_LIBRARY[name]
        # Unknown symbol.
        else:            
            raise KeyError('Object %r not found' % name)
            # NOTE: if name is unknown, just raise Python dict's exception
            # TODO: raise a custom VBA exception?

    def get(self, name):

        # First try to get the item using the current with context.
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

    def contains(self, name):
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
        var = var.lower()
        log.info("Looking up doc var " + var)
        if (var not in self.doc_vars):

            # Can't find a doc var with this name. See if we have an internal variable
            # with this name.
            log.debug("doc var named " + var + " not found.")
            try:
                var_value = self.get(var)
                if (var_value is not None):
                    return self.get_doc_var(var_value)
            except KeyError:
                pass

            # Can't find it. Do we have a wild card doc var to guess for
            # this value?
            if ("*" in self.doc_vars):
                return self.doc_vars["*"]

            # No wildcard variable. Return nothing.
            return None

        # Found it.
        r = self.doc_vars[var]
        log.debug("Found doc var " + var + " = " + str(r))
        return r
            
    # TODO: set_global?

    def set(self, name, value, var_type=None, do_with_prefix=True):
        if (not isinstance(name, basestring)):
            return
        # convert to lowercase
        name = name.lower()
        if name in self.locals:
            self.locals[name] = value
        # check globals, but avoid to overwrite subs and functions:
        elif name in self.globals and not is_procedure(self.globals[name]):
            self.globals[name] = value
            log.debug("Set global var " + name + " = " + str(value))
        else:
            # new name, always stored in locals:
            self.locals[name] = value

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
            
    def report_action(self, action, params=None, description=None):
        self.engine.report_action(action, params, description)

