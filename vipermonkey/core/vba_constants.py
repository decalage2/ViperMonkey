"""
ViperMonkey: Map of many VBA constants.

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

import random

def is_constant(name):
    """
    Check to see if there is a VBA constant with the given name.
    """
    name = str(name).lower()
    return (name in all_vba_constants.globals)

def get_constant(name):
    """
    Use this to get the value of a VBA constant.
    """
    name = str(name).lower()
    if is_constant(name):
        return all_vba_constants.globals[name]
    return None

def get_type(name):
    """
    Get the data type for a VBA constant if known.
    """
    name = str(name).lower()
    if (name in all_vba_constants.types):
        return all_vba_constants.types[name]
    return None
        
class VbaConstants(object):
    """
    This contains many many many builtin VBA constant values.
    Don't create one of these objects directly. Use the get_constant() function.
    """

    def __init__(self):

        self.globals = {}
        self.types = {}
        
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
        self.globals["NoLineBreakAfter".lower()] = ""
        
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

        # WdDisableFeaturesIntroducedAfter enumeration (Word)
        #   
        # Specifies the version of Microsoft Word for which to disable all features introduced after that version.
        
        # Specifies Word for Windows 95, versions 7.0 and 7.0a.
        self.globals["wd70".lower()] = 0
        # Specifies Word for Windows 95, versions 7.0 and 7.0a, Asian edition.
        self.globals["wd70FE".lower()] = 1
        # Specifies Word 97 for Windows. Default.
        self.globals["wd80".lower()] = 2
        
        # WdEmphasisMark enumeration (Word)
        #   
        # Specifies the type of emphasis mark to use for a character or designated character string.
        
        # No emphasis mark.
        self.globals["wdEmphasisMarkNone".lower()] = 0
        # A comma.
        self.globals["wdEmphasisMarkOverComma".lower()] = 2
        # A solid black circle.
        self.globals["wdEmphasisMarkOverSolidCircle".lower()] = 1
        # An empty white circle.
        self.globals["wdEmphasisMarkOverWhiteCircle".lower()] = 3
        # A solid black circle.
        self.globals["wdEmphasisMarkUnderSolidCircle".lower()] = 4
        
        # WdUseFormattingFrom enumeration (Word)
        #   
        # Specifies a source to copy formatting from.
        
        # Copy source formatting from the current item.
        self.globals["wdFormattingFromCurrent".lower()] = 0
        # Prompt the user for formatting to use.
        self.globals["wdFormattingFromPrompt".lower()] = 2
        # Copy source formatting from the current selection.
        self.globals["wdFormattingFromSelected".lower()] = 1

        # MsoArrowheadLength Enum
        #
        # Specifies the length of the arrowhead at the end of a line.

        # Medium.
        self.globals["msoArrowheadLengthMedium".lower()] = 2	
        # Return value only; indicates a combination of the other states in the specified shape range.
        self.globals["msoArrowheadLengthMixed".lower()] = -2	
        # Long.
        self.globals["msoArrowheadLong".lower()] = 3	
        # Short
        self.globals["msoArrowheadShort".lower()] = 1	

        # MsoBalloonType Enum
        #
        # This object, member, or enumeration is deprecated and is not intended to be used in your code.

        self.globals["msoBalloonTypeBullets".lower()] = 1	
        self.globals["msoBalloonTypeButtons".lower()] = 0	
        self.globals["msoBalloonTypeNumbers".lower()] = 2	
        
        # WdLigatures enumeration (Word)
        #   
        # Specifies the type of ligatures applied to a font.
        
        # Applies all types of ligatures to the font.
        self.globals["wdLigaturesAll".lower()] = 15
        # Applies contextual ligatures to the font. Contextual ligatures are often designed to enhance readability, but may also be solely ornamental. Contextual ligatures may also be contextual alternates.
        self.globals["wdLigaturesContextual".lower()] = 2
        # Applies contextual and discretional ligatures to the font.
        self.globals["wdLigaturesContextualDiscretional".lower()] = 10
        # Applies contextual and historical ligatures to the font.
        self.globals["wdLigaturesContextualHistorical".lower()] = 6
        # Applies contextual, historical, and discretional ligatures to a font.
        self.globals["wdLigaturesContextualHistoricalDiscretional".lower()] = 14
        # Applies discretional ligatures to the font. Discretional ligatures are most often designed to be ornamental at the discretion of the type developer.
        self.globals["wdLigaturesDiscretional".lower()] = 8
        # Applies historical ligatures to the font. Historical ligatures are similar to standard ligatures in that they were originally intended to improve the readability of the font, but may look archaic to the modern reader.
        self.globals["wdLigaturesHistorical".lower()] = 4
        # Applies historical and discretional ligatures to the font.
        self.globals["wdLigaturesHistoricalDiscretional".lower()] = 12
        # Does not apply any ligatures to the font.
        self.globals["wdLigaturesNone".lower()] = 0
        # Applies standard ligatures to the font. Standard ligatures are designed to enhance readability. Standard ligatures in Latin languages include "fi", "fl", and "ff", for example.
        self.globals["wdLigaturesStandard".lower()] = 1
        # Applies standard and contextual ligatures to the font.
        self.globals["wdLigaturesStandardContextual".lower()] = 3
        # Applies standard, contextual and discretional ligatures to the font.
        self.globals["wdLigaturesStandardContextualDiscretional".lower()] = 11
        # Applies standard, contextual, and historical ligatures to the font.
        self.globals["wdLigaturesStandardContextualHistorical".lower()] = 7
        # Applies standard and discretional ligatures to the font.
        self.globals["wdLigaturesStandardDiscretional".lower()] = 9
        # Applies standard and historical ligatures to the font.
        self.globals["wdLigaturesStandardHistorical".lower()] = 5
        # Applies standard historical and discretional ligatures to the font.
        self.globals["wdLigaturesStandardHistoricalDiscretional".lower()] = 13
        
        # WdListType enumeration (Word)
        #   
        # Specifies a type of list.
        
        # Bulleted list.
        self.globals["wdListBullet".lower()] = 2
        # ListNum fields that can be used in the body of a paragraph.
        self.globals["wdListListNumOnly".lower()] = 1
        # Mixed numeric list.
        self.globals["wdListMixedNumbering".lower()] = 5
        # List with no bullets, numbering, or outlining.
        self.globals["wdListNoNumbering".lower()] = 0
        # Outlined list.
        self.globals["wdListOutlineNumbering".lower()] = 4
        # Picture bulleted list.
        self.globals["wdListPictureBullet".lower()] = 6
        # Simple numeric list.
        self.globals["wdListSimpleNumbering".lower()] = 3
        
        # WdTemplateType enumeration (Word)
        #   
        # Specifies the type of template.
        
        # An attached template.
        self.globals["wdAttachedTemplate".lower()] = 2
        # A global template.
        self.globals["wdGlobalTemplate".lower()] = 1
        # The normal default template.
        self.globals["wdNormalTemplate".lower()] = 0
        
        # WdViewType enumeration (Word)
        #   
        # Specifies the view type.
        
        # A master view.
        self.globals["wdMasterView".lower()] = 5
        # A normal view.
        self.globals["wdNormalView".lower()] = 1
        # An outline view.
        self.globals["wdOutlineView".lower()] = 2
        # A print preview view.
        self.globals["wdPrintPreview".lower()] = 4
        # A print view.
        self.globals["wdPrintView".lower()] = 3
        # A reading view.
        self.globals["wdReadingView".lower()] = 7
        # A Web view.
        self.globals["wdWebView".lower()] = 6
        
        # WdNumberForm enumeration (Word)
        #
        # Specifies the number form setting for an OpenType font.
        
        # Applies the default number form for the font.
        self.globals["wdNumberFormDefault".lower()] = 0
        # Applies the lining number form to the font.
        self.globals["wdNumberFormLining".lower()] = 1
        # Applies the "old-style" number form to the font.
        self.globals["wdNumberFormOldstyle".lower()] = 2
        
        # WdOMathFunctionType enumeration (Word)
        #   
        # Specifies the type of equation function.
        
        # Equation accent mark.
        self.globals["wdOMathFunctionAcc".lower()] = 1
        # Equation fraction bar.
        self.globals["wdOMathFunctionBar".lower()] = 2
        # Border box.
        self.globals["wdOMathFunctionBorderBox".lower()] = 4
        # Box.
        self.globals["wdOMathFunctionBox".lower()] = 3
        # Equation delimiters.
        self.globals["wdOMathFunctionDelim".lower()] = 5
        # Equation array.
        self.globals["wdOMathFunctionEqArray".lower()] = 6
        # Equation fraction.
        self.globals["wdOMathFunctionFrac".lower()] = 7
        # Equation function.
        self.globals["wdOMathFunctionFunc".lower()] = 8
        # Group character.
        self.globals["wdOMathFunctionGroupChar".lower()] = 9
        # Equation lower limit.
        self.globals["wdOMathFunctionLimLow".lower()] = 10
        # Equation upper limit.
        self.globals["wdOMathFunctionLimUpp".lower()] = 11
        # Equation matrix.
        self.globals["wdOMathFunctionMat".lower()] = 12
        # Equation N-ary operator.
        self.globals["wdOMathFunctionNary".lower()] = 13
        # Equation normal text.
        self.globals["wdOMathFunctionNormalText".lower()] = 21
        # Equation phantom.
        self.globals["wdOMathFunctionPhantom".lower()] = 14
        # Equation base expression.
        self.globals["wdOMathFunctionRad".lower()] = 16
        # Scr pre.
        self.globals["wdOMathFunctionScrPre".lower()] = 15
        # Scr. sub.
        self.globals["wdOMathFunctionScrSub".lower()] = 17
        # Scr. sub sup.
        self.globals["wdOMathFunctionScrSubSup".lower()] = 18
        # Scr sup.
        self.globals["wdOMathFunctionScrSup".lower()] = 19
        # Equation text.
        self.globals["wdOMathFunctionText".lower()] = 20
        
        # WdOMathHorizAlignType enumeration (Word)
        #   
        # Specifies the horizontal alignment for an equation.
        
        # Centered.
        self.globals["wdOMathHorizAlignCenter".lower()] = 0
        # Left alignment.
        self.globals["wdOMathHorizAlignLeft".lower()] = 1
        # Right alignment.
        self.globals["wdOMathHorizAlignRight".lower()] = 2
        
        # WdOpenFormat enumeration (Word)
        #   
        # Specifies the format to use when opening a document.
        
        # A Microsoft Word format that is backward compatible with earlier versions of Word.
        self.globals["wdOpenFormatAllWord".lower()] = 6
        # The existing format.
        self.globals["wdOpenFormatAuto".lower()] = 0
        # Word format.
        self.globals["wdOpenFormatDocument".lower()] = 1
        # Encoded text format.
        self.globals["wdOpenFormatEncodedText".lower()] = 5
        # Rich text format (RTF).
        self.globals["wdOpenFormatRTF".lower()] = 3
        # As a Word template.
        self.globals["wdOpenFormatTemplate".lower()] = 2
        # Unencoded text format.
        self.globals["wdOpenFormatText".lower()] = 4
        # (&H12)	OpenDocument Text format.
        self.globals["wdOpenFormatOpenDocumentText".lower()] = 18
        # Unicode text format.
        self.globals["wdOpenFormatUnicodeText".lower()] = 5
        # HTML format.
        self.globals["wdOpenFormatWebPages".lower()] = 7
        # XML format.
        self.globals["wdOpenFormatXML".lower()] = 8
        # Word template format.
        self.globals["wdOpenFormatAllWordTemplates".lower()] = 13
        # Microsoft Word 97 document format.
        self.globals["wdOpenFormatDocument97".lower()] = 1
        # Word 97 template format.
        self.globals["wdOpenFormatTemplate97".lower()] = 2
        # XML document format.
        self.globals["wdOpenFormatXMLDocument".lower()] = 9
        # Open XML file format saved as a single XML file.
        self.globals["wdOpenFormatXMLDocumentSerialized".lower()] = 14
        # XML document format with macros enabled.
        self.globals["wdOpenFormatXMLDocumentMacroEnabled".lower()] = 10
        # Open XML file format with macros enabled saved as a single XML file.
        self.globals["wdOpenFormatXMLDocumentMacroEnabledSerialized".lower()] = 15
        # XML template format.
        self.globals["wdOpenFormatXMLTemplate".lower()] = 11
        # (&H10)	Open XML template format saved as a XML single file.
        self.globals["wdOpenFormatXMLTemplateSerialized".lower()] = 16
        # XML template format with macros enabled.
        self.globals["wdOpenFormatXMLTemplateMacroEnabled".lower()] = 12
        # (&H11)	Open XML template format with macros enabled saved as a single XML file.
        self.globals["wdOpenFormatXMLTemplateMacroEnabledSerialized".lower()] = 17
        
        # WdPaperSize enumeration (Word)
        #   
        # Specifies a paper size.
        
        # 10 inches wide, 14 inches long.
        self.globals["wdPaper10x14".lower()] = 0
        # Legal 11 inches wide, 17 inches long.
        self.globals["wdPaper11x17".lower()] = 1
        # A3 dimensions.
        self.globals["wdPaperA3".lower()] = 6
        # A4 dimensions.
        self.globals["wdPaperA4".lower()] = 7
        # Small A4 dimensions.
        self.globals["wdPaperA4Small".lower()] = 8
        # A5 dimensions.
        self.globals["wdPaperA5".lower()] = 9
        # B4 dimensions.
        self.globals["wdPaperB4".lower()] = 10
        # B5 dimensions.
        self.globals["wdPaperB5".lower()] = 11
        # C sheet dimensions.
        self.globals["wdPaperCSheet".lower()] = 12
        # Custom paper size.
        self.globals["wdPaperCustom".lower()] = 41
        # D sheet dimensions.
        self.globals["wdPaperDSheet".lower()] = 13
        # Legal envelope, size 10.
        self.globals["wdPaperEnvelope10".lower()] = 25
        # Envelope, size 11.
        self.globals["wdPaperEnvelope11".lower()] = 26
        # Envelope, size 12.
        self.globals["wdPaperEnvelope12".lower()] = 27
        # Envelope, size 14.
        self.globals["wdPaperEnvelope14".lower()] = 28
        # Envelope, size 9.
        self.globals["wdPaperEnvelope9".lower()] = 24
        # B4 envelope.
        self.globals["wdPaperEnvelopeB4".lower()] = 29
        # B5 envelope.
        self.globals["wdPaperEnvelopeB5".lower()] = 30
        # B6 envelope.
        self.globals["wdPaperEnvelopeB6".lower()] = 31
        # C3 envelope.
        self.globals["wdPaperEnvelopeC3".lower()] = 32
        # C4 envelope.
        self.globals["wdPaperEnvelopeC4".lower()] = 33
        # C5 envelope.
        self.globals["wdPaperEnvelopeC5".lower()] = 34
        # C6 envelope.
        self.globals["wdPaperEnvelopeC6".lower()] = 35
        # C65 envelope.
        self.globals["wdPaperEnvelopeC65".lower()] = 36
        # DL envelope.
        self.globals["wdPaperEnvelopeDL".lower()] = 37
        # Italian envelope.
        self.globals["wdPaperEnvelopeItaly".lower()] = 38
        # Monarch envelope.
        self.globals["wdPaperEnvelopeMonarch".lower()] = 39
        # Personal envelope.
        self.globals["wdPaperEnvelopePersonal".lower()] = 40
        # E sheet dimensions.
        self.globals["wdPaperESheet".lower()] = 14
        # Executive dimensions.
        self.globals["wdPaperExecutive".lower()] = 5
        # German legal fanfold dimensions.
        self.globals["wdPaperFanfoldLegalGerman".lower()] = 15
        # German standard fanfold dimensions.
        self.globals["wdPaperFanfoldStdGerman".lower()] = 16
        # United States fanfold dimensions.
        self.globals["wdPaperFanfoldUS".lower()] = 17
        # Folio dimensions.
        self.globals["wdPaperFolio".lower()] = 18
        # Ledger dimensions.
        self.globals["wdPaperLedger".lower()] = 19
        # Legal dimensions.
        self.globals["wdPaperLegal".lower()] = 4
        # Letter dimensions.
        self.globals["wdPaperLetter".lower()] = 2
        # Small letter dimensions.
        self.globals["wdPaperLetterSmall".lower()] = 3
        # Note dimensions.
        self.globals["wdPaperNote".lower()] = 20
        # Quarto dimensions.
        self.globals["wdPaperQuarto".lower()] = 21
        # Statement dimensions.
        self.globals["wdPaperStatement".lower()] = 22
        # Tabloid dimensions.
        self.globals["wdPaperTabloid".lower()] = 23
        
        # WdRevisionType enumeration (Word)
        #   
        # Specifies the type of a change that is marked with a revision mark.
        
        # No revision.
        self.globals["wdNoRevision".lower()] = 0
        # Table cell deleted.
        self.globals["wdRevisionCellDeletion".lower()] = 17
        # Table cell inserted.
        self.globals["wdRevisionCellInsertion".lower()] = 16
        # Table cells merged.
        self.globals["wdRevisionCellMerge".lower()] = 18
        # This object, member, or enumeration is deprecated and is not intended to be used in your code.
        self.globals["wdRevisionCellSplit".lower()] = 19
        # Revision marked as a conflict.
        self.globals["wdRevisionConflict".lower()] = 7
        # Deletion revision conflict in a coauthored document.
        self.globals["wdRevisionConflictDelete".lower()] = 21
        # Insertion revision conflict in a coauthored document
        self.globals["wdRevisionConflictInsert".lower()] = 20
        # Deletion.
        self.globals["wdRevisionDelete".lower()] = 2
        # Field display changed.
        self.globals["wdRevisionDisplayField".lower()] = 5
        # Insertion.
        self.globals["wdRevisionInsert".lower()] = 1
        # Content moved from.
        self.globals["wdRevisionMovedFrom".lower()] = 14
        # Content moved to.
        self.globals["wdRevisionMovedTo".lower()] = 15
        # Paragraph number changed.
        self.globals["wdRevisionParagraphNumber".lower()] = 4
        # Paragraph property changed.
        self.globals["wdRevisionParagraphProperty".lower()] = 10
        # Property changed.
        self.globals["wdRevisionProperty".lower()] = 3
        # Revision marked as reconciled conflict.
        self.globals["wdRevisionReconcile".lower()] = 6
        # Replaced.
        self.globals["wdRevisionReplace".lower()] = 9
        # Section property changed.
        self.globals["wdRevisionSectionProperty".lower()] = 12
        # Style changed.
        self.globals["wdRevisionStyle".lower()] = 8
        # Style definition changed.
        self.globals["wdRevisionStyleDefinition".lower()] = 13
        # Table property changed.
        self.globals["wdRevisionTableProperty".lower()] = 11
        
        # WdBreakType enumeration (Word)
        #   
        # Specifies type of break.
        
        # Column break at the insertion point.
        self.globals["wdColumnBreak".lower()] = 8
        # Line break.
        self.globals["wdLineBreak".lower()] = 6
        # Line break.
        self.globals["wdLineBreakClearLeft".lower()] = 9
        # Line break.
        self.globals["wdLineBreakClearRight".lower()] = 10
        # Page break at the insertion point.
        self.globals["wdPageBreak".lower()] = 7
        # New section without a corresponding page break.
        self.globals["wdSectionBreakContinuous".lower()] = 3
        # Section break with the next section beginning on the next even-numbered page. If the section break falls on an even-numbered page, Word leaves the next odd-numbered page blank.
        self.globals["wdSectionBreakEvenPage".lower()] = 4
        # Section break on next page.
        self.globals["wdSectionBreakNextPage".lower()] = 2
        # Section break with the next section beginning on the next odd-numbered page. If the section break falls on an odd-numbered page, Word leaves the next even-numbered page blank.
        self.globals["wdSectionBreakOddPage".lower()] = 5
        # Ends the current line and forces the text to continue below a picture, table, or other item. The text continues on the next blank line that does not contain a table aligned with the left or right margin.
        self.globals["wdTextWrappingBreak".lower()] = 11
        
        # WdDocumentType enumeration
        #   
        # Specifies a document type.
        
        # Document.
        self.globals["wdTypeDocument".lower()] = 0
        # Frameset.
        self.globals["wdTypeFrameset".lower()] = 2
        # Template.
        self.globals["wdTypeTemplate".lower()] = 1
        
        # WdWrapSideType enumeration (Word)
        #
        # Specifies whether the document text should wrap on both sides of the specified shape, on either the left or right side only, or on the side of the shape that is farthest from the page margin.
        
        # Both sides of the specified shape.
        self.globals["wdWrapBoth".lower()] = 0
        # Side of the shape that is farthest from the page margin.
        self.globals["wdWrapLargest".lower()] = 3
        # Left side of shape only.
        self.globals["wdWrapLeft".lower()] = 1
        # Right side of shape only.
        self.globals["wdWrapRight".lower()] = 2
        
        # WdRecoveryType enumeration (Word)
        #
        # Specifies the formatting to use when pasting the selected table cells.
        
        # Pastes a Microsoft Office Excel chart as an embedded OLE object.
        self.globals["wdChart".lower()] = 14
        # Pastes an Excel chart and links it to the original Excel spreadsheet.
        self.globals["wdChartLinked".lower()] = 15
        # Pastes an Excel chart as a picture.
        self.globals["wdChartPicture".lower()] = 13
        # Preserves original formatting of the pasted material.
        self.globals["wdFormatOriginalFormatting".lower()] = 16
        # Pastes as plain, unformatted text.
        self.globals["wdFormatPlainText".lower()] = 22
        # Matches the formatting of the pasted text to the formatting of surrounding text.
        self.globals["wdFormatSurroundingFormattingWithEmphasis".lower()] = 20
        # Merges a pasted list with neighboring lists.
        self.globals["wdListCombineWithExistingList".lower()] = 24
        # Continues numbering of a pasted list from the list in the document.
        self.globals["wdListContinueNumbering".lower()] = 7
        # Not supported.
        self.globals["wdListDontMerge".lower()] = 25
        # Restarts numbering of a pasted list.
        self.globals["wdListRestartNumbering".lower()] = 8
        # Not supported.
        self.globals["wdPasteDefault".lower()] = 0
        # Pastes a single cell table as a separate table.
        self.globals["wdSingleCellTable".lower()] = 6
        # Pastes a single cell as text.
        self.globals["wdSingleCellText".lower()] = 5
        # Merges pasted cells into an existing table by inserting the pasted rows between the selected rows.
        self.globals["wdTableAppendTable".lower()] = 10
        # Inserts a pasted table as rows between two rows in the target table.
        self.globals["wdTableInsertAsRows".lower()] = 11
        # Pastes an appended table without merging table styles.
        self.globals["wdTableOriginalFormatting".lower()] = 12
        # Pastes table cells and overwrites existing table cells.
        self.globals["wdTableOverwriteCells".lower()] = 23
        # Uses the styles that are in use in the destination document.
        self.globals["wdUseDestinationStylesRecovery".lower()] = 19
        
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
        self.globals["Application.OperatingSystem".lower()] = "Windows NT"
        self.globals[".DNSHostName".lower()] = "acomputer.acompany.com"
        self.globals[".Domain".lower()] = "acompany.com"
        self.globals["wscript.network.UserName".lower()] = "humungulous"

        # WdCaptionNumberStyle enumeration (Word)
        #    
        # Specifies the number style to be used with the CaptionLabel object.
        
        #  Arabic style.
        self.globals["wdCaptionNumberStyleArabic".lower()] = 0
        #  Full-width Arabic style.
        self.globals["wdCaptionNumberStyleArabicFullWidth".lower()] = 14
        #  Arabic letter style 1.
        self.globals["wdCaptionNumberStyleArabicLetter1".lower()] = 46
        #  Arabic letter style 2.
        self.globals["wdCaptionNumberStyleArabicLetter2".lower()] = 48
        #  Chosung style.
        self.globals["wdCaptionNumberStyleChosung".lower()] = 25
        #  Ganada style.
        self.globals["wdCaptionNumberStyleGanada".lower()] = 24
        #  Hanja read style.
        self.globals["wdCaptionNumberStyleHanjaRead".lower()] = 41
        #  Hanja read digit style.
        self.globals["wdCaptionNumberStyleHanjaReadDigit".lower()] = 42
        #  Hebrew letter style 1.
        self.globals["wdCaptionNumberStyleHebrewLetter1".lower()] = 45
        #  Hebrew letter style 2.
        self.globals["wdCaptionNumberStyleHebrewLetter2".lower()] = 47
        #  Hindi Arabic style.
        self.globals["wdCaptionNumberStyleHindiArabic".lower()] = 51
        #  Hindi cardinal style.
        self.globals["wdCaptionNumberStyleHindiCardinalText".lower()] = 52
        #  Hindi letter style 1.
        self.globals["wdCaptionNumberStyleHindiLetter1".lower()] = 49
        #  Hindi letter style 2.
        self.globals["wdCaptionNumberStyleHindiLetter2".lower()] = 50
        #  Kanji style.
        self.globals["wdCaptionNumberStyleKanji".lower()] = 10
        #  Kanji digit style.
        self.globals["wdCaptionNumberStyleKanjiDigit".lower()] = 11
        #  Kanji traditional style.
        self.globals["wdCaptionNumberStyleKanjiTraditional".lower()] = 16
        #  Lowercase letter style.
        self.globals["wdCaptionNumberStyleLowercaseLetter".lower()] = 4
        #  Lowercase roman style.
        self.globals["wdCaptionNumberStyleLowercaseRoman".lower()] = 2
        #  Number in circle style.
        self.globals["wdCaptionNumberStyleNumberInCircle".lower()] = 18
        #  Simplified Chinese number style 2.
        self.globals["wdCaptionNumberStyleSimpChinNum2".lower()] = 38
        #  Simplified Chinese number style 3.
        self.globals["wdCaptionNumberStyleSimpChinNum3".lower()] = 39
        #  Thai Arabic style.
        self.globals["wdCaptionNumberStyleThaiArabic".lower()] = 54
        #  Thai cardinal text style.
        self.globals["wdCaptionNumberStyleThaiCardinalText".lower()] = 55
        #  Thai letter style.
        self.globals["wdCaptionNumberStyleThaiLetter".lower()] = 53
        #  Traditional Chinese number style 2.
        self.globals["wdCaptionNumberStyleTradChinNum2".lower()] = 34
        #  Traditional Chinese number style 3.
        self.globals["wdCaptionNumberStyleTradChinNum3".lower()] = 35
        #  Uppercase letter style.
        self.globals["wdCaptionNumberStyleUppercaseLetter".lower()] = 3
        #  Uppercase roman style.
        self.globals["wdCaptionNumberStyleUppercaseRoman".lower()] = 1
        #  Vietnamese cardinal text style.
        self.globals["wdCaptionNumberStyleVietCardinalText".lower()] = 56
        #  Zodiac style 1.
        self.globals["wdCaptionNumberStyleZodiac1".lower()] = 30
        #  Zodiac style 2.
        self.globals["wdCaptionNumberStyleZodiac2".lower()] = 31
        
        # WdPartOfSpeech enumeration (Word)
        #   
        # Specifies the part of speech that a word represents when returned by the Word thesaurus service.
        
        #  An adjective.
        self.globals["wdAdjective".lower()] = 0
        #  An adverb.
        self.globals["wdAdverb".lower()] = 2
        #  A conjunction.
        self.globals["wdConjunction".lower()] = 5
        #  An idiom.
        self.globals["wdIdiom".lower()] = 8
        #  An interjection.
        self.globals["wdInterjection".lower()] = 7
        #  A noun.
        self.globals["wdNoun".lower()] = 1
        #  Some other part of speech.
        self.globals["wdOther".lower()] = 9
        #  A preposition.
        self.globals["wdPreposition".lower()] = 6
        #  A pronoun.
        self.globals["wdPronoun".lower()] = 4
        #  A verb.
        self.globals["wdVerb".lower()] = 3
        
        # WdCursorType enumeration (Word)
        #   
        # Specifies the state (shape) of the cursor.
        
        #  I-beam cursor shape.
        self.globals["wdCursorIBeam".lower()] = 1
        #  Normal cursor shape. Default; cursor takes shape designated by Windows or the application.
        self.globals["wdCursorNormal".lower()] = 2
        self.types["wdCursorNormal".lower()] = "Integer"
        #  Diagonal cursor shape starting at upper-left corner.
        self.globals["wdCursorNorthwestArrow".lower()] = 3
        #  Hourglass cursor shape.
        self.globals["wdCursorWait".lower()] = 0
        
        # WdConstants enumeration (Word)
        #    
        # This enumeration groups together constants used with various Microsoft Word methods.
        
        #  Represents the Auto value for the specified setting.
        self.globals["wdAutoPosition".lower()] = 0
        #  Indicates that selection will be extended backward using the MoveStartUntil or MoveStartWhile method of the Range or Selection object.
        self.globals["wdBackward".lower()] = -1073741823
        #  Represents the creator code for objects created by Microsoft Word.
        self.globals["wdCreatorCode".lower()] = 1297307460
        #  Represents the first item in a collection.
        self.globals["wdFirst".lower()] = 1
        #  Indicates that selection will be extended forward using the MoveStartUntil or MoveStartWhile method of the Range or Selection object.
        self.globals["wdForward".lower()] = 1073741823
        #  Toggles a property's value.
        self.globals["wdToggle".lower()] = 9999998
        #  Represents an undefined value.
        self.globals["wdUndefined".lower()] = 9999999
        
        # WdFramesetNewFrameLocation enumeration (Word)
        #   
        # Specifies the position of a new frame in relation to an existing frame.
        
        #  Above existing frame.
        self.globals["wdFramesetNewFrameAbove".lower()] = 0
        #  Below existing frame.
        self.globals["wdFramesetNewFrameBelow".lower()] = 1
        #  To the left of existing frame.
        self.globals["wdFramesetNewFrameLeft".lower()] = 3
        #  To the right of existing frame.
        self.globals["wdFramesetNewFrameRight".lower()] = 2
        
        # WdIndexSortBy enumeration (Word)
        #
        # Specifies the criteria by which Word sorts the specified index.
        
        #  Sort by the number of strokes in a character.
        self.globals["wdIndexSortByStroke".lower()] = 0
        #  Sort phonetically.
        self.globals["wdIndexSortBySyllable".lower()] = 1
        
        # WdIndexFormat enumeration (Word)
        #   
        # Specifies the formatting for indexes in a document.
        
        #  Bulleted.
        self.globals["wdIndexBulleted".lower()] = 4
        #  Classic.
        self.globals["wdIndexClassic".lower()] = 1
        #  Fancy.
        self.globals["wdIndexFancy".lower()] = 2
        #  Formal.
        self.globals["wdIndexFormal".lower()] = 5
        #  Modern.
        self.globals["wdIndexModern".lower()] = 3
        #  Simple.
        self.globals["wdIndexSimple".lower()] = 6
        #  From template.
        self.globals["wdIndexTemplate".lower()] = 0
        
        # WdOLEPlacement enumeration (Word)
        #   
        # Specifies the placement for an OLE object.
        
        #  Float over text.
        self.globals["wdFloatOverText".lower()] = 1
        #  In line with text.
        self.globals["wdInLine".lower()] = 0
        
        # WdPasteOptions enumeration (Word)
        #   
        # Indicates how to paste copied text.
        
        #  Keeps formatting from the source document.
        self.globals["wdKeepSourceFormatting".lower()] = 0
        #  Keeps text only, without formatting.
        self.globals["wdKeepTextOnly".lower()] = 2
        #  Matches formatting to the destination document.
        self.globals["wdMatchDestinationFormatting".lower()] = 1
        #  Matches formatting to the destination document using styles for formatting.
        self.globals["wdUseDestinationStyles".lower()] = 3
        
        # WdSpecialPane enumeration (Word)
        #   
        # Specifies an item to display in the active window pane.
        
        #  Selected comments.
        self.globals["wdPaneComments".lower()] = 15
        #  The page footer.
        self.globals["wdPaneCurrentPageFooter".lower()] = 17
        #  The page header.
        self.globals["wdPaneCurrentPageHeader".lower()] = 16
        #  The endnote continuation notice.
        self.globals["wdPaneEndnoteContinuationNotice".lower()] = 12
        #  The endnote continuation separator.
        self.globals["wdPaneEndnoteContinuationSeparator".lower()] = 13
        #  Endnotes.
        self.globals["wdPaneEndnotes".lower()] = 8
        #  The endnote separator.
        self.globals["wdPaneEndnoteSeparator".lower()] = 14
        #  The even pages footer.
        self.globals["wdPaneEvenPagesFooter".lower()] = 6
        #  The even pages header.
        self.globals["wdPaneEvenPagesHeader".lower()] = 3
        #  The first page footer.
        self.globals["wdPaneFirstPageFooter".lower()] = 5
        #  The first page header.
        self.globals["wdPaneFirstPageHeader".lower()] = 2
        #  The footnote continuation notice.
        self.globals["wdPaneFootnoteContinuationNotice".lower()] = 9
        #  The footnote continuation separator.
        self.globals["wdPaneFootnoteContinuationSeparator".lower()] = 10
        #  Footnotes.
        self.globals["wdPaneFootnotes".lower()] = 7
        #  The footnote separator.
        self.globals["wdPaneFootnoteSeparator".lower()] = 11
        #  No display.
        self.globals["wdPaneNone".lower()] = 0
        #  The primary footer pane.
        self.globals["wdPanePrimaryFooter".lower()] = 4
        #  The primary header pane.
        self.globals["wdPanePrimaryHeader".lower()] = 1
        #  The revisions pane.
        self.globals["wdPaneRevisions".lower()] = 18
        #  The revisions pane displays along the bottom of the document window.
        self.globals["wdPaneRevisionsHoriz".lower()] = 19
        #  The revisions pane displays along the left side of the document window.
        self.globals["wdPaneRevisionsVert".lower()] = 20
        
        # WdBuiltInProperty enumeration (Word)
        #   
        # Specifies a built-in document property.
        
        #  Name of application.
        self.globals["wdPropertyAppName".lower()] = 9
        #  Author.
        self.globals["wdPropertyAuthor".lower()] = 3
        #  Byte count.
        self.globals["wdPropertyBytes".lower()] = 22
        #  Category.
        self.globals["wdPropertyCategory".lower()] = 18
        #  Character count.
        self.globals["wdPropertyCharacters".lower()] = 16
        #  Character count with spaces.
        self.globals["wdPropertyCharsWSpaces".lower()] = 30
        #  Comments.
        self.globals["wdPropertyComments".lower()] = 5
        #  Company.
        self.globals["wdPropertyCompany".lower()] = 21
        #  Not supported.
        self.globals["wdPropertyFormat".lower()] = 19
        #  Not supported.
        self.globals["wdPropertyHiddenSlides".lower()] = 27
        #  Not supported.
        self.globals["wdPropertyHyperlinkBase".lower()] = 29
        #  Keywords.
        self.globals["wdPropertyKeywords".lower()] = 4
        #  Last author.
        self.globals["wdPropertyLastAuthor".lower()] = 7
        #  Line count.
        self.globals["wdPropertyLines".lower()] = 23
        #  Manager.
        self.globals["wdPropertyManager".lower()] = 20
        #  Not supported.
        self.globals["wdPropertyMMClips".lower()] = 28
        #  Notes.
        self.globals["wdPropertyNotes".lower()] = 26
        #  Page count.
        self.globals["wdPropertyPages".lower()] = 14
        #  Paragraph count.
        self.globals["wdPropertyParas".lower()] = 24
        #  Revision number.
        self.globals["wdPropertyRevision".lower()] = 8
        #  Security setting.
        self.globals["wdPropertySecurity".lower()] = 17
        #  Not supported.
        self.globals["wdPropertySlides".lower()] = 25
        #  Subject.
        self.globals["wdPropertySubject".lower()] = 2
        #  Template name.
        self.globals["wdPropertyTemplate".lower()] = 6
        #  Time created.
        self.globals["wdPropertyTimeCreated".lower()] = 11
        #  Time last printed.
        self.globals["wdPropertyTimeLastPrinted".lower()] = 10
        #  Time last saved.
        self.globals["wdPropertyTimeLastSaved".lower()] = 12
        #  Title.
        self.globals["wdPropertyTitle".lower()] = 1
        #  Number of edits to VBA project.
        self.globals["wdPropertyVBATotalEdit".lower()] = 13
        #  Word count.
        self.globals["wdPropertyWords".lower()] = 15
        
        # WdRelativeHorizontalSize enumeration (Word)
        #    
        # Specifies the relative width of a shape using the value specified in the WidthRelative property for a Shape or ShapeRange object.
        
        #  Width is relative to the size of the inside margin; to the size of the left margin for odd pages, and to the size of the right margin for even pages.
        self.globals["wdRelativeHorizontalSizeInnerMarginArea".lower()] = 4
        #  Width is relative to the size of the left margin.
        self.globals["wdRelativeHorizontalSizeLeftMarginArea".lower()] = 2
        #  Width is relative to the space between the left margin and the right margin.
        self.globals["wdRelativeHorizontalSizeMargin".lower()] = 0
        #  Width is relative to the size of the outside margin; to the size of the right margin for odd pages, and to the size of the left margin for even pages.
        self.globals["wdRelativeHorizontalSizeOuterMarginArea".lower()] = 5
        #  Width is relative to the width of the page.
        self.globals["wdRelativeHorizontalSizePage".lower()] = 1
        #  Width is relative to the width of the right margin.
        self.globals["wdRelativeHorizontalSizeRightMarginArea".lower()] = 3
        
        # WdReplace enumeration (Word)
        #   
        # Specifies the number of replacements to be made when find and replace is used.
        
        #  Replace all occurrences.
        self.globals["wdReplaceAll".lower()] = 2
        #  Replace no occurrences.
        self.globals["wdReplaceNone".lower()] = 0
        #  Replace the first occurrence encountered.
        self.globals["wdReplaceOne".lower()] = 1
        
        # WdSeekView enumeration (Word)
        #   
        # Specifies the document element to display in the print layout view.
        
        #  The current page footer.
        self.globals["wdSeekCurrentPageFooter".lower()] = 10
        #  The current page header.
        self.globals["wdSeekCurrentPageHeader".lower()] = 9
        #  Endnotes.
        self.globals["wdSeekEndnotes".lower()] = 8
        #  The even pages footer.
        self.globals["wdSeekEvenPagesFooter".lower()] = 6
        #  The even pages header.
        self.globals["wdSeekEvenPagesHeader".lower()] = 3
        #  The first page footer.
        self.globals["wdSeekFirstPageFooter".lower()] = 5
        #  The first page header.
        self.globals["wdSeekFirstPageHeader".lower()] = 2
        #  Footnotes.
        self.globals["wdSeekFootnotes".lower()] = 7
        #  The main document.
        self.globals["wdSeekMainDocument".lower()] = 0
        #  The primary footer.
        self.globals["wdSeekPrimaryFooter".lower()] = 4
        #  The primary header.
        self.globals["wdSeekPrimaryHeader".lower()] = 1
        
        # WdMailMergeDestination enumeration (Word)
        #   
        # Specifies a destination for mail merge results.
        
        #  Send results to email recipient.
        self.globals["wdSendToEmail".lower()] = 2
        #  Send results to fax recipient.
        self.globals["wdSendToFax".lower()] = 3
        #  Send results to a new Word document.
        self.globals["wdSendToNewDocument".lower()] = 0
        #  Send results to a printer.
        self.globals["wdSendToPrinter".lower()] = 1
        
        # WdBuildingBlockTypes enumeration (Word)
        #    
        # Specifies the type of building block.
        
        #  Autotext building block.
        self.globals["wdTypeAutoText".lower()] = 9
        #  Bibliography building block.
        self.globals["wdTypeBibliography".lower()] = 34
        #  Cover page building block.
        self.globals["wdTypeCoverPage".lower()] = 2
        #  Custom building block.
        self.globals["wdTypeCustom1".lower()] = 29
        #  Custom building block.
        self.globals["wdTypeCustom2".lower()] = 30
        #  Custom building block.
        self.globals["wdTypeCustom3".lower()] = 31
        #  Custom building block.
        self.globals["wdTypeCustom4".lower()] = 32
        #  Custom building block.
        self.globals["wdTypeCustom5".lower()] = 33
        #  Custom autotext building block.
        self.globals["wdTypeCustomAutoText".lower()] = 23
        #  Custom bibliography building block.
        self.globals["wdTypeCustomBibliography".lower()] = 35
        #  Custom cover page building block.
        self.globals["wdTypeCustomCoverPage".lower()] = 16
        #  Custom equations building block.
        self.globals["wdTypeCustomEquations".lower()] = 17
        #  Custom footers building block.
        self.globals["wdTypeCustomFooters".lower()] = 18
        #  Custom headers building block.
        self.globals["wdTypeCustomHeaders".lower()] = 19
        #  Custom page numbering building block.
        self.globals["wdTypeCustomPageNumber".lower()] = 20
        #  Building block for custom page numbering on the bottom of the page.
        self.globals["wdTypeCustomPageNumberBottom".lower()] = 26
        #  Custom page numbering building block.
        self.globals["wdTypeCustomPageNumberPage".lower()] = 27
        #  Building block for custom page numbering on the top of the page.
        self.globals["wdTypeCustomPageNumberTop".lower()] = 25
        #  Custom quick parts building block.
        self.globals["wdTypeCustomQuickParts".lower()] = 15
        #  Custom table of contents building block.
        self.globals["wdTypeCustomTableOfContents".lower()] = 28
        #  Custom table building block.
        self.globals["wdTypeCustomTables".lower()] = 21
        #  Custom text box building block.
        self.globals["wdTypeCustomTextBox".lower()] = 24
        #  Custom watermark building block.
        self.globals["wdTypeCustomWatermarks".lower()] = 22
        #  Equation building block.
        self.globals["wdTypeEquations".lower()] = 3
        #  Footer building block.
        self.globals["wdTypeFooters".lower()] = 4
        #  Header building block.
        self.globals["wdTypeHeaders".lower()] = 5
        #  Page numbering building block.
        self.globals["wdTypePageNumber".lower()] = 6
        #  Building block for page numbering on the bottom of the page.
        self.globals["wdTypePageNumberBottom".lower()] = 12
        #  Page numbering building block.
        self.globals["wdTypePageNumberPage".lower()] = 13
        #  Building block for page numbering on the top of the page.
        self.globals["wdTypePageNumberTop".lower()] = 11
        #  Quick parts building block.
        self.globals["wdTypeQuickParts".lower()] = 1
        #  Table of contents building block.
        self.globals["wdTypeTableOfContents".lower()] = 14
        #  Table building block.
        self.globals["wdTypeTables".lower()] = 7
        #  Text box building block.
        self.globals["wdTypeTextBox".lower()] = 10
        #  Watermark building block.
        self.globals["wdTypeWatermarks".lower()] = 8
        
        # WdBuiltinStyle Enum
        #
        # Specifies a built-in Microsoft Word style.
        
        # Bibliography.
        self.globals["wdStyleBibliography".lower()] = -266
        # Block Quotation.
        self.globals["wdStyleBlockQuotation".lower()] = -85
        # Body Text.
        self.globals["wdStyleBodyText".lower()] = -67
        # Body Text 2.
        self.globals["wdStyleBodyText2".lower()] = -81
        # Body Text 3.
        self.globals["wdStyleBodyText3".lower()] = -82
        # Body Text First Indent.
        self.globals["wdStyleBodyTextFirstIndent".lower()] = -78
        # Body Text First Indent 2.
        self.globals["wdStyleBodyTextFirstIndent2".lower()] = -79
        # Body Text Indent.
        self.globals["wdStyleBodyTextIndent".lower()] = -68
        # Body Text Indent 2.
        self.globals["wdStyleBodyTextIndent2".lower()] = -83
        # Body Text Indent 3.
        self.globals["wdStyleBodyTextIndent3".lower()] = -84
        # Book title.
        self.globals["wdStyleBookTitle".lower()] = -265
        # Caption.
        self.globals["wdStyleCaption".lower()] = -35
        # Closing.
        self.globals["wdStyleClosing".lower()] = -64
        # Comment Reference.
        self.globals["wdStyleCommentReference".lower()] = -40
        # Comment Text.
        self.globals["wdStyleCommentText".lower()] = -31
        # Date.
        self.globals["wdStyleDate".lower()] = -77
        # Default Paragraph Font.
        self.globals["wdStyleDefaultParagraphFont".lower()] = -66
        # Emphasis.
        self.globals["wdStyleEmphasis".lower()] = -89
        # Endnote Reference.
        self.globals["wdStyleEndnoteReference".lower()] = -43
        # Endnote Text.
        self.globals["wdStyleEndnoteText".lower()] = -44
        # Envelope Address.
        self.globals["wdStyleEnvelopeAddress".lower()] = -37
        # Envelope Return.
        self.globals["wdStyleEnvelopeReturn".lower()] = -38
        # Footer.
        self.globals["wdStyleFooter".lower()] = -33
        # Footnote Reference.
        self.globals["wdStyleFootnoteReference".lower()] = -39
        # Footnote Text.
        self.globals["wdStyleFootnoteText".lower()] = -30
        # Header.
        self.globals["wdStyleHeader".lower()] = -32
        # Heading 1.
        self.globals["wdStyleHeading1".lower()] = -2
        # Heading 2.
        self.globals["wdStyleHeading2".lower()] = -3
        # Heading 3.
        self.globals["wdStyleHeading3".lower()] = -4
        # Heading 4.
        self.globals["wdStyleHeading4".lower()] = -5
        # Heading 5.
        self.globals["wdStyleHeading5".lower()] = -6
        # Heading 6.
        self.globals["wdStyleHeading6".lower()] = -7
        # Heading 7.
        self.globals["wdStyleHeading7".lower()] = -8
        # Heading 8.
        self.globals["wdStyleHeading8".lower()] = -9
        # Heading 9.
        self.globals["wdStyleHeading9".lower()] = -10
        # HTML Acronym.
        self.globals["wdStyleHtmlAcronym".lower()] = -96
        # HTML Address.
        self.globals["wdStyleHtmlAddress".lower()] = -97
        # HTML City.
        self.globals["wdStyleHtmlCite".lower()] = -98
        # HTML Code.
        self.globals["wdStyleHtmlCode".lower()] = -99
        # HTML Definition.
        self.globals["wdStyleHtmlDfn".lower()] = -100
        # HTML Keyboard.
        self.globals["wdStyleHtmlKbd".lower()] = -101
        # Normal (Web).
        self.globals["wdStyleHtmlNormal".lower()] = -95
        # HTML Preformatted.
        self.globals["wdStyleHtmlPre".lower()] = -102
        # HTML Sample.
        self.globals["wdStyleHtmlSamp".lower()] = -103
        # HTML Typewriter.
        self.globals["wdStyleHtmlTt".lower()] = -104
        # HTML Variable.
        self.globals["wdStyleHtmlVar".lower()] = -105
        # Hyperlink.
        self.globals["wdStyleHyperlink".lower()] = -86
        # Followed Hyperlink.
        self.globals["wdStyleHyperlinkFollowed".lower()] = -87
        # Index 1.
        self.globals["wdStyleIndex1".lower()] = -11
        # Index 2.
        self.globals["wdStyleIndex2".lower()] = -12
        # Index 3.
        self.globals["wdStyleIndex3".lower()] = -13
        # Index 4.
        self.globals["wdStyleIndex4".lower()] = -14
        # Index 5.
        self.globals["wdStyleIndex5".lower()] = -15
        # Index 6.
        self.globals["wdStyleIndex6".lower()] = -16
        # Index 7.
        self.globals["wdStyleIndex7".lower()] = -17
        # Index8.
        self.globals["wdStyleIndex8".lower()] = -18
        # Index 9.
        self.globals["wdStyleIndex9".lower()] = -19
        # Index Heading
        self.globals["wdStyleIndexHeading".lower()] = -34
        # Intense Emphasis.
        self.globals["wdStyleIntenseEmphasis".lower()] = -262
        # Intense Quote.
        self.globals["wdStyleIntenseQuote".lower()] = -182
        # Intense Reference.
        self.globals["wdStyleIntenseReference".lower()] = -264
        # Line Number.
        self.globals["wdStyleLineNumber".lower()] = -41
        # List.
        self.globals["wdStyleList".lower()] = -48
        # List 2.
        self.globals["wdStyleList2".lower()] = -51
        # List 3.
        self.globals["wdStyleList3".lower()] = -52
        # List 4.
        self.globals["wdStyleList4".lower()] = -53
        # List 5.
        self.globals["wdStyleList5".lower()] = -54
        # List Bullet.
        self.globals["wdStyleListBullet".lower()] = -49
        # List Bullet 2.
        self.globals["wdStyleListBullet2".lower()] = -55
        # List Bullet 3.
        self.globals["wdStyleListBullet3".lower()] = -56
        # List Bullet 4.
        self.globals["wdStyleListBullet4".lower()] = -57
        # List Bullet 5.
        self.globals["wdStyleListBullet5".lower()] = -58
        # List Continue.
        self.globals["wdStyleListContinue".lower()] = -69
        # List Continue 2.
        self.globals["wdStyleListContinue2".lower()] = -70
        # List Continue 3.
        self.globals["wdStyleListContinue3".lower()] = -71
        # List Continue 4.
        self.globals["wdStyleListContinue4".lower()] = -72
        # List Continue 5.
        self.globals["wdStyleListContinue5".lower()] = -73
        # List Number.
        self.globals["wdStyleListNumber".lower()] = -50
        # List Number 2.
        self.globals["wdStyleListNumber2".lower()] = -59
        # List Number 3.
        self.globals["wdStyleListNumber3".lower()] = -60
        # List Number 4.
        self.globals["wdStyleListNumber4".lower()] = -61
        # List Number 5.
        self.globals["wdStyleListNumber5".lower()] = -62
        # List Paragraph.
        self.globals["wdStyleListParagraph".lower()] = -180
        # Macro Text.
        self.globals["wdStyleMacroText".lower()] = -46
        # Message Header.
        self.globals["wdStyleMessageHeader".lower()] = -74
        # Document Map.
        self.globals["wdStyleNavPane".lower()] = -90
        # Normal.
        self.globals["wdStyleNormal".lower()] = -1
        # Normal Indent.
        self.globals["wdStyleNormalIndent".lower()] = -29
        # Normal (applied to an object).
        self.globals["wdStyleNormalObject".lower()] = -158
        # Normal (applied within a table).
        self.globals["wdStyleNormalTable".lower()] = -106
        # Note Heading.
        self.globals["wdStyleNoteHeading".lower()] = -80
        # Page Number.
        self.globals["wdStylePageNumber".lower()] = -42
        # Plain Text.
        self.globals["wdStylePlainText".lower()] = -91
        # Quote.
        self.globals["wdStyleQuote".lower()] = -181
        # Salutation.
        self.globals["wdStyleSalutation".lower()] = -76
        # Signature.
        self.globals["wdStyleSignature".lower()] = -65
        # Strong.
        self.globals["wdStyleStrong".lower()] = -88
        # Subtitle.
        self.globals["wdStyleSubtitle".lower()] = -75
        # Subtle Emphasis.
        self.globals["wdStyleSubtleEmphasis".lower()] = -261
        # Subtle Reference.
        self.globals["wdStyleSubtleReference".lower()] = -263
        # Colorful Grid.
        self.globals["wdStyleTableColorfulGrid".lower()] = -172
        # Colorful List.
        self.globals["wdStyleTableColorfulList".lower()] = -171
        # Colorful Shading.
        self.globals["wdStyleTableColorfulShading".lower()] = -170
        # Dark List.
        self.globals["wdStyleTableDarkList".lower()] = -169
        # Light Grid.
        self.globals["wdStyleTableLightGrid".lower()] = -161
        # Light Grid Accent 1.
        self.globals["wdStyleTableLightGridAccent1".lower()] = -175
        # Light List.
        self.globals["wdStyleTableLightList".lower()] = -160
        # Light List Accent 1.
        self.globals["wdStyleTableLightListAccent1".lower()] = -174
        # Light Shading.
        self.globals["wdStyleTableLightShading".lower()] = -159
        # Light Shading Accent 1.
        self.globals["wdStyleTableLightShadingAccent1".lower()] = -173
        # Medium Grid 1.
        self.globals["wdStyleTableMediumGrid1".lower()] = -166
        # Medium Grid 2.
        self.globals["wdStyleTableMediumGrid2".lower()] = -167
        # Medium Grid 3.
        self.globals["wdStyleTableMediumGrid3".lower()] = -168
        # Medium List 1.
        self.globals["wdStyleTableMediumList1".lower()] = -164
        # Medium List 1 Accent 1.
        self.globals["wdStyleTableMediumList1Accent1".lower()] = -178
        # Medium List 2.
        self.globals["wdStyleTableMediumList2".lower()] = -165
        # Medium Shading 1.
        self.globals["wdStyleTableMediumShading1".lower()] = -162
        # Medium List 1 Accent 1.
        self.globals["wdStyleTableMediumShading1Accent1".lower()] = -176
        # Medium Shading 2.
        self.globals["wdStyleTableMediumShading2".lower()] = -163
        # Medium Shading 2 Accent 1.
        self.globals["wdStyleTableMediumShading2Accent1".lower()] = -177
        # Table of Authorities.
        self.globals["wdStyleTableOfAuthorities".lower()] = -45
        # Table of Figures.
        self.globals["wdStyleTableOfFigures".lower()] = -36
        # Title.
        self.globals["wdStyleTitle".lower()] = -63
        # TOA Heading.
        self.globals["wdStyleTOAHeading".lower()] = -47
        # TOC 1.
        self.globals["wdStyleTOC1".lower()] = -20
        # TOC 2.
        self.globals["wdStyleTOC2".lower()] = -21
        # TOC 3.
        self.globals["wdStyleTOC3".lower()] = -22
        # TOC 4.
        self.globals["wdStyleTOC4".lower()] = -23
        # TOC 5.
        self.globals["wdStyleTOC5".lower()] = -24
        # TOC 6.
        self.globals["wdStyleTOC6".lower()] = -25
        # TOC 7.
        self.globals["wdStyleTOC7".lower()] = -26
        # TOC 8.
        self.globals["wdStyleTOC8".lower()] = -27
        # TOC 9.
        self.globals["wdStyleTOC9".lower()] = -28
        # TOC Heading.
        self.globals["wdStyleTocHeading".lower()] = -267
        
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

        # MsoColorType enumeration (Office)
        #
        # Specifies the color type.
        #
        # Color Management System color type.
        self.globals["msoColorTypeCMS".lower()] = 4
        # Color is determined by values of cyan, magenta, yellow, and black.
        self.globals["msoColorTypeCMYK".lower()] = 3
        # Not supported.
        self.globals["msoColorTypeInk".lower()] = 5
        # Not supported.
        self.globals["msoColorTypeMixed".lower()] = -2
        # Color is determined by values of red, green, and blue.
        self.globals["msoColorTypeRGB".lower()] = 1
        # Color is defined by an application-specific scheme.
        self.globals["msoColorTypeScheme".lower()] = 2

        # MsoTextUnderlineType enumeration (Office)
        #
        # Indicates the type of underline for text.
        #
        # Specifies no underline.
        self.globals["msoNoUnderline".lower()] = 0
        # Specifies a dash underline.
        self.globals["msoUnderlineDashHeavyLine".lower()] = 8
        # Specifies a dash line underline.
        self.globals["msoUnderlineDashLine".lower()] = 7
        # Specifies a long heavy line underline.
        self.globals["msoUnderlineDashLongHeavyLine".lower()] = 10
        # Specifies a dashed long line underline.
        self.globals["msoUnderlineDashLongLine".lower()] = 9
        # Specifies a dot dash heavy line underline.
        self.globals["msoUnderlineDotDashHeavyLine".lower()] = 12
        # Specifies a dot dash line underline.
        self.globals["msoUnderlineDotDashLine".lower()] = 11
        # Specifies a dot dot dash heavy line underline.
        self.globals["msoUnderlineDotDotDashHeavyLine".lower()] = 14
        # Specifies a dot dot dash line underline.
        self.globals["msoUnderlineDotDotDashLine".lower()] = 13
        # Specifies a dotted heavy line underline.
        self.globals["msoUnderlineDottedHeavyLine".lower()] = 6
        # Specifies a dotted line underline.
        self.globals["msoUnderlineDottedLine".lower()] = 5
        # Specifies a double line underline.
        self.globals["msoUnderlineDoubleLine".lower()] = 3
        # Specifies a heavy line underline.
        self.globals["msoUnderlineHeavyLine".lower()] = 4
        # Specifies a mixed of underline types.
        self.globals["msoUnderlineMixed".lower()] = -2
        # Specifies a single line underline.
        self.globals["msoUnderlineSingleLine".lower()] = 2
        # Specifies a wavy double line underline.
        self.globals["msoUnderlineWavyDoubleLine".lower()] = 17
        # Specifies a wavy heavy line underline.
        self.globals["msoUnderlineWavyHeavyLine".lower()] = 16
        # Specifies a wavy line underline.
        self.globals["msoUnderlineWavyLine".lower()] = 15
        # Specifies underlining words.
        self.globals["msoUnderlineWords".lower()] = 1
        
        # MsoContactCardAddressType Enum        
        self.globals["msoContactCardAddressTypeIM".lower()] = 3
        self.globals["msoContactCardAddressTypeOutlook".lower()] = 1
        self.globals["msoContactCardAddressTypeSMTP".lower()] = 2
        self.globals["msoContactCardAddressTypeUnknown".lower()] = 0

        # MsoContactCardStyle Enum
        self.globals["msoContactCardFull".lower()] = 1
        self.globals["msoContactCardHover".lower()] = 0
        
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

        # WdMailMergeActiveRecord enumeration (Word)
        #
        # Specifies the active record in a mail merge result set.
        
        # The first record in the data source.
        self.globals["wdFirstDataSourceRecord".lower()] = -6
        # The first record in the result set.
        self.globals["wdFirstRecord".lower()] = -4
        # The last record in the data source.
        self.globals["wdLastDataSourceRecord".lower()] = -7
        # The last record in the result set.
        self.globals["wdLastRecord".lower()] = -5
        # The next record in the data source.
        self.globals["wdNextDataSourceRecord".lower()] = -8
        # The next record in the result set.
        self.globals["wdNextRecord".lower()] = -2
        # No active record.
        self.globals["wdNoActiveRecord".lower()] = -1
        # The previous record in the data source.
        self.globals["wdPreviousDataSourceRecord".lower()] = -9
        # The previous record in the result set.
        self.globals["wdPreviousRecord".lower()] = -3

        # WdAlignmentTabAlignment enumeration (Word)
        #   
        # Specifies tab alignment.
        
        # Centered tab.
        self.globals["wdCenter".lower()] = 1
        # Left-aligned tab.
        self.globals["wdLeft".lower()] = 0
        # Right-aligned tab.
        self.globals["wdRight".lower()] = 2

        # WdUnits enumeration (Word)
        #   
        # Specifies a unit of measure to use.
        
        # A cell.
        self.globals["wdCell".lower()] = 12
        # A character.
        self.globals["wdCharacter".lower()] = 1
        # Character formatting.
        self.globals["wdCharacterFormatting".lower()] = 13
        # A column.
        self.globals["wdColumn".lower()] = 9
        # The selected item.
        self.globals["wdItem".lower()] = 16
        # A line.
        self.globals["wdLine".lower()] = 5
        # A paragraph.
        self.globals["wdParagraph".lower()] = 4
        # Paragraph formatting.
        self.globals["wdParagraphFormatting".lower()] = 14
        # A row.
        self.globals["wdRow".lower()] = 10
        # The screen dimensions.
        self.globals["wdScreen".lower()] = 7
        # A section.
        self.globals["wdSection".lower()] = 8
        # A sentence.
        self.globals["wdSentence".lower()] = 3
        # A story.
        self.globals["wdStory".lower()] = 6
        # A table.
        self.globals["wdTable".lower()] = 15
        # A window.
        self.globals["wdWindow".lower()] = 11
        # A word.
        self.globals["wdWord".lower()] = 2

        # WdPageBorderArt enumeration (Word)
        #
        # Specifies the graphical page border setting of a page.
        
        #  An apple border.
        self.globals["wdArtApples".lower()] = 1
        #  An arched scalloped border.
        self.globals["wdArtArchedScallops".lower()] = 97
        #  A baby pacifier border.
        self.globals["wdArtBabyPacifier".lower()] = 70
        #  A baby rattle border.
        self.globals["wdArtBabyRattle".lower()] = 71
        #  Balloons in three colors as the border.
        self.globals["wdArtBalloons3Colors".lower()] = 11
        #  A hot air balloon border.
        self.globals["wdArtBalloonsHotAir".lower()] = 12
        #  A basic black-dashed border.
        self.globals["wdArtBasicBlackDashes".lower()] = 155
        #  A basic black-dotted border.
        self.globals["wdArtBasicBlackDots".lower()] = 156
        #  A basic black squares border.
        self.globals["wdArtBasicBlackSquares".lower()] = 154
        #  A basic thin-lines border.
        self.globals["wdArtBasicThinLines".lower()] = 151
        #  A basic white-dashed border.
        self.globals["wdArtBasicWhiteDashes".lower()] = 152
        #  A basic white-dotted border.
        self.globals["wdArtBasicWhiteDots".lower()] = 147
        #  A basic white squares border.
        self.globals["wdArtBasicWhiteSquares".lower()] = 153
        #  A basic wide inline border.
        self.globals["wdArtBasicWideInline".lower()] = 150
        #  A basic wide midline border.
        self.globals["wdArtBasicWideMidline".lower()] = 148
        #  A basic wide outline border.
        self.globals["wdArtBasicWideOutline".lower()] = 149
        #  A bats border.
        self.globals["wdArtBats".lower()] = 37
        #  A birds border.
        self.globals["wdArtBirds".lower()] = 102
        #  A birds-in-flight border.
        self.globals["wdArtBirdsFlight".lower()] = 35
        #  A cabins border.
        self.globals["wdArtCabins".lower()] = 72
        #  A cake slice border.
        self.globals["wdArtCakeSlice".lower()] = 3
        #  A candy corn border.
        self.globals["wdArtCandyCorn".lower()] = 4
        #  A Celtic knotwork border.
        self.globals["wdArtCelticKnotwork".lower()] = 99
        #  A certificate banner border.
        self.globals["wdArtCertificateBanner".lower()] = 158
        #  A chain-link border.
        self.globals["wdArtChainLink".lower()] = 128
        #  A champagne bottle border.
        self.globals["wdArtChampagneBottle".lower()] = 6
        #  A checked-bar black border.
        self.globals["wdArtCheckedBarBlack".lower()] = 145
        #  A checked-bar colored border.
        self.globals["wdArtCheckedBarColor".lower()] = 61
        #  A checkered border.
        self.globals["wdArtCheckered".lower()] = 144
        #  A Christmas tree border.
        self.globals["wdArtChristmasTree".lower()] = 8
        #  A circles-and-lines border.
        self.globals["wdArtCirclesLines".lower()] = 91
        #  A circles-and-rectangles border.
        self.globals["wdArtCirclesRectangles".lower()] = 140
        #  A classical wave border.
        self.globals["wdArtClassicalWave".lower()] = 56
        #  A clocks border.
        self.globals["wdArtClocks".lower()] = 27
        #  A compass border.
        self.globals["wdArtCompass".lower()] = 54
        #  A confetti border.
        self.globals["wdArtConfetti".lower()] = 31
        #  A confetti border using shades of gray.
        self.globals["wdArtConfettiGrays".lower()] = 115
        #  A confetti outline border.
        self.globals["wdArtConfettiOutline".lower()] = 116
        #  A confetti streamers border.
        self.globals["wdArtConfettiStreamers".lower()] = 14
        #  A confetti white border.
        self.globals["wdArtConfettiWhite".lower()] = 117
        #  A triangles border.
        self.globals["wdArtCornerTriangles".lower()] = 141
        #  A coupon-cut-out dashes border.
        self.globals["wdArtCouponCutoutDashes".lower()] = 163
        #  A coupon-cut-out dots border.
        self.globals["wdArtCouponCutoutDots".lower()] = 164
        #  A crazy maze border.
        self.globals["wdArtCrazyMaze".lower()] = 100
        #  A butterfly border.
        self.globals["wdArtCreaturesButterfly".lower()] = 32
        #  A fish border.
        self.globals["wdArtCreaturesFish".lower()] = 34
        #  An insect border.
        self.globals["wdArtCreaturesInsects".lower()] = 142
        #  A ladybug border.
        self.globals["wdArtCreaturesLadyBug".lower()] = 33
        #  A cross-stitch border.
        self.globals["wdArtCrossStitch".lower()] = 138
        #  A cup border.
        self.globals["wdArtCup".lower()] = 67
        #  A deco arch border.
        self.globals["wdArtDecoArch".lower()] = 89
        #  A deco arch colored border.
        self.globals["wdArtDecoArchColor".lower()] = 50
        #  A deco blocks border.
        self.globals["wdArtDecoBlocks".lower()] = 90
        #  A diamond border using shades of gray.
        self.globals["wdArtDiamondsGray".lower()] = 88
        #  A double-D border.
        self.globals["wdArtDoubleD".lower()] = 55
        #  A double-diamonds border.
        self.globals["wdArtDoubleDiamonds".lower()] = 127
        #  An earth number 1 border.
        self.globals["wdArtEarth1".lower()] = 22
        #  An earth number 2 border.
        self.globals["wdArtEarth2".lower()] = 21
        #  An eclipsing squares number 1 border.
        self.globals["wdArtEclipsingSquares1".lower()] = 101
        #  An eclipsing squares number 2 border.
        self.globals["wdArtEclipsingSquares2".lower()] = 86
        #  A black eggs border.
        self.globals["wdArtEggsBlack".lower()] = 66
        #  A fans border.
        self.globals["wdArtFans".lower()] = 51
        #  A film border.
        self.globals["wdArtFilm".lower()] = 52
        #  A fire crackers border.
        self.globals["wdArtFirecrackers".lower()] = 28
        #  A block flowers print border.
        self.globals["wdArtFlowersBlockPrint".lower()] = 49
        #  A daisies border.
        self.globals["wdArtFlowersDaisies".lower()] = 48
        #  A modern flowers number 1 border.
        self.globals["wdArtFlowersModern1".lower()] = 45
        #  A modern flowers number 2 border.
        self.globals["wdArtFlowersModern2".lower()] = 44
        #  A pansy border.
        self.globals["wdArtFlowersPansy".lower()] = 43
        #  A red rose border.
        self.globals["wdArtFlowersRedRose".lower()] = 39
        #  A rose border.
        self.globals["wdArtFlowersRoses".lower()] = 38
        #  A teacup border.
        self.globals["wdArtFlowersTeacup".lower()] = 103
        #  A tiny flower border.
        self.globals["wdArtFlowersTiny".lower()] = 42
        #  A gems border.
        self.globals["wdArtGems".lower()] = 139
        #  A gingerbread man border.
        self.globals["wdArtGingerbreadMan".lower()] = 69
        #  A gradient border.
        self.globals["wdArtGradient".lower()] = 122
        #  A handmade number 1 border.
        self.globals["wdArtHandmade1".lower()] = 159
        #  A handmade number 2 border.
        self.globals["wdArtHandmade2".lower()] = 160
        #  A heart-balloon border.
        self.globals["wdArtHeartBalloon".lower()] = 16
        #  A heart border in shades of gray.
        self.globals["wdArtHeartGray".lower()] = 68
        #  A hearts border.
        self.globals["wdArtHearts".lower()] = 15
        #  A heebie-jeebies border.
        self.globals["wdArtHeebieJeebies".lower()] = 120
        #  A holly border.
        self.globals["wdArtHolly".lower()] = 41
        #  A funky house border.
        self.globals["wdArtHouseFunky".lower()] = 73
        #  An hypnotic border.
        self.globals["wdArtHypnotic".lower()] = 87
        #  An ice cream cones border.
        self.globals["wdArtIceCreamCones".lower()] = 5
        #  A light bulb border.
        self.globals["wdArtLightBulb".lower()] = 121
        #  A lightning number 1 border.
        self.globals["wdArtLightning1".lower()] = 53
        #  A lightning number 2 border.
        self.globals["wdArtLightning2".lower()] = 119
        #  A maple leaf border.
        self.globals["wdArtMapleLeaf".lower()] = 81
        #  A maple muffins border.
        self.globals["wdArtMapleMuffins".lower()] = 2
        #  A map pins border.
        self.globals["wdArtMapPins".lower()] = 30
        #  A marquee border.
        self.globals["wdArtMarquee".lower()] = 146
        #  A marquee toothed border.
        self.globals["wdArtMarqueeToothed".lower()] = 131
        #  A moons border.
        self.globals["wdArtMoons".lower()] = 125
        #  A mosaic border.
        self.globals["wdArtMosaic".lower()] = 118
        #  A music notes border.
        self.globals["wdArtMusicNotes".lower()] = 79
        #  A northwest border.
        self.globals["wdArtNorthwest".lower()] = 104
        #  An ovals border.
        self.globals["wdArtOvals".lower()] = 126
        #  A packages border.
        self.globals["wdArtPackages".lower()] = 26
        #  A black palms border.
        self.globals["wdArtPalmsBlack".lower()] = 80
        #  A colored palms border.
        self.globals["wdArtPalmsColor".lower()] = 10
        #  A paper clips border.
        self.globals["wdArtPaperClips".lower()] = 82
        #  A papyrus border.
        self.globals["wdArtPapyrus".lower()] = 92
        #  A party favor border.
        self.globals["wdArtPartyFavor".lower()] = 13
        #  A party glass border.
        self.globals["wdArtPartyGlass".lower()] = 7
        #  A pencils border.
        self.globals["wdArtPencils".lower()] = 25
        #  A people border.
        self.globals["wdArtPeople".lower()] = 84
        #  A people-wearing-hats border.
        self.globals["wdArtPeopleHats".lower()] = 23
        #  A people-waving border.
        self.globals["wdArtPeopleWaving".lower()] = 85
        #  A poinsettias border.
        self.globals["wdArtPoinsettias".lower()] = 40
        #  A postage stamp border.
        self.globals["wdArtPostageStamp".lower()] = 135
        #  A pumpkin number 1 border.
        self.globals["wdArtPumpkin1".lower()] = 65
        #  A pushpin note number 1 border.
        self.globals["wdArtPushPinNote1".lower()] = 63
        #  A pushpin note number 2 border.
        self.globals["wdArtPushPinNote2".lower()] = 64
        #  A pyramids border.
        self.globals["wdArtPyramids".lower()] = 113
        #  An external pyramids border.
        self.globals["wdArtPyramidsAbove".lower()] = 114
        #  A quadrants border.
        self.globals["wdArtQuadrants".lower()] = 60
        #  A rings border.
        self.globals["wdArtRings".lower()] = 29
        #  A safari border.
        self.globals["wdArtSafari".lower()] = 98
        #  A saw-tooth border.
        self.globals["wdArtSawtooth".lower()] = 133
        #  A saw-tooth border using shades of gray.
        self.globals["wdArtSawtoothGray".lower()] = 134
        #  A scared cat border.
        self.globals["wdArtScaredCat".lower()] = 36
        #  A Seattle border.
        self.globals["wdArtSeattle".lower()] = 78
        #  A shadowed squared border.
        self.globals["wdArtShadowedSquares".lower()] = 57
        #  A shark-tooth border.
        self.globals["wdArtSharksTeeth".lower()] = 132
        #  A shorebird tracks border.
        self.globals["wdArtShorebirdTracks".lower()] = 83
        #  A sky rocket border.
        self.globals["wdArtSkyrocket".lower()] = 77
        #  A fancy snowflake border.
        self.globals["wdArtSnowflakeFancy".lower()] = 76
        #  A snowflake border.
        self.globals["wdArtSnowflakes".lower()] = 75
        #  A sombrero border.
        self.globals["wdArtSombrero".lower()] = 24
        #  A southwest border.
        self.globals["wdArtSouthwest".lower()] = 105
        #  A stars border.
        self.globals["wdArtStars".lower()] = 19
        #  A 3D stars border.
        self.globals["wdArtStars3D".lower()] = 17
        #  A black stars border.
        self.globals["wdArtStarsBlack".lower()] = 74
        #  A shadowed stars border.
        self.globals["wdArtStarsShadowed".lower()] = 18
        #  A stars-on-top border.
        self.globals["wdArtStarsTop".lower()] = 157
        #  A sun border.
        self.globals["wdArtSun".lower()] = 20
        #  A swirling border.
        self.globals["wdArtSwirligig".lower()] = 62
        #  A torn-paper border.
        self.globals["wdArtTornPaper".lower()] = 161
        #  A black torn-paper border.
        self.globals["wdArtTornPaperBlack".lower()] = 162
        #  A trees border.
        self.globals["wdArtTrees".lower()] = 9
        #  A triangle party border.
        self.globals["wdArtTriangleParty".lower()] = 123
        #  A triangles border.
        self.globals["wdArtTriangles".lower()] = 129
        #  A tribal number 1 border.
        self.globals["wdArtTribal1".lower()] = 130
        #  A tribal number 2 border.
        self.globals["wdArtTribal2".lower()] = 109
        #  A tribal number 3 border.
        self.globals["wdArtTribal3".lower()] = 108
        #  A tribal number 4 border.
        self.globals["wdArtTribal4".lower()] = 107
        #  A tribal number 5 border.
        self.globals["wdArtTribal5".lower()] = 110
        #  A tribal number 6 border.
        self.globals["wdArtTribal6".lower()] = 106
        #  A twisted lines number 1 border.
        self.globals["wdArtTwistedLines1".lower()] = 58
        #  A twisted lines number 2 border.
        self.globals["wdArtTwistedLines2".lower()] = 124
        #  A vine border.
        self.globals["wdArtVine".lower()] = 47
        #  A wave-line border.
        self.globals["wdArtWaveline".lower()] = 59
        #  A weaving angle border.
        self.globals["wdArtWeavingAngles".lower()] = 96
        #  A weaving braid border.
        self.globals["wdArtWeavingBraid".lower()] = 94
        #  A weaving ribbon border.
        self.globals["wdArtWeavingRibbon".lower()] = 95
        #  A weaving strips border.
        self.globals["wdArtWeavingStrips".lower()] = 136
        #  A white flower border.
        self.globals["wdArtWhiteFlowers".lower()] = 46
        #  A woodwork border.
        self.globals["wdArtWoodwork".lower()] = 93
        #  An X illusion border.
        self.globals["wdArtXIllusions".lower()] = 111
        #  A zany triangle border.
        self.globals["wdArtZanyTriangles".lower()] = 112
        #  A zigzag border.
        self.globals["wdArtZigZag".lower()] = 137
        #  A zigzag stitch border.
        self.globals["wdArtZigZagStitch".lower()] = 143
        
        # WdColor enumeration (Word)
        #
        # Specifies the 24-bit color to apply.
        
        #  Aqua color
        self.globals["wdColorAqua".lower()] = 13421619
        #  Automatic color; default; usually black
        self.globals["wdColorAutomatic".lower()] = -16777216
        #  Black color
        self.globals["wdColorBlack".lower()] = 0
        #  Blue color
        self.globals["wdColorBlue".lower()] = 16711680
        #  Blue-gray color
        self.globals["wdColorBlueGray".lower()] = 10053222
        #  Bright green color
        self.globals["wdColorBrightGreen".lower()] = 65280
        #  Brown color
        self.globals["wdColorBrown".lower()] = 13209
        #  Dark blue color
        self.globals["wdColorDarkBlue".lower()] = 8388608
        #  Dark green color
        self.globals["wdColorDarkGreen".lower()] = 13056
        #  Dark red color
        self.globals["wdColorDarkRed".lower()] = 128
        #  Dark teal color
        self.globals["wdColorDarkTeal".lower()] = 6697728
        #  Dark yellow color
        self.globals["wdColorDarkYellow".lower()] = 32896
        #  Gold color
        self.globals["wdColorGold".lower()] = 52479
        #  Shade 05 of gray color
        self.globals["wdColorGray05".lower()] = 15987699
        #  Shade 10 of gray color
        self.globals["wdColorGray10".lower()] = 15132390
        #  Shade 125 of gray color
        self.globals["wdColorGray125".lower()] = 14737632
        #  Shade 15 of gray color
        self.globals["wdColorGray15".lower()] = 14277081
        #  Shade 20 of gray color
        self.globals["wdColorGray20".lower()] = 13421772
        #  Shade 25 of gray color
        self.globals["wdColorGray25".lower()] = 12632256
        #  Shade 30 of gray color
        self.globals["wdColorGray30".lower()] = 11776947
        #  Shade 35 of gray color
        self.globals["wdColorGray35".lower()] = 10921638
        #  Shade 375 of gray color
        self.globals["wdColorGray375".lower()] = 10526880
        #  Shade 40 of gray color
        self.globals["wdColorGray40".lower()] = 10066329
        #  Shade 45 of gray color
        self.globals["wdColorGray45".lower()] = 9211020
        #  Shade 50 of gray color
        self.globals["wdColorGray50".lower()] = 8421504
        #  Shade 55 of gray color
        self.globals["wdColorGray55".lower()] = 7566195
        #  Shade 60 of gray color
        self.globals["wdColorGray60".lower()] = 6710886
        #  Shade 625 of gray color
        self.globals["wdColorGray625".lower()] = 6316128
        #  Shade 65 of gray color
        self.globals["wdColorGray65".lower()] = 5855577
        #  Shade 70 of gray color
        self.globals["wdColorGray70".lower()] = 5000268
        #  Shade 75 of gray color
        self.globals["wdColorGray75".lower()] = 4210752
        #  Shade 80 of gray color
        self.globals["wdColorGray80".lower()] = 3355443
        #  Shade 85 of gray color
        self.globals["wdColorGray85".lower()] = 2500134
        #  Shade 875 of gray color
        self.globals["wdColorGray875".lower()] = 2105376
        #  Shade 90 of gray color
        self.globals["wdColorGray90".lower()] = 1644825
        #  Shade 95 of gray color
        self.globals["wdColorGray95".lower()] = 789516
        #  Green color
        self.globals["wdColorGreen".lower()] = 32768
        #  Indigo color
        self.globals["wdColorIndigo".lower()] = 10040115
        #  Lavender color
        self.globals["wdColorLavender".lower()] = 16751052
        #  Light blue color
        self.globals["wdColorLightBlue".lower()] = 16737843
        #  Light green color
        self.globals["wdColorLightGreen".lower()] = 13434828
        #  Light orange color
        self.globals["wdColorLightOrange".lower()] = 39423
        #  Light turquoise color
        self.globals["wdColorLightTurquoise".lower()] = 16777164
        #  Light yellow color
        self.globals["wdColorLightYellow".lower()] = 10092543
        #  Lime color
        self.globals["wdColorLime".lower()] = 52377
        #  Olive green color
        self.globals["wdColorOliveGreen".lower()] = 13107
        #  Orange color
        self.globals["wdColorOrange".lower()] = 26367
        #  Pale blue color
        self.globals["wdColorPaleBlue".lower()] = 16764057
        #  Pink color
        self.globals["wdColorPink".lower()] = 16711935
        #  Plum color
        self.globals["wdColorPlum".lower()] = 6697881
        #  Red color
        self.globals["wdColorRed".lower()] = 255
        #  Rose color
        self.globals["wdColorRose".lower()] = 13408767
        #  Sea green color
        self.globals["wdColorSeaGreen".lower()] = 6723891
        #  Sky blue color
        self.globals["wdColorSkyBlue".lower()] = 16763904
        #  Tan color
        self.globals["wdColorTan".lower()] = 10079487
        #  Teal color
        self.globals["wdColorTeal".lower()] = 8421376
        #  Turquoise color
        self.globals["wdColorTurquoise".lower()] = 16776960
        #  Violet color
        self.globals["wdColorViolet".lower()] = 8388736
        #  White color
        self.globals["wdColorWhite".lower()] = 16777215
        #  Yellow color
        self.globals["wdColorYellow".lower()] = 65535
        
        # WdCompareTarget Enum
        #
        # Specifies the target document for displaying document comparison differences.
        
        #  Places comparison differences in the current document. Default.
        self.globals["wdCompareTargetCurrent".lower()] = 1
        #  Places comparison differences in a new document.
        self.globals["wdCompareTargetNew".lower()] = 2
        #  Places comparison differences in the target document.
        self.globals["wdCompareTargetSelected".lower()] = 0
        
        # WdSmartTagControlType enumeration (Word)
        #   
        # Specifies the type of control associated with a SmartTagAction object.
        
        #  ActiveX control.
        self.globals["wdControlActiveX".lower()] = 13
        #  Button.
        self.globals["wdControlButton".lower()] = 6
        #  Check box.
        self.globals["wdControlCheckbox".lower()] = 9
        #  Combo box.
        self.globals["wdControlCombo".lower()] = 12
        #  Document fragment.
        self.globals["wdControlDocumentFragment".lower()] = 14
        #  Document fragment URL.
        self.globals["wdControlDocumentFragmentURL".lower()] = 15
        #  Help.
        self.globals["wdControlHelp".lower()] = 3
        #  Help URL.
        self.globals["wdControlHelpURL".lower()] = 4
        #  Image.
        self.globals["wdControlImage".lower()] = 8
        #  Label.
        self.globals["wdControlLabel".lower()] = 7
        #  Link.
        self.globals["wdControlLink".lower()] = 2
        #  List box.
        self.globals["wdControlListbox".lower()] = 11
        #  Radio group.
        self.globals["wdControlRadioGroup".lower()] = 16
        #  Separator.
        self.globals["wdControlSeparator".lower()] = 5
        #  Smart tag.
        self.globals["wdControlSmartTag".lower()] = 1
        #  Text box.
        self.globals["wdControlTextbox".lower()] = 10
        
        # WdDeletedTextMark enumeration (Word)
        #   
        # Specifies the formatting of text that is deleted while change tracking is enabled.
        
        #  Deleted text is displayed in bold.
        self.globals["wdDeletedTextMarkBold".lower()] = 5
        #  Deleted text is marked up by using caret characters.
        self.globals["wdDeletedTextMarkCaret".lower()] = 2
        #  Deleted text is displayed in a specified color (default is red).
        self.globals["wdDeletedTextMarkColorOnly".lower()] = 9
        #  Deleted text is marked up by using double-underline characters.
        self.globals["wdDeletedTextMarkDoubleUnderline".lower()] = 8
        #  Deleted text is hidden.
        self.globals["wdDeletedTextMarkHidden".lower()] = 0
        #  Deleted text is displayed in italic.
        self.globals["wdDeletedTextMarkItalic".lower()] = 6
        #  Deleted text is not marked up.
        self.globals["wdDeletedTextMarkNone".lower()] = 4
        #  Deleted text is marked up by using pound characters.
        self.globals["wdDeletedTextMarkPound".lower()] = 3
        #  Deleted text is marked up by using strikethrough characters.
        self.globals["wdDeletedTextMarkStrikeThrough".lower()] = 1
        #  Deleted text is underlined.
        self.globals["wdDeletedTextMarkUnderline".lower()] = 7
        #  Deleted text is marked up by using double-strikethrough characters.
        self.globals["wdDeletedTextMarkDoubleStrikeThrough".lower()] = 10
        
        # WdDiacriticColor enumeration (Word)
        #   
        # Specifies whether to apply a different color to diacritics in bi-directional or Latin style languages.
        
        #  Bi-directional language (Arabic, Hebrew, and so forth).
        self.globals["wdDiacriticColorBidi".lower()] = 0
        #  Latin style languages.
        self.globals["wdDiacriticColorLatin".lower()] = 1
        
        # WdWordDialog enumeration (Word)
        #   
        # Indicates the Microsoft Word dialog boxes with which you can work and specifies arguments, if applicable, that you can use to get or set values in a dialog box.
        
        #  (none)
        self.globals["wdDialogBuildingBlockOrganizer".lower()] = 2067
        #  Drive, Path, Password
        self.globals["wdDialogConnect".lower()] = 420
        #  (none)
        self.globals["wdDialogConsistencyChecker".lower()] = 1121
        #  (none)
        self.globals["wdDialogContentControlProperties".lower()] = 2394
        #  Application
        self.globals["wdDialogControlRun".lower()] = 235
        #  IconNumber, ActivateAs, IconFileName, Caption, Class, DisplayIcon, Floating
        self.globals["wdDialogConvertObject".lower()] = 392
        #  FileName, Directory
        self.globals["wdDialogCopyFile".lower()] = 300
        #  (none)
        self.globals["wdDialogCreateAutoText".lower()] = 872
        #  (none)
        self.globals["wdDialogCreateSource".lower()] = 1922
        #  LinkStyles
        self.globals["wdDialogCSSLinks".lower()] = 1261
        #  (none)
        self.globals["wdDialogDocumentInspector".lower()] = 1482
        #  FileName, Directory, Template, Title, Created, LastSaved, LastSavedBy, Revision, Time, Printed, Pages, Words, Characters, Paragraphs, Lines, FileSize
        self.globals["wdDialogDocumentStatistics".lower()] = 78
        #  Horizontal, Vertical, RelativeTo
        self.globals["wdDialogDrawAlign".lower()] = 634
        #  SnapToGrid, XGrid, YGrid, XOrigin, YOrigin, SnapToShapes, XGridDisplay, YGridDisplay, FollowMargins, ViewGridLines, DefineLineBasedOnGrid
        self.globals["wdDialogDrawSnapToGrid".lower()] = 633
        #  Name, Context, InsertAs, Insert, Add, Define, InsertAsText, Delete, CompleteAT
        self.globals["wdDialogEditAutoText".lower()] = 985
        #  Macintosh-only. For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdDialogEditCreatePublisher".lower()] = 732
        #  Find, Replace, Direction, MatchCase, WholeWord, PatternMatch, SoundsLike, FindNext, ReplaceOne, ReplaceAll, Format, Wrap, FindAllWordForms, MatchByte, FuzzyFind, Destination, CorrectEnd, MatchKashida, MatchDiacritics, MatchAlefHamza, MatchControl
        self.globals["wdDialogEditFind".lower()] = 112
        #  Wrap, WidthRule, FixedWidth, HeightRule, FixedHeight, PositionHorz, PositionHorzRel, DistFromText, PositionVert, PositionVertRel, DistVertFromText, MoveWithText, LockAnchor, RemoveFrame
        self.globals["wdDialogEditFrame".lower()] = 458
        #  Find, Replace, Direction, MatchCase, WholeWord, PatternMatch, SoundsLike, FindNext, ReplaceOne, ReplaceAll, Format, Wrap, FindAllWordForms, MatchByte, FuzzyFind, Destination, CorrectEnd, MatchKashida, MatchDiacritics, MatchAlefHamza, MatchControl
        self.globals["wdDialogEditGoTo".lower()] = 896
        #  (none)
        self.globals["wdDialogEditGoToOld".lower()] = 811
        #  UpdateMode, Locked, SavePictureInDoc, UpdateNow, OpenSource, KillLink, Link, Application, Item, FileName, PreserveFormatLinkUpdate
        self.globals["wdDialogEditLinks".lower()] = 124
        #  Verb
        self.globals["wdDialogEditObject".lower()] = 125
        #  IconNumber, Link, DisplayIcon, Class, DataType, IconFileName, Caption, Floating
        self.globals["wdDialogEditPasteSpecial".lower()] = 111
        #  Macintosh-only. For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdDialogEditPublishOptions".lower()] = 735
        #  Find, Replace, Direction, MatchCase, WholeWord, PatternMatch, SoundsLike, FindNext, ReplaceOne, ReplaceAll, Format, Wrap, FindAllWordForms, MatchByte, FuzzyFind, Destination, CorrectEnd, MatchKashida, MatchDiacritics, MatchAlefHamza, MatchControl
        self.globals["wdDialogEditReplace".lower()] = 117
        #  (none)
        self.globals["wdDialogEditStyle".lower()] = 120
        #  Macintosh-only. For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdDialogEditSubscribeOptions".lower()] = 736
        #  Macintosh-only. For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdDialogEditSubscribeTo".lower()] = 733
        #  Category, CategoryName
        self.globals["wdDialogEditTOACategory".lower()] = 625
        #  (none)
        self.globals["wdDialogEmailOptions".lower()] = 863
        #  Tab, PaperSize, TopMargin, BottomMargin, LeftMargin, RightMargin, Gutter, PageWidth, PageHeight, Orientation, FirstPage, OtherPages, VertAlign, ApplyPropsTo, Default, FacingPages, HeaderDistance, FooterDistance, SectionStart, OddAndEvenPages, DifferentFirstPage, Endnotes, LineNum, StartingNum, FromText, CountBy, NumMode, TwoOnOne, GutterPosition, LayoutMode, CharsLine, LinesPage, CharPitch, LinePitch, DocFontName, DocFontSize, PageColumns, TextFlow, FirstPageOnLeft, SectionType, RTLAlignment
        self.globals["wdDialogFileDocumentLayout".lower()] = 178
        #  SearchName, SearchPath, Name, SubDir, Title, Author, Keywords, Subject, Options, MatchCase, Text, PatternMatch, DateSavedFrom, DateSavedTo, SavedBy, DateCreatedFrom, DateCreatedTo, View, SortBy, ListBy, SelectedFile, Add, Delete, ShowFolders, MatchByte
        self.globals["wdDialogFileFind".lower()] = 99
        #  Macintosh-only. For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdDialogFileMacCustomPageSetupGX".lower()] = 737
        #  Macintosh-only. For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdDialogFileMacPageSetup".lower()] = 685
        #  Macintosh-only. For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdDialogFileMacPageSetupGX".lower()] = 444
        #  Template, NewTemplate, DocumentType, Visible
        self.globals["wdDialogFileNew".lower()] = 79
        #  Name, ConfirmConversions, ReadOnly, LinkToSource, AddToMru, PasswordDoc, PasswordDot, Revert, WritePasswordDoc, WritePasswordDot, Connection, SQLStatement, SQLStatement1, Format, Encoding, Visible, OpenExclusive, OpenAndRepair, SubType, DocumentDirection, NoEncodingDialog, XMLTransform
        self.globals["wdDialogFileOpen".lower()] = 80
        #  Tab, PaperSize, TopMargin, BottomMargin, LeftMargin, RightMargin, Gutter, PageWidth, PageHeight, Orientation, FirstPage, OtherPages, VertAlign, ApplyPropsTo, Default, FacingPages, HeaderDistance, FooterDistance, SectionStart, OddAndEvenPages, DifferentFirstPage, Endnotes, LineNum, StartingNum, FromText, CountBy, NumMode, TwoOnOne, GutterPosition, LayoutMode, CharsLine, LinesPage, CharPitch, LinePitch, DocFontName, DocFontSize, PageColumns, TextFlow, FirstPageOnLeft, SectionType, RTLAlignment, FolioPrint
        self.globals["wdDialogFilePageSetup".lower()] = 178
        #  Background, AppendPrFile, Range, PrToFileName, From, To, Type, NumCopies, Pages, Order, PrintToFile, Collate, FileName, Printer, OutputPrinter, DuplexPrint, PrintZoomColumn, PrintZoomRow, PrintZoomPaperWidth, PrintZoomPaperHeight, ZoomPaper
        self.globals["wdDialogFilePrint".lower()] = 88
        #  Macintosh-only. For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdDialogFilePrintOneCopy".lower()] = 445
        #  Printer, Options, Network, DoNotSetAsSysDefault
        self.globals["wdDialogFilePrintSetup".lower()] = 97
        #  Subject, Message, AllAtOnce, ReturnWhenDone, TrackStatus, Protect, AddSlip, RouteDocument, AddRecipient, OldRecipient, ResetSlip, ClearSlip, ClearRecipients, Address
        self.globals["wdDialogFileRoutingSlip".lower()] = 624
        #  Name, Format, LockAnnot, Password, AddToMru, WritePassword, RecommendReadOnly, EmbedFonts, NativePictureFormat, FormsData, SaveAsAOCELetter, WriteVersion, VersionDesc, InsertLineBreaks, AllowSubstitutions, LineEnding, AddBiDiMarks
        self.globals["wdDialogFileSaveAs".lower()] = 84
        #  (none)
        self.globals["wdDialogFileSaveVersion".lower()] = 1007
        #  Title, Subject, Author, Keywords, Comments, FileName, Directory, Template, CreateDate, LastSavedDate, LastSavedBy, RevisionNumber, EditTime, LastPrintedDate, NumPages, NumWords, NumChars, NumParas, NumLines, Update, FileSize
        self.globals["wdDialogFileSummaryInfo".lower()] = 86
        #  AutoVersion, VersionDesc
        self.globals["wdDialogFileVersions".lower()] = 945
        #  FitTextWidth
        self.globals["wdDialogFitText".lower()] = 983
        #  UnavailableFont, SubstituteFont
        self.globals["wdDialogFontSubstitution".lower()] = 581
        #  Points, Underline, Color, StrikeThrough, Superscript, Subscript, Hidden, SmallCaps, AllCaps, Spacing, Position, Kerning, KerningMin, Default, Tab, Font, Bold, Italic, DoubleStrikeThrough, Shadow, Outline, Emboss, Engrave, Scale, Animations, CharAccent, FontMajor, FontLowAnsi, FontHighAnsi, CharacterWidthGrid, ColorRGB, UnderlineColor, PointsBi, ColorBi, FontNameBi, BoldBi, ItalicBi, DiacColor
        self.globals["wdDialogFormatAddrFonts".lower()] = 103
        #  ApplyTo, Shadow, TopBorder, LeftBorder, BottomBorder, RightBorder, HorizBorder, VertBorder, TopColor, LeftColor, BottomColor, RightColor, HorizColor, VertColor, FromText, Shading, Foreground, Background, Tab, FineShading, TopStyle, LeftStyle, BottomStyle, RightStyle, HorizStyle, VertStyle, TopWeight, LeftWeight, BottomWeight, RightWeight, HorizWeight, VertWeight, BorderObjectType, BorderArtWeight, BorderArt, FromTextTop, FromTextBottom, FromTextLeft, FromTextRight, OffsetFrom, InFront, SurroundHeader, SurroundFooter, JoinBorder, LineColor, WhichPages, TL2BRBorder, TR2BLBorder, TL2BRColor, TR2BLColor, TL2BRStyle, TR2BLStyle, TL2BRWeight, TR2BLWeight, ForegroundRGB, BackgroundRGB, TopColorRGB, LeftColorRGB, BottomColorRGB, RightColorRGB, HorizColorRGB, VertColorRGB, TL2BRColorRGB, TR2BLColorRGB, LineColorRGB
        self.globals["wdDialogFormatBordersAndShading".lower()] = 189
        #  (none)
        self.globals["wdDialogFormatBulletsAndNumbering".lower()] = 824
        #  Type, Gap, Angle, Drop, Length, Border, AutoAttach, Accent
        self.globals["wdDialogFormatCallout".lower()] = 610
        #  Type
        self.globals["wdDialogFormatChangeCase".lower()] = 322
        #  Columns, ColumnNo, ColumnWidth, ColumnSpacing, EvenlySpaced, ApplyColsTo, ColLine, StartNewCol, FlowColumnsRtl
        self.globals["wdDialogFormatColumns".lower()] = 177
        #  ApplyTo, Shadow, TopBorder, LeftBorder, BottomBorder, RightBorder, HorizBorder, VertBorder, TopColor, LeftColor, BottomColor, RightColor, HorizColor, VertColor, FromText, Shading, Foreground, Background, Tab, FineShading, TopStyle, LeftStyle, BottomStyle, RightStyle, HorizStyle, VertStyle, TopWeight, LeftWeight, BottomWeight, RightWeight, HorizWeight, VertWeight, BorderObjectType, BorderArtWeight, BorderArt, FromTextTop, FromTextBottom, FromTextLeft, FromTextRight, OffsetFrom, InFront, SurroundHeader, SurroundFooter, JoinBorder, LineColor, WhichPages, TL2BRBorder, TR2BLBorder, TL2BRColor, TR2BLColor, TL2BRStyle, TR2BLStyle, TL2BRWeight, TR2BLWeight, ForegroundRGB, BackgroundRGB, TopColorRGB, LeftColorRGB, BottomColorRGB, RightColorRGB, HorizColorRGB, VertColorRGB, TL2BRColorRGB, TR2BLColorRGB, LineColorRGB
        self.globals["wdDialogFormatDefineStyleBorders".lower()] = 185
        #  Points, Underline, Color, StrikeThrough, Superscript, Subscript, Hidden, SmallCaps, AllCaps, Spacing, Position, Kerning, KerningMin, Default, Tab, Font, Bold, Italic, DoubleStrikeThrough, Shadow, Outline, Emboss, Engrave, Scale, Animations, CharAccent, FontMajor, FontLowAnsi, FontHighAnsi, CharacterWidthGrid, ColorRGB, UnderlineColor, PointsBi, ColorBi, FontNameBi, BoldBi, ItalicBi, DiacColor
        self.globals["wdDialogFormatDefineStyleFont".lower()] = 181
        #  Wrap, WidthRule, FixedWidth, HeightRule, FixedHeight, PositionHorz, PositionHorzRel, DistFromText, PositionVert, PositionVertRel, DistVertFromText, MoveWithText, LockAnchor, RemoveFrame
        self.globals["wdDialogFormatDefineStyleFrame".lower()] = 184
        #  Language, CheckLanguage, Default, NoProof
        self.globals["wdDialogFormatDefineStyleLang".lower()] = 186
        #  LeftIndent, RightIndent, Before, After, LineSpacingRule, LineSpacing, Alignment, WidowControl, KeepWithNext, KeepTogether, PageBreak, NoLineNum, DontHyphen, Tab, FirstIndent, OutlineLevel, Kinsoku, WordWrap, OverflowPunct, TopLinePunct, AutoSpaceDE, LineHeightGrid, AutoSpaceDN, CharAlign, CharacterUnitLeftIndent, AdjustRight, CharacterUnitFirstIndent, CharacterUnitRightIndent, LineUnitBefore, LineUnitAfter, NoSpaceBetweenParagraphsOfSameStyle, OrientationBi
        self.globals["wdDialogFormatDefineStylePara".lower()] = 182
        #  Position, DefTabs, Align, Leader, Set, Clear, ClearAll
        self.globals["wdDialogFormatDefineStyleTabs".lower()] = 183
        #  Left, PositionHorzRel, Top, PositionVertRel, LockAnchor, FloatOverText, LayoutInCell, WrapSide, TopDistanceFromText, BottomDistanceFromText, LeftDistanceFromText, RightDistanceFromText, Wrap, WordWrap, AutoSize, HRWidthType, HRHeight, HRNoshade, HRAlign, Text, AllowOverlap, HorizRule
        self.globals["wdDialogFormatDrawingObject".lower()] = 960
        #  Position, Font, DropHeight, DistFromText
        self.globals["wdDialogFormatDropCap".lower()] = 488
        #  Style, Text, Enclosure
        self.globals["wdDialogFormatEncloseCharacters".lower()] = 1162
        #  Points, Underline, Color, StrikeThrough, Superscript, Subscript, Hidden, SmallCaps, AllCaps, Spacing, Position, Kerning, KerningMin, Default, Tab, Font, Bold, Italic, DoubleStrikeThrough, Shadow, Outline, Emboss, Engrave, Scale, Animations, CharAccent, FontMajor, FontLowAnsi, FontHighAnsi, CharacterWidthGrid, ColorRGB, UnderlineColor, PointsBi, ColorBi, FontNameBi, BoldBi, ItalicBi, DiacColor
        self.globals["wdDialogFormatFont".lower()] = 174
        #  Wrap, WidthRule, FixedWidth, HeightRule, FixedHeight, PositionHorz, PositionHorzRel, DistFromText, PositionVert, PositionVertRel, DistVertFromText, MoveWithText, LockAnchor, RemoveFrame
        self.globals["wdDialogFormatFrame".lower()] = 190
        #  ChapterNumber, NumRestart, NumFormat, StartingNum, Level, Separator, DoubleQuote, PgNumberingStyle
        self.globals["wdDialogFormatPageNumber".lower()] = 298
        #  LeftIndent, RightIndent, Before, After, LineSpacingRule, LineSpacing, Alignment, WidowControl, KeepWithNext, KeepTogether, PageBreak, NoLineNum, DontHyphen, Tab, FirstIndent, OutlineLevel, Kinsoku, WordWrap, OverflowPunct, TopLinePunct, AutoSpaceDE, LineHeightGrid, AutoSpaceDN, CharAlign, CharacterUnitLeftIndent, AdjustRight, CharacterUnitFirstIndent, CharacterUnitRightIndent, LineUnitBefore, LineUnitAfter, NoSpaceBetweenParagraphsOfSameStyle, OrientationBi
        self.globals["wdDialogFormatParagraph".lower()] = 175
        #  SetSize, CropLeft, CropRight, CropTop, CropBottom, ScaleX, ScaleY, SizeX, SizeY
        self.globals["wdDialogFormatPicture".lower()] = 187
        #  Points, Underline, Color, StrikeThrough, Superscript, Subscript, Hidden, SmallCaps, AllCaps, Spacing, Position, Kerning, KerningMin, Default, Tab, Font, Bold, Italic, DoubleStrikeThrough, Shadow, Outline, Emboss, Engrave, Scale, Animations, CharAccent, FontMajor, FontLowAnsi, FontHighAnsi, CharacterWidthGrid, ColorRGB, UnderlineColor, PointsBi, ColorBi, FontNameBi, BoldBi, ItalicBi, DiacColor
        self.globals["wdDialogFormatRetAddrFonts".lower()] = 221
        #  SectionStart, VertAlign, Endnotes, LineNum, StartingNum, FromText, CountBy, NumMode, SectionType
        self.globals["wdDialogFormatSectionLayout".lower()] = 176
        #  Name, Delete, Merge, NewName, BasedOn, NextStyle, Type, FileName, Source, AddToTemplate, Define, Rename, Apply, New, Link
        self.globals["wdDialogFormatStyle".lower()] = 180
        #  Template, Preview
        self.globals["wdDialogFormatStyleGallery".lower()] = 505
        #  (none)
        self.globals["wdDialogFormatStylesCustom".lower()] = 1248
        #  Position, DefTabs, Align, Leader, Set, Clear, ClearAll
        self.globals["wdDialogFormatTabs".lower()] = 179
        #  (none)
        self.globals["wdDialogFormatTheme".lower()] = 855
        #  (none)
        self.globals["wdDialogFormattingRestrictions".lower()] = 1427
        #  (none)
        self.globals["wdDialogFormFieldHelp".lower()] = 361
        #  Entry, Exit, Name, Enable, TextType, TextWidth, TextDefault, TextFormat, CheckSize, CheckWidth, CheckDefault, Type, OwnHelp, HelpText, OwnStat, StatText, Calculate
        self.globals["wdDialogFormFieldOptions".lower()] = 353
        #  (none)
        self.globals["wdDialogFrameSetProperties".lower()] = 1074
        #  APPNAME, APPCOPYRIGHT, APPUSERNAME, APPORGANIZATION, APPSERIALNUMBER
        self.globals["wdDialogHelpAbout".lower()] = 9
        #  WPCommand, HelpText, DemoGuidance
        self.globals["wdDialogHelpWordPerfectHelp".lower()] = 10
        #  CommandKeyHelp, DocNavKeys, MouseSimulation, DemoGuidance, DemoSpeed, HelpType
        self.globals["wdDialogHelpWordPerfectHelpOptions".lower()] = 511
        #  (none)
        self.globals["wdDialogHorizontalInVertical".lower()] = 1160
        #  (none)
        self.globals["wdDialogIMESetDefault".lower()] = 1094
        #  Name
        self.globals["wdDialogInsertAddCaption".lower()] = 402
        #  Clear, ClearAll, Object, Label, Position
        self.globals["wdDialogInsertAutoCaption".lower()] = 359
        #  Name, SortBy, Add, Delete, Goto, Hidden
        self.globals["wdDialogInsertBookmark".lower()] = 168
        #  Type
        self.globals["wdDialogInsertBreak".lower()] = 159
        #  Label, TitleAutoText, Title, Delete, Position, AutoCaption, ExcludeLabel
        self.globals["wdDialogInsertCaption".lower()] = 357
        #  Label, FormatNumber, ChapterNumber, Level, Separator, CapNumberingStyle
        self.globals["wdDialogInsertCaptionNumbering".lower()] = 358
        #  ReferenceType, ReferenceKind, ReferenceItem, InsertAsHyperLink, InsertPosition, SeparateNumbers, SeparatorCharacters
        self.globals["wdDialogInsertCrossReference".lower()] = 367
        #  Format, Style, LinkToSource, Connection, SQLStatement, SQLStatement1, PasswordDoc, PasswordDot, DataSource, From, To, IncludeFields, WritePasswordDoc, WritePasswordDot
        self.globals["wdDialogInsertDatabase".lower()] = 341
        #  DateTimePic, InsertAsField, DbCharField, DateLanguage, CalendarType
        self.globals["wdDialogInsertDateTime".lower()] = 165
        #  Field
        self.globals["wdDialogInsertField".lower()] = 166
        #  Name, Range, ConfirmConversions, Link, Attachment
        self.globals["wdDialogInsertFile".lower()] = 164
        #  Reference, NoteType, Symbol, FootNumberAs, EndNumberAs, FootnotesAt, EndnotesAt, FootNumberingStyle, EndNumberingStyle, FootStartingNum, FootRestartNum, EndStartingNum, EndRestartNum, ApplyPropsTo
        self.globals["wdDialogInsertFootnote".lower()] = 370
        #  Entry, Exit, Name, Enable, TextType, TextWidth, TextDefault, TextFormat, CheckSize, CheckWidth, CheckDefault, Type, OwnHelp, HelpText, OwnStat, StatText, Calculate
        self.globals["wdDialogInsertFormField".lower()] = 483
        #  (none)
        self.globals["wdDialogInsertHyperlink".lower()] = 925
        #  Outline, Fields, From, To, TableId, AddedStyles, Caption, HeadingSeparator, Replace, MarkEntry, AutoMark, MarkCitation, Type, RightAlignPageNumbers, Passim, KeepFormatting, Columns, Category, Label, ShowPageNumbers, AccentedLetters, Filter, SortBy, Leader, TOCUseHyperlinks, TOCHidePageNumInWeb, IndexLanguage, UseOutlineLevel
        self.globals["wdDialogInsertIndex".lower()] = 170
        #  Outline, Fields, From, To, TableId, AddedStyles, Caption, HeadingSeparator, Replace, MarkEntry, AutoMark, MarkCitation, Type, RightAlignPageNumbers, Passim, KeepFormatting, Columns, Category, Label, ShowPageNumbers, AccentedLetters, Filter, SortBy, Leader, TOCUseHyperlinks, TOCHidePageNumInWeb, IndexLanguage, UseOutlineLevel
        self.globals["wdDialogInsertIndexAndTables".lower()] = 473
        #  MergeField, WordField
        self.globals["wdDialogInsertMergeField".lower()] = 167
        #  NumPic
        self.globals["wdDialogInsertNumber".lower()] = 812
        #  IconNumber, FileName, Link, DisplayIcon, Tab, Class, IconFileName, Caption, Floating
        self.globals["wdDialogInsertObject".lower()] = 172
        #  Type, Position, FirstPage
        self.globals["wdDialogInsertPageNumbers".lower()] = 294
        #  Name, LinkToFile, New, FloatOverText
        self.globals["wdDialogInsertPicture".lower()] = 163
        #  (none)
        self.globals["wdDialogInsertPlaceholder".lower()] = 2348
        #  (none)
        self.globals["wdDialogInsertSource".lower()] = 2120
        #  Name, ConfirmConversions, ReadOnly, LinkToSource, AddToMru, PasswordDoc, PasswordDot, Revert, WritePasswordDoc, WritePasswordDot, Connection, SQLStatement, SQLStatement1, Format, Encoding, Visible, OpenExclusive, OpenAndRepair, SubType, DocumentDirection, NoEncodingDialog, XMLTransform
        self.globals["wdDialogInsertSubdocument".lower()] = 583
        #  Font, Tab, CharNum, CharNumLow, Unicode, Hint
        self.globals["wdDialogInsertSymbol".lower()] = 162
        #  Outline, Fields, From, To, TableId, AddedStyles, Caption, HeadingSeparator, Replace, MarkEntry, AutoMark, MarkCitation, Type, RightAlignPageNumbers, Passim, KeepFormatting, Columns, Category, Label, ShowPageNumbers, AccentedLetters, Filter, SortBy, Leader, TOCUseHyperlinks, TOCHidePageNumInWeb, IndexLanguage, UseOutlineLevel
        self.globals["wdDialogInsertTableOfAuthorities".lower()] = 471
        #  Outline, Fields, From, To, TableId, AddedStyles, Caption, HeadingSeparator, Replace, MarkEntry, AutoMark, MarkCitation, Type, RightAlignPageNumbers, Passim, KeepFormatting, Columns, Category, Label, ShowPageNumbers, AccentedLetters, Filter, SortBy, Leader, TOCUseHyperlinks, TOCHidePageNumInWeb, IndexLanguage, UseOutlineLevel
        self.globals["wdDialogInsertTableOfContents".lower()] = 171
        #  Outline, Fields, From, To, TableId, AddedStyles, Caption, HeadingSeparator, Replace, MarkEntry, AutoMark, MarkCitation, Type, RightAlignPageNumbers, Passim, KeepFormatting, Columns, Category, Label, ShowPageNumbers, AccentedLetters, Filter, SortBy, Leader, TOCUseHyperlinks, TOCHidePageNumInWeb, IndexLanguage, UseOutlineLevel
        self.globals["wdDialogInsertTableOfFigures".lower()] = 472
        #  IconNumber, FileName, Link, DisplayIcon, Tab, Class, IconFileName, Caption, Floating
        self.globals["wdDialogInsertWebComponent".lower()] = 1324
        #  (none)
        self.globals["wdDialogLabelOptions".lower()] = 1367
        #  SenderCity, DateFormat, IncludeHeaderFooter, LetterStyle, Letterhead, LetterheadLocation, LetterheadSize, RecipientName, RecipientAddress, Salutation, SalutationType, RecipientGender, RecipientReference, MailingInstructions, AttentionLine, LetterSubject, CCList, SenderName, ReturnAddress, Closing, SenderJobTitle, SenderCompany, SenderInitials, EnclosureNumber, PageDesign, InfoBlock, SenderGender, ReturnAddressSF, RecipientCode, SenderCode, SenderReference
        self.globals["wdDialogLetterWizard".lower()] = 821
        #  ListType
        self.globals["wdDialogListCommands".lower()] = 723
        #  CheckErrors, Destination, MergeRecords, From, To, Suppression, MailMerge, QueryOptions, MailSubject, MailAsAttachment, MailAddress
        self.globals["wdDialogMailMerge".lower()] = 676
        #  CheckErrors
        self.globals["wdDialogMailMergeCheck".lower()] = 677
        #  FileName, PasswordDoc, PasswordDot, HeaderRecord, MSQuery, SQLStatement, SQLStatement1, Connection, LinkToSource, WritePasswordDoc
        self.globals["wdDialogMailMergeCreateDataSource".lower()] = 642
        #  FileName, PasswordDoc, PasswordDot, HeaderRecord, MSQuery, SQLStatement, SQLStatement1, Connection, LinkToSource, WritePasswordDoc
        self.globals["wdDialogMailMergeCreateHeaderSource".lower()] = 643
        #  (none)
        self.globals["wdDialogMailMergeFieldMapping".lower()] = 1304
        #  (none)
        self.globals["wdDialogMailMergeFindRecipient".lower()] = 1326
        #  (none)
        self.globals["wdDialogMailMergeFindRecord".lower()] = 569
        #  (none)
        self.globals["wdDialogMailMergeHelper".lower()] = 680
        #  (none)
        self.globals["wdDialogMailMergeInsertAddressBlock".lower()] = 1305
        #  (none)
        self.globals["wdDialogMailMergeInsertAsk".lower()] = 4047
        #  (none)
        self.globals["wdDialogMailMergeInsertFields".lower()] = 1307
        #  (none)
        self.globals["wdDialogMailMergeInsertFillIn".lower()] = 4048
        #  (none)
        self.globals["wdDialogMailMergeInsertGreetingLine".lower()] = 1306
        #  (none)
        self.globals["wdDialogMailMergeInsertIf".lower()] = 4049
        #  (none)
        self.globals["wdDialogMailMergeInsertNextIf".lower()] = 4053
        #  (none)
        self.globals["wdDialogMailMergeInsertSet".lower()] = 4054
        #  (none)
        self.globals["wdDialogMailMergeInsertSkipIf".lower()] = 4055
        #  (none)
        self.globals["wdDialogMailMergeOpenDataSource".lower()] = 81
        #  (none)
        self.globals["wdDialogMailMergeOpenHeaderSource".lower()] = 82
        #  (none)
        self.globals["wdDialogMailMergeQueryOptions".lower()] = 681
        #  (none)
        self.globals["wdDialogMailMergeRecipients".lower()] = 1308
        #  (none)
        self.globals["wdDialogMailMergeSetDocumentType".lower()] = 1339
        #  (none)
        self.globals["wdDialogMailMergeUseAddressBook".lower()] = 779
        #  (none)
        self.globals["wdDialogMarkCitation".lower()] = 463
        #  (none)
        self.globals["wdDialogMarkIndexEntry".lower()] = 169
        #  (none)
        self.globals["wdDialogMarkTableOfContentsEntry".lower()] = 442
        #  (none)
        self.globals["wdDialogMyPermission".lower()] = 1437
        #  (none)
        self.globals["wdDialogNewToolbar".lower()] = 586
        #  (none)
        self.globals["wdDialogNoteOptions".lower()] = 373
        #  (none)
        self.globals["wdDialogOMathRecognizedFunctions".lower()] = 2165
        #  (none)
        self.globals["wdDialogOrganizer".lower()] = 222
        #  (none)
        self.globals["wdDialogPermission".lower()] = 1469
        #  (none)
        self.globals["wdDialogPhoneticGuide".lower()] = 986
        #  (none)
        self.globals["wdDialogReviewAfmtRevisions".lower()] = 570
        #  (none)
        self.globals["wdDialogSchemaLibrary".lower()] = 1417
        #  (none)
        self.globals["wdDialogSearch".lower()] = 1363
        #  (none)
        self.globals["wdDialogShowRepairs".lower()] = 1381
        #  (none)
        self.globals["wdDialogSourceManager".lower()] = 1920
        #  (none)
        self.globals["wdDialogStyleManagement".lower()] = 1948
        #  (none)
        self.globals["wdDialogTableAutoFormat".lower()] = 563
        #  (none)
        self.globals["wdDialogTableCellOptions".lower()] = 1081
        #  (none)
        self.globals["wdDialogTableColumnWidth".lower()] = 143
        #  (none)
        self.globals["wdDialogTableDeleteCells".lower()] = 133
        #  (none)
        self.globals["wdDialogTableFormatCell".lower()] = 612
        #  (none)
        self.globals["wdDialogTableFormula".lower()] = 348
        #  (none)
        self.globals["wdDialogTableInsertCells".lower()] = 130
        #  (none)
        self.globals["wdDialogTableInsertRow".lower()] = 131
        #  (none)
        self.globals["wdDialogTableInsertTable".lower()] = 129
        #  (none)
        self.globals["wdDialogTableOfCaptionsOptions".lower()] = 551
        #  (none)
        self.globals["wdDialogTableOfContentsOptions".lower()] = 470
        #  (none)
        self.globals["wdDialogTableProperties".lower()] = 861
        #  (none)
        self.globals["wdDialogTableRowHeight".lower()] = 142
        #  (none)
        self.globals["wdDialogTableSort".lower()] = 199
        #  (none)
        self.globals["wdDialogTableSplitCells".lower()] = 137
        #  (none)
        self.globals["wdDialogTableTableOptions".lower()] = 1080
        #  (none)
        self.globals["wdDialogTableToText".lower()] = 128
        #  (none)
        self.globals["wdDialogTableWrapping".lower()] = 854
        #  (none)
        self.globals["wdDialogTCSCTranslator".lower()] = 1156
        #  (none)
        self.globals["wdDialogTextToTable".lower()] = 127
        #  (none)
        self.globals["wdDialogToolsAcceptRejectChanges".lower()] = 506
        #  (none)
        self.globals["wdDialogToolsAdvancedSettings".lower()] = 206
        #  (none)
        self.globals["wdDialogToolsAutoCorrect".lower()] = 378
        #  (none)
        self.globals["wdDialogToolsAutoCorrectExceptions".lower()] = 762
        #  (none)
        self.globals["wdDialogToolsAutoManager".lower()] = 915
        #  (none)
        self.globals["wdDialogToolsAutoSummarize".lower()] = 874
        #  (none)
        self.globals["wdDialogToolsBulletsNumbers".lower()] = 196
        #  (none)
        self.globals["wdDialogToolsCompareDocuments".lower()] = 198
        #  (none)
        self.globals["wdDialogToolsCreateDirectory".lower()] = 833
        #  (none)
        self.globals["wdDialogToolsCreateEnvelope".lower()] = 173
        #  (none)
        self.globals["wdDialogToolsCreateLabels".lower()] = 489
        #  (none)
        self.globals["wdDialogToolsCustomize".lower()] = 152
        #  (none)
        self.globals["wdDialogToolsCustomizeKeyboard".lower()] = 432
        #  (none)
        self.globals["wdDialogToolsCustomizeMenuBar".lower()] = 615
        #  (none)
        self.globals["wdDialogToolsCustomizeMenus".lower()] = 433
        #  (none)
        self.globals["wdDialogToolsDictionary".lower()] = 989
        #  (none)
        self.globals["wdDialogToolsEnvelopesAndLabels".lower()] = 607
        #  (none)
        self.globals["wdDialogToolsGrammarSettings".lower()] = 885
        #  (none)
        self.globals["wdDialogToolsHangulHanjaConversion".lower()] = 784
        #  (none)
        self.globals["wdDialogToolsHighlightChanges".lower()] = 197
        #  (none)
        self.globals["wdDialogToolsHyphenation".lower()] = 195
        #  (none)
        self.globals["wdDialogToolsLanguage".lower()] = 188
        #  (none)
        self.globals["wdDialogToolsMacro".lower()] = 215
        #  (none)
        self.globals["wdDialogToolsMacroRecord".lower()] = 214
        #  (none)
        self.globals["wdDialogToolsManageFields".lower()] = 631
        #  (none)
        self.globals["wdDialogToolsMergeDocuments".lower()] = 435
        #  (none)
        self.globals["wdDialogToolsOptions".lower()] = 974
        #  (none)
        self.globals["wdDialogToolsOptionsAutoFormat".lower()] = 959
        #  (none)
        self.globals["wdDialogToolsOptionsAutoFormatAsYouType".lower()] = 778
        #  (none)
        self.globals["wdDialogToolsOptionsBidi".lower()] = 1029
        #  (none)
        self.globals["wdDialogToolsOptionsCompatibility".lower()] = 525
        #  (none)
        self.globals["wdDialogToolsOptionsEdit".lower()] = 224
        #  (none)
        self.globals["wdDialogToolsOptionsEditCopyPaste".lower()] = 1356
        #  (none)
        self.globals["wdDialogToolsOptionsFileLocations".lower()] = 225
        #  (none)
        self.globals["wdDialogToolsOptionsFuzzy".lower()] = 790
        #  (none)
        self.globals["wdDialogToolsOptionsGeneral".lower()] = 203
        #  (none)
        self.globals["wdDialogToolsOptionsPrint".lower()] = 208
        #  (none)
        self.globals["wdDialogToolsOptionsSave".lower()] = 209
        #  (none)
        self.globals["wdDialogToolsOptionsSecurity".lower()] = 1361
        #  (none)
        self.globals["wdDialogToolsOptionsSmartTag".lower()] = 1395
        #  (none)
        self.globals["wdDialogToolsOptionsSpellingAndGrammar".lower()] = 211
        #  (none)
        self.globals["wdDialogToolsOptionsTrackChanges".lower()] = 386
        #  (none)
        self.globals["wdDialogToolsOptionsTypography".lower()] = 739
        #  (none)
        self.globals["wdDialogToolsOptionsUserInfo".lower()] = 213
        #  (none)
        self.globals["wdDialogToolsOptionsView".lower()] = 204
        #  (none)
        self.globals["wdDialogToolsProtectDocument".lower()] = 503
        #  (none)
        self.globals["wdDialogToolsProtectSection".lower()] = 578
        #  (none)
        self.globals["wdDialogToolsRevisions".lower()] = 197
        #  (none)
        self.globals["wdDialogToolsSpellingAndGrammar".lower()] = 828
        #  (none)
        self.globals["wdDialogToolsTemplates".lower()] = 87
        #  (none)
        self.globals["wdDialogToolsThesaurus".lower()] = 194
        #  (none)
        self.globals["wdDialogToolsUnprotectDocument".lower()] = 521
        #  (none)
        self.globals["wdDialogToolsWordCount".lower()] = 228
        #  (none)
        self.globals["wdDialogTwoLinesInOne".lower()] = 1161
        #  (none)
        self.globals["wdDialogUpdateTOC".lower()] = 331
        #  (none)
        self.globals["wdDialogViewZoom".lower()] = 577
        #  (none)
        self.globals["wdDialogWebOptions".lower()] = 898
        #  (none)
        self.globals["wdDialogWindowActivate".lower()] = 220
        #  (none)
        self.globals["wdDialogXMLElementAttributes".lower()] = 1460
        #  (none)
        self.globals["wdDialogXMLOptions".lower()] = 1425
        
        # WdWordDialogTab enumeration (Word)
        #   
        # Specifies the active tab when the specified dialog box is displayed.
        
        #  General tab of the Email Options dialog box.
        self.globals["wdDialogEmailOptionsTabQuoting".lower()] = 1900002
        #  Email Signature tab of the Email Options dialog box.
        self.globals["wdDialogEmailOptionsTabSignature".lower()] = 1900000
        #  Personal Stationary tab of the Email Options dialog box.
        self.globals["wdDialogEmailOptionsTabStationary".lower()] = 1900001
        #  Margins tab of the Page Setup dialog box, with Apply To drop-down list active.
        self.globals["wdDialogFilePageSetupTabCharsLines".lower()] = 150004
        #  Layout tab of the Page Setup dialog box.
        self.globals["wdDialogFilePageSetupTabLayout".lower()] = 150003
        #  Margins tab of the Page Setup dialog box.
        self.globals["wdDialogFilePageSetupTabMargins".lower()] = 150000
        #  Paper tab of the Page Setup dialog box.
        self.globals["wdDialogFilePageSetupTabPaper".lower()] = 150001
        #  Borders tab of the Borders dialog box.
        self.globals["wdDialogFormatBordersAndShadingTabBorders".lower()] = 700000
        #  Page Border tab of the Borders dialog box.
        self.globals["wdDialogFormatBordersAndShadingTabPageBorder".lower()] = 700001
        #  Shading tab of the Borders dialog box.
        self.globals["wdDialogFormatBordersAndShadingTabShading".lower()] = 700002
        #  Bulleted tab of the Bullets and Numbering dialog box.
        self.globals["wdDialogFormatBulletsAndNumberingTabBulleted".lower()] = 1500000
        #  Numbered tab of the Bullets and Numbering dialog box.
        self.globals["wdDialogFormatBulletsAndNumberingTabNumbered".lower()] = 1500001
        #  Outline Numbered tab of the Bullets and Numbering dialog box.
        self.globals["wdDialogFormatBulletsAndNumberingTabOutlineNumbered".lower()] = 1500002
        #  Colors and Lines tab of the Format Drawing Object dialog box.
        self.globals["wdDialogFormatDrawingObjectTabColorsAndLines".lower()] = 1200000
        #  Colors and Lines tab of the Format Drawing Object dialog box.
        self.globals["wdDialogFormatDrawingObjectTabHR".lower()] = 1200007
        #  Picture tab of the Format Drawing Object dialog box.
        self.globals["wdDialogFormatDrawingObjectTabPicture".lower()] = 1200004
        #  Position tab of the Format Drawing Object dialog box.
        self.globals["wdDialogFormatDrawingObjectTabPosition".lower()] = 1200002
        #  Size tab of the Format Drawing Object dialog box.
        self.globals["wdDialogFormatDrawingObjectTabSize".lower()] = 1200001
        #  Textbox tab of the Format Drawing Object dialog box.
        self.globals["wdDialogFormatDrawingObjectTabTextbox".lower()] = 1200005
        #  Web tab of the Format Drawing Object dialog box.
        self.globals["wdDialogFormatDrawingObjectTabWeb".lower()] = 1200006
        #  Wrapping tab of the Format Drawing Object dialog box.
        self.globals["wdDialogFormatDrawingObjectTabWrapping".lower()] = 1200003
        #  Animation tab of the Font dialog box.
        self.globals["wdDialogFormatFontTabAnimation".lower()] = 600002
        #  Character Spacing tab of the Font dialog box.
        self.globals["wdDialogFormatFontTabCharacterSpacing".lower()] = 600001
        #  Font tab of the Font dialog box.
        self.globals["wdDialogFormatFontTabFont".lower()] = 600000
        #  Indents and Spacing tab of the Paragraph dialog box.
        self.globals["wdDialogFormatParagraphTabIndentsAndSpacing".lower()] = 1000000
        #  Line and Page Breaks tab of the Paragraph dialog box, with choices appropriate for Asian text.
        self.globals["wdDialogFormatParagraphTabTeisai".lower()] = 1000002
        #  Line and Page Breaks tab of the Paragraph dialog box.
        self.globals["wdDialogFormatParagraphTabTextFlow".lower()] = 1000001
        #  Index tab of the Index and Tables dialog box.
        self.globals["wdDialogInsertIndexAndTablesTabIndex".lower()] = 400000
        #  Table of Authorities tab of the Index and Tables dialog box.
        self.globals["wdDialogInsertIndexAndTablesTabTableOfAuthorities".lower()] = 400003
        #  Table of Contents tab of the Index and Tables dialog box.
        self.globals["wdDialogInsertIndexAndTablesTabTableOfContents".lower()] = 400001
        #  Table of Figures tab of the Index and Tables dialog box.
        self.globals["wdDialogInsertIndexAndTablesTabTableOfFigures".lower()] = 400002
        #  Special Characters tab of the Symbol dialog box.
        self.globals["wdDialogInsertSymbolTabSpecialCharacters".lower()] = 200001
        #  Symbols tab of the Symbol dialog box.
        self.globals["wdDialogInsertSymbolTabSymbols".lower()] = 200000
        #  Letter Format tab of the Letter Wizard dialog box.
        self.globals["wdDialogLetterWizardTabLetterFormat".lower()] = 1600000
        #  Other Elements tab of the Letter Wizard dialog box.
        self.globals["wdDialogLetterWizardTabOtherElements".lower()] = 1600002
        #  Recipient Info tab of the Letter Wizard dialog box.
        self.globals["wdDialogLetterWizardTabRecipientInfo".lower()] = 1600001
        #  Sender Info tab of the Letter Wizard dialog box.
        self.globals["wdDialogLetterWizardTabSenderInfo".lower()] = 1600003
        #  All Endnotes tab of the Note Options dialog box.
        self.globals["wdDialogNoteOptionsTabAllEndnotes".lower()] = 300001
        #  All Footnotes tab of the Note Options dialog box.
        self.globals["wdDialogNoteOptionsTabAllFootnotes".lower()] = 300000
        #  AutoText tab of the Organizer dialog box.
        self.globals["wdDialogOrganizerTabAutoText".lower()] = 500001
        #  Command Bars tab of the Organizer dialog box.
        self.globals["wdDialogOrganizerTabCommandBars".lower()] = 500002
        #  Macros tab of the Organizer dialog box.
        self.globals["wdDialogOrganizerTabMacros".lower()] = 500003
        #  Styles tab of the Organizer dialog box.
        self.globals["wdDialogOrganizerTabStyles".lower()] = 500000
        #  Cell tab of the Table Properties dialog box.
        self.globals["wdDialogTablePropertiesTabCell".lower()] = 1800003
        #  Column tab of the Table Properties dialog box.
        self.globals["wdDialogTablePropertiesTabColumn".lower()] = 1800002
        #  Row tab of the Table Properties dialog box.
        self.globals["wdDialogTablePropertiesTabRow".lower()] = 1800001
        #  Table tab of the Table Properties dialog box.
        self.globals["wdDialogTablePropertiesTabTable".lower()] = 1800000
        #  Templates tab of the Templates and Add-ins dialog box.
        self.globals["wdDialogTemplates".lower()] = 2100000
        #  Linked CSS tab of the Templates and Add-ins dialog box.
        self.globals["wdDialogTemplatesLinkedCSS".lower()] = 2100003
        #  XML Expansion Packs tab of the Templates and Add-ins dialog box.
        self.globals["wdDialogTemplatesXMLExpansionPacks".lower()] = 2100002
        #  XML Schema tab of the Templates and Add-ins dialog box.
        self.globals["wdDialogTemplatesXMLSchema".lower()] = 2100001
        #  First Letter tab of the AutoCorrect Exceptions dialog box.
        self.globals["wdDialogToolsAutoCorrectExceptionsTabFirstLetter".lower()] = 1400000
        #  Hangul and Alphabet tab of the AutoCorrect Exceptions dialog box. Available only in multi-language versions.
        self.globals["wdDialogToolsAutoCorrectExceptionsTabHangulAndAlphabet".lower()] = 1400002
        #  Other Corrections tab of the AutoCorrect Exceptions dialog box.
        self.globals["wdDialogToolsAutoCorrectExceptionsTabIac".lower()] = 1400003
        #  Initial Caps tab of the AutoCorrect Exceptions dialog box.
        self.globals["wdDialogToolsAutoCorrectExceptionsTabInitialCaps".lower()] = 1400001
        #  AutoCorrect tab of the AutoCorrect dialog box.
        self.globals["wdDialogToolsAutoManagerTabAutoCorrect".lower()] = 1700000
        #  AutoFormat tab of the AutoCorrect dialog box.
        self.globals["wdDialogToolsAutoManagerTabAutoFormat".lower()] = 1700003
        #  Format As You Type tab of the AutoCorrect dialog box.
        self.globals["wdDialogToolsAutoManagerTabAutoFormatAsYouType".lower()] = 1700001
        #  AutoText tab of the AutoCorrect dialog box.
        self.globals["wdDialogToolsAutoManagerTabAutoText".lower()] = 1700002
        #  Smart Tags tab of the AutoCorrect dialog box.
        self.globals["wdDialogToolsAutoManagerTabSmartTags".lower()] = 1700004
        #  Envelopes tab of the Envelopes and Labels dialog box.
        self.globals["wdDialogToolsEnvelopesAndLabelsTabEnvelopes".lower()] = 800000
        #  Labels tab of the Envelopes and Labels dialog box.
        self.globals["wdDialogToolsEnvelopesAndLabelsTabLabels".lower()] = 800001
        #  Not supported.
        self.globals["wdDialogToolsOptionsTabAcetate".lower()] = 1266
        #  Complex Scripts tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabBidi".lower()] = 1029
        #  Compatibility tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabCompatibility".lower()] = 525
        #  Edit tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabEdit".lower()] = 224
        #  File Locations tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabFileLocations".lower()] = 225
        #  Not supported.
        self.globals["wdDialogToolsOptionsTabFuzzy".lower()] = 790
        #  General tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabGeneral".lower()] = 203
        #  Hangul Hanja Conversion tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabHangulHanjaConversion".lower()] = 786
        #  Print tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabPrint".lower()] = 208
        #  Spelling and Grammar tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabProofread".lower()] = 211
        #  Save tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabSave".lower()] = 209
        #  Security tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabSecurity".lower()] = 1361
        #  Track Changes tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabTrackChanges".lower()] = 386
        #  Asian Typography tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabTypography".lower()] = 739
        #  User Information tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabUserInfo".lower()] = 213
        #  View tab of the Options dialog box.
        self.globals["wdDialogToolsOptionsTabView".lower()] = 204
        #  Browsers tab of the Web Options dialog box.
        self.globals["wdDialogWebOptionsBrowsers".lower()] = 2000000
        #  Encoding tab of the Web Options dialog box.
        self.globals["wdDialogWebOptionsEncoding".lower()] = 2000003
        #  Files tab of the Web Options dialog box.
        self.globals["wdDialogWebOptionsFiles".lower()] = 2000001
        #  Fonts tab of the Web Options dialog box.
        self.globals["wdDialogWebOptionsFonts".lower()] = 2000004
        #  General tab of the Web Options dialog box.
        self.globals["wdDialogWebOptionsGeneral".lower()] = 2000000
        #  Pictures tab of the Web Options dialog box.
        self.globals["wdDialogWebOptionsPictures".lower()] = 2000002
        #  Edit tab of the Style Management dialog box.
        self.globals["wdDialogStyleManagementTabEdit".lower()] = 2200000
        #  Recommend tab of the Style Management dialog box.
        self.globals["wdDialogStyleManagementTabRecommend".lower()] = 2200001
        #  Restrict tab of the Style Management dialog box.
        self.globals["wdDialogStyleManagementTabRestrict".lower()] = 2200002
        
        # WdFarEastLineBreakLevel enumeration (Word)
        #
        # Specifies the line break control level for the specified document.
        
        #  Custom line break control.
        self.globals["wdFarEastLineBreakLevelCustom".lower()] = 2
        #  Normal line break control.
        self.globals["wdFarEastLineBreakLevelNormal".lower()] = 0
        #  Strict line break control.
        self.globals["wdFarEastLineBreakLevelStrict".lower()] = 1
        
        # WdFieldType enumeration (Word)
        #    
        # Specifies a Microsoft Word field. Unless otherwise specified, the field types described in this enumeration can be added interactively to a Word document by using the Field dialog box. See the Word Help for more information about specific field codes.
        
        #  Add-in field. Not available through the Field dialog box. Used to store data that is hidden from the user interface.
        self.globals["wdFieldAddin".lower()] = 81
        #  AddressBlock field.
        self.globals["wdFieldAddressBlock".lower()] = 93
        #  Advance field.
        self.globals["wdFieldAdvance".lower()] = 84
        #  Ask field.
        self.globals["wdFieldAsk".lower()] = 38
        #  Author field.
        self.globals["wdFieldAuthor".lower()] = 17
        #  AutoNum field.
        self.globals["wdFieldAutoNum".lower()] = 54
        #  AutoNumLgl field.
        self.globals["wdFieldAutoNumLegal".lower()] = 53
        #  AutoNumOut field.
        self.globals["wdFieldAutoNumOutline".lower()] = 52
        #  AutoText field.
        self.globals["wdFieldAutoText".lower()] = 79
        #  AutoTextList field.
        self.globals["wdFieldAutoTextList".lower()] = 89
        #  BarCode field.
        self.globals["wdFieldBarCode".lower()] = 63
        #  BidiOutline field.
        self.globals["wdFieldBidiOutline".lower()] = 92
        #  Comments field.
        self.globals["wdFieldComments".lower()] = 19
        #  Compare field.
        self.globals["wdFieldCompare".lower()] = 80
        #  CreateDate field.
        self.globals["wdFieldCreateDate".lower()] = 21
        #  Data field.
        self.globals["wdFieldData".lower()] = 40
        #  Database field.
        self.globals["wdFieldDatabase".lower()] = 78
        #  Date field.
        self.globals["wdFieldDate".lower()] = 31
        #  DDE field. No longer available through the Field dialog box, but supported for documents created in earlier versions of Word.
        self.globals["wdFieldDDE".lower()] = 45
        #  DDEAuto field. No longer available through the Field dialog box, but supported for documents created in earlier versions of Word.
        self.globals["wdFieldDDEAuto".lower()] = 46
        #  DisplayBarcode field.
        self.globals["wdFieldDisplayBarcode".lower()] = 99
        #  DocProperty field.
        self.globals["wdFieldDocProperty".lower()] = 85
        #  DocVariable field.
        self.globals["wdFieldDocVariable".lower()] = 64
        #  EditTime field.
        self.globals["wdFieldEditTime".lower()] = 25
        #  Embedded field.
        self.globals["wdFieldEmbed".lower()] = 58
        #  Empty field. Acts as a placeholder for field content that has not yet been added. A field added by pressing Ctrl+F9 in the user interface is an Empty field.
        self.globals["wdFieldEmpty".lower()] = -1
        #  = (Formula) field.
        self.globals["wdFieldExpression".lower()] = 34
        #  FileName field.
        self.globals["wdFieldFileName".lower()] = 29
        #  FileSize field.
        self.globals["wdFieldFileSize".lower()] = 69
        #  Fill-In field.
        self.globals["wdFieldFillIn".lower()] = 39
        #  FootnoteRef field. Not available through the Field dialog box. Inserted programmatically or interactively.
        self.globals["wdFieldFootnoteRef".lower()] = 5
        #  FormCheckBox field.
        self.globals["wdFieldFormCheckBox".lower()] = 71
        #  FormDropDown field.
        self.globals["wdFieldFormDropDown".lower()] = 83
        #  FormText field.
        self.globals["wdFieldFormTextInput".lower()] = 70
        #  EQ (Equation) field.
        self.globals["wdFieldFormula".lower()] = 49
        #  Glossary field. No longer supported in Word.
        self.globals["wdFieldGlossary".lower()] = 47
        #  GoToButton field.
        self.globals["wdFieldGoToButton".lower()] = 50
        #  GreetingLine field.
        self.globals["wdFieldGreetingLine".lower()] = 94
        #  HTMLActiveX field. Not currently supported.
        self.globals["wdFieldHTMLActiveX".lower()] = 91
        #  Hyperlink field.
        self.globals["wdFieldHyperlink".lower()] = 88
        #  If field.
        self.globals["wdFieldIf".lower()] = 7
        #  Import field. Cannot be added through the Field dialog box, but can be added interactively or through code.
        self.globals["wdFieldImport".lower()] = 55
        #  Include field. Cannot be added through the Field dialog box, but can be added interactively or through code.
        self.globals["wdFieldInclude".lower()] = 36
        #  IncludePicture field.
        self.globals["wdFieldIncludePicture".lower()] = 67
        #  IncludeText field.
        self.globals["wdFieldIncludeText".lower()] = 68
        #  Index field.
        self.globals["wdFieldIndex".lower()] = 8
        #  XE (Index Entry) field.
        self.globals["wdFieldIndexEntry".lower()] = 4
        #  Info field.
        self.globals["wdFieldInfo".lower()] = 14
        #  Keywords field.
        self.globals["wdFieldKeyWord".lower()] = 18
        #  LastSavedBy field.
        self.globals["wdFieldLastSavedBy".lower()] = 20
        #  Link field.
        self.globals["wdFieldLink".lower()] = 56
        #  ListNum field.
        self.globals["wdFieldListNum".lower()] = 90
        #  MacroButton field.
        self.globals["wdFieldMacroButton".lower()] = 51
        #  MergeBarcode field.
        self.globals["wdFieldMergeBarcode".lower()] = 98
        #  MergeField field.
        self.globals["wdFieldMergeField".lower()] = 59
        #  MergeRec field.
        self.globals["wdFieldMergeRec".lower()] = 44
        #  MergeSeq field.
        self.globals["wdFieldMergeSeq".lower()] = 75
        #  Next field.
        self.globals["wdFieldNext".lower()] = 41
        #  NextIf field.
        self.globals["wdFieldNextIf".lower()] = 42
        #  NoteRef field.
        self.globals["wdFieldNoteRef".lower()] = 72
        #  NumChars field.
        self.globals["wdFieldNumChars".lower()] = 28
        #  NumPages field.
        self.globals["wdFieldNumPages".lower()] = 26
        #  NumWords field.
        self.globals["wdFieldNumWords".lower()] = 27
        #  OCX field. Cannot be added through the Field dialog box, but can be added through code by using the AddOLEControl method of the Shapes collection or of the InlineShapes collection.
        self.globals["wdFieldOCX".lower()] = 87
        #  Page field.
        self.globals["wdFieldPage".lower()] = 33
        #  PageRef field.
        self.globals["wdFieldPageRef".lower()] = 37
        #  Print field.
        self.globals["wdFieldPrint".lower()] = 48
        #  PrintDate field.
        self.globals["wdFieldPrintDate".lower()] = 23
        #  Private field.
        self.globals["wdFieldPrivate".lower()] = 77
        #  Quote field.
        self.globals["wdFieldQuote".lower()] = 35
        #  Ref field.
        self.globals["wdFieldRef".lower()] = 3
        #  RD (Reference Document) field.
        self.globals["wdFieldRefDoc".lower()] = 11
        #  RevNum field.
        self.globals["wdFieldRevisionNum".lower()] = 24
        #  SaveDate field.
        self.globals["wdFieldSaveDate".lower()] = 22
        #  Section field.
        self.globals["wdFieldSection".lower()] = 65
        #  SectionPages field.
        self.globals["wdFieldSectionPages".lower()] = 66
        #  Seq (Sequence) field.
        self.globals["wdFieldSequence".lower()] = 12
        #  Set field.
        self.globals["wdFieldSet".lower()] = 6
        #  Shape field. Automatically created for any drawn picture.
        self.globals["wdFieldShape".lower()] = 95
        #  SkipIf field.
        self.globals["wdFieldSkipIf".lower()] = 43
        #  StyleRef field.
        self.globals["wdFieldStyleRef".lower()] = 10
        #  Subject field.
        self.globals["wdFieldSubject".lower()] = 16
        #  Macintosh only. For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdFieldSubscriber".lower()] = 82
        #  Symbol field.
        self.globals["wdFieldSymbol".lower()] = 57
        #  Template field.
        self.globals["wdFieldTemplate".lower()] = 30
        #  Time field.
        self.globals["wdFieldTime".lower()] = 32
        #  Title field.
        self.globals["wdFieldTitle".lower()] = 15
        #  TOA (Table of Authorities) field.
        self.globals["wdFieldTOA".lower()] = 73
        #  TOA (Table of Authorities Entry) field.
        self.globals["wdFieldTOAEntry".lower()] = 74
        #  TOC (Table of Contents) field.
        self.globals["wdFieldTOC".lower()] = 13
        #  TOC (Table of Contents Entry) field.
        self.globals["wdFieldTOCEntry".lower()] = 9
        #  UserAddress field.
        self.globals["wdFieldUserAddress".lower()] = 62
        #  UserInitials field.
        self.globals["wdFieldUserInitials".lower()] = 61
        #  UserName field.
        self.globals["wdFieldUserName".lower()] = 60
        #  Bibliography field.
        self.globals["wdFieldBibliography".lower()] = 97
        #  Citation field.
        self.globals["wdFieldCitation".lower()] = 96
        
        # WdInformation enumeration (Word)
        #
        # Specifies the type of information returned about a specified selection or range.
        
        #  Returns the number of the page that contains the active end of the specified selection or range. If you set a starting page number or make other manual adjustments, returns the adjusted page number (unlike wdActiveEndPageNumber).
        self.globals["wdActiveEndAdjustedPageNumber".lower()] = 1
        #  Returns the number of the page that contains the active end of the specified selection or range, counting from the beginning of the document. Any manual adjustments to page numbering are disregarded (unlike wdActiveEndAdjustedPageNumber).
        self.globals["wdActiveEndPageNumber".lower()] = 3
        #  Returns the number of the section that contains the active end of the specified selection or range.
        self.globals["wdActiveEndSectionNumber".lower()] = 2
        #  Returns True if the specified selection or range is at the end-of-row mark in a table.
        self.globals["wdAtEndOfRowMarker".lower()] = 31
        #  Returns True if Caps Lock is in effect.
        self.globals["wdCapsLock".lower()] = 21
        #  Returns the table column number that contains the end of the specified selection or range.
        self.globals["wdEndOfRangeColumnNumber".lower()] = 17
        #  Returns the table row number that contains the end of the specified selection or range.
        self.globals["wdEndOfRangeRowNumber".lower()] = 14
        #  Returns the character position of the first character in the specified selection or range. If the selection or range is collapsed, the character number immediately to the right of the range or selection is returned (this is the same as the character column number displayed in the status bar after "Col").
        self.globals["wdFirstCharacterColumnNumber".lower()] = 9
        #  Returns the character position of the first character in the specified selection or range. If the selection or range is collapsed, the character number immediately to the right of the range or selection is returned (this is the same as the character line number displayed in the status bar after "Ln").
        self.globals["wdFirstCharacterLineNumber".lower()] = 10
        #  Returns True if the selection or range is an entire frame or text box.
        self.globals["wdFrameIsSelected".lower()] = 11
        #  Returns a value that indicates the type of header or footer that contains the specified selection or range. See the table in the remarks section for additional information.
        self.globals["wdHeaderFooterType".lower()] = 33
        #  Returns the horizontal position of the specified selection or range; this is the distance from the left edge of the selection or range to the left edge of the page measured in points (1 point = 20 twips, 72 points = 1 inch). If the selection or range isn't within the screen area, returns -1.
        self.globals["wdHorizontalPositionRelativeToPage".lower()] = 5
        #  Returns the horizontal position of the specified selection or range relative to the left edge of the nearest text boundary enclosing it, in points (1 point = 20 twips, 72 points = 1 inch). If the selection or range isn't within the screen area, returns -1.
        self.globals["wdHorizontalPositionRelativeToTextBoundary".lower()] = 7
        #  Returns True if the specified selection or range is in a bibliography.
        self.globals["wdInBibliography".lower()] = 42
        #  Returns True if the specified selection or range is in a citation.
        self.globals["wdInCitation".lower()] = 43
        #  For information about this constant, consult the language reference Help included with Microsoft Office Macintosh Edition.
        self.globals["wdInClipboard".lower()] = 38
        #  Returns True if the specified selection or range is in a comment pane.
        self.globals["wdInCommentPane".lower()] = 26
        #  Returns True if the specified selection or range is in a content control.
        self.globals["wdInContentControl".lower()] = 46
        #  Returns True if the specified selection or range is in a cover page.
        self.globals["wdInCoverPage".lower()] = 41
        #  Returns True if the specified selection or range is in an endnote area in print layout view or in the endnote pane in normal view.
        self.globals["wdInEndnote".lower()] = 36
        #  Returns True if the specified selection or range is in a field code.
        self.globals["wdInFieldCode".lower()] = 44
        #  Returns True if the specified selection or range is in a field result.
        self.globals["wdInFieldResult".lower()] = 45
        #  Returns True if the specified selection or range is in a footnote area in print layout view or in the footnote pane in normal view.
        self.globals["wdInFootnote".lower()] = 35
        #  Returns True if the specified selection or range is in the footnote or endnote pane in normal view or in a footnote or endnote area in print layout view. For more information, see the descriptions of wdInFootnote and wdInEndnote in the preceding paragraphs.
        self.globals["wdInFootnoteEndnotePane".lower()] = 25
        #  Returns True if the selection or range is in the header or footer pane or in a header or footer in print layout view.
        self.globals["wdInHeaderFooter".lower()] = 28
        #  Returns True if the selection or range is in a master document (that is, a document that contains at least one subdocument).
        self.globals["wdInMasterDocument".lower()] = 34
        #  Returns True if the selection or range is in the header or footer pane or in a header or footer in print layout view.
        self.globals["wdInWordMail".lower()] = 37
        #  Returns the greatest number of table columns within any row in the selection or range.
        self.globals["wdMaximumNumberOfColumns".lower()] = 18
        #  Returns the greatest number of table rows within the table in the specified selection or range.
        self.globals["wdMaximumNumberOfRows".lower()] = 15
        #  Returns the number of pages in the document associated with the selection or range.
        self.globals["wdNumberOfPagesInDocument".lower()] = 4
        #  Returns True if Num Lock is in effect.
        self.globals["wdNumLock".lower()] = 22
        #  Returns True if Overtype mode is in effect. The Overtype property can be used to change the state of the Overtype mode.
        self.globals["wdOverType".lower()] = 23
        #  Returns a value that indicates where the selection is in relation to a footnote, endnote, or comment reference, as shown in the table in the remarks section.
        self.globals["wdReferenceOfType".lower()] = 32
        #  Returns True if change tracking is in effect.
        self.globals["wdRevisionMarking".lower()] = 24
        #  Returns a value that indicates the current selection mode, as shown in the following table.
        self.globals["wdSelectionMode".lower()] = 20
        #  Returns the table column number that contains the beginning of the selection or range.
        self.globals["wdStartOfRangeColumnNumber".lower()] = 16
        #  Returns the table row number that contains the beginning of the selection or range.
        self.globals["wdStartOfRangeRowNumber".lower()] = 13
        #  Returns the vertical position of the selection or range; this is the distance from the top edge of the selection to the top edge of the page measured in points (1 point = 20 twips, 72 points = 1 inch). If the selection isn't visible in the document window, returns -1.
        self.globals["wdVerticalPositionRelativeToPage".lower()] = 6
        #  Returns the vertical position of the selection or range relative to the top edge of the nearest text boundary enclosing it, in points (1 point = 20 twips, 72 points = 1 inch). This is useful for determining the position of the insertion point within a frame or table cell. If the selection isn't visible, returns -1.
        self.globals["wdVerticalPositionRelativeToTextBoundary".lower()] = 8
        #  Returns True if the selection is in a table.
        self.globals["wdWithInTable".lower()] = 12
        #  Returns the current percentage of magnification as set by the Percentage property.
        self.globals["wdZoomPercentage".lower()] = 19
        
        # WdColorIndex enumeration (Word)
        #   
        # Specifies the color to apply.
        
        #  Automatic color. Default; usually black.
        self.globals["wdAuto".lower()] = 0
        #  Black color.
        self.globals["wdBlack".lower()] = 1
        #  Blue color.
        self.globals["wdBlue".lower()] = 2
        #  Bright green color.
        self.globals["wdBrightGreen".lower()] = 4
        #  Color defined by document author.
        self.globals["wdByAuthor".lower()] = -1
        #  Dark blue color.
        self.globals["wdDarkBlue".lower()] = 9
        #  Dark red color.
        self.globals["wdDarkRed".lower()] = 13
        #  Dark yellow color.
        self.globals["wdDarkYellow".lower()] = 14
        #  Shade 25 of gray color.
        self.globals["wdGray25".lower()] = 16
        #  Shade 50 of gray color.
        self.globals["wdGray50".lower()] = 15
        #  Green color.
        self.globals["wdGreen".lower()] = 11
        #  Removes highlighting that has been applied.
        self.globals["wdNoHighlight".lower()] = 0
        #  Pink color.
        self.globals["wdPink".lower()] = 5
        #  Red color.
        self.globals["wdRed".lower()] = 6
        #  Teal color.
        self.globals["wdTeal".lower()] = 10
        #  Turquoise color.
        self.globals["wdTurquoise".lower()] = 3
        #  Violet color.
        self.globals["wdViolet".lower()] = 12
        #  White color.
        self.globals["wdWhite".lower()] = 8
        #  Yellow color.
        self.globals["wdYellow".lower()] = 7
        
        # WdHorizontalLineWidthType enumeration (Word)
        #    
        # Specifies how Word interprets the width (length) of the specified horizontal line.
        
        #  Microsoft Word interprets the width (length) of the specified horizontal line as a fixed value (in points). This is the default value for horizontal lines added with the AddHorizontalLine method. Setting the Width property for the InlineShape object associated with a horizontal line sets the WidthType property to this value.
        self.globals["wdHorizontalLineFixedWidth".lower()] = -2
        #  Word interprets the width (length) of the specified horizontal line as a percentage of the screen width. This is the default value for horizontal lines added with the AddHorizontalLineStandard method. Setting the PercentWidth property on a horizontal line sets the WidthType property to this value.
        self.globals["wdHorizontalLinePercentWidth".lower()] = -1
        
        # WdLanguageID enumeration
        #   
        # Specifies the language to use.
        
        #  African language.
        self.globals["wdAfrikaans".lower()] = 1078
        #  Albanian language.
        self.globals["wdAlbanian".lower()] = 1052
        #  Amharic language.
        self.globals["wdAmharic".lower()] = 1118
        #  Arabic language.
        self.globals["wdArabic".lower()] = 1025
        #  Arabic Algerian language.
        self.globals["wdArabicAlgeria".lower()] = 5121
        #  Arabic Bahraini language.
        self.globals["wdArabicBahrain".lower()] = 15361
        #  Arabic Egyptian language.
        self.globals["wdArabicEgypt".lower()] = 3073
        #  Arabic Iraqi language.
        self.globals["wdArabicIraq".lower()] = 2049
        #  Arabic Jordanian language.
        self.globals["wdArabicJordan".lower()] = 11265
        #  Arabic Kuwaiti language.
        self.globals["wdArabicKuwait".lower()] = 13313
        #  Arabic Lebanese language.
        self.globals["wdArabicLebanon".lower()] = 12289
        #  Arabic Libyan language.
        self.globals["wdArabicLibya".lower()] = 4097
        #  Arabic Moroccan language.
        self.globals["wdArabicMorocco".lower()] = 6145
        #  Arabic Omani language.
        self.globals["wdArabicOman".lower()] = 8193
        #  Arabic Qatari language.
        self.globals["wdArabicQatar".lower()] = 16385
        #  Arabic Syrian language.
        self.globals["wdArabicSyria".lower()] = 10241
        #  Arabic Tunisian language.
        self.globals["wdArabicTunisia".lower()] = 7169
        #  Arabic United Arab Emirates language.
        self.globals["wdArabicUAE".lower()] = 14337
        #  Arabic Yemeni language.
        self.globals["wdArabicYemen".lower()] = 9217
        #  Armenian language.
        self.globals["wdArmenian".lower()] = 1067
        #  Assamese language.
        self.globals["wdAssamese".lower()] = 1101
        #  Azeri Cyrillic language.
        self.globals["wdAzeriCyrillic".lower()] = 2092
        #  Azeri Latin language.
        self.globals["wdAzeriLatin".lower()] = 1068
        #  Basque (Basque).
        self.globals["wdBasque".lower()] = 1069
        #  Belgian Dutch language.
        self.globals["wdBelgianDutch".lower()] = 2067
        #  Belgian French language.
        self.globals["wdBelgianFrench".lower()] = 2060
        #  Bengali language.
        self.globals["wdBengali".lower()] = 1093
        #  Bulgarian language.
        self.globals["wdBulgarian".lower()] = 1026
        #  Burmese language.
        self.globals["wdBurmese".lower()] = 1109
        #  Belarusian language.
        self.globals["wdByelorussian".lower()] = 1059
        #  Catalan language.
        self.globals["wdCatalan".lower()] = 1027
        #  Cherokee language.
        self.globals["wdCherokee".lower()] = 1116
        #  Chinese Hong Kong SAR language.
        self.globals["wdChineseHongKongSAR".lower()] = 3076
        #  Chinese Macao SAR language.
        self.globals["wdChineseMacaoSAR".lower()] = 5124
        #  Chinese Singapore language.
        self.globals["wdChineseSingapore".lower()] = 4100
        #  Croatian language.
        self.globals["wdCroatian".lower()] = 1050
        #  Czech language.
        self.globals["wdCzech".lower()] = 1029
        #  Danish language.
        self.globals["wdDanish".lower()] = 1030
        #  Divehi language.
        self.globals["wdDivehi".lower()] = 1125
        #  Dutch language.
        self.globals["wdDutch".lower()] = 1043
        #  Edo language.
        self.globals["wdEdo".lower()] = 1126
        #  Australian English language.
        self.globals["wdEnglishAUS".lower()] = 3081
        #  Belize English language.
        self.globals["wdEnglishBelize".lower()] = 10249
        #  Canadian English language.
        self.globals["wdEnglishCanadian".lower()] = 4105
        #  Caribbean English language.
        self.globals["wdEnglishCaribbean".lower()] = 9225
        #  Indonesian English language.
        self.globals["wdEnglishIndonesia".lower()] = 14345
        #  Irish English language.
        self.globals["wdEnglishIreland".lower()] = 6153
        #  Jamaican English language.
        self.globals["wdEnglishJamaica".lower()] = 8201
        #  New Zealand English language.
        self.globals["wdEnglishNewZealand".lower()] = 5129
        #  Filipino English language.
        self.globals["wdEnglishPhilippines".lower()] = 13321
        #  South African English language.
        self.globals["wdEnglishSouthAfrica".lower()] = 7177
        #  Tobago Trinidad English language.
        self.globals["wdEnglishTrinidadTobago".lower()] = 11273
        #  United Kingdom English language.
        self.globals["wdEnglishUK".lower()] = 2057
        #  United States English language.
        self.globals["wdEnglishUS".lower()] = 1033
        #  Zimbabwe English language.
        self.globals["wdEnglishZimbabwe".lower()] = 12297
        #  Estonian language.
        self.globals["wdEstonian".lower()] = 1061
        #  Faeroese language.
        self.globals["wdFaeroese".lower()] = 1080
        #  Filipino language.
        self.globals["wdFilipino".lower()] = 1124
        #  Finnish language.
        self.globals["wdFinnish".lower()] = 1035
        #  French language.
        self.globals["wdFrench".lower()] = 1036
        #  French Cameroon language.
        self.globals["wdFrenchCameroon".lower()] = 11276
        #  French Canadian language.
        self.globals["wdFrenchCanadian".lower()] = 3084
        #  French (Congo (DRC)) language.
        self.globals["wdFrenchCongoDRC".lower()] = 9228
        #  French Cote d'Ivoire language.
        self.globals["wdFrenchCotedIvoire".lower()] = 12300
        #  French Haiti language.
        self.globals["wdFrenchHaiti".lower()] = 15372
        #  French Luxembourg language.
        self.globals["wdFrenchLuxembourg".lower()] = 5132
        #  French Mali language.
        self.globals["wdFrenchMali".lower()] = 13324
        #  French Monaco language.
        self.globals["wdFrenchMonaco".lower()] = 6156
        #  French Morocco language.
        self.globals["wdFrenchMorocco".lower()] = 14348
        #  French Reunion language.
        self.globals["wdFrenchReunion".lower()] = 8204
        #  French Senegal language.
        self.globals["wdFrenchSenegal".lower()] = 10252
        #  French West Indies language.
        self.globals["wdFrenchWestIndies".lower()] = 7180
        #  Frisian Netherlands language.
        self.globals["wdFrisianNetherlands".lower()] = 1122
        #  Fulfulde language.
        self.globals["wdFulfulde".lower()] = 1127
        #  Irish (Irish) language.
        self.globals["wdGaelicIreland".lower()] = 2108
        #  Scottish Gaelic language.
        self.globals["wdGaelicScotland".lower()] = 1084
        #  Galician language.
        self.globals["wdGalician".lower()] = 1110
        #  Georgian language.
        self.globals["wdGeorgian".lower()] = 1079
        #  German language.
        self.globals["wdGerman".lower()] = 1031
        #  German Austrian language.
        self.globals["wdGermanAustria".lower()] = 3079
        #  German Liechtenstein language.
        self.globals["wdGermanLiechtenstein".lower()] = 5127
        #  German Luxembourg language.
        self.globals["wdGermanLuxembourg".lower()] = 4103
        #  Greek language.
        self.globals["wdGreek".lower()] = 1032
        #  Guarani language.
        self.globals["wdGuarani".lower()] = 1140
        #  Gujarati language.
        self.globals["wdGujarati".lower()] = 1095
        #  Hausa language.
        self.globals["wdHausa".lower()] = 1128
        #  Hawaiian language.
        self.globals["wdHawaiian".lower()] = 1141
        #  Hebrew language.
        self.globals["wdHebrew".lower()] = 1037
        #  Hindi language.
        self.globals["wdHindi".lower()] = 1081
        #  Hungarian language.
        self.globals["wdHungarian".lower()] = 1038
        #  Ibibio language.
        self.globals["wdIbibio".lower()] = 1129
        #  Icelandic language.
        self.globals["wdIcelandic".lower()] = 1039
        #  Igbo language.
        self.globals["wdIgbo".lower()] = 1136
        #  Indonesian language.
        self.globals["wdIndonesian".lower()] = 1057
        #  Inuktitut language.
        self.globals["wdInuktitut".lower()] = 1117
        #  Italian language.
        self.globals["wdItalian".lower()] = 1040
        #  Japanese language.
        self.globals["wdJapanese".lower()] = 1041
        #  Kannada language.
        self.globals["wdKannada".lower()] = 1099
        #  Kanuri language.
        self.globals["wdKanuri".lower()] = 1137
        #  Kashmiri language.
        self.globals["wdKashmiri".lower()] = 1120
        #  Kazakh language.
        self.globals["wdKazakh".lower()] = 1087
        #  Khmer language.
        self.globals["wdKhmer".lower()] = 1107
        #  Kirghiz language.
        self.globals["wdKirghiz".lower()] = 1088
        #  Konkani language.
        self.globals["wdKonkani".lower()] = 1111
        #  Korean language.
        self.globals["wdKorean".lower()] = 1042
        #  Kyrgyz language.
        self.globals["wdKyrgyz".lower()] = 1088
        #  No specified language.
        self.globals["wdLanguageNone".lower()] = 0
        #  Lao language.
        self.globals["wdLao".lower()] = 1108
        #  Latin language.
        self.globals["wdLatin".lower()] = 1142
        #  Latvian language.
        self.globals["wdLatvian".lower()] = 1062
        #  Lithuanian language.
        self.globals["wdLithuanian".lower()] = 1063
        #  Macedonian (FYROM) language.
        self.globals["wdMacedonianFYROM".lower()] = 1071
        #  Malayalam language.
        self.globals["wdMalayalam".lower()] = 1100
        #  Malay Brunei Darussalam language.
        self.globals["wdMalayBruneiDarussalam".lower()] = 2110
        #  Malaysian language.
        self.globals["wdMalaysian".lower()] = 1086
        #  Maltese language.
        self.globals["wdMaltese".lower()] = 1082
        #  Manipuri language.
        self.globals["wdManipuri".lower()] = 1112
        #  Marathi language.
        self.globals["wdMarathi".lower()] = 1102
        #  Mexican Spanish language.
        self.globals["wdMexicanSpanish".lower()] = 2058
        #  Mongolian language.
        self.globals["wdMongolian".lower()] = 1104
        #  Nepali language.
        self.globals["wdNepali".lower()] = 1121
        #  Disables proofing if the language ID identifies a language in which an object is grammatically validated using the Microsoft Word proofing tools.
        self.globals["wdNoProofing".lower()] = 1024
        #  Norwegian Bokmol language.
        self.globals["wdNorwegianBokmol".lower()] = 1044
        #  Norwegian Nynorsk language.
        self.globals["wdNorwegianNynorsk".lower()] = 2068
        #  Oriya language.
        self.globals["wdOriya".lower()] = 1096
        #  Oromo language.
        self.globals["wdOromo".lower()] = 1138
        #  Pashto language.
        self.globals["wdPashto".lower()] = 1123
        #  Persian language.
        self.globals["wdPersian".lower()] = 1065
        #  Polish language.
        self.globals["wdPolish".lower()] = 1045
        #  Portuguese language.
        self.globals["wdPortuguese".lower()] = 2070
        #  Portuguese (Brazil) language.
        self.globals["wdPortugueseBrazil".lower()] = 1046
        #  Punjabi language.
        self.globals["wdPunjabi".lower()] = 1094
        #  Rhaeto Romanic language.
        self.globals["wdRhaetoRomanic".lower()] = 1047
        #  Romanian language.
        self.globals["wdRomanian".lower()] = 1048
        #  Romanian Moldova language.
        self.globals["wdRomanianMoldova".lower()] = 2072
        #  Russian language.
        self.globals["wdRussian".lower()] = 1049
        #  Russian Moldova language.
        self.globals["wdRussianMoldova".lower()] = 2073
        #  Sami Lappish language.
        self.globals["wdSamiLappish".lower()] = 1083
        #  Sanskrit language.
        self.globals["wdSanskrit".lower()] = 1103
        #  Serbian Cyrillic language.
        self.globals["wdSerbianCyrillic".lower()] = 3098
        #  Serbian Latin language.
        self.globals["wdSerbianLatin".lower()] = 2074
        #  Sesotho language.
        self.globals["wdSesotho".lower()] = 1072
        #  Simplified Chinese language.
        self.globals["wdSimplifiedChinese".lower()] = 2052
        #  Sindhi language.
        self.globals["wdSindhi".lower()] = 1113
        #  Sindhi (Pakistan) language.
        self.globals["wdSindhiPakistan".lower()] = 2137
        #  Sinhalese language.
        self.globals["wdSinhalese".lower()] = 1115
        #  Slovakian language.
        self.globals["wdSlovak".lower()] = 1051
        #  Slovenian language.
        self.globals["wdSlovenian".lower()] = 1060
        #  Somali language.
        self.globals["wdSomali".lower()] = 1143
        #  Sorbian language.
        self.globals["wdSorbian".lower()] = 1070
        #  Spanish language.
        self.globals["wdSpanish".lower()] = 1034
        #  Spanish Argentina language.
        self.globals["wdSpanishArgentina".lower()] = 11274
        #  Spanish Bolivian language.
        self.globals["wdSpanishBolivia".lower()] = 16394
        #  Spanish Chilean language.
        self.globals["wdSpanishChile".lower()] = 13322
        #  Spanish Colombian language.
        self.globals["wdSpanishColombia".lower()] = 9226
        #  Spanish Costa Rican language.
        self.globals["wdSpanishCostaRica".lower()] = 5130
        #  Spanish Dominican Republic language.
        self.globals["wdSpanishDominicanRepublic".lower()] = 7178
        #  Spanish Ecuadorian language.
        self.globals["wdSpanishEcuador".lower()] = 12298
        #  Spanish El Salvadorian language.
        self.globals["wdSpanishElSalvador".lower()] = 17418
        #  Spanish Guatemala language.
        self.globals["wdSpanishGuatemala".lower()] = 4106
        #  Spanish Honduran language.
        self.globals["wdSpanishHonduras".lower()] = 18442
        #  Spanish Modern Sort language.
        self.globals["wdSpanishModernSort".lower()] = 3082
        #  Spanish Nicaraguan language.
        self.globals["wdSpanishNicaragua".lower()] = 19466
        #  Spanish Panamanian language.
        self.globals["wdSpanishPanama".lower()] = 6154
        #  Spanish Paraguayan language.
        self.globals["wdSpanishParaguay".lower()] = 15370
        #  Spanish Peruvian language.
        self.globals["wdSpanishPeru".lower()] = 10250
        #  Spanish Puerto Rican language.
        self.globals["wdSpanishPuertoRico".lower()] = 20490
        #  Spanish Uruguayan language.
        self.globals["wdSpanishUruguay".lower()] = 14346
        #  Spanish Venezuelan language.
        self.globals["wdSpanishVenezuela".lower()] = 8202
        #  Sutu language.
        self.globals["wdSutu".lower()] = 1072
        #  Swahili language.
        self.globals["wdSwahili".lower()] = 1089
        #  Swedish language.
        self.globals["wdSwedish".lower()] = 1053
        #  Swedish Finnish language.
        self.globals["wdSwedishFinland".lower()] = 2077
        #  Swiss French language.
        self.globals["wdSwissFrench".lower()] = 4108
        #  Swiss German language.
        self.globals["wdSwissGerman".lower()] = 2055
        #  Swiss Italian language.
        self.globals["wdSwissItalian".lower()] = 2064
        #  Syriac language.
        self.globals["wdSyriac".lower()] = 1114
        #  Tajik language.
        self.globals["wdTajik".lower()] = 1064
        #  Tamazight language.
        self.globals["wdTamazight".lower()] = 1119
        #  Tamazight Latin language.
        self.globals["wdTamazightLatin".lower()] = 2143
        #  Tamil language.
        self.globals["wdTamil".lower()] = 1097
        #  Tatar language.
        self.globals["wdTatar".lower()] = 1092
        #  Telugu language.
        self.globals["wdTelugu".lower()] = 1098
        #  Thai language.
        self.globals["wdThai".lower()] = 1054
        #  Tibetan language.
        self.globals["wdTibetan".lower()] = 1105
        #  Tigrigna Eritrea language.
        self.globals["wdTigrignaEritrea".lower()] = 2163
        #  Tigrigna Ethiopic language.
        self.globals["wdTigrignaEthiopic".lower()] = 1139
        #  Traditional Chinese language.
        self.globals["wdTraditionalChinese".lower()] = 1028
        #  Tsonga language.
        self.globals["wdTsonga".lower()] = 1073
        #  Tswana language.
        self.globals["wdTswana".lower()] = 1074
        #  Turkish language.
        self.globals["wdTurkish".lower()] = 1055
        #  Turkmen language.
        self.globals["wdTurkmen".lower()] = 1090
        #  Ukrainian language.
        self.globals["wdUkrainian".lower()] = 1058
        #  Urdu language.
        self.globals["wdUrdu".lower()] = 1056
        #  Uzbek Cyrillic language.
        self.globals["wdUzbekCyrillic".lower()] = 2115
        #  Uzbek Latin language.
        self.globals["wdUzbekLatin".lower()] = 1091
        #  Venda language.
        self.globals["wdVenda".lower()] = 1075
        #  Vietnamese language.
        self.globals["wdVietnamese".lower()] = 1066
        #  Welsh language.
        self.globals["wdWelsh".lower()] = 1106
        #  Xhosa language.
        self.globals["wdXhosa".lower()] = 1076
        #  Yi language.
        self.globals["wdYi".lower()] = 1144
        #  Yiddish language.
        self.globals["wdYiddish".lower()] = 1085
        #  Yoruba language.
        self.globals["wdYoruba".lower()] = 1130
        #  Zulu language.
        self.globals["wdZulu".lower()] = 1077
        
        # WdKeyCategory enumeration (Word)
        #   
        # Specifies the type of item assigned to the key binding.
        
        #  Key is assigned to autotext.
        self.globals["wdKeyCategoryAutoText".lower()] = 4
        #  Key is assigned to a command.
        self.globals["wdKeyCategoryCommand".lower()] = 1
        #  Key is disabled.
        self.globals["wdKeyCategoryDisable".lower()] = 0
        #  Key is assigned to a font.
        self.globals["wdKeyCategoryFont".lower()] = 3
        #  Key is assigned to a macro.
        self.globals["wdKeyCategoryMacro".lower()] = 2
        #  Key is not assigned.
        self.globals["wdKeyCategoryNil".lower()] = -1
        #  Key is assigned to a prefix.
        self.globals["wdKeyCategoryPrefix".lower()] = 7
        #  Key is assigned to a style.
        self.globals["wdKeyCategoryStyle".lower()] = 5
        #  Key is assigned to a symbol.
        self.globals["wdKeyCategorySymbol".lower()] = 6
        
        # WdKey enumeration (Word)
        #   
        # Specifies a keyboard character. Although uppercase and lowercase characters are designated by using different values in a character encoding map, they share a single constant in this enumeration.
        
        #  The 0 key.
        self.globals["wdKey0".lower()] = 48
        #  The 1 key.
        self.globals["wdKey1".lower()] = 49
        #  The 2 key.
        self.globals["wdKey2".lower()] = 50
        #  The 3 key.
        self.globals["wdKey3".lower()] = 51
        #  The 4 key.
        self.globals["wdKey4".lower()] = 52
        #  The 5 key.
        self.globals["wdKey5".lower()] = 53
        #  The 6 key.
        self.globals["wdKey6".lower()] = 54
        #  The 7 key.
        self.globals["wdKey7".lower()] = 55
        #  The 8 key.
        self.globals["wdKey8".lower()] = 56
        #  The 9 key.
        self.globals["wdKey9".lower()] = 57
        #  The A key.
        self.globals["wdKeyA".lower()] = 65
        #  The ALT key.
        self.globals["wdKeyAlt".lower()] = 1024
        #  The B key.
        self.globals["wdKeyB".lower()] = 66
        #  The ` key.
        self.globals["wdKeyBackSingleQuote".lower()] = 192
        #  The \ key.
        self.globals["wdKeyBackSlash".lower()] = 220
        #  The BACKSPACE key.
        self.globals["wdKeyBackspace".lower()] = 8
        #  The C key.
        self.globals["wdKeyC".lower()] = 67
        #  The ] key.
        self.globals["wdKeyCloseSquareBrace".lower()] = 221
        #  The , key.
        self.globals["wdKeyComma".lower()] = 188
        #  The Windows command key or Macintosh COMMAND key.
        self.globals["wdKeyCommand".lower()] = 512
        #  The CTRL key.
        self.globals["wdKeyControl".lower()] = 512
        #  The D key.
        self.globals["wdKeyD".lower()] = 68
        #  The DELETE key.
        self.globals["wdKeyDelete".lower()] = 46
        #  The E key.
        self.globals["wdKeyE".lower()] = 69
        #  The END key.
        self.globals["wdKeyEnd".lower()] = 35
        #  The = key.
        self.globals["wdKeyEquals".lower()] = 187
        #  The ESC key.
        self.globals["wdKeyEsc".lower()] = 27
        #  The F key.
        self.globals["wdKeyF".lower()] = 70
        #  The F1 key.
        self.globals["wdKeyF1".lower()] = 112
        #  The F10 key.
        self.globals["wdKeyF10".lower()] = 121
        #  The F11 key.
        self.globals["wdKeyF11".lower()] = 122
        #  The F12 key.
        self.globals["wdKeyF12".lower()] = 123
        #  The F13 key.
        self.globals["wdKeyF13".lower()] = 124
        #  The F14 key.
        self.globals["wdKeyF14".lower()] = 125
        #  The F15 key.
        self.globals["wdKeyF15".lower()] = 126
        #  The F16 key.
        self.globals["wdKeyF16".lower()] = 127
        #  The F2 key.
        self.globals["wdKeyF2".lower()] = 113
        #  The F3 key.
        self.globals["wdKeyF3".lower()] = 114
        #  The F4 key.
        self.globals["wdKeyF4".lower()] = 115
        #  The F5 key.
        self.globals["wdKeyF5".lower()] = 116
        #  The F6 key.
        self.globals["wdKeyF6".lower()] = 117
        #  The F7 key.
        self.globals["wdKeyF7".lower()] = 118
        #  The F8 key.
        self.globals["wdKeyF8".lower()] = 119
        #  The F9 key.
        self.globals["wdKeyF9".lower()] = 120
        #  The G key.
        self.globals["wdKeyG".lower()] = 71
        #  The H key.
        self.globals["wdKeyH".lower()] = 72
        #  The HOME key.
        self.globals["wdKeyHome".lower()] = 36
        #  The - key.
        self.globals["wdKeyHyphen".lower()] = 189
        #  The I key.
        self.globals["wdKeyI".lower()] = 73
        #  The INSERT key.
        self.globals["wdKeyInsert".lower()] = 45
        #  The J key.
        self.globals["wdKeyJ".lower()] = 74
        #  The K key.
        self.globals["wdKeyK".lower()] = 75
        #  The L key.
        self.globals["wdKeyL".lower()] = 76
        #  The M key.
        self.globals["wdKeyM".lower()] = 77
        #  The N key.
        self.globals["wdKeyN".lower()] = 78
        #  The 0 key.
        self.globals["wdKeyNumeric0".lower()] = 96
        #  The 1 key.
        self.globals["wdKeyNumeric1".lower()] = 97
        #  The 2 key.
        self.globals["wdKeyNumeric2".lower()] = 98
        #  The 3 key.
        self.globals["wdKeyNumeric3".lower()] = 99
        #  The 4 key.
        self.globals["wdKeyNumeric4".lower()] = 100
        #  The 5 key.
        self.globals["wdKeyNumeric5".lower()] = 101
        #  .
        self.globals["wdKeyNumeric5Special".lower()] = 12
        #  The 6 key.
        self.globals["wdKeyNumeric6".lower()] = 102
        #  The 7 key.
        self.globals["wdKeyNumeric7".lower()] = 103
        #  The 8 key.
        self.globals["wdKeyNumeric8".lower()] = 104
        #  The 9 key.
        self.globals["wdKeyNumeric9".lower()] = 105
        #  The + key on the numeric keypad.
        self.globals["wdKeyNumericAdd".lower()] = 107
        #  The . key on the numeric keypad.
        self.globals["wdKeyNumericDecimal".lower()] = 110
        #  The / key on the numeric keypad.
        self.globals["wdKeyNumericDivide".lower()] = 111
        #  The * key on the numeric keypad.
        self.globals["wdKeyNumericMultiply".lower()] = 106
        #  The - key on the numeric keypad.
        self.globals["wdKeyNumericSubtract".lower()] = 109
        #  The O key.
        self.globals["wdKeyO".lower()] = 79
        #  The [ key.
        self.globals["wdKeyOpenSquareBrace".lower()] = 219
        #  The mouse option key or Macintosh OPTION key.
        self.globals["wdKeyOption".lower()] = 1024
        #  The P key.
        self.globals["wdKeyP".lower()] = 80
        #  The PAGE DOWN key.
        self.globals["wdKeyPageDown".lower()] = 34
        #  The PAGE UP key.
        self.globals["wdKeyPageUp".lower()] = 33
        #  The PAUSE key.
        self.globals["wdKeyPause".lower()] = 19
        #  The . key.
        self.globals["wdKeyPeriod".lower()] = 190
        #  The Q key.
        self.globals["wdKeyQ".lower()] = 81
        #  The R key.
        self.globals["wdKeyR".lower()] = 82
        #  The ENTER or RETURN key.
        self.globals["wdKeyReturn".lower()] = 13
        #  The S key.
        self.globals["wdKeyS".lower()] = 83
        #  The SCROLL LOCK key.
        self.globals["wdKeyScrollLock".lower()] = 145
        #  The ; key.
        self.globals["wdKeySemiColon".lower()] = 186
        #  The SHIFT key.
        self.globals["wdKeyShift".lower()] = 256
        #  The ' key.
        self.globals["wdKeySingleQuote".lower()] = 222
        #  The / key.
        self.globals["wdKeySlash".lower()] = 191
        #  The SPACEBAR key.
        self.globals["wdKeySpacebar".lower()] = 32
        #  The T key.
        self.globals["wdKeyT".lower()] = 84
        #  The TAB key.
        self.globals["wdKeyTab".lower()] = 9
        #  The U key.
        self.globals["wdKeyU".lower()] = 85
        #  The V key.
        self.globals["wdKeyV".lower()] = 86
        #  The W key.
        self.globals["wdKeyW".lower()] = 87
        #  The X key.
        self.globals["wdKeyX".lower()] = 88
        #  The Y key.
        self.globals["wdKeyY".lower()] = 89
        #  The Z key.
        self.globals["wdKeyZ".lower()] = 90
        #  No key.
        self.globals["wdNoKey".lower()] = 255
        
        # WdCompatibility enumeration (Word)
        # 
        # Specifies a compatibility option.
        
        #  Align table rows independently.
        self.globals["wdAlignTablesRowByRow".lower()] = 39
        #  Use line-breaking rules.
        self.globals["wdApplyBreakingRules".lower()] = 46
        #  Autospace like Microsoft Word 95.
        self.globals["wdAutospaceLikeWW7".lower()] = 38
        #  Treat " as "" in mail merge data sources.
        self.globals["wdConvMailMergeEsc".lower()] = 6
        #  Adjust line height to grid height in the table.
        self.globals["wdDontAdjustLineHeightInTable".lower()] = 36
        #  Balance SBCS characters and DBCS characters.
        self.globals["wdDontBalanceSingleByteDoubleByteWidth".lower()] = 16
        #  Do not break wrapped tables across pages.
        self.globals["wdDontBreakWrappedTables".lower()] = 43
        #  Do not snap text to grid inside table with inline objects.
        self.globals["wdDontSnapTextToGridInTableWithObjects".lower()] = 44
        #  Draw underline on trailing spaces.
        self.globals["wdDontULTrailSpace".lower()] = 15
        #  Do not use Asian rules for line breaks with character grid.
        self.globals["wdDontUseAsianBreakRulesInGrid".lower()] = 48
        #  Do not use HTML paragraph auto spacing.
        self.globals["wdDontUseHTMLParagraphAutoSpacing".lower()] = 35
        #  Do not allow hanging punctuation with character grid.
        self.globals["wdDontWrapTextWithPunctuation".lower()] = 47
        #  Do not center "exact line height" lines.
        self.globals["wdExactOnTop".lower()] = 28
        #  Do not expand character spaces on the line ending Shift+Return.
        self.globals["wdExpandShiftReturn".lower()] = 14
        #  Lay out footnotes like Word 6.x/95/97.
        self.globals["wdFootnoteLayoutLikeWW8".lower()] = 34
        #  Forget last tab alignment.
        self.globals["wdForgetLastTabAlignment".lower()] = 37
        #  Allow tables to extend into margins.
        self.globals["wdGrowAutofit".lower()] = 50
        #  Lay out tables with raw width.
        self.globals["wdLayoutRawTableWidth".lower()] = 40
        #  Allow table rows to lay out apart.
        self.globals["wdLayoutTableRowsApart".lower()] = 41
        #  Convert backslash characters into yen signs.
        self.globals["wdLeaveBackslashAlone".lower()] = 13
        #  Line wrap like Word 6.0.
        self.globals["wdLineWrapLikeWord6".lower()] = 32
        #  Use larger small caps like Word 5.x for the Macintosh.
        self.globals["wdMWSmallCaps".lower()] = 22
        #  Do not balance columns for continuous section starts.
        self.globals["wdNoColumnBalance".lower()] = 5
        #  Suppress extra line spacing like WordPerfect 5.x.
        self.globals["wdNoExtraLineSpacing".lower()] = 23
        #  Do not add leading (extra space) between rows of text.
        self.globals["wdNoLeading".lower()] = 20
        #  Add space for underline.
        self.globals["wdNoSpaceForUL".lower()] = 21
        #  Do not add extra space for raised/lowered characters.
        self.globals["wdNoSpaceRaiseLower".lower()] = 2
        #  Do not add automatic tab stop for hanging indent.
        self.globals["wdNoTabHangIndent".lower()] = 1
        #  Combine table borders like Word 5.x for the Macintosh.
        self.globals["wdOrigWordTableRules".lower()] = 9
        #  Print body text before header/footer.
        self.globals["wdPrintBodyTextBeforeHeader".lower()] = 19
        #  Print colors as black on noncolor printers.
        self.globals["wdPrintColBlack".lower()] = 3
        #  Select entire field with first or last character.
        self.globals["wdSelectFieldWithFirstOrLastCharacter".lower()] = 45
        #  Lay out autoshapes like Word 97.
        self.globals["wdShapeLayoutLikeWW8".lower()] = 33
        #  Show hard page or column breaks in frames.
        self.globals["wdShowBreaksInFrames".lower()] = 11
        #  Expand/condense by whole number of points.
        self.globals["wdSpacingInWholePoints".lower()] = 18
        #  Substitute fonts based on font size.
        self.globals["wdSubFontBySize".lower()] = 25
        #  Suppress extra line spacing at bottom of page.
        self.globals["wdSuppressBottomSpacing".lower()] = 29
        #  Suppress Space Before after a hard page or column break.
        self.globals["wdSuppressSpBfAfterPgBrk".lower()] = 7
        #  Suppress extra line spacing at top of page.
        self.globals["wdSuppressTopSpacing".lower()] = 8
        #  Suppress extra line spacing at top of page like Word 5.x for the Macintosh.
        self.globals["wdSuppressTopSpacingMac5".lower()] = 17
        #  Swap left and right borders on odd facing pages.
        self.globals["wdSwapBordersFacingPages".lower()] = 12
        #  Do not blank the area behind metafile pictures.
        self.globals["wdTransparentMetafiles".lower()] = 10
        #  Truncate font height.
        self.globals["wdTruncateFontHeight".lower()] = 24
        #  Use printer metrics to lay out document.
        self.globals["wdUsePrinterMetrics".lower()] = 26
        #  Use Microsoft Word 2002 table style rules.
        self.globals["wdUseWord2002TableStyleRules".lower()] = 49
        #  Use Microsoft Word 2010 table style rules.
        self.globals["wdUseWord2010TableStyleRules".lower()] = 69
        #  Use Microsoft Word 97 line breaking rules for Asian text.
        self.globals["wdUseWord97LineBreakingRules".lower()] = 42
        #  Do full justification like WordPerfect 6.x for Windows.
        self.globals["wdWPJustification".lower()] = 31
        #  Set the width of a space like WordPerfect 5.x.
        self.globals["wdWPSpaceWidth".lower()] = 30
        #  Wrap trailing spaces to next line.
        self.globals["wdWrapTrailSpaces".lower()] = 4
        #  Use Word 6.x/95 border rules.
        self.globals["wdWW6BorderRules".lower()] = 27
        #  Allow space between paragraphs of the same style in a table.
        self.globals["wdAllowSpaceOfSameStyleInTable".lower()] = 54
        #  Use Microsoft Word 2003 table autofit rules.
        self.globals["wdAutofitLikeWW11".lower()] = 57
        #  Do not autofit tables next to wrapped objects.
        self.globals["wdDontAutofitConstrainedTables".lower()] = 56
        #  Do not use hanging indent as tab stop for bullets and numbering.
        self.globals["wdDontUseIndentAsNumberingTabStop".lower()] = 52
        #  Use Word 2003 hanging-punctuation rules in Asian languages.
        self.globals["wdFELineBreak11".lower()] = 53
        #  Do not use proportional width for Korean characters.
        self.globals["wdHangulWidthLikeWW11".lower()] = 59
        #  Split apart page break and paragraph mark.
        self.globals["wdSplitPgBreakAndParaMark".lower()] = 60
        #  Underline the tab character between the number and the text in numbered lists.
        self.globals["wdUnderlineTabInNumList".lower()] = 58
        #  Use the Normal style instead of the List Paragraph style for bulleted or numbered lists.
        self.globals["wdUseNormalStyleForList".lower()] = 51
        #  Use Word 2003 indent rules for text next to wrapped objects.
        self.globals["wdWW11IndentRules".lower()] = 55
        
        # WdLineStyle enumeration (Word)
        #   
        # Specifies the border style for an object.
        
        #  A dash followed by a dot.
        self.globals["wdLineStyleDashDot".lower()] = 5
        #  A dash followed by two dots.
        self.globals["wdLineStyleDashDotDot".lower()] = 6
        #  A dash followed by a dot stroke, thus rendering a border similar to a barber pole.
        self.globals["wdLineStyleDashDotStroked".lower()] = 20
        #  A dash followed by a large gap.
        self.globals["wdLineStyleDashLargeGap".lower()] = 4
        #  A dash followed by a small gap.
        self.globals["wdLineStyleDashSmallGap".lower()] = 3
        #  Dots.
        self.globals["wdLineStyleDot".lower()] = 2
        #  Double solid lines.
        self.globals["wdLineStyleDouble".lower()] = 7
        #  Double wavy solid lines.
        self.globals["wdLineStyleDoubleWavy".lower()] = 19
        #  The border appears to have a 3D embossed look.
        self.globals["wdLineStyleEmboss3D".lower()] = 21
        #  The border appears to have a 3D engraved look.
        self.globals["wdLineStyleEngrave3D".lower()] = 22
        #  The border appears to be inset.
        self.globals["wdLineStyleInset".lower()] = 24
        #  No border.
        self.globals["wdLineStyleNone".lower()] = 0
        #  The border appears to be outset.
        self.globals["wdLineStyleOutset".lower()] = 23
        #  A single solid line.
        self.globals["wdLineStyleSingle".lower()] = 1
        #  A single wavy solid line.
        self.globals["wdLineStyleSingleWavy".lower()] = 18
        #  An internal single thick solid line surrounded by a single thin solid line with a large gap between them.
        self.globals["wdLineStyleThickThinLargeGap".lower()] = 16
        #  An internal single thick solid line surrounded by a single thin solid line with a medium gap between them.
        self.globals["wdLineStyleThickThinMedGap".lower()] = 13
        #  An internal single thick solid line surrounded by a single thin solid line with a small gap between them.
        self.globals["wdLineStyleThickThinSmallGap".lower()] = 10
        #  An internal single thin solid line surrounded by a single thick solid line with a large gap between them.
        self.globals["wdLineStyleThinThickLargeGap".lower()] = 15
        #  An internal single thin solid line surrounded by a single thick solid line with a medium gap between them.
        self.globals["wdLineStyleThinThickMedGap".lower()] = 12
        #  An internal single thin solid line surrounded by a single thick solid line with a small gap between them.
        self.globals["wdLineStyleThinThickSmallGap".lower()] = 9
        #  An internal single thin solid line surrounded by a single thick solid line surrounded by a single thin solid line with a large gap between all lines.
        self.globals["wdLineStyleThinThickThinLargeGap".lower()] = 17
        #  An internal single thin solid line surrounded by a single thick solid line surrounded by a single thin solid line with a medium gap between all lines.
        self.globals["wdLineStyleThinThickThinMedGap".lower()] = 14
        #  An internal single thin solid line surrounded by a single thick solid line surrounded by a single thin solid line with a small gap between all lines.
        self.globals["wdLineStyleThinThickThinSmallGap".lower()] = 11
        #  Three solid thin lines.
        self.globals["wdLineStyleTriple".lower()] = 8
        
        # WdListNumberStyle enumeration (Word)
        #   
        # Specifies the numeric style to apply to a list.
        
        #  Aiueo numeric style.
        self.globals["wdListNumberStyleAiueo".lower()] = 20
        #  Aiueo half-width numeric style.
        self.globals["wdListNumberStyleAiueoHalfWidth".lower()] = 12
        #  Arabic numeric style.
        self.globals["wdListNumberStyleArabic".lower()] = 0
        #  Arabic 1 numeric style.
        self.globals["wdListNumberStyleArabic1".lower()] = 46
        #  Arabic 2 numeric style.
        self.globals["wdListNumberStyleArabic2".lower()] = 48
        #  Arabic full-width numeric style.
        self.globals["wdListNumberStyleArabicFullWidth".lower()] = 14
        #  Arabic LZ numeric style.
        self.globals["wdListNumberStyleArabicLZ".lower()] = 22
        #  Arabic LZ2 numeric style.
        self.globals["wdListNumberStyleArabicLZ2".lower()] = 62
        #  Arabic LZ3 numeric style.
        self.globals["wdListNumberStyleArabicLZ3".lower()] = 63
        #  Arabic LZ4 numeric style.
        self.globals["wdListNumberStyleArabicLZ4".lower()] = 64
        #  Bullet style.
        self.globals["wdListNumberStyleBullet".lower()] = 23
        #  Cardinal text style.
        self.globals["wdListNumberStyleCardinalText".lower()] = 6
        #  Chosung style.
        self.globals["wdListNumberStyleChosung".lower()] = 25
        #  Ganada style.
        self.globals["wdListNumberStyleGanada".lower()] = 24
        #  GB numeric 1 style.
        self.globals["wdListNumberStyleGBNum1".lower()] = 26
        #  GB numeric 2 style.
        self.globals["wdListNumberStyleGBNum2".lower()] = 27
        #  GB numeric 3 style.
        self.globals["wdListNumberStyleGBNum3".lower()] = 28
        #  GB numeric 4 style.
        self.globals["wdListNumberStyleGBNum4".lower()] = 29
        #  Hanqul style.
        self.globals["wdListNumberStyleHangul".lower()] = 43
        #  Hanja style.
        self.globals["wdListNumberStyleHanja".lower()] = 44
        #  Hanja Read style.
        self.globals["wdListNumberStyleHanjaRead".lower()] = 41
        #  Hanja Read Digit style.
        self.globals["wdListNumberStyleHanjaReadDigit".lower()] = 42
        #  Hebrew 1 style.
        self.globals["wdListNumberStyleHebrew1".lower()] = 45
        #  Hebrew 2 style.
        self.globals["wdListNumberStyleHebrew2".lower()] = 47
        #  Hindi Arabic style.
        self.globals["wdListNumberStyleHindiArabic".lower()] = 51
        #  Hindi Cardinal text style.
        self.globals["wdListNumberStyleHindiCardinalText".lower()] = 52
        #  Hindi letter 1 style.
        self.globals["wdListNumberStyleHindiLetter1".lower()] = 49
        #  Hindi letter 2 style.
        self.globals["wdListNumberStyleHindiLetter2".lower()] = 50
        #  Iroha style.
        self.globals["wdListNumberStyleIroha".lower()] = 21
        #  Iroha half width style.
        self.globals["wdListNumberStyleIrohaHalfWidth".lower()] = 13
        #  Kanji style.
        self.globals["wdListNumberStyleKanji".lower()] = 10
        #  Kanji Digit style.
        self.globals["wdListNumberStyleKanjiDigit".lower()] = 11
        #  Kanji traditional style.
        self.globals["wdListNumberStyleKanjiTraditional".lower()] = 16
        #  Kanji traditional 2 style.
        self.globals["wdListNumberStyleKanjiTraditional2".lower()] = 17
        #  Legal style.
        self.globals["wdListNumberStyleLegal".lower()] = 253
        #  Legal LZ style.
        self.globals["wdListNumberStyleLegalLZ".lower()] = 254
        #  Lowercase Bulgarian style.
        self.globals["wdListNumberStyleLowercaseBulgarian".lower()] = 67
        #  Lowercase Greek style.
        self.globals["wdListNumberStyleLowercaseGreek".lower()] = 60
        #  Lowercase letter style.
        self.globals["wdListNumberStyleLowercaseLetter".lower()] = 4
        #  Lowercase Roman style.
        self.globals["wdListNumberStyleLowercaseRoman".lower()] = 2
        #  Lowercase Russian style.
        self.globals["wdListNumberStyleLowercaseRussian".lower()] = 58
        #  Lowercase Turkish style.
        self.globals["wdListNumberStyleLowercaseTurkish".lower()] = 65
        #  No style applied.
        self.globals["wdListNumberStyleNone".lower()] = 255
        #  Number in circle style.
        self.globals["wdListNumberStyleNumberInCircle".lower()] = 18
        #  Ordinal style.
        self.globals["wdListNumberStyleOrdinal".lower()] = 5
        #  Ordinal text style.
        self.globals["wdListNumberStyleOrdinalText".lower()] = 7
        #  Picture bullet style.
        self.globals["wdListNumberStylePictureBullet".lower()] = 249
        #  Simplified Chinese numeric 1 style.
        self.globals["wdListNumberStyleSimpChinNum1".lower()] = 37
        #  Simplified Chinese numeric 2 style.
        self.globals["wdListNumberStyleSimpChinNum2".lower()] = 38
        #  Simplified Chinese numeric 3 style.
        self.globals["wdListNumberStyleSimpChinNum3".lower()] = 39
        #  Simplified Chinese numeric 4 style.
        self.globals["wdListNumberStyleSimpChinNum4".lower()] = 40
        #  Thai Arabic style.
        self.globals["wdListNumberStyleThaiArabic".lower()] = 54
        #  Thai Cardinal text style.
        self.globals["wdListNumberStyleThaiCardinalText".lower()] = 55
        #  Thai letter style.
        self.globals["wdListNumberStyleThaiLetter".lower()] = 53
        #  Traditional Chinese numeric 1 style.
        self.globals["wdListNumberStyleTradChinNum1".lower()] = 33
        #  Traditional Chinese numeric 2 style.
        self.globals["wdListNumberStyleTradChinNum2".lower()] = 34
        #  Traditional Chinese numeric 3 style.
        self.globals["wdListNumberStyleTradChinNum3".lower()] = 35
        #  Traditional Chinese numeric 4 style.
        self.globals["wdListNumberStyleTradChinNum4".lower()] = 36
        #  Uppercase Bulgarian style.
        self.globals["wdListNumberStyleUppercaseBulgarian".lower()] = 68
        #  Uppercase Greek style.
        self.globals["wdListNumberStyleUppercaseGreek".lower()] = 61
        #  Uppercase letter style.
        self.globals["wdListNumberStyleUppercaseLetter".lower()] = 3
        #  Uppercase Roman style.
        self.globals["wdListNumberStyleUppercaseRoman".lower()] = 1
        #  Uppercase Russian style.
        self.globals["wdListNumberStyleUppercaseRussian".lower()] = 59
        #  Uppercase Turkish style.
        self.globals["wdListNumberStyleUppercaseTurkish".lower()] = 66
        #  Vietnamese Cardinal text style.
        self.globals["wdListNumberStyleVietCardinalText".lower()] = 56
        #  Zodiac 1 style.
        self.globals["wdListNumberStyleZodiac1".lower()] = 30
        #  Zodiac 2 style.
        self.globals["wdListNumberStyleZodiac2".lower()] = 31
        #  Zodiac 3 style.
        self.globals["wdListNumberStyleZodiac3".lower()] = 32
        
        # WdMoveToTextMark enumeration (Word)
        #    
        # Marks the moved-to text when text in a document with tracked changes is moved from one place to another.
        
        #  Marks moved text with bold formatting.
        self.globals["wdMoveToTextMarkBold".lower()] = 1
        #  Marks moved text with color only. Use the MoveToTextColor property to set the color of moved text.
        self.globals["wdMoveToTextMarkColorOnly".lower()] = 5
        #  Moved text is marked with a double strikethrough.
        self.globals["wdMoveToTextMarkDoubleStrikeThrough".lower()] = 7
        #  Moved text is marked with a double underline.
        self.globals["wdMoveToTextMarkDoubleUnderline".lower()] = 4
        #  Marks moved text with italic formatting.
        self.globals["wdMoveToTextMarkItalic".lower()] = 2
        #  No special formatting for moved text.
        self.globals["wdMoveToTextMarkNone".lower()] = 0
        #  Moved text is marked with a strikethrough.
        self.globals["wdMoveToTextMarkStrikeThrough".lower()] = 6
        #  Underlines moved text.
        self.globals["wdMoveToTextMarkUnderline".lower()] = 3
        
        # WdNumberSpacing enumeration (Word)
        #   
        # Specifies the number spacing setting for an OpenType font.
        
        #  Applies the default number spacing for the font.
        self.globals["wdNumberSpacingDefault".lower()] = 0
        #  Applies proportional number spacing to the font.
        self.globals["wdNumberSpacingProportional".lower()] = 1
        #  Applies tabular number spacing to the font.
        self.globals["wdNumberSpacingTabular".lower()] = 2
        
        # WdPageNumberStyle enumeration (Word)
        #   
        # Specifies the style to apply to page numbers.
        
        #  Arabic style.
        self.globals["wdPageNumberStyleArabic".lower()] = 0
        #  Arabic full width style.
        self.globals["wdPageNumberStyleArabicFullWidth".lower()] = 14
        #  Arabic letter 1 style.
        self.globals["wdPageNumberStyleArabicLetter1".lower()] = 46
        #  Arabic letter 2 style.
        self.globals["wdPageNumberStyleArabicLetter2".lower()] = 48
        #  Hanja Read style.
        self.globals["wdPageNumberStyleHanjaRead".lower()] = 41
        #  Hanja Read Digit style.
        self.globals["wdPageNumberStyleHanjaReadDigit".lower()] = 42
        #  Hebrew letter 1 style.
        self.globals["wdPageNumberStyleHebrewLetter1".lower()] = 45
        #  Hebrew letter 2 style.
        self.globals["wdPageNumberStyleHebrewLetter2".lower()] = 47
        #  Hindi Arabic style.
        self.globals["wdPageNumberStyleHindiArabic".lower()] = 51
        #  Hindi Cardinal text style.
        self.globals["wdPageNumberStyleHindiCardinalText".lower()] = 52
        #  Hindi letter 1 style.
        self.globals["wdPageNumberStyleHindiLetter1".lower()] = 49
        #  Hindi letter 2 style.
        self.globals["wdPageNumberStyleHindiLetter2".lower()] = 50
        #  Kanji style.
        self.globals["wdPageNumberStyleKanji".lower()] = 10
        #  Kanji Digit style.
        self.globals["wdPageNumberStyleKanjiDigit".lower()] = 11
        #  Kanji traditional style.
        self.globals["wdPageNumberStyleKanjiTraditional".lower()] = 16
        #  Lowercase letter style.
        self.globals["wdPageNumberStyleLowercaseLetter".lower()] = 4
        #  Lowercase Roman style.
        self.globals["wdPageNumberStyleLowercaseRoman".lower()] = 2
        #  Number in circle style.
        self.globals["wdPageNumberStyleNumberInCircle".lower()] = 18
        #  Number in dash style.
        self.globals["wdPageNumberStyleNumberInDash".lower()] = 57
        #  Simplified Chinese number 1 style.
        self.globals["wdPageNumberStyleSimpChinNum1".lower()] = 37
        #  Simplified Chinese number 2 style.
        self.globals["wdPageNumberStyleSimpChinNum2".lower()] = 38
        #  Thai Arabic style.
        self.globals["wdPageNumberStyleThaiArabic".lower()] = 54
        #  Thai Cardinal Text style.
        self.globals["wdPageNumberStyleThaiCardinalText".lower()] = 55
        #  Thai letter style.
        self.globals["wdPageNumberStyleThaiLetter".lower()] = 53
        #  Traditional Chinese number 1 style.
        self.globals["wdPageNumberStyleTradChinNum1".lower()] = 33
        #  Traditional Chinese number 2 style.
        self.globals["wdPageNumberStyleTradChinNum2".lower()] = 34
        #  Uppercase letter style.
        self.globals["wdPageNumberStyleUppercaseLetter".lower()] = 3
        #  Uppercase Roman style.
        self.globals["wdPageNumberStyleUppercaseRoman".lower()] = 1
        #  Vietnamese Cardinal text style.
        self.globals["wdPageNumberStyleVietCardinalText".lower()] = 56
        
        # WdEnvelopeOrientation enumeration (Word)
        #   
        # Specifies the orientation of envelopes.
        
        #  Center clockwise orientation.
        self.globals["wdCenterClockwise".lower()] = 7
        #  Center landscape orientation.
        self.globals["wdCenterLandscape".lower()] = 4
        #  Center portrait orientation.
        self.globals["wdCenterPortrait".lower()] = 1
        #  Left clockwise orientation.
        self.globals["wdLeftClockwise".lower()] = 6
        #  Left landscape orientation.
        self.globals["wdLeftLandscape".lower()] = 3
        #  Left portrait orientation.
        self.globals["wdLeftPortrait".lower()] = 0
        #  Right clockwise orientation.
        self.globals["wdRightClockwise".lower()] = 8
        #  Right landscape orientation.
        self.globals["wdRightLandscape".lower()] = 5
        #  Right portrait orientation.
        self.globals["wdRightPortrait".lower()] = 2
        
        # WdSelectionFlags enumeration (Word)
        #   
        # Specifies the properties of the selection.
        
        #  The selection is the active selection.
        self.globals["wdSelActive".lower()] = 8
        #  The selection is at the end of the letter.
        self.globals["wdSelAtEOL".lower()] = 2
        #  The selection was overtyped.
        self.globals["wdSelOvertype".lower()] = 4
        #  The selection was replaced.
        self.globals["wdSelReplace".lower()] = 16
        #  The selection is at the start of the active document.
        self.globals["wdSelStartActive".lower()] = 1
        
        # WdSortFieldType enumeration (Word)
        #   
        # Specifies the sort type to apply when sorting a column.
        
        #  Alphanumeric order.
        self.globals["wdSortFieldAlphanumeric".lower()] = 0
        #  Date order.
        self.globals["wdSortFieldDate".lower()] = 2
        #  Japanese JIS order.
        self.globals["wdSortFieldJapanJIS".lower()] = 4
        #  Korean KS order.
        self.globals["wdSortFieldKoreaKS".lower()] = 6
        #  Numeric order.
        self.globals["wdSortFieldNumeric".lower()] = 1
        #  Stroke order.
        self.globals["wdSortFieldStroke".lower()] = 5
        #  Syllable order.
        self.globals["wdSortFieldSyllable".lower()] = 3
        
        # WdSortSeparator enumeration (Word)
        #
        # Specifies the type of field separator.
        
        #  Comma.
        self.globals["wdSortSeparateByCommas".lower()] = 1
        #  Default table separator.
        self.globals["wdSortSeparateByDefaultTableSeparator".lower()] = 2
        #  Tab.
        self.globals["wdSortSeparateByTabs".lower()] = 0
        
        # WdTableFormatApply enumeration (Word)
        #
        # Specifies how table formatting should be applied.
        
        #  AutoFit.
        self.globals["wdTableFormatApplyAutoFit".lower()] = 16
        #  Borders.
        self.globals["wdTableFormatApplyBorders".lower()] = 1
        #  Color.
        self.globals["wdTableFormatApplyColor".lower()] = 8
        #  Apply AutoFormat to first column.
        self.globals["wdTableFormatApplyFirstColumn".lower()] = 128
        #  Font.
        self.globals["wdTableFormatApplyFont".lower()] = 4
        #  Apply AutoFormat to heading rows.
        self.globals["wdTableFormatApplyHeadingRows".lower()] = 32
        #  Apply AutoFormat to last column.
        self.globals["wdTableFormatApplyLastColumn".lower()] = 256
        #  Apply AutoFormat to last row.
        self.globals["wdTableFormatApplyLastRow".lower()] = 64
        #  Shading.
        self.globals["wdTableFormatApplyShading".lower()] = 2
        
        # WdTableFormat enumeration (Word)
        #   
        # Specifies the predefined format to apply to a table.
        
        #  3D effects format number 1.
        self.globals["wdTableFormat3DEffects1".lower()] = 32
        #  3D effects format number 2.
        self.globals["wdTableFormat3DEffects2".lower()] = 33
        #  3D effects format number 3.
        self.globals["wdTableFormat3DEffects3".lower()] = 34
        #  Classic format number 1.
        self.globals["wdTableFormatClassic1".lower()] = 4
        #  Classic format number 2.
        self.globals["wdTableFormatClassic2".lower()] = 5
        #  Classic format number 3.
        self.globals["wdTableFormatClassic3".lower()] = 6
        #  Classic format number 4.
        self.globals["wdTableFormatClassic4".lower()] = 7
        #  Colorful format number 1.
        self.globals["wdTableFormatColorful1".lower()] = 8
        #  Colorful format number 2.
        self.globals["wdTableFormatColorful2".lower()] = 9
        #  Colorful format number 3.
        self.globals["wdTableFormatColorful3".lower()] = 10
        #  Columns format number 1.
        self.globals["wdTableFormatColumns1".lower()] = 11
        #  Columns format number 2.
        self.globals["wdTableFormatColumns2".lower()] = 12
        #  Columns format number 3.
        self.globals["wdTableFormatColumns3".lower()] = 13
        #  Columns format number 4.
        self.globals["wdTableFormatColumns4".lower()] = 14
        #  Columns format number 5.
        self.globals["wdTableFormatColumns5".lower()] = 15
        #  Contemporary format.
        self.globals["wdTableFormatContemporary".lower()] = 35
        #  Elegant format.
        self.globals["wdTableFormatElegant".lower()] = 36
        #  Grid format number 1.
        self.globals["wdTableFormatGrid1".lower()] = 16
        #  Grid format number 2.
        self.globals["wdTableFormatGrid2".lower()] = 17
        #  Grid format number 3.
        self.globals["wdTableFormatGrid3".lower()] = 18
        #  Grid format number 4.
        self.globals["wdTableFormatGrid4".lower()] = 19
        #  Grid format number 5.
        self.globals["wdTableFormatGrid5".lower()] = 20
        #  Grid format number 6.
        self.globals["wdTableFormatGrid6".lower()] = 21
        #  Grid format number 7.
        self.globals["wdTableFormatGrid7".lower()] = 22
        #  Grid format number 8.
        self.globals["wdTableFormatGrid8".lower()] = 23
        #  List format number 1.
        self.globals["wdTableFormatList1".lower()] = 24
        #  List format number 2.
        self.globals["wdTableFormatList2".lower()] = 25
        #  List format number 3.
        self.globals["wdTableFormatList3".lower()] = 26
        #  List format number 4.
        self.globals["wdTableFormatList4".lower()] = 27
        #  List format number 5.
        self.globals["wdTableFormatList5".lower()] = 28
        #  List format number 6.
        self.globals["wdTableFormatList6".lower()] = 29
        #  List format number 7.
        self.globals["wdTableFormatList7".lower()] = 30
        #  List format number 8.
        self.globals["wdTableFormatList8".lower()] = 31
        #  No formatting.
        self.globals["wdTableFormatNone".lower()] = 0
        #  Professional format.
        self.globals["wdTableFormatProfessional".lower()] = 37
        #  Simple format number 1.
        self.globals["wdTableFormatSimple1".lower()] = 1
        #  Simple format number 2.
        self.globals["wdTableFormatSimple2".lower()] = 2
        #  Simple format number 3.
        self.globals["wdTableFormatSimple3".lower()] = 3
        #  Subtle format number 1.
        self.globals["wdTableFormatSubtle1".lower()] = 38
        #  Subtle format number 2.
        self.globals["wdTableFormatSubtle2".lower()] = 39
        #  Web format number 1.
        self.globals["wdTableFormatWeb1".lower()] = 40
        #  Web format number 2.
        self.globals["wdTableFormatWeb2".lower()] = 41
        #  Web format number 3.
        self.globals["wdTableFormatWeb3".lower()] = 42
        
        # WdLineType enumeration (Word)
        #   
        # Specifies whether a line is a line of text or a table row.
        
        #  A table row.
        self.globals["wdTableRow".lower()] = 1
        #  A line of text in the body of the document.
        self.globals["wdTextLine".lower()] = 0
        
        # WdTextureIndex enumeration (Word)
        #   
        # Specifies the shading texture to use for a selected item.
        
        #  10 percent shading.
        self.globals["wdTexture10Percent".lower()] = 100
        #  12.5 percent shading.
        self.globals["wdTexture12Pt5Percent".lower()] = 125
        #  15 percent shading.
        self.globals["wdTexture15Percent".lower()] = 150
        #  17.5 percent shading.
        self.globals["wdTexture17Pt5Percent".lower()] = 175
        #  20 percent shading.
        self.globals["wdTexture20Percent".lower()] = 200
        #  22.5 percent shading.
        self.globals["wdTexture22Pt5Percent".lower()] = 225
        #  25 percent shading.
        self.globals["wdTexture25Percent".lower()] = 250
        #  27.5 percent shading.
        self.globals["wdTexture27Pt5Percent".lower()] = 275
        #  2.5 percent shading.
        self.globals["wdTexture2Pt5Percent".lower()] = 25
        #  30 percent shading.
        self.globals["wdTexture30Percent".lower()] = 300
        #  32.5 percent shading.
        self.globals["wdTexture32Pt5Percent".lower()] = 325
        #  35 percent shading.
        self.globals["wdTexture35Percent".lower()] = 350
        #  37.5 percent shading.
        self.globals["wdTexture37Pt5Percent".lower()] = 375
        #  40 percent shading.
        self.globals["wdTexture40Percent".lower()] = 400
        #  42.5 percent shading.
        self.globals["wdTexture42Pt5Percent".lower()] = 425
        #  45 percent shading.
        self.globals["wdTexture45Percent".lower()] = 450
        #  47.5 percent shading.
        self.globals["wdTexture47Pt5Percent".lower()] = 475
        #  50 percent shading.
        self.globals["wdTexture50Percent".lower()] = 500
        #  52.5 percent shading.
        self.globals["wdTexture52Pt5Percent".lower()] = 525
        #  55 percent shading.
        self.globals["wdTexture55Percent".lower()] = 550
        #  57.5 percent shading.
        self.globals["wdTexture57Pt5Percent".lower()] = 575
        #  5 percent shading.
        self.globals["wdTexture5Percent".lower()] = 50
        #  60 percent shading.
        self.globals["wdTexture60Percent".lower()] = 600
        #  62.5 percent shading.
        self.globals["wdTexture62Pt5Percent".lower()] = 625
        #  65 percent shading.
        self.globals["wdTexture65Percent".lower()] = 650
        #  67.5 percent shading.
        self.globals["wdTexture67Pt5Percent".lower()] = 675
        #  70 percent shading.
        self.globals["wdTexture70Percent".lower()] = 700
        #  72.5 percent shading.
        self.globals["wdTexture72Pt5Percent".lower()] = 725
        #  75 percent shading.
        self.globals["wdTexture75Percent".lower()] = 750
        #  77.5 percent shading.
        self.globals["wdTexture77Pt5Percent".lower()] = 775
        #  7.5 percent shading.
        self.globals["wdTexture7Pt5Percent".lower()] = 75
        #  80 percent shading.
        self.globals["wdTexture80Percent".lower()] = 800
        #  82.5 percent shading.
        self.globals["wdTexture82Pt5Percent".lower()] = 825
        #  85 percent shading.
        self.globals["wdTexture85Percent".lower()] = 850
        #  87.5 percent shading.
        self.globals["wdTexture87Pt5Percent".lower()] = 875
        #  90 percent shading.
        self.globals["wdTexture90Percent".lower()] = 900
        #  92.5 percent shading.
        self.globals["wdTexture92Pt5Percent".lower()] = 925
        #  95 percent shading.
        self.globals["wdTexture95Percent".lower()] = 950
        #  97.5 percent shading.
        self.globals["wdTexture97Pt5Percent".lower()] = 975
        #  Horizontal cross shading.
        self.globals["wdTextureCross".lower()] = -11
        #  Dark horizontal cross shading.
        self.globals["wdTextureDarkCross".lower()] = -5
        #  Dark diagonal cross shading.
        self.globals["wdTextureDarkDiagonalCross".lower()] = -6
        #  Dark diagonal down shading.
        self.globals["wdTextureDarkDiagonalDown".lower()] = -3
        #  Dark diagonal up shading.
        self.globals["wdTextureDarkDiagonalUp".lower()] = -4
        #  Dark horizontal shading.
        self.globals["wdTextureDarkHorizontal".lower()] = -1
        #  Dark vertical shading.
        self.globals["wdTextureDarkVertical".lower()] = -2
        #  Diagonal cross shading.
        self.globals["wdTextureDiagonalCross".lower()] = -12
        #  Diagonal down shading.
        self.globals["wdTextureDiagonalDown".lower()] = -9
        #  Diagonal up shading.
        self.globals["wdTextureDiagonalUp".lower()] = -10
        #  Horizontal shading.
        self.globals["wdTextureHorizontal".lower()] = -7
        #  No shading.
        self.globals["wdTextureNone".lower()] = 0
        #  Solid shading.
        self.globals["wdTextureSolid".lower()] = 1000
        #  Vertical shading.
        self.globals["wdTextureVertical".lower()] = -8
        
        # WdTofFormat enumeration (Word)
        #   
        # Specifies the type of formatting to apply to the table of figures in the active document.
        
        #  Centered formatting.
        self.globals["wdTOFCentered".lower()] = 3
        #  Classic formatting.
        self.globals["wdTOFClassic".lower()] = 1
        #  Distinctive formatting.
        self.globals["wdTOFDistinctive".lower()] = 2
        #  Formal formatting.
        self.globals["wdTOFFormal".lower()] = 4
        #  Simple formatting.
        self.globals["wdTOFSimple".lower()] = 5
        #  Template formatting.
        self.globals["wdTOFTemplate".lower()] = 0

        # WdStoryType enumeration (Word)

        # Comments story.
        self.globals["wdCommentsStory".lower()] = 4	
        # Endnote continuation notice story.
        self.globals["wdEndnoteContinuationNoticeStory".lower()] = 17	
        # Endnote continuation separator story.
        self.globals["wdEndnoteContinuationSeparatorStory".lower()] = 16	
        # Endnote separator story.
        self.globals["wdEndnoteSeparatorStory".lower()] = 15	
        # Endnotes story.
        self.globals["wdEndnotesStory".lower()] = 3	
        # Even pages footer story.
        self.globals["wdEvenPagesFooterStory".lower()] = 8	
        # Even pages header story.
        self.globals["wdEvenPagesHeaderStory".lower()] = 6	
        # First page footer story.
        self.globals["wdFirstPageFooterStory".lower()] = 11	
        # First page header story.
        self.globals["wdFirstPageHeaderStory".lower()] = 10	
        # Footnote continuation notice story.
        self.globals["wdFootnoteContinuationNoticeStory".lower()] = 14	
        # Footnote continuation separator story.
        self.globals["wdFootnoteContinuationSeparatorStory".lower()] = 13	
        # Footnote separator story.
        self.globals["wdFootnoteSeparatorStory".lower()] = 12	
        # Footnotes story.
        self.globals["wdFootnotesStory".lower()] = 2	
        # Main text story.
        self.globals["wdMainTextStory".lower()] = 1	
        # Primary footer story.
        self.globals["wdPrimaryFooterStory".lower()] = 9	
        # Primary header story.
        self.globals["wdPrimaryHeaderStory".lower()] = 7	
        # Text frame story.
        self.globals["wdTextFrameStory".lower()] = 5	
        
        # WdTwoLinesInOneType enumeration (Word)
        #   
        # Specifies the character to use to enclose two lines being written into one.
        
        #  Enclose the lines using angle brackets.
        self.globals["wdTwoLinesInOneAngleBrackets".lower()] = 4
        #  Enclose the lines using curly brackets.
        self.globals["wdTwoLinesInOneCurlyBrackets".lower()] = 5
        #  Use no enclosing character.
        self.globals["wdTwoLinesInOneNoBrackets".lower()] = 1
        #  Restore the two lines of text written into one to two separate lines.
        self.globals["wdTwoLinesInOneNone".lower()] = 0
        #  Enclose the lines using parentheses.
        self.globals["wdTwoLinesInOneParentheses".lower()] = 2
        #  Enclose the lines using square brackets.
        self.globals["wdTwoLinesInOneSquareBrackets".lower()] = 3
        
        # WdCountry enumeration (Word)
        #   
        # Specifies the country/region setting of the current system.
        
        #  Argentina
        self.globals["wdArgentina".lower()] = 54
        #  Brazil
        self.globals["wdBrazil".lower()] = 55
        #  Canada
        self.globals["wdCanada".lower()] = 2
        #  Chile
        self.globals["wdChile".lower()] = 56
        #  China
        self.globals["wdChina".lower()] = 86
        #  Denmark
        self.globals["wdDenmark".lower()] = 45
        #  Finland
        self.globals["wdFinland".lower()] = 358
        #  France
        self.globals["wdFrance".lower()] = 33
        #  Germany
        self.globals["wdGermany".lower()] = 49
        #  Iceland
        self.globals["wdIceland".lower()] = 354
        #  Italy
        self.globals["wdItaly".lower()] = 39
        #  Japan
        self.globals["wdJapan".lower()] = 81
        #  Korea
        self.globals["wdKorea".lower()] = 82
        #  Latin America
        self.globals["wdLatinAmerica".lower()] = 3
        #  Mexico
        self.globals["wdMexico".lower()] = 52
        #  Netherlands
        self.globals["wdNetherlands".lower()] = 31
        #  Norway
        self.globals["wdNorway".lower()] = 47
        #  Peru
        self.globals["wdPeru".lower()] = 51
        #  Spain
        self.globals["wdSpain".lower()] = 34
        #  Sweden
        self.globals["wdSweden".lower()] = 46
        #  Taiwan
        self.globals["wdTaiwan".lower()] = 886
        #  United Kingdom
        self.globals["wdUK".lower()] = 44
        #  United States
        self.globals["wdUS".lower()] = 1
        #  Venezuela
        self.globals["wdVenezuela".lower()] = 58
        
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

        # WdOrientation enumeration (Word)
        self.globals["wdOrientLandscape".lower()] = 1
        self.globals["wdOrientPortrait".lower()] = 0
        
        # Misc.
        self.globals["ActiveDocument.PageSetup.PageWidth".lower()] = 10
        self.globals["ThisDocument.PageSetup.PageWidth".lower()] = 10
        self.globals["ActiveDocument.PageSetup.Orientation".lower()] = 1
        self.globals["ThisDocument.PageSetup.Orientation".lower()] = 1
        self.globals["ActiveDocument.Scripts.Count".lower()] = 0
        self.globals["ThisDocument.Scripts.Count".lower()] = 0

        self.globals["ActiveDocument.FullName".lower()] = "C:\\CURRENT_FILE_NAME.docm"
        self.globals["ThisDocument.FullName".lower()] = "C:\\CURRENT_FILE_NAME.docm"
        self.globals["ActiveDocument.Name".lower()] = "CURRENT_FILE_NAME.docm"
        self.globals["ThisDocument.Name".lower()] = "CURRENT_FILE_NAME.docm"
        self.globals["Application.ActiveDocument.FullName".lower()] = "C:\\CURRENT_FILE_NAME.docm"
        self.globals["Application.ThisDocument.FullName".lower()] = "C:\\CURRENT_FILE_NAME.docm"
        self.globals["Application.ActiveDocument.Name".lower()] = "CURRENT_FILE_NAME.docm"
        self.globals["Application.ThisDocument.Name".lower()] = "CURRENT_FILE_NAME.docm"

        self.globals["ActiveWorkbook.FullName".lower()] = "C:\\CURRENT_FILE_NAME.xls"
        self.globals["ThisWorkbook.FullName".lower()] = "C:\\CURRENT_FILE_NAME.xls"
        self.globals["ActiveWorkbook.Name".lower()] = "CURRENT_FILE_NAME.xls"
        self.globals["ThisWorkbook.Name".lower()] = "CURRENT_FILE_NAME.xls"
        self.globals["Application.ActiveWorkbook.FullName".lower()] = "C:\\CURRENT_FILE_NAME.xls"
        self.globals["Application.ThisWorkbook.FullName".lower()] = "C:\\CURRENT_FILE_NAME.xls"
        self.globals["Application.ActiveWorkbook.Name".lower()] = "CURRENT_FILE_NAME.xls"
        self.globals["Application.ThisWorkbook.Name".lower()] = "CURRENT_FILE_NAME.xls"

        self.globals["ActiveDocument.Application.StartupPath".lower()] = "C:\\AppData\\Local\\Temp\\"
        
        self.globals["TotalPhysicalMemory".lower()] = 2097741824
        self.globals["OSlanguage".lower()] = "**MATCH ANY**"
        self.globals["Err.Number".lower()] = "**MATCH ANY**"
        self.globals["Err.HelpFile".lower()] = "Some value for Err.HelpFile"
        self.globals["Err.HelpContext".lower()] = "Some value for Err.HelpContext"
        self.globals["Selection".lower()] = "**SELECTED TEXT IN DOC**"
        self.globals["msoFontAlignTop".lower()] = 1
        self.globals["msoTextBox".lower()] = "**MATCH ANY**"
        self.globals["Application.MouseAvailable".lower()] = True
        self.globals["Application.PathSeparator".lower()] = "\\"
        self.globals["Application.Name".lower()] = "Microsoft Word"
        self.globals["RecentFiles.Count".lower()] = 4 + random.randint(1, 10)
        self.globals["ActiveDocument.Revisions.Count".lower()] = 1 + random.randint(1, 3)
        self.globals["ThisDocument.Revisions.Count".lower()] = 1 + random.randint(1, 3)
        self.globals["Revisions.Count".lower()] = 1 + random.randint(1, 3)
        self.globals["ReadyState".lower()] = "**MATCH ANY**"
        self.globals["Application.Caption".lower()] = "**MATCH ANY**"
        self.globals["Application.System.Version".lower()] = "**MATCH ANY**"
        self.globals["BackStyle".lower()] = "**MATCH ANY**"
        self.globals["responseText".lower()] = "**MATCH ANY**"
        self.globals["NumberOfLogicalProcessors".lower()] = 4
        self.globals[".NumberOfLogicalProcessors".lower()] = 4
        self.globals["ActiveWorkbook.Name".lower()] = "**MATCH ANY**"
        self.globals["me.Status".lower()] = 200
        self.globals["BackColor".lower()] = "**MATCH ANY**"
        self.globals["me.BackColor".lower()] = "**MATCH ANY**"
        self.globals["Empty".lower()] = "NULL"
        self.globals["Scripting.FileSystemObject.Drives.DriveLetter".lower()] = "B"
        self.globals["Wscript.ScriptName".lower()] = "__CURRENT_SCRIPT_NAME__"
        
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
        self.globals["xlThousandMillions".lower()] = -9
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

        # MsoAnimationType Enum
        #
        # This object, member, or enumeration is deprecated and is not intended to be used in your code.
        self.globals["msoAnimationAppear".lower()] = 32	
        self.globals["msoAnimationBeginSpeaking".lower()] = 4	
        self.globals["msoAnimationCharacterSuccessMajor".lower()] = 6	
        self.globals["msoAnimationCheckingSomething".lower()] = 103	
        self.globals["msoAnimationDisappear".lower()] = 31	
        self.globals["msoAnimationEmptyTrash".lower()] = 116	
        self.globals["msoAnimationGestureDown".lower()] = 113	
        self.globals["msoAnimationGestureLeft".lower()] = 114	
        self.globals["msoAnimationGestureRight".lower()] = 19	
        self.globals["msoAnimationGestureUp".lower()] = 115	
        self.globals["msoAnimationGetArtsy".lower()] = 100	
        self.globals["msoAnimationGetAttentionMajor".lower()] = 11	
        self.globals["msoAnimationGetAttentionMinor".lower()] = 12	
        self.globals["msoAnimationGetTechy".lower()] = 101	
        self.globals["msoAnimationGetWizardy".lower()] = 102	
        self.globals["msoAnimationGoodbye".lower()] = 3	
        self.globals["msoAnimationGreeting".lower()] = 2	
        self.globals["msoAnimationIdle".lower()] = 1	
        self.globals["msoAnimationListensToComputer".lower()] = 26	
        self.globals["msoAnimationLookDown".lower()] = 104	
        self.globals["msoAnimationLookDownLeft".lower()] = 105	
        self.globals["msoAnimationLookDownRight".lower()] = 106	
        self.globals["msoAnimationLookLeft".lower()] = 107	
        self.globals["msoAnimationLookRight".lower()] = 108	
        self.globals["msoAnimationLookUp".lower()] = 109	
        self.globals["msoAnimationLookUpLeft".lower()] = 110	
        self.globals["msoAnimationLookUpRight".lower()] = 111	
        self.globals["msoAnimationPrinting".lower()] = 18	
        self.globals["msoAnimationRestPose".lower()] = 5	
        self.globals["msoAnimationSaving".lower()] = 112	
        self.globals["msoAnimationSearching".lower()] = 13	
        self.globals["msoAnimationSendingMail".lower()] = 25	
        self.globals["msoAnimationThinking".lower()] = 24	
        self.globals["msoAnimationWorkingAtSomething".lower()] = 23	
        self.globals["msoAnimationWritingNotingSomething".lower()] = 22	

        # MsoAutoSize Enum
        #
        # Determines the type of automatic sizing allowed.        
        self.globals["msoAutoSizeNone".lower()] = 0	
        self.globals["msoAutoSizeShapeToFitText".lower()] = 1	
        self.globals["msoAutoSizeTextToFitShape".lower()] = 2	
        
        # WdSaveFormat enumeration (Word)
        self.globals["wdFormatDocument".lower()] = 0
        self.globals["wdFormatDOSText".lower()] = 4
        self.globals["wdFormatDOSTextLineBreaks".lower()] = 5
        self.globals["wdFormatEncodedText".lower()] = 7
        self.globals["wdFormatFilteredHTML".lower()] = 10
        self.globals["wdFormatFlatXML".lower()] = 19
        self.globals["wdFormatFlatXMLMacroEnabled".lower()] = 20
        self.globals["wdFormatFlatXMLTemplate".lower()] = 21
        self.globals["wdFormatFlatXMLTemplateMacroEnabled".lower()] = 22
        self.globals["wdFormatOpenDocumentText".lower()] = 23
        self.globals["wdFormatHTML".lower()] = 8
        self.globals["wdFormatRTF".lower()] = 6
        self.globals["wdFormatStrictOpenXMLDocument".lower()] = 24
        self.globals["wdFormatTemplate".lower()] = 1
        self.globals["wdFormatText".lower()] = 2
        self.globals["wdFormatTextLineBreaks".lower()] = 3
        self.globals["wdFormatUnicodeText".lower()] = 7
        self.globals["wdFormatWebArchive".lower()] = 9
        self.globals["wdFormatXML".lower()] = 11
        self.globals["wdFormatDocument97".lower()] = 0
        self.globals["wdFormatDocumentDefault".lower()] = 16
        self.globals["wdFormatPDF".lower()] = 17
        self.globals["wdFormatTemplate97".lower()] = 1
        self.globals["wdFormatXMLDocument".lower()] = 12
        self.globals["wdFormatXMLDocumentMacroEnabled".lower()] = 13
        self.globals["wdFormatXMLTemplate".lower()] = 14
        self.globals["wdFormatXMLTemplateMacroEnabled".lower()] = 15
        self.globals["wdFormatXPS".lower()] = 18

        # WdUnderline enumeration (Word)
        #
        # Specifies the type of underline to apply.
        
        #  Dashes.
        self.globals["wdUnderlineDash".lower()] = 7
        #  Heavy dashes.
        self.globals["wdUnderlineDashHeavy".lower()] = 23
        #  Long dashes.
        self.globals["wdUnderlineDashLong".lower()] = 39
        #  Long heavy dashes.
        self.globals["wdUnderlineDashLongHeavy".lower()] = 55
        #  Alternating dots and dashes.
        self.globals["wdUnderlineDotDash".lower()] = 9
        #  Alternating heavy dots and heavy dashes.
        self.globals["wdUnderlineDotDashHeavy".lower()] = 25
        #  An alternating dot-dot-dash pattern.
        self.globals["wdUnderlineDotDotDash".lower()] = 10
        #  An alternating heavy dot-dot-dash pattern.
        self.globals["wdUnderlineDotDotDashHeavy".lower()] = 26
        #  Dots.
        self.globals["wdUnderlineDotted".lower()] = 4
        #  Heavy dots.
        self.globals["wdUnderlineDottedHeavy".lower()] = 20
        #  A double line.
        self.globals["wdUnderlineDouble".lower()] = 3
        self.types["wdUnderlineDouble".lower()] = "Integer"
        #  No underline.
        self.globals["wdUnderlineNone".lower()] = 0
        #  A single line. default.
        self.globals["wdUnderlineSingle".lower()] = 1
        #  A single thick line.
        self.globals["wdUnderlineThick".lower()] = 6
        #  A single wavy line.
        self.globals["wdUnderlineWavy".lower()] = 11
        #  A double wavy line.
        self.globals["wdUnderlineWavyDouble".lower()] = 43
        #  A heavy wavy line.
        self.globals["wdUnderlineWavyHeavy".lower()] = 27
        #  Underline individual words only.        
        self.globals["wdUnderlineWords".lower()] = 2
        
        # endregion

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

####### Global VBA Constant Repository
all_vba_constants = VbaConstants()
