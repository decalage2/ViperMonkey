#!/usr/bin/env python
"""
ViperMonkey: VBA Grammar - Reserved Keywords

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

from pyparsing import *

from logger import log
from identifiers import *

# --- RESERVED KEYWORDS ------------------------------------------------------

def caselessKeywordsList(keywords):
    """
    build a pyparsing parser from a list of caseless keywords

    :param keywords: tuple or list of keyword names (strings)
    """
    # start with the first keyword:
    p = CaselessKeyword(keywords[0])
    # then add all the other keywords:
    for kw in keywords[1:]:
        p |= CaselessKeyword(kw)
    return p

# 3.3.5.2 Reserved Identifiers and IDENTIFIER
# A <Statement-keyword> is a <reserved-identifier> that is the first syntactic item of a statement or
# declaration.
statement_keyword = caselessKeywordsList(
    ("Call", "Const", "Declare", "DefBool", "DefByte",
     "DefCur", "DefDate", "DefDbl", "DefInt", "DefLng", "DefLngLng", "DefLngPtr", "DefObj",
     "DefSng", "DefStr", "DefVar", "Dim", "Do", "Else", "ElseIf", "End", "EndIf",
     "Enum", "Event", "Exit", "For", "Friend", "Function",
     "GoSub", "GoTo", "If", "Implements", "Let", "Lock", "Loop", "LSet", "Next",
     "On", "Open", "Option", "Private", "Public", "RaiseEvent", "ReDim",
     "Resume", "RSet", "Select", "Set", "Static", "Stop", "Sub",
     "Unlock", "Wend", "While", "With", "Write"))

rem_keyword = CaselessKeyword("Rem")

# A <marker-keyword> is a <reserved-identifier> that is used as part of the interior
# syntactic structure of a statement.
marker_keyword = caselessKeywordsList(
    ("Any", "As", "ByRef", "ByVal ", "Case", "Each", "Else", "In", "New",
     "Shared", "Until", "WithEvents", "Write", "Optional", "ParamArray", "Preserve",
     "Tab", "Then"))

# An <operator-identifier> is a <reserved-identifier> that is used
# as an operator within expressions.
operator_identifier = caselessKeywordsList(
    ("AddressOf", "And", "Eqv", "Imp", "Is", "Like", "New", "Mod",
     "Not", "Or", "TypeOf", "Xor"))

# A <reserved-name> is a <reserved-identifier> that is used within expressions
# as if it was a normal program defined entity (section 2.2).
reserved_name = caselessKeywordsList((  # TODO: fix this one!
    "Asc", "Abs", "CBool", "CByte", "CCur", "CDate",  # "CDbl", "CDec", "CInt",
    "CLng", "CLngLng", "CLngPtr", "CSng", "CStr", "CVar", "CVErr",
    "DoEvents", "Fix", "Int", "Len", "LenB", "PSet", "Sgn", "String"))

# A <special-form> is a <reserved-identifier> that is used in an expression as
# if it was a program defined procedure name but which has special syntactic rules for
# its argument.
special_form = caselessKeywordsList((
    "Array", "Circle", "InputB", "LBound", "UBound"))

# A <reserved-type-identifier> is used within a declaration to identify the specific
# declared type (section 2.2) of an entity.

# TODO: Add more of these as needed or generalize.
#reserved_complex_type_identifier = caselessKeywordsList(("MSForms.fmScrollAction", "MSForms.ReturnSingle"))
simple_type_identifier = Word(initChars=alphas, bodyChars=alphanums + '_')
reserved_complex_type_identifier = Group(simple_type_identifier + ZeroOrMore("." + simple_type_identifier))

reserved_atomic_type_identifier = caselessKeywordsList((
    "Boolean", "Byte", "Currency", "Date", "Double", "Integer",
    "Long", "LongLong", "LongPtr", "Single", "String", "Variant"))

reserved_type_identifier = reserved_atomic_type_identifier | reserved_complex_type_identifier

# A <boolean-literal-identifier> specifying "true" or "false" has a declared type of
# Boolean and a data value of True or False, respectively.
boolean_literal_identifier = CaselessKeyword("true") | CaselessKeyword("false")

# An <object-literal-identifier> has a
# declared type of Object and the data value Nothing.
object_literal_identifier = CaselessKeyword("nothing")

# A <variant-literal-identifier> specifying
# "empty" or "null" has a declared type of Variant and the data value Empty or Null, respectively.
variant_literal_identifier = CaselessKeyword("empty") | CaselessKeyword("null")

# A <literal-identifier> is a <reserved-identifier> that represents a specific distinguished data value
# (section 2.1).
#literal_identifier = boolean_literal_identifier | object_literal_identifier \
#                     | variant_literal_identifier
literal_identifier = boolean_literal_identifier | object_literal_identifier

# A <reserved-for-implementation-use> is a <reserved-identifier> that currently has no defined
# meaning to the VBA language but is reserved for use by language implementers.
reserved_for_implementation_use = caselessKeywordsList((
    "Attribute", "LINEINPUT", "VB_Base", "VB_Control",
    "VB_Creatable", "VB_Customizable", "VB_Description", "VB_Exposed", "VB_Ext_KEY ",
    "VB_GlobalNameSpace", "VB_HelpID", "VB_Invoke_Func", "VB_Invoke_Property ",
    "VB_Invoke_PropertyPut", "VB_Invoke_PropertyPutRefVB_MemberFlags", "VB_Name",
    "VB_PredeclaredId", "VB_ProcData", "VB_TemplateDerived", "VB_UserMemId",
    "VB_VarDescription", "VB_VarHelpID", "VB_VarMemberFlags", "VB_VarProcData ",
    "VB_VarUserMemId"))

# A <future-reserved> is a <reserved-identifier> that currently has no defined meaning to the VBA language but
# is reserved for possible future extensions to the language.
future_reserved = caselessKeywordsList(("CDecl", "Decimal", "DefDec"))

# reserved-identifier = Statement-keyword / marker-keyword / operator-identifier /
# special-form / reserved-name / literal-identifier / rem-keyword /
# reserved-for-implementation-use / future-reserved
reserved_identifier = statement_keyword | marker_keyword | operator_identifier \
                      | special_form | reserved_name | literal_identifier | rem_keyword \
                      | reserved_for_implementation_use | future_reserved

