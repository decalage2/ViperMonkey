"""@package vipermonkey.core.statements Parsing and emulation of
VBA/VBScript statements.

"""

# pylint: disable=pointless-string-statement
"""
ViperMonkey: VBA Grammar - Statements

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

# ------------------------------------------------------------------------------
# CHANGELOG:
# 2015-02-12 v0.01 PL: - first prototype
# 2015-2016        PL: - many updates
# 2016-06-11 v0.02 PL: - split vipermonkey into several modules
# 2018-06-20 v0.06 PL: - fixed a slight issue in Dim_Statement.__repr__

__version__ = '0.08'

# --- IMPORTS ------------------------------------------------------------------

import logging

# Important: need to change the default pyparsing whitespace setting, because CRLF
# is not a whitespace for VBA.
import pyparsing
pyparsing.ParserElement.setDefaultWhitespaceChars(' \t\x19')

from pyparsing import CaselessKeyword, Combine, delimitedList, FollowedBy, \
    Forward, Group, LineStart, Literal, NotAny, OneOrMore, Optional, \
    ParseException, ParseResults, Regex, Suppress, White, ZeroOrMore, \
    CharsNotIn

from identifiers import identifier, lex_identifier, TODO_identifier_or_object_attrib, \
    TODO_identifier_or_object_attrib_loose, enum_val_id, unrestricted_name, \
    reserved_type_identifier, typed_name
from literals import integer, quoted_string, literal, decimal_literal, \
    quoted_string_keep_quotes
from comments_eol import rem_statement, EOS
from expressions import any_expression, boolean_expression, BoolExpr, expression, \
    file_pointer, function_call, Function_Call, member_access_expression, \
    MemberAccessExpression, simple_name_expression, SimpleNameExpression, \
    file_pointer_loose, expr_list, expr_const, expr_list_strict, \
    function_call_limited
from vba_context import Context, is_procedure
from reserved import reserved_complex_type_identifier
from from_unicode_str import from_unicode_str
from vba_object import eval_arg, eval_args, VbaLibraryFunc, VBA_Object
from python_jit import _loop_vars_to_python, to_python, _updated_vars_to_python, _eval_python, \
    enter_loop, exit_loop
import procedures
from var_in_expr_visitor import var_in_expr_visitor
from function_call_visitor import function_call_visitor
import vb_str
import loop_transform
import utils
from utils import safe_str_convert
import vba_conversion

import traceback
from logger import log
import sys
import re
import base64
from curses_ascii import isprint
import hashlib

def is_simple_statement(s):
    """Check to see if the given VBAObject is a simple (not compound)
    statement.
    
    @param s (VBA_Object object) The VBA Object to check.

    @return (boolean) True if it is a simple statement, False if not.

    """
    return isinstance(s, (Dim_Statement,
                          Exit_For_Statement,
                          Exit_Function_Statement,
                          Exit_While_Statement,
                          File_Open,
                          Goto_Statement,
                          LSet_Statement,
                          Let_Statement,
                          On_Error_Statement,
                          Option_Statement,
                          Print_Statement,
                          Prop_Assign_Statement,
                          Redim_Statement))
    

# --- UNKNOWN STATEMENT ------------------------------------------------------

class UnknownStatement(VBA_Object):
    """Base class for all VBA statement objects (used to emulate
    VBA/VBScript statements).

    """

    def __init__(self, original_str, location, tokens):
        super(UnknownStatement, self).__init__(original_str, location, tokens)
        self.text = tokens.text
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Unknown statement: %s' % repr(self.text)

    def eval(self, context, params=None):

        # pylint.
        params = params
        context = context
        
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug(self)


# Known keywords used at the beginning of statements
known_keywords_statement_start = (Optional(CaselessKeyword('Public') | CaselessKeyword('Private') | CaselessKeyword('End')) + \
                                  (CaselessKeyword('Sub') | CaselessKeyword('Function'))) | \
                                  CaselessKeyword('Set') | CaselessKeyword('For') | CaselessKeyword('Next') | \
                                  CaselessKeyword('If') | CaselessKeyword('Then') | CaselessKeyword('Else') | \
                                  CaselessKeyword('ElseIf') | CaselessKeyword('End If') | CaselessKeyword('New') | \
                                  CaselessKeyword('#If') | CaselessKeyword('#Else') | \
                                  CaselessKeyword('#ElseIf') | CaselessKeyword('#End If') | \
                                  CaselessKeyword('Exit') | CaselessKeyword('Type') | \
                                  CaselessKeyword('As') | CaselessKeyword("ByVal") | \
                                  CaselessKeyword('While') | CaselessKeyword('Do') | \
                                  CaselessKeyword('Until') | CaselessKeyword('Select') | \
                                  CaselessKeyword('Case') | CaselessKeyword('On') | CaselessKeyword('End') 

# catch-all for unknown statements
unknown_statement = NotAny(known_keywords_statement_start) + \
                    Combine(OneOrMore(CharsNotIn('":\'\x0A\x0D') | quoted_string_keep_quotes),
                            adjacent=False).setResultsName('text')
unknown_statement.setParseAction(UnknownStatement)


# --- ATTRIBUTE statement ----------------------------------------------------------

# 4.2 Modules

class Attribute_Statement(VBA_Object):
    """Emulate a VB Attribute statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(Attribute_Statement, self).__init__(original_str, location, tokens)
        self.name = tokens.name
        self.value = tokens.value
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Attribute %s = %r' % (self.name, self.value)


# MS-GRAMMAR: procedural-module-header = attribute "VB_Name" attr-eq quoted-identifier attr-end
# MS-GRAMMAR: class-module-header = 1*class-attr
# MS-GRAMMAR: class-attr = attribute "VB_Name" attr-eq quoted-identifier attr-end
# / attribute "VB_GlobalNameSpace" attr-eq "False" attr-end
# / attribute "VB_Creatable" attr-eq "False" attr-end
# / attribute "VB_PredeclaredId" attr-eq boolean-literal-identifier attr-end
# / attribute "VB_Exposed" attr-eq boolean-literal-identifier attr-end
# / attribute "VB_Customizable" attr-eq boolean-literal-identifier attr-end
# MS-GRAMMAR: attribute = LINE-START "Attribute"
# MS-GRAMMAR: attr-eq = "="
# MS-GRAMMAR: attr-end = LINE-END
# MS-GRAMMAR: quoted-identifier = double-quote NO-WS IDENTIFIER NO-WS double-quote

quoted_identifier = Combine(Suppress('"') + identifier + Suppress('"'))
quoted_identifier.setParseAction(lambda t: str(t[0]))

# TODO: here I use lex_identifier instead of identifier because attrib names are reserved identifiers
attribute_statement = CaselessKeyword('Attribute').suppress() + lex_identifier('name') + Suppress('=') + literal('value')
attribute_statement.setParseAction(Attribute_Statement)

# --- OPTION statement ----------------------------------------------------------

class Option_Statement(VBA_Object):
    """Emulate a VB Option statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(Option_Statement, self).__init__(original_str, location, tokens)
        self.name = tokens.name
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as Option_Statement' % self)

    def __repr__(self):
        return 'Option %s' % (self.name)


option_statement = CaselessKeyword('Option').suppress() + unrestricted_name + Optional(unrestricted_name)
option_statement.setParseAction(Option_Statement)

# --- TYPE EXPRESSIONS -------------------------------------------------------

# 5.6.16.7 Type Expressions
#
# MS-GRAMMAR: type-expression = BUILTIN-TYPE / defined-type-expression
# MS-GRAMMAR: defined-type-expression = simple-name-expression / member-access-expression

# TODO: for now we use a generic syntax
type_expression = lex_identifier + Optional('.' + lex_identifier)

# --- TYPE DECLARATIONS -------------------------------------------------------

type_declaration_composite = Optional(CaselessKeyword('Public') | CaselessKeyword('Private')) + CaselessKeyword('Type') + \
                             lex_identifier + Suppress(EOS) + \
                             OneOrMore(lex_identifier + \
                                       Optional(Suppress(Literal('(') + Optional(expr_list) + Literal(')'))) + \
                                       Optional(Suppress(Literal('(') + expression + CaselessKeyword("To") + expression + Literal(')'))) + \
                                       CaselessKeyword('As') + reserved_type_identifier + \
                                       Suppress(Optional("*" + (decimal_literal | lex_identifier))) + Suppress(EOS)) + \
                             CaselessKeyword('End') + CaselessKeyword('Type') + \
                             ZeroOrMore( Literal(':') + (CaselessKeyword('Public') | CaselessKeyword('Private')) + \
                                         CaselessKeyword('Type') + lex_identifier + \
                                         Optional(Suppress(Literal('(') + Optional(expr_list) + Literal(')'))) + \
                                         Suppress(EOS) + \
                                         OneOrMore(lex_identifier + CaselessKeyword('As') + reserved_type_identifier + \
                                                   Suppress(EOS)) + \
                                         CaselessKeyword('End') + CaselessKeyword('Type') )

type_declaration = type_declaration_composite

# --- FUNCTION TYPE DECLARATIONS ---------------------------------------------

# 5.3.1.4 Function Type Declarations
#
# MS-GRAMMAR: function-type = "as" type-expression [array-designator]
# MS-GRAMMAR: array-designator = "(" ")"

array_designator = Literal("(") + Literal(")")
function_type = CaselessKeyword("as") + type_expression + Optional(array_designator)

# --- PARAMETERS ----------------------------------------------------------

class Parameter(VBA_Object):
    """VBA parameter with name and type, e.g. 'abc as string'

    """

    def __init__(self, original_str, location, tokens):
        super(Parameter, self).__init__(original_str, location, tokens)
        self.name = tokens.name
        self.my_type = tokens.type
        self.init_val = tokens.init_val
        self.is_array = False
        self.mechanism = safe_str_convert(tokens.mechanism)
        self.is_optional = (len(tokens.is_optional) > 0)
        # Is this an array parameter?
        if (('(' in safe_str_convert(tokens)) and (')' in safe_str_convert(tokens))):
            # Arrays are always passed by reference.
            self.mechanism = 'ByRef'
            self.is_array = True
        # The default parameter passing mechanism is ByRef.
        # See https://www.bettersolutions.com/vba/macros/byval-or-byref.htm
        if (len(self.mechanism) == 0):
            self.mechanism = 'ByRef'
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as Parameter' % self)

    def __repr__(self):
        r = ""
        if (self.mechanism):
            r += safe_str_convert(self.mechanism) + " "
        r += safe_str_convert(self.name)
        if self.my_type:
            r += ' as ' + safe_str_convert(self.my_type)
        if (self.init_val):
            r += ' = ' + safe_str_convert(self.init_val)
        return r

    def to_python(self, context, params=None, indent=0):

        # pylint.
        params = params
        indent = indent
        
        name_str = safe_str_convert(self.name)
        init_str = ""
        if ((self.init_val is not None) and (len(safe_str_convert(self.init_val)) > 0)):
            init_str = "=" + to_python(self.init_val, context=context)
        r = name_str + init_str
        return r
    
# 5.3.1.5 Parameter Lists
#
# MS-GRAMMAR: procedure-parameters = "(" [parameter-list] ")"
# MS-GRAMMAR: property-parameters = "(" [parameter-list ","] value-param ")"
# MS-GRAMMAR: parameter-list = (positional-parameters "," optional-parameters )
#                   / (positional-parameters ["," param-array])
#                   / optional-parameters / param-array
# MS-GRAMMAR: positional-parameters = positional-param *("," positional-param)
# MS-GRAMMAR: optional-parameters = optional-param *("," optional-param)
# MS-GRAMMAR: value-param = positional-param
# MS-GRAMMAR: positional-param = [parameter-mechanism] param-dcl
# MS-GRAMMAR: optional-param = optional-prefix param-dcl [default-value]
# MS-GRAMMAR: param-array = "paramarray" IDENTIFIER "(" ")" ["as" ("variant" / "[variant]")]
# MS-GRAMMAR: param-dcl = untyped-name-param-dcl / typed-name-param-dcl
# MS-GRAMMAR: untyped-name-param-dcl = IDENTIFIER [parameter-type]
# MS-GRAMMAR: typed-name-param-dcl = TYPED-NAME [array-designator]
# MS-GRAMMAR: optional-prefix = ("optional" [parameter-mechanism]) / ([parameter-mechanism] ("optional"))
# MS-GRAMMAR: parameter-mechanism = "byval" / " byref"
# MS-GRAMMAR: parameter-type = [array-designator] "as" (type-expression / "Any")
# MS-GRAMMAR: default-value = "=" constant-expression


default_value = Literal("=").suppress() + expr_const('default_value')  # TODO: constant_expression

parameter_mechanism = CaselessKeyword('ByVal') | CaselessKeyword('ByRef')

optional_prefix = (CaselessKeyword("optional") + parameter_mechanism) \
                  | (parameter_mechanism + CaselessKeyword("optional"))

parameter_type = Optional(array_designator) + CaselessKeyword("as").suppress() \
                 + (type_expression | CaselessKeyword("Any"))

untyped_name_param_dcl = identifier + Optional(parameter_type)

# MS-GRAMMAR: procedure_parameters = "(" [parameter_list] ")"
# MS-GRAMMAR: property_parameters = "(" [parameter_list ","] value_param ")"
# MS-GRAMMAR: parameter_list = (positional_parameters "," optional_parameters )
#                   | (positional_parameters ["," param_array])
#                   | optional_parameters | param_array
# MS-GRAMMAR: positional_parameters = positional_param *("," positional_param)
# MS-GRAMMAR: optional_parameters = optional_param *("," optional_param)
# MS-GRAMMAR: value_param = positional_param
# MS-GRAMMAR: positional_param = [parameter_mechanism] param_dcl
# MS-GRAMMAR: optional_param = optional_prefix param_dcl [default_value]
# MS-GRAMMAR: param_array = "paramarray" IDENTIFIER "(" ")" ["as" ("variant" | "[variant]")]
# MS-GRAMMAR: param_dcl = untyped_name_param_dcl | typed_name_param_dcl
# MS-GRAMMAR: typed_name_param_dcl = TYPED_NAME [array_designator]

parameter = Optional(CaselessKeyword("optional").suppress())('is_optional') + \
            Optional(parameter_mechanism('mechanism')) + Optional(CaselessKeyword("ParamArray").suppress()) + \
            TODO_identifier_or_object_attrib('name') + \
            Optional(CaselessKeyword("(") + ZeroOrMore(" ").suppress() + CaselessKeyword(")")) + \
            Optional(CaselessKeyword('as').suppress() + (lex_identifier('type') ^ reserved_complex_type_identifier('type'))) + \
            Optional('=' + expression('init_val'))
parameter.setParseAction(Parameter)

parameters_list = delimitedList(parameter, delim=',')

# --- STATEMENT LABELS -------------------------------------------------------

# 5.4.1.1 Statement Labels
#
# MS-GRAMMAR: statement-label-definition = LINE-START ((identifier-statement-label ":") / (line-number-label [":"] ))
# MS-GRAMMAR: statement-label = identifier-statement-label / line-number-label
# MS-GRAMMAR: statement-label-list = statement-label ["," statement-label]
# MS-GRAMMAR: identifier-statement-label = IDENTIFIER
# MS-GRAMMAR: line-number-label = INTEGER

statement_label_definition = LineStart() + ((identifier('label_name') + Suppress(":"))
                                            | (integer('label_int') + Optional(Suppress(":"))))
statement_label = identifier | integer
statement_label_list = delimitedList(statement_label, delim=',')

# --- STATEMENT BLOCKS -------------------------------------------------------

# 5.4.1 Statement Blocks
#
# A statement block is a sequence of 0 or more statements.
#
# MS-GRAMMAR: statement-block = *(block-statement EOS)
# MS-GRAMMAR: block-statement = statement-label-definition / rem-statement / statement
# MS-GRAMMAR: statement = control-statement / data-manipulation-statement / error-handling-statement / filestatement

# --- TAGGED BLOCK ------------------------------------------------------
# Associate a block of statements with a label. This will be used to handle
# GOTO statements.

class TaggedBlock(VBA_Object):
    """A label and the block of statements associated with the label.

    """

    def __init__(self, original_str, location, tokens):
        super(TaggedBlock, self).__init__(original_str, location, tokens)
        if (tokens is None):
            # Make empty tagged block object.
            return
        self.block = tokens.block
        self.label = safe_str_convert(tokens.label).replace(":", "")
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Tagged Block: %s: %s' % (repr(self.label), repr(self.block))

    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return

        # Assign all const variables first.
        do_const_assignments(self.block, context)

        for s in self.block:
            if (not hasattr(s, "eval")):
                continue
            s.eval(context, params=params)

            # Was there an error that will make us jump to an error handler?
            if (context.must_handle_error()):
                break
            context.clear_error()

            # Did we just run a GOTO? If so we should not run the
            # statements after the GOTO.
            if (context.goto_executed or s.exited_with_goto):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("GOTO executed. Go to next loop iteration.")
                break
            
        # Run the error handler if we have one and we broke out of the statement
        # loop with an error.
        context.handle_error(params)


tagged_block = Forward()
label_statement = Forward()
        
# need to declare statement beforehand:
statement = Forward()
statement_no_orphan = Forward()
statements_line = Forward()
statements_line_no_eos = Forward()
statement_restricted = Forward()
external_function = Forward()

# NOTE: statements should NOT include EOS
block_statement = rem_statement | external_function | (statement_no_orphan ^ statements_line_no_eos)
# tagged_block broken out so it does not consume the final EOS in the statement block.
simple_call_list = Forward()
statement_block = ZeroOrMore(simple_call_list ^ tagged_block ^ (block_statement + EOS.suppress()))
statement_block_not_empty = OneOrMore(tagged_block ^ (block_statement + EOS.suppress()))
tagged_block <<= label_statement('label') + Suppress(EOS) + statement_block('block')
tagged_block.setParseAction(TaggedBlock)

def do_const_assignments(code_block, context):
    """Perform all of the const variable declarations in a given code
    block (used during emulation). This sets the values of all named
    constants assigned in the given code block.

    @param code_block (list) A list of statements.
    
    @param context (Context object) The context in which to save
    the constant assignments.

    """

    # Make sure we can iterate.
    if (not isinstance(code_block, list)):
        code_block = [code_block]

    # Emulate all the const assignments in the code block.
    for s in code_block:
        if (isinstance(s, Dim_Statement) and (s.decl_type.lower() == "const")):
            log.info("Pre-running const assignment '" + safe_str_convert(s) + "'")
            s.eval(context)

# --- DIM statement ----------------------------------------------------------

class Dim_Statement(VBA_Object):
    """Emulate a Dim statement.

    """

    def __init__(self, original_str, location, tokens):
        super(Dim_Statement, self).__init__(original_str, location, tokens)
        
        # Track whether this is a const variable.
        self.decl_type = ""
        var_info = []
        for f in tokens:
            if (safe_str_convert(f).lower() == "const"):
                self.decl_type = safe_str_convert(f)
            if (isinstance(f, ParseResults)):
                var_info.append(f)
        tokens = var_info
        
        # Track the initial value of the variable.
        self.init_val = "NULL"
        last_var = tokens[0]
        if ((len(last_var) >= 3) and
            (last_var[len(last_var) - 2] == '=')):
            self.init_val = last_var[len(last_var) - 1]
            
        # Track each variable being declared.
        self.variables = []
        for var in tokens:

            # Is this an array?
            is_array = False
            size = None
            if ((len(var) > 1) and (var[1] == '(')):
                is_array = True
                if (isinstance(var[2], int)):
                    size = var[2]
                if ((len(var) > 3) and (isinstance(var[3], int))):
                    size = var[3]

            # Do we have a type for the variable?
            curr_type = None
            if ((len(var) > 1) and
                (var[-1:][0] != ")") and
                (var[-1:][0] != self.init_val)):
                curr_type = var[-1:][0]

            # Save the variable info.
            self.variables.append((var[0], is_array, curr_type, size))

        # Handle multiple variables declared with the same type.
        tmp_vars = []
        final_type = self.variables[len(self.variables) - 1][2]
        for var in self.variables:
            curr_type = var[2]
            if (curr_type is None):
                curr_type = final_type
            tmp_vars.append((var[0], var[1], curr_type, var[3]))
        self.variables = tmp_vars
        
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as Dim_Statement' % safe_str_convert(self))

    def __repr__(self):
        r = "Dim "
        first = True
        for var in self.variables:
            if (not first):
                r += ", "
            first = False
            r += safe_str_convert(var[0])
            if (var[1]):
                r += "("
                if (var[3] is not None):
                    r += safe_str_convert(var[3])
                r += ")"
            if (var[2]):
                r += " As " + safe_str_convert(var[2])
        if (self.init_val is not None):
            r += " = " + safe_str_convert(self.init_val)
        return r

    def to_python(self, context, params=None, indent=0):        

        # pylint.
        params = params
        
        # Get Python code for the initial variable value(s).
        init_val = ''
        if (self.init_val is not None):
            init_val = to_python(self.init_val, context=context)
            
        # Track each declared variable.
        r = ""
        for var in self.variables:

            # Do we know the variable type?
            curr_init_val = init_val
            curr_type = var[2]
            if (curr_type is not None):

                # Get the initial value.
                if ((curr_type == "Long") or
                    (curr_type == "Byte") or
                    (curr_type == "Integer")):
                    curr_init_val = "0"
                if (curr_type == "String"):
                    curr_init_val = '""'
                if (curr_type == "Boolean"):
                    curr_init_val = "False"
                
                # Is this variable an array?
                if (var[1]):
                    curr_type += " Array"
                    curr_init_val = []
                    if ((var[3] is not None) and
                        ((curr_type == "Byte Array") or
                         (curr_type == "Long Array") or
                         (curr_type == "Integer Array"))):
                        curr_init_val = safe_str_convert([0] * (var[3] + 1))
                    if ((var[3] is not None) and (curr_type == "String Array")):
                        curr_init_val = safe_str_convert([''] * var[3])
                    if ((var[3] is not None) and (curr_type == "Boolean Array")):
                        curr_init_val = [False] * var[3]

            # Handle untyped arrays.
            elif (var[1]):
                curr_init_val = safe_str_convert([])

            # Handle uninitialized global variables.
            if ((context.global_scope) and (curr_init_val is None)):
                curr_init_val = "0"

            # Keep the current variable value if this variable already exists.
            if (context.contains(var[0], local=True)):
                vm_val = context.get(var[0])
                if (vm_val == "__ALREADY_SET__"):
                    vm_val = context.get("__ORIG__" + var[0])
                curr_init_val = to_python(vm_val, context)

            # Handle VB NULL values.
            if (curr_init_val == '"NULL"'):
                curr_init_val = "0"

            # Save the current variable in the copy of the context so
            # later calls of to_python() know the type of the variable.
            context.set(var[0], "__ALREADY_SET__", var_type=curr_type)
            context.set(var[0], "__ALREADY_SET__", var_type=curr_type, force_global=True)
            context.set("__ORIG__" + var[0], curr_init_val, force_local=True)
            context.set("__ORIG__" + var[0], curr_init_val, force_global=True)
                
            # Set the initial value of the declared variable.
            var_name = utils.fix_python_overlap(safe_str_convert(var[0]))
            r += " " * indent + var_name + " = " + safe_str_convert(curr_init_val) + "\n"

        # Done.
        return r
    
    def eval(self, context, params=None):

        # pylint.
        params = params

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return

        # Evaluate the initial variable value(s).
        init_val = ''
        if (self.init_val is not None):
            init_val = eval_arg(self.init_val, context=context)
            
        # Track each declared variable.
        for var in self.variables:

            # Do we know the variable type?
            curr_init_val = init_val
            curr_type = var[2]
            if (curr_type is not None):

                # Get the initial value.
                curr_type = safe_str_convert(curr_type)
                if ((curr_type == "Long") or (curr_type == "Integer")):
                    curr_init_val = 0
                if (curr_type == "String"):
                    curr_init_val = ''
                if (curr_type == "Boolean"):
                    curr_init_val = False
                
                # Is this variable an array?
                if (var[1]):
                    curr_type += " Array"
                    curr_init_val = []
                    if ((var[3] is not None) and
                        ((curr_type == "Byte Array") or (curr_type == "Integer Array"))):
                        curr_init_val = [0] * (var[3] + 1)
                    if ((var[3] is not None) and (curr_type == "String Array")):
                        curr_init_val = [''] * var[3]

            # Handle untyped arrays.
            elif (var[1]):
                curr_init_val = []
                # Know # of elements?
                if (var[3] is not None):
                    # Assume NULL.
                    curr_init_val = [0] * (var[3] + 1)

            # Handle uninitialized global variables.
            if ((context.global_scope) and (curr_init_val is None)):
                curr_init_val = "NULL"

            # Keep the current variable value if this variable already exists.
            if (context.contains(var[0], local=True)):
                curr_init_val = context.get(var[0])
                
            # Set the initial value of the declared variable. And the type.
            is_const = (self.decl_type.lower() == "const")
            is_local = context.in_procedure and (not is_const)
            context.set(var[0], curr_init_val, var_type=curr_type, force_global=is_const, force_local=is_local)
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("DIM " + safe_str_convert(var[0]) + " As " + safe_str_convert(curr_type) + " = " + safe_str_convert(curr_init_val))
    
# 5.4.3.1 Local Variable Declarations
#
# MS-GRAMMAR: local-variable-declaration = ("Dim" ["Shared"] variable-declaration-list)
# MS-GRAMMAR: static-variable-declaration = "Static" variable-declaration-list

# 5.2.3.1 Module Variable Declaration Lists
#
# MS-GRAMMAR: module-variable-declaration = public-variable-declaration / private-variable-declaration
# MS-GRAMMAR: global-variable-declaration = "Global" variable-declaration-list
# MS-GRAMMAR: public-variable-declaration = "Public" ["Shared"] module-variable-declaration-list
# MS-GRAMMAR: private-variable-declaration = ("Private" / "Dim") [ "Shared"] module-variable-declaration-list
# MS-GRAMMAR: module-variable-declaration-list = (withevents-variable-dcl / variable-dcl) *( "," (withevents-variable-dcl / variable-dcl) )
# MS-GRAMMAR: variable-declaration-list = variable-dcl *( "," variable-dcl )

# 5.2.3.1.1 Variable Declarations
#
# MS-GRAMMAR: variable-dcl = typed-variable-dcl / untyped-variable-dcl
# MS-GRAMMAR: typed-variable-dcl = TYPED-NAME [array-dim]
# MS-GRAMMAR: untyped-variable-dcl = IDENTIFIER [array-clause / as-clause]
# MS-GRAMMAR: array-clause = array-dim [as-clause]
# MS-GRAMMAR: as-clause = as-auto-object / as-type

# 5.2.3.1.3 Array Dimensions and Bounds
#
# MS-GRAMMAR: array-dim = "(" [bounds-list] ")"
# MS-GRAMMAR: bounds-list = dim-spec *("," dim-spec)
# MS-GRAMMAR: dim-spec = [lower-bound] upper-bound
# MS-GRAMMAR: lower-bound = constant-expression "to"
# MS-GRAMMAR: upper-bound = constant-expression

# 5.6.16.1 Constant Expressions
#
# A constant expression is an expression usable in contexts which require a value that can be fully
# evaluated statically.
#
# MS-GRAMMAR: constant-expression = expression

# 5.2.3.1.4 Variable Type Declarations
#
# A type specification determines the specified type of a declaration.
#
# MS-GRAMMAR: as-auto-object = "as" "new" class-type-name
# MS-GRAMMAR: as-type = "as" type-spec
# MS-GRAMMAR: type-spec = fixed-length-string-spec / type-expression
# MS-GRAMMAR: fixed-length-string-spec = "string" "*" string-length
# MS-GRAMMAR: string-length = constant-name / INTEGER
# MS-GRAMMAR: constant-name = simple-name-expression

# 5.2.3.1.2 WithEvents Variable Declarations
#
# MS-GRAMMAR: withevents-variable-dcl = "withevents" IDENTIFIER "as" class-type-name
# MS-GRAMMAR: class-type-name = defined-type-expression

# 5.6.16.7 Type Expressions
#
# MS-GRAMMAR: type-expression = BUILTIN-TYPE / defined-type-expression
# MS-GRAMMAR: defined-type-expression = simple-name-expression / member-access-expression


constant_expression = expression
lower_bound = constant_expression + CaselessKeyword('to').suppress()
upper_bound = constant_expression
dim_spec = Optional(lower_bound) + upper_bound
bounds_list = delimitedList(dim_spec)
array_dim = '(' + Optional(bounds_list('bounds')) + ')'
constant_name = simple_name_expression
string_length = constant_name | integer
fixed_length_string_spec = CaselessKeyword("string").suppress() + Suppress("*") + string_length
type_spec = fixed_length_string_spec | type_expression
as_type = CaselessKeyword('As').suppress() + type_spec
defined_type_expression = simple_name_expression  # TODO: | member_access_expression
class_type_name = defined_type_expression
as_auto_object = CaselessKeyword('as').suppress() + CaselessKeyword('new').suppress() + expression
as_clause = as_auto_object | as_type
array_clause = array_dim('bounds') + Optional(as_clause)
untyped_variable_dcl = Suppress(Optional(CaselessKeyword("WithEvents"))) + identifier + Optional(array_clause('bounds') | as_clause)
typed_variable_dcl = Suppress(Optional(CaselessKeyword("WithEvents"))) + typed_name + Optional(array_dim)
# TODO: Set the initial value of the global var in the context.
variable_dcl = (typed_variable_dcl | untyped_variable_dcl) + Optional('=' + expression('expression'))
variable_declaration_list = delimitedList(Group(variable_dcl))
local_variable_declaration = (CaselessKeyword("Dim") | \
                              CaselessKeyword("Static") | \
                              (Suppress(Optional(Literal("#"))) + CaselessKeyword("Const"))) + \
                             Optional(CaselessKeyword("Shared")).suppress() + variable_declaration_list

dim_statement = local_variable_declaration
dim_statement.setParseAction(Dim_Statement)

# --- Global_Var_Statement statement ----------------------------------------------------------

# TODO: Support multiple variables set (e.g. 'name = "bob", age = 20\n')
class Global_Var_Statement(Dim_Statement):
    """A global variable definition statement.

    """    
    pass


public_private = Forward()
global_variable_declaration = Optional(public_private) + \
                              Optional(CaselessKeyword("Shared")).suppress() + \
                              Optional(CaselessKeyword("Const")) + \
                              variable_declaration_list
global_variable_declaration.setParseAction(Global_Var_Statement)

# --- LET STATEMENT --------------------------------------------------------------

class Let_Statement(VBA_Object):
    """A Let variable assignment statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(Let_Statement, self).__init__(original_str, location, tokens)

        # Are we just making an empty Let_Statement object?
        self.string_op = None
        self.index = None
        self.index1 = None
        if (original_str is None):
            return

        # We are making a Let_Statement from parse results.
        self.name = tokens.name
        string_ops = set(["mid", "mid$"])
        self.string_op = None
        if (hasattr(self.name, "__len__") and
            (len(self.name) > 0) and
            (self.name[0].lower() in string_ops)):
            self.string_op = {}
            self.string_op["op"] = self.name[0].lower()
            self.string_op["args"] = self.name[1:]
        self.expression = tokens.expression
        self.index = None
        if (tokens.index != ''):
            self.index = tokens.index
        self.index1 = None
        if (tokens.index1 != ''):
            self.index1 = tokens.index1
        self.op = tokens["op"]
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as Let_Statement' % self)

    def __repr__(self):
        if (self.index is None):
            return 'Let %s %s %r' % (self.name, self.op, self.expression)
        return 'Let %s(%r) %s %r' % (self.name, self.index, self.op, self.expression)

    def to_python(self, context, params=None, indent=0):        

        # If we are not assigning to a boolean variable, assume that any
        # boolean operators on the RHS are bitwise operators.
        old_in_bitwise = context.in_bitwise_expression
        if (context.get_type(self.name) != "Boolean"):
            context.in_bitwise_expression = True
            
        # Are we updating a global variable?
        r = ""
        try:

            # Don't flag funcs as global in Python JIT code.            
            var_val = context.get(self.name, global_only=True)
            if ((not isinstance(var_val, (VbaLibraryFunc, procedures.Function, procedures.Sub))) and
                (var_val != "__FUNC_ARG__") and
                (var_val != "__ALREADY_SET__")):
                
                # It's global and not a func. Treat as global in Python.
                spaces = " " * indent
                r += "global " + utils.fix_python_overlap(safe_str_convert(self.name)) + \
                     "\n" + spaces

        # Not a global.
        except KeyError:
            pass

        # Regular assignment?
        python_var_name = safe_str_convert(self.name)
        if (self.index is None):
            
            # Annoying Mid() assignment?
            if ((self.string_op is not None) and
                ((self.string_op["op"] == "mid") or (self.string_op["op"] == "mid$"))):
                
                # Get the string to modify, substring start index, and substring length.
                args = self.string_op["args"]
                if (len(args) < 3):
                    context.in_bitwise_expression = old_in_bitwise
                    return "ERROR: Wrong # args to mid. " + safe_str_convert(self)
                the_str_var = to_python(args[0], context)
                start = to_python(args[1], context)
                size = to_python(args[2], context)
                rhs = to_python(self.expression, context)
                
                # Modify the string in Python.
                start_chunk = the_str_var + "[:" + start + "-1]"
                end_chunk = the_str_var + "[(" + start + "-1 + " + size + "):]"
                r += the_str_var + " = " + start_chunk + " + " + rhs + " + " + end_chunk

            # Handle conversion of strings to byte arrays, if needed.
            elif (context.get_type(self.name) == "Byte Array"):
                val = "coerce_to_int_list(" + to_python(self.expression, context, params=params) + ")"
                r += utils.fix_python_overlap(python_var_name) + " " + safe_str_convert(self.op) + " " + val

            # Handle conversion of byte arrays to strings, if needed.
            elif (context.get_type(self.name) == "String"):
                val = "coerce_to_str(" + to_python(self.expression, context, params=params) + ")"
                r += utils.fix_python_overlap(python_var_name) + " " + safe_str_convert(self.op) + " " + val

            # Basic assignment.
            else:
                r += utils.fix_python_overlap(python_var_name) + " " + \
                     safe_str_convert(self.op) + " " + \
                     to_python(self.expression, context, params=params)
                
        # Array assignment?
        else:
            py_var = utils.fix_python_overlap(python_var_name)
            if (py_var.startswith(".")):
                py_var = py_var[1:]
            index = to_python(self.index, context, params=params)
            indices = [index]
            if (self.index1 is not None):
                indices.append(to_python(self.index1, context, params=params))
            val = to_python(self.expression, context, params=params)
            op = safe_str_convert(self.op)
            index_str = ""
            first = True
            for i in indices:
                if (not first):
                    index_str += ", "
                first = False
                index_str += i
            index_str = "[" + index_str + "]"
            if (op == "="):
                r += py_var + " = update_array(" + py_var + ", " + index_str + ", " + val + ")"
            else:
                r += py_var + "[" + index + "] " + op + " " + val

        # Mark this variable as set so it does not get overwritten by
        # future to_python() code generation.
        context.set(self.name, "__ALREADY_SET__")

        # Reset whether we think we are in a bitwise expression.
        context.in_bitwise_expression = old_in_bitwise
        
        # Done.
        if (r.startswith(".")):
            r = r[1:]
        r = " " * indent + r
        return r
        
    def _handle_change_callback(self, var_name, context):
        """Handle calling the change callback handler function for a
        variable. This will emulate the change callback handler
        function if the given variable has a callback handler. It will
        do nothing if the variable does not have a callback handler.

        @param var_name (str) The name of the assigned variable.

        @param context (Context object) The context containing the
        callback handler definitions.

        """
        
        # Get the variable name, minus any embedded context.
        var_name = safe_str_convert(var_name)
        if ("." in var_name):
            var_name = var_name[var_name.rindex(".") + 1:]

        # Get the name of the change callback for the variable.
        callback_name = var_name + "_Change"

        # Do we have any functions defined with this callback name?
        try:

            # Can we find something with this name?
            callback = context.get(callback_name)
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Found change callback " + callback_name)

            # Is it a function?
            if ((is_procedure(callback)) and
                (callback_name not in context.skip_handlers)):

                # Block recursive calls of the handler.
                context.skip_handlers.add(callback_name)
                
                # Yes it is. Run it.
                log.info("Running change callback " + callback_name)
                callback.eval(context)
                
                # Open back up recursive calls of the handler.
                context.skip_handlers.remove(callback_name)

        except KeyError:

            # No callback.
            pass

    def _make_let_statement(self, the_str_var, mod_str):
        """Make a Let_Statement object to assign the results of a Mid()
        assignment to the proper variable. This handles assigning to
        items in an array if needed.

        @param the_str_var (VBA_Object object) The variable containing
        the string value being modified with the Mid() assignment.

        @param mod_str (VBA_Object object) The new value for the string.

        @return (VBA_Object object) A Let statement assigning the
        string variable to the new value. Actually looks like a
        regular 'foo = bar' assignment rather than a weird 'Mid(...) =
        bar' statement.

        """

        # Make an empty Let statement.
        tmp_let = Let_Statement(None, None, None)

        # Do we have an array item assignment?
        tmp_let.name = the_str_var
        if (isinstance(the_str_var, Function_Call)):

            # Pull out the name of the 'function'. This is the array var name.
            tmp_let.name = the_str_var.name

            # The array indices are the 'function' args.
            if (len(the_str_var.params) > 0):
                tmp_let.index = the_str_var.params[0]
            if (len(the_str_var.params) > 1):
                tmp_let.index1 = the_str_var.params[1]

        # Set the value to assign.
        tmp_let.expression = mod_str
        tmp_let.op = "="

        # Done.
        return tmp_let
        
    def _handle_string_mod(self, context, rhs):
        """Handle assignments like Mid(a_string, start_pos, len) = "..."

        @param context (Context object) The context in which to save
        the string variable modification.

        @param rhs (VBA_Object object) The already evalulated
        (emulated) value on the right hand side of the assignment
        statement.

        @return (boolean) True if this is a Mid() string modification
        and the context has been updated, False if not.

        """

        # Are we modifying a string?
        if (self.string_op is None):
            return False

        # Modifying a substring?
        if ((self.string_op["op"] == "mid") or (self.string_op["op"] == "mid$")):

            # Get the string to modify, substring start index, and substring length.
            args = self.string_op["args"]
            if (len(args) < 3):
                return False
            the_str = eval_arg(args[0], context)
            the_str_var = args[0]
            start = vba_conversion.int_convert(eval_arg(args[1], context), leave_alone=True)
            size = vba_conversion.int_convert(eval_arg(args[2], context), leave_alone=True)
            
            # Sanity check.
            if ((not isinstance(the_str, str)) and (not isinstance(the_str, list))):
                context.report_general_error("Assigning " + safe_str_convert(self.name) + " failed. " + safe_str_convert(the_str_var) + " not str or list.")
                return False
            # pylint: disable=unidiomatic-typecheck
            if (type(the_str) != type(rhs)):
                context.report_general_error("Assigning " + safe_str_convert(self.name) + " failed. " + safe_str_convert(type(the_str)) + " != " + safe_str_convert(type(rhs)))
                return False
            if (not isinstance(start, int)):
                context.report_general_error("Assigning " + safe_str_convert(self.name) + " failed. Start is not int (" + safe_str_convert(type(start)) + ").")
                return False
            if (not isinstance(size, int)):
                context.report_general_error("Assigning " + safe_str_convert(self.name) + " failed. Size is not int (" + safe_str_convert(type(size)) + ").")
                return False
            if (((start-1 + size) > len(the_str)) or (start < 1)):
                context.report_general_error("Assigning " + safe_str_convert(self.name) + " failed. " + safe_str_convert(start + size) + " out of range.")
                return False

            # Convert to a VB string to handle mixed ASCII/wide char weirdness.
            vb_rhs = vb_str.VbStr(rhs, context.is_vbscript)
            
            # Fix the length of the new data if needed.
            if (vb_rhs.len() > size):
                #rhs = rhs[:size]
                vb_rhs = vb_rhs.get_chunk(0, size)
            if (vb_rhs.len() < size):
                #size = len(rhs)
                size = vb_rhs.len()
                
            # Modify the string.
            vb_the_str = vb_str.VbStr(the_str, context.is_vbscript)
            #mod_str = the_str[:start-1] + rhs + the_str[(start-1 + size):]
            mod_str = vb_the_str.update_chunk(start - 1, start - 1 + size, vb_rhs).to_python_str()

            # Set the string in the context.
            tmp_let = self._make_let_statement(the_str_var, mod_str)
            tmp_let.eval(context)
            return True

        # No string modification.
        return False

    def _handle_autoincrement(self, lhs, rhs):
        """Handle '+=' and '-=' assignment statements.

        @param lhs (VBA_Object object) The left hand side of the
        assignment (already evaluated).
        
        @param rhs (VBA_Object object) The right hand side of the
        assignment (already evaluated).

        @return (??) The result of adding/subtracting the given RHS
        and LHS.

        """
        
        # Add/subtract the rhs from the lhs.
        r = "NULL"
        try:
            if (self.op == "+="):
                r = (lhs + rhs)
            elif (self.op == "-="):
                r = (lhs - rhs)
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("_handle_autoincrement() failed. " + safe_str_convert(e))
        return r

    def _handle_lhs_call(self, context):
        """Handle resolving the LHS where the LHS of the assignment is
        actually a function call, not a variable.

        @param context (Context object) The context in which to save
        the results of the assignment.

        @return (VBA_Object object) The LHS parsed as a function call
        if the LHS is a function call, None if it is not.

        """
        
        # See if the LHS is actually a valid function call.
        if (self.index is None):
            return None
        func_name = safe_str_convert(self.name)
        if ("." in func_name):
            func_name = func_name[func_name.rindex(".") + 1:]
        func_call_str = func_name + "(" + safe_str_convert(self.index).replace("'", "") + ")"
        try:
            func_call = function_call.parseString(func_call_str, parseAll=True)[0]
            return func_call.eval(context)
        except ParseException:
            pass
        return None

    def _convert_str_to_byte_array(self, value, context):
        """Convert a string value to a VB byte array.

        @param value (??) Should be a str for this method to do
        something.

        @param (Context object) The context containing variable types
        (used to figure out whether the string should be converted to
        a byte array).

        @return (tuple) A 2 element tuple where the 1st element is the
        converted (or not) value and the 2nd element is a flag
        indicating if the value was actually converted.

        """

        # Handle conversion of strings to byte arrays, if needed.
        orig_value = value
        if (not ((context.get_type(self.name) == "Byte Array") and
                 (isinstance(value, str)))):
            return (value, value != orig_value)

        # Do we have an actual value to assign?
        if (value != "NULL"):

            # Base64 decoded raw data should not be padded with 0 between each
            # byte. Try to figure out if this is raw data.
            bad_byte_count = 0
            for c in value:
                if (not isprint(c)):
                    bad_byte_count += 1
            is_raw_data = ((len(value) > 0) and (((bad_byte_count + 0.0)/len(value)) > .2))
                    
            # Generate the byte array for the string.
            tmp = []
            for c in value:

                # Append the byte value of the character.
                tmp.append(ord(c))

                # Append padding 0 bytes for wide char strings.
                #
                # TODO: Figure out how VBA figures out if this is a wide string (0 padding added)
                # or not (no padding).
                if ((not isinstance(value, from_unicode_str)) and (not is_raw_data)):
                    tmp.append(0)

            # Got the byte array.
            value = tmp
            return (value, value != orig_value)

        # We are dealing with an unsassigned variable. Don't update
        # the array.
        return (None, True)

    def _convert_byte_array_to_str(self, value, context):
        """Convert a VB byte array to a string value.

        @param value (??) Should be a list for this method to do
        something.

        @param (Context object) The context containing variable types
        (used to figure out whether the byte array should be converted to
        a string).

        @return (tuple) A 2 element tuple where the 1st element is the
        converted (or not) value and the 2nd element is a flag
        indicating if the value was actually converted.

        """

        # Handle conversion of byte arrays to strings, if needed.
        orig_value = value
        if (not ((context.get_type(self.name) == "String") and
                 (isinstance(value, list)))):
            return (value, value != orig_value)
            
        # Do we have a list of integers?
        rhs_type = context.get_type(safe_str_convert(self.expression))
        all_ints = True
        for i in value:
            if (not isinstance(i, int)):
                all_ints = False
                break
        if (all_ints):
            try:
                tmp = ""
                pos = 0
                # TODO: Only handles ASCII strings.
                step = 2
                if ((rhs_type == "Byte Array") or
                    (rhs_type == "Byte")):
                    step = 1
                while (pos < len(value)):
                    # Skip null bytes.
                    c = value[pos]
                    if (c == 0):
                        pos += step
                        continue

                    # Append the byte converted to a character.
                    tmp += chr(c)
                    pos += step
                value = tmp
            except ValueError:
                pass

        # Do we have a list of characters?
        all_chars = True
        for i in value:
            if ((i is not None) and
                ((not isinstance(i, str)) or (len(i) > 1))):
                all_chars = False
                break
        if (all_chars):
            tmp = ""
            for i in value:
                if (i is not None):
                    tmp += i
            value = tmp        

        # Done.
        return (value, value != orig_value)
            
    def eval(self, context, params=None):

        # pylint.
        params = params        

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return
        
        # If a function return value is being set (LHS == current function name),
        # treat references to the function name on the RHS as a variable rather
        # than a function. Do this by initializing a local variable with the function
        # name here if needed.
        if ((context.contains(self.name)) and
            (isinstance(context.get(self.name), procedures.Function))):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Adding uninitialized '" + safe_str_convert(self.name) + "' function return var to local context.")
            context.set(self.name, 'NULL', force_local=True)
        
        # evaluate value of right operand:
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('try eval expression: %s' % self.expression)
        value = eval_arg(self.expression, context=context)
        if (context.have_error()):
            log.warn('Short circuiting assignment %s due to thrown VB error.' % safe_str_convert(self))
            return
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('eval expression: %s = %s' % (self.expression, value))

        # Doing base64 decode with VBA? Maybe?
        if (self.name == ".Text"):

            # Try converting the text from base64.
            try:
                tmp_str = filter(isprint, safe_str_convert(value).strip())
                value = base64.b64decode(tmp_str)
            except Exception as e:
                log.warning("base64 conversion of '" + safe_str_convert(value) + "' failed. " + safe_str_convert(e))

        # Is this setting an interesting field in a COM object?
        if ((safe_str_convert(self.name).endswith(".Arguments")) or
            (safe_str_convert(self.name).endswith(".Path"))):
            context.report_action(self.name, value, 'Possible Scheduled Task Setup', strip_null_bytes=True)
        if (safe_str_convert(self.name).endswith(".CommandLine")):
            context.report_action('Run Command', value, self.name, strip_null_bytes=True)
            
        # Modifying a string using something like Mid() on the LHS of the assignment?
        if (self._handle_string_mod(context, value)):
            return

        # Setting OnSheetActivate function?
        if (safe_str_convert(self.name).endswith("OnSheetActivate")):

            # Emulate the OnSheetActivate function.
            func_name = safe_str_convert(self.expression).strip()
            try:
                func = context.get(func_name)
                log.info("Emulating OnSheetActivate handler function " + func_name + "...")
                func.eval(context)
                return
            except KeyError:
                context.report_general_error("WARNING: Cannot find OnSheetActivate handler function %s" % func_name)

        # Handle auto increment/decrement.
        if ((self.op == "+=") or (self.op == "-=")):
            lhs = context.get(self.name)
            value = self._handle_autoincrement(lhs, value)

        # set variable, non-array access.
        if (self.index is None):

            # Handle conversion of strings to byte arrays, if needed.
            value, changed = self._convert_str_to_byte_array(value, context)
            if (value is None):
                return
                    
            # Handle conversion of byte arrays to strings, if needed.
            if (not changed):
                value, changed = self._convert_byte_array_to_str(value, context)
                if (value is None):
                    return

            # Handle conversion of strings to int, if needed.
            if ((not changed) and
                (((context.get_type(self.name) == "Integer") or
                  (context.get_type(self.name) == "Long")) and
                 (isinstance(value, str)))):
                try:
                    if (value == "NULL"):
                        value = 0
                    else:
                        value = int(value)
                except ValueError:
                    context.report_general_error("Cannot convert '" + safe_str_convert(value) + "' to int. Defaulting to 0.")
                    value = 0

            # Update the variable, if there was no error.
            if (value != "ERROR"):

                # Update the variable.
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug('setting %s = %s' % (self.name, value))
                context.set(self.name, value)

                # See if there is a change callback function for the updated variable.
                self._handle_change_callback(self.name, context)

            else:

                # TODO: Currently we are assuming that 'On Error Resume Next' is being
                # used. Need to actually check what is being done on error.
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug('Not setting ' + self.name + ", eval of RHS gave an error.")

        # Set variable, array access.
        else:

            # Handle conversion of strings to integers, if needed.
            if (((context.get_type(self.name) == "Long Array") or
                 (context.get_type(self.name) == "Integer Array")) and
                (isinstance(value, str))):

                # Do we have an actual value to assign?
                if (value != "NULL"):

                    # Parse the expression to see if it can be resolved to an integer.
                    num = "not an integer"
                    try:
                        expr = expression.parseString(value, parseAll=True)[0]
                        num = safe_str_convert(expr)
                        if (hasattr(expr, "eval")):
                            num = safe_str_convert(expr.eval(context))
                    except ParseException:
                        context.report_general_error("Cannot parse '" + value + "' to integer.")
                    if (not num.isdigit()):
                        context.report_general_error("Cannot convert '" + value + "' to integer. Setting to 0.")
                        num = 0
                    else:
                        num = int(num)
                    value = num
                        
            # Evaluate the index expression(s).
            index = vba_conversion.int_convert(eval_arg(self.index, context=context))
            index1 = None
            if (self.index1 is not None):
                index1 = vba_conversion.int_convert(eval_arg(self.index1, context=context))
                
            # Is array variable being set already represented as a list?
            # Or a string?
            arr_var = None
            try:
                arr_var = context.get(self.name)
            except KeyError:
                context.report_general_error("WARNING: Cannot find array variable %s" % self.name)

                # Maybe this is a goofy function call?
                call_r = self._handle_lhs_call(context)
                if (call_r is not None):
                    return

                # Not a goofy function call. Assume this is an undefined array variable.
                arr_var = []
                
            if ((not isinstance(arr_var, list)) and (not isinstance(arr_var, str))):

                # We are wiping out whatever value this had.
                arr_var = []

            # Handle lists
            if ((isinstance(arr_var, list)) and (index >= 0)):

                # Do we need to extend the length of the list to include the indices?
                if (index >= len(arr_var)):
                    arr_var.extend([0] * (index - len(arr_var) + 1))
                if (index1 is not None):
                    if (not isinstance(arr_var[index], list)):
                        arr_var[index] = []
                    if (index1 >= len(arr_var[index])):
                        arr_var[index].extend([0] * (index1 - len(arr_var[index])))
                
                # We now have a list with the proper # of elements. Set the
                # array element to the proper value.
                if (index1 is None):
                    arr_var = arr_var[:index] + [value] + arr_var[(index + 1):]
                else:
                    new_arr = arr_var[index]
                    new_arr = new_arr[:index1] + [value] + new_arr[(index1 + 1):]
                    arr_var[index] = new_arr

            # Handle strings.
            if isinstance(arr_var, (str, unicode)):

                # Do we need to extend the length of the string to include the index?
                if (index >= len(arr_var)):
                    arr_var += "\0"*(index - len(arr_var))
                
                # We now have a string with the proper # of elements. Set the
                # array element to the proper value.
                if isinstance(value, (str, unicode)):
                    arr_var = arr_var[:index] + value + arr_var[(index + 1):]
                elif (isinstance(value, int)):
                    try:
                        arr_var = arr_var[:index] + chr(value) + arr_var[(index + 1):]
                    except Exception as e:
                        log.error(safe_str_convert(e))
                        context.report_general_error(safe_str_convert(value) + " cannot be converted to ASCII.")
                else:
                    context.report_general_error("Unhandled value type " + safe_str_convert(type(value)) + " for array update.")
                        
            # Finally save the updated variable in the context, if there was no error.
            if (value != "ERROR"):

                # Update the array.
                context.set(self.name, arr_var)

                # See if there is a change callback function for the updated variable.
                self._handle_change_callback(self.name, context)

            else:

                # TODO: Currently we are assuming that 'On Error Resume Next' is being
                # used. Need to actually check what is being done on error.
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug('Not setting ' + self.name + ", eval of RHS gave an error.")

# --- LSET STATEMENT --------------------------------------------------------------

class LSet_Statement(Let_Statement):
    """Emulate a LSet statement.

    """
    
    # TODO: Extend eval() method to do the left string alignment of LSet.
    # See https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/lset-statement
    pass


# 5.4.3.8   Let Statement
#
# A let statement performs Let-assignment of a non-object value. The Let keyword itself is optional
# and may be omitted.
#
# MS-GRAMMAR: let-statement = ["Let"] l-expression "=" expression

# TODO: remove Set when Set_Statement implemented:

# Mid(zLGzE1gWt, MbgQPcQzy, 1)
string_modification = (CaselessKeyword('Mid') | CaselessKeyword('Mid$')) + \
                      Optional(Suppress('(')) + expr_list('params') + Optional(Suppress(')'))

let_statement = (
    Optional(CaselessKeyword('Let') | CaselessKeyword('Set')).suppress()
    + Optional(Suppress(CaselessKeyword('Const')))
    + (
        (
            (
                Optional(Suppress('(')) + TODO_identifier_or_object_attrib('name') + Optional(Suppress(')'))
                + (Optional(Suppress('(') + Optional(expression('index')) + Optional(',' + expression('index1')) + Suppress(')')) ^ \
                   Optional(Suppress('(') + expression('index') + Suppress(')') + Suppress('(') + expression('index1') + Suppress(')'))) \
            )
            ^ member_access_expression('name')
            ^ string_modification('name')
        )
        |
        (
            Literal(".")
            + (
                TODO_identifier_or_object_attrib_loose('name')
                + Optional(
                    Suppress('(')
                    + Optional(expression('index'))
                    + Optional(',' + expression('index1'))
                    + Suppress(')')
                )
            )
            ^ member_access_expression('name')
            ^ string_modification('name')
        )
    )
    + (Literal('=') | Literal('+=') | Literal('-='))('op')
    + (expression('expression') ^ boolean_expression('expression'))
)
let_statement.setParseAction(Let_Statement)

lset_statement = (
    CaselessKeyword('LSet').suppress()
    + Optional(Suppress(CaselessKeyword('Const')))
    + Optional(".")
    + (
        (
            TODO_identifier_or_object_attrib('name')
            + Optional(
                Suppress('(')
                + Optional(expression('index'))
                + Optional(',' + expression('index1'))
                + Suppress(')')
            )
        )
        ^ member_access_expression('name')
        ^ string_modification('name')
    )
    + (Literal('=') | Literal('+=') | Literal('-='))('op')
    + (expression('expression') ^ boolean_expression('expression'))
)
lset_statement.setParseAction(LSet_Statement)

# --- PROPERTY ASSIGNMENT STATEMENT --------------------------------------------------------------

class Prop_Assign_Statement(VBA_Object):
    """A Property assignment statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(Prop_Assign_Statement, self).__init__(original_str, location, tokens)
        self.prop = tokens.prop
        self.param = tokens.param
        self.value = tokens.value
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as Prop_Assign_Statement' % self)

    def __repr__(self):
        return safe_str_convert(self.prop) + " " + safe_str_convert(self.param) + ":=" + safe_str_convert(self.value)

    def to_python(self, context, params=None, indent=0):

        # pylint.
        params = params
        context = context
        
        return " " * indent + "pass"
    
    def eval(self, context, params=None):

        # pylint.
        params = params
        
        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return


prop_assign_statement = (
    Optional(Suppress("."))
    + (member_access_expression("prop") ^ lex_identifier("prop"))
    + lex_identifier('param')
    + Suppress(':=')
    + expression('value')
    + ZeroOrMore(',' + lex_identifier('param') + Suppress(':=') + expression('value'))
)
prop_assign_statement.setParseAction(Prop_Assign_Statement)

# --- FOR statement -----------------------------------------------------------

class For_Statement(VBA_Object):
    """A For loop statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(For_Statement, self).__init__(original_str, location, tokens)
        self.is_loop = True
        self.name = tokens.name
        self.start_value = tokens.start_value
        self.end_value = tokens.end_value
        self.step_value = tokens.get('step_value', 1)
        if self.step_value != 1:
            self.step_value = self.step_value[0]
        self.statements = tokens.statements
        self.body = self.statements
        self.only_atomic = None
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        r = 'For %s = %r to %r step %r' % (self.name,
                                           self.start_value, self.end_value, self.step_value)
        r += "\\n" + str(self.body)
        return r

    def _get_loop_indices(self, context):
        """Get the start index, end index, and step for the loop.

        @param context (Context object) The context containing the
        current variable state.

        @return (tuple) A 3 element tuple where the 1st element is the
        start index value, the 2nd element is the end index value, and
        the 3rd element is the loop step. (None, None, None) is
        returned on error.

        """
        
        # Get the start index. If this is a string, convert to an int.
        start = eval_arg(self.start_value, context=context)
        if (isinstance(start, basestring)):
            start = vba_conversion.int_convert(start)

        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('FOR loop - start: %r = %r' % (self.start_value, start))

        # Get the end index. If this is a string, convert to an int.
        end = eval_arg(self.end_value, context=context)
        if (isinstance(end, basestring)):
            end = vba_conversion.int_convert(end)
        if (end is None):
            log.warning("Not emulating For loop. Loop end '" + safe_str_convert(self.end_value) + "' evaluated to None.")
            return (None, None, None)
            
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('FOR loop - end: %r = %r' % (self.end_value, end))

        # Get the loop step value.
        if self.step_value != 1:
            step = eval_arg(self.step_value, context=context)
            if (isinstance(step, basestring)):
                step = vba_conversion.int_convert(step)
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('FOR loop - step: %r = %r' % (self.step_value, step))
        else:
            step = 1

        # Handle backwards loops.
        if ((start > end) and (step > 0)):
            step = step * -1

        # Done.
        return (start, end, step)
        
    def _get_loop_indices_python(self, context):
        """Get the start index, end index, and step of the loop as Python
        code. 

        @param context (Context object) The context containing the
        current variable state.

        @return (tuple) A 3 element tuple where the 1st element is the
        start index value in Python, the 2nd element is the end index
        value in Python, and the 3rd element is the loop step in
        Python.

        """

        # Get the start index.
        start = to_python(self.start_value, context=context)
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('FOR loop - start: %r = %r' % (self.start_value, start))

        # Get the end index. If this is a string, convert to an int.
        end = to_python(self.end_value, context=context)
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('FOR loop - end: %r = %r' % (self.end_value, end))

        # Get the loop step value.
        if self.step_value != 1:
            step = to_python(self.step_value, context=context)
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('FOR loop - step: %r = %r' % (self.step_value, step))
        else:
            step = "1"

        # Done.
        return (start, end, step)
    
    def to_python(self, context, params=None, indent=0):
        """Convert this loop to Python code.

        @warning This modifies the given context!!

        @param context (Context object) Context for the Python code
        generation (local and global variables). Current program state
        will be read from the context.

        @param params (list) Any parameters provided to the object.
        
        @param indent (int) The number of spaces of indent to use at
        the beginning of the generated Python code.

        @return (str) The current object with it's emulation
        implemented as Python code.
        """

        # Get the loop variable.
        loop_var = safe_str_convert(self.name)

        # Make a copy of the context so we can mark variables as loop index variables.
        #tmp_context = Context(context=context, _locals=context.locals, copy_globals=True)
        tmp_context = context
        tmp_context.set(loop_var, "__LOOP_VAR__", force_local=True)
        tmp_context.set(loop_var, "__LOOP_VAR__", force_global=True)        
        
        # Boilerplate used by the Python.
        indent_str = " " * indent
        
        # Get the start index, end index, and step of the loop.
        start, end, step = self._get_loop_indices_python(context)

        # If we have an empty loop body we can punt and skip the loop.
        if (len(self.statements) == 0):
            r = indent_str + loop_var + " = " + safe_str_convert(end) + "\n"
            return r
        
        # Set up doing this for loop in Python.
        if (step < 0):
            step = abs(step)
        loop_start = indent_str + "exit_all_loops = False\n"
        loop_start += indent_str + loop_var + " = " + safe_str_convert(start) + "\n"
        loop_start += indent_str + "while (((" + loop_var + " <= coerce_to_int(" + safe_str_convert(end) + ")) and (" + safe_str_convert(step) + " > 0)) or " + \
                      "((" + loop_var + " >= coerce_to_int(" + safe_str_convert(end) + ")) and (" + safe_str_convert(step) + " < 0))):\n"
        loop_start += indent_str + " " * 4 + "if exit_all_loops:\n"
        loop_start += indent_str + " " * 8 + "break\n"
        loop_start = indent_str + "# Start emulated loop.\n" + loop_start

        # Set up initialization of variables used in the loop.
        loop_init, prog_var = _loop_vars_to_python(self, tmp_context, indent)
            
        # Save the updated variable values.
        save_vals = _updated_vars_to_python(self, context, indent)
        
        # Set up the loop body.
        loop_body = ""
        end_var = safe_str_convert(end)
        loop_body += indent_str + " " * 4 + \
                     "if (int(float(" + loop_var + ")/(coerce_to_int(" + end_var + ")" + \
                     " if coerce_to_int(" + end_var + ") != 0 else 1)*100) == " + prog_var + "):\n"
        body_escaped = safe_str_convert(self).replace('"', '\\"').replace("\\n", " :: ")
        loop_body += indent_str + " " * 8 + \
                     "safe_print(str(int(float(" + loop_var + ")/(coerce_to_int(" + end_var + ") if coerce_to_int(" + end_var + ") != 0 else 1)*100)) + " + \
                     "\"% done with loop " + body_escaped + "\")\n"
        loop_body += indent_str + " " * 8 + prog_var + " += 1\n"
        enter_loop()
        body_str = to_python(self.statements, tmp_context, params=params, indent=indent+4, statements=True)
        exit_loop()
        if (body_str.strip() == '""'):
            body_str = "\n"
        loop_body += body_str
        # --while
        loop_body += indent_str + " " * 4 + loop_var + " += " + safe_str_convert(step) + "\n"
        
        # Full python code for the loop.
        python_code = loop_init + "\n" + \
                      loop_start + "\n" + \
                      loop_body + "\n" + \
                      save_vals + "\n"

        # Done.
        return python_code

    def _handle_medium_loop(self, context, params, end, step):
        """Do short circuited emulation of loops used purely for obfuscation
        that just do the same # repeated assignment.

        @param context (Context object) The current program state.

        @param params (??) Parameters passed to the eval() method of
        this loop object.
        
        @param end (int) The upper bound of the loop indices.

        @param step (int) The step with with to increment the loop
        counter.

        @return (boolean) True if this method has handled emulation of
        the loop, False if not.

        """
        
        # Handle loops used purely for obfuscation that just do the same
        # repeated assignment.
        #
        # For j = 0 To 190
        # .TextBox1 = s1
        # .TextBox1 = s2
        # Next j

        # Do we just do assignments to simple name expressions that are not
        # the loop counter in the body?
        all_static_assigns = True
        for s in self.statements:

            # Is asignment?
            if (not isinstance(s, Let_Statement)):
                all_static_assigns = False
                break

            # Is a variable on the rhs? Or a constant?
            # TODO: Add other constant types.
            is_constant = (safe_str_convert(s.expression).isdigit())
            if ((not isinstance(s.expression, SimpleNameExpression)) and (not is_constant)):
                all_static_assigns = False
                break

            # Is the variable the loop index variable?
            if (safe_str_convert(s.expression).strip().lower() == safe_str_convert(self.name).strip().lower()):
                all_static_assigns = False
                break

        # Does the loop body do the same thing repeatedly?
        if (not all_static_assigns):
            return False
        
        # The loop body has all static assignments. Emulate the loop body once.
        log.info("Short circuited loop. " + safe_str_convert(self))
        for s in self.statements:

            # Emulate the statement.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('FOR loop eval statement: %r' % s)
            if (not isinstance(s, VBA_Object)):
                continue
            s.eval(context=context)
                
            # Was there an error that will make us jump to an error handler?
            if (context.must_handle_error()):
                break
            context.clear_error()

        # Run the error handler if we have one and we broke out of the statement
        # loop with an error.
        context.handle_error(params)

        # Set the loop index.
        try:
            context.set(self.name, end + step)
        except TypeError:
            return False
                     
        return True
                
    def _handle_simple_loop(self, context, start, end, step):
        """Do short circuited emulation of loops used purely for obfuscation
        that just increment/decrement the loop counter.

        @param context (Context object) The current program state.

        @param params (??) Parameters passed to the eval() method of
        this loop object.
        
        @param end (int) The upper bound of the loop indices.

        @param step (int) The step with with to increment the loop
        counter.

        @return (tuple) A 2 element tuple where the 1st element is the
        loop index variable (str) and the 2nd element is the final
        value of the loop index variable (int).

        """
        
        # Handle simple loops used purely for obfuscation.
        #
        # For vPHpqvZhLlFhzUmTfwXoRrfZRjfRu = 1 To 833127186
        # vPHpqvZhLlFhzUmTfwXoRrfZRjfRu = vPHpqvZhLlFhzUmTfwXoRrfZRjfRu + 1
        # Next
        #
        # For XfDQcHXF4W = 1 To I6nB6p5Bio
        #   VXjDxrfvbG0vUiQ = VXjDxrfvbG0vUiQ + 1
        # Next XfDQcHXF4W
        
        # Do we just have 1 line in the loop body?
        if (len(self.statements) != 1):
            return (None, None)

        # Are we just declaring a variable in the loop body?
        body_raw = safe_str_convert(self.statements[0]).replace("Let ", "")
        body = body_raw.replace("(", "").replace(")", "").strip()
        if (body.startswith("Dim ")):

            # Just run the loop body once.
            self.statements[0].eval(context)

            # Set the final value of the loop index variable.
            context.set(self.name, end + step)

            # Indicate that the loop was short circuited.
            log.info("Short circuited Dim only loop " + safe_str_convert(self))
            return ("N/A", "N/A")

        # Are we just assigning a variable to the loop counter?
        if (body.endswith(" = " + safe_str_convert(self.name))):

            # Just assign the variable to the final loop counter value, unless
            # we have an array update on the LHS.
            fields = body_raw.split(" ")
            var = fields[0].strip()
            if (("(" not in var) and (")" not in var)):
                context.set(self.name, end + step)
                return (var, end + step)

        # Are we just doing 1 Debug.Print in the loop?
        body1 = body.replace("Call_Statement:", "").strip()
        if (body1.startswith("Debug.Print")):

            # Just run the loop body once.
            self.statements[0].eval(context)

            # Set the final value of the loop index variable.
            context.set(self.name, end + step)

            # Indicate that the loop was short circuited.
            log.info("Short circuited Debug.Print only loop " + safe_str_convert(self))
            return ("N/A", "N/A")

        # Are we just doing 1 "On Error ..." statement in the loop?
        if (re.search(r"'On', 'Error', 'Goto',", body) is not None):

            # Just run the loop body once.
            self.statements[0].eval(context)

            # Set the final value of the loop index variable.
            context.set(self.name, end + step)

            # Indicate that the loop was short circuited.
            log.info("Short circuited 'On Error' only loop " + safe_str_convert(self))
            return ("N/A", "N/A")
            
        # Are we just modifying a single variable each loop iteration by a single literal value?
        #   VXjDxrfvbG0vUiQ = VXjDxrfvbG0vUiQ + 1
        #   v787311 = v787311 + v350504 - v979958
        fields = body.split(" ")
        if (len(fields) < 5):
            return (None, None)
        op = fields[3].strip()
        var = fields[0].strip()
        if (var != fields[2].strip()):
            return (None, None)
        if (op not in ['+', '-', '*']):
            return (None, None)

        # Skip loops where the computation depends on the loop
        # index.
        for f in fields[2:]:
            if (f.strip() == safe_str_convert(self.name).strip()):
                return (None, None)
                
        # Figure out the value to use to change the variable in the loop.
        expr_str = ""
        for e in fields[4:]:
            expr_str += " " + e
        num = None
        try:
            expr = expression.parseString(expr_str, parseAll=True)[0]
            num = safe_str_convert(expr)
            if (hasattr(expr, "eval")):
                num = safe_str_convert(expr.eval(context))
        except ParseException:
            return (None, None)
        if (not num.isdigit()):
            return (None, None)
        
        # Get the initial value of variable being modified in the loop.
        init_val = None
        try:

            # Get the initial value if there is one.
            init_val = context.get(var)
            if (init_val == "NULL"):
                init_val = 0

            # Can only handle integers.
            if (not safe_str_convert(init_val).isdigit()):
                return (None, None)
            init_val = int(safe_str_convert(init_val))

        except KeyError:

            # The variable is undeclared/uninitialized. Default to 0.
            init_val = 0

        # Figure out the # of loop iterations that will run.
        num_iters = (end - start + 1)/step
            
        # We are just modifying a variable each time. Figure out the final
        # value of the variable modified in the loop.
        try:
            num = int(num)
        except ValueError:
            return (None, None)
        r = None
        if (op == "+"):
            r = (var, init_val + num_iters*num)
        elif (op == "-"):
            r = (var, init_val - num_iters*num)
        elif (op == "*"):
            r = (var, init_val * pow(num, num_iters))
        else:
            return (None, None)

        # Set the final value of the loop index variable.
        context.set(self.name, end + step)

        # Return the loop result.
        return r

    def _no_state_change(self, prev_context, context):
        """Check to see if there is any meaningful difference between 2 given
        program states.

        @param prev_context (Context object) The previous program state.

        @param context (Context object) The current program state.

        @return (boolean) True if the loop body only contains atomic
        statements (no ifs, selects, etc.) and the previous program
        state (minus the loop variable) is equal to the current
        program state.

        """

        # Sanity check.
        if ((prev_context is None) or (context is None)):
            return False
        
        # First check to see if the loop body only contains atomic statements.
        if (self.only_atomic is None):
            self.only_atomic = True
            for s in self.statements:
                if (not isinstance(s, VBA_Object)):
                    continue
                if ((not is_simple_statement(s)) and (not s.is_useless)):
                    self.only_atomic = False
        if (not self.only_atomic):
            return False

        # Remove the loop counter variable from the previous loop iteration
        # program state and the current program state.
        prev_context = Context(context=prev_context, _locals=prev_context.locals, copy_globals=True)\
                                        .delete(self.name)\
                                        .delete(self.name.lower())\
                                        .delete("now")\
                                        .delete("application.username")\
                                        .delete("recentfiles.count")\
                                        .delete("activedocument.revisions.count")\
                                        .delete("thisdocument.revisions.count")\
                                        .delete("revisions.count")
        context = Context(context=context, _locals=context.locals, copy_globals=True)\
                                   .delete(self.name)\
                                   .delete(self.name.lower())\
                                   .delete("now")\
                                   .delete("application.username")\
                                   .delete("recentfiles.count")\
                                   .delete("activedocument.revisions.count")\
                                   .delete("thisdocument.revisions.count")\
                                   .delete("revisions.count")

        # There is no state change if the previous state is equal to the
        # current state.
        r = (prev_context == context)
        return r
    
    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return
        
        # evaluate values:
        self.exited_with_goto = False
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('FOR loop: evaluating start, end, step')

        # Do not bother running loops with empty bodies.
        if (len(self.statements) == 0):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("FOR loop: empty body. Skipping.")
            return

        # Assign all const variables first.
        do_const_assignments(self.statements, context)        
        
        # Get the start index, end index, and step of the loop.
        start, end, step = self._get_loop_indices(context)
        if (start is None):
            log.warn("Cannot resolve loop index information, not doing JIT loop emulation.")
            return
            
        # Set the loop index variable to the start value.
        context.set(self.name, start)
            
        # See if we have a simple style loop put in purely for obfuscation.
        var, val = self._handle_simple_loop(context, start, end, step)
        if ((var is not None) and (val is not None)):
            log.info("Short circuited loop. Set " + safe_str_convert(var) + " = " + safe_str_convert(val))
            context.set(var, val)
            self.is_useless = True
            return

        # See if we have a more complicated style loop put in purely for obfuscation.
        do_body_once = self._handle_medium_loop(context, params, end, step)
        if (do_body_once):
            self.is_useless = True
            return

        # See if we can convert the loop to Python and directly emulate it.
        if (_eval_python(self, context, params=params, add_boilerplate=True)):
            return
        
        # Set end to valid values.
        if ((VBA_Object.loop_upper_bound > 0) and (end > VBA_Object.loop_upper_bound)):

            # Fix the loop upper bound if it is ridiculously huge. We are assuming that a
            # really huge loop is just there to foil emulation.
            if (end > 100000000):
                end = 10
            else:

                # Might be legitimate. Set to a smaller but still large value.
                end = VBA_Object.loop_upper_bound
            log.warn("FOR loop: upper loop iteration bound exceeded, setting to %r" % end)
        
        # Track that the current loop is running.
        context.loop_stack.append(None)
        context.loop_object_stack.append(self)
        my_loop_stack_pos = len(context.loop_stack) - 1

        # Track the context from the previous loop iteration to see if we have
        # a loop that is just there for obfuscation.
        num_no_change = 0
        prev_context = None

        # Sometimes I/O from progress printing can slow down emulation in
        # large loops. Track the # of iterations run to throttle logging if
        # needed.
        num_iters_run = 0
        throttle_io_limit = 100

        # Sanity check whether we can find the loop variable.
        if (not context.contains(self.name)):
            log.warn("Cannot find loop variable " + safe_str_convert(self.name) + ". Skipping loop.")
            return

        # Loop until the loop is broken out of or we hit the last index.
        context.clear_general_errors()
        while (((step > 0) and (context.get(self.name) <= end)) or
               ((step < 0) and (context.get(self.name) >= end))):

            # We have already handled any gotos from the previous loop iteration.
            context.goto_executed = False
            
            # For performance don't check for loops that don't change the state unless it looks like
            # they may actually be a non-state changing loop.
            if ((num_iters_run < 10) or (num_no_change > 0)):

                # Is the loop body a simple series of atomic statements and has
                # nothing changed in the program state since the last iteration?
                if (self._no_state_change(prev_context, context)):
                    num_no_change += 1
                    if (num_no_change >= context.max_static_iters * 5):
                        log.warn("Possible useless For loop detected. Exiting loop.")
                        self.is_useless = True
                        break
                else:
                    num_no_change = 0                
                prev_context = Context(context=context, _locals=context.locals, copy_globals=True)

            # Throttle logging if this is a long running loop.
            num_iters_run += 1
            if ((num_iters_run > throttle_io_limit) and ((num_iters_run % 500) == 0)):
                log.warning("Long running loop. I/O has been throttled.")
            if ((num_iters_run > throttle_io_limit) and (not context.throttle_logging)):
                log.warning("Throttling output logging...")
                context.throttle_logging = True
            if (((num_iters_run < throttle_io_limit) or ((num_iters_run % 5000) == 0)) and
                context.throttle_logging):
                log.warning("Output is throttled...")
                context.throttle_logging = False

            # Break long running loops that appear to be generating a lot of errors.
            if (context.get_general_errors() > (VBA_Object.loop_upper_bound/10)):
                log.error("Loop is generating too many errors. Breaking loop.")
                break
                
            # Execute the loop body.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('FOR loop: %s = %r' % (self.name, context.get(self.name)))
            done = False
            for s in self.statements:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug('FOR loop eval statement: %r' % s)
                if (not isinstance(s, VBA_Object)):
                    continue
                s.eval(context=context)
                
                # Has 'Exit For' been called?
                if ((my_loop_stack_pos >= len(context.loop_stack)) or context.loop_stack[my_loop_stack_pos]):
                    
                    # Yes we have. Stop this loop.
                    self.exited_with_goto = (context.loop_stack[my_loop_stack_pos] == "GOTO")
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("FOR loop: exited loop with 'Exit For'")
                    done = True
                    break

                # Was there an error that will make us jump to an error handler?
                if (context.must_handle_error()):

                    # Does the error handler just call Next to go to the next loop iteration?
                    if (not context.do_next_iter_on_error()):
                        done = True
                    break
                context.clear_error()

                # Did we just run a GOTO? If so we should not run the
                # statements after the GOTO.
                #if (isinstance(s, Goto_Statement)):
                if (context.goto_executed or s.exited_with_goto):
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("GOTO executed. Go to next loop iteration.")
                    break
                
            # Finished with the loop due to 'Exit For' or error?
            if (done):
                break

            # No errors, so clear them.
            context.clear_error()
            
            # Increment the loop counter by the step.
            val = context.get(self.name)
            try:
                val = int(val)
                step = int(step)
            except Exception as e:
                context.report_general_error("Cannot update loop counter. Breaking loop. " + safe_str_convert(e))
                break
            new_index = val + step
            context.set(self.name, new_index)

            # Are we manually setting the loop index variable to a constant value
            # in the loop body? This can cause infinite loops.
            if (((new_index < start) and (step > 0)) or
                ((new_index > start) and (step < 0))):

                # Infinite loop. Break out.
                log.warn("Possible infinite For loop detected. Exiting loop.")
                break
        
        # Remove tracking of this loop.
        if (len(context.loop_stack) > 0):
            context.loop_stack.pop()
        if (len(context.loop_object_stack) > 0):
            context.loop_object_stack.pop()
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('FOR loop: end.')
            
        # Run the error handler if we have one and we broke out of the statement
        # loop with an error.
        context.handle_error(params)

        # We are parsing Next's as being an integral part of the for loop
        # (it's really not). This means we are only handling GOTOs within the
        # loop body, so once we get out of the loop we need to run the statement
        # after the loop.
        context.goto_executed = False
        
# 5.6.16.6 Bound Variable Expressions
#
# A <bound-variable-expression> is invalid if it is classified as something other than a variable
# expression. The expression is invalid even if it is classified as an unbound member expression that
# could be resolved to a variable expression.
#
# MS-GRAMMAR: bound-variable-expression = l-expression


bound_variable_expression = TODO_identifier_or_object_attrib  # l_expression

# 5.4.2.3 For Statement
#
# A <for-statement> executes a sequence of statements a specified number of times.
#
# MS-GRAMMAR: for-statement = simple-for-statement / explicit-for-statement
# MS-GRAMMAR: simple-for-statement = for-clause EOS statement-block "Next"
# MS-GRAMMAR: explicit-for-statement = for-clause EOS statement-block ("Next" / (nested-for-statement ",")) bound-variable-expression
# MS-GRAMMAR: nested-for-statement = explicit-for-statement / explicit-for-each-statement
# MS-GRAMMAR: for-clause = "For" bound-variable-expression "=" start-value "To" end-value [stepclause]
# MS-GRAMMAR: start-value = expression
# MS-GRAMMAR: end-value = expression
# MS-GRAMMAR: step-clause = "Step" step-increment
# MS-GRAMMAR: step-increment = expression

step_clause = CaselessKeyword('Step').suppress() + expression

# TODO: bound_variable_expression instead of lex_identifier
for_clause = CaselessKeyword("For").suppress() \
             + lex_identifier('name') \
             + Suppress(Optional(CaselessKeyword("As") + type_expression)) \
             + Suppress("=") + expression('start_value') \
             + CaselessKeyword("To").suppress() + expression('end_value') \
             + Optional(step_clause('step_value'))

simple_for_statement = for_clause + Suppress(EOS) + statement_block('statements') \
                       + (CaselessKeyword("Next").suppress() | CaselessKeyword("End").suppress()) \
                       + Optional(lex_identifier) \
                       + FollowedBy(EOS)  # NOTE: the statement should NOT include EOS!

simple_for_statement.setParseAction(For_Statement)

# Some maldocs have a floating Next statement that is not associated with a loop.
# Handle that here.
bad_next_statement = CaselessKeyword("Next") + Suppress(EOS)

# For the line parser:
for_start = for_clause + Suppress(EOS)
for_start.setParseAction(For_Statement)

for_end = CaselessKeyword("Next").suppress() + Optional(lex_identifier) + Suppress(EOS)

# --- FOR EACH statement -----------------------------------------------------------

class For_Each_Statement(VBA_Object):
    """Emulate a VB For-Each loop.

    """
    
    def __init__(self, original_str, location, tokens):
        super(For_Each_Statement, self).__init__(original_str, location, tokens)
        self.is_loop = True
        self.statements = tokens.statements
        self.body = self.statements
        self.item = tokens.clause.item
        self.container = tokens.clause.container
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        return 'For Each %r In %r ...' % (self.item, self.container)

    def to_python(self, context, params=None, indent=0):
        """Convert this loop to Python code.

        @warning This modifies the given context!!

        @param context (Context object) Context for the Python code
        generation (local and global variables). Current program state
        will be read from the context.

        @param params (list) Any parameters provided to the object.
        
        @param indent (int) The number of spaces of indent to use at
        the beginning of the generated Python code.

        @return (str) The current object with it's emulation
        implemented as Python code.
        """

        # Get the loop variable.
        loop_var = safe_str_convert(self.item)

        # Make a copy of the context so we can mark variables as loop index variables.
        #tmp_context = Context(context=context, _locals=context.locals, copy_globals=True)
        tmp_context = context
        tmp_context.set(loop_var, "__LOOP_VAR__")
        tmp_context.set(loop_var, "__LOOP_VAR__", force_global=True)
        
        # Boilerplate used by the Python.
        indent_str = " " * indent
        
        # Get the values to iterate over.
        loop_vals = to_python(self.container, tmp_context)

        # Set up doing this for loop in Python.
        loop_start = indent_str + "exit_all_loops = False\n"
        loop_start += indent_str + "for " + loop_var + " in " + loop_vals + ":\n"
        loop_start += indent_str + " " * 4 + "if exit_all_loops:\n"
        loop_start += indent_str + " " * 8 + "break\n"
        loop_start = indent_str + "# Start emulated loop.\n" + loop_start

        # Set up initialization of variables used in the loop.
        loop_init, prog_var = _loop_vars_to_python(self, tmp_context, indent)
        hash_object = hashlib.md5(safe_str_convert(self).encode())
        len_var = "len_" + hash_object.hexdigest()
        pos_var = "pos_" + hash_object.hexdigest()
        loop_init += indent_str + len_var + " = len(" + loop_vals + ")\n"
        loop_init += indent_str + pos_var + " = 0\n"
            
        # Save the updated variable values.
        save_vals = _updated_vars_to_python(self, context, indent)
        
        # Set up the loop body.
        loop_body = ""
        loop_body += indent_str + " " * 4 + pos_var + " += 1\n"
        loop_body += indent_str + " " * 4 + \
                     "if (int(float(" + pos_var + ")/(" + len_var + " if " + len_var + " != 0 else 1)*100) == " + prog_var + "):\n"
        body_escaped = safe_str_convert(self).replace('"', '\\"').replace("\\n", " :: ")
        loop_body += indent_str + " " * 8 + \
                     "safe_print(str(int(float(" + pos_var + ")/(" + len_var + \
                     " if " + len_var + " != 0 else 1)*100)) + \"% done with loop " + body_escaped + "\")\n"
        loop_body += indent_str + " " * 8 + prog_var + " += 1\n"
        enter_loop()
        loop_body += to_python(self.statements, tmp_context, params=params, indent=indent+4, statements=True)
        exit_loop()
        
        # Full python code for the loop.
        python_code = loop_init + "\n" + \
                      loop_start + "\n" + \
                      loop_body + "\n" + \
                      save_vals + "\n"

        # Done.
        return python_code

    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return
        
        # Track that the current loop is running.
        self.exited_with_goto = False
        context.loop_stack.append(None)
        context.loop_object_stack.append(self)
        my_loop_stack_pos = len(context.loop_stack) - 1
        
        # Get the container of values we are iterating through.

        # Might be an expression.
        container = eval_arg(self.container, context=context)
        try:
            # Could be a variable.
            container = context.get(self.container)
        except KeyError:
            pass
        except AssertionError:
            pass

        # Assign all const variables first.
        do_const_assignments(self.statements, context)

        # See if we can convert the loop to Python and directly emulate it.
        if (_eval_python(self, context, params=params, add_boilerplate=True)):
            return
        
        # Try iterating over the values in the container.
        if (not isinstance(container, list)):
            container = [container]
        try:
            for item_val in container:

                # Set the loop item variable in the context.
                context.set(self.item, item_val)
                
                # Execute the loop body.
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug('FOR EACH loop: %r = %r' % (self.item, context.get(self.item)))
                done = False
                context.goto_executed = False
                for s in self.statements:
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug('FOR EACH loop eval statement: %r' % s)
                    if (not isinstance(s, VBA_Object)):
                        continue
                    s.eval(context=context)

                    # Has 'Exit For' been called?
                    if ((my_loop_stack_pos >= len(context.loop_stack)) or context.loop_stack[my_loop_stack_pos]):

                        # Yes we have. Stop this loop.
                        self.exited_with_goto = (context.loop_stack[my_loop_stack_pos] == "GOTO")
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug("FOR EACH loop: exited loop with 'Exit For'")
                        done = True
                        break

                    # Was there an error that will make us jump to an error handler?
                    if (context.must_handle_error()):
                        done = True
                        break
                    context.clear_error()

                    # Did we just run a GOTO? If so we should not run the
                    # statements after the GOTO.
                    #if (isinstance(s, Goto_Statement)):
                    if (context.goto_executed or s.exited_with_goto):
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug("GOTO executed. Go to next loop iteration.")
                        break
                    
                # Finished with the loop due to 'Exit For' or error?
                if (done):
                    break

        except Exception:

            # The data type for the container may not be iterable. Do nothing.
            pass
        
        # Remove tracking of this loop.
        if (len(context.loop_stack) > 0):
            context.loop_stack.pop()
        if (len(context.loop_object_stack) > 0):
            context.loop_object_stack.pop()
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('FOR EACH loop: end.')

        # Run the error handler if we have one and we broke out of the statement
        # loop with an error.
        context.handle_error(params)
        

for_each_clause = CaselessKeyword("For").suppress() \
                  + CaselessKeyword("Each").suppress() \
                  + lex_identifier("item") \
                  + CaselessKeyword("In").suppress() \
                  + expression("container") \

real_simple_for_each_statement = for_each_clause('clause') + Suppress(EOS) + statement_block('statements') \
                                 + CaselessKeyword("Next").suppress() \
                                 + Optional(lex_identifier) \
                                 + FollowedBy(EOS)  # NOTE: the statement should NOT include EOS!
real_simple_for_each_statement.setParseAction(For_Each_Statement)

bogus_simple_for_each_statement = for_each_clause('clause') + Suppress(EOS) + statement_block('statements') + ~CaselessKeyword("Next") + \
                                  CaselessKeyword("End") + (CaselessKeyword("Sub") | CaselessKeyword("Function"))
bogus_simple_for_each_statement.setParseAction(For_Each_Statement)


# --- WHILE statement -----------------------------------------------------------

def _get_guard_variables(loop_obj, context):
    """Pull out the variables that appear in the guard expression of a
    while loop and their values in the context. Return as a dict.

    @param loop_obj (While_Statement or Do_Statement object) The loop
    for which to get the guard expression variable information.

    @param context (Context object) The current program state.

    @return (dict) A map from guard variable names to current values.

    """

    # Sanity check.
    if (not hasattr(loop_obj.guard, "accept")):
        return {}
    
    # Get the names of the variables in the loop guard.
    var_visitor = var_in_expr_visitor()
    loop_obj.guard.accept(var_visitor)
    guard_var_names = var_visitor.variables

    # Get their current values.
    r = {}
    for var in guard_var_names:
        try:
            r[var] = context.get(var)
        except Exception:
            pass

    # Return the values of the vars in the loop guard.
    return r

class While_Statement(VBA_Object):
    """Emulate a VB While loop.

    """
    
    def __init__(self, original_str, location, tokens):
        super(While_Statement, self).__init__(original_str, location, tokens)
        self.is_loop = True
        self.original_str = original_str[location:]
        self.loop_type = tokens.clause.type
        self.guard = tokens.clause.guard
        self.body = tokens[2]
        self._local_calls = None
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        r = "Do " + safe_str_convert(self.loop_type) + " " + safe_str_convert(self.guard) + "\\n"
        r += safe_str_convert(self.body) + "\\nLoop"
        return r

    def to_python(self, context, params=None, indent=0):
        """Convert this loop to Python code.

        @warning This modifies the given context!!

        @param context (Context object) Context for the Python code
        generation (local and global variables). Current program state
        will be read from the context.

        @param params (list) Any parameters provided to the object.
        
        @param indent (int) The number of spaces of indent to use at
        the beginning of the generated Python code.

        @return (str) The current object with it's emulation
        implemented as Python code.
        """

        # Boilerplate used by the Python.
        indent_str = " " * indent

        # Logic is flipped for do until loops.
        until_pre = ""
        until_post = ""
        if (self.loop_type.lower() == "until"):
            until_pre = "not ("
            until_post = ")"
        
        # Set up doing this for loop in Python.
        loop_start = indent_str + "exit_all_loops = False\n"
        loop_start += indent_str + "max_errors = " + safe_str_convert(VBA_Object.loop_upper_bound/10) + "\n"
        loop_start += indent_str + "while " + until_pre + to_python(self.guard, context) + until_post + ":\n"
        loop_start += indent_str + " " * 4 + "if exit_all_loops:\n"
        loop_start += indent_str + " " * 8 + "break\n"
        loop_start = indent_str + "# Start emulated loop.\n" + loop_start

        # Set up initialization of variables used in the loop.
        loop_init, prog_var = _loop_vars_to_python(self, context, indent)
            
        # Save the updated variable values.
        save_vals = _updated_vars_to_python(self, context, indent)
        
        # Set up the loop body.
        loop_str = safe_str_convert(self).replace('"', '\\"').replace("\\n", " :: ")
        if (len(loop_str) > 100):
            loop_str = loop_str[:100] + " ..."
        loop_body = ""
        # Report progress.
        loop_body += indent_str + " " * 4 + "if (" + prog_var + " % 100) == 0:\n"
        loop_body += indent_str + " " * 8
        loop_body += "safe_print(\"Done \" + safe_str_convert(" + prog_var + ") + \" iterations of While loop '" + loop_str + "'\")\n"
        loop_body += indent_str + " " * 4 + prog_var + " += 1\n"
        # No infinite loops.
        loop_body += indent_str + " " * 4 + "if (" + prog_var + " > " + safe_str_convert(VBA_Object.loop_upper_bound) + ") or " + \
                     "(vm_context.get_general_errors() > max_errors):\n"
        loop_body += indent_str + " " * 8 + "raise ValueError('Infinite Loop')\n"
        enter_loop()
        loop_body += to_python(self.body, context, params=params, indent=indent+4, statements=True)
        exit_loop()
        
        # Full python code for the loop.
        python_code = loop_init + "\n" + \
                      loop_start + "\n" + \
                      loop_body + "\n" + \
                      save_vals + "\n"

        # Done.
        return python_code
        
    def _eval_guard(self, curr_counter, final_val, comp_op):
        """Evaluate the guard expression of a loop. This works for guard
        expressions that are simple comparison expressions.

        @param curr_counter (int) The current value of the loop index.

        @param final_val (int) The upper/lower bound for the loop index.

        @param comp_op (str) The operator to use to compare the
        current value of the loop index with the upper/lower
        bound. Valid values are "<=", "<", ">=", or "==".

        @return (boolean) True if the loop guard expression is true,
        False if not.

        """
        
        if (comp_op == "<="):
            return (curr_counter <= final_val)
        if (comp_op == "<"):
            return (curr_counter < final_val)
        if (comp_op == ">="):
            return (curr_counter >= final_val)
        if (comp_op == ">"):
            return (curr_counter > final_val)
        if ((comp_op == "==") or (comp_op == "=")):
            return (curr_counter == final_val)
        log.error("Loop guard operator '" + safe_str_convert(comp_op) + " cannot be emulated.")
        return False
        
    def _handle_simple_loop(self, context):
        """Do short circuited emulation of loops used purely for obfuscation
        that just increment/decrement the loop counter.

        @param context (Context object) The current program state.
        
        @return (boolean) True if this method has emulated the loop,
        False if not.

        """

        # Handle simple loops used purely for obfuscation.
        #
        # While b52 <= b35
        # b52 = b52 + 1
        # Wend

        # Do we just have 1 or 2 lines in the loop body?
        if ((len(self.body) != 1) and (len(self.body) != 2)):
            return False

        # Are we just sleeping in the loop?
        if ("sleep(" in safe_str_convert(self.body[0]).lower()):
            return True

        # Are we just executing dynamic VB in the loop?
        if (("execute(" in safe_str_convert(self.body[0]).lower()) or
            ("executeglobal(" in safe_str_convert(self.body[0]).lower())):

            # Run the loop once.
            for s in self.body:
                if (not isinstance(s, VBA_Object)):
                    continue
                s.eval(context=context)

            return True
        
        # Do we have a simple loop guard?
        loop_counter = safe_str_convert(self.guard).strip()
        m = re.match(r"(\w+)\s*([<>=]{1,2})\s*(\w+)", loop_counter)
        if (m is None):
            return False

        # We have a simple loop guard. Pull out the loop variable, upper bound, and
        # comparison op.
        loop_counter = m.group(1)
        comp_op = m.group(2)
        upper_bound = m.group(3)
        
        # Are we just modifying the loop counter variable each loop iteration?
        var_inc = loop_counter + " = " + loop_counter
        body = safe_str_convert(self.body[0]).replace("Let ", "").replace("(", "").replace(")", "").strip()
        if_block = None
        if (not body.startswith(var_inc)):

            # We can handle a single if statement and a single loop variable modify statement.
            if (len(self.body) != 2):
                return False
            
            # Are we incrementing the loop counter and doing something if the loop counter
            # is equal to a specific value?
            body = None
            for s in self.body:

                # Modifying the loop variable?
                tmp = safe_str_convert(s).replace("Let ", "").replace("(", "").replace(")", "").strip()
                if (tmp.startswith(var_inc)):
                    body = tmp
                    continue

                # If statement looking for specific value of the loop variable?
                if (isinstance(s, If_Statement)):

                    # Check the loop guard to see if it is 'loop_var = ???'.
                    if_guard = s.pieces[0]["guard"]
                    if_guard_str = safe_str_convert(if_guard).strip()
                    if (if_guard_str.startswith(loop_counter + " = ")):

                        # We are only handling simple If statements (no Else or ElseIf).
                        if (("Else " in safe_str_convert(s)) or ("ElseIf " in safe_str_convert(s))):
                            return False
                        
                        # Pull out the loop counter value we are looking for and
                        # what to run when the counter equals that.
                        if_block = s.pieces[0]["body"]
                        
                        # We can only handle ints for the loop counter value to check for.
                        try:
                            start = if_guard_str.rindex("=") + 1
                            tmp = if_guard_str[start:].strip()
                            _ = int(safe_str_convert(tmp))
                        except ValueError:
                            return False

            if (if_block is None):
                body = None
                        
        # Bomb out if this is not a simple loop.
        if (body is None):
            return False
                        
        # Pull out the operator and integer value used to update the loop counter
        # in the loop body.
        if (" " not in body):
            return False
        body = body.replace(var_inc, "").strip()
        op = body[:body.index(" ")]
        if (op not in ["+", "-", "*"]):
            return False
        num = body[body.index(" ") + 1:]
        try:
            num = int(num)
        except Exception:
            return False

        # Now just compute the final loop counter value right here in Python.
        curr_counter = vba_conversion.coerce_to_int(eval_arg(loop_counter, context=context, treat_as_var_name=True))
        final_val = eval_arg(upper_bound, context=context, treat_as_var_name=True)
        try:
            final_val = int(final_val)
        except Exception:
            return False
        
        # Simple case first. Set the final loop counter value if possible.
        if ((num == 1) and (op == "+")):
            if (comp_op == "<="):
                curr_counter = final_val + 1
            if (comp_op == "<"):
                curr_counter = final_val

        # Now emulate the loop in Python.
        running = self._eval_guard(curr_counter, final_val, comp_op)
        if (self.loop_type.lower() == "until"):
            running = (not running)
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Short circuiting loop evaluation: Guard: " + safe_str_convert(self.guard))
            log.debug("Short circuiting loop evaluation: Body: " + safe_str_convert(self.body))
        while (running):
            
            # Update the loop counter.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Short circuiting loop evaluation: Guard: " + safe_str_convert(self.guard))
                log.debug("Short circuiting loop evaluation: Test: " + safe_str_convert(curr_counter) + " " + comp_op + " " + safe_str_convert(final_val))
            if (op == "+"):
                curr_counter += num
            if (op == "-"):
                curr_counter -= num
            if (op == "*"):
                curr_counter *= num

            # See if we are done.
            running = self._eval_guard(curr_counter, final_val, comp_op)
            if (self.loop_type.lower() == "until"):
                running = (not running)

        # Update the loop counter in the context.
        context.set(loop_counter, curr_counter)

        # Do the targeted if block if we have one and we have reached the proper loop
        # counter value.
        if (if_block is not None):
            for stmt in if_block:
                if (not isinstance(stmt, VBA_Object)):
                    continue
                if (hasattr(stmt, "eval")):
                    stmt.eval(context)
        
        # We short circuited the loop evaluation.
        return True

    def _has_local_calls(self, context):
        """See if the current loop body makes any local function calls.

        @param context (Context object) The current program state.

        @return (boolean) True if the loop body calls local functions,
        False if not.

        """

        # Already computed?
        if (self._local_calls is not None):
            return self._local_calls

        # Sanity check.
        if (not hasattr(self.body, "accept")):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Loop body has no accept() method.")
            return True

        # Get the names of all the called functions in the loop body.
        call_visitor = function_call_visitor()
        for s in self.body:
            if (not isinstance(s, VBA_Object)):
                continue
            s.accept(call_visitor)

        # See if any of the called functions are local.
        for func in call_visitor.called_funcs:
            if (func not in context.external_funcs):
                # Not an external call, so it is local.
                self._local_calls = True
                return True

        # Only external calls.
        self._local_calls = False
        return False
            
    def _no_state_change(self, prev_context, context):
        """Check to see if there is any meaningful difference between 2 given
        program states.

        @param prev_context (Context object) The previous program state.

        @param context (Context object) The current program state.

        @return (boolean) True if the loop body contains no calls and
        the previous program state (minus the guard variables) is
        equal to the current program state.

        """

        # Sanity check.
        if ((prev_context is None) or (context is None)):
            return False
        
        # First check to see if the loop body contains no local calls.
        if (self._has_local_calls(context)):
            return False

        # Remove the loop counter variables from the previous loop iteration
        # program state and the current program state.
        guard_vars = _get_guard_variables(self, context)
        prev_context = Context(context=prev_context,
                               _locals=prev_context.locals,
                               copy_globals=True).delete("now").delete("application.username")
        for gvar in guard_vars:
            prev_context = prev_context.delete(gvar)
        curr_context = Context(context=context, _locals=context.locals, copy_globals=True).delete("now").delete("application.username")
        for gvar in guard_vars:
            curr_context = curr_context.delete(gvar)
        
        # There is no state change if the previous state is equal to the
        # current state.
        r = (prev_context == curr_context)
        return r

    def _has_constant_loop_guard(self):
        """Check to see if the loop guard is a literal expression that always
        evaluates True or False.

        @return (boolean) Return True or False if the loop guard
        always evaluates to True or False.  Return None if it does
        not.

        """

        # If the guard contains variables it may not be infinite.
        var_visitor = var_in_expr_visitor()
        self.guard.accept(var_visitor)
        if (len(var_visitor.variables) > 0):
            return None

        # We have no variables. See if the guard evaluates to a constant expression.
        
        # Evaluate the loop guard with an empty context.
        empty_context = Context()
        eval_guard_empty = safe_str_convert(eval_arg(self.guard, empty_context)).strip()
        if (eval_guard_empty == "True"):
            return True
        if (eval_guard_empty == "False"):
            return False
        return None
        
    def eval(self, context, params=None):

        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return None
        
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('WHILE loop: start: ' + safe_str_convert(self))

        # Do not bother running loops with empty bodies.
        self.exited_with_goto = False
        if (len(self.body) == 0):

            # Evaluate the loop guard once in case interesting functions are called in
            # the guard.
            if (hasattr(self.guard, "eval")):
                self.guard.eval(context)
            
            log.info("WHILE loop: empty body. Skipping.")
            return None

        # Assign all const variables first.
        do_const_assignments(self.body, context)

        # See if we can transform the loop to a simpler form and just emulate that.
        new_loop = loop_transform.transform_loop(self)
        if (new_loop != self):

            # We have something simpler. Just emulate that.
            log.warning("Emulating transformed loop...")
            return new_loop.eval(context, params=params)
        
        # See if we can short circuit the loop.
        if (self._handle_simple_loop(context)):

            # We short circuited the loop. Done.
            return None

        # Some loops have a constant guard expression that always evaluates to True
        # (infinite loop). Just run those loops a few times.
        init_guard_val = self._has_constant_loop_guard()
        max_loop_iters = VBA_Object.loop_upper_bound
        is_infinite_loop = False
        if (init_guard_val is not None):

            # Always runs?
            if (init_guard_val):
                log.warn("Found infinite loop w. constant loop guard. Limiting iterations.")
                max_loop_iters = 2
                is_infinite_loop = True

            # Never runs?
            else:
                log.warn("Found loop that never runs w. constant loop guard. Skipping.")
                return None

        # Try converting the loop to Python and running that.
        # Don't do Python JIT on short circuited infinite loops.
        if ((not is_infinite_loop) and
            (_eval_python(self, context, add_boilerplate=True))):
            return None
        
        # Track that the current loop is running.
        context.loop_stack.append(None)
        context.loop_object_stack.append(self)
        my_loop_stack_pos = len(context.loop_stack) - 1
        
        # Some loop guards check the readystate value on an object. To simulate this
        # will will just go around the loop a small fixed # of times.
        if (".readyState" in safe_str_convert(self.guard)):
            log.info("Limiting # of iterations of a .readyState loop.")
            max_loop_iters = 5
            
        # Get the initial values of all the variables that appear in the loop guard.
        old_guard_vals = _get_guard_variables(self, context)

        # Track the context from the previous loop iteration to see if we have
        # a loop that is just there for obfuscation.
        num_no_change_body = 0
        prev_context = None
        
        # Loop until the loop is broken out of or we violate the loop guard.
        num_iters = 0
        num_no_change = 0
        context.clear_general_errors()
        while (True):
            
            # For performance don't check for loops that don't change the state unless it looks like
            # they may actually be a non-state changing loop.
            if ((num_iters < 10) or (num_no_change > 0)):

                # Is the loop body a simple series of atomic statements and has
                # nothing changed in the program state since the last iteration?
                if (self._no_state_change(prev_context, context)):
                    num_no_change_body += 1
                    if (num_no_change_body >= context.max_static_iters * 500):
                        log.warn("Possible useless While loop detected. Exiting loop.")
                        self.is_useless = True
                        break
                else:
                    num_no_change = 0
                prev_context = Context(context=context, _locals=context.locals, copy_globals=True)
            
            # Break infinite loops.
            if (num_iters > max_loop_iters):
                log.error("Maximum loop iterations exceeded. Breaking loop.")
                break
            num_iters += 1

            # Break long running loops that appear to be generating a lot of errors.
            if (context.get_general_errors() > (max_loop_iters/10000)):
                log.error("Loop is generating too many errors. Breaking loop.")
                break
                
            # Test the loop guard to see if we should exit the loop.
            guard_val = eval_arg(self.guard, context)
            if (self.loop_type.lower() == "until"):
                guard_val = (not guard_val)
            if (not guard_val):
                break
            
            # Execute the loop body.
            done = False
            context.goto_executed = False
            for s in self.body:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug('WHILE loop eval statement: %r' % s)
                if (not isinstance(s, VBA_Object)):
                    continue
                s.eval(context=context)

                # Has 'Exit For' been called?
                if ((my_loop_stack_pos >= len(context.loop_stack)) or context.loop_stack[my_loop_stack_pos]):

                    # Yes we have. Stop this loop.
                    self.exited_with_goto = (context.loop_stack[my_loop_stack_pos] == "GOTO")
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("WHILE loop: exited loop with 'Exit For'")
                    done = True
                    break

                # Was there an error that will make us jump to an error handler?
                if (context.must_handle_error()):
                    done = True
                    break
                context.clear_error()

                # Did we just run a GOTO? If so we should not run the
                # statements after the GOTO.
                #if (isinstance(s, Goto_Statement)):
                if (context.goto_executed or s.exited_with_goto):
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("GOTO executed. Go to next loop iteration.")
                    break
                
            # Finished with the loop due to 'Exit For' or error?
            if (done):
                break

            # Does it look like this might be an infinite loop? Check this by
            # seeing if any changes have been made to the variables in the loop
            # guard.
            curr_guard_vals = _get_guard_variables(self, context)
            if (curr_guard_vals == old_guard_vals):
                num_no_change += 1
                if (num_no_change >= context.max_static_iters):
                    log.warn("Possible infinite While loop detected. Exiting loop.")
                    break
            else:
                num_no_change = 0

        # Remove tracking of this loop.
        if (len(context.loop_stack) > 0):
            context.loop_stack.pop()
        if (len(context.loop_object_stack) > 0):
            context.loop_object_stack.pop()
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('WHILE loop: end.')

        # Run the error handler if we have one and we broke out of the statement
        # loop with an error.
        context.handle_error(params)
        

while_type = CaselessKeyword("While") | CaselessKeyword("Until")
        
while_clause = Optional(CaselessKeyword("Do").suppress()) + while_type("type") + boolean_expression("guard")

simple_while_statement = while_clause("clause") + Suppress(EOS) + Group(statement_block('body')) \
                       + (CaselessKeyword("Loop").suppress() |
                          CaselessKeyword("Wend").suppress() |
                          (CaselessKeyword("End").suppress() + CaselessKeyword("While").suppress()))

simple_while_statement.setParseAction(While_Statement)

# --- DO statement -----------------------------------------------------------

class Do_Statement(VBA_Object):
    """Emulate a VB Do-While loop.

    """
    
    def __init__(self, original_str, location, tokens):
        super(Do_Statement, self).__init__(original_str, location, tokens)
        self.is_loop = True
        self.loop_type = tokens.type
        self.guard = tokens.guard
        if (self.guard is None):
            self.guard = True
        self.body = tokens[0]
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        r = "Do\\n" + safe_str_convert(self.body) + "\\n"
        r += "Loop " + safe_str_convert(self.loop_type) + " " + safe_str_convert(self.guard)
        return r

    def to_python(self, context, params=None, indent=0):
        """
        Convert this loop to Python code.
        """

        # Boilerplate used by the Python.
        indent_str = " " * indent

        # Set up doing this for loop in Python.
        loop_start = indent_str + "exit_all_loops = False\n"
        loop_start += indent_str + "max_errors = " + safe_str_convert(VBA_Object.loop_upper_bound/10) + "\n"
        loop_start += indent_str + "while (True):\n"
        loop_start += indent_str + " " * 4 + "if exit_all_loops:\n"
        loop_start += indent_str + " " * 8 + "break\n"
        loop_start = indent_str + "# Start emulated loop.\n" + loop_start

        # Set up initialization of variables used in the loop.
        loop_init, prog_var = _loop_vars_to_python(self, context, indent)
            
        # Save the updated variable values.
        save_vals = _updated_vars_to_python(self, context, indent)
        
        # Set up the loop body.
        loop_str = safe_str_convert(self).replace('"', '\\"').replace("\\n", " :: ")
        if (len(loop_str) > 100):
            loop_str = loop_str[:100] + " ..."
        loop_body = ""
        # Report progress.
        loop_body += indent_str + " " * 4 + "if (" + prog_var + " % 100) == 0:\n"
        loop_body += indent_str + " " * 8
        loop_body += "safe_print(\"Done \" + str(" + prog_var + ") + \" iterations of Do While loop '" + loop_str + "'\")\n"
        loop_body += indent_str + " " * 4 + prog_var + " += 1\n"
        # No infinite loops.
        loop_body += indent_str + " " * 4 + "if (" + prog_var + " > " + safe_str_convert(VBA_Object.loop_upper_bound/10) + ") or " + \
                     "(vm_context.get_general_errors() > max_errors):\n"
        loop_body += indent_str + " " * 8 + "raise ValueError('Infinite Loop')\n"
        enter_loop()
        loop_body += to_python(self.body, context, params=params, indent=indent+4, statements=True)
        exit_loop()
        
        # Simulate the do-while loop by checking the not of the guard and exiting if needed at
        # the end of the loop body. Only do this if we actually have a guard.
        if (len(safe_str_convert(self.guard).strip()) > 0):
            if (self.loop_type.lower() == "until"):
                loop_body += indent_str + " " * 4 + "if (" + to_python(self.guard, context) + "):\n"
            else:
                loop_body += indent_str + " " * 4 + "if (not (" + to_python(self.guard, context) + ")):\n"
            loop_body += indent_str + " " * 8 + "break\n"
        
        # Full python code for the loop.
        python_code = loop_init + "\n" + \
                      loop_start + "\n" + \
                      loop_body + "\n" + \
                      save_vals + "\n"

        # Done.
        return python_code
    
    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return
        
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('DO loop: start: ' + safe_str_convert(self))

        # Do not bother running loops with empty bodies.
        self.exited_with_goto = True
        if (len(self.body) == 0):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("DO loop: empty body. Skipping.")
            return
        
        # Assign all const variables first.
        do_const_assignments(self.body, context)
        
        # Some loop guards check the readystate value on an object. To simulate this
        # will will just go around the loop a small fixed # of times.
        max_loop_iters = VBA_Object.loop_upper_bound
        if (".readyState" in safe_str_convert(self.guard)):
            log.info("Limiting # of iterations of a .readyState loop.")
            max_loop_iters = 5

        # See if we can convert the loop to Python and directly emulate it.
        if (_eval_python(self, context, params=params, add_boilerplate=True)):
            return

        # Track that the current loop is running.
        context.loop_stack.append(None)
        context.loop_object_stack.append(self)
        my_loop_stack_pos = len(context.loop_stack) - 1
        
        # Get the initial values of all the variables that appear in the loop guard.
        old_guard_vals = _get_guard_variables(self, context)
            
        # Loop until the loop is broken out of or we violate the loop guard.
        num_iters = 0
        num_no_change = 0
        while (True):

            # Break infinite loops.
            if (num_iters > max_loop_iters):
                log.error("Maximum loop iterations exceeded. Breaking loop.")
                break
            num_iters += 1
            
            # Execute the loop body.
            done = False
            context.goto_executed = False
            for s in self.body:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug('DO loop eval statement: %r' % s)
                if (not isinstance(s, VBA_Object)):
                    continue
                s.eval(context=context)

                # Has 'Exit For' been called?
                if ((my_loop_stack_pos >= len(context.loop_stack)) or context.loop_stack[my_loop_stack_pos]):

                    # Yes we have. Stop this loop.
                    self.exited_with_goto = (context.loop_stack[my_loop_stack_pos] == "GOTO")
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Do loop: exited loop with 'Exit For'")
                    done = True
                    break

                # Was there an error that will make us jump to an error handler?
                if (context.must_handle_error()):
                    done = True
                    break
                context.clear_error()

                # Did we just run a GOTO? If so we should not run the
                # statements after the GOTO.
                #if (isinstance(s, Goto_Statement)):
                if (context.goto_executed or s.exited_with_goto):
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("GOTO executed. Go to next loop iteration.")
                    break
                
            # Finished with the loop due to 'Exit For'?
            if (done):
                break

            # Test the loop guard to see if we should exit the loop.
            guard_val = True

            # Evaluate the guard if we have one.
            have_guard = (len(safe_str_convert(self.guard).strip()) > 0)
            if have_guard:
                guard_val = eval_arg(self.guard, context)
                if (self.loop_type.lower() == "until"):
                    guard_val = (not guard_val)
            if (not guard_val):
                break

            # Does it look like this might be an infinite loop? Check this by
            # seeing if any changes have been made to the variables in the loop
            # guard.
            if have_guard:
                curr_guard_vals = _get_guard_variables(self, context)
                if (curr_guard_vals == old_guard_vals):
                    num_no_change += 1
                    if (num_no_change >= context.max_static_iters):
                        log.warn("Possible infinite While loop detected. Exiting loop.")
                        break
                else:
                    num_no_change = 0
            
        # Remove tracking of this loop.
        if (len(context.loop_stack) > 0):
            context.loop_stack.pop()
        if (len(context.loop_object_stack) > 0):
            context.loop_object_stack.pop()
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('DO loop: end.')

        # Run the error handler if we have one and we broke out of the statement
        # loop with an error.
        context.handle_error(params)
        

simple_do_statement = Suppress(CaselessKeyword("Do")) + Suppress(EOS) + \
                      Group(statement_block('body')) + \
                      Suppress(CaselessKeyword("Loop")) + Optional(while_type("type") + boolean_expression("guard"))

simple_do_statement.setParseAction(Do_Statement)


# --- SELECT statement -----------------------------------------------------------

class Select_Statement(VBA_Object):
    """Emulate a VB Select statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(Select_Statement, self).__init__(original_str, location, tokens)
        self.select_val = tokens.select_val
        self.cases = tokens.cases
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        r = ""
        r += safe_str_convert(self.select_val)
        for case in self.cases:
            r += safe_str_convert(case)
        r += "End Select"
        return r

    def _to_python_if(self, context, indent, case, first):
        """
        Convert a single Select case to a Python if, elif, or else statement.
        """

        # Get the value being checked as Python.
        select_val_str = to_python(self.select_val, context)

        # Figure out the Python for the value being checked in this case.
        case.case_val.var_to_check = select_val_str
        case_guard_str = to_python(case.case_val, context)
        
        # Figure out the Python control flow construct to use.
        indent_str = " " * indent
        flow_str = "if "
        if (not first):
            flow_str = "elif "

        # Set up the check for this case.
        r = indent_str + flow_str + "(" + case_guard_str + "):\n"
            
        # Final catchall case?
        if ('in ["Else"]' in case_guard_str):
            r = indent_str + "else:\n"

        # Add in the case body.
        r += to_python(case.body, context, indent=indent+4, statements=True)
            
        return r
            
    def to_python(self, context, params=None, indent=0):

        # pylint.
        params = params
        
        r = ""
        first = True
        for case in self.cases:
            r += self._to_python_if(context, indent, case, first)
            first = False
        return r
    
    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return
        
        # Get the current value of the guard expression for the select.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("eval select: " + safe_str_convert(self))
        if (not isinstance(self.select_val, VBA_Object)):
            return
        select_guard_val = self.select_val.eval(context, params)

        # Loop through each case, seeing which one applies.
        for case in self.cases:

            # Get the case guard statement.
            case_guard = case.case_val

            # Is this the case we should take?
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval select: checking '" + safe_str_convert(select_guard_val) + " == " + safe_str_convert(case_guard) + "'")
            if (case_guard.eval(context, [select_guard_val])):

                # Evaluate the body of this case.
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("eval select: take case " + safe_str_convert(case))
                for statement in case.body:

                    # Emulate the statement.
                    if (not isinstance(statement, VBA_Object)):
                        continue
                    statement.eval(context, params)

                    # Was there an error that will make us jump to an error handler?
                    if (context.must_handle_error()):
                        break
                    context.clear_error()

                    # Did we just run a GOTO? If so we should not run the
                    # statements after the GOTO.
                    #if (isinstance(s, Goto_Statement)):
                    if (context.goto_executed or statement.exited_with_goto):
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug("GOTO executed. Break out of Select.")
                        break

                # Run the error handler if we have one and we broke out of the statement
                # loop with an error.
                context.handle_error(params)
                    
                # Done with the select.
                break

class Select_Clause(VBA_Object):
    """Emulate a clause of a Select statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(Select_Clause, self).__init__(original_str, location, tokens)
        self.select_val = tokens.select_val
        try:
            self.select_val = tokens.select_val[0]
        except TypeError:
            pass
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        r = ""
        r += "Select Case " + safe_str_convert(self.select_val) + "\\n " 
        return r

    def to_python(self, context, params=None, indent=0):

        # pylint.
        params = params
        indent = indent
        
        # Just returns the value being checked.
        return to_python(self.select_val, context)
    
    def eval(self, context, params=None):
        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return None
        if (hasattr(self.select_val, "eval")):
            return self.select_val.eval(context, params)
        return self.select_val

class Case_Clause_Atomic(VBA_Object):
    """Emulate simple clause of a case in a Select statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(Case_Clause_Atomic, self).__init__(original_str, location, tokens)

        # Parsed Else clause?
        if (tokens[0] == "Else"):
            self.case_val = ["Else"]

        # Do we have a range of values clause?
        self.test_range = ((tokens.lbound != "") and (tokens.ubound != ""))
        if (self.test_range):
            self.case_val = [tokens.lbound, tokens.ubound]
        else:
            self.case_val = tokens
            
        # Are we testing a set of values (possibly 1 value)?
        if ((not self.test_range) and
            (tokens.case_val is not None) and
            (tokens.case_val != "")):
            self.case_val = tokens
        self.test_set = (not self.test_range) and (len(self.case_val) > 1)

        # Set the flag so we know this is an Else clause.
        self.is_else = False
        for v in self.case_val:
            if (safe_str_convert(v).lower() == "else"):
                self.is_else = True
                break
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        r = ""
        if (self.test_range):
            r += safe_str_convert(self.case_val[0]) + " To " + safe_str_convert(self.case_val[1])
        elif (self.test_set):
            first = True
            for val in self.case_val:
                if (not first):
                    r += ", "
                first = False
                r += safe_str_convert(val)
        else:
            r += safe_str_convert(self.case_val[0])
        return r

    def to_python(self, context, params=None, indent=0):

        # pylint.
        params = params
        indent = indent
        
        # All select clause checks will checking for the select value being in a list of values.
        r = ""
        if (self.test_range):
            r += "range(" + to_python(self.case_val[0], context) + ", " + to_python(self.case_val[1], context) + " + 1)"
        elif (self.test_set):
            r += "["
            first = True
            for val in self.case_val:
                if (not first):
                    r += ", "
                first = False
                r += to_python(val, context)
            r += "]"
        else:
            r += "[" + to_python(self.case_val[0], context) + "]"
        return r
        
    def eval(self, context, params=None):
        """Evaluate the guard of this case against the given value.

        @param context (Context object) Context for the evaluation
        (local and global variables). State updates will be reflected
        in the given context.

        @param params (list) Any parameters provided to the object.

        @return (any) The result of evaluating the guard.
        """

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return False
        
        # Get the value against which to test the guard. This must already be
        # evaluated.
        test_val = params[0]

        # Is this the default case?
        if (self.is_else):
            return True
        
        # Are we testing to see if this is in a range of values?
        if (self.test_range):

            # Eval the start and end of the range.
            start = None
            end = None
            try:
                start = vba_conversion.int_convert(eval_arg(self.case_val[0], context))
                end = vba_conversion.int_convert(eval_arg(self.case_val[1], context)) + 1
            except Exception as e:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Select test range failed. " + safe_str_convert(e))
                return False                

            # Is the test val in the range?
            return (test_val in range(start, end))

        # Are we testing to see if this is in a set of values?
        if (self.test_set):

            # Construct the set of values against which to test.
            expected_vals = set()
            for val in self.case_val:
                try:
                    expected_vals.add(eval_arg(val, context))
                except Exception as e:
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Select test set add failed. " + safe_str_convert(e))
                    return False

            # Is the test val in the set?
            return (test_val in expected_vals)

        # We just have a regular test.
        expected_val = eval_arg(self.case_val[0], context)
        if (isinstance(test_val, int) and isinstance(expected_val, float)):
            test_val = 0.0 + test_val
        if (isinstance(test_val, float) and isinstance(expected_val, int)):
            expected_val = 0.0 + expected_val
        test_str = safe_str_convert(test_val)
        expected_str = safe_str_convert(expected_val)
        if (((test_str == "NULL") and (expected_str == "")) or
            ((expected_str == "NULL") and (test_str == ""))):
            return True
        return (test_str == expected_str)

class Case_Clause(VBA_Object):
    """Emulate a clause of a case in a Select statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(Case_Clause, self).__init__(original_str, location, tokens)
        self.clauses = []
        for clause in tokens:
            self.clauses.append(clause)
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        r = "Case "
        first = True
        for clause in self.clauses:
            if (not first):
                r += ", "
            first = False
            r += safe_str_convert(clause)
        return r

    def to_python(self, context, params=None, indent=0):

        # pylint.
        params = params
        indent = indent
        
        r = ""
        first = True
        for clause in self.clauses:
            if (not first):
                r += " or "
            first = False
            curr_str = to_python(clause, context)
            if ((not curr_str.startswith("range(")) and
                (not curr_str.startswith("["))):
                curr_str = "[" + curr_str + "]"
            r += self.var_to_check + " in " + curr_str
        return r
        
    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return False
        
        # Check each clause.
        for clause in self.clauses:
            guard_val = clause.eval(context, params=params)
            if (guard_val):
                return True
        return False
    
class Select_Case(VBA_Object):
    """Emulate a case in a Select statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(Select_Case, self).__init__(original_str, location, tokens)
        self.case_val = tokens.case_val
        self.body = tokens.body
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        r = ""
        r += safe_str_convert(self.case_val) + " " + safe_str_convert(self.body)
        return r

    def eval(self, context, params=None):

        # pylint.
        params = params
        
        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return
    

select_clause = CaselessKeyword("Select").suppress() + CaselessKeyword("Case").suppress() \
                + (expression("select_val") ^ boolean_expression("select_val"))
select_clause.setParseAction(Select_Clause)

#case_clause_atomic = ((expression("lbound") + CaselessKeyword("To").suppress() + expression("ubound")) | \
#                      (CaselessKeyword("Else")) | \
#                      (any_expression("case_val") + ZeroOrMore(Suppress(",") + any_expression)))
case_clause_atomic = ((expression("lbound") + CaselessKeyword("To").suppress() + expression("ubound")) | \
                      (CaselessKeyword("Else")) | \
                      (any_expression("case_val")))
case_clause_atomic.setParseAction(Case_Clause_Atomic)

case_clause = CaselessKeyword("Case").suppress() + \
              Suppress(Optional(CaselessKeyword("Is") + \
                                (Literal('=') ^ Literal('<') ^ Literal('>') ^ Literal('<=') ^ Literal('>=') ^ Literal('<>')))) + \
              case_clause_atomic + ZeroOrMore(Suppress(",") + case_clause_atomic)
case_clause.setParseAction(Case_Clause)

simple_statements_line = Forward()
select_case = case_clause("case_val") + \
              Optional((NotAny(EOS) + Group(simple_statements_line)("body")) ^ \
                       (Suppress(EOS) + Group(statement_block_not_empty('statements'))("body")))
select_case.setParseAction(Select_Case)

simple_select_statement = select_clause("select_val") + Suppress(EOS) + Group(ZeroOrMore(select_case + Suppress(Optional(EOS))))("cases") \
                          + Suppress(Optional(EOS)) + CaselessKeyword("End").suppress() + CaselessKeyword("Select").suppress()
simple_select_statement.setParseAction(Select_Statement)


# --- IF-THEN-ELSE statement ----------------------------------------------------------

class If_Statement(VBA_Object):
    """Emulate a VB If statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(If_Statement, self).__init__(original_str, location, tokens)

        # Copy constructor?
        self.is_bogus = False
        if (isinstance(tokens, If_Statement)):
            self.pieces = tokens.pieces
            return
        if ((len(tokens) == 1) and (isinstance(tokens[0], If_Statement))):
            self.pieces = tokens[0].pieces
            return

        # bogus_if_statement parsed?
        if ((len(tokens) == 1) and (isinstance(tokens[0], BoolExpr))):
            self.is_bogus = True
            return
        
        # Save the boolean guard and body for each case in the if, in order.
        self.pieces = []
        for tok in tokens:
            # If or ElseIf.
            if (len(tok) == 2):
                self.pieces.append({ 'guard' : tok[0], 'body' : tok[1]})
            # Else.
            elif (len(tok) == 1):
                self.pieces.append({ 'guard' : None, 'body' : tok[0]})
            # Bug.
            else:
                log.error('If part %r has wrong # elements.' % safe_str_convert(tok))

        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def get_children(self):
        """Return the child VBA objects of the current object.

        @return (list) A list of the children (VBA_Object) of this
        object.

        """

        if (self._children is not None):
            return self._children
        self._children = []
        if (self.is_bogus):
            return self._children
        for piece in self.pieces:

            # Handle If bodies.
            if (isinstance(piece["body"], VBA_Object)):
                self._children.append(piece["body"])
            if isinstance(piece['body'], (ParseResults, list)):
                for i in piece["body"]:
                    if (isinstance(i, VBA_Object)):
                        self._children.append(i)
            if (isinstance(piece["body"], dict)):
                for i in piece["body"].values():
                    if (isinstance(i, VBA_Object)):
                        self._children.append(i)

            # Handle If guards.
            if (isinstance(piece["guard"], VBA_Object)):
                self._children.append(piece["guard"])
            if isinstance(piece['guard'], (ParseResults, list)):
                for i in piece["guard"]:
                    if (isinstance(i, VBA_Object)):
                        self._children.append(i)
            if (isinstance(piece["guard"], dict)):
                for i in piece["guard"].values():
                    if (isinstance(i, VBA_Object)):
                        self._children.append(i)

        # Done. Return the children.
        return self._children

    def __repr__(self):
        return self._to_str(False)

    def full_str(self):
        return self._to_str(True)
    
    def _to_str(self, full_str):
        if (self.is_bogus):
            return "BOGUS IF STATEMENT"
        r = ""
        first = True
        for piece in self.pieces:

            # Pick the right keyword for this piece of the if.
            keyword = "If"
            if (not first):
                keyword = "ElseIf"
            if (piece["guard"] is None):
                keyword = "Else"
            first = False
            r += keyword + " "

            # Add in the guard.
            guard = ""
            keyword = ""
            if (piece["guard"] is not None):
                guard = None
                if (full_str):
                    guard = piece["guard"].full_str()
                else:
                    guard = piece["guard"].__repr__()
                    if (len(guard) > 5):
                        guard = guard[:6] + "..."
            r += guard + " "
            keyword = "Then "

            # Add in the body.
            r += keyword
            body = None
            if (full_str):
                body = piece["body"].full_str()
            else:
                body = piece["body"].__repr__().replace("\n", "; ")
                if (len(body) > 25):
                    body = body[:26] + "..."
            r += body + " "

        if (full_str):
            print guard
            print body
            sys.exit(0)
        return r

    def to_python(self, context, params=None, indent=0):

        # pylint.
        params = params
        
        # Not handling broken if statements.
        if (self.is_bogus):
            return ""

        # Make the Python code.
        r = ""
        first = True
        indent_str = " " * indent
        for piece in self.pieces:

            # Pick the right keyword for this piece of the if.
            r += indent_str
            keyword = "if"
            if (not first):
                keyword = "elif"
            if (piece["guard"] is None):
                keyword = "else"
            first = False
            r += keyword + " "

            # Add in the guard.
            guard = ""
            keyword = ""
            if (piece["guard"] is not None):
                guard = to_python(piece["guard"], context)
            r += guard

            # Add in the body.
            r += ":\n"
            body_str = to_python(piece["body"], context, indent=indent+4, statements=True)
            if (len(body_str.strip()) == 0):
                body_str = " " * (indent + 4) + "pass\n"
            r += body_str

        # Done.
        return r
    
    def eval(self, context, params=None):

        # pylint.
        params = params
        
        # Skip this if it is a bogus, do nothing if statement.
        if (self.is_bogus):
            return
        
        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return
        
        # Walk through each case of the if, seeing which one applies (if any).
        for piece in self.pieces:

            # Evaluate the guard, if it has one. Else parts have no guard.
            guard = True
            if (piece["guard"] is not None):
                guard = piece["guard"].eval(context)

            # Does this case apply?
            if (guard):

                # Yes it does. Emulate the statements in the body.
                for stmt in piece["body"]:
                    if (not isinstance(stmt, VBA_Object)):
                        continue
                    if (hasattr(stmt, "eval")):
                        stmt.eval(context)

                # We have emulated the if.
                break


# Grammar element for IF statements.
multi_line_if_statement = Group( CaselessKeyword("If").suppress() + \
                                 boolean_expression + \
                                 CaselessKeyword("Then").suppress() + Suppress(EOS) + \
                                 Group(statement_block)) + \
                                 ZeroOrMore(
                                     Group( CaselessKeyword("ElseIf").suppress() + \
                                            boolean_expression + \
                                            CaselessKeyword("Then").suppress() + Suppress(EOS) + \
                                            Group(statement_block))
                                 ) + \
                                 Optional(
                                     Group(CaselessKeyword("Else").suppress() + Group(simple_statements_line)) + Suppress(EOS) | \
                                     Group(CaselessKeyword("Else").suppress() + Suppress(EOS) + Group(statement_block))
                                 ) + \
                                 CaselessKeyword("End").suppress() + CaselessKeyword("If").suppress()
bad_if_statement = Group( CaselessKeyword("If").suppress() + boolean_expression + CaselessKeyword("Then").suppress() + Suppress(EOS) + \
                          Group(statement_block('statements'))) + \
                          ZeroOrMore(
                              Group( CaselessKeyword("ElseIf").suppress() + \
                                     boolean_expression + \
                                     CaselessKeyword("Then").suppress() + Suppress(EOS) + \
                                     Group(statement_block('statements')))
                          ) + \
                          Optional(
                              Group(CaselessKeyword("Else").suppress() + Suppress(EOS) + \
                                    Group(statement_block('statements')))
                          )

_single_line_if_statement = Group( CaselessKeyword("If").suppress() + boolean_expression + CaselessKeyword("Then").suppress() + \
                                   Group(simple_statements_line('statements')) )  + \
                                   ZeroOrMore(
                                       Group( CaselessKeyword("ElseIf").suppress() + \
                                              boolean_expression + \
                                              CaselessKeyword("Then").suppress() + \
                                              Group(simple_statements_line('statements')))
                                   ) + \
                                   Optional(
                                       (Group(CaselessKeyword("Else").suppress() + Group(simple_statements_line('statements'))) ^
                                        Group(CaselessKeyword("Else").suppress()))
                                   ) + Suppress(Optional(Optional(Literal(":")) + CaselessKeyword("End") + CaselessKeyword("If")))
single_line_if_statement = _single_line_if_statement
single_line_if_statement.setParseAction(If_Statement)

bogus_if_statement = CaselessKeyword("If").suppress() + boolean_expression + Optional(CaselessKeyword("Then")).suppress()

simple_if_statement = multi_line_if_statement ^ _single_line_if_statement ^ bogus_if_statement
simple_if_statement.setParseAction(If_Statement)

# --- IF-THEN-ELSE statement, macro version ----------------------------------------------------------

class If_Statement_Macro(If_Statement):
    """Emulate a VB If macro statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(If_Statement_Macro, self).__init__(original_str, location, tokens)
        self.external_functions = {}
        for piece in self.pieces:
            for token in piece["body"]:
                if isinstance(token, External_Function):
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("saving VBA macro external func decl: %r" % token.name)
                    self.external_functions[token.name] = token

    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return
        
        # TODO: Properly evaluating this will involve supporting compile time variables
        # that can be set via options when running ViperMonkey. For now just run the then
        # block.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("eval: " + safe_str_convert(self))
        then_part = self.pieces[0]
        for stmt in then_part["body"]:
            if (isinstance(stmt, VBA_Object)):
                stmt.eval(context)


# Grammar element for #IF statements.
simple_if_statement_macro = Group( CaselessKeyword("#If").suppress() + boolean_expression + CaselessKeyword("Then").suppress() + \
                                   Suppress(EOS) + \
                                   Group(statement_block('statements'))) + \
                                   ZeroOrMore(
                                       Group( Suppress(CaselessKeyword("#ElseIf") | CaselessKeyword("ElseIf")) + \
                                              boolean_expression + CaselessKeyword("Then").suppress() + Suppress(EOS) + \
                                              Group(statement_block('statements')))
                                   ) + \
                                   Optional(
                                       Group(Suppress(CaselessKeyword("#Else") | CaselessKeyword("Else")) + Suppress(EOS) + \
                                             Group(statement_block('statements')))
                                   ) + \
                                   CaselessKeyword("#End If").suppress() + FollowedBy(EOS)

simple_if_statement_macro.setParseAction(If_Statement_Macro)

# --- CALL statement ----------------------------------------------------------

class Call_Statement(VBA_Object):
    """Emulate a VB Call statement.

    """
    
    # List of interesting functions to log calls to.
    log_funcs = ["CreateProcessA", "CreateProcessW", "CreateProcess", ".run", "CreateObject",
                 "Open", ".Open", "GetObject", "Create", ".Create", "Environ",
                 "CreateTextFile", ".CreateTextFile", ".Eval", "Run",
                 "SetExpandedStringValue", "WinExec", "FileCopy", "Load",
                 "FolderExists", "FileExists"]
    
    def __init__(self, original_str, location, tokens, name=None, params=None):
        super(Call_Statement, self).__init__(original_str, location, tokens)

        # Direct creation.
        if ((name is not None) and (params is not None)):
            self.name = name
            self.params = params
            return

        # Save the call info.
        self.name = tokens.name
        if (safe_str_convert(self.name).endswith("@")):
            self.name = safe_str_convert(self.name).replace("@", "")
        if (safe_str_convert(self.name).endswith("!")):
            self.name = safe_str_convert(self.name).replace("!", "")
        if (safe_str_convert(self.name).endswith("#")):
            self.name = safe_str_convert(self.name).replace("#", "")
        if (safe_str_convert(self.name).endswith("%")):
            self.name = safe_str_convert(self.name).replace("%", "")
        self.params = tokens.params

        # Some calls will be counted as useless when figuring
        # out if we can skip emulating a loop.
        if (safe_str_convert(self.name).lower() == "debug.print"):
            self.is_useless = True

        # Done.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Call_Statement: %s(%r)' % (self.name, self.params)

    def _to_python_handle_with_calls(self, context, indent):
        """Convert a method call of an object specified with a With statement
        to Python code.

        @param context (Context object) The current program state.

        @param indent (int) The number of spaces of indent to use at
        the beginning of the generated Python code.

        @return (str) The current object with it's emulation
        implemented as Python code if this is a with object method
        call. None will be returned if it is not.

        """
        
        # Is this a call like '.WriteText "foo"'?
        func_name = safe_str_convert(self.name).strip()
        if (not func_name.startswith(".")):
            return None

        # We have a call to a function whose name starts with '.'. Are
        # we in a With block?
        if (len(context.with_prefix) == 0):
            return None

        # We have a method call of the With object. Make a member
        # access expression representing the method call of the
        # With object.
        tmp_var = SimpleNameExpression(None, None, None, name=safe_str_convert(context.with_prefix_raw))
        call_obj = Function_Call(None, None, None, old_call=self)
        call_obj.name = func_name[1:] # Get rid of initial '.'
        full_expr = MemberAccessExpression(None, None, None, raw_fields=(tmp_var, [call_obj], []))
        
        # Get python code for the fully qualified object method call.
        r = to_python(full_expr, context, indent=indent)
        return r
    
    def to_python(self, context, params=None, indent=0):

        # Reset the called function name if this is an alias for an imported external
        # DLL function.
        dll_func_name = context.get_true_name(self.name)
        is_external = False
        if (dll_func_name is not None):
            is_external = True
            self.name = dll_func_name
        
        # With block call statement?
        with_call_str = self._to_python_handle_with_calls(context, indent)
        if (with_call_str is not None):
            return with_call_str
        
        # Get a list of the Python expressions for each parameter.
        py_params = []
        # Expressions with boolean operators are probably bitwise operators.
        old_bitwise = context.in_bitwise_expression
        context.in_bitwise_expression = True
        for p in self.params:
            py_params.append(to_python(p, context, params))
        context.in_bitwise_expression = old_bitwise

        # Is the whole call stuffed into the name?
        indent_str = " " * indent
        if ((isinstance(self.name, VBA_Object)) and (len(self.params) == 0)):
            r = to_python(self.name, context, params)
            if (r.startswith(".")):
                r = r[1:]
            r = indent_str + r
            return r
            
        # Is this a VBA internal function? Or a call to an external function?
        func_name = safe_str_convert(self.name)
        if ("." in func_name):
            func_name = func_name[func_name.index(".") + 1:]
        import vba_library
        is_internal = (func_name.lower() in vba_library.VBA_LIBRARY)
        if (is_internal or is_external):

            # Make the Python parameter list.
            first = True
            args = "["
            for p in py_params:
                if (not first):
                    args += ", "
                first = False
                args += p

            # Execute() (dynamic VB execution) will be converted to Python and needs some
            # special arguments so the exec() of the JIT generated code works.
            if ((safe_str_convert(func_name) == "Execute") or
                (safe_str_convert(func_name) == "ExecuteGlobal") or
                (safe_str_convert(func_name) == "AddCode") or
                (safe_str_convert(func_name) == "AddFromString")):
                args += ", locals(), \"__JIT_EXEC__\""
            args += "]"

            # Internal function?
            r = None
            if is_internal:
                r = indent_str + "core.vba_library.run_function(\"" + safe_str_convert(func_name) + "\", vm_context, " + args + ")"
            else:
                r = indent_str + "core.vba_library.run_external_function(\"" + safe_str_convert(func_name) + "\", vm_context, " + args + ",\"\")"
            return r
                
        # Generate the Python function call to a local function.
        r = func_name + "("
        first = True
        for p in py_params:
            if (not first):
                r += ", "
            first = False
            r += p
        r += ")"
        if (r.startswith(".")):
            r = r[1:]
        r = indent_str + r
        
        # Done.
        return r

    def _handle_as_member_access(self, context):
        """Certain object method calls need to be handled as member access
        expressions. Given parsing limitations some of these are
        parsed as regular calls, so convert those to member access
        expressions here

        @param context (Context object) The current program state.

        @return (MemeberAccessExpression object) The call converted to
        a member access expressionm if possible, None if not.

        """

        # Is this a method call?
        func_name = safe_str_convert(self.name).strip()
        if (("." not in func_name) or (func_name.startswith("."))):
            return None
        short_func_name = func_name[func_name.rindex(".") + 1:]
        
        # It's a method call. Is it one we are handling as a member
        # access expression?
        memb_funcs = set(["AddItem", "Append_3"])
        if (short_func_name not in memb_funcs):
            return None

        # It should be handled as a member access expression.
        # Convert it.
        func_call_str = func_name + "("
        first = True
        for p in self.params:
            if (not first):
                func_call_str += ", "
            first = False
            p_eval = eval_arg(p, context=context)
            if isinstance(p_eval, str):
                p_eval = p_eval.replace('"', '""').replace("\n", "\\n").replace("\r", "\\r")
                p_eval = '"' + p_eval + '"'
            func_call_str += safe_str_convert(p_eval)
        func_call_str += ")"
        try:
            memb_exp = member_access_expression.parseString(func_call_str, parseAll=True)[0]

            # Evaluate the call as a member access expression.
            return memb_exp.eval(context)
        except ParseException as e:

            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Eval "' + func_call_str + '" as member access expression failed. ' + safe_str_convert(e))
                
            # Can't eval as a member access expression.
            return None
        
    def _handle_with_calls(self, context):
        """Emulate a method call of an object specified with a With statement.

        @param context (Context object) The current program state.

        @return (str) The result of emulating this call if this is a
        with object method call. None will be returned if it is not.

        """
        
        # Can we handle this call as a member access expression?
        as_member_access = self._handle_as_member_access(context)
        if (as_member_access is not None):
            return as_member_access
        
        # Is this a call like '.WriteText "foo"'?
        func_name = safe_str_convert(self.name).strip()
        if (not func_name.startswith(".")):
            return None

        # We have a call to a function whose name starts with '.'. Are
        # we in a With block?
        if (len(context.with_prefix) == 0):
            return None

        # We have a method call of the With object. Make a member
        # access expression representing the method call of the
        # With object.
        call_obj = Function_Call(None, None, None, old_call=self)
        call_obj.name = func_name[1:] # Get rid of initial '.'
        full_expr = MemberAccessExpression(None, None, None, raw_fields=(context.with_prefix, [call_obj], []))

        # Evaluate the fully qualified object method call.
        r = eval_arg(full_expr, context)
        return r
        
    def eval(self, context, params=None):

        # pylint.
        params = params
        
        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exit function previously called. Not evaluating '" + safe_str_convert(self) + "'")
            return None

        # Save the unresolved argument values.
        import vba_library
        vba_library.var_names = self.params
        
        # Reset the called function name if this is an alias for an imported external
        # DLL function.
        dll_func_name = context.get_true_name(self.name)
        is_external = False
        if (dll_func_name is not None):
            is_external = True
            self.name = dll_func_name

        # Are we calling a member access expression?
        if isinstance(self.name, MemberAccessExpression):

            # Just evaluate the expression as the call.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Call of member access expression " + safe_str_convert(self.name))
            r = self.name.eval(context, self.params)
            return r

        # TODO: The following should share the same code as MemberAccessExpression and Function_Call?

        # Get argument values.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Call: eval params: " + safe_str_convert(self.params))
        call_params = eval_args(self.params, context=context)
        str_params = repr(call_params)
        if (len(str_params) > 80):
            str_params = str_params[:80] + "..."

        # Would Visual Basic have thrown an error when evaluating the arguments?
        if (context.have_error()):
            log.warn('Short circuiting function call %s(%s) due to thrown VB error.' % (self.name, str_params))
            return None

        # Log functions of interest.
        if (not context.throttle_logging):
            log.info('Calling Procedure: %s(%r)' % (self.name, str_params))
        if (is_external):
            context.report_action("External Call", self.name + "(" + safe_str_convert(call_params) + ")", self.name, strip_null_bytes=True)
        # pylint: disable=protected-access
        if ((self.name.lower() in context._log_funcs) or
            (any(self.name.lower().endswith(func.lower()) for func in Function_Call.log_funcs))):
            tmp_call_params = call_params
            if ((safe_str_convert(self.name).endswith(".Run")) and (isinstance(call_params, list))):
                cmd = ""
                for p in call_params:
                    if (isinstance(p, str) and (len(p) > len(cmd))):
                        cmd = p
                if (len(cmd) > 0):
                    tmp_call_params = cmd
            context.report_action(self.name, tmp_call_params, 'Interesting Function Call', strip_null_bytes=True)

        # Handle method calls inside a With statement.
        r = self._handle_with_calls(context)
        if (r is not None):
            return r
        
        # Handle VBA functions:
        func_name = safe_str_convert(self.name).strip()
        if func_name.lower() == 'msgbox':
            # 6.1.2.8.1.13 MsgBox
            context.report_action('Display Message', call_params, 'MsgBox', strip_null_bytes=True)
            # vbOK = 1
            return 1
        elif '.' in func_name:
            tmp_call_params = call_params
            if (func_name.endswith(".Write")):
                tmp_call_params = []
                for p in call_params:
                    if (isinstance(p, str)):
                        tmp_call_params.append(p.replace("\x00", ""))
                    else:
                        tmp_call_params.append(p)
            if ((func_name.lower() != "Debug.Print".lower()) and
                (func_name.lower() != "WScript.Echo".lower()) and                
                (not func_name.endswith("Add")) and
                (not func_name.endswith("Write")) and
                (len(tmp_call_params) > 0)):
                tmp_call_params1 = tmp_call_params
                if ((safe_str_convert(func_name).endswith(".Run")) and (isinstance(tmp_call_params, list))):
                    cmd = ""
                    for p in tmp_call_params:
                        if (isinstance(p, str) and (len(p) > len(cmd))):
                            cmd = p
                    if (len(cmd) > 0):
                        tmp_call_params1 = cmd
                context.report_action('Object.Method Call', tmp_call_params1, func_name, strip_null_bytes=True)

        # Emulate the function body.
        try:

            # Pull out the function name if referenced via a module, etc.
            if ("." in func_name):
                func_name = func_name[func_name.index(".") + 1:]
                
            # Get the function.
            s = context.get(func_name)
            if (s is None):
                raise KeyError("func not found")
            if (hasattr(s, "eval")):
                ret = s.eval(context=context, params=call_params)
                
                # Set the values of the arguments passed as ByRef parameters.
                if (hasattr(s, "byref_params") and s.byref_params):
                    for byref_param_info in s.byref_params.keys():
                        if (byref_param_info[1] < len(self.params)):
                            arg_var_name = safe_str_convert(self.params[byref_param_info[1]])
                            context.set(arg_var_name, s.byref_params[byref_param_info])

                # We are out of the called function, so if we exited the called function early
                # it does not apply to the current function.
                context.exit_func = False

                # Return function result.
                return ret
            
        except KeyError:
            try:
                tmp_name = func_name.replace("$", "").replace("VBA.", "").replace("Math.", "").\
                           replace("[", "").replace("]", "").replace("'", "").replace('"', '')
                if ("." in tmp_name):
                    tmp_name = tmp_name[tmp_name.rindex(".") + 1:]
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Looking for procedure %r" % tmp_name)
                s = context.get(tmp_name)
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Found procedure " + tmp_name + " = " + safe_str_convert(s))
                if (s):
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Found procedure. Running procedure " + tmp_name)
                    s.eval(context=context, params=call_params)
            except KeyError:

                # If something like Application.Run("foo", 12) is called, foo(12) will be run.
                # Try to handle that.
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Did not find procedure.")
                if ((func_name == "Application.Run") or (func_name == "Run")):

                    # Pull the name of what is being run from the 1st arg.
                    new_func = call_params[0]

                    # The remaining params are passed as arguments to the other function.
                    new_params = call_params[1:]

                    # See if we can run the other function.
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Try indirect run of function '" + new_func + "'")
                    r = "NULL"
                    try:

                        # Emulate the function, drilling down through layers of indirection to get the func name.
                        s = context.get(new_func)
                        while (isinstance(s, str)):
                            s = context.get(s)
                            if isinstance(s, (VbaLibraryFunc, procedures.Function, procedures.Sub)):
                                s = s.eval(context=context, params=new_params)
                                r = s

                                # We are out of the called function, so if we exited the called function early
                                # it does not apply to the current function.
                                context.exit_func = False
                            
                        # Return the function result. This is "NULL" if we did not run a function.
                        return r

                    except KeyError:

                        # Return the function result. This is "NULL" if we did not run a function.
                        context.increase_general_errors()
                        log.warning('Function %r not found' % func_name)
                        return r

                # Report that we could not find the function.
                context.increase_general_errors()
                log.warning('Function %r not found' % func_name)
                    
            except Exception as e:
                traceback.print_exc(file=sys.stdout)
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("General error: " + safe_str_convert(e))
                return None

        # Should never get here.
        return None


# 5.4.2.1 Call Statement
# a call statement is similar to a function call, except it is a statement on its own, not part of an expression
# call statement params may be surrounded by parentheses or not
call_params = (
    (Suppress('(') + Optional(expr_list('params')) + Suppress(')'))
    # Handle missing 1st call argument.
    ^ (White(" \t") + Optional(Literal(",")) + expr_list('params'))
)
call_params_strict = (
    (Suppress('(') + Optional(expr_list_strict('params')) + Suppress(')'))
    # Handle missing 1st call argument.
    ^ (White(" \t") + Optional(Literal(",")) + expr_list_strict('params'))
)
call_statement0 = NotAny(known_keywords_statement_start) + \
                  Optional(CaselessKeyword('Call').suppress()) + \
                  (member_access_expression('name'))  + \
                  Suppress(Optional(NotAny(White()) + '$') + \
                           Optional(NotAny(White()) + '#') + \
                           Optional(NotAny(White()) + '@') + \
                           Optional(NotAny(White()) + '%') + \
                           Optional(NotAny(White()) + '!')) + \
                  Optional(call_params_strict) + \
                  Suppress(Optional("," + CaselessKeyword("0")) + \
                           Optional("," + (CaselessKeyword("true") | CaselessKeyword("false"))))

call_statement1 = NotAny(known_keywords_statement_start) + \
                  Optional(CaselessKeyword('Call').suppress()) + \
                  (TODO_identifier_or_object_attrib_loose('name')) + \
                  Suppress(Optional(NotAny(White()) + '$') + \
                           Optional(NotAny(White()) + '#') + \
                           Optional(NotAny(White()) + '@') + \
                           Optional(NotAny(White()) + '%') + \
                           Optional(NotAny(White()) + '!')) + \
                  Optional(call_params) + \
                  Suppress(Optional("," + CaselessKeyword("0")) + \
                           Optional("," + (CaselessKeyword("true") | CaselessKeyword("false"))))

call_statement2 = NotAny(known_keywords_statement_start) + \
                  Optional(CaselessKeyword('Call').suppress()) + \
                  Combine(lex_identifier + OneOrMore(Literal(".") + lex_identifier)).setResultsName('name') + \
                  Suppress(Optional(NotAny(White()) + '$') + \
                           Optional(NotAny(White()) + '#') + \
                           Optional(NotAny(White()) + '@') + \
                           Optional(NotAny(White()) + '%') + \
                           Optional(NotAny(White()) + '!')) + \
                  Optional(call_params) + \
                  Suppress(Optional("," + CaselessKeyword("0")) + \
                           Optional("," + (CaselessKeyword("true") | CaselessKeyword("false"))))

call_statement0.setParseAction(Call_Statement)
call_statement1.setParseAction(Call_Statement)
call_statement2.setParseAction(Call_Statement)

call_statement = (call_statement1 ^ call_statement0 ^ call_statement2)

# --- EXIT FOR statement ----------------------------------------------------------

class Exit_For_Statement(VBA_Object):
    """Emulate a Exit For statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(Exit_For_Statement, self).__init__(original_str, location, tokens)
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Exit For'

    def to_python(self, context, params=None, indent=0):

        # pylint.
        params = params
        context = context
        
        return " " * indent + "break"

    def eval(self, context, params=None):

        # pylint.
        params = params
        
        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return
        # Update the loop stack to indicate that the current loop should exit.
        if (len(context.loop_stack) > 0):
            context.loop_stack.pop()
        context.loop_stack.append("EXIT_FOR")

class Exit_While_Statement(Exit_For_Statement):
    """Emulate a VB Exit While statement.

    """
    
    def __repr__(self):
        return 'Exit Do'


# Break out of a For loop.
exit_for_statement = CaselessKeyword('Exit').suppress() + CaselessKeyword('For').suppress()
exit_for_statement.setParseAction(Exit_For_Statement)

# Break out of a While Do loop.
exit_while_statement = CaselessKeyword('Exit').suppress() + CaselessKeyword('Do').suppress()
exit_while_statement.setParseAction(Exit_While_Statement)

# Break out of a loop.
exit_loop_statement = exit_for_statement | exit_while_statement

# --- EXIT FUNCTION statement ----------------------------------------------------------

class Exit_Function_Statement(VBA_Object):
    """Emulate a VB Exit Function statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(Exit_Function_Statement, self).__init__(original_str, location, tokens)
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Exit Function'

    def to_python(self, context, params=None, indent=0):

        # pylint.
        params = params
        context = context
        
        return " " * indent + "exit_all_loops = True"
    
    def eval(self, context, params=None):

        # pylint.
        params = params
        
        # Mark that we should return from the current function.
        log.info("Explicit exit function invoked")
        context.exit_func = True


# Return from a function.
exit_func_statement = (CaselessKeyword('Exit').suppress() + CaselessKeyword('Function').suppress()) | \
                      (CaselessKeyword('Exit').suppress() + CaselessKeyword('Sub').suppress()) | \
                      (CaselessKeyword('Return').suppress()) #| \
#                      ((CaselessKeyword('End').suppress()) + ~CaselessKeyword("Function"))
exit_func_statement.setParseAction(Exit_Function_Statement)

# --- REDIM statement ----------------------------------------------------------

class Redim_Statement(VBA_Object):
    """Emulate a VB ReDim statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(Redim_Statement, self).__init__(original_str, location, tokens)
        self.item = safe_str_convert(tokens.item)
        self.raw_item = tokens.item
        self.start = None
        if (hasattr(tokens, "start")):
            self.start = tokens.start
        self.end = None
        if (hasattr(tokens, "end")):
            self.end = tokens.end
        self.data_type = None
        if (hasattr(tokens, "data_type")):
            self.data_type = tokens.data_type
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r' % self)

    def __repr__(self):
        r = 'ReDim ' + safe_str_convert(self.item)
        if ((self.start is not None) and (self.end is not None)):
            r += "(" + safe_str_convert(self.start) + " To " + safe_str_convert(self.end) + ")"
        if (self.data_type is not None):
            r += " As " + self.data_type
        return r

    def to_python(self, context, params=None, indent=0):

        # pylint.
        params = params
        context = context
        indent = indent
        
        # TODO: Needs work.
        return "ERROR: ReDim JIT generation needs work."
    # pylint: disable=pointless-string-statement
    """
        # Is this a Variant type?
        indent_str = " " * indent
        var_name = utils.fix_python_overlap(safe_str_convert(self.item))
        if (safe_str_convert(context.get_type(self.item)) == "Variant"):

            # Variant types cannot hold string values, so assume that the variable
            # should hold an array.
            return indent_str + var_name + " = []"

        # Is this a Byte array?
        # Or calling ReDim on something that does not exist (grrr)?
        elif ((safe_str_convert(context.get_type(self.item)) == "Byte Array") or
              (self.data_type == "Byte") or
              (not context.contains(self.item))):

            # Do we have a start and end for the new size?
            if ((self.start is not None) and (self.end is not None)):

                # Compute the new array size.
                start = None
                end = None
                try:

                    # Get the start and end of the new array. Must be integer constants.
                    start = "int(" + to_python(self.start, context=context) + ")"
                    end = "int(" + to_python(self.end, context=context) + ")"

                    # Resize the list.
                    new_list = "[0] * (" + end + " - " + start + ")"
                    return indent_str + var_name + " = " + new_list

                except:
                    pass

        # Resize array?
        elif (isinstance(self.raw_item, Function_Call)):

            # Got a new size?
            if (len(self.raw_item.params) > 0):

                # Get the new size.
                new_size = "int(" + to_python(self.raw_item.params[0], context=context) + ")"

                # Resize list.
                new_list = "[0] * (" + new_size + ")"
                var_name = utils.fix_python_overlap(safe_str_convert(self.raw_item.name))
                return indent_str + var_name + " = " + new_list
                    
        return "ERROR: Cannot generate python code for '" + safe_str_convert(self) + "'"
    """
    
    def eval(self, context, params=None):

        # pylint.
        params = params

        # Pull out the variable being redimmed.
        redim_var = safe_str_convert(self.item)
        if ("(" in redim_var):
            redim_var = redim_var[:redim_var.index("(")]

        # Is this a Variant type?
        if (safe_str_convert(context.get_type(self.item)) == "Variant"):

            # Variant types cannot hold string values, so assume that the variable
            # should hold an array.
            context.set(self.item, [])

        # Is this a Byte array?
        # Or calling ReDim on something that does not exist (grrr)?
        elif (((safe_str_convert(context.get_type(self.item)) == "Byte Array") or
               (not context.contains(self.item))) and
              (self.start is not None) and
              (self.end is not None) and
              (len(safe_str_convert(self.start).strip()) > 0) and
              (len(safe_str_convert(self.end).strip()) > 0)):

            # We have a start and end for the new size.

            # Compute the new array size.
            start = None
            end = None
            try:

                # Get the start and end of the new array. Must be integer constants.
                start = int(eval_arg(self.start, context=context))
                end = int(eval_arg(self.end, context=context))
                
                # Resize the list.
                new_list = [0] * (end - start)
                context.set(self.item, new_list)
                
            except Exception:
                pass

        # Resize array?
        elif (isinstance(self.raw_item, Function_Call)):

            # Got a new size?
            if (len(self.raw_item.params) > 0):

                # Get the new size.
                new_size = eval_arg(self.raw_item.params[0], context=context)
                
                # Got a value we can work with?
                if (isinstance(new_size, int)):
                    new_list = [0] * (new_size + 1)
                    var_name = self.raw_item.name
                    context.set(var_name, new_list)
                    
        return


# Array redim statement
redim_item = Optional(CaselessKeyword('Preserve')) + \
             expression('item') + \
             Optional('(' + expression('start') + CaselessKeyword('To') + expression('end') + \
                      ZeroOrMore("," + expression + CaselessKeyword('To') + expression) + ')') + \
             Optional(CaselessKeyword('As') + lex_identifier('data_type'))
redim_statement = CaselessKeyword('ReDim').suppress() + redim_item + ZeroOrMore("," + redim_item)

redim_statement.setParseAction(Redim_Statement)

# --- WITH statement ----------------------------------------------------------

class With_Statement(VBA_Object):
    """Emulate a With statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(With_Statement, self).__init__(original_str, location, tokens)
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("tokens = " + safe_str_convert(tokens))
        self.body = tokens[-1]
        self.env = tokens.env
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r' % self)

    def __repr__(self):
        return 'With ' + safe_str_convert(self.env) + "\\n" + safe_str_convert(self.body) + " End With"

    def to_python(self, context, params=None, indent=0):

        # pylint.
        params = params
        
        # Currently we are only supporting JIT emulation of With blocks
        # based on Scripting.Dictionary. Is that what we have?
        with_dict = None
        if ((context.with_prefix_raw is not None) and
            (context.contains(safe_str_convert(context.with_prefix_raw)))):
            with_dict = context.get(safe_str_convert(context.with_prefix_raw))
            if (not isinstance(with_dict, dict)):
                with_dict = None
        if (with_dict is None):
            return "ERROR: Only doing JIT on Scripting.Dictionary With blocks."

        # Save the dict representing the Scripting.Dictionary.
        r = ""
        indent_str = " " * indent
        r += indent_str + "# With block: " + safe_str_convert(self).replace("\\n", "\\\\n")[:50] + "...\n"
        r += indent_str + "with_dict = " + safe_str_convert(with_dict) + "\n"
        
        # Convert the with body to Python.
        r += to_python(self.body, context, indent=indent, statements=True)

        # Done.
        return r
                
    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return

        # Evaluate the with prefix value. This calls any functions that appear in the
        # with prefix.
        prefix_val = eval_arg(self.env, context)

        # Track the with prefix.
        context.with_prefix_raw = self.env
        if (len(context.with_prefix) > 0):
            context.with_prefix += "." + safe_str_convert(self.env)
            #context.with_prefix += "." + safe_str_convert(prefix_val)
        else:
            context.with_prefix = safe_str_convert(prefix_val)
        if (context.with_prefix.startswith(".")):
            context.with_prefix = context.with_prefix[1:]

        # Assign all const variables first.
        do_const_assignments(self.body, context)
            
        # Evaluate each statement in the with block.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("START WITH")
        try:
            _ = iter(self.body)
        except TypeError:
            self.body = [self.body]
        for s in self.body:

            # Emulate the statement.
            if (not isinstance(s, VBA_Object)):
                continue
            s.eval(context)

            # Was there an error that will make us jump to an error handler?
            if (context.must_handle_error()):
                break
            context.clear_error()

            # Did we just run a GOTO? If so we should not run the
            # statements after the GOTO.
            #if (isinstance(s, Goto_Statement)):
            if (context.goto_executed or s.exited_with_goto):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("GOTO executed. Go to next loop iteration.")
                break
            
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("END WITH")
            
        # Remove the current with prefix.
        context.with_prefix_raw = None
        if ("." not in context.with_prefix):
            context.with_prefix = ""
        else:
            # Pop back to previous With context.
            end = context.with_prefix.rindex(".")
            context.with_prefix = context.with_prefix[:end]

        # Run the error handler if we have one and we broke out of the statement
        # loop with an error.
        context.handle_error(params)
        
        return


# With statement
with_statement = CaselessKeyword('With').suppress() + Optional(".") + \
                 (member_access_expression('env') ^ ((lex_identifier('env') ^ function_call_limited('env')))) + \
                 Suppress(EOS) + \
                 Group(statement_block('body')) + \
                 CaselessKeyword('End').suppress() + CaselessKeyword('With').suppress()
with_statement.setParseAction(With_Statement)

# --- GOTO statement ----------------------------------------------------------

class Goto_Statement(VBA_Object):
    """Emulate a VB Goto statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(Goto_Statement, self).__init__(original_str, location, tokens)
        self.label = tokens.label
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as Goto_Statement' % self)

    def __repr__(self):
        return 'Goto ' + safe_str_convert(self.label)

    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return
        
        # Do we know the code block associated with the GOTO label?
        if (self.label not in context.tagged_blocks):

            # We don't know where to go. Punt.
            context.report_general_error("GOTO target " + safe_str_convert(self.label) + " is unknown.")
            return

        # We know where to go. Get the code block to execute.
        block = context.tagged_blocks[self.label]

        # Are we in a loop and have we just jumped out of it (grrrr!)?
        if (len(context.loop_object_stack) > 0):

            # Find which loop (if any) we are jumping to.
            curr_loop = context.loop_object_stack[-1]
            jump_loop = None
            tag_block_txt = safe_str_convert(block).replace(" ", "").replace("\n", "")
            pos = len(context.loop_stack)
            for tmp_loop in context.loop_object_stack[::-1]:

                # Is the tagged block in this loop?
                pos -= 1
                tmp_loop_txt = safe_str_convert(tmp_loop.body).replace(" ", "").replace("\n", "")
                if (tag_block_txt in tmp_loop_txt):
                    jump_loop = tmp_loop
                    break

            # Did we jump out of ALL the loops?
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("GOTO in loop.")
                log.debug("Jump to: " + tag_block_txt)
            if (jump_loop is None):

                # Mark all the loops as exited.
                context.loop_stack = ["GOTO"] * len(context.loop_stack)
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Jumped out of all loops.")
                    log.debug(context.loop_stack)

            # Did we jump out of SOME of the nested loops?
            elif (jump_loop != curr_loop):

                # Exit from all the nested loops up to the one we jumped to.
                tmp_stack = context.loop_stack
                context.loop_stack = context.loop_stack[:pos+1]
                context.loop_stack.extend(["GOTO"] * (len(tmp_stack) - (pos + 1)))
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Jumped out of some loops.")
                    log.debug(context.loop_stack)
                
        # Execute the code block.
        if (not context.throttle_logging):
            log.info("GOTO " + safe_str_convert(self.label))
        block.eval(context, params)

        # Tag that we have just emulated all the statements associated with the goto.
        # The execution flow was covered by emulating the destination of the goto,
        # so the regular code flow is now null and void.
        context.goto_executed = True


# Goto statement
goto_statement = (CaselessKeyword('Goto').suppress() | CaselessKeyword('Gosub').suppress()) + \
                 (lex_identifier('label') | decimal_literal('label'))
goto_statement.setParseAction(Goto_Statement)

# --- GOTO LABEL statement ----------------------------------------------------------

class Label_Statement(VBA_Object):
    """Emulate a VB Label statement (labeled block used for Goto).

    """
    
    def __init__(self, original_str, location, tokens):
        super(Label_Statement, self).__init__(original_str, location, tokens)
        self.label = tokens.label
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as Label_Statement' % self)

    def __repr__(self):
        return safe_str_convert(self.label) + ':'

    def eval(self, context, params=None):

        # pylint.
        params = params
        context = context
        
        # Currently stubbed out.
        return


# Goto label statement
label_statement <<= identifier('label') + Suppress(':')
label_statement.setParseAction(Label_Statement)

# --- ON ERROR STATEMENT -------------------------------------------------------------

class On_Error_Statement(VBA_Object):
    """Emulate a VB On Error statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(On_Error_Statement, self).__init__(original_str, location, tokens)
        self.tokens = tokens
        self.label = None
        if ((len(tokens) == 4) and (tokens[2].lower() == "goto")):
            self.label = safe_str_convert(tokens[3])
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as On_Error_Statement' % self)

    def __repr__(self):
        return safe_str_convert(self.tokens)

    def to_python(self, context, params=None, indent=0):

        # pylint.
        params = params
        context = context
        
        indent_str = " " * indent
        return indent_str + "# '" + safe_str_convert(self) + "' not emulated.\n" + \
            indent_str + "pass"
    
    def eval(self, context, params=None):

        # pylint.
        params = params
        
        # Do we have a goto error handler?
        if (self.label is not None):

            # Do we have a labeled block that matches the error handler block?
            if (self.label in context.tagged_blocks):

                # Set the error handler in the context.
                context.error_handler = context.tagged_blocks[self.label]
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Setting On Error handler block to '" + self.label + "'.")

            # Can't find error handler block.
            else:
                log.warning("Cannot find error handler block '" + self.label + "'.")

        return


on_error_statement = CaselessKeyword('On') + Optional(Suppress(CaselessKeyword('Local'))) + (CaselessKeyword('Error') | lex_identifier) + \
                     ((CaselessKeyword('Goto') + (decimal_literal | lex_identifier)) |
                      (CaselessKeyword('Resume') + CaselessKeyword('Next')))

on_error_statement.setParseAction(On_Error_Statement)

# --- RESUME STATEMENT -------------------------------------------------------------

resume_statement = CaselessKeyword('Resume') + Optional(lex_identifier)

# --- FILE OPEN -------------------------------------------------------------

class File_Open(VBA_Object):
    """Emulate a VB Open statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(File_Open, self).__init__(original_str, location, tokens)
        self.file_name = tokens.file_name
        self.file_id = tokens.file_id
        self.file_mode = None
        if (hasattr(tokens.type, "mode")):
            self.file_mode = tokens.type.mode
        self.file_access = None
        if (hasattr(tokens.type, "access")):
            self.file_access = tokens.type.access
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as File_Open' % self)

    def __repr__(self):
        r = "Open " + safe_str_convert(self.file_name) + " For " + safe_str_convert(self.file_mode)
        if (self.file_access is not None):
            r += " Access " + safe_str_convert(self.file_access)
        r += " As " + safe_str_convert(self.file_id)
        return r

    def eval(self, context, params=None):

        # pylint.
        params = params
        
        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return
        
        # Get the file name.
        name = self.file_name
        
        # Eval the name if it is not obviously a path.
        if (not safe_str_convert(name).lower().startswith("c:")):
            name = eval_arg(self.file_name, context=context)
            try:
                # Could be a variable.
                name = context.get(self.file_name)
            except KeyError:
                pass
            except AssertionError:
                pass

        # Store file id variable in context.
        file_id = ""
        if self.file_id:

            # Is the fileid already a #NNN fileid?
            file_id = safe_str_convert(self.file_id)
            if not file_id.startswith('#'):

                # No, Might be a variable containing the number of the file.
                try:
                    file_id = "#" + safe_str_convert(context.get(file_id))
                except KeyError:
                    # Punt and hope this is referring to the next open file ID.
                    file_id = "#" + safe_str_convert(context.get_num_open_files() + 1)

            # The fileid already is a #??? construct.
            else:

                # Is it something like #VAR_NAME (not numeric)?
                tmp_id = file_id[1:]
                if (not tmp_id.isdigit()):

                    # No, Might be a variable containing the number of the file.
                    try:
                        file_id = "#" + safe_str_convert(context.get(tmp_id))
                    except KeyError:
                        # Punt and hope this is referring to the next open file ID.
                        file_id = "#" + safe_str_convert(context.get_num_open_files() + 1)
                
            context.set(file_id, name, force_global=True)

        # Save that the file is opened.
        context.report_action("OPEN", safe_str_convert(name), 'Open File', strip_null_bytes=True)
        context.open_file(name, file_id)


file_type = (
    Suppress(CaselessKeyword("For"))
    + (
        CaselessKeyword("Append")
        | CaselessKeyword("Binary")
        | CaselessKeyword("Input")
        | CaselessKeyword("Output")
        | CaselessKeyword("Input")
        | CaselessKeyword("Random")
    )("mode")
    + Suppress(Optional(CaselessKeyword("Lock")))
    + Optional(
        Optional(Suppress(CaselessKeyword("Access")))
        + (
            CaselessKeyword("Read Write")
            ^ CaselessKeyword("Read Shared")
            ^ CaselessKeyword("Read")
            ^ CaselessKeyword("Shared")
            ^ CaselessKeyword("Write")
        )("access")
    )
)

file_open_statement = (
    Suppress(CaselessKeyword("Open"))
    + expression("file_name")
    + Optional(
        file_type("type")
        + Suppress(CaselessKeyword("As"))
        + (file_pointer("file_id") | TODO_identifier_or_object_attrib("file_id") | file_pointer_loose("file_id"))
        + Suppress(Optional(CaselessKeyword("Len") + Literal("=") + expression))
    )
)
file_open_statement.setParseAction(File_Open)

# --- PRINT -------------------------------------------------------------

class Print_Statement(VBA_Object):
    """Emulate a VB Print statement.

    """

    def __init__(self, original_str, location, tokens):
        super(Print_Statement, self).__init__(original_str, location, tokens)
        self.file_id = tokens.file_id
        self.value = tokens.value
        # TODO: Actually write the ';' values to the file.
        self.more_values = tokens.more_values
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as Print_Statement' % self)

    def __repr__(self):
        r = "Print " + safe_str_convert(self.file_id) + ", " + safe_str_convert(self.value)
        return r

    def eval(self, context, params=None):

        # pylint.
        params = params
        
        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return
        
        # Get the ID of the file.
        file_id = eval_arg(self.file_id, context=context)
        try:
            # Could be a variable.
            file_id = context.get(self.file_id)
        except KeyError:
            pass
        except AssertionError:
            pass

        # Get the data.
        data = eval_arg(self.value, context=context)

        context.write_file(file_id, data)
        if (isinstance(data, str)):
            context.write_file(file_id, '\r\n')


print_statement = Suppress(CaselessKeyword("Print")) + file_pointer("file_id") + Suppress(Optional(",")) + expression("value") + \
                  ZeroOrMore(Suppress(Literal(';')) + expression)("more_values") + Suppress(Optional("," + lex_identifier))
print_statement.setParseAction(Print_Statement)

# --- DOEVENTS STATEMENT -------------------------------------------------------------

doevents_statement = Suppress(CaselessKeyword("DoEvents"))

# --- STATEMENTS -------------------------------------------------------------

# simple statement: fits on a single line (excluding for/if/do/etc blocks)
simple_statement = (
    NotAny(Regex(r"End\s+Sub"))
    + (
        print_statement
        | dim_statement
        | option_statement
        | (
            prop_assign_statement
            ^ (let_statement | lset_statement | call_statement)
            ^ label_statement
            ^ expression
        )
        | exit_loop_statement
        | exit_func_statement
        | redim_statement
        | goto_statement
        | on_error_statement
        | file_open_statement
        | doevents_statement
        | rem_statement
        | resume_statement
        | global_variable_declaration
    )
)

# No label statement.
simple_statement_restricted = (
    NotAny(Regex(r"End\s+Sub"))
    + (
        print_statement
        | dim_statement
        | option_statement
        | (
            prop_assign_statement
            ^ (let_statement | lset_statement | call_statement)
            ^ expression
        )
        | exit_loop_statement
        | exit_func_statement
        | redim_statement
        | goto_statement
        | on_error_statement
        | file_open_statement
        | doevents_statement
        | rem_statement
        | resume_statement
        | single_line_if_statement
    )
)

simple_statements_line <<= (
   (simple_statement_restricted + OneOrMore(Suppress(':') + simple_statement_restricted))
   ^ simple_statement_restricted
)

statements_line <<= (
    tagged_block
    ^ (Optional(statement_restricted + ZeroOrMore(Suppress(':') + statement_restricted)) + EOS.suppress())
)

statements_line_no_eos <<= (
    tagged_block
    ^ (Optional(statement_restricted + ZeroOrMore(Suppress(':') + statement_restricted)))
)

# --- EXTERNAL FUNCTION ------------------------------------------------------

class External_Function(VBA_Object):
    """Emulate calling an external Function from a DLL.

    """

    file_count = 0
    def _createfile(self, params, context):
        """Set up tracking of a newly opened file in the program state
        object.

        @param params (list) The parameters passed to the called function.
        
        @param context (Context object) The program state. This tracks
        open/closed files and their contents.

        @return (str) The name of the new file if one was "opened",
        None if not.

        """
        
        # Get a name for the file.
        fname = None
        if ((params[0] is not None) and (len(params[0]) > 0)):
            fname = "#" + safe_str_convert(params[0])
        else:
            External_Function.file_count += 1
            fname = "#SOME_FILE_" + safe_str_convert(External_Function.file_count)

        # Save that the file is opened.
        context.open_file(fname)

        # Return the name of the "file".
        return fname

    def _writefile(self, params, context):
        """Simulate writing a file in the program state object.

        @param params (list) The parameters passed to the called function.
        
        @param context (Context object) The program state. This tracks
        open/closed files and their contents.

        @return (int) 0 (success) if the file was "written", 1 if not.

        """
        
        # Simulate the write.
        file_id = params[0]

        # Make sure the file exists.
        if (file_id not in context.open_files):
            context.report_general_error("File " + safe_str_convert(file_id) + " not open. Cannot write.")
            return 1
        
        # We can only write single byte values for now.
        data = params[1]
        if (not isinstance(data, int)):
            context.report_general_error("Cannot WriteFile() data that is not int.")
            return 0
        context.write_file(file_id, chr(data))
        return 0

    def _closehandle(self, params, context):
        """Simulate closing a file in the program state object.

        @param params (list) The parameters passed to the called function.
        
        @param context (Context object) The program state. This tracks
        open/closed files and their contents.

        @return (int) 0 (success) is always returned.

        """
        
        # Simulate the file close.
        file_id = params[0]
        context.close_file(file_id)
        return 0
    
    def __init__(self, original_str, location, tokens):
        super(External_Function, self).__init__(original_str, location, tokens)
        self.name = safe_str_convert(tokens.function_name)
        self.params = tokens.params
        self.lib_name = safe_str_convert(tokens.lib_info.lib_name)
        # normalize lib name: remove quotes, lowercase, add .dll if no extension
        if isinstance(self.lib_name, basestring):
            self.lib_name = safe_str_convert(tokens.lib_name).strip('"').lower()
            if '.' not in self.lib_name:
                self.lib_name += '.dll'
        self.lib_name = safe_str_convert(self.lib_name)
        self.alias_name = safe_str_convert(tokens.lib_info.alias_name)
        if isinstance(self.alias_name, basestring):
            # TODO: this might not be necessary if alias is parsed as quoted string
            self.alias_name = self.alias_name.strip('"')
        if (len(self.alias_name.strip()) == 0):
            self.alias_name = self.name
        self.return_type = tokens.return_type
        self.vars = {}
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r' % self)

    def __repr__(self):
        return 'External Function %s (%s) from %s alias %s' % (self.name, self.params, self.lib_name, self.alias_name)

    def to_python(self, context, params=None, indent=0):

        # pylint.
        context = context
        params = params
        
        # Get information about the DLL.
        lib_info = safe_str_convert(self.lib_name) + " / " + safe_str_convert(self.alias_name)

        # Just make a Python comment.
        indent_str = " " * indent
        r = indent_str + "# DLL Import: " + safe_str_convert(self.name) + " -> " + lib_info + "\n"
        return r
        
    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            log.info("Exiting " + str(type(self)) + " due to explicit function exit.")
            return 0

        # If we emulate an external function we are treating it like a VBA builtin function.
        # So we won't create a new context.

        # Resolve aliased function names.
        if self.alias_name:
            function_name = self.alias_name
        else:
            function_name = self.name
        if (not context.throttle_logging):
            log.info('Evaluating external function %s(%r)' % (function_name, params))

        # Log certain function calls.
        function_name = function_name.lower()
        if function_name.startswith('urldownloadtofile'):
            context.report_action('Download URL', params[1], 'External Function: urlmon.dll / URLDownloadToFile', strip_null_bytes=True)
            context.report_action('Write File', params[2], 'External Function: urlmon.dll / URLDownloadToFile', strip_null_bytes=True)
            # return 0 when no error occurred:
            return 0
        elif function_name.startswith('shellexecute'):
            cmd = None
            if (len(params) >= 4):
                cmd = safe_str_convert(params[2]) + " " + safe_str_convert(params[3])
            else:
                cmd = safe_str_convert(params[1]) + " " + safe_str_convert(params[2])
            context.report_action('Run Command', cmd, function_name, strip_null_bytes=True)
            # return 0 when no error occurred:
            return 0
        else:
            call_str = safe_str_convert(self.alias_name) + "(" + safe_str_convert(params) + ")"
            call_str = call_str.replace('\x00', "")
            context.report_action('External Call', call_str, safe_str_convert(self.lib_name) + " / " + safe_str_convert(self.alias_name))
        
        # Simulate certain external calls of interest.
        if (function_name.startswith('createfile')):
            return self._createfile(params, context)

        if (function_name.startswith('writefile')):
            return self._writefile(params, context)

        if (function_name.startswith('closehandle')):
            return self._closehandle(params, context)

        # Emulate certain calls.
        try:
            s = context.get_lib_func(function_name)
            if (s is None):
                raise KeyError("func not found")
            r = s.eval(context=context, params=params)
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("External function " + safe_str_convert(function_name) + " returns " + safe_str_convert(r))
            return r
        except KeyError:
            pass
        
        # TODO: return result according to the known DLLs and functions
        log.warning('Unknown external function %s from DLL %s' % (function_name, self.lib_name))

        # Assume that returning 0 means the call failed, return 1 to (hopefully) indicate success.
        return 1


function_type2 = CaselessKeyword('As').suppress() + lex_identifier('return_type') \
                 + Optional(Literal(".") + lex_identifier) \
                 + Optional(Literal('(') + Literal(')')).suppress()

public_private <<= Optional(CaselessKeyword('Public') | \
                            CaselessKeyword('Private') | \
                            CaselessKeyword('Global') | \
                            CaselessKeyword('Friend')) + \
                   Optional(CaselessKeyword('WithEvents'))

params_list_paren = Suppress('(') + Optional(parameters_list('params')) + Suppress(')')

# 5.2.3.5 External Procedure Declaration
lib_info = CaselessKeyword('Lib').suppress() + quoted_string('lib_name') \
           + Optional(CaselessKeyword('Alias') + quoted_string('alias_name'))

# TODO: identifier or lex_identifier
external_function <<= public_private + Suppress(CaselessKeyword('Declare') + Optional(CaselessKeyword('PtrSafe')) + \
                                                (CaselessKeyword('Function') | CaselessKeyword('Sub'))) + \
                                                lex_identifier('function_name') + lib_info('lib_info') + \
                                                Optional(params_list_paren) + Optional(function_type2)
external_function.setParseAction(External_Function)

# --- TRY/CATCH STATEMENT ------------------------------------------------------

class TryCatch(VBA_Object):
    """Emulate a VB Try/Catch exception handling statement.

    """

    def __init__(self, original_str, location, tokens):
        super(TryCatch, self).__init__(original_str, location, tokens)
        tmp = TaggedBlock(original_str, location, None)
        tmp.block = tokens["try_block"]
        tmp.label = "try_block"
        self.try_block = tmp
        tmp = TaggedBlock(original_str, location, None)
        tmp.block = tokens["catch_block"]
        tmp.label = "catch_block"
        self.catch_block = tmp
        self.except_var = tokens["exception_var"]
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r' % self)

    def __repr__(self):
        return "Try::" + safe_str_convert(self.try_block) + "::Catch " + safe_str_convert(self.except_var) + " As Exception::" + safe_str_convert(self.catch_block) + "::End Try"

    def eval(self, context, params=None):

        # pylint.
        params = params
        
        # Treat the catch block like an onerror goto block. To do this locally override the current error
        # handler block.
        old_handler = context.get_error_handler()
        context.error_handler = self.catch_block

        # Evaluate the try block.
        self.try_block.eval(context)

        # Reset the error handler block.
        context.error_handler = old_handler


try_catch = Suppress(CaselessKeyword('Try')) + Suppress(EOS) + statement_block('try_block') + \
            Suppress(CaselessKeyword('Catch')) + lex_identifier('exception_var') + \
            Suppress(CaselessKeyword('As')) + Suppress(CaselessKeyword('Exception')) + \
            Suppress(EOS) + statement_block('catch_block') + Suppress(CaselessKeyword('##End')) + Suppress(CaselessKeyword('##Try'))
try_catch.setParseAction(TryCatch)

# --- NAME nnn AS yyy statement ----------------------------------------------------------

class NameStatement(VBA_Object):
    """Emulate a VB file renaming Name statement.

    """

    def __init__(self, original_str, location, tokens):
        super(NameStatement, self).__init__(original_str, location, tokens)
        self.old_name = tokens.old_name
        self.new_name = tokens.new_name
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as NameStatement' % self)

    def __repr__(self):
        return "Name " + safe_str_convert(self.old_name) + " As " + safe_str_convert(self.new_name)

    def eval(self, context, params=None):

        # pylint.
        params = params
        
        # Resolve names.
        old_name = eval_arg(self.old_name, context=context)
        new_name = eval_arg(self.new_name, context=context)

        # Report file rename.
        context.report_action("File Rename", "Rename '" + old_name + "' to '" + new_name + "'", "File Rename", strip_null_bytes=True)
        

name_statement = CaselessKeyword('Name') + expression("old_name") + CaselessKeyword('As') + expression("new_name")
name_statement.setParseAction(NameStatement)

# --- STOP statement ----------------------------------------------------------

class Stop_Statement(VBA_Object):
    """Emulate a VB Stop statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(Stop_Statement, self).__init__(original_str, location, tokens)
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Stop'

    def eval(self, context, params=None):
        # Looks like this is for debugging, so we will assume execution is contunued.
        pass


stop_statement = CaselessKeyword('Stop').suppress()
stop_statement.setParseAction(Stop_Statement)

# --- LINE INPUT statement ----------------------------------------------------------

class Line_Input_Statement(VBA_Object):
    """Emulate a VB Line Input statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(Line_Input_Statement, self).__init__(original_str, location, tokens)
        self.file_id = tokens.file_id
        self.var = tokens.var
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as Line_Input_Statement' % self)

    def __repr__(self):
        return 'Line Input #' + safe_str_convert(self.file_id) + ", " + safe_str_convert(self.var)

    def eval(self, context, params=None):

        # pylint.
        context = context
        params = params
        
        # TODO: Implement Line Input functionality.
        log.warn("'Line Input' statements not emulated. Treating '" + safe_str_convert(self) + "' as a NOOP.")


line_input_statement = CaselessKeyword('Line').suppress() + CaselessKeyword('Input').suppress() + \
                       Literal("#").suppress() + expression("file_id") + Literal(",") + \
                       expression("var")
line_input_statement.setParseAction(Line_Input_Statement)

# --- Large block of simple function calls. ----------------------------------------------------------

def quick_parse_simple_call(tokens):
    """Quickly parse a block of simple function calls.

    @param tokens (PyParsing token list) The basic parsed items in the
    block of simple function calls.

    @return (list) A list of Call_Statement objects.

    """
    
    text = safe_str_convert(tokens[0]).strip()
    r = []
    for i in text.split("\n"):
        i = i.strip()
        if (len(i) == 0):
            continue

        # Try to directly create the parsed call.
        name = None
        params = None

        # Pull out name and paramaters of call like foo(1,2,3).
        if ("(" in i):
            name = i[:i.index("(")].strip()
            params_str = i[i.index("(") + 1:].strip()
            if (params_str.endswith(")")):
                params_str = params_str[:-1]
                params = params_str.split(",")

        # Pull out name and paramaters of call like foo 1,2,3).
        elif (" " in i):
            name = i[:i.index(" ")].strip()
            params_str = i[i.index(" ") + 1:].strip()
            params = params_str.split(",")

        # Do we have 1 of the 2 handled call forms?
        if ((name is not None) and (params is not None)):

            # See if we can directly generate the parsed parameters.
            tmp_params = []
            for p in params:

                # Integer parameter?
                if (p.isdigit()):
                    tmp_params.append(int(p))

                # Variable parameter?
                elif (re.match(r"[_a-zA-Z][_a-zA-Z\d]*", p) is not None):
                    tmp_params.append(SimpleNameExpression(None, None, None, p))

                # Unhandled parameter type.
                else:
                    tmp_params = None
                    break
            params = tmp_params

        # Directly create the call statement?
        if ((name is not None) and (params is not None)):
            r.append(Call_Statement(None, None, None, name=name, params=params))

        # Parse out the call statement
        else:
            r.append(call_statement0.parseString(i, parseAll=True)[0])

    # Done. Return the list of call statements.
    return r


simple_call_list = Regex(re.compile("(?:\w+\s*\(?(?:\w+\s*,\s*)*\s*\w+\)?\n){100,}"))
simple_call_list.setParseAction(quick_parse_simple_call)

# --- Orphaned Statement Closing Markers ----------------------------------------------------------

class Orphaned_Marker(VBA_Object):
    """Handle a floating, unused end statement block marker.

    """
    
    def __init__(self, original_str, location, tokens):
        super(Orphaned_Marker, self).__init__(original_str, location, tokens)
        log.warning("Orphaned statement marker found.")

    def __repr__(self):
        return "' ORPHANED MARKER"

    def eval(self, context, params=None):
        pass
        

orphaned_marker = Suppress((CaselessKeyword("End") + CaselessKeyword("Function")) ^ \
                           (CaselessKeyword("End") + CaselessKeyword("Sub")))
orphaned_marker.setParseAction(Orphaned_Marker)

# --- Enum Statement ----------------------------------------------------------
# 
# Enum SecurityLevel 
#  IllegalEntry = -1 
#  SecurityLevel1 = 0 
#  SecurityLevel2 = 1 
# End Enum 
#
# Enum flxMask
#    [Ampersand (&)] = 1
#    UpperA = 2
#    LowerA = 3
#    UpperC = 4
#    LowerC = 5
#    [Number Sign (#)] = 6
#    [Nine Sign (9)] = 7
#    [Question Mark (?)] = 8
#    NoPos = 9
#    [DecPoint (.)] = 10
# End Enum
#
# Enum CarType
#   Sedan         'Value = 0
#   HatchBack = 2 'Value = 2
#   SUV = 10      'Value = 10
#   Truck         'Value = 11
# End Enum

class EnumStatement(VBA_Object):
    """Emulate a VB Enum statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(EnumStatement, self).__init__(original_str, location, tokens)
        self.name = safe_str_convert(tokens[0])
        self.values = []
        enum_vals = tokens[1]
        last_val = -1
        for enum_val in enum_vals:
            last_val += 1
            if (len(enum_val) == 2):
                last_val = enum_val[1]
            self.values.append((safe_str_convert(enum_val[0]), last_val))
                
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as Enum_Statement' % self)

    def __repr__(self):
        r = "Enum " + self.name + "\\n"
        for enum_val in self.values:
            r += "  " + enum_val[0] + " = " + safe_str_convert(enum_val[1]) + " \\n"
        r += "End Enum"
        return r

    def eval(self, context, params=None):

        # pylint.
        params = params
        
        # Add the enum values as variables to the context.
        for enum_val in self.values:
            context.set(enum_val[0], enum_val[1], force_global=True)


enum_value = Group((lex_identifier | enum_val_id)("name") + Optional(Suppress(Literal("=")) + integer("value")))
enum_statement = Suppress(Optional(CaselessKeyword('Public') | CaselessKeyword('Private'))) + \
                 Suppress(CaselessKeyword("Enum")) + lex_identifier("enum_name") + Suppress(EOS) + \
                 Group(ZeroOrMore(enum_value + Suppress(EOS))("enum_values")) + \
                 Suppress(CaselessKeyword("End")) + Suppress(CaselessKeyword("Enum"))
enum_statement.setParseAction(EnumStatement)
    
# WARNING: This is a NASTY hack to handle a cyclic import problem between procedures and
# statements. To allow local function/sub definitions the grammar elements from procedure are
# needed here in statements. But, procedures also needs the grammar elements defined here in
# statements. Just placing the statement grammar definition in this file like normal leads
# to a Python import error. To get around this the statement grammar element is being actually
# set in extend_statement_grammar(). extend_statement_grammar() is called at the end of
# procedures.py, so when all of the elements in procedures.py have actually beed defined the
# statement grammar element can be safely set.
def extend_statement_grammar():
    """Nasty hack to get around problems with cyclic imports.

    """
    
    # statement has to be declared beforehand using Forward(), so here we use
    # the "<<=" operator:
    global statement
    global statement_no_orphan
    global statement_restricted

    statement <<= try_catch | type_declaration | simple_for_statement | real_simple_for_each_statement | simple_if_statement | \
                  line_input_statement | simple_if_statement_macro | simple_while_statement | \
                  simple_do_statement | simple_select_statement | with_statement| simple_statement | rem_statement | \
                  (procedures.simple_function ^ orphaned_marker) | \
                  (procedures.simple_sub ^ orphaned_marker) | \
                  (procedures.property_let ^ orphaned_marker) | \
                  (procedures.property_get ^ orphaned_marker) | \
                  name_statement | stop_statement | enum_statement

    statement_no_orphan <<= try_catch | type_declaration | simple_for_statement | real_simple_for_each_statement | simple_if_statement | \
                            line_input_statement | simple_if_statement_macro | simple_while_statement | \
                            simple_do_statement | simple_select_statement | with_statement| simple_statement | rem_statement | \
                            procedures.simple_function | procedures.simple_sub | name_statement | stop_statement | enum_statement

    statement_restricted <<= try_catch | type_declaration | simple_for_statement | real_simple_for_each_statement | simple_if_statement | \
                             line_input_statement | simple_if_statement_macro | simple_while_statement | simple_do_statement | \
                             simple_select_statement | name_statement | with_statement| simple_statement_restricted | rem_statement | \
                             procedures.simple_function | procedures.simple_sub | stop_statement | enum_statement
