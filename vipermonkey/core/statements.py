#!/usr/bin/env python
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

from comments_eol import *
from expressions import *
from vba_context import *
from reserved import *
from from_unicode_str import *
from vba_object import int_convert
import procedures
from var_in_expr_visitor import *

import traceback
import string
from logger import log
import sys
import re
import base64
from curses_ascii import isprint

def is_simple_statement(s):
    """
    Check to see if the given VBAObject is a simple_statement.
    """

    return (isinstance(s, Dim_Statement) or
            isinstance(s, Option_Statement) or
            isinstance(s, Prop_Assign_Statement) or
            isinstance(s, Let_Statement) or
            # Calls run other statements, so they are not simple.
            #isinstance(s, Call_Statement) or
            isinstance(s, Exit_For_Statement) or
            isinstance(s, Exit_While_Statement) or
            isinstance(s, Exit_Function_Statement) or
            isinstance(s, Redim_Statement) or
            isinstance(s, Goto_Statement) or
            isinstance(s, On_Error_Statement) or
            isinstance(s, File_Open) or
            isinstance(s, Print_Statement))
    

# --- UNKNOWN STATEMENT ------------------------------------------------------

class UnknownStatement(VBA_Object):
    """
    Base class for all VBA statements
    """

    def __init__(self, original_str, location, tokens):
        super(UnknownStatement, self).__init__(original_str, location, tokens)
        self.text = tokens.text
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Unknown statement: %s' % repr(self.text)

    def eval(self, context, params=None):
        log.debug(self)

# Known keywords used at the beginning of statements
known_keywords_statement_start = (Optional(CaselessKeyword('Public') | CaselessKeyword('Private') | CaselessKeyword('End')) + \
                                  (CaselessKeyword('Sub') | CaselessKeyword('Function'))) | \
                                  CaselessKeyword('Set') | CaselessKeyword('For') | CaselessKeyword('Next') | \
                                  CaselessKeyword('If') | CaselessKeyword('Then') | CaselessKeyword('Else') | \
                                  CaselessKeyword('ElseIf') | CaselessKeyword('End If') | CaselessKeyword('New') | \
                                  CaselessKeyword('#If') | CaselessKeyword('#Else') | CaselessKeyword('#ElseIf') | CaselessKeyword('#End If') | \
                                  CaselessKeyword('Exit') | CaselessKeyword('Type') | CaselessKeyword('As') | CaselessKeyword("ByVal") | \
                                  CaselessKeyword('While') | CaselessKeyword('Do') | CaselessKeyword('Until') | CaselessKeyword('Select') | \
                                  CaselessKeyword('Case') | CaselessKeyword('On') 

# catch-all for unknown statements
unknown_statement = NotAny(known_keywords_statement_start) + \
                    Combine(OneOrMore(CharsNotIn('":\'\x0A\x0D') | quoted_string_keep_quotes),
                            adjacent=False).setResultsName('text')
unknown_statement.setParseAction(UnknownStatement)


# --- ATTRIBUTE statement ----------------------------------------------------------

# 4.2 Modules

class Attribute_Statement(VBA_Object):

    def __init__(self, original_str, location, tokens):
        super(Attribute_Statement, self).__init__(original_str, location, tokens)
        self.name = tokens.name
        self.value = tokens.value
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
    def __init__(self, original_str, location, tokens):
        super(Option_Statement, self).__init__(original_str, location, tokens)
        self.name = tokens.name
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Option %s' % (self.name)

option_statement = CaselessKeyword('Option').suppress() + unrestricted_name + Optional(unrestricted_name)
option_statement.setParseAction(Option_Statement)

# --- NAME nnn AS yyy statement ----------------------------------------------------------

class Name_As_Statement(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(Name_As_Statement, self).__init__(original_str, location, tokens)
        self.old_name = tokens.old_name
        self.new_name = tokens.new_name
        log.debug('parsed %r' % self)

    def __repr__(self):
        return "Name " + str(self.old_name) + " As " + str(self.new_name)
    
name_as_statement = CaselessKeyword('Name').suppress() + lex_identifier('old_name') + CaselessKeyword('As').suppress() + lex_identifier('new_name')
name_as_statement.setParseAction(Name_As_Statement)

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
                             OneOrMore(lex_identifier + CaselessKeyword('As') + reserved_type_identifier + \
                                       Suppress(Optional("*" + (decimal_literal | lex_identifier))) + Suppress(EOS)) + \
                             CaselessKeyword('End') + CaselessKeyword('Type') + \
                             ZeroOrMore( Literal(':') + (CaselessKeyword('Public') | CaselessKeyword('Private')) + CaselessKeyword('Type') + \
                                         lex_identifier + Suppress(EOS) + \
                                         OneOrMore(lex_identifier + CaselessKeyword('As') + reserved_type_identifier + Suppress(EOS)) + \
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
    """
    VBA parameter with name and type, e.g. 'abc as string'
    """

    def __init__(self, original_str, location, tokens):
        super(Parameter, self).__init__(original_str, location, tokens)
        self.name = tokens.name
        self.my_type = tokens.type
        self.init_val = tokens.init_val
        self.mechanism = str(tokens.mechanism)
        # Is this an array parameter?
        if (('(' in str(tokens)) and (')' in str(tokens))):
            # Arrays are always passed by reference.
            self.mechanism = 'ByRef'
        # The default parameter passing mechanism is ByRef.
        # See https://www.bettersolutions.com/vba/macros/byval-or-byref.htm
        if (len(self.mechanism) == 0):
            self.mechanism = 'ByRef'
        log.debug('parsed %r' % self)

    def __repr__(self):
        r = ""
        if (self.mechanism):
            r += str(self.mechanism) + " "
        r += str(self.name)
        if self.my_type:
            r += ' as ' + str(self.my_type)
        if (self.init_val):
            r += ' = ' + str(self.init_val)
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

parameter = Optional(CaselessKeyword("optional").suppress()) + Optional(parameter_mechanism('mechanism')) + TODO_identifier_or_object_attrib('name') + \
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
    """
    A label and the block of statements associated with the label.
    """

    def __init__(self, original_str, location, tokens):
        super(TaggedBlock, self).__init__(original_str, location, tokens)
        if (tokens is None):
            # Make empty tagged block object.
            return
        self.block = tokens.block
        self.label = str(tokens.label).replace(":", "")
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Tagged Block: %s: %s' % (repr(self.label), repr(self.block))

    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return
        for s in self.block:
            s.eval(context, params=params)

            # Was there an error that will make us jump to an error handler?
            if (context.must_handle_error()):
                break
            context.clear_error()

            # Did we just run a GOTO? If so we should not run the
            # statements after the GOTO.
            if (isinstance(s, Goto_Statement)):
                log.debug("GOTO executed. Go to next loop iteration.")
                break
            
        # Run the error handler if we have one and we broke out of the statement
        # loop with an error.
        context.handle_error(params)

tagged_block = Forward()
label_statement = Forward()
        
# need to declare statement beforehand:
statement = Forward()
external_function = Forward()

# NOTE: statements should NOT include EOS
block_statement = rem_statement | external_function | statement
# tagged_block broken out so it does not consume the final EOS in the statement block.
statement_block = ZeroOrMore(tagged_block ^ (block_statement + EOS.suppress()))
statement_block_not_empty = OneOrMore(tagged_block ^ (block_statement + EOS.suppress()))
tagged_block <<= label_statement('label') + Suppress(EOS) + statement_block('block')
tagged_block.setParseAction(TaggedBlock)

# --- DIM statement ----------------------------------------------------------

class Dim_Statement(VBA_Object):
    """
    Dim statement
    """

    def __init__(self, original_str, location, tokens):
        super(Dim_Statement, self).__init__(original_str, location, tokens)
        
        # Track the initial value of the variable.
        self.init_val = "NULL"
        last_var = tokens[-1:][0]
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
        
        log.debug('parsed %r' % str(self))

    def __repr__(self):
        r = "Dim "
        first = True
        for var in self.variables:
            if (not first):
                r += ", "
            first = False
            r += str(var[0])
            if (var[1]):
                r += "("
                if (var[3] is not None):
                    r += str(var[3])
                r += ")"
            if (var[2]):
                r += " As " + str(var[2])
        if (self.init_val is not None):
            r += " = " + str(self.init_val)
        return r

    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
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

            # Set the initial value of the declared variable.
            context.set(var[0], curr_init_val, curr_type)
            log.debug("DIM " + str(var[0]) + " As " + str(curr_type) + " = " + str(curr_init_val))
    
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
untyped_variable_dcl = identifier + Optional(array_clause('bounds') | as_clause)
typed_variable_dcl = typed_name + Optional(array_dim)
# TODO: Set the initial value of the global var in the context.
variable_dcl = (typed_variable_dcl | untyped_variable_dcl) + Optional('=' + expression('expression'))
variable_declaration_list = delimitedList(Group(variable_dcl))
local_variable_declaration = Suppress(CaselessKeyword("Dim") | CaselessKeyword("Static") | CaselessKeyword("Const")) + Optional(CaselessKeyword("Shared")).suppress() + variable_declaration_list

dim_statement = local_variable_declaration
dim_statement.setParseAction(Dim_Statement)

# --- Global_Var_Statement statement ----------------------------------------------------------

# TODO: Support multiple variables set (e.g. 'name = "bob", age = 20\n')
class Global_Var_Statement(Dim_Statement):
    pass

public_private = Forward()
global_variable_declaration = Suppress(Optional(public_private)) + \
                              Optional(CaselessKeyword("Shared")).suppress() + \
                              Optional(CaselessKeyword("Const")).suppress() + \
                              variable_declaration_list
global_variable_declaration.setParseAction(Global_Var_Statement)

# --- LET STATEMENT --------------------------------------------------------------

class Let_Statement(VBA_Object):

    def __init__(self, original_str, location, tokens):
        super(Let_Statement, self).__init__(original_str, location, tokens)
        self.name = tokens.name
        string_ops = set(["mid"])
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
        log.debug('parsed %r' % self)

    def __repr__(self):
        if (self.index is None):
            return 'Let %s %s %r' % (self.name, self.op, self.expression)
        else:
            return 'Let %s(%r) %s %r' % (self.name, self.index, self.op, self.expression)

    def _handle_change_callback(self, var_name, context):

        # Get the variable name, minus any embedded context.
        var_name = str(var_name)
        if ("." in var_name):
            var_name = var_name[var_name.rindex(".") + 1:]

        # Get the name of the change callback for the variable.
        callback_name = var_name + "_Change"

        # Do we have any functions defined with this callback name?
        try:

            # Can we find something with this name?
            callback = context.get(callback_name)
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

    def _handle_string_mod(self, context, rhs):
        """
        Handle assignments like Mid(a_string, start_pos, len) = "..."
        """

        # Are we modifying a string?
        if (self.string_op is None):
            return False

        # Modifying a substring?
        if (self.string_op["op"] == "mid"):

            # Get the string to modify, substring start index, and substring length.
            args = self.string_op["args"]
            if (len(args) < 3):
                return False
            the_str = eval_arg(args[0], context)
            the_str_var = args[0]
            start = eval_arg(args[1], context)
            size = eval_arg(args[2], context)

            # Sanity check.
            if ((not isinstance(the_str, str)) and (not isinstance(the_str, list))):
                log.error("Assigning " + str(self.name) + " failed. " + str(the_str_var) + " not str or list.")
                return False
            if (type(the_str) != type(rhs)):
                log.error("Assigning " + str(self.name) + " failed. " + str(type(the_str)) + " != " + str(type(rhs)))
                return False
            if (((start-1 + size) > len(the_str)) or (start < 1)):
                log.error("Assigning " + str(self.name) + " failed. " + str(start + size) + " out of range.")
                return False
            
            # Modify the string.
            mod_str = the_str[:start-1] + rhs + the_str[(start-1 + size):]

            # Set the string in the context.
            context.set(str(the_str_var), mod_str)
            return True

        # No string modification.
        return False

    def _handle_autoincrement(self, lhs, rhs):

        # Add/subtract the rhs from the lhs.
        r = "NULL"
        try:
            if (self.op == "+="):
                r = (lhs + rhs)
            elif (self.op == "-="):
                r = (lhs - rhs)
        except:
            pass
        return r
            
    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return
        
        # If a function return value is being set (LHS == current function name),
        # treat references to the function name on the RHS as a variable rather
        # than a function. Do this by initializing a local variable with the function
        # name here if needed.
        if ((context.contains(self.name)) and
            (isinstance(context.get(self.name), procedures.Function))):
            log.debug("Adding uninitialized '" + str(self.name) + "' function return var to local context.")
            context.set(self.name, 'NULL')
        
        # evaluate value of right operand:
        log.debug('try eval expression: %s' % self.expression)
        rhs_type = context.get_type(str(self.expression))
        value = eval_arg(self.expression, context=context)
        if (context.have_error()):
            log.warn('Short circuiting assignment %s due to thrown VB error.' % str(self))
            return
        log.debug('eval expression: %s = %s' % (self.expression, value))

        # Doing base64 decode with VBA? Maybe?
        if (self.name == ".Text"):

            # Try converting the text from base64.
            try:
                tmp_str = filter(isprint, str(value).strip())
                value = base64.b64decode(tmp_str)
            except Exception as e:
                log.warning("base64 conversion of '" + str(value) + "' failed. " + str(e))
                
        # Is this setting an interesting field in a COM object?
        if ((str(self.name).endswith(".Arguments")) or
            (str(self.name).endswith(".Path"))):
            context.report_action(self.name, value, 'Possible Scheduled Task Setup', strip_null_bytes=True)

        # Modifying a string using something like Mid() on the LHS of the assignment?
        if (self._handle_string_mod(context, value)):
            return

        # Setting OnSheetActivate function?
        if (str(self.name).endswith("OnSheetActivate")):

            # Emulate the OnSheetActivate function.
            func_name = str(self.expression).strip()
            try:
                func = context.get(func_name)
                log.info("Emulating OnSheetActivate handler function " + func_name + "...")
                func.eval(context)
                return
            except KeyError:
                log.error("WARNING: Cannot find OnSheetActivate handler function %s" % func_name)

        # Handle auto increment/decrement.
        if ((self.op == "+=") or (self.op == "-=")):
            lhs = context.get(self.name)
            value = self._handle_autoincrement(lhs, value)
                
        # set variable, non-array access.
        if (self.index is None):

            # Handle conversion of strings to byte arrays, if needed.
            if ((context.get_type(self.name) == "Byte Array") and
                (isinstance(value, str))):

                # Do we have an actual value to assign?
                if (value != "NULL"):

                    # Generate the byte array for the string.
                    tmp = []
                    pos = 0
                    for c in value:

                        # Append the byte value of the character.
                        tmp.append(ord(c))

                        # Append padding 0 bytes for wide char strings.
                        #
                        # TODO: Figure out how VBA figures out if this is a wide string (0 padding added)
                        # or not (no padding).
                        if (not isinstance(value, from_unicode_str)):
                            tmp.append(0)

                    # Got the byte array.
                    value = tmp

                # We are dealing with an unsassigned variable. Don't update
                # the array.
                else:
                    return
                    
            # Handle conversion of byte arrays to strings, if needed.
            elif ((context.get_type(self.name) == "String") and
                  (isinstance(value, list))):

                # Do we have a list of integers?
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
                        if (rhs_type == "Byte Array"):
                            step = 1
                        while (pos < len(value)):
                            tmp += chr(value[pos])
                            pos += step
                        value = tmp
                    except:
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

            # Handle conversion of strings to int, if needed.
            elif (((context.get_type(self.name) == "Integer") or
                   (context.get_type(self.name) == "Long")) and
                  (isinstance(value, str))):
                try:
                    value = int(value)
                except:
                    log.error("Cannot convert '" + str(value) + "' to int. Defaulting to 0.")
                    value = 0

            # Update the variable, if there was no error.
            if (value != "ERROR"):

                # Update the variable.
                log.debug('setting %s = %s' % (self.name, value))
                context.set(self.name, value)

                # See if there is a change callback function for the updated variable.
                self._handle_change_callback(self.name, context)

            else:

                # TODO: Currently we are assuming that 'On Error Resume Next' is being
                # used. Need to actually check what is being done on error.
                log.debug('Not setting ' + self.name + ", eval of RHS gave an error.")

        # Set variable, array access.
        else:

            # Evaluate the index expression(s).
            index = int_convert(eval_arg(self.index, context=context))
            if (self.index1 is not None):
                log.error('Multidimensional arrays not handled. Setting "%s(%r, %r) = %s" failed.' % (self.name, index, index1, value))
                return
                
            # Is array variable being set already represented as a list?
            # Or a string?
            arr_var = None
            try:
                arr_var = context.get(self.name)
            except KeyError:
                log.error("WARNING: Cannot find array variable %s" % self.name)
            if ((not isinstance(arr_var, list)) and (not isinstance(arr_var, str))):

                # We are wiping out whatever value this had.
                arr_var = []

            # Handle lists
            if (isinstance(arr_var, list)):
            
                # Do we need to extend the length of the list to include the index?
                if (index >= len(arr_var)):
                    arr_var.extend([0] * (index - len(arr_var)))
                
                # We now have a list with the proper # of elements. Set the
                # array element to the proper value.
                arr_var = arr_var[:index] + [value] + arr_var[(index + 1):]

            # Handle strings.
            if ((isinstance(arr_var, str)) or (isinstance(arr_var, unicode))):

                # Do we need to extend the length of the string to include the index?
                if (index >= len(arr_var)):
                    arr_var += "\0"*(index - len(arr_var))
                
                # We now have a string with the proper # of elements. Set the
                # array element to the proper value.
                if ((isinstance(value, str)) or (isinstance(value, unicode))):
                    arr_var = arr_var[:index] + value + arr_var[(index + 1):]
                elif (isinstance(value, int)):
                    try:
                        arr_var = arr_var[:index] + chr(value) + arr_var[(index + 1):]
                    except Exception as e:
                        log.error(str(e))
                        log.error(str(value) + " cannot be converted to ASCII.")
                else:
                    log.error("Unhandled value type " + str(type(value)) + " for array update.")
                        
            # Finally save the updated variable in the context, if there was no error.
            if (value != "ERROR"):

                # Update the array.
                context.set(self.name, arr_var)

                # See if there is a change callback function for the updated variable.
                self._handle_change_callback(self.name, context)

            else:

                # TODO: Currently we are assuming that 'On Error Resume Next' is being
                # used. Need to actually check what is being done on error.
                log.debug('Not setting ' + self.name + ", eval of RHS gave an error.")
        
# 5.4.3.8   Let Statement
#
# A let statement performs Let-assignment of a non-object value. The Let keyword itself is optional
# and may be omitted.
#
# MS-GRAMMAR: let-statement = ["Let"] l-expression "=" expression

# TODO: remove Set when Set_Statement implemented:

# Mid(zLGzE1gWt, MbgQPcQzy, 1)
string_modification = CaselessKeyword('Mid') + Optional(Suppress('(')) + expr_list('params') + Optional(Suppress(')'))

let_statement = (
    Optional(CaselessKeyword('Let') | CaselessKeyword('Set')).suppress()
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
let_statement.setParseAction(Let_Statement)

# --- PROPERTY ASSIGNMENT STATEMENT --------------------------------------------------------------

class Prop_Assign_Statement(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(Prop_Assign_Statement, self).__init__(original_str, location, tokens)
        self.prop = tokens.prop
        self.param = tokens.param
        self.value = tokens.value
        log.debug('parsed %r as Prop_Assign_Statement' % self)

    def __repr__(self):
        return str(self.prop) + " " + str(self.param) + ":=" + str(self.value)

    def eval(self, context, params=None):
        # Exit if an exit function statement was previously called.
        if (context.exit_func):
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

    def __init__(self, original_str, location, tokens):
        super(For_Statement, self).__init__(original_str, location, tokens)
        self.name = tokens.name
        self.start_value = tokens.start_value
        self.end_value = tokens.end_value
        self.step_value = tokens.get('step_value', 1)
        if self.step_value != 1:
            self.step_value = self.step_value[0]
        self.statements = tokens.statements
        log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        return 'For %s = %r to %r step %r' % (self.name,
                                              self.start_value, self.end_value, self.step_value)

    def _handle_medium_loop(self, context, params, end, step):

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
            is_constant = (str(s.expression).isdigit())
            if ((not isinstance(s.expression, SimpleNameExpression)) and (not is_constant)):
                all_static_assigns = False
                break

            # Is the variable the loop index variable?
            if (str(s.expression).strip().lower() == str(self.name).strip().lower()):
                all_static_assigns = False
                break

        # Does the loop body do the same thing repeatedly?
        if (not all_static_assigns):
            return False

        # The loop body has all static assignments. Emulate the loop body once.
        log.info("Short circuited loop. " + str(self))
        for s in self.statements:

            # Emulate the statement.
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
        context.set(self.name, end + step)
                     
        return True
                
    def _handle_simple_loop(self, context, start, end, step):

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
        body_raw = str(self.statements[0]).replace("Let ", "")
        body = body_raw.replace("(", "").replace(")", "").strip()
        if (body.startswith("Dim ")):

            # Just run the loop body once.
            self.statements[0].eval(context)

            # Set the final value of the loop index variable.
            context.set(self.name, end + step)

            # Indicate that the loop was short circuited.
            log.info("Short circuited Dim only loop " + str(self))
            return ("N/A", "N/A")

        # Are we just assigning a variable to the loop counter?
        if (body.endswith(" = " + str(self.name))):

            # Just assign the variable to the final loop counter value, unless
            # we have an array update on the LHS.
            fields = body_raw.split(" ")
            var = fields[0].strip()
            if (("(" not in var) and (")" not in var)):
                context.set(self.name, end + step)
                return (var, end + step)
            
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

        # Figure out the value to use to change the variable in the loop.
        expr_str = ""
        for e in fields[4:]:
            expr_str += e
        num = None
        try:
            expr = expression.parseString(expr_str, parseAll=True)[0]
            num = str(expr)
            if (hasattr(expr, "eval")):
                num = str(expr.eval(context))
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
            if (not str(init_val).isdigit()):
                return (None, None)
            init_val = int(str(init_val))

        except KeyError:

            # The variable is undeclared/uninitialized. Default to 0.
            init_val = 0

        # Figure out the # of loop iterations that will run.
        num_iters = (end - start + 1)/step
            
        # We are just modifying a variable each time. Figure out the final
        # value of the variable modified in the loop.
        try:
            num = int(num)
        except:
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
        """
        Return True if the loop body only contains atomic statements (no ifs, selects, etc.) and
        the previous program state (minus the loop variable) is equal to the current program state.
        """

        # Sanity check.
        if ((prev_context is None) or (context is None)):
            return False
        
        # First check to see if the loop body only contains atomic statements.
        for s in self.statements:
            if (not isinstance(s, VBA_Object)):
                continue
            if ((not is_simple_statement(s)) and (not s.is_useless)):
                return False

        # Remove the loop counter variable from the previous loop iteration
        # program state and the current program state.
        prev_context = Context(context=prev_context, _locals=prev_context.locals, copy_globals=True).delete(self.name).delete("now").delete("application.username")
        context = Context(context=context, _locals=context.locals, copy_globals=True).delete(self.name).delete("now").delete("application.username")

        # There is no state change if the previous state is equal to the
        # current state.
        r = (prev_context == context)
        return r
    
    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return
        
        # evaluate values:
        log.debug('FOR loop: evaluating start, end, step')

        # Do not bother running loops with empty bodies.
        if (len(self.statements) == 0):
            log.debug("FOR loop: empty body. Skipping.")
            return

        # Get the start index. If this is a string, convert to an int.
        start = eval_arg(self.start_value, context=context)
        if (isinstance(start, basestring)):
            try:
                start = int(start)
            except:

                # Is this a single character?
                if (len(start) == 1):

                    # Looks like this Chr() should be an int.
                    start = ord(start[0])

        log.debug('FOR loop - start: %r = %r' % (self.start_value, start))

        # Get the end index. If this is a string, convert to an int.
        end = eval_arg(self.end_value, context=context)
        if (isinstance(end, basestring)):
            try:
                if (end == "NULL"):
                    end = 0
                else:
                    end = int(end)
            except:

                # Is this a single character?
                if (len(end) == 1):

                    # Looks like this Chr() should be an int.
                    end = ord(end[0])

        if (isinstance(end, float)):
            end = int(end)
        if (not isinstance(end, int)):
            end = 0
        log.debug('FOR loop - end: %r = %r' % (self.end_value, end))

        # Get the loop step value.
        if self.step_value != 1:
            step = eval_arg(self.step_value, context=context)
            log.debug('FOR loop - step: %r = %r' % (self.step_value, step))
        else:
            step = 1

        # Handle backwards loops.
        if ((start > end) and (step > 0)):
            step = step * -1
            
        # Set the loop index variable to the start value.
        context.set(self.name, start)
            
        # See if we have a simple style loop put in purely for obfuscation.
        var, val = self._handle_simple_loop(context, start, end, step)
        if ((var is not None) and (val is not None)):
            log.info("Short circuited loop. Set " + str(var) + " = " + str(val))
            context.set(var, val)
            self.is_useless = True
            return

        # See if we have a more complicated style loop put in purely for obfuscation.
        do_body_once = self._handle_medium_loop(context, params, end, step)
        if (do_body_once):
            self.is_useless = True
            return

        # Set end to valid values.
        if ((VBA_Object.loop_upper_bound > 0) and (end > VBA_Object.loop_upper_bound)):
            end = VBA_Object.loop_upper_bound
            log.debug("FOR loop: upper loop iteration bound exceeded, setting to %r" % end)
        
        # Track that the current loop is running.
        context.loop_stack.append(True)

        # Track the context from the previous loop iteration to see if we have
        # a loop that is just there for obfuscation.
        num_no_change = 0
        prev_context = None
        
        # Loop until the loop is broken out of or we hit the last index.
        while (((step > 0) and (context.get(self.name) <= end)) or
               ((step < 0) and (context.get(self.name) >= end))):

            # Handle assigning the loop index variable to a constant value
            # in the loop body. This can cause infinite loops.
            last_index = context.get(self.name)
            
            # Is the loop body a simple series of atomic statements and has
            # nothing changed in the program state since the last iteration?
            if (self._no_state_change(prev_context, context)):
                num_no_change += 1
                if (num_no_change >= context.max_static_iters * 5):
                    log.warn("Possible useless For loop detected. Exiting loop.")
                    self.is_useless = True
                    break
            prev_context = Context(context=context, _locals=context.locals, copy_globals=True)
            
            # Execute the loop body.
            log.debug('FOR loop: %s = %r' % (self.name, context.get(self.name)))
            done = False
            for s in self.statements:
                log.debug('FOR loop eval statement: %r' % s)
                if (not isinstance(s, VBA_Object)):
                    continue
                s.eval(context=context)
                
                # Has 'Exit For' been called?
                if (not context.loop_stack[-1]):

                    # Yes we have. Stop this loop.
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
                if (isinstance(s, Goto_Statement)):
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
                log.error("Cannot update loop counter. Breaking loop. " + str(e))
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
        context.loop_stack.pop()
        log.debug('FOR loop: end.')

        # Run the error handler if we have one and we broke out of the statement
        # loop with an error.
        context.handle_error(params)
        
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

    def __init__(self, original_str, location, tokens):
        super(For_Each_Statement, self).__init__(original_str, location, tokens)
        self.statements = tokens.statements
        self.item = tokens.clause.item
        self.container = tokens.clause.container
        log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        return 'For Each %r In %r ...' % (self.item, self.container)

    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return
        
        # Track that the current loop is running.
        context.loop_stack.append(True)

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

        # Try iterating over the values in the container.
        if (not isinstance(container, list)):
            container = [container]
        try:
            for item_val in container:

                # Set the loop item variable in the context.
                context.set(self.item, item_val)
                
                # Execute the loop body.
                log.debug('FOR EACH loop: %r = %r' % (self.item, context.get(self.item)))
                done = False
                for s in self.statements:
                    log.debug('FOR EACH loop eval statement: %r' % s)
                    if (not isinstance(s, VBA_Object)):
                        continue
                    s.eval(context=context)

                    # Has 'Exit For' been called?
                    if (not context.loop_stack[-1]):

                        # Yes we have. Stop this loop.
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
                    if (isinstance(s, Goto_Statement)):
                        log.debug("GOTO executed. Go to next loop iteration.")
                        break
                    
                # Finished with the loop due to 'Exit For' or error?
                if (done):
                    break

        except:

            # The data type for the container may not be iterable. Do nothing.
            pass
        
        # Remove tracking of this loop.
        context.loop_stack.pop()
        log.debug('FOR EACH loop: end.')

        # Run the error handler if we have one and we broke out of the statement
        # loop with an error.
        context.handle_error(params)
        
for_each_clause = CaselessKeyword("For").suppress() \
                  + CaselessKeyword("Each").suppress() \
                  + lex_identifier("item") \
                  + CaselessKeyword("In").suppress() \
                  + expression("container") \

simple_for_each_statement = for_each_clause('clause') + Suppress(EOS) + statement_block('statements') \
                            + CaselessKeyword("Next").suppress() \
                            + Optional(lex_identifier) \
                            + FollowedBy(EOS)  # NOTE: the statement should NOT include EOS!

simple_for_each_statement.setParseAction(For_Each_Statement)

# --- WHILE statement -----------------------------------------------------------

def _get_guard_variables(loop_obj, context):
    """
    Pull out the variables that appear in the guard expression and their
    values in the context. Return as a dict.
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
        except:
            pass

    # Return the values of the vars in the loop guard.
    return r

class While_Statement(VBA_Object):

    def __init__(self, original_str, location, tokens):
        super(While_Statement, self).__init__(original_str, location, tokens)
        self.loop_type = tokens.clause.type
        self.guard = tokens.clause.guard
        self.body = tokens[2]
        log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        r = "Do " + str(self.loop_type) + " " + str(self.guard) + "\\n"
        r += str(self.body) + "\\nLoop"
        return r

    def _eval_guard(self, curr_counter, final_val, comp_op):
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
        log.error("Loop guard operator '" + str(comp_op) + " cannot be emulated.")
        return False
        
    def _handle_simple_loop(self, context):

        # Handle simple loops used purely for obfuscation.
        #
        # While b52 <= b35
        # b52 = b52 + 1
        # Wend

        # Do we just have 1 or 2 lines in the loop body?
        if ((len(self.body) != 1) and (len(self.body) != 2)):
            return False

        # Are we just sleeping in the loop?
        if ("sleep(" in str(self.body[0]).lower()):
            return True
        
        # Do we have a simple loop guard?
        loop_counter = str(self.guard).strip()
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
        body = str(self.body[0]).replace("Let ", "").replace("(", "").replace(")", "").strip()
        if_block = None
        if_val = None
        if (not body.startswith(var_inc)):

            # We can handle a single if statement and a single loop variable modify statement.
            if (len(self.body) != 2):
                return False
            
            # Are we incrementing the loop counter and doing something if the loop counter
            # is equal to a specific value?
            body = None
            for s in self.body:

                # Modifying the loop variable?
                tmp = str(s).replace("Let ", "").replace("(", "").replace(")", "").strip()
                if (tmp.startswith(var_inc)):
                    body = tmp
                    continue

                # If statement looking for specific value of the loop variable?
                if (isinstance(s, If_Statement)):

                    # Check the loop guard to see if it is 'loop_var = ???'.
                    if_guard = s.pieces[0]["guard"]
                    if_guard_str = str(if_guard).strip()
                    if (if_guard_str.startswith(loop_counter + " = ")):

                        # Pull out the loop counter value we are looking for and
                        # what to run when the counter equals that.
                        if_block = s.pieces[0]["body"]

                        # We can only handle ints for the loop counter value to check for.
                        try:
                            start = if_guard_str.rindex("=") + 1
                            tmp = if_guard_str[start:].strip()
                            if_val = int(str(tmp))
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
        except:
            return False

        # Now just compute the final loop counter value right here in Python.
        curr_counter = coerce_to_int(eval_arg(loop_counter, context=context, treat_as_var_name=True))
        final_val = eval_arg(upper_bound, context=context, treat_as_var_name=True)
        try:
            final_val = int(final_val)
        except:
            return False
        
        # Simple case first. Set the final loop counter value if possible.
        if ((num == 1) and (op == "+")):
            if (comp_op == "<="):
                curr_counter = final_val + 1
            if (comp_op == "<"):
                curr_counter = final_val

        # Now emulate the loop in Python.
        running = self._eval_guard(curr_counter, final_val, comp_op)
        log.debug("Short circuiting loop evaluation: Guard: " + str(self.guard))
        log.debug("Short circuiting loop evaluation: Body: " + str(self.body))
        while (running):
            
            # Update the loop counter.
            log.debug("Short circuiting loop evaluation: Guard: " + str(self.guard))
            log.debug("Short circuiting loop evaluation: Test: " + str(curr_counter) + " " + comp_op + " " + str(final_val))
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
            
    def eval(self, context, params=None):

        if (context.exit_func):
            return
        
        log.debug('WHILE loop: start: ' + str(self))

        # Do not bother running loops with empty bodies.
        if (len(self.body) == 0):
            log.info("WHILE loop: empty body. Skipping.")
            return

        # See if we can short circuit the loop.
        if (self._handle_simple_loop(context)):

            # We short circuited the loop. Done.
            return
        
        # Track that the current loop is running.
        context.loop_stack.append(True)

        # Some loop guards check the readystate value on an object. To simulate this
        # will will just go around the loop a small fixed # of times.
        max_loop_iters = VBA_Object.loop_upper_bound
        if (".readyState" in str(self.guard)):
            log.info("Limiting # of iterations of a .readyState loop.")
            max_loop_iters = 5

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
            
            # Test the loop guard to see if we should exit the loop.
            guard_val = eval_arg(self.guard, context)
            if (self.loop_type.lower() == "until"):
                guard_val = (not guard_val)
            if (not guard_val):
                break
            
            # Execute the loop body.
            done = False
            for s in self.body:
                log.debug('WHILE loop eval statement: %r' % s)
                if (not isinstance(s, VBA_Object)):
                    continue
                s.eval(context=context)

                # Has 'Exit For' been called?
                if (not context.loop_stack[-1]):

                    # Yes we have. Stop this loop.
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
                if (isinstance(s, Goto_Statement)):
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
        context.loop_stack.pop()
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
    def __init__(self, original_str, location, tokens):
        super(Do_Statement, self).__init__(original_str, location, tokens)
        self.loop_type = tokens.type
        self.guard = tokens.guard
        if (self.guard is None):
            self.guard = True
        self.body = tokens[0]
        log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        r = "Do\\n" + str(self.body) + "\\n"
        r += "Loop " + str(self.loop_type) + " " + str(self.guard)
        return r

    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return
        
        log.debug('DO loop: start: ' + str(self))

        # Do not bother running loops with empty bodies.
        if (len(self.body) == 0):
            log.debug("DO loop: empty body. Skipping.")
            return
        
        # Track that the current loop is running.
        context.loop_stack.append(True)

        # Some loop guards check the readystate value on an object. To simulate this
        # will will just go around the loop a small fixed # of times.
        max_loop_iters = VBA_Object.loop_upper_bound
        if (".readyState" in str(self.guard)):
            log.info("Limiting # of iterations of a .readyState loop.")
            max_loop_iters = 5

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
            for s in self.body:
                log.debug('DO loop eval statement: %r' % s)
                if (not isinstance(s, VBA_Object)):
                    continue
                s.eval(context=context)

                # Has 'Exit For' been called?
                if (not context.loop_stack[-1]):

                    # Yes we have. Stop this loop.
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
                if (isinstance(s, Goto_Statement)):
                    log.debug("GOTO executed. Go to next loop iteration.")
                    break
                
            # Finished with the loop due to 'Exit For'?
            if (done):
                break

            # Test the loop guard to see if we should exit the loop.
            guard_val = eval_arg(self.guard, context)
            if (self.loop_type.lower() == "until"):
                guard_val = (not guard_val)
            if (not guard_val):
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
        context.loop_stack.pop()
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
    def __init__(self, original_str, location, tokens):
        super(Select_Statement, self).__init__(original_str, location, tokens)
        self.select_val = tokens.select_val
        self.cases = tokens.cases
        log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        r = ""
        r += str(self.select_val)
        for case in self.cases:
            r += str(case)
        r += "End Select"
        return r

    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return
        
        # Get the current value of the guard expression for the select.
        log.debug("eval select: " + str(self))
        if (not isinstance(self.select_val, VBA_Object)):
            return
        select_guard_val = self.select_val.eval(context, params)

        # Loop through each case, seeing which one applies.
        for case in self.cases:

            # Get the case guard statement.
            case_guard = case.case_val

            # Is this the case we should take?
            log.debug("eval select: checking '" + str(select_guard_val) + " == " + str(case_guard) + "'")
            if (case_guard.eval(context, [select_guard_val])):

                # Evaluate the body of this case.
                log.debug("eval select: take case " + str(case))
                for statement in case.body:

                    # Emulate the statement.
                    if (not isinstance(statement, VBA_Object)):
                        continue
                    statement.eval(context, params)

                    # Was there an error that will make us jump to an error handler?
                    if (context.must_handle_error()):
                        break
                    context.clear_error()

                # Run the error handler if we have one and we broke out of the statement
                # loop with an error.
                context.handle_error(params)
                    
                # Done with the select.
                break

class Select_Clause(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(Select_Clause, self).__init__(original_str, location, tokens)
        self.select_val = tokens.select_val[0]
        log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        r = ""
        r += "Select Case " + str(self.select_val) + "\\n " 
        return r

    def eval(self, context, params=None):
        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return
        if (hasattr(self.select_val, "eval")):
            return self.select_val.eval(context, params)
        else:
            return self.select_val

class Case_Clause_Atomic(VBA_Object):
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
            if (str(v).lower() == "else"):
                self.is_else = True
                break
        log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        r = ""
        if (self.test_range):
            r += str(self.case_val[0]) + " To " + str(self.case_val[1])
        elif (self.test_set):
            first = True
            for val in self.case_val:
                if (not first):
                    r += ", "
                first = False
                r += str(val)
        else:
            r += str(self.case_val[0])
        return r

    def eval(self, context, params=None):
        """
        Evaluate the guard of this case against the given value.
        """

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return
        
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
                start = int_convert(eval_arg(self.case_val[0], context))
                end = int_convert(eval_arg(self.case_val[1], context)) + 1
            except:
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
                except:
                    return False

            # Is the test val in the set?
            return (test_val in expected_vals)

        # We just have a regular test.
        expected_val = eval_arg(self.case_val[0], context)
        return (test_val == expected_val)

class Case_Clause(VBA_Object):

    def __init__(self, original_str, location, tokens):
        super(Case_Clause, self).__init__(original_str, location, tokens)
        self.clauses = []
        for clause in tokens:
            self.clauses.append(clause)
        log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        r = "Case "
        first = True
        for clause in self.clauses:
            if (not first):
                r += ", "
            first = False
            r += str(clause)
        return r

    def eval(self, context, params=None):
        """
        Evaluate the guard of this case against the given value.
        """

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return
        
        # Check each clause.
        for clause in self.clauses:
            guard_val = clause.eval(context, params=params)
            if (guard_val):
                return True
        return False
    
class Select_Case(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(Select_Case, self).__init__(original_str, location, tokens)
        self.case_val = tokens.case_val
        self.body = tokens.body
        log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        r = ""
        r += str(self.case_val) + " " + str(self.body)
        return r

    def eval(self, context, params=None):
        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return
    
select_clause = CaselessKeyword("Select").suppress() + CaselessKeyword("Case").suppress() \
                + expression("select_val")
select_clause.setParseAction(Select_Clause)

case_clause_atomic = ((expression("lbound") + CaselessKeyword("To").suppress() + expression("ubound")) | \
                      (CaselessKeyword("Else")) | \
                      (any_expression("case_val") + ZeroOrMore(Suppress(",") + any_expression)))
case_clause_atomic.setParseAction(Case_Clause_Atomic)

case_clause = CaselessKeyword("Case").suppress() + Suppress(Optional(CaselessKeyword("Is") + Literal('='))) + \
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
    def __init__(self, original_str, location, tokens):
        super(If_Statement, self).__init__(original_str, location, tokens)

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
                log.error('If part %r has wrong # elements.' % str(tok))

        log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def get_children(self):
        """
        Return the child VBA objects of the current object.
        """

        if (self._children is not None):
            return self._children
        self._children = []
        for piece in self.pieces:
            if (isinstance(piece["body"], VBA_Object)):
                self._children.append(piece["body"])
            if ((isinstance(piece["body"], list)) or
                (isinstance(piece["body"], pyparsing.ParseResults))):
                for i in piece["body"]:
                    if (isinstance(i, VBA_Object)):
                        self._children.append(i)
            if (isinstance(piece["body"], dict)):
                for i in piece["body"].values():
                    if (isinstance(i, VBA_Object)):
                        self._children.append(i)
        return self._children
                
    def __repr__(self):
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
                guard = piece["guard"].__repr__()
                if (len(guard) > 5):
                    guard = guard[:6] + "..."
            r += guard + " "
            keyword = "Then "

            # Add in the body.
            r += keyword
            body = piece["body"].__repr__().replace("\n", "; ")
            if (len(body) > 5):
                body = body[:6] + "..."

        return r
            
    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
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
multi_line_if_statement = Group( CaselessKeyword("If").suppress() + boolean_expression + CaselessKeyword("Then").suppress() + Suppress(EOS) + \
                                 Group(statement_block('statements'))) + \
                                 ZeroOrMore(
                                     Group( CaselessKeyword("ElseIf").suppress() + boolean_expression + CaselessKeyword("Then").suppress() + Suppress(EOS) + \
                                            Group(statement_block('statements')))
                                 ) + \
                                 Optional(
                                     Group(CaselessKeyword("Else").suppress() + Group(simple_statements_line('statements'))) + Suppress(EOS) | \
                                     Group(CaselessKeyword("Else").suppress() + Suppress(EOS) + Group(statement_block('statements')))
                                 ) + \
                                 CaselessKeyword("End").suppress() + CaselessKeyword("If").suppress()
bad_if_statement = Group( CaselessKeyword("If").suppress() + boolean_expression + CaselessKeyword("Then").suppress() + Suppress(EOS) + \
                          Group(statement_block('statements'))) + \
                          ZeroOrMore(
                              Group( CaselessKeyword("ElseIf").suppress() + boolean_expression + CaselessKeyword("Then").suppress() + Suppress(EOS) + \
                                     Group(statement_block('statements')))
                          ) + \
                          Optional(
                              Group(CaselessKeyword("Else").suppress() + Suppress(EOS) + \
                                    Group(statement_block('statements')))
                          )

single_line_if_statement = Group( CaselessKeyword("If").suppress() + boolean_expression + CaselessKeyword("Then").suppress() + \
                                  Group(simple_statements_line('statements')) )  + \
                                  ZeroOrMore(
                                      Group( CaselessKeyword("ElseIf").suppress() + boolean_expression + CaselessKeyword("Then").suppress() + \
                                             Group(simple_statements_line('statements')))
                                  ) + \
                                  Optional(
                                      Group(CaselessKeyword("Else").suppress() + \
                                            Group(simple_statements_line('statements')))
                                  ) + Suppress(Optional(CaselessKeyword("End") + CaselessKeyword("If")))
simple_if_statement = multi_line_if_statement ^ single_line_if_statement

simple_if_statement.setParseAction(If_Statement)

# --- IF-THEN-ELSE statement, macro version ----------------------------------------------------------

class If_Statement_Macro(If_Statement):

    def __init__(self, original_str, location, tokens):
        super(If_Statement_Macro, self).__init__(original_str, location, tokens)
        self.external_functions = {}
        for piece in self.pieces:
            for token in piece["body"]:
                if isinstance(token, External_Function):
                    log.debug("saving VBA macro external func decl: %r" % token.name)
                    self.external_functions[token.name] = token

    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return
        
        # TODO: Properly evaluating this will involve supporting compile time variables
        # that can be set via options when running ViperMonkey. For now just run the then
        # block.
        log.debug("eval: " + str(self))
        then_part = self.pieces[0]
        for stmt in then_part["body"]:
            if (isinstance(stmt, VBA_Object)):
                stmt.eval(context)

# Grammar element for #IF statements.
simple_if_statement_macro = Group( CaselessKeyword("#If").suppress() + boolean_expression + CaselessKeyword("Then").suppress() + Suppress(EOS) + \
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

    # List of interesting functions to log calls to.
    log_funcs = ["CreateProcessA", "CreateProcessW", ".run", "CreateObject",
                 "Open", ".Open", "GetObject", "Create", ".Create", "Environ",
                 "CreateTextFile", ".CreateTextFile", ".Eval", "Run",
                 "SetExpandedStringValue", "WinExec", "FileCopy", "Load"]
    
    def __init__(self, original_str, location, tokens):
        super(Call_Statement, self).__init__(original_str, location, tokens)
        self.name = tokens.name
        if (str(self.name).endswith("@")):
            self.name = str(self.name).replace("@", "")
        if (str(self.name).endswith("!")):
            self.name = str(self.name).replace("!", "")
        if (str(self.name).endswith("#")):
            self.name = str(self.name).replace("#", "")
        if (str(self.name).endswith("%")):
            self.name = str(self.name).replace("%", "")
        self.params = tokens.params
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Call_Statement: %s(%r)' % (self.name, self.params)

    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return

        # Save the unresolved argument values.
        import vba_library
        vba_library.var_names = self.params
        
        # Reset the called function name if this is an alias for an imported external
        # DLL function.
        dll_func_name = context.get_true_name(self.name)
        if (dll_func_name is not None):
            self.name = dll_func_name

        # Are we calling a member access expression?
        if isinstance(self.name, MemberAccessExpression):
            # If we have parameters, then we must have an error
            # because the MemberAccessExpression is going to ignore them.
            assert not self.params, 'Unexpected parameters. Parsing has failed.'
            # Just evaluate the expression as the call.
            log.debug("Call of member access expression " + str(self.name))
            return self.name.eval(context, self.params)

        # TODO: The following should share the same code as MemberAccessExpression and Function_Call?

        # Get argument values.
        log.debug("Call: eval params: " + str(self.params))
        call_params = eval_args(self.params, context=context)
        str_params = repr(call_params)
        if (len(str_params) > 80):
            str_params = str_params[:80] + "..."

        # Would Visual Basic have thrown an error when evaluating the arguments?
        if (context.have_error()):
            log.warn('Short circuiting function call %s(%s) due to thrown VB error.' % (self.name, str_params))
            return None

        # Log functions of interest.
        log.info('Calling Procedure: %s(%r)' % (self.name, str_params))
        if self.name.lower() in context._log_funcs \
                or any(self.name.lower().endswith(func.lower()) for func in Function_Call.log_funcs):
            context.report_action(self.name, call_params, 'Interesting Function Call', strip_null_bytes=True)
        
        # Handle VBA functions:
        func_name = str(self.name)
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
            if ((func_name != "Debug.Print") and
                (not func_name.endswith("Add")) and
                (not func_name.endswith("Write")) and
                (len(tmp_call_params) > 0)):
                context.report_action('Object.Method Call', tmp_call_params, func_name, strip_null_bytes=True)
        try:

            # Emulate the function body.
            s = context.get(func_name)
            if (s is None):
                raise KeyError("func not found")
            if (hasattr(s, "eval")):
                ret = s.eval(context=context, params=call_params)

                # Set the values of the arguments passed as ByRef parameters.
                if (hasattr(s, "byref_params") and s.byref_params):
                    for byref_param_info in s.byref_params.keys():
                        arg_var_name = str(self.params[byref_param_info[1]])
                        context.set(arg_var_name, s.byref_params[byref_param_info])
                return ret
            
        except KeyError:
            try:
                tmp_name = func_name.replace("$", "").replace("VBA.", "").replace("Math.", "").\
                           replace("[", "").replace("]", "").replace("'", "").replace('"', '')
                if ("." in tmp_name):
                    tmp_name = tmp_name[tmp_name.rindex(".") + 1:]
                log.debug("Looking for procedure %r" % tmp_name)
                s = context.get(tmp_name)
                log.debug("Found procedure " + tmp_name + " = " + str(s))
                if (s):
                    log.debug("Found procedure. Running procedure " + tmp_name)
                    s.eval(context=context, params=call_params)
            except KeyError:

                # If something like Application.Run("foo", 12) is called, foo(12) will be run.
                # Try to handle that.
                log.debug("Did not find procedure.")
                if ((func_name == "Application.Run") or (func_name == "Run")):

                    # Pull the name of what is being run from the 1st arg.
                    new_func = call_params[0]

                    # The remaining params are passed as arguments to the other function.
                    new_params = call_params[1:]

                    # See if we can run the other function.
                    log.debug("Try indirect run of function '" + new_func + "'")
                    try:
                        s = context.get(new_func)
                        return s.eval(context=context, params=new_params)
                    except KeyError:
                        pass
                log.error('Procedure %r not found' % func_name)
            except Exception as e:
                traceback.print_exc(file=sys.stdout)
                log.debug("General error: " + str(e))
                return

# 5.4.2.1 Call Statement
# a call statement is similar to a function call, except it is a statement on its own, not part of an expression
# call statement params may be surrounded by parentheses or not
call_params = (
    (Suppress('(') + Optional(expr_list('params')) + Suppress(')'))
    ^ (White(" \t") + expr_list('params'))
)
call_statement0 = NotAny(known_keywords_statement_start) + \
                  Optional(CaselessKeyword('Call').suppress()) + \
                  (member_access_expression('name') | TODO_identifier_or_object_attrib_loose('name')) + \
                  Suppress(Optional(NotAny(White()) + '$') + \
                           Optional(NotAny(White()) + '#') + \
                           Optional(NotAny(White()) + '@') + \
                           Optional(NotAny(White()) + '%') + \
                           Optional(NotAny(White()) + '!')) + \
                           Optional(call_params) + \
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
call_statement0.setParseAction(Call_Statement)
call_statement1.setParseAction(Call_Statement)

call_statement = (call_statement0 ^ call_statement1)

# --- EXIT FOR statement ----------------------------------------------------------

class Exit_For_Statement(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(Exit_For_Statement, self).__init__(original_str, location, tokens)
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Exit For'

    def eval(self, context, params=None):
        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return
        # Update the loop stack to indicate that the current loop should exit.
        context.loop_stack.pop()
        context.loop_stack.append(False)

class Exit_While_Statement(Exit_For_Statement):
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
    def __init__(self, original_str, location, tokens):
        super(Exit_Function_Statement, self).__init__(original_str, location, tokens)
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Exit Function'

    def eval(self, context, params=None):
        # Mark that we should return from the current function.
        context.exit_func = True

# Return from a function.
exit_func_statement = (CaselessKeyword('Exit').suppress() + CaselessKeyword('Function').suppress()) | \
                      (CaselessKeyword('Exit').suppress() + CaselessKeyword('Sub').suppress()) | \
                      (CaselessKeyword('Return').suppress()) | \
                      ((CaselessKeyword('End').suppress()) + ~CaselessKeyword("Function"))
exit_func_statement.setParseAction(Exit_Function_Statement)

# --- REDIM statement ----------------------------------------------------------

class Redim_Statement(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(Redim_Statement, self).__init__(original_str, location, tokens)
        self.item = str(tokens.item)
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'ReDim ' + str(self.item)

    def eval(self, context, params=None):

        # Is this a Variant type?
        if (str(context.get_type(self.item)) == "Variant"):

            # Variant types cannot hold string values, so assume that the variable
            # should hold an array.
            context.set(self.item, [])
            
        return

# Array redim statement
redim_statement = CaselessKeyword('ReDim').suppress() + \
                  Optional(CaselessKeyword('Preserve')) + \
                  expression('item') + \
                  Optional('(' + expression + CaselessKeyword('To') + expression + \
                           ZeroOrMore("," + expression + CaselessKeyword('To') + expression) + \
                           ')').suppress() + \
                  Optional(CaselessKeyword('As') + lex_identifier).suppress()
redim_statement.setParseAction(Redim_Statement)

# --- WITH statement ----------------------------------------------------------

class With_Statement(VBA_Object):

    def __init__(self, original_str, location, tokens):
        super(With_Statement, self).__init__(original_str, location, tokens)
        log.debug("tokens = " + str(tokens))
        self.body = tokens[1]
        self.env = tokens.env
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'With ' + str(self.env) + "\\n" + str(self.body) + " End With"

    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return

        # Evaluate the with prefix value. This calls any functions that appear in the
        # with prefix.
        prefix_val = eval_arg(self.env, context)

        # Track the with prefix.
        if (len(context.with_prefix) > 0):
            context.with_prefix += "." + str(self.env)
            #context.with_prefix += "." + str(prefix_val)
        else:
            context.with_prefix = str(prefix_val)
        if (context.with_prefix.startswith(".")):
            context.with_prefix = context.with_prefix[1:]
            
        # Evaluate each statement in the with block.
        log.debug("START WITH")
        try:
            tmp1 = iter(self.body)
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
            if (isinstance(s, Goto_Statement)):
                log.debug("GOTO executed. Go to next loop iteration.")
                break
            
        log.debug("END WITH")
            
        # Remove the current with prefix.
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
with_statement = CaselessKeyword('With').suppress() + (member_access_expression('env') ^ \
                                                       (Optional(".") + (lex_identifier('env') ^ function_call_limited('env')))) + Suppress(EOS) + \
                 Group(statement_block('body')) + \
                 CaselessKeyword('End').suppress() + CaselessKeyword('With').suppress()
with_statement.setParseAction(With_Statement)

# --- GOTO statement ----------------------------------------------------------

class Goto_Statement(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(Goto_Statement, self).__init__(original_str, location, tokens)
        self.label = tokens.label
        log.debug('parsed %r as Goto_Statement' % self)

    def __repr__(self):
        return 'Goto ' + str(self.label)

    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return
        
        # Do we know the code block associated with the GOTO label?
        if (self.label not in context.tagged_blocks):

            # We don't know where to go. Punt.
            log.error("GOTO target " + str(self.label) + " is unknown.")
            return

        # We know where to go. Get the code block to execute.
        block = context.tagged_blocks[self.label]

        # Execute the code block.
        log.info("GOTO " + str(self.label))
        block.eval(context, params)

# Goto statement
goto_statement = CaselessKeyword('Goto').suppress() + lex_identifier('label')
goto_statement.setParseAction(Goto_Statement)

# --- GOTO LABEL statement ----------------------------------------------------------

class Label_Statement(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(Label_Statement, self).__init__(original_str, location, tokens)
        self.label = tokens.label
        log.debug('parsed %r as Label_Statement' % self)

    def __repr__(self):
        return str(self.label) + ':'

    def eval(self, context, params=None):
        # Currently stubbed out.
        return

# Goto label statement
label_statement <<= identifier('label') + Suppress(':')
label_statement.setParseAction(Label_Statement)

# --- ON ERROR STATEMENT -------------------------------------------------------------

class On_Error_Statement(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(On_Error_Statement, self).__init__(original_str, location, tokens)
        self.tokens = tokens
        self.label = None
        if ((len(tokens) == 4) and (tokens[2].lower() == "goto")):
            self.label = str(tokens[3])
        log.debug('parsed %r as On_Error_Statement' % self)

    def __repr__(self):
        return str(self.tokens)

    def eval(self, context, params=None):

        # Do we have a goto error handler?
        if (self.label is not None):

            # Do we have a labeled block that matches the error handler block?
            if (self.label in context.tagged_blocks):

                 # Set the error handler in the context.
                context.error_handler = context.tagged_blocks[self.label]
                log.debug("Setting On Error handler block to '" + self.label + "'.")

            # Can't find error handler block.
            else:
                log.warning("Cannot find error handler block '" + self.label + "'.")

        return

on_error_statement = CaselessKeyword('On') + Optional(Suppress(CaselessKeyword('Local'))) + CaselessKeyword('Error') + \
                     ((CaselessKeyword('Goto') + (decimal_literal | lex_identifier)) |
                      (CaselessKeyword('Resume') + CaselessKeyword('Next')))

on_error_statement.setParseAction(On_Error_Statement)

# --- RESUME STATEMENT -------------------------------------------------------------

resume_statement = CaselessKeyword('Resume') + Optional(lex_identifier)

# --- FILE OPEN -------------------------------------------------------------

class File_Open(VBA_Object):
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
        log.debug('parsed %r as File_Open' % self)

    def __repr__(self):
        r = "Open " + str(self.file_name) + " For " + str(self.file_mode)
        if (self.file_access is not None):
            r += " Access " + str(self.file_access)
        r += " As " + str(self.file_id)
        return r

    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return
        
        # Get the file name.

        # Might be an expression.
        name = eval_arg(self.file_name, context=context)
        try:
            # Could be a variable.
            name = context.get(self.file_name)
        except KeyError:
            pass
        except AssertionError:
            pass

        # Store file id variable in context.
        if self.file_id:
            file_id = str(self.file_id)
            if not file_id.startswith('#'):
                file_id = '#' + file_id
            context.set(file_id, name)

        # Save that the file is opened.
        context.report_action("OPEN", str(name), 'Open File', strip_null_bytes=True)
        context.open_file(name)


file_type = (
    Suppress(CaselessKeyword("For"))
    + (
        CaselessKeyword("Append")
        | CaselessKeyword("Binary")
        | CaselessKeyword("Input")
        | CaselessKeyword("Output")
        | CaselessKeyword("Random")
    )("mode")
    + Suppress(Optional(CaselessKeyword("Lock")))
    + Optional(
        Suppress(CaselessKeyword("Access"))
        + (
            CaselessKeyword("Read Write")
            ^ CaselessKeyword("Read")
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
        + (file_pointer("file_id") | TODO_identifier_or_object_attrib("file_id"))
    )
)
file_open_statement.setParseAction(File_Open)

# --- PRINT -------------------------------------------------------------

class Print_Statement(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(Print_Statement, self).__init__(original_str, location, tokens)
        self.file_id = tokens.file_id
        self.value = tokens.value
        # TODO: Actually write the ';' values to the file.
        self.more_values = tokens.more_values
        log.debug('parsed %r as Print_Statement' % self)

    def __repr__(self):
        r = "Print " + str(self.file_id) + ", " + str(self.value)
        return r

    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
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
        context.write_file(file_id, '\r\n')


print_statement = Suppress(CaselessKeyword("Print")) + file_pointer("file_id") + Suppress(Optional(",")) + expression("value") + \
                  ZeroOrMore(Suppress(Literal(';')) + expression)("more_values") + Suppress(Optional("," + lex_identifier))
print_statement.setParseAction(Print_Statement)

# --- DOEVENTS STATEMENT -------------------------------------------------------------

doevents_statement = Suppress(CaselessKeyword("DoEvents"))

# --- STATEMENTS -------------------------------------------------------------

# simple statement: fits on a single line (excluding for/if/do/etc blocks)
#simple_statement = dim_statement | option_statement | (prop_assign_statement ^ expression ^ (let_statement | call_statement) ^ label_statement) | exit_loop_statement | \
#                   exit_func_statement | redim_statement | goto_statement | on_error_statement | file_open_statement | doevents_statement | \
#                   rem_statement | print_statement | resume_statement
simple_statement = (
    NotAny(Regex(r"End\s+Sub"))
    + (
        print_statement
        | dim_statement
        | option_statement
        | (
            prop_assign_statement
            ^ (let_statement | call_statement)
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
    )
)

simple_statements_line <<= (
   (simple_statement + OneOrMore(Suppress(':') + simple_statement))
   ^ simple_statement
)

statements_line = (
    tagged_block
    ^ (Optional(statement + ZeroOrMore(Suppress(':') + statement)) + EOS.suppress())
)

# --- EXTERNAL FUNCTION ------------------------------------------------------

class External_Function(VBA_Object):
    """
    External Function from a DLL
    """

    file_count = 0
    def _createfile(self, params, context):

        # Get a name for the file.
        fname = None
        if ((params[0] is not None) and (len(params[0]) > 0)):
            fname = "#" + str(params[0])
        else:
            External_Function.file_count += 1
            fname = "#SOME_FILE_" + str(External_Function.file_count)

        # Save that the file is opened.
        context.open_file(fname)

        # Return the name of the "file".
        return fname

    def _writefile(self, params, context):

        # Simulate the write.
        file_id = params[0]

        # Make sure the file exists.
        if (file_id not in context.open_files):
            log.error("File " + str(file_id) + " not open. Cannot write.")
            return 1
        
        # We can only write single byte values for now.
        data = params[1]
        if (not isinstance(data, int)):
            log.error("Cannot WriteFile() data that is not int.")
            return 0
        context.write_file(file_id, chr(data))
        return 0

    def _closehandle(self, params, context):

        # Simulate the file close.
        file_id = params[0]
        context.close_file(file_id)
        return 0
    
    def __init__(self, original_str, location, tokens):
        super(External_Function, self).__init__(original_str, location, tokens)
        self.name = str(tokens.function_name)
        self.params = tokens.params
        self.lib_name = str(tokens.lib_info.lib_name)
        # normalize lib name: remove quotes, lowercase, add .dll if no extension
        if isinstance(self.lib_name, basestring):
            self.lib_name = str(tokens.lib_name).strip('"').lower()
            if '.' not in self.lib_name:
                self.lib_name += '.dll'
        self.lib_name = str(self.lib_name)
        self.alias_name = str(tokens.lib_info.alias_name)
        if isinstance(self.alias_name, basestring):
            # TODO: this might not be necessary if alias is parsed as quoted string
            self.alias_name = self.alias_name.strip('"')
        if (len(self.alias_name.strip()) == 0):
            self.alias_name = self.name
        self.return_type = tokens.return_type
        self.vars = {}
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'External Function %s (%s) from %s alias %s' % (self.name, self.params, self.lib_name, self.alias_name)

    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return
        
        # create a new context for this execution:
        caller_context = context
        context = Context(context=caller_context)
        if self.alias_name:
            function_name = self.alias_name
        else:
            function_name = self.name
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
                cmd = str(params[2]) + " " + str(params[3])
            else:
                cmd = str(params[1]) + " " + str(params[2])
            context.report_action('Run Command', cmd, function_name, strip_null_bytes=True)
            # return 0 when no error occurred:
            return 0
        else:
            call_str = str(self.alias_name) + "(" + str(params) + ")"
            call_str = call_str.replace('\x00', "")
            context.report_action('External Call', call_str, str(self.lib_name) + " / " + str(self.alias_name))
        
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
            log.debug("External function " + str(function_name) + " returns " + str(r))
            return r
        except KeyError:
            pass
        
        # TODO: return result according to the known DLLs and functions
        log.warning('Unknown external function %s from DLL %s' % (function_name, self.lib_name))
        return 0

function_type2 = CaselessKeyword('As').suppress() + lex_identifier('return_type') \
                 + Optional(Literal('(') + Literal(')')).suppress()

public_private <<= Optional(CaselessKeyword('Public') | CaselessKeyword('Private') | CaselessKeyword('Global')).suppress() + \
                   Optional(CaselessKeyword('WithEvents')).suppress()

params_list_paren = Suppress('(') + Optional(parameters_list('params')) + Suppress(')')

# 5.2.3.5 External Procedure Declaration
lib_info = CaselessKeyword('Lib').suppress() + quoted_string('lib_name') \
           + Optional(CaselessKeyword('Alias') + quoted_string('alias_name'))

# TODO: identifier or lex_identifier
external_function <<= public_private + Suppress(CaselessKeyword('Declare') + Optional(CaselessKeyword('PtrSafe')) + \
                                                (CaselessKeyword('Function') | CaselessKeyword('Sub'))) + \
                                                lex_identifier('function_name') + lib_info('lib_info') + Optional(params_list_paren) + Optional(function_type2)
external_function.setParseAction(External_Function)

# --- TRY/CATCH STATEMENT ------------------------------------------------------

class TryCatch(VBA_Object):
    """
    Try/Catch exception handling statement.
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
        log.debug('parsed %r' % self)

    def __repr__(self):
        return "Try::" + str(self.try_block) + "::Catch " + str(self.except_var) + " As Exception::" + str(self.catch_block) + "::End Try"

    def eval(self, context, params=None):

        # Treat the catch block like an onerror goto block. To do this locally override the current error
        # handler block.
        old_handler = context.get_error_handler()
        context.error_handler = self.catch_block

        # Evaluate the try block.
        self.try_block.eval(context)

        # Reset the error handler block.
        context.error_handler = old_handler

try_catch = Suppress(CaselessKeyword('Try')) + Suppress(EOS) + statement_block('try_block') + \
            Suppress(CaselessKeyword('Catch')) + lex_identifier('exception_var') + Suppress(CaselessKeyword('As')) + Suppress(CaselessKeyword('Exception')) + \
            Suppress(EOS) + statement_block('catch_block') + Suppress(CaselessKeyword('End')) + Suppress(CaselessKeyword('Try'))
try_catch.setParseAction(TryCatch)

# WARNING: This is a NASTY hack to handle a cyclic import problem between procedures and
# statements. To allow local function/sub definitions the grammar elements from procedure are
# needed here in statements. But, procedures also needs the grammar elements defined here in
# statements. Just placing the statement grammar definition in this file like normal leads
# to a Python import error. To get around this the statement grammar element is being actually
# set in extend_statement_grammar(). extend_statement_grammar() is called at the end of
# procedures.py, so when all of the elements in procedures.py have actually beed defined the
# statement grammar element can be safely set.
def extend_statement_grammar():

    # statement has to be declared beforehand using Forward(), so here we use
    # the "<<=" operator:
    global statement
    statement <<= try_catch | type_declaration | name_as_statement | simple_for_statement | simple_for_each_statement | simple_if_statement | \
                  simple_if_statement_macro | simple_while_statement | simple_do_statement | simple_select_statement | \
                  with_statement| simple_statement | rem_statement | procedures.simple_function | procedures.simple_sub

