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

# ViperMonkey is copyright (c) 2015-2018 Philippe Lagadec (http://www.decalage.info)
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

__version__ = '0.06'

# --- IMPORTS ------------------------------------------------------------------

from comments_eol import *
from expressions import *
from vba_context import *
from reserved import *
from from_unicode_str import *
from vba_object import int_convert

from logger import log
import sys
import re

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

type_declaration_composite = (CaselessKeyword('Public') | CaselessKeyword('Private')) + CaselessKeyword('Type') + \
                             lex_identifier + Suppress(EOS) + \
                             OneOrMore(lex_identifier + CaselessKeyword('As') + reserved_type_identifier + Suppress(EOS)) + \
                             CaselessKeyword('End') + CaselessKeyword('Type')

# TODO: Add in simple type declarations.
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
        self.block = tokens.block
        self.label = str(tokens.label).replace(":", "")
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Tagged Block: %s: %s' % (repr(self.label), repr(self.block))

    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return
        for curr_statement in self.block:
            curr_statement.eval(context, params=params)

tagged_block = Forward()
label_statement = Forward()
        
# need to declare statement beforehand:
statement = Forward()
external_function = Forward()

# NOTE: statements should NOT include EOS
block_statement = rem_statement | external_function | statement
# tagged_block broken out so it does not consume the final EOS in the statement block.
statement_block = ZeroOrMore(tagged_block ^ (block_statement + EOS.suppress()))
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
            if ((len(var) > 1) and (var[1] == '(')):
                is_array = True

            # Do we have a type for the variable?
            curr_type = None
            if ((len(var) > 1) and (var[-1:][0] != ")")):
                curr_type = var[-1:][0]

            # Save the variable info.
            self.variables.append((var[0], is_array, curr_type))

        # Handle multiple variables declared with the same type.
        tmp_vars = []
        final_type = self.variables[len(self.variables) - 1][2]
        for var in self.variables:
            curr_type = var[2]
            if (curr_type is None):
                curr_type = final_type
            tmp_vars.append((var[0], var[1], curr_type))
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
                r += "()"
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
                
                # Is this variable an array?
                if (var[1]):
                    curr_type += " Array"
                    curr_init_val = []

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
array_dim = '(' + Optional(bounds_list).suppress() + ')'
constant_name = simple_name_expression
string_length = constant_name | integer
fixed_length_string_spec = CaselessKeyword("string").suppress() + Suppress("*") + string_length
type_spec = fixed_length_string_spec | type_expression
as_type = CaselessKeyword('as').suppress() + type_spec
defined_type_expression = simple_name_expression  # TODO: | member_access_expression
class_type_name = defined_type_expression
as_auto_object = CaselessKeyword('as').suppress() + CaselessKeyword('new').suppress() + class_type_name
as_clause = as_auto_object | as_type
array_clause = array_dim + Optional(as_clause)
untyped_variable_dcl = identifier + Optional(array_clause | as_clause)
typed_variable_dcl = typed_name + Optional(array_dim)
# TODO: Set the initial value of the global var in the context.
variable_dcl = (typed_variable_dcl | untyped_variable_dcl) + Optional('=' + expression('expression'))
variable_declaration_list = delimitedList(Group(variable_dcl))
local_variable_declaration = Suppress(CaselessKeyword("Dim") | CaselessKeyword("Static") | CaselessKeyword("Const")) + Optional(CaselessKeyword("Shared")).suppress() + variable_declaration_list

dim_statement = local_variable_declaration
dim_statement.setParseAction(Dim_Statement)

# --- Global_Var_Statement statement ----------------------------------------------------------

class Global_Var_Statement(VBA_Object):
    """
    Dim statement
    """

    def __init__(self, original_str, location, tokens):
        super(Global_Var_Statement, self).__init__(original_str, location, tokens)
        self.name = tokens[0][0]
        self.value = ''
        if (len(tokens[0]) >= 3):
            self.value = tokens[0][len(tokens[0]) - 1]
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Global %r' % repr(self.tokens)

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
        self.expression = tokens.expression
        self.index = None
        if (tokens.index != ''):
            self.index = tokens.index
        log.debug('parsed %r' % self)

    def __repr__(self):
        if (self.index is None):
            return 'Let %s = %r' % (self.name, self.expression)
        else:
            return 'Let %s(%r) = %r' % (self.name, self.index, self.expression)

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
            if (is_procedure(callback)):

                # Yes it is. Run it.
                log.info("Running change callback " + callback_name)
                callback.eval(context)

        except KeyError:

            # No callback.
            pass
        
    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        if (context.exit_func):
            return
        
        # evaluate value of right operand:
        log.debug('try eval expression: %s' % self.expression)
        value = eval_arg(self.expression, context=context)
        log.debug('eval expression: %s = %s' % (self.expression, value))

        # set variable, non-array access.
        if (self.index is None):

            # Handle conversion of strings to byte arrays, if needed.
            if ((context.get_type(self.name) == "Byte Array") and
                (isinstance(value, str))):

                # Do we have an actual value to assign?
                if (value != "NULL"):
                    tmp = []
                    for c in value:
                        tmp.append(ord(c))
                        # TODO: Figure out how VBA figures out if this is a wide string (0 padding added)
                        # or not (no padding).
                        if (not isinstance(value, from_unicode_str)):
                            tmp.append(0)
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
                        while (pos < len(value)):
                            tmp += chr(value[pos])
                            pos += 2
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

        # set variable, array access.
        else:

            # Evaluate the index expression.
            index = int_convert(eval_arg(self.index, context=context))
            log.debug('setting %s(%r) = %s' % (self.name, index, value))

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

let_statement = Optional(CaselessKeyword('Let') | CaselessKeyword('Set')).suppress() + \
                Optional(Suppress(CaselessKeyword('Const'))) + \
                ((TODO_identifier_or_object_attrib('name') + Optional(Suppress('(') + Optional(expression('index')) + Suppress(')'))) ^ \
                 member_access_expression('name')) + \
                Literal('=').suppress() + \
                (expression('expression') ^ boolean_expression('expression'))
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

prop_assign_statement = ((member_access_expression("prop") ^ (Suppress(".") + lex_identifier("prop")))+ \
                         lex_identifier('param') + Suppress(':=') + expression('value') + \
                         ZeroOrMore(',' + lex_identifier('param') + Suppress(':=') + expression('value')))
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

    def _handle_simple_loop(self, context, start, end, step):

        # Handle simple loops used purely for obfuscation.
        #
        # For vPHpqvZhLlFhzUmTfwXoRrfZRjfRu = 1 To 833127186
        # vPHpqvZhLlFhzUmTfwXoRrfZRjfRu = vPHpqvZhLlFhzUmTfwXoRrfZRjfRu + 1
        # Next

        # Do we just have 1 line in the loop body?
        if (len(self.statements) != 1):
            return (None, None)

        # Are we just modifying the loop counter variable each loop iteration?
        var_inc = str(self.name) + " = " + str(self.name)
        body = str(self.statements[0]).replace("Let ", "").replace("(", "").replace(")", "").strip()
        if (not body.startswith(var_inc)):
            return (None, None)

        # We are just modifying the loop variable each time. Figure out the final
        # iteration value.
        if (" " not in body):
            return (None, None)
        body = body.replace(var_inc, "").strip()
        op = body[:body.index(" ")]
        num = body[body.index(" ") + 1:]
        try:
            num = int(num)
        except:
            return (None, None)
        if (op == "+"):
            return (self.name, end + num)
        if (op == "-"):
            return (self.name, end - num)
        if (op == "*"):
            return (self.name, end * num)
        return (None, None)
    
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
                pass
        log.debug('FOR loop - start: %r = %r' % (self.start_value, start))

        # Get the end index. If this is a string, convert to an int.
        end = eval_arg(self.end_value, context=context)
        if (isinstance(end, basestring)):
            try:
                end = int(end)
            except:
                pass
        if (not isinstance(end, int)):
            end = 0
        log.debug('FOR loop - end: %r = %r' % (self.end_value, end))

        # Set start and end to valid values.
        if ((VBA_Object.loop_upper_bound > 0) and (end > VBA_Object.loop_upper_bound)):
            end = VBA_Object.loop_upper_bound
            log.debug("FOR loop: upper loop iteration bound exceeded, setting to %r" % end)
        if self.step_value != 1:
            step = eval_arg(self.step_value, context=context)
            log.debug('FOR loop - step: %r = %r' % (self.step_value, step))
        else:
            step = 1

        # See if we have a simple style loop put in purely for obfuscation.
        var, val = self._handle_simple_loop(context, start, end, step)
        if ((var is not None) and (val is not None)):
            log.info("Short circuited loop. Set " + str(var) + " = " + str(val))
            context.set(var, val)
            return
            
        # Track that the current loop is running.
        context.loop_stack.append(True)

        # Set the loop index variable to the start value.
        context.set(self.name, start)

        # Loop until the loop is broken out of or we hit the last index.
        while (context.get(self.name) <= end):

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

            # Finished with the loop due to 'Exit For'?
            if (done):
                break

            # Increment the loop counter by the step.
            val = context.get(self.name)
            context.set(self.name, val + step)
        
        # Remove tracking of this loop.
        context.loop_stack.pop()
        log.debug('FOR loop: end.')

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

                # Finished with the loop due to 'Exit For'?
                if (done):
                    break

        except:

            # The data type for the container may not be iterable. Do nothing.
            pass
        
        # Remove tracking of this loop.
        context.loop_stack.pop()
        log.debug('FOR EACH loop: end.')

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

        # Do we just have 1 line in the loop body?
        if (len(self.body) != 1):
            return False

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
        if (not body.startswith(var_inc)):
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

        # Update the loop counter in the context.
        context.set(loop_counter, curr_counter)

        # We short circuited the loop evaluation.
        return True
    
    def eval(self, context, params=None):

        if (context.exit_func):
            return
        
        log.debug('WHILE loop: start: ' + str(self))

        # Do not bother running loops with empty bodies.
        if (len(self.body) == 0):
            log.debug("WHILE loop: empty body. Skipping.")
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
        
        # Loop until the loop is broken out of or we violate the loop guard.
        num_iters = 0
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

            # Finished with the loop due to 'Exit For'?
            if (done):
                break
        
        # Remove tracking of this loop.
        context.loop_stack.pop()
        log.debug('WHILE loop: end.')

while_type = CaselessKeyword("While") | CaselessKeyword("Until")
        
while_clause = Optional(CaselessKeyword("Do").suppress()) + while_type("type") + boolean_expression("guard")

simple_while_statement = while_clause("clause") + Suppress(EOS) + Group(statement_block('body')) \
                       + (CaselessKeyword("Loop").suppress() | CaselessKeyword("Wend").suppress())

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
        
        # Loop until the loop is broken out of or we violate the loop guard.
        num_iters = 0
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

            # Finished with the loop due to 'Exit For'?
            if (done):
                break

            # Test the loop guard to see if we should exit the loop.
            guard_val = eval_arg(self.guard, context)
            if (self.loop_type.lower() == "until"):
                guard_val = (not guard_val)
            if (not guard_val):
                break
            
        # Remove tracking of this loop.
        context.loop_stack.pop()
        log.debug('DO loop: end.')

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
                    if (not isinstance(statement, VBA_Object)):
                        continue
                    statement.eval(context, params)

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
        r += str(self.case_val) + str(self.body)
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
                      (expression("case_val") + ZeroOrMore(Suppress(",") + expression)))
case_clause_atomic.setParseAction(Case_Clause_Atomic)

case_clause = CaselessKeyword("Case").suppress() + case_clause_atomic + ZeroOrMore(Suppress(",") + case_clause_atomic)
case_clause.setParseAction(Case_Clause)

select_case = case_clause("case_val") + Suppress(EOS) + Group(statement_block('statements'))("body")
select_case.setParseAction(Select_Case)

simple_select_statement = select_clause("select_val") + Suppress(EOS) + Group(OneOrMore(select_case))("cases") \
                          + CaselessKeyword("End").suppress() + CaselessKeyword("Select").suppress()
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
                                     Group(CaselessKeyword("Else").suppress() + Suppress(EOS) + \
                                           Group(statement_block('statements')))
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
simple_statements_line = Forward()
single_line_if_statement = Group( CaselessKeyword("If").suppress() + boolean_expression + CaselessKeyword("Then").suppress() + \
                                  Group(simple_statements_line('statements')) )  + \
                                  ZeroOrMore(
                                      Group( CaselessKeyword("ElseIf").suppress() + boolean_expression + CaselessKeyword("Then").suppress() + \
                                             Group(simple_statements_line('statements')))
                                  ) + \
                                  Optional(
                                      Group(CaselessKeyword("Else").suppress() + \
                                            Group(simple_statements_line('statements')))
                                  )
simple_if_statement = multi_line_if_statement ^ single_line_if_statement

simple_if_statement.setParseAction(If_Statement)

# --- IF-THEN-ELSE statement, macro version ----------------------------------------------------------

class If_Statement_Macro(If_Statement):

    def __init__(self, original_str, location, tokens):
        super(If_Statement_Macro, self).__init__(original_str, location, tokens)
        pass

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
                 "CreateTextFile", ".CreateTextFile", "Eval", ".Eval", "Run",
                 "SetExpandedStringValue", "WinExec"]
    
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
        
        # Get argument values.
        call_params = eval_args(self.params, context=context)
        str_params = repr(call_params)
        if (len(str_params) > 80):
            str_params = str_params[:80] + "..."
        log.info('Calling Procedure: %s(%r)' % (self.name, str_params))

        # Log functions of interest.
        save = False
        for func in Function_Call.log_funcs:
            if (str(self.name).lower().endswith(func.lower())):
                save = True
                break
        if (save):
            context.report_action(self.name, call_params, 'Interesting Function Call')
        
        # Handle VBA functions:
        func_name = str(self.name)
        if func_name.lower() == 'msgbox':
            # 6.1.2.8.1.13 MsgBox
            context.report_action('Display Message', repr(call_params[0]), 'MsgBox')
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
            context.report_action('Object.Method Call', tmp_call_params, func_name)
        try:

            # Emulate the function body.
            s = context.get(func_name)
            if (s is None):
                raise KeyError("func not found")
            s.eval(context=context, params=call_params)

            # Set the values of the arguments passed as ByRef parameters.
            if (hasattr(s, "byref_params")):
                for byref_param_info in s.byref_params.keys():
                    arg_var_name = str(self.params[byref_param_info[1]])
                    context.set(arg_var_name, s.byref_params[byref_param_info])
            
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
                        s.eval(context=context, params=new_params)
                        return
                    except KeyError:
                        pass
                log.error('Procedure %r not found' % func_name)
            except Exception as e:
                log.debug("General error: " + str(e))
                raise e
                
# 5.4.2.1 Call Statement
# a call statement is similar to a function call, except it is a statement on its own, not part of an expression
# call statement params may be surrounded by parentheses or not
call_params = (Suppress('(') + Optional(expr_list('params')) + Suppress(')')) ^ expr_list('params')
call_statement = NotAny(known_keywords_statement_start) \
                 + Optional(CaselessKeyword('Call').suppress()) \
                 + (member_access_expression_limited('name') | TODO_identifier_or_object_attrib_loose('name')) + Optional(call_params)
call_statement.setParseAction(Call_Statement)

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
                      (CaselessKeyword('Return').suppress()) | (CaselessKeyword('End').suppress())
exit_func_statement.setParseAction(Exit_Function_Statement)

# --- REDIM statement ----------------------------------------------------------

class Redim_Statement(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(Redim_Statement, self).__init__(original_str, location, tokens)
        self.item = tokens.item
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'ReDim ' + str(self.item)

    def eval(self, context, params=None):
        # Currently stubbed out.
        return

# Array redim statement
redim_statement = CaselessKeyword('ReDim').suppress() + \
                  Optional(CaselessKeyword('Preserve')) + \
                  expression('item') + \
                  Optional('(' + expression + CaselessKeyword('To') + expression + ')').suppress() + \
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
        
        # Track the with prefix.
        if (len(context.with_prefix) > 0):
            context.with_prefix += "." + str(self.env)
        else:
            context.with_prefix = str(self.env)
            
        # Evaluate each statement in the with block.
        log.debug("START WITH")
        for s in self.body:
            if (not isinstance(s, VBA_Object)):
                continue
            s.eval(context)
        log.debug("END WITH")
            
        # Remove the current with prefix.
        if ("." not in context.with_prefix):
            context.with_prefix = ""
        else:
            end = context.with_prefix.rindex(".")
            context.with_prefix = context.with_prefix[:end]
            
        return

# With statement
with_statement = CaselessKeyword('With').suppress() + (member_access_expression('env') ^ lex_identifier('env') ^ function_call_limited('env')) + Suppress(EOS) + \
                 Group(statement_block('body')) + \
                 CaselessKeyword('End').suppress() + CaselessKeyword('With').suppress()
with_statement.setParseAction(With_Statement)

# --- GOTO statement ----------------------------------------------------------

# TODO: Emulation of Goto statements needs to be added. This can be
# done by changing the parsing of a Label statement to include the
# label and then the statement list following the label. When parsed
# the Label statement VBA_Object will track the statement list
# associated with the label. Add a mapping from labels to statement
# lists in the context. Then evaluating a Goto statement will involve
# looking up the statement list for the label, evaluating those
# statements, and then exiting the current function.

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
        log.debug('parsed %r as On_Error_Statement' % self)

    def __repr__(self):
        return str(self.tokens)

    def eval(self, context, params=None):
        # Currently stubbed out.
        return

on_error_statement = CaselessKeyword('On') + CaselessKeyword('Error') + \
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

        # Save that the file is opened.
        context.open_files[self.file_id] = {}
        context.open_files[self.file_id]["name"] = name
        context.open_files[self.file_id]["contents"] = []

file_type = Suppress(CaselessKeyword("For")) + \
            (CaselessKeyword("Append") | CaselessKeyword("Binary") | CaselessKeyword("Input") | CaselessKeyword("Output") | CaselessKeyword("Random"))("mode") + \
            Optional(Suppress(CaselessKeyword("Access")) + \
                     (CaselessKeyword("Read Write") ^ CaselessKeyword("Read") ^ CaselessKeyword("Write"))("access"))

#file_open_statement = Suppress(CaselessKeyword("Open")) + lex_identifier("file_name") + file_type("type") + \
#                      Suppress(CaselessKeyword("As")) + file_pointer("file_id")
file_open_statement = Suppress(CaselessKeyword("Open")) + expression("file_name") + file_type("type") + \
                      Suppress(CaselessKeyword("As")) + file_pointer("file_id")
file_open_statement.setParseAction(File_Open)

# --- PRINT -------------------------------------------------------------

class Print_Statement(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(Print_Statement, self).__init__(original_str, location, tokens)
        self.file_id = tokens.file_id
        self.value = tokens.value
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

        # Get the data.
        data = eval_arg(self.value, context=context)

        # Are we writing a string?
        if (isinstance(data, str)):
            for c in data:
                context.open_files[file_id]["contents"].append(ord(c))

        # Are we writing a list?
        elif (isinstance(data, list)):
            for c in data:
                context.open_files[file_id]["contents"].append(c)

        # Unhandled.
        else:
            log.error("Unhandled Put() data type to Print. " + str(type(data)) + ".")

print_statement = Suppress(CaselessKeyword("Print")) + file_pointer("file_id") + Suppress(Optional(",")) + expression("value")
print_statement.setParseAction(Print_Statement)

# --- DOEVENTS STATEMENT -------------------------------------------------------------

doevents_statement = Suppress(CaselessKeyword("DoEvents"))

# --- STATEMENTS -------------------------------------------------------------

# simple statement: fits on a single line (excluding for/if/do/etc blocks)
#simple_statement = dim_statement | option_statement | (prop_assign_statement ^ expression ^ (let_statement | call_statement) ^ label_statement) | exit_loop_statement | \
#                   exit_func_statement | redim_statement | goto_statement | on_error_statement | file_open_statement | doevents_statement | \
#                   rem_statement | print_statement | resume_statement
simple_statement = dim_statement | option_statement | (prop_assign_statement ^ expression ^ (let_statement | call_statement)) | exit_loop_statement | \
                   exit_func_statement | redim_statement | goto_statement | on_error_statement | file_open_statement | doevents_statement | \
                   rem_statement | print_statement | resume_statement
simple_statements_line <<= simple_statement + ZeroOrMore(Suppress(':') + simple_statement)

# statement has to be declared beforehand using Forward(), so here we use
# the "<<=" operator:
statement <<= type_declaration | name_as_statement | simple_for_statement | simple_for_each_statement | simple_if_statement | \
              simple_if_statement_macro | simple_while_statement | simple_do_statement | simple_select_statement | \
              with_statement| simple_statement | rem_statement

statements_line = tagged_block ^ \
                  (Optional(statement + ZeroOrMore(Suppress(':') + statement)) + EOS.suppress())

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
        context.open_files[fname] = {}
        context.open_files[fname]["name"] = fname
        context.open_files[fname]["contents"] = []
        log.info("Created file " + fname)
        
        # Return the name of the "file".
        return fname

    def _writefile(self, params, context):

        # Simulate the write.
        file_id = params[0]

        # Make sure the file exists.
        if (file_id not in context.open_files):
            log.error("File " + file_id + " not open. Cannot write.")
            return 1
        
        # We can only write single byte values for now.
        data = params[1]
        if (not isinstance(data, int)):
            log.error("Cannot WriteFile() data that is not int.")
            return 0
        context.open_files[file_id]["contents"].append(data)
        return 0

    def _closehandle(self, params, context):

        # Simulate the file close.
        file_id = params[0]
        context.dump_file(file_id)
        return 0
    
    def __init__(self, original_str, location, tokens):
        super(External_Function, self).__init__(original_str, location, tokens)
        self.name = tokens.function_name
        self.params = tokens.params
        self.lib_name = tokens.lib_name
        # normalize lib name: remove quotes, lowercase, add .dll if no extension
        if isinstance(self.lib_name, basestring):
            self.lib_name = tokens.lib_name.strip('"').lower()
            if '.' not in self.lib_name:
                self.lib_name += '.dll'
        self.alias_name = tokens.alias_name
        if isinstance(self.alias_name, basestring):
            # TODO: this might not be necessary if alias is parsed as quoted string
            self.alias_name = self.alias_name.strip('"')
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
        # TODO: use separate classes for each known DLL and methods for functions?
        # TODO: use the alias name instead of the name!
        if self.alias_name:
            function_name = self.alias_name
        else:
            function_name = self.name
        log.info('Evaluating external function %s(%r)' % (function_name, params))

        # Log certain function calls.
        function_name = function_name.lower()
        if function_name.startswith('urldownloadtofile'):
            context.report_action('Download URL', params[1], 'External Function: urlmon.dll / URLDownloadToFile')
            context.report_action('Write File', params[2], 'External Function: urlmon.dll / URLDownloadToFile')
            # return 0 when no error occurred:
            return 0
        if function_name.startswith('shellexecute'):
            cmd = str(params[2]) + str(params[3])
            context.report_action('Run Command', cmd, function_name)
            # return 0 when no error occurred:
            return 0

        # Simulate certain external calls of interest.
        if (function_name.startswith('createfile')):
            return self._createfile(params, context)

        if (function_name.startswith('writefile')):
            return self._writefile(params, context)

        if (function_name.startswith('closehandle')):
            return self._closehandle(params, context)
        
        # TODO: return result according to the known DLLs and functions
        log.error('Unknown external function %s from DLL %s' % (function_name, self.lib_name))
        return 0

function_type2 = CaselessKeyword('As').suppress() + lex_identifier('return_type') \
                 + Optional(Literal('(') + Literal(')')).suppress()

public_private <<= Optional(CaselessKeyword('Public') | CaselessKeyword('Private') | CaselessKeyword('Global')).suppress()

params_list_paren = Suppress('(') + Optional(parameters_list('params')) + Suppress(')')

# 5.2.3.5 External Procedure Declaration
lib_info = CaselessKeyword('Lib').suppress() + quoted_string('lib_name') \
           + Optional(CaselessKeyword('Alias') + quoted_string('alias_name'))

# TODO: identifier or lex_identifier
external_function <<= public_private + Suppress(CaselessKeyword('Declare') + Optional(CaselessKeyword('PtrSafe')) + \
                                                (CaselessKeyword('Function') | CaselessKeyword('Sub'))) + \
                                                lex_identifier('function_name') + lib_info + Optional(params_list_paren) + Optional(function_type2)
external_function.setParseAction(External_Function)
