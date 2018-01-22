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


# ------------------------------------------------------------------------------
# CHANGELOG:
# 2015-02-12 v0.01 PL: - first prototype
# 2015-2016        PL: - many updates
# 2016-06-11 v0.02 PL: - split vipermonkey into several modules

__version__ = '0.02'

# ------------------------------------------------------------------------------
# TODO:

# --- IMPORTS ------------------------------------------------------------------

from comments_eol import *
from expressions import *
from vba_context import *

from logger import log
log.debug('importing statements')

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


# catch-all for unknown statements
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


# procedural-module-header = attribute "VB_Name" attr-eq quoted-identifier attr-end
# class-module-header = 1*class-attr
# class-attr = attribute "VB_Name" attr-eq quoted-identifier attr-end
# / attribute "VB_GlobalNameSpace" attr-eq "False" attr-end
# / attribute "VB_Creatable" attr-eq "False" attr-end
# / attribute "VB_PredeclaredId" attr-eq boolean-literal-identifier attr-end
# / attribute "VB_Exposed" attr-eq boolean-literal-identifier attr-end
# / attribute "VB_Customizable" attr-eq boolean-literal-identifier attr-end
# attribute = LINE-START "Attribute"
# attr-eq = "="
# attr-end = LINE-END

# quoted-identifier = double-quote NO-WS IDENTIFIER NO-WS double-quote
quoted_identifier = Combine(Suppress('"') + identifier + Suppress('"'))
quoted_identifier.setParseAction(lambda t: str(t[0]))

# TODO: here I use lex_identifier instead of identifier because attrib names are reserved identifiers
attribute_statement = CaselessKeyword('Attribute').suppress() + lex_identifier('name') + Suppress('=') + literal(
    'value')
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


# --- TYPE EXPRESSIONS -------------------------------------------------------

# 5.6.16.7 Type Expressions
# type-expression = BUILTIN-TYPE / defined-type-expression
# defined-type-expression = simple-name-expression / member-access-expression

# TODO: for now we use a generic syntax
type_expression = lex_identifier

# --- TYPE DECLARATIONS -------------------------------------------------------

type_declaration_composite = (CaselessKeyword('Public') | CaselessKeyword('Private')) + CaselessKeyword('Type') + \
                             lex_identifier + Suppress(EOS) + \
                             OneOrMore(lex_identifier + CaselessKeyword('As') + reserved_type_identifier + Suppress(EOS)) + \
                             CaselessKeyword('End') + CaselessKeyword('Type')

# TODO: Add in simple type declarations.
type_declaration = type_declaration_composite

# --- FUNCTION TYPE DECLARATIONS ---------------------------------------------

# 5.3.1.4 Function Type Declarations
# function-type = "as" type-expression [array-designator]
# array-designator = "(" ")"

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
        self.type = tokens.type
        log.debug('parsed %r' % self)

    def __repr__(self):
        r = self.name
        if self.type:
            r += ' as %s' % self.type
        return r


# TODO 5.3.1.5 Parameter Lists
# TODO: differentiate dim params from sub/function params?

# 5.3.1.5 Parameter Lists
# procedure-parameters = "(" [parameter-list] ")"
# property-parameters = "(" [parameter-list ","] value-param ")"
# parameter-list = (positional-parameters "," optional-parameters )
#                   / (positional-parameters ["," param-array])
#                   / optional-parameters / param-array
# positional-parameters = positional-param *("," positional-param)
# optional-parameters = optional-param *("," optional-param)
# value-param = positional-param
# positional-param = [parameter-mechanism] param-dcl
# optional-param = optional-prefix param-dcl [default-value]
# param-array = "paramarray" IDENTIFIER "(" ")" ["as" ("variant" / "[variant]")]
# param-dcl = untyped-name-param-dcl / typed-name-param-dcl
# untyped-name-param-dcl = IDENTIFIER [parameter-type]
# typed-name-param-dcl = TYPED-NAME [array-designator]
# optional-prefix = ("optional" [parameter-mechanism]) / ([parameter-mechanism] ("optional"))
# parameter-mechanism = "byval" / " byref"
# parameter-type = [array-designator] "as" (type-expression / "Any")
# default-value = "=" constant-expression

default_value = Literal("=").suppress() + expr_const('default_value')  # TODO: constant_expression

parameter_mechanism = CaselessKeyword('ByVal') | CaselessKeyword('ByRef')

optional_prefix = (CaselessKeyword("optional") + parameter_mechanism) \
                  | (parameter_mechanism + CaselessKeyword("optional"))

parameter_type = Optional(array_designator) + CaselessKeyword("as").suppress() \
                 + (type_expression | CaselessKeyword("Any"))

untyped_name_param_dcl = identifier + Optional(parameter_type)

# TODO:
# procedure_parameters = "(" [parameter_list] ")"
# property_parameters = "(" [parameter_list ","] value_param ")"
# parameter_list = (positional_parameters "," optional_parameters )
#                   | (positional_parameters ["," param_array])
#                   | optional_parameters | param_array
# positional_parameters = positional_param *("," positional_param)
# optional_parameters = optional_param *("," optional_param)
# value_param = positional_param
# positional_param = [parameter_mechanism] param_dcl
# optional_param = optional_prefix param_dcl [default_value]
# param_array = "paramarray" IDENTIFIER "(" ")" ["as" ("variant" | "[variant]")]
# param_dcl = untyped_name_param_dcl | typed_name_param_dcl
# typed_name_param_dcl = TYPED_NAME [array_designator]

parameter = Optional(CaselessKeyword("optional").suppress()) + Optional(parameter_mechanism).suppress() + TODO_identifier_or_object_attrib('name') + \
            Optional(CaselessKeyword("(") + ZeroOrMore(" ") + CaselessKeyword(")")).suppress() + \
            Optional(CaselessKeyword('as').suppress() + lex_identifier('type'))
parameter.setParseAction(Parameter)

parameters_list = delimitedList(parameter, delim=',')

# --- STATEMENT LABELS -------------------------------------------------------

# 5.4.1.1 Statement Labels
# statement-label-definition = LINE-START ((identifier-statement-label ":") / (line-number-label [":"] ))
# statement-label = identifier-statement-label / line-number-label
# statement-label-list = statement-label ["," statement-label]
# identifier-statement-label = IDENTIFIER
# line-number-label = INTEGER

statement_label_definition = LineStart() + ((identifier('label_name') + Suppress(":"))
                                            | (integer('label_int') + Optional(Suppress(":"))))
statement_label = identifier | integer
statement_label_list = delimitedList(statement_label, delim=',')

# TODO: StatementLabel class

# --- STATEMENT BLOCKS -------------------------------------------------------

# 5.4.1 Statement Blocks
# A statement block is a sequence of 0 or more statements.
# statement-block = *(block-statement EOS)
# block-statement = statement-label-definition / rem-statement / statement
# statement = control-statement / data-manipulation-statement / error-handling-statement /
# filestatement

# need to declare statement beforehand:
statement = Forward()
external_function = Forward()

# NOTE: statements should NOT include EOS
block_statement = rem_statement | external_function | statement | statement_label_definition
statement_block = ZeroOrMore(block_statement + EOS.suppress())

# --- DIM statement ----------------------------------------------------------

class Dim_Statement(VBA_Object):
    """
    Dim statement
    """

    def __init__(self, original_str, location, tokens):
        super(Dim_Statement, self).__init__(original_str, location, tokens)

        # [['b1', '(', ')', 'Byte']]
        # [['b7', '(', ')', 'Byte', '=', s]]
        # [['l', 'Long']]
        # [['b2', '(', ')'], ['b3'], ['b4', '(', ')', 'Byte']]
        
        # Get the type (if there is one) of the declared variable.
        self.type = None
        last_var = tokens[len(tokens) - 1]
        if (len(last_var) > 1):

            # If this is a typed array declaration the type will be the
            # 4th element.
            if ((last_var[1] == '(') and
                (len(last_var) > 3) and
                (last_var[3] != '=')):
                self.type = last_var[3]

            # If this is a typed non-array decl the type will be the 2nd
            # element.
            elif (len(last_var) == 2):
                self.type = last_var[1]
                
        # Track the initial value of the variable.
        self.init_val = None
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
            self.variables.append((var[0], is_array))
        
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
        if (self.type is not None):
            r += " As " + str(self.type)
        if (self.init_val is not None):
            r += " = " + str(self.init_val)
        return r

    def eval(self, context, params=None):

        # Evaluate the initial variable value(s).
        init_val = ''
        if (self.init_val is not None):
            init_val = eval_arg(self.init_val, context=context)
        elif ((self.type == "Long") or (self.type == "Integer")):
            init_val = 0
            
        # Track each declared variable.
        for var in self.variables:

            # Do we know the variable type?
            curr_init_val = init_val
            curr_type = None
            if (self.type is not None):
                curr_type = str(self.type)

                # Is this variable an array?
                if (var[1]):
                    curr_type += " Array"
                    curr_init_val = []

            # Set the initial value of the declared variable.
            context.set(var[0], curr_init_val, curr_type)
    
# 5.4.3.1 Local Variable Declarations
# local-variable-declaration = ("Dim" ["Shared"] variable-declaration-list)
# static-variable-declaration = "Static" variable-declaration-list

# 5.2.3.1 Module Variable Declaration Lists
# module-variable-declaration = public-variable-declaration / private-variable-declaration
# global-variable-declaration = "Global" variable-declaration-list
# public-variable-declaration = "Public" ["Shared"] module-variable-declaration-list
# private-variable-declaration = ("Private" / "Dim") [ "Shared"] module-variable-declaration-
# list
# module-variable-declaration-list = (withevents-variable-dcl / variable-dcl)
# *( "," (withevents-variable-dcl / variable-dcl) )
# variable-declaration-list = variable-dcl *( "," variable-dcl )

# 5.2.3.1.1 Variable Declarations
# variable-dcl = typed-variable-dcl / untyped-variable-dcl
# typed-variable-dcl = TYPED-NAME [array-dim]
# untyped-variable-dcl = IDENTIFIER [array-clause / as-clause]
# array-clause = array-dim [as-clause]
# as-clause = as-auto-object / as-type

# 5.2.3.1.3 Array Dimensions and Bounds
# array-dim = "(" [bounds-list] ")"
# bounds-list = dim-spec *("," dim-spec)
# dim-spec = [lower-bound] upper-bound
# lower-bound = constant-expression "to"
# upper-bound = constant-expression

# 5.6.16.1 Constant Expressions
# A constant expression is an expression usable in contexts which require a value that can be fully
# evaluated statically.
# constant-expression = expression

# 5.2.3.1.4 Variable Type Declarations
# A type specification determines the specified type of a declaration.
# as-auto-object = "as" "new" class-type-name
# as-type = "as" type-spec
# type-spec = fixed-length-string-spec / type-expression
# fixed-length-string-spec = "string" "*" string-length
# string-length = constant-name / INTEGER
# constant-name = simple-name-expression

# 5.2.3.1.2 WithEvents Variable Declarations
# withevents-variable-dcl = "withevents" IDENTIFIER "as" class-type-name
# class-type-name = defined-type-expression

# 5.6.16.7 Type Expressions
# type-expression = BUILTIN-TYPE / defined-type-expression
# defined-type-expression = simple-name-expression / member-access-expression

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
local_variable_declaration = CaselessKeyword("Dim").suppress() + Optional(
    CaselessKeyword("Shared")).suppress() + variable_declaration_list

dim_statement = local_variable_declaration

# dim_statement = CaselessKeyword('Dim').suppress() + \
#                 Optional(CaselessKeyword("Shared")).suppress() + parameters_list
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

    def eval(self, context, params=None):

        # evaluate value of right operand:
        log.debug('try eval expression: %s' % self.expression)
        value = eval_arg(self.expression, context=context)
        log.debug('eval expression: %s = %s' % (self.expression, value))

        # set variable, non-array access.
        if (self.index is None):

            # Handle conversion of strings to byte arrays, if needed.
            if ((context.get_type(self.name) == "Byte Array") and
                (isinstance(value, str))):
                tmp = []
                for c in value:
                    tmp.append(ord(c))
                    tmp.append(0)
                value = tmp

            # Handle conversion of byte arrays to strings, if needed.
            if ((context.get_type(self.name) == "String") and
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
                    
            log.debug('setting %s = %s' % (self.name, value))
            context.set(self.name, value)

        # set variable, array access.
        else:

            # Evaluate the index expression.
            index = int(eval_arg(self.index, context=context))
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
            if (isinstance(arr_var, str)):

                # Do we need to extend the length of the string to include the index?
                if (index >= len(arr_var)):
                    arr_var += "\0"*(index - len(arr_var))
                
                # We now have a string with the proper # of elements. Set the
                # array element to the proper value.
                if (isinstance(value, str)):
                    arr_var = arr_var[:index] + value + arr_var[(index + 1):]
                elif (isinstance(value, int)):
                    try:
                        arr_var = arr_var[:index] + chr(value) + arr_var[(index + 1):]
                    except Exception as e:
                        log.error(str(e))
                        log.error(str(value) + " cannot be converted to ASCII.")
                else:
                    log.error("Unhandled value type " + str(type(value)) + " for array update.")
                        
            # Finally save the updated variable in the context.
            context.set(self.name, arr_var)
            
# 5.4.3.8   Let Statement
# A let statement performs Let-assignment of a non-object value. The Let keyword itself is optional
# and may be omitted.
# let-statement = ["Let"] l-expression "=" expression

# TODO: remove Set when Set_Statement implemented:
# let_statement = Optional(CaselessKeyword('Let') | CaselessKeyword('Set')).suppress() \
#                 + l_expression('name') + Literal('=').suppress() + expression('expression')

# previous custom grammar (incomplete):
let_statement = Optional(CaselessKeyword('Let') | CaselessKeyword('Set')).suppress() + \
                Optional(Suppress('Const')) + \
                ((TODO_identifier_or_object_attrib('name') + Optional(Suppress('(') + expression('index') + Suppress(')'))) ^ \
                 member_access_expression('name')) + \
                Literal('=').suppress() + \
                (expression('expression') ^ boolean_expression('expression'))

let_statement.setParseAction(Let_Statement)

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

    def eval(self, context, params=None):
        # evaluate values:
        log.debug('FOR loop: evaluating start, end, step')
        start = eval_arg(self.start_value, context=context)
        log.debug('FOR loop - start: %r = %r' % (self.start_value, start))
        end = eval_arg(self.end_value, context=context)
        log.debug('FOR loop - end: %r = %r' % (self.end_value, end))
        if ((VBA_Object.loop_upper_bound > 0) and (end > VBA_Object.loop_upper_bound)):
            end = VBA_Object.loop_upper_bound
            log.debug("FOR loop: upper loop iteration bound exceeded, setting to %r" % end)
        if self.step_value != 1:
            step = eval_arg(self.step_value, context=context)
            log.debug('FOR loop - step: %r = %r' % (self.step_value, step))
        else:
            step = 1

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
# bound-variable-expression = l-expression
# Static Semantics.
# A <bound-variable-expression> is invalid if it is classified as something other than a variable
# expression. The expression is invalid even if it is classified as an unbound member expression that
# could be resolved to a variable expression.

bound_variable_expression = TODO_identifier_or_object_attrib  # l_expression

# 5.4.2.3 For Statement
# A <for-statement> executes a sequence of statements a specified number of times.

# for-statement = simple-for-statement / explicit-for-statement
# simple-for-statement = for-clause EOS statement-block "Next"
# explicit-for-statement = for-clause EOS statement-block
# ("Next" / (nested-for-statement ",")) bound-variable-expression
# nested-for-statement = explicit-for-statement / explicit-for-each-statement
# for-clause = "For" bound-variable-expression "=" start-value "To" end-value [stepclause]
# start-value = expression
# end-value = expression
# step-clause = "Step" step-increment
# step-increment = expression

step_clause = CaselessKeyword('Step').suppress() + expression

# TODO: bound_variable_expression instead of lex_identifier
for_clause = CaselessKeyword("For").suppress() \
             + lex_identifier('name') \
             + Suppress(Optional(CaselessKeyword("As") + type_expression)) \
             + Suppress("=") + expression('start_value') \
             + CaselessKeyword("To").suppress() + expression('end_value') \
             + Optional(step_clause('step_value'))

simple_for_statement = for_clause + Suppress(EOS) + statement_block('statements') \
                       + CaselessKeyword("Next").suppress() \
                       + Optional(lex_identifier) \
                       + FollowedBy(EOS)  # NOTE: the statement should NOT include EOS!

simple_for_statement.setParseAction(For_Statement)

# For the line parser:
for_start = for_clause + Suppress(EOL)
for_start.setParseAction(For_Statement)

for_end = CaselessKeyword("Next").suppress() + Optional(lex_identifier) + Suppress(EOL)

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

    def eval(self, context, params=None):

        log.debug('DO loop: start: ' + str(self))
        
        # Track that the current loop is running.
        context.loop_stack.append(True)

        # Loop until the loop is broken out of or we violate the loop guard.
        while (True):

            # Test the loop guard to see if we should exit the loop.
            guard_val = eval_arg(self.guard, context)
            if (self.loop_type.lower() == "until"):
                guard_val = (not guard_val)
            if (not guard_val):
                break
            
            # Execute the loop body.
            done = False
            for s in self.body:
                log.debug('DO loop eval statement: %r' % s)
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
        
        # Remove tracking of this loop.
        context.loop_stack.pop()
        log.debug('DO loop: end.')

while_type = CaselessKeyword("While") | CaselessKeyword("Until")
        
while_clause = Optional(CaselessKeyword("Do").suppress()) + while_type("type") + boolean_expression("guard")

simple_while_statement = while_clause("clause") + Suppress(EOS) + Group(statement_block('body')) \
                       + (CaselessKeyword("Loop").suppress() | CaselessKeyword("Wend").suppress())

simple_while_statement.setParseAction(While_Statement)

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

        # Get the current value of the guard expression for the select.
        log.debug("eval select: " + str(self))
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
        return self.select_val.eval(context, params)

class Case_Clause(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(Case_Clause, self).__init__(original_str, location, tokens)
        self.case_val = tokens.case_val
        self.test_range = ((tokens.lbound != "") and (tokens.lbound != ""))
        self.test_set = (not self.test_range) and (len(self.case_val) > 1)
        self.is_else = False
        for v in self.case_val:
            if (str(v).lower() == "else"):
                self.is_else = True
                break
        log.debug('parsed %r as %s' % (self, self.__class__.__name__))

    def __repr__(self):
        r = "Case "
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
        r += "\\n"
        return r

    def eval(self, context, params=None):
        """
        Evaluate the guard of this case against the given value.
        """

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
                start = int(eval_arg(self.case_val[0], context))
                end = int(eval_arg(self.case_val[1], context)) + 1
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
        pass
    
select_clause = CaselessKeyword("Select").suppress() + CaselessKeyword("Case").suppress() \
                + expression("select_val")
select_clause.setParseAction(Select_Clause)

case_clause = CaselessKeyword("Case").suppress() + \
              ((expression("lbound") + CaselessKeyword("To").suppress() + expression("ubound")) | \
               (CaselessKeyword("Else")) | \
               (expression("case_val") + ZeroOrMore(Suppress(",") + expression)))
                             
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
                                 CaselessKeyword("End If").suppress()
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

        # TODO: Properly evaluating this will involve supporting compile time variables
        # that can be set via options when running ViperMonkey. For now just run the then
        # block.
        log.debug("eval: " + str(self))
        then_part = self.pieces[0]
        for stmt in then_part["body"]:
            stmt.eval(context)

# Grammar element for #IF statements.
simple_if_statement_macro = Group( CaselessKeyword("#If").suppress() + boolean_expression + CaselessKeyword("Then").suppress() + Suppress(EOS) + \
                                   Group(statement_block('statements'))) + \
                                   ZeroOrMore(
                                       Group( CaselessKeyword("#ElseIf").suppress() + boolean_expression + CaselessKeyword("Then").suppress() + Suppress(EOS) + \
                                              Group(statement_block('statements')))
                                   ) + \
                                   Optional(
                                       Group(CaselessKeyword("#Else").suppress() + Suppress(EOS) + \
                                             Group(statement_block('statements')))
                                   ) + \
                                   CaselessKeyword("#End If").suppress() + FollowedBy(EOS)

simple_if_statement_macro.setParseAction(If_Statement_Macro)

# --- CALL statement ----------------------------------------------------------

class Call_Statement(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(Call_Statement, self).__init__(original_str, location, tokens)
        self.name = tokens.name
        self.params = tokens.params
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Procedure Call: %s(%r)' % (self.name, self.params)

    def eval(self, context, params=None):
        log.info('Eval Params before calling Procedure: %s(%r)' % (self.name, self.params))
        # TODO fix params here!
        call_params = eval_args(self.params, context=context)
        log.info('Calling Procedure: %s(%r)' % (self.name, call_params))
        # Handle VBA functions:
        func_name = str(self.name)
        if func_name.lower() == 'msgbox':
            # 6.1.2.8.1.13 MsgBox
            context.report_action('Display Message', repr(call_params[0]), 'MsgBox')
            # vbOK = 1
            return 1
        elif '.' in func_name:
            context.report_action('Object.Method Call', repr(call_params), func_name)
        try:
            s = context.get(func_name)
            s.eval(context=context, params=call_params)
        except KeyError:
            try:
                tmp_name = func_name.replace("$", "").replace("VBA.", "").replace("Math.", "")
                if ("." in tmp_name):
                    tmp_name = func_name[tmp_name.rindex(".") + 1:]
                log.debug("Looking for procedure %r" % tmp_name)
                s = context.get(tmp_name)
                s.eval(context=context, params=call_params)
            except KeyError:

                # If something like Application.Run("foo", 12) is called, foo(12) will be run.
                # Try to handle that.
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


# TODO: 5.4.2.1 Call Statement
# a call statement is similar to a function call, except it is a statement on its own, not part of an expression
# call statement params may be surrounded by parentheses or not
call_params = (Suppress('(') + Optional(expr_list('params')) + Suppress(')')) ^ expr_list('params')
call_statement = NotAny(known_keywords_statement_start) \
                 + Optional(CaselessKeyword('Call').suppress()) \
                 + (member_access_expression_limited('name') | TODO_identifier_or_object_attrib('name')) + Optional(call_params)
call_statement.setParseAction(Call_Statement)

# --- EXIT FOR statement ----------------------------------------------------------

class Exit_For_Statement(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(Exit_For_Statement, self).__init__(original_str, location, tokens)
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Exit For'

    def eval(self, context, params=None):
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
                      (CaselessKeyword('Return').suppress())
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
redim_statement = CaselessKeyword('ReDim').suppress() + expression('item') + \
                  Optional('(' + expression + CaselessKeyword('To') + expression + ')').suppress() + \
                  Optional(CaselessKeyword('As') + lex_identifier).suppress()
redim_statement.setParseAction(Redim_Statement)

# --- WITH statement ----------------------------------------------------------

class With_Statement(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(With_Statement, self).__init__(original_str, location, tokens)
        self.body = tokens.body
        self.env = tokens.env
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'With ' + str(self.env) + "\\n" + str(self.body) + " End With"

    def eval(self, context, params=None):
        # TODO: Currently stubbed out. Need to track the containing environment object name(s) in a stack
        # and append them to the names of variables like ".foo" when referencing variables in the With.
        return

# With statement
with_statement = CaselessKeyword('With').suppress() + lex_identifier('env') + Suppress(EOS) + \
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
        # TODO: Currently stubbed out. Need to tie this label to the following statements somehow.
        return

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
label_statement = identifier('label') + Suppress(':')
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

# --- STATEMENTS -------------------------------------------------------------

# simple statement: fits on a single line (excluding for/if/do/etc blocks)
simple_statement = dim_statement | option_statement | (let_statement ^ call_statement ^ label_statement) | exit_loop_statement | \
                   exit_func_statement | redim_statement | goto_statement | on_error_statement
simple_statements_line <<= simple_statement + ZeroOrMore(Suppress(':') + simple_statement)

# statement has to be declared beforehand using Forward(), so here we use
# the "<<=" operator:
statement <<= type_declaration | simple_for_statement | simple_for_each_statement | simple_if_statement | \
              simple_if_statement_macro | simple_while_statement | simple_select_statement | with_statement| simple_statement

# TODO: potential issue here, as some statements can be multiline, such as for loops... => check MS-VBAL
# TODO: can we have '::' with an empty statement?
# TODO: use statement_block instead!
statements_line = Optional(statement + ZeroOrMore(Suppress(':') + statement)) + EOS.suppress()

# --- EXTERNAL FUNCTION ------------------------------------------------------

class External_Function(VBA_Object):
    """
    External Function from a DLL
    """

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
        # create a new context for this execution:
        caller_context = context
        context = Context(context=caller_context)
        # TODO: use separate classes for each known DLL and methods for functions?
        # TODO: use the alias name instead of the name!
        if self.alias_name:
            function_name = self.alias_name
        else:
            function_name = self.name
        log.debug('evaluating External Function %s(%r)' % (function_name, params))
        function_name = function_name.lower()
        if self.lib_name.startswith('urlmon'):
            if function_name.startswith('urldownloadtofile'):
                context.report_action('Download URL', params[1], 'External Function: urlmon.dll / URLDownloadToFile')
                context.report_action('Write File', params[2], 'External Function: urlmon.dll / URLDownloadToFile')
                # return 0 when no error occurred:
                return 0
        if function_name.lower().startswith('shellexecute'):
            cmd = str(params[2]) + str(params[3])
            context.report_action('Run Command', cmd, function_name)
            # return 0 when no error occurred:
            return 0
        # TODO: return result according to the known DLLs and functions
        log.error('Unknown external function %s from DLL %s' % (function_name, self.lib_name))
        return None

function_type2 = CaselessKeyword('As').suppress() + lex_identifier('return_type') \
                 + Optional(Literal('(') + Literal(')')).suppress()

public_private <<= Optional(CaselessKeyword('Public') | CaselessKeyword('Private')).suppress()

params_list_paren = Suppress('(') + Optional(parameters_list('params')) + Suppress(')')

# 5.2.3.5 External Procedure Declaration
lib_info = CaselessKeyword('Lib').suppress() + quoted_string('lib_name') \
           + Optional(CaselessKeyword('Alias') + quoted_string('alias_name'))

# TODO: identifier or lex_identifier
external_function <<= public_private + Suppress(CaselessKeyword('Declare') + Optional(CaselessKeyword('PtrSafe'))
                                                + CaselessKeyword('Function')) + lex_identifier('function_name') + lib_info \
                                                + Optional(params_list_paren) + Optional(function_type2)
external_function.setParseAction(External_Function)


