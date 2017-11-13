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
                                  CaselessKeyword('ElseIf') | CaselessKeyword('End If') | CaselessKeyword('New')

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
        # print 'Attribute_Statement.init:'
        # pprint.pprint(tokens.asList())
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



parameter = Optional(parameter_mechanism).suppress() + lex_identifier('name') \
            + Optional(CaselessKeyword('as').suppress() + Word(alphas).setResultsName('type'))
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

# NOTE: statements should NOT include EOS
block_statement = rem_statement | statement | statement_label_definition
statement_block = ZeroOrMore(block_statement + EOS.suppress())

# --- DIM statement ----------------------------------------------------------

class Dim_Statement(VBA_Object):
    """
    Dim statement
    """

    def __init__(self, original_str, location, tokens):
        super(Dim_Statement, self).__init__(original_str, location, tokens)
        # print 'Dim_Statement.init:'
        # pprint.pprint(tokens.asList())
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Dim %r' % repr(self.tokens)


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
array_dim = Suppress('(') + Optional(bounds_list) + Suppress(')')
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
variable_dcl = typed_variable_dcl | untyped_variable_dcl
variable_declaration_list = delimitedList(variable_dcl)
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
        self.name = tokens[0]
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Global %r' % repr(self.tokens)

global_variable_declaration = CaselessKeyword("Public").suppress() + Optional(
    CaselessKeyword("Shared")).suppress() + variable_declaration_list
global_variable_declaration.setParseAction(Global_Var_Statement)

# --- LET STATEMENT --------------------------------------------------------------

class Let_Statement(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(Let_Statement, self).__init__(original_str, location, tokens)
        self.name = tokens.name
        self.expression = tokens.expression
        # print 'Let_Statement.init:'
        # pprint.pprint(tokens.asList())
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'Let %s = %r' % (self.name, self.expression)

    def eval(self, context, params=None):
        # evaluate value of right operand:
        value = eval_arg(self.expression, context=context)
        log.debug('eval expression: %s = %s' % (self.expression, value))
        # set variable
        log.debug('setting %s = %s' % (self.name, value))
        context.set(self.name, value)

# 5.4.3.8   Let Statement
# A let statement performs Let-assignment of a non-object value. The Let keyword itself is optional
# and may be omitted.
# let-statement = ["Let"] l-expression "=" expression

# TODO: remove Set when Set_Statement implemented:
# let_statement = Optional(CaselessKeyword('Let') | CaselessKeyword('Set')).suppress() \
#                 + l_expression('name') + Literal('=').suppress() + expression('expression')

# previous custom grammar (incomplete):
let_statement = Optional(CaselessKeyword('Let') | CaselessKeyword('Set')).suppress() \
                + TODO_identifier_or_object_attrib('name') + Literal('=').suppress() + expression('expression')

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
        if self.step_value != 1:
            step = eval_arg(self.step_value, context=context)
            log.debug('FOR loop - step: %r = %r' % (self.step_value, step))
        else:
            step = 1
        # loop using xrange until end+1, because python stops when index>=end+1
        for val in xrange(start, end + 1, step):
            # TODO: what if name is already a global variable?
            # force a set_local?
            log.debug('FOR loop: %s = %r' % (self.name, val))
            context.set(self.name, val)
            for s in self.statements:
                log.debug('FOR loop eval statement: %r' % s)
                s.eval(context=context)
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
             + Suppress("=") + expression('start_value') \
             + CaselessKeyword("To").suppress() + expression('end_value') \
             + Optional(step_clause('step_value'))

# def log_for_clause(s=None,l=None,t=None):
#     print('FOR CLAUSE: loc=%d tokens=%r original=%r' % (l,t,s))
# for_clause.setParseAction(log_for_clause)

# def log_EOS(s=None,l=None,t=None):
#     print('EOS: loc=%d tokens=%r original=%r' % (l,t,s))
# EOS.setParseAction(log_EOS)

# def log_statement_block(s=None,l=None,t=None):
#     print('statement_block: loc=%d tokens=%r original=%r' % (l,t,s))
# statement_block.setParseAction(log_statement_block)

simple_for_statement = for_clause + Suppress(EOS) + statement_block('statements') \
                       + CaselessKeyword("Next").suppress() \
                       + Optional(lex_identifier) \
                       + FollowedBy(EOS)  # NOTE: the statement should NOT include EOS!
# + Optional(matchPreviousExpr(lex_identifier)) \
simple_for_statement.setParseAction(For_Statement)


# This does not work with pyparsing, need to be a bit smarter:
# explicit_for_statement = Forward()
#
# nested_for_statement = explicit_for_statement #| explicit_for_each_statement
#
# explicit_for_statement = for_clause + Suppress(EOS) + statement_block('statements') \
#     + (CaselessKeyword("Next").suppress() | (nested_for_statement + Literal(","))) \
#     + bound_variable_expression('next_name')
#
# for_statement = simple_for_statement | explicit_for_statement
# for_statement.setParseAction(For_Statement)

# For the line parser:
for_start = for_clause + Suppress(EOL)
for_start.setParseAction(For_Statement)

for_end = CaselessKeyword("Next").suppress() + Optional(lex_identifier) + Suppress(EOL)

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
simple_if_statement = Group( CaselessKeyword("If").suppress() + boolean_expression + CaselessKeyword("Then").suppress() + Suppress(EOS) + \
                             Group(statement_block('statements'))) + \
                      ZeroOrMore(
                          Group( CaselessKeyword("ElseIf").suppress() + boolean_expression + CaselessKeyword("Then").suppress() + Suppress(EOS) + \
                                 Group(statement_block('statements')))
                      ) + \
                      Optional(
                          Group(CaselessKeyword("Else").suppress() + Suppress(EOS) + \
                                Group(statement_block('statements')))
                      ) + \
                      CaselessKeyword("End If").suppress() + FollowedBy(EOS)

simple_if_statement.setParseAction(If_Statement)

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
        if self.name.lower() == 'msgbox':
            # 6.1.2.8.1.13 MsgBox
            context.report_action('Display Message', repr(call_params[0]), 'MsgBox')
            # vbOK = 1
            return 1
        elif '.' in self.name:
            context.report_action('Object.Method Call', repr(call_params), self.name)
        try:
            s = context.get(self.name)
            s.eval(context=context, params=call_params)
        except KeyError:
            try:
                tmp_name = self.name.replace("$", "").replace("VBA.", "")
                if ("." in tmp_name):
                    tmp_name = self.name[tmp_name.rindex(".") + 1:]
                log.debug("Looking for procedure %r" % tmp_name)
                s = context.get(tmp_name)
                s.eval(context=context, params=call_params)
            except KeyError:
                log.error('Procedure %r not found' % self.name)


# TODO: 5.4.2.1 Call Statement
# a call statement is similar to a function call, except it is a statement on its own, not part of an expression
# call statement params may be surrounded by parentheses or not
call_params = (Suppress('(') + Optional(expr_list('params')) + Suppress(')')) | expr_list('params')
call_statement = NotAny(known_keywords_statement_start) \
                 + Optional(CaselessKeyword('Call').suppress()) \
                 + TODO_identifier_or_object_attrib('name') + Optional(call_params)
call_statement.setParseAction(Call_Statement)

# --- STATEMENTS -------------------------------------------------------------

# simple statement: fits on a single line (excluding for/if/do/etc blocks)
simple_statement = dim_statement | option_statement | let_statement | call_statement | unknown_statement
simple_statements_line = Optional(simple_statement + ZeroOrMore(Suppress(':') + simple_statement)) + EOS.suppress()

# statement has to be declared beforehand using Forward(), so here we use
# the "<<=" operator:
statement <<= simple_for_statement | simple_if_statement | simple_statement

# TODO: potential issue here, as some statements can be multiline, such as for loops... => check MS-VBAL
# TODO: can we have '::' with an empty statement?
# TODO: use statement_block instead!
statements_line = Optional(statement + ZeroOrMore(Suppress(':') + statement)) + EOS.suppress()

