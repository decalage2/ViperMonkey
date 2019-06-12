#!/usr/bin/env python
"""
ViperMonkey: VBA Grammar - Procedures

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

from vba_context import *
from statements import *
from identifiers import *

from logger import log
from tagged_block_finder_visitor import *

# --- SUB --------------------------------------------------------------------

class Sub(VBA_Object):

    def __init__(self, original_str, location, tokens):
        super(Sub, self).__init__(original_str, location, tokens)
        self.name = tokens.sub_name
        self.params = tokens.params
        self.statements = tokens.statements
        self.bogus_if = None
        if (len(tokens.bogus_if) > 0):
            self.bogus_if = tokens.bogus_if
        # Get a dict mapping labeled blocks of code to labels.
        # This will be used to handle GOTO statements when emulating.
        visitor = tagged_block_finder_visitor()
        self.accept(visitor)
        self.tagged_blocks = visitor.blocks
        log.info('parsed %r' % self)

    def __repr__(self):
        return 'Sub %s (%s): %d statement(s)' % (self.name, self.params, len(self.statements))

    def eval(self, context, params=None):

        # create a new context for this execution:
        caller_context = context
        # Looks like local variables from the calling context can be accessed in the called
        # function, so keep those.
        context = Context(context=caller_context, _locals=context.locals)

        # Set the information about labeled code blocks in the called
        # context. This will be used when emulating GOTOs.
        context.tagged_blocks = self.tagged_blocks

        # Compute the argument values.
        call_info = {}
        call_info["FUNCTION_NAME -->"] = self.name

        # Set the default parameter values.
        for param in self.params:
            init_val = None
            if (param.init_val is not None):
                init_val = eval_arg(param.init_val, context=context)
            call_info[param.name] = init_val

        # Set given parameter values.
        self.byref_params = {}
        if ((params is not None) and (len(params) == len(self.params))):

            # TODO: handle named parameters
            for i in range(len(params)):

                # Set the parameter value.
                param_name = self.params[i].name
                param_value = params[i]

                # Handle empty string parameters.
                if ((param_value == 0) and (self.params[i].my_type == "String")):
                    param_value = ""

                # Coerce parameters to String if needed.
                if (self.params[i].my_type == "String"):
                    param_value = str(param_value)
                    
                # Add the parameter value to the local function context.
                log.debug('Function %s: setting param %s = %r' % (self.name, param_name, param_value))
                call_info[param_name] = param_value

                # Is this a ByRef parameter?
                if (self.params[i].mechanism == "ByRef"):

                    # Save it so we can pull out the updated value in the Call statement.
                    self.byref_params[(param_name, i)] = None
            
        # Do we have an obvious recursive loop? Detect this by looking for the current call
        # with the exact same arguments appearing in the call stack.
        # TODO: This needs more work and testing.
        if (context.call_stack.count(call_info) > 0):
            log.warn("Recursive infinite loop detected. Aborting call " + str(call_info))
            return "NULL"

        # Add the current call to the call stack.
        context.call_stack.append(call_info)

        # Set the parameter values in the current context.
        for param_name in call_info.keys():
            context.set(param_name, call_info[param_name], force_local=True)

        # Variable updates can go in the local scope.
        old_global_scope = context.global_scope
        context.global_scope = False
                    
        # Emulate the function.
        log.debug('evaluating Sub %s(%s)' % (self.name, params))
        log.info('evaluating Sub %s' % self.name)
        # TODO self.call_params
        context.got_error = False
        for s in self.statements:

            # Emulate the current statement.
            log.debug('Sub %s eval statement: %s' % (self.name, s))
            if (isinstance(s, VBA_Object)):
                s.eval(context=context)

            # Was there an error that will make us jump to an error handler?
            if (context.must_handle_error()):
                break
            context.clear_error()

            # Did we just run a GOTO? If so we should not run the
            # statements after the GOTO.
            if (isinstance(s, Goto_Statement)):
                log.debug("GOTO executed. Go to next loop iteration.")
                break
            
        # Reset variable update scoping.
        context.global_scope = old_global_scope
            
        # Run the error handler if we have one and we broke out of the statement
        # loop with an error.
        context.handle_error(params)
            
        # Handle trailing if's with no end if.
        if (self.bogus_if is not None):
            if (isinstance(self.bogus_if, VBA_Object)):
                self.bogus_if.eval(context=context)
            elif (isinstance(self.bogus_if, list)):
                for cmd in self.bogus_if:
                    cmd.eval(context=context)

        # Save the values of the ByRef parameters.
        for byref_param in self.byref_params.keys():
            self.byref_params[byref_param] = context.get(byref_param[0].lower())

        # Done with call. Pop this call off the call stack.
        del context.call_stack[-1]
            
        # Handle subs with no return values.
        try:            
            context.get(self.name)
        except KeyError:

            # No return value explicitly set. It looks like VBA uses an empty string as
            # these funcion values.
            context.set(self.name, '')

# 5.3.1.1 Procedure Scope
#
# MS-GRAMMAR: procedure-scope = ["global" / "public" / "private" / "friend"]

procedure_scope = Optional(CaselessKeyword('Public') | CaselessKeyword('Private')
                           | CaselessKeyword('Global') | CaselessKeyword('Friend')).suppress()

# 5.3.1.2 Static Procedures

static_keyword = Optional(CaselessKeyword('static'))

# 5.4 Procedure Bodies and Statements

# 5.3.1.3 Procedure Names
#
# MS-GRAMMAR: subroutine-name = IDENTIFIER / prefixed-name
# MS-GRAMMAR: function-name = TYPED-NAME / subroutine-name
# MS-GRAMMAR: prefixed-name = event-handler-name / implemented-name / lifecycle-handler-name

# 5.3.1.8 Event Handler Declarations
#
# MS-GRAMMAR: event-handler-name = IDENTIFIER

# 5.3.1.9 Implemented Name Declarations
#
# MS-GRAMMAR: implemented-name = IDENTIFIER

# 5.3.1.10 Lifecycle Handler Declarations
#
# MS-GRAMMAR: lifecycle-handler-name = "Class_Initialize" / "Class_Terminate"

lifecycle_handler_name = CaselessKeyword("Class_Initialize") | CaselessKeyword("Class_Terminate")
implemented_name = identifier  # duplicate, not used
event_handler_name = identifier  # duplicate, not used
prefixed_name = identifier | lifecycle_handler_name  # simplified

subroutine_name = identifier | lifecycle_handler_name  # simplified

# MS-GRAMMAR: typed_name = identifier + optional type_suffix => simplified
# MS-GRAMMAR: function_name = typed_name | subroutine_name

function_name = Combine(identifier + Suppress(Optional(type_suffix))) | lifecycle_handler_name

# 5.3.1 Procedure Declarations
#
# MS-GRAMMAR: end-label = statement-label-definition

end_label = statement_label_definition

# MS-GRAMMAR: procedure-tail = [WS] LINE-END / single-quote comment-body / ":" rem-statement

procedure_tail = FollowedBy(line_terminator) | comment_single_quote | Literal(":") + rem_statement

# NOTE: rem statement does NOT include the line terminator => BUG?
# TODO: here i assume that procedure tail does NOT include the line terminator

# MS-GRAMMAR: subroutine-declaration = procedure-scope [initial-static]
#       "sub" subroutine-name [procedure-parameters] [trailing-static] EOS
#       [procedure-body EOS]
#       [end-label] "end" "sub" procedure-tail
# MS-GRAMMAR: function-declaration = procedure-scope [initial-static]
#       "function" function-name [procedure-parameters] [function-type]
#       [trailing-static] EOS
#       [procedure-body EOS]
#       [end-label] "end" "function" procedure-tail
# MS-GRAMMAR: property-get-declaration = procedure-scope [initial-static]
#       "Property" "Get"
#       function-name [procedure-parameters] [function-type] [trailing-static] EOS
#       [procedure-body EOS]
#       [end-label] "end" "property" procedure-tail
# MS-GRAMMAR: property-lhs-declaration = procedure-scope [initial-static]
#       "Property" ("Let" / "Set")
#       subroutine-name property-parameters [trailing-static] EOS
#       [procedure-body EOS]
#       [end-label] "end" "property" procedure-tail

sub_start = Optional(CaselessKeyword('Static')) + public_private + CaselessKeyword('Sub').suppress() + lex_identifier('sub_name') \
            + Optional(params_list_paren) + EOS.suppress()
sub_start_single = Optional(CaselessKeyword('Static')) + public_private + CaselessKeyword('Sub').suppress() + lex_identifier('sub_name') \
                   + Optional(params_list_paren) + Suppress(':')
sub_end = (CaselessKeyword('End') + (CaselessKeyword('Sub') | CaselessKeyword('Function')) + EOS).suppress()
simple_sub_end = (CaselessKeyword('End') + (CaselessKeyword('Sub') | CaselessKeyword('Function'))).suppress()
sub_end_single = Optional(Suppress(':')) + (CaselessKeyword('End') + (CaselessKeyword('Sub') | CaselessKeyword('Function')) + EOS).suppress()
multiline_sub = (sub_start + \
                 Group(ZeroOrMore(statements_line)).setResultsName('statements') + \
                 Optional(bad_if_statement('bogus_if')) + \
                 Suppress(Optional(bad_next_statement)) + \
                 sub_end)
simple_multiline_sub = (sub_start + \
                        Group(ZeroOrMore(statements_line)).setResultsName('statements') + \
                        Optional(bad_if_statement('bogus_if')) + \
                        Suppress(Optional(bad_next_statement)) + \
                        simple_sub_end)
# Static Sub autoopEN(): Call atecyx: End Sub
singleline_sub = sub_start_single + simple_statements_line('statements') + sub_end_single
sub = singleline_sub | multiline_sub
simple_sub = simple_multiline_sub
sub.setParseAction(Sub)
simple_sub.setParseAction(Sub)

# for line parser:
sub_start_line = public_private + CaselessKeyword('Sub').suppress() + lex_identifier('sub_name') \
                 + Optional(params_list_paren) + EOS.suppress()
sub_start_line.setParseAction(Sub)

# --- FUNCTION --------------------------------------------------------------------

# TODO: Function should inherit from Sub, or use only one class for both

class Function(VBA_Object):

    def __init__(self, original_str, location, tokens):
        super(Function, self).__init__(original_str, location, tokens)
        self.return_type = None
        if (hasattr(tokens, "return_type")):
            self.return_type = tokens.return_type
        self.name = tokens.function_name
        self.params = tokens.params
        self.statements = tokens.statements
        try:
            len(self.statements)
        except:
            self.statements = [self.statements]
        self.return_type = tokens.return_type
        self.vars = {}
        self.bogus_if = None
        if (len(tokens.bogus_if) > 0):
            self.bogus_if = tokens.bogus_if
        # Get a dict mapping labeled blocks of code to labels.
        # This will be used to handle GOTO statements when emulating.
        visitor = tagged_block_finder_visitor()
        self.accept(visitor)
        self.tagged_blocks = visitor.blocks
        log.info('parsed %r' % self)

    def __repr__(self):
        return 'Function %s (%s): %d statement(s)' % (self.name, self.params, len(self.statements))

    def eval(self, context, params=None):

        # create a new context for this execution:
        caller_context = context
        # Looks like local variables from the calling context can be accessed in the called
        # function, so keep those.
        context = Context(context=caller_context, _locals=context.locals)
        
        # Set the information about labeled code blocks in the called
        # context. This will be used when emulating GOTOs.
        context.tagged_blocks = self.tagged_blocks

        # Compute the argument values.
        call_info = {}
        call_info["FUNCTION_NAME -->"] = self.name

        # add function name in locals if the function takes 0 arguments. This is
        # needed since otherwise it is not possible to differentiate a function call
        # from a reference to the function return value in the function body.
        if (len(self.params) == 0):
            call_info[self.name] = 'NULL'

        # Set the default parameter values.
        for param in self.params:
            init_val = None
            if (param.init_val is not None):
                init_val = eval_arg(param.init_val, context=context)
            call_info[param.name] = init_val

        # Array accesses of calls to functions that return an array are parsed as
        # function calls with the array indices given as function call arguments. Note
        # that this parsing problem only occurs for 0 argument functions (foo(12)).
        # Array accesses of functions with parameters look like 'bar(1,2,3)(12)', so they
        # parse properly.
        #
        # Check for the 0 parameter function array access case here.
        array_indices = None
        if ((self.params is not None) and
            (params is not None) and
            (len(self.params) == 0) and
            (len(params) > 0)):
            array_indices = params
            
        # Set given parameter values.
        self.byref_params = {}
        if ((params is not None) and (len(params) <= len(self.params))):

            # TODO: handle named parameters
            for i in range(len(params)):

                # Set the parameter value.
                param_name = self.params[i].name
                param_value = params[i]

                # Handle empty string parameters.
                if ((param_value == 0) and (self.params[i].my_type == "String")):
                    param_value = ""

                # Coerce parameters to String if needed.
                if (self.params[i].my_type == "String"):
                    param_value = str(param_value)
                    
                # Add the parameter value to the local function context.
                log.debug('Function %s: setting param %s = %r' % (self.name, param_name, param_value))
                call_info[param_name] = param_value

                # Is this a ByRef parameter?
                if (self.params[i].mechanism == "ByRef"):

                    # Save it so we can pull out the updated value in the Call statement.
                    self.byref_params[(param_name, i)] = None
            
        # Do we have an obvious recursive loop? Detect this by looking for the current call
        # with the exact same arguments appearing in the call stack.
        # TODO: This needs more work and testing.
        if (context.call_stack.count(call_info) > 0):
            log.warn("Recursive infinite loop detected. Aborting call " + str(call_info))
            return "NULL"

        # Add the current call to the call stack.
        context.call_stack.append(call_info)

        # Set the parameter values in the current context.
        for param_name in call_info.keys():
            context.set(param_name, call_info[param_name], force_local=True)
        
        # Variable updates can go in the local scope.
        old_global_scope = context.global_scope
        context.global_scope = False
        
        # Emulate the function.
        log.debug('evaluating Function %s(%s)' % (self.name, params))
        # TODO self.call_params
        context.got_error = False
        for s in self.statements:
            log.debug('Function %s eval statement: %s' % (self.name, s))
            if (isinstance(s, VBA_Object)):
                s.eval(context=context)

            # Have we exited from the function with 'Exit Function'?
            if (context.exit_func):
                break

            # Was there an error that will make us jump to an error handler?
            if (context.must_handle_error()):
                break
            context.clear_error()

            # Did we just run a GOTO? If so we should not run the
            # statements after the GOTO.
            if (isinstance(s, Goto_Statement)):
                log.debug("GOTO executed. Go to next loop iteration.")
                break
            
        # Reset variable update scoping.
        context.global_scope = old_global_scope

        # Run the error handler if we have one and we broke out of the statement
        # loop with an error.
        context.handle_error(params)
            
        # Handle trailing if's with no end if.
        if (self.bogus_if is not None):
            self.bogus_if.eval(context=context)

        # Done with call. Pop this call off the call stack.
        del context.call_stack[-1]
            
        # TODO: get result from context.locals
        context.exit_func = False
        try:

            # Save the values of the ByRef parameters.
            for byref_param in self.byref_params.keys():
                self.byref_params[byref_param] = context.get(byref_param[0].lower())

            # Get the return value.
            return_value = context.get(self.name)
            if ((return_value is None) or (isinstance(return_value, Function))):
                return_value = ''
            log.debug('Function %s: return value = %r' % (self.name, return_value))

            # Convert the return value to a String if needed.
            if ((self.return_type == "String") and (not isinstance(return_value, str))):
                return_value = coerce_to_string(return_value)

            # Handle array accesses of the results of 0 parameter functions if needed.
            if (array_indices is not None):

                # Does the function actually return an array?
                if (isinstance(return_value, list)):

                    # Are the array indices valid?
                    all_int = True
                    for i in array_indices:
                        if (not isinstance(i, int)):
                            all_int = False
                            break
                    if (all_int):

                        # Perform the array access.
                        for i in array_indices:
                            return_value = return_value[i]

                    # Invalid array indices.
                    else:
                        log.warn("Array indices " + str(array_indices) + " are invalid. " + \
                                 "Not doing array access of function return value.")

                # Function does not return array.
                else:
                    log.warn(str(self) + " does not return an array. Not doing array access.")
                
            return return_value

        except KeyError:
            
            # No return value explicitly set. It looks like VBA uses an empty string as
            # these funcion values.
            return ''

# TODO 5.3.1.4 Function Type Declarations
function_start = Optional(CaselessKeyword('Static')) + Optional(public_private) + Optional(CaselessKeyword('Static')) + \
                 CaselessKeyword('Function').suppress() + TODO_identifier_or_object_attrib('function_name') + \
                 Optional(params_list_paren) + Optional(function_type2("return_type")) + EOS.suppress()
function_start_single = Optional(CaselessKeyword('Static')) + Optional(public_private) + Optional(CaselessKeyword('Static')) + \
                        CaselessKeyword('Function').suppress() + TODO_identifier_or_object_attrib('function_name') + \
                        Optional(params_list_paren) + Optional(function_type2) + Suppress(':')

function_end = (CaselessKeyword('End') + CaselessKeyword('Function') + EOS).suppress()
simple_function_end = (CaselessKeyword('End') + CaselessKeyword('Function')).suppress()
function_end_single = Optional(Suppress(':')) + (CaselessKeyword('End') + CaselessKeyword('Function') + EOS).suppress()

multiline_function = (function_start + \
                      Group(ZeroOrMore(statements_line)).setResultsName('statements') + \
                      Optional(bad_if_statement('bogus_if')) + \
                      Suppress(Optional(bad_next_statement)) + \
                      function_end)
simple_multiline_function = (function_start + \
                             Group(ZeroOrMore(statements_line)).setResultsName('statements') + \
                             Optional(bad_if_statement('bogus_if')) + \
                             Suppress(Optional(bad_next_statement)) + \
                             simple_function_end)

singleline_function = function_start_single + simple_statements_line('statements') + function_end_single
function = singleline_function | multiline_function
simple_function = simple_multiline_function            
function.setParseAction(Function)
simple_function.setParseAction(Function)

# for line parser:
function_start_line = public_private + CaselessKeyword('Function').suppress() + lex_identifier('function_name') \
                 + Optional(params_list_paren) + Optional(function_type2) + EOS.suppress()
function_start_line.setParseAction(Function)

extend_statement_grammar()
