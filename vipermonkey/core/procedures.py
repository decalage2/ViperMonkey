"""@package procedures Parsing and Emulation of VBA/VBScript Functions
and Subs.

"""

# pylint: disable=pointless-string-statement
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

#import sys
import logging

# Important: need to change the default pyparsing whitespace setting, because CRLF
# is not a whitespace for VBA.
import pyparsing
pyparsing.ParserElement.setDefaultWhitespaceChars(' \t\x19')

from pyparsing import CaselessKeyword, Group, Optional, Suppress, \
    ZeroOrMore, Literal

from vba_context import Context
from statements import extend_statement_grammar, public_private, simple_statements_line, \
    bogus_simple_for_each_statement, do_const_assignments, Do_Statement, While_Statement, \
    For_Each_Statement, For_Statement, FollowedBy, Combine, params_list_paren, bad_next_statement, \
    bad_if_statement, statements_line, function_type2, type_expression
from identifiers import lex_identifier, identifier, TODO_identifier_or_object_attrib, \
    type_suffix
from comments_eol import EOS, comment_single_quote, rem_statement
from vba_lines import line_terminator
import utils
from utils import safe_str_convert
from logger import log
from tagged_block_finder_visitor import tagged_block_finder_visitor
from vba_object import coerce_to_str, VBA_Object, eval_arg
from python_jit import to_python, _check_for_iocs
from python_jit import _get_var_vals

# --- SUB --------------------------------------------------------------------

class Sub(VBA_Object):
    """Emulate a VBA/VBScript Sub (subroutine).

    """
    
    def __init__(self, original_str, location, tokens):
        super(Sub, self).__init__(original_str, location, tokens)
        self.name = tokens.sub_name
        self.params = tokens.params
        self.min_param_length = len(self.params)
        for param in self.params:
            if (param.is_optional):
                self.min_param_length -= 1
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

    def to_python(self, context, params=None, indent=0):

        # Get the global variables read in the function body.
        tmp_context = Context(context=context, _locals=context.locals, copy_globals=True)
        global_var_info, _ = _get_var_vals(self, tmp_context, global_only=True)
        
        # Set up the initial values for the global variables.
        global_var_init_str = ""
        indent_str = " " * indent
        for global_var in global_var_info:
            val = to_python(global_var_info[global_var], context)
            global_var_init_str += indent_str + safe_str_convert(global_var) + " = " + safe_str_convert(val) + "\n"

        # Make a copy of the context so we can mark variables as function
        # arguments.
        tmp_context = Context(context=context)
        for param in self.params:
            tmp_context.set(param.name, "__FUNC_ARG__")

        # Save the name of the current function so we can handle exit function calls.
        tmp_context.curr_func_name = safe_str_convert(self.name)

        # Global variable initialization goes first.
        r = global_var_init_str
        
        # Define the function prototype.
        indent_str = " " * indent
        func_args = "("
        first = True
        for param in self.params:
            if (not first):
                func_args += ", "
            first = False
            func_args += utils.fix_python_overlap(to_python(param, tmp_context))
        func_args += ")"
        r += indent_str + "def " + safe_str_convert(self.name) + func_args + ":\n"

        # Init return value.
        r += indent_str + " " * 4 + "import core.vba_library\n"
        r += indent_str + " " * 4 + "global vm_context\n\n"
        r += indent_str + " " * 4 + "# Function return value.\n"
        r += indent_str + " " * 4 + safe_str_convert(self.name) + " = 0\n\n"

        # Global variables used in the function.
        r += indent_str + " " * 4 + "# Referenced global variables.\n"
        for global_var in global_var_info:
            r += indent_str + " " * 4 + "global " + safe_str_convert(global_var) + "\n"
        r += "\n"
        
        # Function body.
        r += to_python(self.statements, tmp_context, indent=indent+4, statements=True)

        # Check for IOCs.
        r += "\n" + _check_for_iocs(self, tmp_context, indent=indent+4)
        
        # Done.
        return r
    
    def eval(self, context, params=None):

        # create a new context for this execution:
        caller_context = context
        context = Context(context=caller_context)
        context.in_procedure = True

        # Save the name of the current function so we can handle exit function calls.
        context.curr_func_name = safe_str_convert(self.name)
        
        # We are entering the function so reset whether we executed a goto.
        context.goto_executed = False
        
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
            # pylint: disable=consider-using-enumerate
            for i in range(len(params)):

                # Set the parameter value.
                param_name = self.params[i].name
                param_value = params[i]

                # Handle empty string parameters.
                if ((param_value == 0) and (self.params[i].my_type == "String")):
                    param_value = ""

                # Coerce parameters to String if needed.
                if ((self.params[i].my_type == "String") and (not self.params[i].is_array)):
                    param_value = safe_str_convert(param_value)
                    
                # Add the parameter value to the local function context.
                if (log.getEffectiveLevel() == logging.DEBUG):
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
            log.warn("Recursive infinite loop detected. Aborting call " + safe_str_convert(call_info))
            #print self
            #print call_info
            #print context.call_stack
            #sys.exit(0)
            return "NULL"

        # Add the current call to the call stack.
        context.call_stack.append(call_info)

        # Assign all const variables first.
        do_const_assignments(self.statements, context)
        
        # Set the parameter values in the current context.
        for param_name in call_info:
            context.set(param_name, call_info[param_name], force_local=True)

        # Variable updates can go in the local scope.
        old_global_scope = context.global_scope
        context.global_scope = False
                    
        # Emulate the function.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('evaluating Sub %s(%s)' % (self.name, params))
        log.info('evaluating Sub %s' % self.name)
        # TODO self.call_params
        context.clear_error()
        for s in self.statements:

            # Emulate the current statement.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Sub %s eval statement: %s' % (self.name, s))
            if (isinstance(s, VBA_Object)):
                s.eval(context=context)

            # Was there an error that will make us jump to an error handler?
            #if (context.have_error()):
            if (context.must_handle_error()):
                break
            context.clear_error()

            # Did we just run a GOTO? If so we should not run the
            # statements after the GOTO.
            if (context.goto_executed or
                (hasattr(s, "exited_with_goto") and s.exited_with_goto)):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("GOTO executed. Control flow handled by GOTO, so skip rest of procedure statements.")
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
        for byref_param in self.byref_params:
            self.byref_params[byref_param] = context.get(byref_param[0].lower())

        # Done with call. Pop this call off the call stack.
        del context.call_stack[-1]

        # We are leaving the function so reset whether we executed a goto.
        context.goto_executed = False

        # Bubble up any unhandled errors to the caller.
        caller_context.got_error = context.got_error

        # Same with whether we did any wildcard value tests.
        caller_context.tested_wildcard = context.tested_wildcard
        
        # Handle subs with no return values.
        try:            
            context.get(self.name)
        except KeyError:

            # No return value explicitly set. It looks like VBA uses an empty string as
            # these funcion values.
            context.set(self.name, '')

        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Returning from sub " + safe_str_convert(self))

        return "NULL"
            

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

#end_label = statement_label_definition

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

sub_start = Optional(CaselessKeyword('Static')) + Optional(CaselessKeyword('Default')) + \
            public_private + Optional(CaselessKeyword('Static')) + Optional(CaselessKeyword('Default')) + \
            CaselessKeyword('Sub').suppress() + lex_identifier('sub_name') + Optional(params_list_paren) + EOS.suppress()
sub_start_single = Optional(CaselessKeyword('Static')) + Optional(CaselessKeyword('Default')) + \
                   public_private + CaselessKeyword('Sub').suppress() + lex_identifier('sub_name') \
                   + Optional(params_list_paren) + Suppress(':')
sub_end = (CaselessKeyword('End') + (CaselessKeyword('Sub') | CaselessKeyword('Function')) + EOS).suppress() | \
          bogus_simple_for_each_statement
simple_sub_end = (CaselessKeyword('End') + (CaselessKeyword('Sub') | CaselessKeyword('Function'))).suppress()
sub_end_single = Optional(Suppress(':')) + (CaselessKeyword('End') + \
                                            (CaselessKeyword('Sub') | CaselessKeyword('Function')) + EOS).suppress()
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

def is_loop_statement(s):
    """Check to see if the given VBA_Object is a looping construct
    (While, For, etc.).

    @param s (VBA_Object object) The thing to check to see if it is a
    loop statement.

    @return (boolean) True if it is a loop, False if not.

    """
    return isinstance(s, (Do_Statement, For_Each_Statement, For_Statement, While_Statement))

class Function(VBA_Object):
    """Emulate a VBA/VBScript Function.

    """
    
    def __init__(self, original_str, location, tokens):
        super(Function, self).__init__(original_str, location, tokens)
        self.return_type = None
        if (hasattr(tokens, "return_type")):
            self.return_type = tokens.return_type
        self.name = tokens.function_name
        self.params = tokens.params
        self.min_param_length = len(self.params)
        for param in self.params:
            if (param.is_optional):
                self.min_param_length -= 1
        self.statements = tokens.statements
        try:
            len(self.statements)
        except TypeError:
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

    def to_python(self, context, params=None, indent=0):
        
        # Get the global variables read in the function body.
        tmp_context = Context(context=context, _locals=context.locals, copy_globals=True)
        global_var_info, _ = _get_var_vals(self, tmp_context, global_only=True)
        
        # Set up the initial values for the global variables.
        global_var_init_str = ""
        indent_str = " " * indent
        for global_var in global_var_info:
            val = to_python(global_var_info[global_var], context)
            global_var_init_str += indent_str + safe_str_convert(global_var) + " = " + safe_str_convert(val) + "\n"
        
        # Make a copy of the context so we can mark variables as function
        # arguments.
        tmp_context = Context(context=context)
        for param in self.params:
            tmp_context.set(param.name, "__FUNC_ARG__")

        # Save the name of the current function so we can handle exit function calls.
        tmp_context.curr_func_name = safe_str_convert(self.name)

        # Global variable initialization goes first.
        r = global_var_init_str
        
        # Define the function prototype.
        func_args = "("
        first = True
        for param in self.params:
            if (not first):
                func_args += ", "
            first = False
            func_args += utils.fix_python_overlap(to_python(param, tmp_context))
        func_args += ")"
        r += indent_str + "def " + safe_str_convert(self.name) + func_args + ":\n"

        # Init return value.
        r += indent_str + " " * 4 + "import core.vba_library\n"
        r += indent_str + " " * 4 + "global vm_context\n\n"
        r += indent_str + " " * 4 + "# Function return value.\n"
        r += indent_str + " " * 4 + safe_str_convert(self.name) + " = 0\n\n"

        # Global variables used in the function.
        r += indent_str + " " * 4 + "# Referenced global variables.\n"
        for global_var in global_var_info:
            r += indent_str + " " * 4 + "global " + safe_str_convert(global_var) + "\n"
        r += "\n"
            
        # Function body.
        r += to_python(self.statements, tmp_context, indent=indent+4, statements=True)

        # Check for IOCs.
        r += "\n" + _check_for_iocs(self, tmp_context, indent=indent+4)
        
        # Return the function return val.
        r += "\n" + indent_str + " " * 4 + "return " + safe_str_convert(self.name) + "\n"

        # Done.
        return r

    def eval(self, context, params=None):

        # create a new context for this execution:
        caller_context = context
        # Looks like local variables from the calling context can be accessed in the called
        # function, so keep those.
        #context = Context(context=caller_context, _locals=context.locals)
        # TODO: Local variable inheritence needs to be investigated more...
        context = Context(context=caller_context)        
        context.in_procedure = True

        # We are entering the function so reset whether we executed a goto.
        context.goto_executed = False

        # Save the name of the current function so we can handle exit function calls.
        context.curr_func_name = safe_str_convert(self.name)
        
        # Set the information about labeled code blocks in the called
        # context. This will be used when emulating GOTOs.
        context.tagged_blocks = self.tagged_blocks

        # Compute the argument values.
        call_info = {}
        call_info["FUNCTION_NAME -->"] = (self.name, None)

        # add function name in locals if the function takes 0 arguments. This is
        # needed since otherwise it is not possible to differentiate a function call
        # from a reference to the function return value in the function body.
        if (len(self.params) == 0):
            call_info[self.name] = ('NULL', None)

        # Set the default parameter values.
        for param in self.params:
            init_val = None
            if (param.init_val is not None):
                init_val = eval_arg(param.init_val, context=context)
            call_info[param.name] = (init_val, None)
            
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
        defined_param_pos = -1
        for defined_param in self.params:

            # Get the given parameter at this position, if we have one.
            defined_param_pos += 1
            param_value = "NULL"
            param_name = defined_param.name
            if ((params is not None) and (defined_param_pos < len(params))):
                param_value = params[defined_param_pos]

            # Handle empty string parameters.
            if (((param_value == 0) or (param_value == "NULL")) and (defined_param.my_type == "String")):
                param_value = ""

            # Coerce parameters to String if needed.
            if (defined_param.my_type == "String"):
                param_value = utils.safe_str_convert(param_value)
                    
            # Add the parameter value to the local function context.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Function %s: setting param %s = %r' % (self.name, param_name, param_value))

            # Handle params with default values.
            if ((param_name not in call_info) or
                (call_info[param_name] == ('', None)) or
                (param_value != "")):
                call_info[param_name] = (param_value, defined_param.my_type)

            # Is this a ByRef parameter?
            if (defined_param.mechanism == "ByRef"):

                # Save it so we can pull out the updated value in the Call statement.
                self.byref_params[(param_name, defined_param_pos)] = None
                
        # Do we have an obvious recursive loop? Detect this by looking for the current call
        # with the exact same arguments appearing in the call stack.
        # TODO: This needs more work and testing.
        if (context.call_stack.count(call_info) > 0):
            log.warn("Recursive infinite loop detected. Aborting call " + safe_str_convert(call_info))
            #print self
            #print call_info
            #print context.call_stack
            #sys.exit(0)
            return "NULL"

        # Add the current call to the call stack.
        context.call_stack.append(call_info)
        
        # Assign all const variables first.
        do_const_assignments(self.statements, context)
        
        # Set the parameter values in the current context.
        for param_name in call_info:
            param_val, param_type = call_info[param_name]
            context.set(param_name, param_val, var_type=param_type, force_local=True)
        
        # Variable updates can go in the local scope.
        old_global_scope = context.global_scope
        context.global_scope = False
        
        # Emulate the function.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('evaluating Function %s(%s)' % (self.name, params))
        # TODO self.call_params
        context.clear_error()
        for s in self.statements:
            if (log.getEffectiveLevel() == logging.DEBUG):
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

            # If the just run statement was a loop, the GOTO was run in
            # the loop and we have finished the loop, so run the statements
            # after the loop.
            if (is_loop_statement(s)):
                context.goto_executed = False
                s.exited_with_goto = False
                
            # Did we just run a GOTO? If so we should not run the
            # statements after the GOTO.
            if (context.goto_executed or s.exited_with_goto):
                if (log.getEffectiveLevel() == logging.DEBUG):
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
        
        # We are leaving the function so reset whether we executed a goto.
        context.goto_executed = False

        # Bubble up any unhandled errors to the caller.
        caller_context.got_error = context.got_error

        # Same with whether we did any wildcard value tests.
        caller_context.tested_wildcard = context.tested_wildcard
        
        # TODO: get result from context.locals
        context.exit_func = False
        try:

            # Save the values of the ByRef parameters.
            for byref_param in self.byref_params:
                if (context.contains(byref_param[0].lower())):
                    self.byref_params[byref_param] = context.get(byref_param[0].lower())

            # Get the return value.
            return_value = context.get(self.name, local_only=True)
            if ((return_value is None) or (isinstance(return_value, Function))):
                return_value = ''
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Function %s: return value = %r' % (self.name, return_value))

            # Convert the return value to a String if needed.
            if ((self.return_type == "String") and (not isinstance(return_value, str))):
                return_value = coerce_to_str(return_value)

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
                        log.warn("Array indices " + safe_str_convert(array_indices) + " are invalid. " + \
                                 "Not doing array access of function return value.")

                # Function does not return array.
                else:
                    log.warn(safe_str_convert(self) + " does not return an array. Not doing array access.")
                    
            # Copy all the global variables from the function context to the caller
            # context so global updates are tracked.
            for global_var in context.globals.keys():
                caller_context.globals[global_var] = context.globals[global_var]
                    
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Returning from func " + safe_str_convert(self))
            return return_value

        except KeyError:
            
            # No return value explicitly set. It looks like VBA uses an empty string as
            # these funcion values.
            return ''


# TODO 5.3.1.4 Function Type Declarations
function_start = Optional(CaselessKeyword('Static')) + Optional(CaselessKeyword('Default')) + \
                 Optional(public_private) + \
                 Optional(CaselessKeyword('Static')) + Optional(CaselessKeyword('Default')) + \
                 CaselessKeyword('Function').suppress() + TODO_identifier_or_object_attrib('function_name') + \
                 Optional(params_list_paren) + Optional(function_type2("return_type")) + EOS.suppress()
function_start_single = Optional(CaselessKeyword('Static')) + Optional(CaselessKeyword('Default')) + \
                        Optional(public_private) + \
                        Optional(CaselessKeyword('Static')) + Optional(CaselessKeyword('Default')) + \
                        CaselessKeyword('Function').suppress() + TODO_identifier_or_object_attrib('function_name') + \
                        Optional(params_list_paren) + Optional(function_type2) + Suppress(':')

function_end = (CaselessKeyword('End') + CaselessKeyword('Function') + EOS).suppress() | \
               (bogus_simple_for_each_statement + Suppress(EOS))
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

# --- PROPERTY LET --------------------------------------------------------------------

# Evaluating a property let handler looks like calling a Sub, so inherit from Sub to get the
# eval() method.
class PropertyLet(Sub):
    """Emulate a VBA/VBScript 'Property Let...' statement.

    """
    
    def __init__(self, original_str, location, tokens):
        super(PropertyLet, self).__init__(original_str, location, tokens)
        self.name = tokens.property_name
        self.params = tokens.params
        self.min_param_length = len(self.params)
        for param in self.params:
            if (param.is_optional):
                self.min_param_length -= 1
        self.statements = tokens.statements
        try:
            len(self.statements)
        except TypeError:
            self.statements = [self.statements]
        # Get a dict mapping labeled blocks of code to labels.
        # This will be used to handle GOTO statements when emulating.
        visitor = tagged_block_finder_visitor()
        self.accept(visitor)
        self.tagged_blocks = visitor.blocks
        log.info('parsed %r' % self)

    def __repr__(self):
        return 'Property Let %s (%s): %d statement(s)' % (self.name, self.params, len(self.statements))

# [ Public | Private | Friend ] [ Static ] Property Let name ( [ arglist ], value )
# [ statements ]
# [ Exit Property ]
# [ statements ]
# End Property

property_let = Optional(CaselessKeyword('Static')) + Optional(CaselessKeyword('Default')) + \
               public_private + \
               Optional(CaselessKeyword('Static')) + Optional(CaselessKeyword('Default')) + \
               CaselessKeyword('Property').suppress() + \
               (CaselessKeyword('Let').suppress() | CaselessKeyword('Set').suppress()) + \
               lex_identifier('property_name') + params_list_paren + \
               Group(ZeroOrMore(statements_line)).setResultsName('statements') + \
               (CaselessKeyword('End') + CaselessKeyword('Property') + EOS).suppress()
property_let.setParseAction(PropertyLet)

# --- PROPERTY GET --------------------------------------------------------------------

# Evaluating a property get handler looks like calling a Function, so inherit from Function to get the
# eval() method.
class PropertyGet(Function):

    def __init__(self, original_str, location, tokens):
        super(PropertyGet, self).__init__(original_str, location, tokens)
        self.name = tokens.property_name
        self.params = tokens.params
        self.min_param_length = len(self.params)
        for param in self.params:
            if (param.is_optional):
                self.min_param_length -= 1
        self.statements = tokens.statements
        try:
            len(self.statements)
        except:
            self.statements = [self.statements]
        # Get a dict mapping labeled blocks of code to labels.
        # This will be used to handle GOTO statements when emulating.
        visitor = tagged_block_finder_visitor()
        self.accept(visitor)
        self.tagged_blocks = visitor.blocks
        log.info('parsed %r' % self)

    def __repr__(self):
        return 'Property Get %s (%s): %d statement(s)' % (self.name, self.params, len(self.statements))

property_get = Optional(CaselessKeyword('Static')) + Optional(CaselessKeyword('Default')) + \
               public_private + \
               Optional(CaselessKeyword('Static')) + Optional(CaselessKeyword('Default')) + \
               CaselessKeyword('Property').suppress() + CaselessKeyword('Get').suppress() + \
               lex_identifier('property_name') + Optional(params_list_paren) + \
               Suppress(Optional(CaselessKeyword("As") + type_expression)) + \
               Group(ZeroOrMore(statements_line)).setResultsName('statements') + \
               (CaselessKeyword('End') + CaselessKeyword('Property') + EOS).suppress()
property_get.setParseAction(PropertyGet)

# Ugh. Handle cyclic import problem.
extend_statement_grammar()
