"""
ViperMonkey: VBA Grammar - Modules

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

# For Python 2+3 support:
from __future__ import print_function

__version__ = '0.02'

# --- IMPORTS ------------------------------------------------------------------

import logging

from comments_eol import *
from procedures import *
from statements import *
import vba_context
from function_defn_visitor import *
from vba_object import to_python

from logger import log

# === VBA MODULE AND STATEMENTS ==============================================

# --- MODULE -----------------------------------------------------------------

class Module(VBA_Object):

    def _handle_func_decls(self, tokens):
        """
        Look for functions/subs declared anywhere, including inside the body 
        of other functions/subs.
        """

        # Look through each parsed item in the module for function/sub
        # definitions.
        for token in tokens:
            if (not hasattr(token, "accept")):
                continue
            func_visitor = function_defn_visitor()
            token.accept(func_visitor)
            for i in func_visitor.func_objects:

                # Sub to add?
                if isinstance(i, Sub):
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("saving sub decl: %r" % i.name)
                    self.subs[i.name] = i

                # Func to add?
                elif isinstance(i, Function):
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("saving func decl: %r" % i.name)
                    self.functions[i.name] = i

                # Property Let function to add?
                elif isinstance(i, PropertyLet):
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("saving property let decl: %r" % i.name)
                    self.props[i.name] = i
        
    def __init__(self, original_str, location, tokens):

        super(Module, self).__init__(original_str, location, tokens)

        self.name = None
        self.code = None  # set by ViperMonkey after parsing
        self.attributes = {}
        self.options = []
        self.functions = {}
        self.props = {}
        self.external_functions = {}
        self.subs = {}
        self.global_vars = {}
        self.loose_lines = []

        # Save all function/sub definitions.
        self._handle_func_decls(tokens)

        # Handle other statements.
        for token in tokens:

            if isinstance(token, If_Statement_Macro):
                for n in token.external_functions.keys():
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("saving external func decl: %r" % n)
                    self.external_functions[n] = token.external_functions[n]

            elif isinstance(token, External_Function):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("saving external func decl: %r" % token.name)
                self.external_functions[token.name] = token

            elif isinstance(token, Attribute_Statement):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("saving attrib decl: %r" % token.name)
                self.attributes[token.name] = token.value

            elif isinstance(token, Global_Var_Statement):

                # Global variable initialization is now handled by emulating the
                # LooseLines blocks of code in the module.
                self.loose_lines.append(token)

            elif isinstance(token, Dim_Statement):

                # Global variable initialization is now handled by emulating the
                # LooseLines blocks of code in the module.
                self.loose_lines.append(token)

            elif isinstance(token, LooseLines):

                # Save the loose lines block itself.
                self.loose_lines.append(token)

                # Function and Sub definitions could be in the loose lines block.
                # Save those also.
                for curr_statement in token.block:
                    if isinstance(curr_statement, External_Function):
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug("saving external func decl: %r" % curr_statement.name)
                        self.external_functions[curr_statement.name] = curr_statement
                    
        self.name = self.attributes.get('VB_Name', None)

    def __repr__(self):
        r = 'Module %r\n' % self.name
        for sub in self.subs.values():
            r += '  %r\n' % sub
        for func in self.functions.values():
            r += '  %r\n' % func
        for extfunc in self.external_functions.values():
            r += '  %r\n' % extfunc
        for prop in self.props.values():
            r += '  %r\n' % func
        return r

    def eval(self, context, params=None):

        # Perform all of the const assignments first.
        for block in self.loose_lines:
            if (isinstance(block, Sub) or
                isinstance(block, Function) or
                isinstance(block, External_Function)):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Skip loose line const eval of " + str(block))
                continue
            if (isinstance(block, LooseLines)):
                context.global_scope = True
                do_const_assignments(block.block, context)
                context.global_scope = False
        
        # Emulate the loose line blocks (statements that appear outside sub/func
        # defs) in order.
        done_emulation = False
        for block in self.loose_lines:
            if (isinstance(block, Sub) or
                isinstance(block, Function) or
                isinstance(block, External_Function)):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Skip loose line eval of " + str(block))
                continue
            context.global_scope = True
            block.eval(context, params)
            context.global_scope = False
            done_emulation = True

        # Return if we ran anything.
        return done_emulation

    def to_python(self, context, params=None, indent=0):
        return to_python(self.loose_lines, context, indent=indent, statements=True)
    
    def load_context(self, context):
        """
        Load functions/subs defined in the module into the given
        context.
        """
        
        for name, _sub in self.subs.items():
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('(1) storing sub "%s" in globals' % name)
            context.set(name, _sub)
            context.set(name, _sub, force_global=True)
        for name, _function in self.functions.items():
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('(1) storing function "%s" in globals' % name)
            context.set(name, _function)
            context.set(name, _function, force_global=True)
        for name, _prop in self.props.items():
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('(1) storing property let "%s" in globals' % name)
            context.set(name, _prop)
            context.set(name, _prop, force_global=True)
        for name, _function in self.external_functions.items():
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('(1) storing external function "%s" in globals' % name)
            context.set(name, _function)
        for name, _var in self.global_vars.items():
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('(1) storing global var "%s" = %s in globals (1)' % (name, str(_var)))
            if (isinstance(name, str)):
                context.set(name, _var)
                context.set(name, _var, force_global=True)
            if (isinstance(name, list)):
                context.set(name[0], _var, var_type=name[1])
                context.set(name[0], _var, var_type=name[1], force_global=True)
            
# see MS-VBAL 4.2 Modules
#
# MS-GRAMMAR: procedural_module_header = CaselessKeyword('Attribute') + CaselessKeyword('VB_Name') + Literal('=') + quoted_string
# MS-GRAMMAR: procedural_module = procedural_module_header + procedural_module_body
# MS-GRAMMAR: class_module = class_module_header + class_module_body
# MS-GRAMMAR: module = procedural_module | class_module

# Module Header:

header_statement = attribute_statement
# TODO: can we have '::' with an empty statement?
header_statements_line = (Optional(header_statement + ZeroOrMore(Suppress(':') + header_statement)) + EOL.suppress()) | \
                         option_statement | \
                         type_declaration | \
                         simple_if_statement_macro
module_header = ZeroOrMore(header_statements_line)

# 5.1 Module Body Structure

# 5.2 Module Declaration Section Structure

# TODO: 5.2.1 Option Directives
# TODO: 5.2.2 Implicit Definition Directives
# TODO: 5.2.3 Module Declarations

loose_lines = Forward()
#declaration_statement = external_function | global_variable_declaration | loose_lines | option_statement | dim_statement | rem_statement
declaration_statement = external_function | loose_lines | global_variable_declaration | \
                        option_statement | dim_statement | rem_statement | type_declaration
declaration_statements_line = Optional(declaration_statement + ZeroOrMore(Suppress(':') + declaration_statement)) \
                              + EOL.suppress()

module_declaration = ZeroOrMore(declaration_statements_line)

# 5.3 Module Code Section Structure

# TODO: 5.3.1 Procedure Declarations

# TODO: add rem statememt and others?
empty_line = EOL.suppress()

pointless_empty_tuple = Suppress('(') + Suppress(')')

class LooseLines(VBA_Object):
    """
    A list of Visual Basic statements that don't appear in a Sub or Function.
    This is mainly appicable to VBScript files.
    """

    def __init__(self, original_str, location, tokens):
        super(LooseLines, self).__init__(original_str, location, tokens)
        self.block = tokens.block
        log.info('parsed %r' % self)

    def __repr__(self):
        s = repr(self.block)
        if (len(s) > 35):
            s = s[:35] + " ...)"
        return 'Loose Lines Block: %s: %s statement(s)' % (s, len(self.block))

    def to_python(self, context, params=None, indent=0):
        return to_python(self.block, context, indent=indent, statements=True)
    
    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        #if (context.exit_func):
        #    return

        # Assign all const variables first.
        do_const_assignments(self.block, context)
        
        # Emulate the statements in the block.
        log.info("Emulating " + str(self) + " ...")
        context.global_scope = True
        for curr_statement in self.block:

            # Don't emulate declared functions.
            if (isinstance(curr_statement, Sub) or
                isinstance(curr_statement, Function) or
                isinstance(curr_statement, External_Function)):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Skip loose line eval of " + str(curr_statement))
                continue
            
            # Is this something we can emulate?
            if (not isinstance(curr_statement, VBA_Object)):
                continue
            curr_statement.eval(context, params=params)

            # Was there an error that will make us jump to an error handler?
            if (context.must_handle_error()):
                break
            context.clear_error()
            
        # Run the error handler if we have one and we broke out of the statement
        # loop with an error.
        context.handle_error(params)
            
loose_lines <<= OneOrMore(pointless_empty_tuple ^ simple_call_list ^ tagged_block ^ (block_statement + EOS.suppress()) ^ orphaned_marker)('block')
loose_lines.setParseAction(LooseLines)

# TODO: add optional empty lines after each sub/function?
module_code = ZeroOrMore(
    option_statement
    | sub
    | function
    | property_let
    | Suppress(empty_line)
    | simple_if_statement_macro
    | loose_lines
    | type_declaration
)

module_body = module_declaration + module_code

#module = module_header + module_body
module = ZeroOrMore(
    option_statement
    | sub
    | function
    | property_let
    | Suppress(empty_line)
    | simple_if_statement_macro
    | loose_lines
    | type_declaration
    | declaration_statements_line
    | header_statements_line
)
module.setParseAction(Module)

# === LINE PARSER ============================================================

# Parser matching any line of VBA code:
vba_line = (
    sub_start_line
    | sub_end
    | function_start
    | function_end
    | for_start
    | for_end
    | header_statements_line
    # check if we have a basic literal before checking simple_statement_line
    # otherwise we will get things like "Chr(36)" being reported as a Call_Statement
    | (expr_const + EOL.suppress())
    | simple_statements_line
    | declaration_statements_line
    | empty_line
    | (expression + EOL.suppress())
)
