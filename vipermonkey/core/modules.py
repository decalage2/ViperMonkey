#!/usr/bin/env python
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

from comments_eol import *
from procedures import *
from statements import *
import vba_context

from logger import log

# === VBA MODULE AND STATEMENTS ==============================================

# --- MODULE -----------------------------------------------------------------

class Module(VBA_Object):

    def __init__(self, original_str, location, tokens):

        super(Module, self).__init__(original_str, location, tokens)

        self.name = None
        self.code = None  # set by ViperMonkey after parsing
        self.attributes = {}
        self.options = []
        self.functions = {}
        self.external_functions = {}
        self.subs = {}
        self.global_vars = {}
        self.loose_lines = []

        for token in tokens:
            if isinstance(token, If_Statement_Macro):
                for n in token.external_functions.keys():
                    log.debug("saving external func decl: %r" % n)
                    self.external_functions[n] = token.external_functions[n]
            if isinstance(token, Sub):
                log.debug("saving sub decl: %r" % token.name)
                self.subs[token.name] = token
            if isinstance(token, Function):
                log.debug("saving func decl: %r" % token.name)
                self.functions[token.name] = token
            if isinstance(token, External_Function):
                log.debug("saving external func decl: %r" % token.name)
                self.external_functions[token.name] = token
            elif isinstance(token, Attribute_Statement):
                log.debug("saving attrib decl: %r" % token.name)
                self.attributes[token.name] = token.value
            elif isinstance(token, Global_Var_Statement):

                # Global variable initialization is now handled by emulating the
                # LooseLines blocks of code in the module.
                pass
                """
                # Get the initial value(s) for the global variable(s).
                context = vba_context.Context()
                token.eval(context)

                # Set up the global variables.
                for var in token.variables:
                    init_val = "NULL"
                    try:
                        init_val = context.get(var[0])
                    except KeyError:
                        pass
                    log.debug("saving global var decl (0): %r = %r" % (var[0], init_val))
                    self.global_vars[var[0]] = init_val
                """

            elif isinstance(token, Dim_Statement):

                # Add the declared variables to the global variables.
                for var in token.variables:

                    # Get the initial value.
                    curr_init_val = token.init_val
                    
                    # Get initial var value based on type.
                    curr_type = var[2]
                    if ((curr_type is not None) and
                        ((curr_init_val is None) or (curr_init_val is "NULL"))):

                        # Get the initial value.
                        if ((curr_type == "Long") or
                            (curr_type == "Integer") or
                            (curr_type == "Byte")):
                            curr_init_val = 0
                        if (curr_type == "String"):
                            curr_init_val = ''
                
                        # Is this variable an array?
                        if (var[1]):
                            curr_type += " Array"
                            if ((len(var) >= 4) and (var[3] is not None)):
                                curr_init_val = [curr_init_val] * var[3]
                            else:
                                curr_init_val = []
                                
                    # Set the initial value of the declared variable.
                    self.global_vars[var[0]] = curr_init_val
                    log.debug("saving global var decl (1): %r = %r" % (var[0], curr_init_val))

            elif isinstance(token, LooseLines):
                self.loose_lines.append(token)
                    
        self.name = self.attributes.get('VB_Name', None)
        # TODO: should not use print
        print(self)

    def __repr__(self):
        r = 'Module %r\n' % self.name
        for sub in self.subs.values():
            r += '  %r\n' % sub
        for func in self.functions.values():
            r += '  %r\n' % func
        for extfunc in self.external_functions.values():
            r += '  %r\n' % extfunc
        return r

    def eval(self, context, params=None):

        # Emulate the loose line blocks (statements that appear outside sub/func
        # defs) in order.
        for block in self.loose_lines:
            block.eval(context, params)

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

declaration_statement = option_statement | dim_statement | global_variable_declaration | external_function | rem_statement
declaration_statements_line = Optional(declaration_statement + ZeroOrMore(Suppress(':') + declaration_statement)) \
                              + EOL.suppress()

module_declaration = ZeroOrMore(declaration_statements_line)

# 5.3 Module Code Section Structure

# TODO: 5.3.1 Procedure Declarations

# TODO: add rem statememt and others?
empty_line = EOL.suppress()

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

    def eval(self, context, params=None):

        # Exit if an exit function statement was previously called.
        #if (context.exit_func):
        #    return

        # Emulate the statements in the block.
        log.info("Emulating " + str(self) + " ...")
        context.global_scope = True
        for curr_statement in self.block:

            # Is this something we can emulate?
            if (not isinstance(curr_statement, VBA_Object)):
                continue
            curr_statement.eval(context, params=params)

            # Was there an error that will make us jump to an error handler?
            if (context.must_handle_error()):
                break
            
        # Run the error handler if we have one and we broke out of the statement
        # loop with an error.
        context.handle_error(params)
            
loose_lines = OneOrMore(tagged_block ^ (block_statement + EOS.suppress()))('block')
loose_lines.setParseAction(LooseLines)

# TODO: add optional empty lines after each sub/function?
module_code = ZeroOrMore(option_statement | sub | function | Suppress(empty_line) | simple_if_statement_macro | loose_lines)

module_body = module_declaration + module_code

module = module_header + module_body
module.setParseAction(Module)

# === LINE PARSER ============================================================

# Parser matching any line of VBA code:
vba_line = declaration_statements_line \
        | sub_start_line \
        | sub_end \
        | function_start \
        | function_end \
        | for_start \
        | for_end \
        | header_statements_line \
        | simple_statements_line \
        | empty_line
