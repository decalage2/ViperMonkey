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


# ------------------------------------------------------------------------------
# CHANGELOG:
# 2015-02-12 v0.01 PL: - first prototype
# 2015-2016        PL: - many updates
# 2016-06-11 v0.02 PL: - split vipermonkey into several modules

__version__ = '0.02'

# ------------------------------------------------------------------------------
# TODO:

# --- IMPORTS ------------------------------------------------------------------

from procedures import *

from logger import log
log.debug('importing modules')

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
        # print tokens
        # print 'Module.init:'
        # pprint.pprint(tokens.asList())
        for token in tokens:
            if isinstance(token, Sub):
                self.subs[token.name] = token
            if isinstance(token, Function):
                self.functions[token.name] = token
            if isinstance(token, External_Function):
                self.external_functions[token.name] = token
            elif isinstance(token, Attribute_Statement):
                self.attributes[token.name] = token.value
        self.name = self.attributes.get('VB_Name', None)
        print self

    # def trace(self, entrypoint='*auto'):
    #     print self.subs['AutoOpen'].eval()

    def __repr__(self):
        r = 'Module %r\n' % self.name
        for sub in self.subs.itervalues():
            r += '  %r\n' % sub
        for func in self.functions.itervalues():
            r += '  %r\n' % func
        for extfunc in self.external_functions.itervalues():
            r += '  %r\n' % extfunc
        return r


# see MS-VBAL 4.2 Modules

# procedural_module_header = CaselessKeyword('Attribute') + CaselessKeyword('VB_Name') + Literal('=') + quoted_string

# procedural_module = procedural_module_header + procedural_module_body
# class_module = class_module_header + class_module_body

# module = procedural_module | class_module

# Module Header:

header_statement = attribute_statement
# TODO: can we have '::' with an empty statement?
header_statements_line = Optional(header_statement + ZeroOrMore(Suppress(':') + header_statement)) + EOL.suppress()
# module_header = ZeroOrMore(header_statements_line)
module_header = OneOrMore(header_statements_line)

# 5.1 Module Body Structure

# 5.2 Module Declaration Section Structure

# TODO: 5.2.1 Option Directives
# TODO: 5.2.2 Implicit Definition Directives
# TODO: 5.2.3 Module Declarations

declaration_statement = option_statement | dim_statement | external_function | unknown_statement
declaration_statements_line = Optional(declaration_statement + ZeroOrMore(Suppress(':') + declaration_statement)) \
                              + EOL.suppress()

module_declaration = ZeroOrMore(declaration_statements_line)

# 5.3 Module Code Section Structure

# TODO: 5.3.1 Procedure Declarations

# TODO: add rem statememt and others?
empty_line = EOL.suppress()

# TODO: add optional empty lines after each sub/function?
module_code = ZeroOrMore(sub | function | empty_line)  # + ZeroOrMore(empty_line)

module_body = module_declaration + module_code

module = module_header + module_body
module.setParseAction(Module)


# module = ZeroOrMore(sub | function | statements_line).setParseAction(Module)


