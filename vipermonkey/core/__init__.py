#!/usr/bin/env python
"""
ViperMonkey: core package - ViperMonkey class

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

# ------------------------------------------------------------------------------
# CHANGELOG:
# 2015-02-12 v0.01 PL: - first prototype
# 2015-2016        PL: - many updates
# 2016-06-11 v0.02 PL: - split vipermonkey into several modules
# 2016-11-05 v0.03 PL: - fixed issue #13 in scan_expressions, context was missing

__version__ = '0.03'

# ------------------------------------------------------------------------------
# TODO:
# TODO: detect subs/functions with same name (in different modules)
# TODO: can several projects call each other?
# TODO: Word XML with several projects?
# - cleanup main, use optionparser
# - option -e to extract and evaluate constant expressions
# - option -t to trace execution
# - option --entrypoint to specify the Sub name to use as entry point
# - use olevba to get all modules from a file
# Environ => VBA object
# vbCRLF, etc => Const (parse to string)
# py2vba: convert python string to VBA string, e.g. \" => "" (for olevba to scan expressions) - same thing for ints, etc?
# TODO: expr_int / expr_str
# TODO: eval(parent) => for statements to set local variables into parent functions/procedures + main VBA module
# TODO: __repr__ for printing
# TODO: Environ('str') => '%str%'
# TODO: determine the order of Auto subs for Word, Excel

# TODO later:
# - add VBS support (two modes?)

# ------------------------------------------------------------------------------
# REFERENCES:
# - [MS-VBAL]: VBA Language Specification
#   https://msdn.microsoft.com/en-us/library/dd361851.aspx
# - [MS-OVBA]: Microsoft Office VBA File Format Structure
#   http://msdn.microsoft.com/en-us/library/office/cc313094%28v=office.12%29.aspx


# --- IMPORTS ------------------------------------------------------------------

# TODO: add pyparsing to thirdparty folder, update setup.py
from pyparsing import *

# Enable PackRat for better performance:
# (see https://pythonhosted.org/pyparsing/pyparsing.ParserElement-class.html#enablePackrat)
ParserElement.enablePackrat()

# TODO: replace with tablestream
import prettytable

from logger import log


# === VBA GRAMMAR =====================================================================================================

from vba_lines import *
from modules import *

# Make sure we populate the VBA Library:
from vba_library import *

# === ViperMonkey class ======================================================

class ViperMonkey(object):
    # TODO: load multiple modules from a file using olevba

    def __init__(self):
        self.modules = []
        self.modules_code = []
        self.globals = {}
        # list of actions (stored as tuples by report_action)
        self.actions = []

    def add_module(self, vba_code):
        # collapse long lines ending with " _"
        vba_code = vba_collapse_long_lines(vba_code)
        # log.debug('Parsing VBA Module:\n' + vba_code)
        try:
            m = module.parseString(vba_code, parseAll=True)[0]
            # store the code in the module object:
            m.code = vba_code
            self.modules.append(m)
            # TODO: add all subs/functions and global variables to self.globals
            for name, _sub in m.subs.items():
                log.debug('storing sub "%s" in globals' % name)
                self.globals[name.lower()] = _sub
            for name, _function in m.functions.items():
                log.debug('storing function "%s" in globals' % name)
                self.globals[name.lower()] = _function
            for name, _function in m.external_functions.items():
                log.debug('storing external function "%s" in globals' % name)
                self.globals[name.lower()] = _function
        except ParseException as err:
            print('*** PARSING ERROR ***')
            print(err.line)
            print(" " * (err.column - 1) + "^")
            print(err)

    def add_module2(self, vba_code):
        """
        add VBA code for a module and parse it using the alternate line parser
        :param vba_code: str, VBA code
        :return: None
        """
        # collapse long lines ending with " _"
        vba_code = vba_collapse_long_lines(vba_code)
        # log.debug('Parsing VBA Module:\n' + vba_code)
        m = Module(original_str=vba_code, location=0, tokens=[])
        # store the code in the module object:
        m.code = vba_code
        # parse lines one by one:
        lines = vba_code.splitlines(True)
        for i in range(len(lines)):
            line = lines[i]
            log.debug('Parsing line %d: %s' % (i, line))
            try:
                l = vba_line.parseString(line, parseAll=True)
                print(l)
            except ParseException as err:
                print('*** PARSING ERROR ***')
                print(err.line)
                print(" " * (err.column - 1) + "^")
                print(err)
        # self.modules.append(m)
        # # TODO: add all subs/functions and global variables to self.globals
        # for name, _sub in m.subs.items():
        #     log.debug('storing sub "%s" in globals' % name)
        #     self.globals[name.lower()] = _sub
        # for name, _function in m.functions.items():
        #     log.debug('storing function "%s" in globals' % name)
        #     self.globals[name.lower()] = _function
        # for name, _function in m.external_functions.items():
        #     log.debug('storing external function "%s" in globals' % name)
        #     self.globals[name.lower()] = _function

    def trace(self, entrypoint='*auto'):
        # TODO: use the provided entrypoint
        # Create the global context for the engine
        context = Context(_globals=self.globals, engine=self)
        # reset the actions list, in case it is called several times
        self.actions = []
        # TODO: look for ALL auto* subs, in the same order as MS Office
        # TODO: how to handle auto subs calling other auto subs?
        for entry_point in ('autoopen', 'workbook_open', 'document_open'):
            if entry_point in self.globals:
                self.globals[entry_point].eval(context=context)

    def eval(self, expr):
        """
        Parse and evaluate a single VBA expression
        :param expr: str, expression to be evaluated
        :return: value of the evaluated expression
        """
        # Create the global context for the engine
        context = Context(_globals=self.globals, engine=self)
        # reset the actions list, in case it is called several times
        self.actions = []
        e = expression.parseString(expr)[0]
        log.debug('e=%r - type=%s' % (e, type(e)))
        value = e.eval(context=context)
        return value

    def report_action(self, action, params=None, description=None):
        """
        Callback function for each evaluated statement to report macro actions
        """
        # store the action for later use:
        self.actions.append((action, params, description))
        log.info("ACTION: %s - params %r - %s" % (action, params, description))

    def dump_actions(self):
        """
        return a table of all actions recorded by trace(), as a prettytable object
        that can be printed or reused.
        """
        t = prettytable.PrettyTable(('Action', 'Parameters', 'Description'))
        t.align = 'l'
        t.max_width['Action'] = 20
        t.max_width['Parameters'] = 25
        t.max_width['Description'] = 25
        for action in self.actions:
            t.add_row(action)
        return t


def scan_expressions(vba_code):
    """
    Scan VBA code to extract constant VBA expressions, i.e. expressions
    that can be evaluated as a constant value. Iterate over these expressions,
    yield the expression and its evaluated value as a tuple.

    :param vba_code: str, VBA source code
    :return: iterator, yield (expression, evaluated value)
    """
    # context to evaluate expressions:
    context = Context()
    for m in expr_const.scanString(vba_code):
        e = m[0][0]
        # only yield expressions which are not plain constants
        # a VBA expression should have an eval() method:
        if hasattr(e, 'eval'):
            # print 'eval(%s) = %s' % (repr(e), repr(e.eval()))
            # print repr(e.eval())
            yield (e, e.eval(context))


# Soundtrack: This code was developed while listening to The Chameleons "Monkeyland"