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
# 2016-12-17 v0.04 PL: - improved line-based parser (issue #2)
# 2016-12-18       PL: - line parser: added support for sub/functions (issue #2)

__version__ = '0.04'

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

import sys

# TODO: add pyparsing to thirdparty folder, update setup.py
from pyparsing import *

# TODO: replace with tablestream
import prettytable

# sudo pypy -m pip install unidecode
import unidecode
import string

from logger import log
from procedures import Function
from procedures import Sub
from function_call_visitor import *
from function_defn_visitor import *
from function_import_visitor import *
from var_defn_visitor import *

# === FUNCTIONS ==============================================================

def list_startswith(_list, lstart):
    """
    Check if a list (_list) starts with all the items from another list (lstart)
    :param _list: list
    :param lstart: list
    :return: bool, True if _list starts with all the items of lstart.
    """
    # log.debug('list_startswith: %r <? %r' % (_list, lstart))
    if _list is None:
        return False
    lenlist = len(_list)
    lenstart = len(lstart)
    if lenlist >= lenstart:
        # if _list longer or as long as lstart, check 1st items:
        # log.debug('_list[:lenstart] = %r' % _list[:lenstart])
        return (_list[:lenstart] == lstart)
    else:
        # _list smaller than lstart: always false
        return False


# === VBA GRAMMAR ============================================================

from vba_lines import *
from modules import *

# Make sure we populate the VBA Library:
from vba_library import *

# === ViperMonkey class ======================================================

class ViperMonkey(object):
    # TODO: load multiple modules from a file using olevba

    def __init__(self, filename):
        self.filename = filename
        self.modules = []
        self.modules_code = []
        self.globals = {}
        # list of actions (stored as tuples by report_action)
        self.actions = []

        # Track the loaded Excel spreadsheet (xlrd).
        self.loaded_excel = None
        
        # Track data saved in document variables.
        self.doc_vars = {}

        # Track document text.
        self.doc_text = ""
        
        # List of entry point functions to emulate.
        self.entry_points = ['autoopen', 'document_open', 'autoclose',
                             'document_close', 'auto_open', 'autoexec',
                             'autoexit', 'document_beforeclose', 'workbook_open',
                             'workbook_activate', 'auto_close', 'workbook_close',
                             'workbook_deactivate', 'documentopen', 'app_documentopen']

        # List of suffixes of the names of callback functions that provide alternate
        # methods for running things on document (approximately) open.
        # See https://www.greyhathacker.net/?m=201609
        self.callback_suffixes = ['_Activate',
                                  '_BeforeNavigate2',
                                  '_BeforeScriptExecute',
                                  '_Change',
                                  '_DocumentComplete',
                                  '_DownloadBegin',
                                  '_DownloadComplete',
                                  '_FileDownload',
                                  '_GotFocus',
                                  '_Layout',
                                  '_LostFocus',
                                  '_MouseEnter',
                                  '_MouseHover',
                                  '_MouseLeave',
                                  '_MouseMove',
                                  '_NavigateComplete2',
                                  '_NavigateError',
                                  '_Painted',
                                  '_Painting',
                                  '_ProgressChange',
                                  '_PropertyChange',
                                  '_Resize',
                                  '_SetSecureLockIcon',
                                  '_StatusTextChange',
                                  '_TitleChange',
                                  '_Initialize',
                                  '_Click',
                                  '_BeforeClose']
                                  
    def add_compiled_module(self, m):
        """
        Add an already parsed and processed module.
        """
        if (m is None):
            return
        self.modules.append(m)
        for name, _sub in m.subs.items():
            log.debug('(1) storing sub "%s" in globals' % name)
            self.globals[name.lower()] = _sub
        for name, _function in m.functions.items():
            log.debug('(1) storing function "%s" in globals' % name)
            self.globals[name.lower()] = _function
        for name, _function in m.external_functions.items():
            log.debug('(1) storing external function "%s" in globals' % name)
            self.globals[name.lower()] = _function
        for name, _var in m.global_vars.items():
            log.debug('(1) storing global var "%s" = %s in globals (1)' % (name, str(_var)))
            if (isinstance(name, str)):
                self.globals[name.lower()] = _var
            if (isinstance(name, list)):
                self.globals[name[0].lower()] = _var
                self.types[name[0].lower()] = name[1]
        
    def add_module(self, vba_code):

        # collapse long lines ending with " _"
        vba_code = vba_collapse_long_lines(vba_code)

        # Parse the VBA.
        try:
            m = module.parseString(vba_code, parseAll=True)[0]
            # store the code in the module object:
            m.code = vba_code
            self.add_compiled_module(m)

        except ParseException as err:
            print('*** PARSING ERROR (1) ***')
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
        # m = Module(original_str=vba_code, location=0, tokens=[])
        # # store the code in the module object:
        # m.code = vba_code
        # parse lines one by one:
        self.lines = vba_code.splitlines(True)
        tokens = []
        self.line_index = 0
        while self.lines:
            line_index, line, line_keywords = self.parse_next_line()
            # ignore empty lines
            if line_keywords is None:
                log.debug('Empty line or comment: ignored')
                continue
            try:
                # flag set to True when line starts with "public" or "private":
                pub_priv = False
                if line_keywords[0] in ('public', 'private'):
                    pub_priv = True
                    # remove the public/private keyword:
                    line_keywords = line_keywords[1:]
                if line_keywords[0] == 'attribute':
                    l = header_statements_line.parseString(line, parseAll=True)
                elif line_keywords[0] in ('option', 'dim', 'declare'):
                    log.debug('DECLARATION LINE')
                    l = declaration_statements_line.parseString(line, parseAll=True)
                elif line_keywords[0] == 'sub':
                    log.debug('SUB')
                    l = sub_start_line.parseString(line, parseAll=True)
                    l[0].statements = self.parse_block(end=['end', 'sub'])
                elif line_keywords[0] == 'function':
                    log.debug('FUNCTION')
                    l = function_start_line.parseString(line, parseAll=True)
                    l[0].statements = self.parse_block(end=['end', 'function'])
                elif line_keywords[0] == 'for':
                    log.debug('FOR LOOP')
                    # NOTE: a for clause may be followed by ":" and statements on the same line
                    l = for_start.parseString(line) #, parseAll=True)
                    l[0].statements = self.parse_block(end=['next'])
                else:
                    l = vba_line.parseString(line, parseAll=True)
                log.debug(l)
                # if isinstance(l[0], Sub):
                #     # parse statements
                #     pass
                # l is a list of tokens: add it to the module tokens
                tokens.extend(l)
            except ParseException as err:
                print('*** PARSING ERROR (2) ***')
                print(err.line)
                print(" " * (err.column - 1) + "^")
                print(err)
            self.line_index += 1
        # Create the module object once we have all the tokens:
        m = Module(original_str=vba_code, location=0, tokens=tokens)
        self.modules.append(m)
        # # TODO: add all subs/functions and global variables to self.globals
        for name, _sub in m.subs.items():
            log.debug('(2) storing sub "%s" in globals' % name)
            self.globals[name.lower()] = _sub
        for name, _function in m.functions.items():
            log.debug('(2) storing function "%s" in globals' % name)
            self.globals[name.lower()] = _function
        for name, _function in m.external_functions.items():
            log.debug('(2) storing external function "%s" in globals' % name)
            self.globals[name.lower()] = _function
        for name, _var in m.global_vars.items():
                log.debug('(2) storing global var "%s" in globals (2)' % name)
            
    def parse_next_line(self):
        # extract next line
        line = self.lines.pop(0)
        log.debug('Parsing line %d: %s' % (self.line_index, line.rstrip()))
        self.line_index += 1
        # extract first two keywords in lowercase, for quick matching
        line_keywords = line.lower().split(None, 2)
        log.debug('line_keywords: %r' % line_keywords)
        # ignore empty lines
        if len(line_keywords) == 0 or line_keywords[0].startswith("'"):
            # log.debug('Empty line or comment: ignored')
            return self.line_index-1, line, None
        return self.line_index-1, line, line_keywords

    def parse_block(self, end=['end', 'sub']):
        """
        Parse a block of statements, until reaching a line starting with the end string
        :param end: string indicating the end of the block
        :return: list of statements (excluding the last line matching end)
        """
        statements = []
        line_index, line, line_keywords = self.parse_next_line()
        while not list_startswith(line_keywords, end):
            try:
                l = vba_line.parseString(line, parseAll=True)
                log.debug(l)
                statements.extend(l)
            except ParseException as err:
                print('*** PARSING ERROR (3) ***')
                print(err.line)
                print(" " * (err.column - 1) + "^")
                print(err)
            line_index, line, line_keywords = self.parse_next_line()
        return statements

    def _get_external_funcs(self):
        """
        Get a list of external functions called in the macros.
        """

        # Get the names of all called functions, local functions, and defined variables.
        call_visitor = function_call_visitor()
        defn_visitor = function_defn_visitor()
        var_visitor = var_defn_visitor()
        import_visitor = function_import_visitor()
        for module in self.modules:
            module.accept(call_visitor)
            module.accept(defn_visitor)
            module.accept(var_visitor)
            module.accept(import_visitor)

        # Eliminate variables and local functions from the list of called functions.
        r = []
        for f in call_visitor.called_funcs:
            if ((f in defn_visitor.funcs) or
                (f in var_visitor.variables) or
                (len(f) == 0) or
                (("." in f) and (not "Shell" in f))):
                continue

            # Resolve aliases of imported functions to the actual function.
            if (f in import_visitor.aliases):
                if (len(import_visitor.funcs[f]) > 0):
                     r.append(import_visitor.funcs[f])
                continue

            # Regular local function call.
            r.append(f)

        # Sort and return the fingerprint function list.
        r.sort()
        return r
        
    def trace(self, entrypoint='*auto'):
        # TODO: use the provided entrypoint
        # Create the global context for the engine
        context = Context(_globals=self.globals,
                          engine=self,
                          doc_vars=self.doc_vars,
                          loaded_excel=self.loaded_excel,
                          filename=self.filename)

        # Save the document text in the proper variable in the context.
        context.globals["ActiveDocument.Content.Text".lower()] = "\n".join(self.doc_text)
        context.globals["ActiveDocument.Range.Text".lower()] = "\n".join(self.doc_text)
        context.globals["ActiveDocument.Content.Start".lower()] = 0
        context.globals["ActiveDocument.Content.End".lower()] = len("\n".join(self.doc_text))
        context.globals["ActiveDocument.Paragraphs".lower()] = self.doc_text
        
        # reset the actions list, in case it is called several times
        self.actions = []

        # Track the external functions called.
        self.external_funcs = self._get_external_funcs()

        # First emulate any Visual Basic that appears outside of subs/funcs.
        log.info("Emulating loose statements...")
        done_emulation = False
        for m in self.modules:
            if (m.eval(context=context)):
                done_emulation = True
        
        # Look for hardcoded entry functions.
        for entry_point in self.entry_points:
            entry_point = entry_point.lower()
            log.debug("Trying entry point " + entry_point)
            if entry_point in self.globals:
                context.report_action('Found Entry Point', str(entry_point), '')
                self.globals[entry_point].eval(context=context)
                context.dump_all_files()
                done_emulation = True

        # Look for callback functions that can act as entry points.
        for name in self.globals.keys():

            # Look for functions whose name ends with a callback suffix.
            for suffix in self.callback_suffixes:

                # Is this a callback?
                if (str(name).lower().endswith(suffix.lower())):

                    # Is this a function?
                    item = self.globals[name]
                    if (isinstance(item, Function) or isinstance(item, Sub)):

                        # Emulate it.
                        context.report_action('Found Entry Point', str(name), '')
                        item.eval(context=context)
                        context.dump_all_files()
                        done_emulation = True

        # Did we find an entry point?
        if (not done_emulation):

            # Count the # of subroutines in the document.
            only_sub = None
            sub_name = None
            sub_count = 0
            for name in self.globals.keys():
                item = self.globals[name]
                if (isinstance(item, Sub)):
                    only_sub = item
                    sub_name = name
                    sub_count += 1

            # If there is only 1 subroutine, emulate that.
            if (sub_count == 1):
                context.report_action('Found Entry Point', str(sub_name), '')
                only_sub.eval(context=context)
                context.dump_all_files()
                
    def eval(self, expr):
        """
        Parse and evaluate a single VBA expression
        :param expr: str, expression to be evaluated
        :return: value of the evaluated expression
        """
        # Create the global context for the engine
        context = Context(_globals=self.globals,
                          engine=self,
                          doc_vars=self.doc_vars,
                          loaded_excel=self.loaded_excel)
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
        try:
            if (isinstance(action, str)):
                action = unidecode.unidecode(action.decode('unicode-escape'))
        except UnicodeDecodeError:
            action = ''.join(filter(lambda x:x in string.printable, action))
        if (isinstance(params, str)):
            try:
                decoded = params.replace("\\", "#ESCAPED_SLASH#").decode('unicode-escape').replace("#ESCAPED_SLASH#", "\\")
                params = unidecode.unidecode(decoded)
            except Exception as e:
                log.warn("Unicode decode of action params failed. " + str(e))
                params = ''.join(filter(lambda x:x in string.printable, params))
        try:
            if (isinstance(description, str)):
                description = unidecode.unidecode(description.decode('unicode-escape'))
        except UnicodeDecodeError as e:
            log.warn("Unicode decode of action description failed. " + str(e))
            description = ''.join(filter(lambda x:x in string.printable, description))
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
            yield (e, e.eval(context))


# Soundtrack: This code was developed while listening to The Chameleons "Monkeyland"
