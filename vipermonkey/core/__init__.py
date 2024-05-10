"""@package vipermonkey.core.__init__ Definition of the main
ViperMonkey emulator class.

"""

# pylint: disable=pointless-string-statement
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
import logging
import string
import re

from pyparsing import ParseException
import prettytable

from logger import log
from procedures import Function
from procedures import Sub
from function_call_visitor import function_call_visitor
from function_defn_visitor import function_defn_visitor
from function_import_visitor import function_import_visitor
from var_defn_visitor import var_defn_visitor
import filetype
import read_ole_fields
from meta import FakeMeta
from vba_lines import vba_collapse_long_lines
from modules import module
# Make sure we populate the VBA Library:
import vba_library
from stubbed_engine import StubbedEngine
import expressions
import vba_context
import excel
from utils import safe_str_convert

# === FUNCTIONS ==============================================================

def list_startswith(_list, lstart):
    """Check if a list (_list) starts with all the items from another
    list (lstart).

    @param _list (list) The 1st list.

    @param lstart (list) The 2nd list.

    @return (boolean) True if _list starts with all the items of
    lstart, False if not.

    """
    if _list is None:
        return False
    lenlist = len(_list)
    lenstart = len(lstart)
    if lenlist >= lenstart:
        # if _list longer or as long as lstart, check 1st items:
        return (_list[:lenstart] == lstart)
    # _list smaller than lstart: always false
    return False


# === VBA GRAMMAR ============================================================

def pull_urls_excel_sheets(workbook):
    """Pull URLs from cells in a given ExcelBook object.

    @param workbook (ExcelBook object) The Excel workbook to process.

    @return (set) A set of all URLs (str) found in Excel cells.

    """

    # Got an Excel workbook?
    if (workbook is None):
        return set()

    # Look through each cell.
    all_cells = excel.pull_cells_workbook(workbook)
    r = set()
    for cell in all_cells:

        # Skip empty cells.
        value = None
        try:
            value = safe_str_convert(cell["value"]).strip()
        except UnicodeEncodeError:
            value = ''.join(filter(lambda x:x in string.printable, cell["value"])).strip()

        if (len(value) == 0):
            continue
        
        # Add http:// for cells that look like they might be URLs
        # missing the http part.        
        pat = r"[A-Za-z0-9_]{3,50}\.[A-Za-z]{2,10}/(?:[A-Za-z0-9_]{1,50}/)*[A-Za-z0-9_\.]{3,50}"
        if (re.search(pat, value) is not None):
            value = "http://" + value

        # Look for URLs in the cell value.
        for url in re.findall(read_ole_fields.URL_REGEX, value):
            r.add(url.strip())

    # Return any URLs found in cells.
    return r

def pull_b64_excel_sheets(workbook):
    """Pull bas64 blobs from cells in a given ExcelBook object.

    @param workbook (ExcelBook object) The Excel workbook to process.

    @return (set) A set of all base64 blobs (str) found in Excel
    cells.

    """

    # Got an Excel workbook?
    if (workbook is None):
        return set()

    # Track potential base64 encoded PE files spread out over
    # multiple cells.
    pe_blobs = []
    curr_pe_blob = None
    
    # Look through each cell.
    all_cells = excel.pull_cells_workbook(workbook)
    r = set()
    for cell in all_cells:

        # Skip empty cells.
        value = None
        try:
            value = safe_str_convert(cell["value"]).strip()
        except UnicodeEncodeError:
            value = ''.join(filter(lambda x:x in string.printable, cell["value"])).strip()

        if (len(value) == 0):
            continue

        # Is this the start of a PE file?
        if (value.strip().startswith("TVqQ") and (len(value) > 100)):

            # Are we already tracking a PE file?
            if (curr_pe_blob is not None):
                pe_blobs.append(curr_pe_blob)

            # Start a new PE blob.
            curr_pe_blob = ""
        
        # Look for strict base64 strings in the cell value.
        base64_pat_strict = r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{0,4}=?=?)?"
        for b64 in re.findall(base64_pat_strict, value):
            b64 = b64.strip()
            r.add(b64)

        # Look for loose, possibly broken up, base64 values.
        if (curr_pe_blob is not None):
            base64_pat_loose = r"[A-Za-z0-9\+/=]{40,}"
            for b64 in re.findall(base64_pat_loose, value):
                b64 = b64.strip()
                curr_pe_blob += b64

    # Save the last base64 encode PE blob.
    if (curr_pe_blob is not None):
        pe_blobs.append(curr_pe_blob)
    for pe_blob in pe_blobs:
        r.add(pe_blob)
                
    # Return any base64 found in cells.
    return r

# === ViperMonkey class ======================================================

class ViperMonkey(StubbedEngine):
    """This is the main class defining the top level VBA/VBScript
    emulator.

    """
    
    # TODO: load multiple modules from a file using olevba

    def __init__(self, filename, data, do_jit=False):
        """Create a new VBA/VBScript emulator object.

        @param filename (str) The name of the file being analyzed.

        @param data (str) The VBA/VBScript code to emulate.

        @param do_jit (boolean) If True use JIT transpilation of VB
        code to Python to speed up loop analysis, if False just
        emulate loops using the regular emulation engine.

        """
        super(ViperMonkey, self).__init__()
        
        self.do_jit = do_jit
        self.comments = None
        self.metadata = None
        self.filename = filename
        self.data = data
        self.modules = []
        self.modules_code = []
        self.decoded_strs = set()
        self.globals = {}
        self.externals = {}
        # list of actions (stored as tuples by report_action)
        self.actions = []
        self.vba = None

        # Figure out whether this is VBScript or VBA.
        vba_pointer = self.filename
        is_data = False
        if ((self.filename is None) or (len(self.filename.strip()) == 0)):
            vba_pointer = self.data
            is_data = True
        self.is_vbscript = False
        if (filetype.is_office_file(vba_pointer, is_data)):
            self.is_vbscript = False
            log.info("Emulating an Office (VBA) file.")
        else:
            self.is_vbscript = True
            log.info("Emulating a VBScript file.")
        #print "\n\nREMOVE THIS!!\n\n"
        #self.is_vbscript = False
            
        # Olevba uses '\n' as EOL, regular VBScript uses '\r\n'.
        if self.is_vbscript:
            vba_library.VBA_LIBRARY['vbCrLf'] = '\r\n'
            
        # Track the loaded Excel spreadsheet (xlrd).
        self.loaded_excel = None
        
        # Track data saved in document variables.
        self.doc_vars = {}

        # Track document text.
        self.doc_text = ""

        # Track document tables.
        self.doc_tables = []
        
        # List of entry point functions to emulate.
        self.entry_points = ['autoopen', 'document_open', 'autoclose',
                             'document_close', 'auto_open', 'autoexec',
                             'autoexit', 'document_beforeclose', 'workbook_open',
                             'workbook_activate', 'auto_close', 'workbook_close',
                             'workbook_deactivate', 'documentopen', 'app_documentopen',
                             'main']

        # List of user-specified entry points. If non-empty only these entry points
        # will be used.
        self.user_entry_points = []

        # List of suffixes of the names of callback functions that provide alternate
        # methods for running things on document (approximately) open.
        # See https://www.greyhathacker.net/?m=201609
        self.callback_suffixes = ['_Activate',
                                  '_BeforeNavigate2',
                                  '_BeforeScriptExecute',
                                  '_Calculate',
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
                                  '_OnConnecting',
                                  '_BeforeClose',
                                  '_OnDisconnected',
                                  '_OnEnterFullScreenMode',
                                  '_Zoom',
                                  '_Scroll',
                                  '_BeforeDropOrPaste']
                                  
    def set_metadata(self, dat):
        """Save Office metadata of the file being analyzed.

        @pram dat (dict) A mapping from metadata field names to
        metadata vales.

        """
        
        # Handle meta information represented as a dict.
        new_dat = dat
        if (isinstance(dat, dict)):
            new_dat = FakeMeta()
            for field in dat.keys():
                setattr(new_dat, safe_str_convert(field), dat[field])
        self.metadata = new_dat
        
    def add_compiled_module(self, m, stream):
        """Add an already parsed and processed module.

        @param m (Module object) The parsed object.

        @param stream (str) The OLE stream name containing the module.

        """
        if (m is None):
            return
        self.modules.append(m)
        for name, _sub in m.subs.items():

            # Append the stream name for duplicate subs
            if (name in self.globals):
                new_name = safe_str_convert(stream) + "::" + safe_str_convert(name)
                log.warn("Renaming duplicate function " + name + " to " + new_name)
                name = new_name

            # Save the sub.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('(1) storing sub "%s" in globals' % name)
            self.globals[name.lower()] = _sub
            self.globals[name] = _sub

        # Functions.
        for name, _function in m.functions.items():
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('(1) storing function "%s" in globals' % name)
            self.globals[name.lower()] = _function
            self.globals[name] = _function

        # Properties.
        for name, _prop in m.functions.items():
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('(1) storing property let "%s" in globals' % name)
            self.globals[name.lower()] = _prop
            self.globals[name] = _prop

        # External DLL functions.
        for name, _function in m.external_functions.items():
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('(1) storing external function "%s" in globals' % name)
            self.globals[name.lower()] = _function
            self.externals[name.lower()] = _function

        # Global variables.
        for name, _var in m.global_vars.items():
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('(1) storing global var "%s" = %s in globals (1)' % (name, safe_str_convert(_var)))
            if (isinstance(name, str)):
                self.globals[name.lower()] = _var
            if (isinstance(name, list)):
                self.globals[name[0].lower()] = _var
                self.types[name[0].lower()] = name[1]
        
    def add_module(self, vba_code):
        """Parse and then add the given VBA module.

        @param vba_code (str) The module source code.

        """
        
        # collapse long lines ending with " _"
        vba_code = vba_collapse_long_lines(vba_code)

        # Parse the VBA.
        try:
            m = module.parseString(vba_code, parseAll=True)[0]
            # store the code in the module object:
            m.code = vba_code
            self.add_compiled_module(m)

        except ParseException as err:
            print '*** PARSING ERROR (1) ***'
            print err.line
            print " " * (err.column - 1) + "^"
            print err
            
    def _get_external_funcs(self):
        """Get a list of external (or VB builtin) functions called in the
        VBA/VBScript code.

        @return (list) The names of called external (or VB builtin)
        functions.

        """

        # Get the names of all called functions, local functions, and defined variables.
        call_visitor = function_call_visitor()
        defn_visitor = function_defn_visitor()
        var_visitor = var_defn_visitor()
        import_visitor = function_import_visitor()
        for curr_module in self.modules:
            curr_module.accept(call_visitor)
            curr_module.accept(defn_visitor)
            curr_module.accept(var_visitor)
            curr_module.accept(import_visitor)

        # Eliminate variables and local functions from the list of called functions.
        r = []
        for f in call_visitor.called_funcs:
            if ((f in defn_visitor.funcs) or
                (f in var_visitor.variables) or
                (len(f) == 0) or
                (("." in f) and ("Shell" not in f))):
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
        
    def trace(self, entrypoint='*auto', regular_emulation=True):
        """Perform the VBA/VBScript emulation.
        """
        
        # Clear out any intermediate IOCs from a previous run.
        vba_context.intermediate_iocs = set()
        vba_context.num_b64_iocs = 0
        vba_context.shellcode = {}
        
        # Create the global context for the engine
        context = vba_context.Context(_globals=self.globals,
                                      engine=self,
                                      doc_vars=self.doc_vars,
                                      loaded_excel=self.loaded_excel,
                                      filename=self.filename,
                                      metadata=self.metadata)
        context.is_vbscript = self.is_vbscript
        context.do_jit = self.do_jit
            
        # Add any URLs we can pull directly from the file being analyzed.
        fname = self.filename
        is_data = False
        if ((fname is None) or (len(fname.strip()) == 0)):
            fname = self.data
            is_data = True
        direct_urls = read_ole_fields.pull_urls_office97(fname, is_data, self.vba)
        for url in direct_urls:
            context.save_intermediate_iocs(url)
        direct_urls = pull_urls_excel_sheets(self.loaded_excel)
        for url in direct_urls:
            context.save_intermediate_iocs(url)

        # Pull base64 saved in Excel cells.
        cell_b64_blobs = pull_b64_excel_sheets(self.loaded_excel)
        for cell_b64_blob in cell_b64_blobs:
            context.save_intermediate_iocs(cell_b64_blob)
            
        # Save the true names of imported external functions.
        for func_name in self.externals:
            func = self.externals[func_name]
            context.dll_func_true_names[func.name] = func.alias_name

        # Save the document tables in the context.
        context.globals["__DOC_TABLE_CONTENTS__"] = self.doc_tables
            
        # Save the document text in the proper variable in the context.
        context.globals["Range.Text".lower()] = "\n".join(self.doc_text)
        context.globals["Me.Content".lower()] = "\n".join(self.doc_text)
        context.globals["Me.Content.Text".lower()] = "\n".join(self.doc_text)
        context.globals["Me.Range.Text".lower()] = "\n".join(self.doc_text)
        context.globals["Me.Range".lower()] = "\n".join(self.doc_text)
        context.globals["Me.Content.Start".lower()] = 0
        context.globals["Me.Content.End".lower()] = len("\n".join(self.doc_text))
        context.globals["Me.Paragraphs".lower()] = self.doc_text
        context.globals["ActiveDocument.Content".lower()] = "\n".join(self.doc_text)
        context.globals["ActiveDocument.Content.Text".lower()] = "\n".join(self.doc_text)
        context.globals["ActiveDocument.Range.Text".lower()] = "\n".join(self.doc_text)
        context.globals["ActiveDocument.Range".lower()] = "\n".join(self.doc_text)
        context.globals["ActiveDocument.Content.Start".lower()] = 0
        context.globals["ActiveDocument.Content.End".lower()] = len("\n".join(self.doc_text))
        context.globals["ActiveDocument.Paragraphs".lower()] = self.doc_text
        context.globals["ThisDocument.Content".lower()] = "\n".join(self.doc_text)
        context.globals["ThisDocument.Content.Text".lower()] = "\n".join(self.doc_text)
        context.globals["ThisDocument.Range.Text".lower()] = "\n".join(self.doc_text)
        context.globals["ThisDocument.Range".lower()] = "\n".join(self.doc_text)
        context.globals["ThisDocument.Content.Start".lower()] = 0
        context.globals["ThisDocument.Content.End".lower()] = len("\n".join(self.doc_text))
        context.globals["ThisDocument.Paragraphs".lower()] = self.doc_text
        context.globals["['Me'].Content.Text".lower()] = "\n".join(self.doc_text)
        context.globals["['Me'].Range.Text".lower()] = "\n".join(self.doc_text)
        context.globals["['Me'].Range".lower()] = "\n".join(self.doc_text)
        context.globals["['Me'].Content.Start".lower()] = 0
        context.globals["['Me'].Content.End".lower()] = len("\n".join(self.doc_text))
        context.globals["['Me'].Paragraphs".lower()] = self.doc_text
        context.globals["['ActiveDocument'].Content.Text".lower()] = "\n".join(self.doc_text)
        context.globals["['ActiveDocument'].Range.Text".lower()] = "\n".join(self.doc_text)
        context.globals["['ActiveDocument'].Range".lower()] = "\n".join(self.doc_text)
        context.globals["['ActiveDocument'].Content.Start".lower()] = 0
        context.globals["['ActiveDocument'].Content.End".lower()] = len("\n".join(self.doc_text))
        context.globals["['ActiveDocument'].Paragraphs".lower()] = self.doc_text
        context.globals["['ThisDocument'].Content.Text".lower()] = "\n".join(self.doc_text)
        context.globals["['ThisDocument'].Range.Text".lower()] = "\n".join(self.doc_text)
        context.globals["['ThisDocument'].Range".lower()] = "\n".join(self.doc_text)
        context.globals["['ThisDocument'].Content.Start".lower()] = 0
        context.globals["['ThisDocument'].Content.End".lower()] = len("\n".join(self.doc_text))
        context.globals["['ThisDocument'].Paragraphs".lower()] = self.doc_text
        context.globals["['ActiveDocument'].Characters".lower()] = list("\n".join(self.doc_text))
        context.globals["ActiveDocument.Characters".lower()] = list("\n".join(self.doc_text))
        context.globals["ActiveDocument.Characters.Count".lower()] = long(len(self.doc_text))
        context.globals["Count".lower()] = 1
        context.globals[".Pages.Count".lower()] = 1
        context.globals["me.Pages.Count".lower()] = 1
        context.globals["['ThisDocument'].Characters".lower()] = list("\n".join(self.doc_text))
        context.globals["ThisDocument.Characters".lower()] = list("\n".join(self.doc_text))
        context.globals["ThisDocument.Sections".lower()] = list("\n".join(self.doc_text))
        context.globals["ActiveDocument.Sections".lower()] = list("\n".join(self.doc_text))

        # Break out document words.
        doc_words = []
        for word in re.split(r"[ \n]", "\n".join(self.doc_text)):
            word = word.strip()
            if (word.startswith("-")):
                word = word[1:]
                doc_words.append("-")
            doc_words.append(word.strip())
        context.globals["ActiveDocument.Words".lower()] = doc_words
        context.globals["ThisDocument.Words".lower()] = doc_words
            
        # Fake up some comments if needed.
        if (self.comments is None):
            context.globals["ActiveDocument.Comments".lower()] = ["Comment 1", "Comment 2"]
            context.globals["ThisDocument.Comments".lower()] = ["Comment 1", "Comment 2"]
        else:
            context.globals["ActiveDocument.Comments".lower()] = self.comments
            context.globals["ThisDocument.Comments".lower()] = self.comments
            if (self.metadata is not None):
                all_comments = ""
                # pylint: disable=not-an-iterable
                for comment in self.comments:
                    all_comments += comment + "/n"
                self.metadata.comments = all_comments
            
        # Reset the actions list, in case it is called several times
        if regular_emulation:
            self.actions = []

        # Track whether wild card values have been checked in boolean expressions.
        tested_wildcard = False

        # Set whether wildcard matches will always match or always fail to match.
        context.wildcard_match_value = regular_emulation
        
        # Track the external functions called.
        self.external_funcs = self._get_external_funcs()
        context.external_funcs = self.external_funcs

        # Track decoded strings.
        self.decoded_strs = set()        

        # First emulate any Visual Basic that appears outside of subs/funcs.
        if (regular_emulation):
            context.report_action('Start Regular Emulation', '', 'All wildcard matches will match')
        else:
            context.report_action('Start Speculative Emulation', '', 'All wildcard matches will fail')
        log.info("Emulating loose statements...")
        done_emulation = False
        for m in self.modules:
            if (m.eval(context=context)):
                context.dump_all_files(autoclose=True)
                done_emulation = context.got_actions
                tested_wildcard = tested_wildcard or context.tested_wildcard
                self.decoded_strs.update(context.get_decoded_strs())
                
        # Only start from user specified entry points if we have any.
        tmp_entry_points = self.entry_points
        only_user_entry_points = (len(self.user_entry_points) > 0)
        if only_user_entry_points:
            tmp_entry_points = self.user_entry_points
            
        # Perform analysis starting at given entry functions.
        for entry_point in tmp_entry_points:
            entry_point = entry_point.lower()
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Trying entry point " + entry_point)
            if ((entry_point in self.globals) and
                (hasattr(self.globals[entry_point], "eval"))):
                context.report_action('Found Entry Point', safe_str_convert(entry_point), '')
                # We will be trying multiple entry points, so make a copy
                # of the context so we don't accumulate stage changes across
                # entry points.
                tmp_context = vba_context.Context(context=context, _locals=context.locals, copy_globals=True)
                self.globals[entry_point].eval(context=tmp_context)
                tmp_context.dump_all_files(autoclose=True)
                self.decoded_strs.update(tmp_context.get_decoded_strs())
                
                # Save whether we got actions from this entry point.
                context.got_actions = tmp_context.got_actions
                done_emulation = True
                tested_wildcard = tested_wildcard or tmp_context.tested_wildcard

        # Stop analysis at the user specified analysis points if we have some.
        if only_user_entry_points:
            if (tested_wildcard and regular_emulation):
                self.trace(regular_emulation=False)
            return

        # Look for callback functions that can act as entry points.
        for name in self.globals:

            # Look for functions whose name ends with a callback suffix.
            for suffix in self.callback_suffixes:

                # Is this a callback?
                if (safe_str_convert(name).lower().endswith(suffix.lower())):

                    # Is this a function?
                    item = self.globals[name]
                    if isinstance(item, (Function, Sub)):

                        # Emulate it.
                        context.report_action('Found Entry Point', safe_str_convert(name), '')
                        # We will be trying multiple entry points, so make a copy
                        # of the context so we don't accumulate stage changes across
                        # entry points.
                        tmp_context = vba_context.Context(context=context, _locals=context.locals, copy_globals=True)
                        item.eval(context=tmp_context)
                        tmp_context.dump_all_files(autoclose=True)
                        # Save whether we got actions from this entry point.
                        context.got_actions = tmp_context.got_actions
                        tested_wildcard = tested_wildcard or tmp_context.tested_wildcard
                        self.decoded_strs.update(tmp_context.get_decoded_strs())
                        
        # Did we find a proper entry point?
        if (not done_emulation):

            # Try heuristics to find possible entry points.
            log.warn("No entry points found. Using heuristics to find entry points...")
            
            # Find any 0 argument subroutines. We will try emulating these as potential entry points.
            zero_arg_subs = []
            for name in self.globals:
                item = self.globals[name]
                if ((isinstance(item, Sub)) and (len(item.params) == 0)):
                    zero_arg_subs.append(item)
                    
            # Emulate all 0 argument subroutines as potential entry points.
            for only_sub in zero_arg_subs:
                sub_name = only_sub.name
                context.report_action('Found Heuristic Entry Point', safe_str_convert(sub_name), '')
                # We will be trying multiple entry points, so make a copy
                # of the context so we don't accumulate stage changes across
                # entry points.
                tmp_context = vba_context.Context(context=context, _locals=context.locals, copy_globals=True)
                only_sub.eval(context=tmp_context)
                tmp_context.dump_all_files(autoclose=True)
                tested_wildcard = tested_wildcard or tmp_context.tested_wildcard
                self.decoded_strs.update(tmp_context.get_decoded_strs())
                
        # If we used some wildcard boolean values in boolean expressions we now have
        # an opportunity to do some really simple speculative emulation. We just
        # emulated the behavior where all comparisons to a wild card value match, now
        # see what the behavior looks like if NONE of the comparisons match.
        if (tested_wildcard and regular_emulation):
            self.trace(regular_emulation=False)
            
    def eval(self, expr):
        """Parse and evaluate a single VBA expression.

        @param expr (str) expression to be evaluated

        @return (any) value of the evaluated expression

        """
        # Create the global context for the engine
        context = vba_context.Context(_globals=self.globals,
                                      engine=self,
                                      doc_vars=self.doc_vars,
                                      loaded_excel=self.loaded_excel)
        # reset the actions list, in case it is called several times
        self.actions = []
        e = expressions.expression.parseString(expr)[0]
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('e=%r - type=%s' % (e, type(e)))
        value = e.eval(context=context)
        return value

    def dump_actions(self):
        """Return a table of all actions recorded by trace(), as a
        prettytable object that can be printed or reused.

        @return (PrettyTable object) The actions performed during
        emulation saved as a PrettyTable object.

        """
        t = prettytable.PrettyTable(('Action', 'Parameters', 'Description'))
        t.align = 'l'
        t.max_width['Action'] = 20
        t.max_width['Parameters'] = 45
        t.max_width['Description'] = 35
        for action in self.actions:
            # Cut insanely large results down to size.
            str_action = safe_str_convert(action)
            if (len(str_action) > 50000):
                new_params = safe_str_convert(action[1])
                if (len(new_params) > 50000):
                    new_params = new_params[:25000] + "... <SNIP> ..." + new_params[-25000:]
                action = (action[0], new_params, action[2])
            t.add_row(action)
        return t

def scan_expressions(vba_code):
    """Scan VBA code to extract constant VBA expressions,
    i.e. expressions that can be evaluated as a constant
    value. Iterate over these expressions, yield the expression and
    its evaluated value as a tuple.

    @param vba_code (str) The VBA/VBScript source code to scan.

    @return (iterator) yield (expression, evaluated value)

    """
    # context to evaluate expressions:
    context = vba_context.Context()
    for m in expressions.expr_const.scanString(vba_code):
        e = m[0][0]
        # only yield expressions which are not plain constants
        # a VBA expression should have an eval() method:
        if hasattr(e, 'eval'):
            yield (e, e.eval(context))


# Soundtrack: This code was developed while listening to The Chameleons "Monkeyland"
