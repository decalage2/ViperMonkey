#!/usr/bin/env pypy

"""@package vipermonkey.vmonkey

The ViperMonkey command line and programatic interface. The top level
function for using ViperMonkey programatically is process_file().

ViperMonkey is a specialized engine to parse, analyze and interpret Microsoft
VBA macros (Visual Basic for Applications), mainly for malware analysis.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

Project Repository:
https://github.com/decalage2/ViperMonkey
"""

from __future__ import print_function

# pylint: disable=pointless-string-statement
"""@mainpage

@section intro Introduction

ViperMonkey is a VBA Emulation engine written in Python, designed to
analyze and deobfuscate malicious VBA Macros contained in Microsoft
Office files (Word, Excel, PowerPoint, Publisher, etc), VBScript
files, and HTA files with VBScript script blocks.

@section workflow Workflow

The high level analysis process implemented by ViperMonkey is as
follows:

1. Start analysis on sample file FFF.
   @see process_file()
2. Dump the VBA macros/VBScript with olevba (https://github.com/decalage2/oletools/wiki/olevba).
   @see _get_vba_parser().
3. Parse the extracted VB. The VB parser uses PyParsing (https://pypi.org/project/pyparsing/).
   @see parse_streams()
4. Read all Excel cell contents (if needed).
   @see read_excel_sheets()
5. Read Word document contents (if needed).
   @see read_ole_fields._read_doc_text()
6. Read text from may places payload text can be hidden.
   @see read_ole_fields.read_payload_hiding_places()
7. Create a ViperMonkey emulator object.
   @see core/__init__.py
8. Call the core.ViperMonkey.trace() method of the ViperMonkey emulator object to 
   start emulation.
9. Create a context object to track the program state. This will be
   updated with variable values, file write information, and actions
   of interest during emulation.
   @see core/vba_context.py
10. Call the eval() methods of VBA_Object objects parsed from the
   VBA/VBScript being emulated. The eval() methods actually emulate
   the input sample. Check out all objects that inherit from
   VBA_Object to see all constructs that can be emulated.
   @see core/vba_object.py
11. During emulation actions of interest are reported with the
   core.vba_context.Context.report_action() method.
12. Intermediate IOCs (URLs and base64 strings) are extracted and
   tracked during emulation with the core.vba_context.Context.save_intermediate_iocs()
   method.
13. Emulation of loops is sped up by doing JIT transpilation of the
   VBA/VBScript loop to Python.
   @see core/python_jit.py

"""

# Do this before any other imports to make sure we have an unlimited
# packrat parsing cache. Do not move or remove this line.
import pyparsing
pyparsing.ParserElement.enablePackrat(cache_size_limit=100000)

import shutil
import logging
import json
import random
import optparse
import sys
import os
import traceback
import colorlog
import re
from datetime import datetime
from datetime import timedelta
import zipfile
import io

import prettytable
from oletools.thirdparty.xglob import xglob
from oletools.olevba import VBA_Parser, filter_vba, FileOpenError
import olefile
    
from core.meta import get_metadata_exif

# add the vipermonkey folder to sys.path (absolute+normalized path):
_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
if _thismodule_dir not in sys.path:
    sys.path.insert(0, _thismodule_dir)

# relative import of core ViperMonkey modules:
import core
import core.excel as excel
import core.read_ole_fields as read_ole_fields
from core.utils import safe_print
from core.utils import safe_str_convert

# for logging
from core.logger import log
from core.logger import CappedFileHandler
from logging import FileHandler

#=== LICENSE ==================================================================

# ViperMonkey is copyright (c) 2015-2021 Philippe Lagadec (http://www.decalage.info)
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

#------------------------------------------------------------------------------
# CHANGELOG:
# 2015-02-12 v0.01 PL: - first prototype
# 2015-2016        PL: - many changes
# 2016-10-06 v0.03 PL: - fixed vipermonkey.core import
# 2016-12-11 v0.04 PL: - fixed relative import for core package (issue #17)
# 2018-01-12 v0.05 KS: - lots of bug fixes and additions by Kirk Sayre (PR #23)
# 2018-06-20 v0.06 PL: - fixed issue #28, import prettytable
# 2018-08-17 v0.07 KS: - lots of bug fixes and additions by Kirk Sayre (PR #34)
#                  PL: - added ASCII art banner

__version__ = '1.0.2'

#------------------------------------------------------------------------------
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
#TODO: expr_int / expr_str
#TODO: eval(parent) => for statements to set local variables into parent functions/procedures + main VBA module
#TODO: __repr__ for printing
#TODO: Environ('str') => '%str%'
#TODO: determine the order of Auto subs for Word, Excel

# TODO later:
# - add VBS support (two modes?)

#------------------------------------------------------------------------------
# REFERENCES:
# - [MS-VBAL]: VBA Language Specification
#   https://msdn.microsoft.com/en-us/library/dd361851.aspx
# - [MS-OVBA]: Microsoft Office VBA File Format Structure
#   http://msdn.microsoft.com/en-us/library/office/cc313094%28v=office.12%29.aspx
    
def get_vb_contents_from_hta(vba_code):
    """Pull out Visual Basic code from .hta file contents.

    @param vba_code (str) The HTA file contents from which to extract
    the VBScript code.

    @return (str) If the given data is HTA that contains VBScript
    script elements, the VBScript in the HTA is returned. If the given
    data is not VBScript HTA, the original data is returned.

    """

    # Fix some obfuscation if needed.
    # '&#86;'
    if (re.search(r"&#\d{1,3};", vba_code) is not None):
        for i in range(0, 256):
            curr_c = chr(i)
            vba_code = vba_code.replace("&#" + safe_str_convert(i) + ";", curr_c)
    
    # Try several regexes to pull out HTA script contents.
    hta_regexes = [
        r"<\s*[Ss][Cc][Rr][Ii][Pp][Tt]\s+(?:(?:[Ll][Aa][Nn][Gg][Uu][Aa][Gg][Ee])|(?:[Tt][Yy][Pp][Ee]))\s*=" + \
        r"\s*[\"']?.{0,10}[Vv][Bb][Ss][Cc][Rr][Ii][Pp][Tt][\"']?\s*>(.{20,}?)</\s*[Ss][Cc][Rr][Ii][Pp][Tt][^>]*>",

        r"<\s*[Ss][Cc][Rr][Ii][Pp][Tt]\s+\%\d{1,10}\s*>(.{20,}?)</\s*[Ss][Cc][Rr][Ii][Pp][Tt][^>]*>",
        r"<\s*[Ss][Cc][Rr][Ii][Pp][Tt]\s+(?:(?:[Ll][Aa][Nn][Gg][Uu][Aa][Gg][Ee])|(?:[Tt][Yy][Pp][Ee]))\s*=" + \
        r"\s*[\"']?.{0,10}[Vv][Bb][Ss][Cc][Rr][Ii][Pp][Tt][\"']?\s*>(.{20,})$",

        # <script type="text/vbscript" LANGUAGE="VBScript" >
        r"<[Ss][Cc][Rr][Ii][Pp][Tt] +[Tt][Yy][Pp][Ee] *= *" + \
        r"[\"'](?:[Tt][Ee][Xx][Tt]/)?(?:(?:[Vv][Bb])|(?:[Jj][Aa]?[Vv]?[Aa]?))[Ss][Cc][Rr][Ii][Pp][Tt][\"']" + \
        r"(?: +[Ll][Aa][Nn][Gg][Uu][Aa][Gg][Ee] *= *[\"'][Vv][Bb][Ss][Cc][Rr][Ii][Pp][Tt][\"'])?[^>]*>" + \
        r"(.{20,}?)(?:(?:</\s*[Ss][Cc][Rr][Ii][Pp][Tt][^>]*>)|$)"
    ]
    
    code = []
    for pat in hta_regexes:
        code = re.findall(pat, vba_code.strip(), re.DOTALL)
        if (len(code) > 0):
            #for c in code:
            #    print("\n\n%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n")
            #    print(c)
            break
    if (len(code) == 0):
        return vba_code        

    # We have script block VB code.    
    
    # Return the code.    
    r = ""
    for b in code:
        b = b.strip()
        if ("</script>" in b.lower()):
            b = b[:b.lower().index("</script>")]
        if ("<![CDATA[" in b.upper()):
            b = b[b.upper().index("<![CDATA[") + len("<![CDATA["):]
            if ("]]>" in b[-10:]):
                b = b[:b.rindex("]]>")]

        # More tag stripping.
        pat = r"<!\-\-(.+)/?/?\-\->"
        tmp_b = re.findall(pat, b, re.DOTALL)
        if (len(tmp_b) > 0):
            b = tmp_b[0].strip()
        if (b.endswith("//")):
            b = b[:-2]
                
        r += b + "\n"
    return r
    
def parse_stream(subfilename,
                 stream_path=None,
                 vba_filename=None,
                 vba_code=None,
                 strip_useless=False,
                 local_funcs=None):
    """Parse the macros from a single OLE stream.

    @param subfilename (str) The name of the file containing the    
    macros.

    @param stream_path (??) ??

    @param vba_filename (??) ??

    @param vba_code (str) The macro code to parse.

    @param local_funcs (list) A list of the names of already declared
    local VBA functions.

    @return (Module object) A parsed module object.

    """
    
    # Set local func list if needed.
    if (local_funcs is None):
        local_funcs = []
    
    # Check for timeouts.
    core.vba_object.limits_exceeded(throw_error=True)
    
    # Are the arguments all in a single tuple?
    if (stream_path is None):
        subfilename, stream_path, vba_filename, vba_code = subfilename

    # Skip old-style XLM macros.
    if (repr(stream_path).strip() == "'xlm_macro'"):
        log.warning("Skipping XLM macro stream...")
        return "empty"
        
    # Collapse long lines.
    vba_code = core.vba_collapse_long_lines(vba_code)
        
    # Filter cruft from the VBA.
    vba_code = filter_vba(vba_code)

    # Pull out Visual Basic from .hta contents (if we are looking at a
    # .hta file).
    vba_code = get_vb_contents_from_hta(vba_code)

    # Do not analyze the file if the VBA looks like garbage characters.
    if (read_ole_fields.is_garbage_vba(vba_code, no_html=True)):
        log.warning("Failed to extract VBScript from HTA. Skipping.")
        return "empty"
        
    # Skip some XML that olevba gives for some 2007+ streams.
    if (vba_code.strip().startswith("<?xml")):
        log.warning("Skipping XML stream.")
        return "empty"
    
    # Strip out code that does not affect the end result of the program.
    if (strip_useless):
        vba_code = core.strip_lines.strip_useless_code(vba_code, local_funcs)
    safe_print('-'*79)
    safe_print('VBA MACRO %s ' % vba_filename)
    safe_print('in file: %s - OLE stream: %s' % (subfilename, repr(stream_path)))
    safe_print('- '*39)
    
    # Parse the macro.
    m = None
    if vba_code.strip() == '':
        safe_print('(empty macro)')
        m = "empty"
    else:
        safe_print('-'*79)
        safe_print('VBA CODE (with long lines collapsed):')
        safe_print(vba_code)
        safe_print('-'*79)
        #sys.exit(0)
        safe_print('PARSING VBA CODE:')
        try:
            m = core.module.parseString(vba_code + "\n", parseAll=True)[0]
            pyparsing.ParserElement.resetCache()
            m.code = vba_code
        except pyparsing.ParseException as err:
            safe_print(err.line)
            safe_print(" "*(err.column-1) + "^")
            safe_print(err)
            log.error("Parse Error. Processing Aborted.")
            return None

    # Check for timeouts.
    core.vba_object.limits_exceeded(throw_error=True)
        
    # Return the parsed macro.
    return m

def get_all_local_funcs(vba):
    """Get the names of all locally defined functions. Also get the names
    of all defined constants. The constant names are saved in
    core.strip_lines.defined_constants.

    @params vba (VBA_Parser object) The olevba VBA_Parser object for
    reading the Office file being analyzed.

    """

    # Find the sub/function definitions.
    pat = r"(?:Sub |Function )([^\(]+)"
    r = []
    for (_, _, _, vba_code) in vba.extract_macros():
        if (vba_code is None):
            continue

        # Get local func names.
        for line in vba_code.split("\n"):
            names = re.findall(pat, line)
            r.extend(names)

        # Get constant defs. This is saved in strip_lines.defined_constants.
        core.strip_lines.find_defined_constants(vba_code)

    # Return local function names.
    return r
            
def parse_streams(vba, strip_useless=False):
    """Parse all the VBA streams and return list of parsed module
    objects.

    @params vba (VBA_Parser object) The olevba VBA_Parser object for
    reading the Office file being analyzed.

    @param strip_useless (boolean) Flag turning on/off modification of
    VB code prior to parsing.

    @return (list) A list of 2 element tuples where the 1st element is
    the parsed Module objects and the 2nd element is the name of the
    OLE stream containing the module.

    """

    # Get the names of all the locally defined functions.
    local_funcs = get_all_local_funcs(vba)
    
    # Parse the VBA streams.
    r = []
    for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
        m = parse_stream(subfilename, stream_path, vba_filename, vba_code, strip_useless, local_funcs)
        if (m is None):
            continue
        r.append((m, stream_path))
    if (len(r) == 0): return None
    return r

# === Top level utility functions ================================================================================

def read_excel_sheets(fname):
    """Read all the sheets of a given Excel file as CSV and return them
    as a ExcelBook object.

    @param fname (str) The name of the Excel file to read.

    @return (core.excel.ExceBook object) On success return the Excel
    sheets as an ExcelBook object. Returns None on error.

    """

    # Read the sheets.
    try:
        f = open(fname, 'rb')
        data = f.read()
        f.close()
        return excel.load_excel_libreoffice(data)
    except Exception as e:
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Reading Excel sheets failed. " + safe_str_convert(e))
        return None
    
def pull_urls_office97(fname):
    """Pull URLs directly from an Office97 file.

    @param fname (str) The name of the file from which to scrape
    URLs.

    @return (set) The URLs scraped from the file. This will be empty
    if there are no URLs.

    """
    return read_ole_fields.pull_urls_office97(fname, False, None)
    
# === Top level Programatic Interface ================================================================================    

# pylint: disable=too-many-arguments
def process_file(container,
                 filename,
                 data,
                 strip_useless=False,
                 entry_points=None,
                 time_limit=None,
                 verbose=False,
                 display_int_iocs=False,
                 set_log=False,
                 tee_log=False,
                 tee_bytes=0,
                 artifact_dir=None,
                 out_file_name=None,
                 do_jit=False):
    """Process an Office file with VBA macros, a VBScript file, or
    VBScript HTA file with ViperMonkey. This is the main programatic
    interface for ViperMonkey.

    @param container (str) Path and filename of container if the file is within
    a zip archive, None otherwise.

    @param filename (str) str, path and filename of file on disk, or
    within the container.

    @param data (bytes) content of the file if it is in a container,
    None if it is a file on disk.
 
    @param strip_useless (boolean) Flag turning on/off modification of
    VB code prior to parsing.

    @param entry_points (list) A list of the names (str) of the VB functions
    from which to start emulation.
    
    @param time_limit (int) The emulation time limit, in minutes. If
    None there is not time limit.

    @param verbose (boolean) Flag turning debug logging on/off.

    @param display_int_iocs (boolean) Flag turning on/off the
    reporting of intermediate IOCs (base64 strings and URLs) found
    during the emulation process.

    @param set_log (boolean) A flag??

    @param tee_log (boolean) A flag turning on/off saving all of
    ViperMonkey's output in a text log file. The log file will be
    FNAME.log, where FNAME is the name of the file being analyzed.

    @param tee_bytes (int) If tee_log is true, this gives the number
    of bytes at which to cap the saved log file.

    @param artifact_dir (str) The directory in which to save artifacts
    dropped by the sample under analysis. If None the artifact
    directory will be FNAME_artifacts/ where FNAME is the name of the
    file being analyzed.

    @param out_file_name (str) The name of the file in which to store
    the ViperMonkey analysis results as JSON. If None no JSON results
    will be saved.

    @param do_jit (str) A flag turning on/off doing VB -> Python
    transpiling of loops to speed up loop emulation.

    @return (list) A list of actions if actions found, an empty list
    if no actions found, and None if there was an error.

    """
    
    # set logging level
    if verbose:
        colorlog.basicConfig(level=logging.DEBUG, format='%(log_color)s%(levelname)-8s %(message)s')
    elif set_log:
        colorlog.basicConfig(level=logging.INFO, format='%(log_color)s%(levelname)-8s %(message)s')

    # assume they want a tee'd file if they give bytes for it
    if tee_bytes > 0:
        tee_log = True

    # add handler for tee'd log file
    if tee_log:

        tee_filename = "./" + filename
        if ("/" in filename):
            tee_filename = "./" + filename[filename.rindex("/") + 1:]

        if tee_bytes > 0:
            capped_handler = CappedFileHandler(tee_filename + ".log", sizecap=tee_bytes)
            capped_handler.setFormatter(logging.Formatter("%(levelname)-8s %(message)s"))
            log.addHandler(capped_handler)
        else:
            file_handler = FileHandler(tee_filename + ".log", mode="w")
            file_handler.setFormatter(logging.Formatter("%(levelname)-8s %(message)s"))
            log.addHandler(file_handler)

    # Check for files that do not exist.
    if (isinstance(data, Exception)):
        log.error("Cannot open file '" + safe_str_convert(filename) + "'.")
        return None
    
    # Read in file contents if we have not already been provided data to analyze.
    if not data:
        # TODO: replace print by writing to a provided output file (sys.stdout by default)
        if container:
            display_filename = '%s in %s' % (filename, container)
        else:
            display_filename = filename
        safe_print('='*79)
        safe_print('FILE: ' + safe_str_convert(display_filename))
        # FIXME: the code below only works if the file is on disk and not in a zip archive
        # TODO: merge process_file and _process_file
        try:
            input_file = open(filename,'rb')
            data = input_file.read()
            input_file.close()
        except IOError as e:
            log.error("Cannot open file '" + safe_str_convert(filename) + "'. " + safe_str_convert(e))
            return None
    r = _process_file(filename,
                      data,
                      strip_useless=strip_useless,
                      entry_points=entry_points,
                      time_limit=time_limit,
                      display_int_iocs=display_int_iocs,
                      artifact_dir=artifact_dir,
                      out_file_name=out_file_name,
                      do_jit=do_jit)

    # Reset logging.
    colorlog.basicConfig(level=logging.ERROR, format='%(log_color)s%(levelname)-8s %(message)s')

    # Done.
    return r

def _remove_duplicate_iocs(iocs):
    """Remove IOC strings that are substrings of other IOC strings.

    @param iocs (list) List of IOCs (str).

    @return (set) The original IOC list with duplicate-ish IOC strings
    stripped out.

    """

    # Track whether to keep an IOC string.
    r = set()
    skip = set()
    log.info("Found " + safe_str_convert(len(iocs)) + " possible IOCs. Stripping duplicates...")
    for ioc1 in iocs:

        # Does this IOC look like straight up garbage?
        if (read_ole_fields.is_garbage_vba(ioc1, test_all=True, bad_pct=.25)):
            skip.add(ioc1)
            continue

        # Looks somewhat sensible. See if it is a duplicate.
        keep_curr = True
        for ioc2 in iocs:
            if (ioc2 in skip):
                continue
            if ((ioc1 != ioc2) and (ioc1 in ioc2)):
                keep_curr = False
                break
            if ((ioc1 != ioc2) and (ioc2 in ioc1)):
                skip.add(ioc2)
        if (keep_curr):
            r.add(ioc1)

    # Return stripped IOC set.
    return r

def _get_vba_parser(data):
    """Get an olevba VBA_Parser object for reading an Office file. This
    handles regular Office files and HTA files with VBScript script
    elements.

    @param data (str) The file contents for which to generate a
    VBA_Parser.

    @return (VBA_Parser object) On success, the olevba VBA_Parser
    object for the given file contents. On error, None.

    """
    
    # First just try the most common case where olevba can directly get the VBA.
    vba = None
    try:
        vba = VBA_Parser('', data, relaxed=True)
    except Exception as e:

        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Creating VBA_PArser() Failed. Trying as HTA. " + safe_str_convert(e))
        
        # If that did not work see if we can pull HTA wrapped VB from the data.
        extracted_data = get_vb_contents_from_hta(data)

        # If this throws an exception it will get passed up.
        vba = VBA_Parser('', extracted_data, relaxed=True)

    # Return the vba parser.
    return vba

def pull_embedded_pe_files(data, out_dir):
    """Directly pull out any PE files embedded in the given data. The PE
    files will be saved in a directory and will be named things like
    embedded*.exe.

    @param data (str) The contents of the file being analyzed.

    @param out_dir (str) The directory in which to save extracted PE
    files.

    """

    # Is this a Office 2007 (zip) file?
    if core.filetype.is_office2007_file(data, is_data=True):

        # convert data to a BytesIO buffer so that we can use zipfile in memory
        # without writing a temp file on disk:
        data_io = io.BytesIO(data)
        # Pull embedded PE files from each file in the zip.
        with zipfile.ZipFile(data_io, "r") as f:
            for name in f.namelist():
                curr_data = f.read(name)
                pull_embedded_pe_files(curr_data, out_dir)
        return
    
    # Is a PE file in the data at all?
    pe_pat = r"MZ.{70,80}This program (?:(?:cannot be run in DOS mode\.)|(?:must be run under Win32))"
    if (re.search(pe_pat, data) is None):
        return

    # There is an embedded PE. Break them out.
    
    # Get where each PE file starts.
    pe_starts = []
    for match in re.finditer(pe_pat, data):
        pe_starts.append(match.span()[0])
    pe_starts.append(len(data))
    
    # Make the 2nd stage output directory if needed.
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    
    # Break out each PE file. Note that we probably will get extra data,
    # but due to the PE file format the file will be a valid PE (with an overlay).
    pos = 0
    out_index = 0
    while (pos < len(pe_starts) - 1):
        curr_data = data[pe_starts[pos]:pe_starts[pos+1]]
        curr_name = out_dir + "/embedded_pe" + safe_str_convert(out_index) + ".bin"
        # Make sure name is unique.
        while os.path.isfile(curr_name):
            out_index += 1
            curr_name = out_dir + "/embedded_pe" + safe_str_convert(out_index) + ".bin"
        f = open(curr_name, "wb")
        f.write(curr_data)
        f.close()
        pos += 1
        out_index += 1
        log.info("Wrote embedded PE file to " + curr_name)

def _report_analysis_results(vm, data, display_int_iocs, orig_filename, out_file_name):
    """Report analysis results (screen and file) to the user. Results will
    be printed to stdout and saved in an output file as JSON if needed.

    @param vm (ViperMonkey object) The ViperMonkey emulation engine
    object that did the emulation.

    @param data (str) The read in Office file (data).

    @param display_int_iocs (boolean) Flag turning on/off the
    reporting of intermediate IOCs (base64 strings and URLs) found
    during the emulation process.

    @param orig_filename (str) path and filename of file on disk, or
    within the container.

    @param out_file_name (str) The name of the file in which to store
    the ViperMonkey analysis results as JSON. If None no JSON results
    will be saved.

    @return (tuple) A 3 element tuple where the 1st element is a list
    of reported actions all converted to strings, the 2nd element is a
    list of unique intermediate IOCs, and the 3rd element is a list of
    shell code bytes injected by the VB (empty list if no shell code).

    """

    # Limit the number of base64 IOCs.
    full_iocs = core.vba_context.intermediate_iocs
    tmp_b64_iocs = []
    for ioc in full_iocs:
        if ("http" not in ioc):
            tmp_b64_iocs.append(ioc)
    tmp_b64_iocs = tmp_b64_iocs + list(read_ole_fields.pull_base64(data))
    tmp_b64_iocs = sorted(tmp_b64_iocs, key=len)[::-1][:200]
    for ioc in tmp_b64_iocs:
        full_iocs.add(ioc)
        core.vba_context.num_b64_iocs += 1
    
    
    # Print table of all recorded actions
    safe_print('\nRecorded Actions:')
    safe_print(vm.dump_actions())
    safe_print('')

    # Report intermediate IOCs.
    tmp_iocs = []
    if (len(full_iocs) > 0):
        tmp_iocs = _remove_duplicate_iocs(full_iocs)
        if (display_int_iocs):
            safe_print('Intermediate IOCs:')
            safe_print('')
            for ioc in tmp_iocs:
                safe_print("+---------------------------------------------------------+")
                safe_print(ioc)
            safe_print("+---------------------------------------------------------+")
            safe_print('')

    # Display injected shellcode.
    shellcode_bytes = core.vba_context.get_shellcode_data()
    if (len(shellcode_bytes) > 0):
        safe_print("+---------------------------------------------------------+")
        safe_print("Shell Code Bytes: " + safe_str_convert(shellcode_bytes))
        safe_print("+---------------------------------------------------------+")
        safe_print('')

    # See if we can directly pull any embedded PE files from the file.
    pull_embedded_pe_files(data, core.vba_context.out_dir)

    # Report VBA builtin fingerprint.
    safe_print('VBA Builtins Called: ' + safe_str_convert(vm.external_funcs))
    safe_print('')

    # Report decoded strings.
    if (len(vm.decoded_strs) > 0):
        safe_print("Decoded Strings (" + str(len(vm.decoded_strs)) + "):")
        for s in vm.decoded_strs:
            safe_print("  " + s)
        safe_print('')

    # Done printing results.
    safe_print('Finished analyzing ' + safe_str_convert(orig_filename) + " .\n")

    # Reporting results in JSON file?
    if out_file_name:

        # Create the results data structure.
        actions_data = []
        for action in vm.actions:
            actions_data.append({
                "action": safe_str_convert(action[0]),
                "parameters": safe_str_convert(action[1]),
                "description": safe_str_convert(action[2])
            })

        out_data = {
            "file_name": orig_filename,
            "potential_iocs": list(tmp_iocs),
            "shellcode" : shellcode_bytes,
            "vba_builtins": vm.external_funcs,
            "actions": actions_data,
            "decoded_strs": list(vm.decoded_strs)
        }

        # Write out the results as JSON.
        try:
            with open(out_file_name, 'w') as out_file:
                out_file.write("\n" + json.dumps(out_data, indent=4))
        except Exception as exc:
            log.error("Failed to output results to output file. " + safe_str_convert(exc))

    # Make sure all the action fields are strings before returning.
    str_actions = []
    for action in vm.actions:
        str_actions.append((safe_str_convert(action[0]),
                            safe_str_convert(action[1]),
                            safe_str_convert(action[2])))    

    # Done.
    return (str_actions, tmp_iocs, shellcode_bytes)

def _save_embedded_files(out_dir, vm):
    """Save any extracted embedded files from the sample in the artifact
    directory.

    @param vm (ViperMonkey object) The ViperMonkey emulation engine
    object that did the emulation.

    @param out_dir (str) The artifact directory.
    """

    # Make the output directory if needed.
    out_dir = safe_str_convert(out_dir)
    if (not os.path.exists(out_dir)):
        log.info("Making dropped sample directory ...")
        os.mkdir(out_dir)
        
    # Save each file.
    out_dir = safe_str_convert(out_dir)
    for file_info in vm.embedded_files:
        short_name = safe_str_convert(file_info[0])
        long_name = safe_str_convert(file_info[1])
        contents = safe_str_convert(file_info[2])
        log.info("Saving embedded file " + long_name + " ...")
        try:
            f = open(out_dir + "/" + short_name, "w")
            f.write(contents)
            f.close()
        except IOError as e:
            log.error("Saving embedded file " + long_name + " failed. " + str(e))

# Wrapper for original function; from here out, only data is a valid variable.
# filename gets passed in _temporarily_ to support dumping to vba_context.out_dir = out_dir.
def _process_file (filename,
                   data,
                   strip_useless=False,
                   entry_points=None,
                   time_limit=None,
                   display_int_iocs=False,
                   artifact_dir=None,
                   out_file_name=None,
                   do_jit=False):
    """Process a single file.

    @param container (str) Path and filename of container if the file is within
    a zip archive, None otherwise.

    @param filename (str) path and filename of file on disk, or within
    the container.

    @param data (bytes) content of the file if it is in a container,
    None if it is a file on disk.

    @param strip_useless (boolean) Flag turning on/off modification of
    VB code prior to parsing.

    @param entry_points (list) A list of the names (str) of the VB functions
    from which to start emulation.

    @param time_limit (int) The emulation time limit, in minutes. If
    None there is not time limit.

    @param display_int_iocs (boolean) Flag turning on/off the
    reporting of intermediate IOCs (base64 strings and URLs) found
    during the emulation process.

    @param artifact_dir (str) The directory in which to save artifacts
    dropped by the sample under analysis. If None the artifact

    @param out_file_name (str) The name of the file in which to store
    the ViperMonkey analysis results as JSON. If None no JSON results
    will be saved.

    @param do_jit (str) A flag turning on/off doing VB -> Python
    transpiling of loops to speed up loop emulation.

    @return (list) A list of actions if actions found, an empty list
    if no actions found, and None if there was an error.

    """

    # Increase Python call depth.
    sys.setrecursionlimit(13000)

    # Set the emulation time limit.
    if (time_limit is not None):
        core.vba_object.max_emulation_time = datetime.now() + timedelta(minutes=time_limit)

    # Create the emulator.
    log.info("Starting emulation...")
    vm = core.ViperMonkey(filename, data, do_jit=do_jit)
    orig_filename = filename
    if (entry_points is not None):
        for entry_point in entry_points:
            vm.user_entry_points.append(entry_point)
    try:
        #TODO: handle olefile errors, when an OLE file is malformed
        if (isinstance(data, Exception)):
            data = None
        vba = None
        try:
            vba = _get_vba_parser(data)
        except FileOpenError as e:

            # Is this an unrecognized format?
            if ("Failed to open file  is not a supported file type, cannot extract VBA Macros." not in safe_str_convert(e)):

                # No, it is some other problem. Pass on the exception.
                raise e

            # This may be VBScript with some null characters. Remove those and try again.
            data = data.replace("\x00", "")
            vba = _get_vba_parser(data)

        # Do we have analyzable VBA/VBScript? Do the analysis even
        # without VBA/VBScript if we are scraping for intermediate
        # IOCs.
        if (vba.detect_vba_macros() or display_int_iocs):

            # Read in document metadata.
            try:
                log.info("Reading document metadata...")
                ole = olefile.OleFileIO(data)
                vm.set_metadata(ole.get_metadata())
            except Exception as e:
                log.warning("Reading in metadata failed. Trying fallback. " + safe_str_convert(e))
                vm.set_metadata(get_metadata_exif(orig_filename))

            # If this is an Excel spreadsheet, read it in.
            vm.loaded_excel = excel.load_excel(data)

            # Set where to store directly dropped files if needed.
            if (artifact_dir is None):
                artifact_dir = "./"
                if ((filename is not None) and ("/" in filename)):
                    artifact_dir = filename[:filename.rindex("/")]
            only_filename = filename
            if ((filename is not None) and ("/" in filename)):
                only_filename = filename[filename.rindex("/")+1:]
            
            # Set the output directory in which to put dumped files generated by
            # the macros.
            out_dir = None
            if (only_filename is not None):
                out_dir = artifact_dir + "/" + only_filename + "_artifacts/"
                if os.path.exists(out_dir):
                    shutil.rmtree(out_dir)
            else:
                out_dir = "/tmp/tmp_file_" + safe_str_convert(random.randrange(0, 10000000000))
            log.info("Saving dropped analysis artifacts in " + out_dir)
            core.vba_context.out_dir = out_dir
            del filename # We already have this in memory, we don't need to read it again.
                
            # Parse the VBA streams.
            log.info("Parsing VB...")
            comp_modules = parse_streams(vba, strip_useless)
            if (comp_modules is None):
                return None
            got_code = False
            for module_info in comp_modules:
                m = module_info[0]
                stream = module_info[1]
                if (m != "empty"):
                    vm.add_compiled_module(m, stream)
                    got_code = True
            if ((not got_code) and (not display_int_iocs)):
                log.info("No VBA or VBScript found. Exiting.")
                return ([], [], [], [])

            # Get the VBA code.
            vba_code = ""
            for (_, _, _, macro_code) in vba.extract_macros():
                if (macro_code is not None):
                    vba_code += macro_code

            # Do not analyze the file if the VBA looks like garbage.
            if (read_ole_fields.is_garbage_vba(vba_code)):
                raise ValueError("VBA looks corrupted. Not analyzing.")

            # Read in text values from all of the various places in
            # Office 97/2000+ that text values can be hidden. So many
            # places.
            read_ole_fields.read_payload_hiding_places(data, orig_filename, vm, vba_code, vba)
            
            # Do Emulation.
            safe_print("")
            safe_print('-'*79)
            safe_print('TRACING VBA CODE (entrypoint = Auto*):')
            if (entry_points is not None):
                log.info("Starting emulation from function(s) " + safe_str_convert(entry_points))
            pyparsing.ParserElement.resetCache()
            vm.vba = vba
            vm.trace()

            # Done with emulation.

            # Report the results.
            str_actions, tmp_iocs, shellcode_bytes = _report_analysis_results(vm, data, display_int_iocs, orig_filename, out_file_name)

            # Save any embedded files as artifacts.
            _save_embedded_files(out_dir, vm)
            
            # Return the results.
            return (str_actions, vm.external_funcs, tmp_iocs, shellcode_bytes)

        # No VBA/VBScript found?
        else:
            safe_print('Finished analyzing ' + safe_str_convert(orig_filename) + " .\n")
            safe_print('No VBA macros found.')
            safe_print('')
            return ([], [], [], [])

    # Handle uncaught exceptions triggered during analysis.
    except Exception as e:

        # Print error info.
        if (("SystemExit" not in safe_str_convert(e)) and (". Aborting analysis." not in safe_str_convert(e))):
            traceback.print_exc()
        log.error(safe_str_convert(e))

        # If this is an out of memory error terminate the process with an
        # error code indicating that there are memory problems. This is so
        # that higer level systems using ViperMonkey can see that there is a
        # memory issue and handle it accordingly.
        if isinstance(e, MemoryError):
            log.error("Exiting ViperMonkey with error code 137 (out of memory)")
            sys.exit(137)

        # Done. Analysis failed.
        return None

def process_file_scanexpr (container, filename, data):
    """Process a single file.

    @param container (str) Path and filename of container if the file is within
    a zip archive, None otherwise.

    @param filename (str) path and filename of file on disk, or within
    the container.

    @param data (bytes) Content of the file if it is in a container,
    None if it is a file on disk.

    """
    #TODO: replace print by writing to a provided output file (sys.stdout by default)
    if container:
        display_filename = '%s in %s' % (filename, container)
    else:
        display_filename = filename
    safe_print('='*79)
    safe_print('FILE: ' + safe_str_convert(display_filename))
    all_code = ''
    try:
        #TODO: handle olefile errors, when an OLE file is malformed
        import oletools
        oletools.olevba.enable_logging()
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('opening %r' % filename)
        vba = VBA_Parser(filename, data, relaxed=True)
        if vba.detect_vba_macros():

            # Read in document metadata.
            vm = core.ViperMonkey(filename, data)
            ole = olefile.OleFileIO(filename)
            try:
                vm.set_metadata(ole.get_metadata())
            except Exception as e:
                log.warning("Reading in metadata failed. Trying fallback. " + safe_str_convert(e))
                vm.set_metadata(get_metadata_exif(filename))
            
            #print 'Contains VBA Macros:'
            for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
                # hide attribute lines:
                #TODO: option to disable attribute filtering
                vba_code = filter_vba(vba_code)
                safe_print('-'*79)
                safe_print('VBA MACRO %s ' % vba_filename)
                safe_print('in file: %s - OLE stream: %s' % (subfilename, repr(stream_path)))
                safe_print('- '*39)
                # detect empty macros:
                if vba_code.strip() == '':
                    safe_print('(empty macro)')
                else:
                    # TODO: option to display code
                    safe_print(vba_code)
                    vba_code = core.vba_collapse_long_lines(vba_code)
                    all_code += '\n' + vba_code
            safe_print('-'*79)
            safe_print('EVALUATED VBA EXPRESSIONS:')
            t = prettytable.PrettyTable(('Obfuscated expression', 'Evaluated value'))
            t.align = 'l'
            t.max_width['Obfuscated expression'] = 36
            t.max_width['Evaluated value'] = 36
            for expression, expr_eval in core.scan_expressions(all_code):
                t.add_row((repr(expression), repr(expr_eval)))
                safe_print(t)

        else:
            safe_print('No VBA macros found.')
    except Exception as e:
        log.error("Caught exception. " + safe_str_convert(e))
        if (log.getEffectiveLevel() == logging.DEBUG):
            traceback.print_exc()

    safe_print('')

def print_version():
    """Print ViperMonkey version information.

    """

    safe_print("Version Information:\n")
    safe_print("ViperMonkey:\t\t" + safe_str_convert(__version__))
    safe_print("Python:\t\t\t" + safe_str_convert(sys.version_info))
    safe_print("pyparsing:\t\t" + safe_str_convert(pyparsing.__version__))
    safe_print("olefile:\t\t" + safe_str_convert(olefile.__version__))
    import oletools.olevba
    safe_print("olevba:\t\t\t" + safe_str_convert(oletools.olevba.__version__))

def main():
    """Main function, called when vipermonkey is run from the command
    line.

    """

    # Increase recursion stack depth.
    sys.setrecursionlimit(13000)
    
    # print banner with version
    # Generated with http://www.patorjk.com/software/taag/#p=display&f=Slant&t=ViperMonkey
    safe_print(''' _    ___                 __  ___            __             
| |  / (_)___  ___  _____/  |/  /___  ____  / /_____  __  __
| | / / / __ \/ _ \/ ___/ /|_/ / __ \/ __ \/ //_/ _ \/ / / /
| |/ / / /_/ /  __/ /  / /  / / /_/ / / / / ,< /  __/ /_/ / 
|___/_/ .___/\___/_/  /_/  /_/\____/_/ /_/_/|_|\___/\__, /  
     /_/                                           /____/   ''')
    safe_print('vmonkey %s - https://github.com/decalage2/ViperMonkey' % __version__)
    safe_print('THIS IS WORK IN PROGRESS - Check updates regularly!')
    safe_print('Please report any issue at https://github.com/decalage2/ViperMonkey/issues')
    safe_print('')

    DEFAULT_LOG_LEVEL = "info" # Default log level
    LOG_LEVELS = {
        'debug':    logging.DEBUG,
        'info':     logging.INFO,
        'warning':  logging.WARNING,
        'error':    logging.ERROR,
        'critical': logging.CRITICAL
        }

    usage = 'usage: %prog [options] <filename> [filename2 ...]'
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-r", action="store_true", dest="recursive",
                      help='find files recursively in subdirectories.')
    parser.add_option("-z", "--zip", dest='zip_password', type='str', default=None,
                      help='if the file is a zip archive, open first file from it, using the '
                           'provided password (requires Python 2.6+)')
    parser.add_option("-f", "--zipfname", dest='zip_fname', type='str', default='*',
                      help='if the file is a zip archive, file(s) to be opened within the zip. '
                           'Wildcards * and ? are supported. (default:*)')
    parser.add_option("-e", action="store_true", dest="scan_expressions",
                      help='Extract and evaluate/deobfuscate constant expressions')
    parser.add_option('-l', '--loglevel', dest="loglevel", action="store", default=DEFAULT_LOG_LEVEL,
                      help="logging level debug/info/warning/error/critical (default=%default)")
    parser.add_option("-s", '--strip', action="store_true", dest="strip_useless_code",
                      help='Strip useless VB code from macros prior to parsing.')
    parser.add_option("-j", '--jit', action="store_true", dest="do_jit",
                      help='Speed up emulation by JIT compilation of VB loops to Python.')
    parser.add_option('-i', '--init', dest="entry_points", action="store", default=None,
                      help="Emulate starting at the given function name(s). Use comma seperated "
                           "list for multiple entries.")
    parser.add_option('-t', '--time-limit', dest="time_limit", action="store", default=None,
                      type='int', help="Time limit (in minutes) for emulation.")
    parser.add_option("-c", '--iocs', action="store_true", dest="display_int_iocs",
                      help='Display potential IOCs stored in intermediate VBA variables '
                           'assigned during emulation (URLs and base64).')
    parser.add_option("-v", '--version', action="store_true", dest="print_version",
                      help='Print version information of packages used by ViperMonkey.')
    parser.add_option("-o", "--out-file", action="store", default=None, type="str",
                      help="JSON output file containing resulting IOCs, builtins, and actions")
    parser.add_option("-p", "--tee-log", action="store_true", default=False,
                      help="output also to a file in addition to standard out")
    parser.add_option("-b", "--tee-bytes", action="store", default=0, type="int",
                      help="number of bytes to limit the tee'd log to")

    (options, args) = parser.parse_args()

    # Print version information and exit?
    if (options.print_version):
        print_version()
        sys.exit(0)
    
    # Print help if no arguments are passed
    if len(args) == 0:
        safe_print(__doc__)
        parser.print_help()
        sys.exit(0)

    # setup logging to the console
    # logging.basicConfig(level=LOG_LEVELS[options.loglevel], format='%(levelname)-8s %(message)s')
    colorlog.basicConfig(level=LOG_LEVELS[options.loglevel], format='%(log_color)s%(levelname)-8s %(message)s')

    json_results = []

    for container, filename, data in xglob.iter_files(args,
                                                      recursive=options.recursive,
                                                      zip_password=options.zip_password,
                                                      zip_fname=options.zip_fname):

        # ignore directory names stored in zip files:
        if container and filename.endswith('/'):
            continue
        if options.scan_expressions:
            process_file_scanexpr(container, filename, data)
        else:
            entry_points = None
            if (options.entry_points is not None):
                entry_points = options.entry_points.split(",")
            process_file(container,
                         filename,
                         data,
                         strip_useless=options.strip_useless_code,
                         entry_points=entry_points,
                         time_limit=options.time_limit,
                         display_int_iocs=options.display_int_iocs,
                         tee_log=options.tee_log,
                         tee_bytes=options.tee_bytes,
                         out_file_name=options.out_file,
                         do_jit=options.do_jit)

            # add json results to list
            if (options.out_file):
                with open(options.out_file, 'r') as json_file:
                    try:
                        json_results.append(json.loads(json_file.read()))
                    except ValueError:
                        pass

    if (options.out_file):
        with open(options.out_file, 'w') as json_file:
            if (len(json_results) > 1):
                json_file.write(json.dumps(json_results, indent=2))
            else:
                json_file.write(json.dumps(json_results[0], indent=2))

        log.info("Saved results JSON to output file " + options.out_file)


if __name__ == '__main__':
    main()

# Soundtrack: This code was developed while listening to The Pixies "Monkey Gone to Heaven"
