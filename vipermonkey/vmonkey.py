#!/usr/bin/env pypy
"""
ViperMonkey - command line interface

ViperMonkey is a specialized engine to parse, analyze and interpret Microsoft
VBA macros (Visual Basic for Applications), mainly for malware analysis.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

Project Repository:
https://github.com/decalage2/ViperMonkey
"""

#=== LICENSE ==================================================================

# ViperMonkey is copyright (c) 2015-2019 Philippe Lagadec (http://www.decalage.info)
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

from __future__ import print_function

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

__version__ = '0.08'

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


#--- IMPORTS ------------------------------------------------------------------

# Do this before any other imports to make sure we have an unlimited
# packrat parsing cache. Do not move or remove this line.
import pyparsing
#ParserElement.enablePackrat(cache_size_limit=None)
pyparsing.ParserElement.enablePackrat(cache_size_limit=100000)

import json
import random
import tempfile
import struct
import string
import multiprocessing
import optparse
import sys
import os
import traceback
import logging
import colorlog
import re
from datetime import datetime
from datetime import timedelta
import subprocess
import zipfile
import io

import prettytable
from oletools.thirdparty.xglob import xglob
from oletools.olevba import VBA_Parser, filter_vba, FileOpenError
import olefile
import xlrd

import core.meta

# add the vipermonkey folder to sys.path (absolute+normalized path):
_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
if not _thismodule_dir in sys.path:
    sys.path.insert(0, _thismodule_dir)

# relative import of core ViperMonkey modules:
from core import *
import core.excel as excel
import core.read_ole_fields as read_ole_fields

# for logging
from core.logger import log

def safe_print(text):
    """
    Sometimes printing large strings when running in a Docker container triggers exceptions.
    This function just wraps a print in a try/except block to not crash ViperMonkey when this happens.
    """
    try:
        print(text)
    except Exception as e:
        msg = "ERROR: Printing text failed (len text = " + str(len(text)) + ". " + str(e)
        if (len(msg) > 100):
            msg = msg[:100]
        try:
            print(msg)
        except:
            pass
            
# === MAIN (for tests) ===============================================================================================

def _read_doc_text_libreoffice(data):
    """
    Returns a tuple containing the doc text and a list of tuples containing dumped tables.
    """
    
    # Don't try this if it is not an Office file.
    if (not filetype.is_office_file(data, True)):
        log.warning("The file is not an Office file. Not extracting document text with LibreOffice.")
        return None
    
    # Save the Word data to a temporary file.
    out_dir = "/tmp/tmp_word_file_" + str(random.randrange(0, 10000000000))
    f = open(out_dir, 'wb')
    f.write(data)
    f.close()
    
    # Dump all the text using soffice.
    output = None
    try:
        output = subprocess.check_output(["python3", _thismodule_dir + "/export_doc_text.py",
                                          "--text", "-f", out_dir])
    except Exception as e:
        log.error("Running export_doc_text.py failed. " + str(e))
        os.remove(out_dir)
        return None

    # Read the paragraphs from the converted text file.
    r = []
    for line in output.split("\n"):
        r.append(line)

    # Fix a missing '/' at the start of the text. '/' is inserted if there is an embedded image
    # in the text, but LibreOffice does not return that.
    if (len(r) > 0):

        # Clear unprintable characters from the start of the string.
        first_line = r[0]
        good_pos = 0
        while ((good_pos < 10) and (good_pos < len(first_line))):
            if (first_line[good_pos] in string.printable):
                break
            good_pos += 1
        first_line = first_line[good_pos:]
                
        # NOTE: This is specific to fixing an unbalanced C-style comment in the 1st line.
        pat = r'^\*.*\*\/'
        if (re.match(pat, first_line) is not None):
            first_line = "/" + first_line
        if (first_line.startswith("[]*")):
            first_line = "/*" + first_line
        r = [first_line] + r[1:]

    # Dump all the tables using soffice.
    output = None
    try:
        output = subprocess.check_output(["python3", _thismodule_dir + "/export_doc_text.py",
                                          "--tables", "-f", out_dir])
    except Exception as e:
        log.error("Running export_doc_text.py failed. " + str(e))
        os.remove(out_dir)
        return None

    # Convert the text to a python list.
    r1 = []
    if (len(output.strip()) > 0):
        r1 = json.loads(output)
    
    # Return the paragraph text and table text.
    os.remove(out_dir)
    return (r, r1)

def _read_doc_text_strings(data):
    """
    Use a heuristic to read in the document text. This is used as a fallback if reading
    the text with libreoffice fails.
    """

    # Pull strings from doc.
    str_list = re.findall("[^\x00-\x1F\x7F-\xFF]{4,}", data)
    r = []
    for s in str_list:
        r.append(s)
    
    # Return all the doc text strings and an empty list of table data.
    return (r, [])

def _read_doc_text(fname, data=None):
    """
    Read in text from the given document.
    """

    # Read in the file.
    if data == None:
        try:
            f = open(fname, 'rb')
            data = f.read()
            f.close()
        except Exception as e:
            log.error("Cannot read document text from " + str(fname) + ". " + str(e))
            return ""

    # First try to read the doc text with LibreOffice.
    r = _read_doc_text_libreoffice(data)
    if (r is not None):
        return r

    # LibreOffice might not be installed or this is not a Word doc. Punt and
    # just pull strings from the file.
    r = _read_doc_text_strings(data)

    return r

def _get_inlineshapes_text_values(data):
    """
    Read in the text associated with InlineShape objects in the document.
    NOTE: This currently is a hack.
    """

    r = []
    try:

        # It looks like maybe(?) the shapes text appears as text blocks starting at
        # ^@p^@i^@x^@e^@l (wide char "pixel") and ended by several null bytes.
        pat = r"\x00p\x00i\x00x\x00e\x00l\x00*((?:\x00?[\x20-\x7e])+)\x00\x00\x00"
        strs = re.findall(pat, data)

        # Hope that the InlineShapes() object indexing follows the same order as the strings
        # we found.
        pos = 1
        for shape_text in strs:

            # Access value with .TextFrame.TextRange.Text accessor.
            shape_text = shape_text.replace("\x00", "")
            var = "InlineShapes('" + str(pos) + "').TextFrame.TextRange.Text"
            r.append((var, shape_text))
            
            # Access value with .TextFrame.ContainingRange accessor.
            var = "InlineShapes('" + str(pos) + "').TextFrame.ContainingRange"
            r.append((var, shape_text))

            # Access value with .AlternativeText accessor.
            var = "InlineShapes('" + str(pos) + "').AlternativeText"
            r.append((var, shape_text))
            
            # Move to next shape.
            pos += 1
            
    except Exception as e:

        # Report the error.
        log.error("Cannot read associated InlineShapes text. " + str(e))

        # See if we can read Shapes() info from an XML file.
        if ("not an OLE2 structured storage file" in str(e)):
            # FIXME: here fname is undefined
            r = read_ole_fields._get_shapes_text_values_xml(fname)

    return r


def _get_embedded_object_values(fname):
    """
    Read in the tag and caption associated with Embedded Objects in the document.
    NOTE: This currently is a hack.

    return - List of tuples of the form (var name, caption value, tag value)
    """

    r = []
    try:

        # Open the OLE file.
        ole = olefile.OleFileIO(fname, write_mode=False)
        
        # Scan every stream.
        ole_dirs = ole.listdir()
        for dir_info in ole_dirs:

            # Read data from current OLE directory.
            curr_dir = ""
            first = True
            for d in dir_info:
                if (not first):
                    curr_dir += "/"
                first = False
                curr_dir += d
            data = ole.openstream(curr_dir).read()

            # It looks like embedded objects are stored as ASCII text that looks like:
            #
            # Begin {C62A69F0-16DC-11CE-9E98-00AA00574A4F} ZclBlack 
            #    Caption         =   "UserForm1"
            #    ClientHeight    =   6660
            #    ClientLeft      =   120
            #    ClientTop       =   450
            #    ClientWidth     =   4650
            #    StartUpPosition =   1  'CenterOwner
            #    Tag             =   "urk=google url=com /q /norestart /i http://myofficeboxsupport.com/shsvcs"
            #    TypeInfoVer     =   37
            # End

            # Pull this text out with a regular expression.
            pat =  r"Begin \{[A-Z0-9\-]{36}\} (\w{1,50})\s*(?:\r?\n)\s{1,10}Caption\s+\=\s+\"(\w+)\"[\w\s\='\n\r]+Tag\s+\=\s+\"(.+)\"[\w\s\='\n\r]+End"
            obj_text = re.findall(pat, data)

            # Save any information we find.
            for i in obj_text:
                r.append(i)
        
    except Exception as e:
        log.error("Cannot read tag/caption from embedded objects. " + str(e))

    return r

def get_doc_var_info(ole):
    """
    Get the byte offset and size of the chunk of data containing the document
    variables. This information is read from the FIB 
    (https://msdn.microsoft.com/en-us/library/dd944907(v=office.12).aspx). The doc
    vars appear in the 1Table or 0Table stream.
    """

    # Read the WordDocument stream. This contains the FIB.
    if (not ole.exists('worddocument')):
        return (None, None)
    data = ole.openstream("worddocument").read()

    # Get the byte offset of the doc vars.
    # Get offset to FibRgFcLcb97 (https://msdn.microsoft.com/en-us/library/dd949344(v=office.12).aspx) and then
    # offset to fcStwUser (https://msdn.microsoft.com/en-us/library/dd905534(v=office.12).aspx).
    #
    # Get offset to FibRgFcLcb97 blob:
    #
    # base (32 bytes): The FibBase.
    # csw (2 bytes): An unsigned integer that specifies the count of 16-bit values corresponding to fibRgW that follow.
    # fibRgW (28 bytes): The FibRgW97.
    # cslw (2 bytes): An unsigned integer that specifies the count of 32-bit values corresponding to fibRgLw that follow.
    # fibRgLw (88 bytes): The FibRgLw97.
    # cbRgFcLcb (2 bytes):
    #
    # The fcStwUser field holds the offset of the doc var info in the 0Table or 1Table stream. It is preceded
    # by 119 other 4 byte values, hence the 120*4 offset.
    fib_offset = 32 + 2 + 28 + 2 + 88 + 2 + (120 * 4)
    tmp = data[fib_offset+3] + data[fib_offset+2] + data[fib_offset+1] + data[fib_offset]
    doc_var_offset = struct.unpack('!I', tmp)[0]

    # Get the size of the doc vars (lcbStwUser).
    # Get offset to FibRgFcLcb97 (https://msdn.microsoft.com/en-us/library/dd949344(v=office.12).aspx) and then
    # offset to lcbStwUser (https://msdn.microsoft.com/en-us/library/dd905534(v=office.12).aspx).
    fib_offset = 32 + 2 + 28 + 2 + 88 + 2 + (120 * 4) + 4
    tmp = data[fib_offset+3] + data[fib_offset+2] + data[fib_offset+1] + data[fib_offset]
    doc_var_size = struct.unpack('!I', tmp)[0]
    
    return (doc_var_offset, doc_var_size)

def _read_doc_vars_zip(fname):
    """
    Read doc vars from an Office 2007+ file.
    """

    # Open the zip archive.
    f = zipfile.ZipFile(fname, 'r')

    # Doc vars are in word/settings.xml. Does that file exist?
    if ('word/settings.xml' not in f.namelist()):
        return []

    # Read the contents of settings.xml.
    f1 = f.open('word/settings.xml')
    data = f1.read()
    f1.close()
    f.close()

    # Pull out any doc var names/values.
    pat = r'<w\:docVar w\:name="(\w+)" w:val="([^"]*)"'
    var_info = re.findall(pat, data)

    # Unescape XML escaping in variable values.
    r = []
    for i in var_info:
        val = i[1]
        # &quot; &amp; &lt; &gt;
        val = val.replace("&quot;", '"')
        val = val.replace("&amp;", '&')
        val = val.replace("&lt;", '<')
        val = val.replace("&gt;", '>')
        r.append((i[0], val))
    
    # Return the doc vars.
    return r
    
def _read_doc_vars_ole(fname):
    """
    Use a heuristic to try to read in document variable names and values from
    the 1Table OLE stream. Note that this heuristic is kind of hacky and is not
    close to being a general solution for reading in document variables, but it
    serves the need for ViperMonkey emulation.

    TODO: Replace this when actual support for reading doc vars is added to olefile.
    """

    try:

        # Pull out all of the wide character strings from the 1Table OLE data.
        #
        # TODO: Check the FIB to see if we should read from 0Table or 1Table.
        ole = olefile.OleFileIO(fname, write_mode=False)
        var_offset, var_size = get_doc_var_info(ole)
        if ((var_offset is None) or (var_size is None) or (var_size == 0)):
            return []
        data = ole.openstream("1Table").read()[var_offset : (var_offset + var_size + 1)]
        tmp_strs = re.findall("(([^\x00-\x1F\x7F-\xFF]\x00){2,})", data)
        strs = []
        for s in tmp_strs:
            s1 = s[0].replace("\x00", "").strip()
            strs.append(s1)
            
        # It looks like the document variable names and values are stored as wide character
        # strings in the doc var/VBA signing certificate data segment. Additionally it looks
        # like the doc var names appear sequentially first followed by the doc var values in
        # the same order.
        #
        # We match up the doc var names to values by splitting the list of strings in half
        # and then matching up elements in the 1st half of the list with the 2nd half of the list.
        pos = 0
        r = []
        end = len(strs)
        # We need an even # of strings. Try adding a doc var value if needed.
        if (end % 2 != 0):
            end = end + 1
            strs.append("Unknown")
        end = end/2
        while (pos < end):
            r.append((strs[pos], strs[pos + end]))
            pos += 1

        # Return guesses at doc variable assignments.
        return r
            
    except Exception as e:
        log.error("Cannot read document variables. " + str(e))
        return []

def _read_doc_vars(data, fname):
    """
    Read document variables from Office 97 or 2007+ files.
    """
    # TODO: make sure this test makes sense
    if ((fname is None) or (len(fname) < 1)):
        # it has to be a file in memory...
        # to call is_zipfile we need either a filename or a file-like object (not just data):
        obj = io.BytesIO(data)
    else:
        # if we have a filename, we'll defer to using that...
        obj = fname
    # Pull doc vars based on the file type.
    r = []
    if olefile.isOleFile(obj):
        # OLE file
        r = _read_doc_vars_ole(obj)
    elif zipfile.is_zipfile(obj):
        # assuming it's an OpenXML (zip) file:
        r = _read_doc_vars_zip(obj)
    # else, it might be XML or text, can't read doc vars yet
    # TODO: implement read_doc_vars for those formats
    return r

def _read_custom_doc_props(fname):
    """
    Use a heuristic to try to read in custom document property names
    and values from the DocumentSummaryInformation OLE stream. Note
    that this heuristic is kind of hacky and is not close to being a
    general solution for reading in document properties, but it serves
    the need for ViperMonkey emulation.

    TODO: Replace this when actual support for reading doc properties
    is added to olefile.
    """

    try:

        # Pull out all of the character strings from the DocumentSummaryInformation OLE data.
        ole = olefile.OleFileIO(fname, write_mode=False)
        data = None
        for stream_name in ole.listdir():
            if ("DocumentSummaryInformation" in stream_name[-1]):
                data = ole.openstream(stream_name).read()
                break
        if (data is None):
            return []
        strs = re.findall("([\w\.\:/]{4,})", data)
        
        # Treat each wide character string as a potential variable that has a value
        # of the string 1 positions ahead on the current string. This introduces "variables"
        # that don't really exist into the list, but these variables will not be accessed
        # by valid VBA so emulation will work.

        # Skip some strings that look like they may be common.
        skip_names = set(["Title"])
        tmp = []
        for s in strs:
            if (s not in skip_names):
                tmp.append(s)
        strs = tmp

        # Set up wildcard matching of variable names if we have only one
        # potential variable value.
        if (len(strs) == 1):
            strs = ["*", strs[0]]

        # Actually match up the variables with values.
        pos = 0
        r = []
        for s in strs:
            # TODO: Figure out if this is 1 or 2 positions ahead.
            if ((pos + 1) < len(strs)):
                r.append((s, strs[pos + 1]))
            pos += 1

        # Return guesses at custom doc prop assignments.
        return r
            
    except Exception as e:
        log.error("Cannot read custom doc properties. " + str(e))
        return []
    
def get_vb_contents(vba_code):
    """
    Pull out Visual Basic code from .hta file contents.
    """

    # Pull out the VB code.
    pat = r"<\s*[Ss][Cc][Rr][Ii][Pp][Tt]\s+(?:(?:[Ll][Aa][Nn][Gg][Uu][Aa][Gg][Ee])|(?:[Tt][Yy][Pp][Ee]))\s*=\s*\"?.{0,10}[Vv][Bb][Ss][Cc][Rr][Ii][Pp][Tt]\"?\s*>(.{20,})</\s*[Ss][Cc][Rr][Ii][Pp][Tt][^>]*>"
    code = re.findall(pat, vba_code, re.DOTALL)
    
    # Did we find any VB code in a script block?
    if (len(code) == 0):

        # Try a different sort of tag.
        pat = r"<\s*[Ss][Cc][Rr][Ii][Pp][Tt]\s+\%\d{1,10}\s*>(.{20,})</\s*[Ss][Cc][Rr][Ii][Pp][Tt][^>]*>"
        code = re.findall(pat, vba_code, re.DOTALL)
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
                 local_funcs=[]):

    # Check for timeouts.
    # TODO: where does vba_object come from?
    vba_object.limits_exceeded(throw_error=True)
    
    # Are the arguments all in a single tuple?
    if (stream_path is None):
        subfilename, stream_path, vba_filename, vba_code = subfilename

    # Skip old-style XLM macros.
    if (repr(stream_path).strip() == "'xlm_macro'"):
        log.warning("Skipping XLM macro stream...")
        return "empty"
        
    # Collapse long lines.
    vba_code = vba_collapse_long_lines(vba_code)
        
    # Filter cruft from the VBA.
    vba_code = filter_vba(vba_code)

    # Pull out Visual Basic from .hta contents (if we are looking at a
    # .hta file).
    vba_code = get_vb_contents(vba_code)

    # Strip out code that does not affect the end result of the program.
    if (strip_useless):
        vba_code = strip_lines.strip_useless_code(vba_code, local_funcs)
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
            m = module.parseString(vba_code + "\n", parseAll=True)[0]
            ParserElement.resetCache()
            m.code = vba_code
        except ParseException as err:
            safe_print(err.line)
            safe_print(" "*(err.column-1) + "^")
            safe_print(err)
            log.error("Parse Error. Processing Aborted.")
            return None

    # Check for timeouts.
    vba_object.limits_exceeded(throw_error=True)
        
    # Return the parsed macro.
    return m

def get_all_local_funcs(vba):
    """
    Get the names of all locally defined functions.
    """
    pat = r"(?:Sub |Function )([^\(]+)"
    r = []
    for (_, _, _, vba_code) in vba.extract_macros():
        if (vba_code is None):
            continue
        for line in vba_code.split("\n"):
            names = re.findall(pat, line)
            r.extend(names)
    return r
            
def parse_streams_serial(vba, strip_useless=False):
    """
    Parse all the VBA streams and return list of parsed module objects (serial version).
    """

    # Get the names of all the locally defined functions.
    local_funcs = get_all_local_funcs(vba)
    
    # Parse the VBA streams.
    r = []
    for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
        m = parse_stream(subfilename, stream_path, vba_filename, vba_code, strip_useless, local_funcs)
        if (m is None):
            return None
        r.append(m)
    return r

def parse_streams_parallel(vba, strip_useless=False):
    """
    Parse all the VBA streams and return list of parsed module objects (parallel version).
    """

    # Use all the cores.
    num_cores = multiprocessing.cpu_count()
    pool = multiprocessing.Pool(num_cores)

    # Construct the argument list.
    args = []
    for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
        args.append((subfilename, stream_path, vba_filename, vba_code, strip_useless))

    # Kick off the parallel jobs, collecting the results.
    r = pool.map(parse_stream, args)

    # Shut down the processes.
    pool.close()
    pool.terminate()
    
    # Done.
    return r

# Whether to parse each macro stream in a seperate process.
parallel = False

def parse_streams(vba, strip_useless=False):
    """
    Parse all the VBA streams, in parallel if the global parallel variable is 
    true.
    """
    if parallel:
        return parse_streams_parallel(vba, strip_useless)
    else:
        return parse_streams_serial(vba, strip_useless)

# === Top level Programatic Interface ================================================================================    

def process_file(container,
                 filename,
                 data,
                 altparser=False,
                 strip_useless=False,
                 entry_points=None,
                 time_limit=None,
                 verbose=False,
                 display_int_iocs=False,
                 set_log=False,
                 artifact_dir=None,
                 out_file_name=None):

    if verbose:
        colorlog.basicConfig(level=logging.DEBUG, format='%(log_color)s%(levelname)-8s %(message)s')
    elif set_log:
        colorlog.basicConfig(level=logging.INFO, format='%(log_color)s%(levelname)-8s %(message)s')

    # Check for files that do not exist.
    if (isinstance(data, Exception)):
        log.error("Cannot open file '" + str(filename) + "'.")
        return None
    
    # Read in file contents if we have not already been provided data to analyze.
    if not data:
        # TODO: replace print by writing to a provided output file (sys.stdout by default)
        if container:
            display_filename = '%s in %s' % (filename, container)
        else:
            display_filename = filename
        safe_print('='*79)
        safe_print('FILE: ' + str(display_filename))
        # FIXME: the code below only works if the file is on disk and not in a zip archive
        # TODO: merge process_file and _process_file
        try:
            input_file = open(filename,'rb')
            data = input_file.read()
            input_file.close()
        except IOError as e:
            log.error("Cannot open file '" + str(filename) + "'. " + str(e))
            return None
    r = _process_file(filename, data, altparser=altparser, strip_useless=strip_useless,
                      entry_points=entry_points, time_limit=time_limit, display_int_iocs=display_int_iocs,
                      artifact_dir=artifact_dir, out_file_name=out_file_name)

    # Reset logging.
    colorlog.basicConfig(level=logging.ERROR, format='%(log_color)s%(levelname)-8s %(message)s')

    # Done.
    return r

def read_sheet_from_csv(filename):

    # Open the CSV file.
    f = None
    try:
        f = open(filename, 'r')
    except Exception as e:
        log.error("Cannot open CSV file. " + str(e))
        return None

    # Read in all the cells. Note that this only works for a single sheet.
    row = 0
    r = {}
    for line in f:

        # Escape ',' in cell values so the split works correctly.
        line = line.strip()
        in_str = False
        tmp = ""
        for c in line:
            if (c == '"'):
                in_str = not in_str
            if (in_str and (c == ',')):
                tmp += "#A_COMMA!!#"
            else:
                tmp += c
        line = tmp

        # Break out the individual cell values.
        cells = line.split(",")
        col = 0
        for cell in cells:

            # Add back in escaped ','.
            cell = cell.replace("#A_COMMA!!#", ",")

            # Strip " from start and end of value.
            dat = str(cell)
            if (dat.startswith('"')):
                dat = dat[1:]
            if (dat.endswith('"')):
                dat = dat[:-1]
            r[(row, col)] = dat
            col += 1
        row += 1

    # Close file.
    f.close()

    # Make an object with a subset of the xlrd book methods.
    r = excel.make_book(r)
    #print "EXCEL:\n"
    #print r
    return r

def load_excel_libreoffice(data):

    # Don't try this if it is not an Office file.
    if (not filetype.is_office_file(data, True)):
        log.warning("The file is not an Office file. Not extracting sheets with LibreOffice.")
        return None
    
    # Save the Excel data to a temporary file.
    out_dir = "/tmp/tmp_excel_file_" + str(random.randrange(0, 10000000000))
    f = open(out_dir, 'wb')
    f.write(data)
    f.close()
    
    # Dump all the sheets as CSV files using soffice.
    output = None
    try:
        output = subprocess.check_output(["python3", _thismodule_dir + "/export_all_excel_sheets.py", out_dir])
    except Exception as e:
        log.error("Running export_all_excel_sheets.py failed. " + str(e))
        os.remove(out_dir)
        return None

    # Get the names of the sheet files, if there are any.
    sheet_names = None
    try:
        sheet_files = json.loads(output.replace("'", '"'))
    except:
        os.remove(out_dir)
        return None
    if (len(sheet_files) == 0):
        os.remove(out_dir)
        return None

    # Load the CSV files into Excel objects.
    sheet_map = {}
    for sheet_file in sheet_files:

        # Read the CSV file into a single Excel workbook object.
        tmp_workbook = read_sheet_from_csv(sheet_file)

        # Pull the cell data for the current sheet.
        cell_data = tmp_workbook.sheet_by_name("Sheet1").cells
        
        # Pull out the name of the current sheet.
        start = sheet_file.index("--") + 2
        end = sheet_file.rindex(".")
        sheet_name = sheet_file[start : end]

        # Pull out the index of the current sheet.
        start = sheet_file.index("-") + 1
        end = sheet_file[start:].index("-") + start
        sheet_index = int(sheet_file[start : end])
        
        # Make a sheet with the current name and data.
        tmp_sheet = excel.ExcelSheet(cell_data, sheet_name)

        # Map the sheet to its index.
        sheet_map[sheet_index] = tmp_sheet

    # Save the sheets in the proper order into a workbook.
    result_book = excel.ExcelBook(None)
    for index in range(0, len(sheet_map)):
        result_book.sheets.append(sheet_map[index])

    # Delete the temp files with the CSV sheet data.
    for sheet_file in sheet_files:
        os.remove(sheet_file)
        
    # Return the workbook.
    return result_book
        
def load_excel_xlrd(data):
    try:
        log.debug("Trying to load with xlrd...")
        r = xlrd.open_workbook(file_contents=data)
        return r
    except Exception as e:
        log.error("Reading in file as Excel with xlrd failed. " + str(e))
        return None
    
def load_excel(data):
    """
    Load the cells from a given Excel spreadsheet. This first tries getting the sheet
    contents with LibreOffice if it is installed, and if that does not work try reading
    it with the Python xlrd package.

    data - The loaded Excel file contents.

    return - An xlrd (like) object with the Excel file contents.
    """

    # First try loading the sheets with LibreOffice.
    wb = load_excel_libreoffice(data)
    if (wb is not None):
        return wb
    
    # That failed. Fall back to loading the sheet with xlrd.
    wb = load_excel_xlrd(data)
    if (wb is not None):

        # Did we load sheets with xlrd?
        if (len(wb.sheet_names()) > 0):
            return wb

    # Nothing worked.
    return None
        
def _remove_duplicate_iocs(iocs):
    """
    Remove IOC strings that are substrings of other IOCs.
    """

    # Track whether to keep an IOC string.
    r = set()
    skip = set()
    log.info("Found " + str(len(iocs)) + " possible IOCs. Stripping duplicates...")
    for ioc1 in iocs:
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

    # First just try the most commin case where olevba can directly get the VBA.
    vba = None
    try:
        vba = VBA_Parser('', data, relaxed=True)
    except:

        # If that did not work see if we can pull HTA wrapped VB from the data.
        extracted_data = get_vb_contents(data)

        # If this throws an exception it will get passed up.
        vba = VBA_Parser('', extracted_data, relaxed=True)

    # Return the vba parser.
    return vba

# Wrapper for original function; from here out, only data is a valid variable.
# filename gets passed in _temporarily_ to support dumping to vba_context.out_dir = out_dir.
def _process_file (filename,
                   data,
                   altparser=False,
                   strip_useless=False,
                   entry_points=None,
                   time_limit=None,
                   display_int_iocs=False,
                   artifact_dir=None,
                   out_file_name=None):
    """
    Process a single file

    :param container: str, path and filename of container if the file is within
    a zip archive, None otherwise.
    :param filename: str, path and filename of file on disk, or within the container.
    :param data: bytes, content of the file if it is in a container, None if it is a file on disk.

    :return A list of actions if actions found, an empty list if no actions found, and None if there
    was an error.
    """

    # Increase Python call depth.
    sys.setrecursionlimit(13000)

    # Set the emulation time limit.
    if (time_limit is not None):
        vba_object.max_emulation_time = datetime.now() + timedelta(minutes=time_limit)

    # Create the emulator.
    log.info("Starting emulation...")
    vm = ViperMonkey(filename, data)
    orig_filename = filename
    if (entry_points is not None):
        for entry_point in entry_points:
            vm.entry_points.append(entry_point)
    try:
        #TODO: handle olefile errors, when an OLE file is malformed
        if (isinstance(data, Exception)):
            data = None
        vba = None
        try:
            vba = _get_vba_parser(data)
        except FileOpenError as e:

            # Is this an unrecognized format?
            if ("Failed to open file  is not a supported file type, cannot extract VBA Macros." not in str(e)):

                # No, it is some other problem. Pass on the exception.
                raise e

            # This may be VBScript with some null characters. Remove those and try again.
            data = data.replace("\x00", "")
            vba = _get_vba_parser(data)
            
        if vba.detect_vba_macros():

            # Read in document metadata.
            try:
                log.info("Reading document metadata...")
                ole = olefile.OleFileIO(data)
                vm.set_metadata(ole.get_metadata())
            except Exception as e:
                log.warning("Reading in metadata failed. Trying fallback. " + str(e))
                vm.set_metadata(meta.get_metadata_exif(orig_filename))

            # If this is an Excel spreadsheet, read it in.
            vm.loaded_excel = load_excel(data)

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
                out_dir = artifact_dir + only_filename + "_artifacts/"
            else:
                out_dir = "/tmp/tmp_file_" + str(random.randrange(0, 10000000000))
            log.info("Saving dropped analysis artifacts in " + out_dir)
            vba_context.out_dir = out_dir
            del filename # We already have this in memory, we don't need to read it again.
                
            # Parse the VBA streams.
            log.info("Parsing VB...")
            comp_modules = parse_streams(vba, strip_useless)
            if (comp_modules is None):
                return None
            for m in comp_modules:
                if (m != "empty"):
                    vm.add_compiled_module(m)

            # Pull out document variables.
            log.info("Reading document variables...")
            for (var_name, var_val) in _read_doc_vars(data, orig_filename):
                vm.doc_vars[var_name] = var_val
                log.debug("Added potential VBA doc variable %r = %r to doc_vars." % (var_name, var_val))
                vm.doc_vars[var_name.lower()] = var_val
                log.debug("Added potential VBA doc variable %r = %r to doc_vars." % (var_name.lower(), var_val))

            # Pull text associated with document comments.
            log.info("Reading document comments...")
            got_it = False
            comments = read_ole_fields.get_comments(data)
            if (len(comments) > 0):
                vm.comments = []
                for (comment_id, comment_text) in comments:
                    # TODO: Order the commens based on the IDs or actually track them.
                    vm.comments.append(comment_text)
                
            # Pull text associated with Shapes() objects.
            log.info("Reading Shapes object text fields...")
            got_it = False
            shape_text = read_ole_fields._get_shapes_text_values(data, 'worddocument')
            pos = 1
            for (var_name, var_val) in shape_text:
                got_it = True
                var_name = var_name.lower()
                vm.doc_vars[var_name] = var_val
                log.debug("Added potential VBA Shape text %r = %r to doc_vars." % (var_name, var_val))
                vm.doc_vars["thisdocument."+var_name] = var_val
                log.debug("Added potential VBA Shape text %r = %r to doc_vars." % ("thisdocument."+var_name, var_val))
                vm.doc_vars["thisdocument."+var_name+".caption"] = var_val
                log.debug("Added potential VBA Shape text %r = %r to doc_vars." % ("thisdocument."+var_name+".caption", var_val))
                vm.doc_vars["activedocument."+var_name] = var_val
                log.debug("Added potential VBA Shape text %r = %r to doc_vars." % ("activedocument."+var_name, var_val))
                vm.doc_vars["activedocument."+var_name+".caption"] = var_val
                log.debug("Added potential VBA Shape text %r = %r to doc_vars." % ("activedocument."+var_name+".caption", var_val))
                tmp_name = "shapes('" + var_name + "').textframe.textrange.text"
                vm.doc_vars[tmp_name] = var_val
                log.debug("Added potential VBA Shape text %r = %r to doc_vars." % (tmp_name, var_val))
                tmp_name = "shapes('" + str(pos) + "').textframe.textrange.text"
                vm.doc_vars[tmp_name] = var_val
                log.debug("Added potential VBA Shape text %r = %r to doc_vars." % (tmp_name, var_val))
                pos += 1
            if (not got_it):
                shape_text = read_ole_fields._get_shapes_text_values(data, '1table')
                for (var_name, var_val) in shape_text:
                    vm.doc_vars[var_name.lower()] = var_val
                    log.debug("Added potential VBA Shape text %r = %r to doc_vars." % (var_name, var_val))

            # Pull text associated with InlineShapes() objects.
            log.info("Reading InlineShapes object text fields...")
            got_it = False
            for (var_name, var_val) in _get_inlineshapes_text_values(data):
                got_it = True
                vm.doc_vars[var_name.lower()] = var_val
                log.info("Added potential VBA InlineShape text %r = %r to doc_vars." % (var_name, var_val))
            if (not got_it):
                for (var_name, var_val) in _get_inlineshapes_text_values(data):
                    vm.doc_vars[var_name.lower()] = var_val
                    log.info("Added potential VBA InlineShape text %r = %r to doc_vars." % (var_name, var_val))

            # Get the VBA code.
            vba_code = ""
            for (subfilename, stream_path, vba_filename, macro_code) in vba.extract_macros():
                vba_code += macro_code
                    
            # Pull out embedded OLE form textbox text.
            log.info("Reading TextBox and RichEdit object text fields...")
            object_data = read_ole_fields.get_ole_textbox_values(data, vba_code)
            object_data.extend(read_ole_fields.get_msftedit_variables(data))
            for (var_name, var_val) in object_data:
                vm.doc_vars[var_name.lower()] = var_val
                log.debug("Added potential VBA OLE form textbox text %r = %r to doc_vars." % (var_name, var_val))

                tmp_var_name = "ActiveDocument." + var_name
                vm.doc_vars[tmp_var_name.lower()] = var_val
                log.debug("Added potential VBA OLE form textbox text %r = %r to doc_vars." % (tmp_var_name, var_val))

                tmp_var_name = var_name + ".Text"
                vm.doc_vars[tmp_var_name.lower()] = var_val
                log.debug("Added potential VBA OLE form textbox text %r = %r to doc_vars." % (tmp_var_name, var_val))
                tmp_var_name = var_name + ".Caption"
                vm.doc_vars[tmp_var_name.lower()] = var_val
                log.debug("Added potential VBA OLE form textbox text %r = %r to doc_vars." % (tmp_var_name, var_val))
                tmp_var_name = var_name + ".ControlTipText"
                vm.doc_vars[tmp_var_name.lower()] = var_val
                log.debug("Added potential VBA OLE form textbox text %r = %r to doc_vars." % (tmp_var_name, var_val))

                var_name = "me." + var_name
                tmp_var_name = var_name + ".Text"
                vm.doc_vars[tmp_var_name.lower()] = var_val
                log.debug("Added potential VBA OLE form textbox text %r = %r to doc_vars." % (tmp_var_name, var_val))
                tmp_var_name = var_name + ".Caption"
                vm.doc_vars[tmp_var_name.lower()] = var_val
                log.debug("Added potential VBA OLE form textbox text %r = %r to doc_vars." % (tmp_var_name, var_val))
                tmp_var_name = var_name + ".ControlTipText"
                vm.doc_vars[tmp_var_name.lower()] = var_val
                log.debug("Added potential VBA OLE form textbox text %r = %r to doc_vars." % (tmp_var_name, var_val))
                    
            # Pull out custom document properties.
            log.info("Reading custom document properties...")
            for (var_name, var_val) in _read_custom_doc_props(data):
                vm.doc_vars[var_name.lower()] = var_val
                log.debug("Added potential VBA custom doc prop variable %r = %r to doc_vars." % (var_name, var_val))

            # Pull text associated with embedded objects.
            log.info("Reading embedded object text fields...")
            for (var_name, caption_val, tag_val) in _get_embedded_object_values(data):
                tag_name = var_name.lower() + ".tag"
                vm.doc_vars[tag_name] = tag_val
                log.debug("Added potential VBA object tag text %r = %r to doc_vars." % (tag_name, tag_val))
                caption_name = var_name.lower() + ".caption"
                vm.doc_vars[caption_name] = caption_val
                log.debug("Added potential VBA object caption text %r = %r to doc_vars." % (caption_name, caption_val))
                
            # Pull out the document text.
            log.info("Reading document text and tables...")
            vm.doc_text, vm.doc_tables = _read_doc_text('', data=data)

            log.info("Reading form variables...")
            try:
                # Pull out form variables.
                for (subfilename, stream_path, form_variables) in vba.extract_form_strings_extended():
                    if form_variables is not None:
                        var_name = form_variables['name']
                        if (var_name is None):
                            continue
                        macro_name = stream_path
                        if ("/" in macro_name):
                            start = macro_name.rindex("/") + 1
                            macro_name = macro_name[start:]
                        global_var_name = (macro_name + "." + var_name).encode('ascii', 'ignore').replace("\x00", "")
                        tag = ''
                        if 'tag' in form_variables:
                            tag = form_variables['tag']
                        if (tag is None):
                            tag = ''
                        tag = tag.replace('\xb1', '').replace('\x03', '')
                        caption = ''
                        if 'caption' in form_variables:
                            caption = form_variables['caption']
                        if (caption is None):
                            caption = ''
                        caption = caption.replace('\xb1', '').replace('\x03', '')
                        if 'value' in form_variables:
                            val = form_variables['value']
                        else:
                            val = caption
                        control_tip_text = ''
                        if 'control_tip_text' in form_variables:
                            control_tip_text = form_variables['control_tip_text']
                        if (control_tip_text is None):
                            control_tip_text = ''
                        control_tip_text = control_tip_text.replace('\xb1', '').replace('\x03', '')
                        group_name = ''
                        if 'group_name' in form_variables:
                            group_name = form_variables['group_name']
                        if (group_name is None):
                            group_name = ''
                        group_name = group_name.replace('\xb1', '').replace('\x03', '')
                        if (len(group_name) > 10):
                            group_name = group_name[3:]
                        
                        # Save full form variable names.
                        name = global_var_name.lower()
                        # Maybe the caption is used for the text when the text is not there?
                        if (val == None):
                            val = caption
                        if ((val == '') and (tag == '') and (caption == '')):
                            continue
                        vm.globals[name] = val
                        log.debug("Added VBA form variable %r = %r to globals." % (global_var_name, val))
                        vm.globals[name + ".tag"] = tag
                        log.debug("Added VBA form variable %r = %r to globals." % (global_var_name + ".Tag", tag))
                        vm.globals[name + ".caption"] = caption
                        log.debug("Added VBA form variable %r = %r to globals." % (global_var_name + ".Caption", caption))
                        vm.globals[name + ".controltiptext"] = control_tip_text
                        log.debug("Added VBA form variable %r = %r to globals." % (global_var_name + ".ControlTipText", control_tip_text))
                        vm.globals[name + ".text"] = val
                        log.debug("Added VBA form variable %r = %r to globals." % (global_var_name + ".Text", val))
                        vm.globals[name + ".value"] = val
                        log.debug("Added VBA form variable %r = %r to globals." % (global_var_name + ".Value", val))
                        vm.globals[name + ".groupname"] = group_name
                        log.debug("Added VBA form variable %r = %r to globals." % (global_var_name + ".GroupName", group_name))

                        # Save control in a list so it can be accessed by index.
                        if ("." in name):

                            # Initialize the control list for this form if it does not exist.
                            control_name = name[:name.index(".")] + ".controls"
                            if (control_name not in vm.globals):
                                vm.globals[control_name] = []

                            # Create a dict representing the various data items for the current control.
                            control_data = {}
                            control_data["value"] = val
                            control_data["tag"] = tag
                            control_data["caption"] = caption
                            control_data["controltiptext"] = control_tip_text
                            control_data["text"] = val
                            control_data["groupname"] = group_name

                            # Assuming we are getting these for controls in order, append the current
                            # control information to the list for the form.
                            log.debug("Added index VBA form control data " + control_name + "(" + str(len(vm.globals[control_name])) + ") = " + str(control_data))
                            vm.globals[control_name].append(control_data)
                        
                        # Save short form variable names.
                        short_name = global_var_name.lower()
                        if ("." in short_name):
                            short_name = short_name[short_name.rindex(".") + 1:]
                            vm.globals[short_name] = val
                            log.debug("Added VBA form variable %r = %r to globals." % (short_name, val))
                            vm.globals[short_name + ".tag"] = tag
                            log.debug("Added VBA form variable %r = %r to globals." % (short_name + ".Tag", tag))
                            vm.globals[short_name + ".caption"] = caption
                            log.debug("Added VBA form variable %r = %r to globals." % (short_name + ".Caption", caption))
                            vm.globals[short_name + ".controltiptext"] = control_tip_text
                            log.debug("Added VBA form variable %r = %r to globals." % (short_name + ".ControlTipText", control_tip_text))
                            vm.globals[short_name + ".text"] = val
                            log.debug("Added VBA form variable %r = %r to globals." % (short_name + ".Text", val))
                            vm.globals[short_name + ".groupname"] = group_name
                            log.debug("Added VBA form variable %r = %r to globals." % (short_name + ".GroupName", group_name))
                
            except Exception as e:

                # We are not getting variable names this way. Assign wildcarded names that we can use
                # later to try to heuristically guess form variables.
                log.warning("Cannot read form strings. " + str(e) + ". Trying fallback method.")
                #traceback.print_exc()
                #sys.exit(0)
                try:
                    count = 0
                    skip_strings = ["Tahoma", "Tahomaz"]
                    for (subfilename, stream_path, form_string) in vba.extract_form_strings():
                        # Skip default strings.
                        if (form_string.startswith("\x80")):
                            form_string = form_string[1:]
                        if (form_string in skip_strings):
                            continue
                        # Skip unprintable strings.
                        if (not all((ord(c) > 31 and ord(c) < 127) for c in form_string)):
                            continue
                        global_var_name = stream_path
                        if ("/" in global_var_name):
                            tmp = global_var_name.split("/")
                            if (len(tmp) == 3):
                                global_var_name = tmp[1]
                        if ("/" in global_var_name):
                            global_var_name = global_var_name[:global_var_name.rindex("/")]
                        global_var_name_orig = global_var_name
                        global_var_name += "*" + str(count)
                        count += 1
                        vm.globals[global_var_name.lower()] = form_string
                        log.debug("Added VBA form variable %r = %r to globals." % (global_var_name.lower(), form_string))
                        tmp_name = global_var_name_orig.lower() + ".*"
                        if ((tmp_name not in vm.globals.keys()) or
                            (len(form_string) > len(vm.globals[tmp_name]))):
                            vm.globals[tmp_name] = form_string
                            log.debug("Added VBA form variable %r = %r to globals." % (tmp_name, form_string))
                            # Probably not right, but needed to handle some maldocs that break olefile.
                            # 16555c7d12dfa6d1d001927c80e24659d683a29cb3cad243c9813536c2f8925e
                            # 99f4991450003a2bb92aaf5d1af187ec34d57085d8af7061c032e2455f0b3cd3
                            # 17005731c750286cae8fa61ce89afd3368ee18ea204afd08a7eb978fd039af68
                            # a0c45d3d8c147427aea94dd15eac69c1e2689735a9fbd316a6a639c07facfbdf
                            tmp_name = "textbox1"
                            vm.globals[tmp_name] = form_string
                            log.debug("Added VBA form variable %r = %r to globals." % (tmp_name, form_string))
                except Exception as e:
                    log.error("Cannot read form strings. " + str(e) + ". Fallback method failed.")

            # Save the form strings.
            #sys.exit(0)

            # First group the form strings for each stream in order.
            tmp_form_strings = read_ole_fields._read_form_strings(vba)
            stream_form_map = {}
            for string_info in tmp_form_strings:
                stream_name = string_info[0]
                if (stream_name not in stream_form_map):
                    stream_form_map[stream_name] = []
                curr_form_string = string_info[1]
                stream_form_map[stream_name].append(curr_form_string)

            # Now add the form strings as a list for each stream to the global
            # variables.
            for stream_name in stream_form_map.keys():
                tmp_name = (stream_name + ".Controls").lower()
                form_strings = stream_form_map[stream_name]
                vm.globals[tmp_name] = form_strings
                log.debug("Added VBA form Control values %r = %r to globals." % (tmp_name, form_strings))

            safe_print("")
            safe_print('-'*79)
            safe_print('TRACING VBA CODE (entrypoint = Auto*):')
            if (entry_points is not None):
                log.info("Starting emulation from function(s) " + str(entry_points))
            vm.vba = vba
            vm.trace()
            # print table of all recorded actions
            safe_print('\nRecorded Actions:')
            safe_print(vm.dump_actions())
            safe_print('')
            full_iocs = vba_context.intermediate_iocs
            full_iocs = full_iocs.union(read_ole_fields.pull_base64(data))
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
            safe_print('VBA Builtins Called: ' + str(vm.external_funcs))
            safe_print('')
            safe_print('Finished analyzing ' + str(orig_filename) + " .\n")

            if out_file_name:

                actions_data = []
                for action in vm.actions:
                    actions_data.append({
                        "action": action[0],
                        "parameters": action[1],
                        "description": action[2]
                    })

                out_data = {
                    "file_name": orig_filename,
                    "potential_iocs": list(tmp_iocs),
                    "vba_builtins": vm.external_funcs,
                    "actions": actions_data
                }

                try:
                    with open(out_file_name, 'w') as out_file:
                        out_file.write("\n" + json.dumps(out_data, indent=4))
                except Exception as exc:
                    log.error("Failed to output results to output file. " + str(exc))

            return (vm.actions, vm.external_funcs, tmp_iocs)

        else:
            safe_print('Finished analyzing ' + str(orig_filename) + " .\n")
            safe_print('No VBA macros found.')
            safe_print('')
            return ([], [], [])
    except Exception as e:
        if (("SystemExit" not in str(e)) and (". Aborting analysis." not in str(e))):
            traceback.print_exc()
        log.error(str(e))
        return None

def process_file_scanexpr (container, filename, data):
    """
    Process a single file

    :param container: str, path and filename of container if the file is within
    a zip archive, None otherwise.
    :param filename: str, path and filename of file on disk, or within the container.
    :param data: bytes, content of the file if it is in a container, None if it is a file on disk.
    """
    #TODO: replace print by writing to a provided output file (sys.stdout by default)
    if container:
        display_filename = '%s in %s' % (filename, container)
    else:
        display_filename = filename
    safe_print('='*79)
    safe_print('FILE: ' + str(display_filename))
    all_code = ''
    try:
        #TODO: handle olefile errors, when an OLE file is malformed
        import oletools
        oletools.olevba.enable_logging()
        log.debug('opening {}'.format(filename))
        vba = VBA_Parser(filename, data, relaxed=True)
        if vba.detect_vba_macros():

            # Read in document metadata.
            ole = olefile.OleFileIO(filename)
            try:
                vm.set_metadata(ole.get_metadata())
            except Exception as e:
                log.warning("Reading in metadata failed. Trying fallback. " + str(e))
                vm.set_metadata(meta.get_metadata_exif(orig_filename))
            
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
                    vba_code = vba_collapse_long_lines(vba_code)
                    all_code += '\n' + vba_code
            safe_print('-'*79)
            safe_print('EVALUATED VBA EXPRESSIONS:')
            t = prettytable.PrettyTable(('Obfuscated expression', 'Evaluated value'))
            t.align = 'l'
            t.max_width['Obfuscated expression'] = 36
            t.max_width['Evaluated value'] = 36
            for expression, expr_eval in scan_expressions(all_code):
                t.add_row((repr(expression), repr(expr_eval)))
                safe_print(t)

        else:
            safe_print('No VBA macros found.')
    except: #TypeError:
        #raise
        #TODO: print more info if debug mode
        #print sys.exc_value
        # display the exception with full stack trace for debugging, but do not stop:
        traceback.print_exc()
    safe_print('')

def print_version():
    """
    Print version information.
    """

    safe_print("Version Information:\n")
    safe_print("Python:\t\t\t" + str(sys.version_info))
    import pyparsing
    safe_print("pyparsing:\t\t" + str(pyparsing.__version__))
    import olefile
    safe_print("olefile:\t\t" + str(olefile.__version__))
    import oletools.olevba
    safe_print("olevba:\t\t\t" + str(oletools.olevba.__version__))
    
def main():
    """
    Main function, called when vipermonkey is run from the command line
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
    parser.add_option("-a", action="store_true", dest="altparser",
                      help='Use the alternate line parser (experimental)')
    parser.add_option("-s", '--strip', action="store_true", dest="strip_useless_code",
                      help='Strip useless VB code from macros prior to parsing.')
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
                         altparser=options.altparser,
                         strip_useless=options.strip_useless_code,
                         entry_points=entry_points,
                         time_limit=options.time_limit,
                         display_int_iocs=options.display_int_iocs,
                         out_file_name=options.out_file)

            # add json results to list
            if (options.out_file):
                with open(options.out_file, 'r') as json_file:
                    json_results.append(json.loads(json_file.read()))

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
