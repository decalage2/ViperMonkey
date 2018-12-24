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

# ViperMonkey is copyright (c) 2015-2018 Philippe Lagadec (http://www.decalage.info)
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

__version__ = '0.07'

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
from pyparsing import *
#ParserElement.enablePackrat(cache_size_limit=None)
ParserElement.enablePackrat(cache_size_limit=100000)

import struct
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

import prettytable
from oletools.thirdparty.xglob import xglob
from oletools.olevba import VBA_Parser, filter_vba
import olefile
import xlrd

# add the vipermonkey folder to sys.path (absolute+normalized path):
_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
if not _thismodule_dir in sys.path:
    sys.path.insert(0, _thismodule_dir)

# The version of pyparsing in the thirdparty directory of oletools is not
# compatible with the version of pyparsing used in ViperMonkey. Make sure
# the oletools thirdparty directory is not in the import path.
item = None
for p in sys.path:
    if (p.endswith("oletools/thirdparty")):
        item = p
        break
if (item is not None):
    sys.path.remove(item)
    
# relative import of core ViperMonkey modules:
from core import *
    
# === MAIN (for tests) ===============================================================================================

def _read_doc_text(fname, data=None):
    """
    Use a heuristic to read in the document text. The current
    heuristic (basically run strings on the document file) is not
    good, so this function is a placeholder until Python support for
    reading in the document text is found.

    TODO: Replace this when a real Python solution for reading the doc
    text is found.
    """

    # Read in the file.
    if data == None:
        try:
            f = open(fname, 'r')
            data = f.read()
            f.close()
        except Exception as e:
            log.error("Cannot read document text from " + str(fname) + ". " + str(e))
            return ""

    # Pull strings from doc.
    str_list = re.findall("[^\x00-\x1F\x7F-\xFF]{4,}", data)
    r = ""
    for s in str_list:
        r += s + "\n"
    
    # Return all the strings.
    return r

def _get_shapes_text_values_xml(fname):
    """
    Read in the text associated with Shape objects in a document saved
    as Flat OPC XML files.

    NOTE: This currently is a hack.
    """

    contents = None
    if fname.startswith("<?xml"):
        contents=fname
    else:

        # it's probably a filename, not a blob of data..
        # Read in the file contents.
        try:
            f = open(fname, "r")
            contents = f.read().strip()
            f.close()
        except:
            contents = fname

    # Is this an XML file?
    if ((not contents.startswith("<?xml")) or
        ("<w:txbxContent>" not in contents)):
        return []

    # It is an XML file.
    log.warning("Looking for Shapes() strings in Flat OPC XML file...")

    # Pull out the text surrounded by <w:txbxContent> ... </w:txbxContent>.
    # These big blocks hold the XML for each piece of Shapes() text.
    blocks = []
    start = contents.index("<w:txbxContent>") + len("<w:txbxContent>")
    end = contents.index("</w:txbxContent>")
    while (start is not None):
        blocks.append(contents[start:end])
        if ("<w:txbxContent>" in contents[end:]):
            start = end + contents[end:].index("<w:txbxContent>") + len("<w:txbxContent>")
            end = end + len("</w:txbxContent>") + contents[end + len("</w:txbxContent>"):].index("</w:txbxContent>")
        else:
            start = None
            end = None
            break
    cmd_strs = []
    for block in blocks:

        # Get all strings surrounded by <w:t> ... </w:t> tags in the block.
        pat = r"\<w\:t[^\>]*\>([^\<]+)\</w\:t\>"
        strs = re.findall(pat, block)

        # These could be broken up with many <w:t> ... </w:t> tags. See if we need to
        # reassemble strings.
        if (len(strs) > 1):

            # Reassemble command string.
            curr_str = ""
            for s in strs:

                # Save current part of command string.
                curr_str += s

            # Use this as the Shape() strings.
            strs = [curr_str]

        # Save the string from this block.
        cmd_strs.append(strs[0])
            
    # Hope that the Shape() object indexing follows the same order as the strings
    # we found.
    r = []
    pos = 1
    for shape_text in cmd_strs:

        # Skip strings that are too short.
        if (len(shape_text) < 100):
            continue
        
        # Access value with .TextFrame.TextRange.Text accessor.
        shape_text = shape_text.replace("&amp;", "&")
        var = "Shapes('" + str(pos) + "').TextFrame.TextRange.Text"
        r.append((var, shape_text))
        
        # Access value with .TextFrame.ContainingRange accessor.
        var = "Shapes('" + str(pos) + "').TextFrame.ContainingRange"
        r.append((var, shape_text))

        # Access value with .AlternativeText accessor.
        var = "Shapes('" + str(pos) + "').AlternativeText"
        r.append((var, shape_text))
        
        # Move to next shape.
        pos += 1

    return r

def _get_ole_textbox_values(obj, stream):
    """
    Read in the text associated with embedded OLE form textbox objects.
    NOTE: This currently is a hack.
    """

    if obj[0:4] == '\xd0\xcf\x11\xe0':
        #its the data blob
        data = obj
    else:
        fname = obj
        try:
            f = open(fname, "rb")
            data = f.read()
            f.close()
        except:
            data = obj

    pat = r"(?:[\x20-\x7e]{5,})|(?:(?:\x00[\x20-\x7e]){5,})"
    index = 0
    r = []
    while ("Microsoft Forms 2.0 TextBox" in data[index:]):

        # Break out the data for an embedded OLE textbox form.
        index = data.index("Microsoft Forms 2.0 TextBox")
        end = index + 5000
        if (end > len(data)):
            end = len(data) - 1
        chunk = data[index : end]
        strs = re.findall(pat, chunk)
    
        # 3rd string looks like the name of the ole form object.
        if (len(strs) < 5):
            continue
        name = strs[3].replace("\x00", "")

        # Item after that looks like start of text of the object.
        text = strs[4].replace("\x00", "")

        # Looks like more text comes after the "SummaryInformation" tag.
        i = 4
        for s in strs[4:]:
            if ((s.replace("\x00", "").strip() == "SummaryInformation") and
                (i < len(strs))):
                text += strs[i + 1].replace("\x00", "")
            i += 1

        # Save the form name and text value.
        r.append((name, text))

        # Move to next chunk.
        index = end

    # Return the OLE form textbox information.
    return r
        
def _get_shapes_text_values(fname, stream):
    """
    Read in the text associated with Shape objects in the document.
    NOTE: This currently is a hack.
    """

    r = []
    try:
        # Read the WordDocument stream.
        ole = olefile.OleFileIO(fname, write_mode=False)
        if (not ole.exists(stream)):
            return []
        data = ole.openstream(stream).read()
        
        # It looks like maybe(?) the shapes text appears as ASCII blocks bounded by
        # 0x0D bytes. We will look for that.
        pat = r"\x0d[\x20-\x7e]{100,}\x0d"
        strs = re.findall(pat, data)

        # Hope that the Shape() object indexing follows the same order as the strings
        # we found.
        pos = 1
        for shape_text in strs:

            # Access value with .TextFrame.TextRange.Text accessor.
            shape_text = shape_text[1:-1]
            var = "Shapes('" + str(pos) + "').TextFrame.TextRange.Text"
            r.append((var, shape_text))
            
            # Access value with .TextFrame.ContainingRange accessor.
            var = "Shapes('" + str(pos) + "').TextFrame.ContainingRange"
            r.append((var, shape_text))

            # Access value with .AlternativeText accessor.
            var = "Shapes('" + str(pos) + "').AlternativeText"
            r.append((var, shape_text))
            
            # Move to next shape.
            pos += 1

        # It looks like maybe(?) the shapes text appears as wide char blocks bounded by
        # 0x0D bytes. We will look for that.
        #pat = r"\x0d(?:\x00[\x20-\x7e]){10,}\x00?\x0d"
        pat = r"(?:\x00[\x20-\x7e]){100,}"
        strs = re.findall(pat, data)
        
        # Hope that the Shape() object indexing follows the same order as the strings
        # we found.
        pos = 1
        for shape_text in strs:

            # Access value with .TextFrame.TextRange.Text accessor.
            shape_text = shape_text[1:-1].replace("\x00", "")
            var = "Shapes('" + str(pos) + "').TextFrame.TextRange.Text"
            r.append((var, shape_text))
            
            # Access value with .TextFrame.ContainingRange accessor.
            var = "Shapes('" + str(pos) + "').TextFrame.ContainingRange"
            r.append((var, shape_text))

            # Access value with .AlternativeText accessor.
            var = "Shapes('" + str(pos) + "').AlternativeText"
            r.append((var, shape_text))
            
            # Move to next shape.
            pos += 1
            
    except Exception as e:

        # Report the error.
        log.error("Cannot read associated Shapes text. " + str(e))

        # See if we can read Shapes() info from an XML file.
        if ("not an OLE2 structured storage file" in str(e)):
            r = _get_shapes_text_values_xml(fname)

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
    
def _read_doc_vars(fname):
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
    
def is_useless_dim(line):
    """
    See if we can skip this Dim statement and still successfully emulate.
    We only use Byte type information when emulating.
    """

    # Is this dimming a Byte variable?
    line = line.strip()
    if (not line.startswith("Dim ")):
        return False
    return (("Byte" not in line) and
            ("Long" not in line) and
            ("Integer" not in line) and
            (":" not in line) and
            ("=" not in line) and
            (not line.strip().endswith("_")))

def is_interesting_call(line, external_funcs, local_funcs):

    # Is this an interesting function call?
    log_funcs = ["CreateProcessA", "CreateProcessW", ".run", "CreateObject",
                 "Open", ".Open", "GetObject", "Create", ".Create", "Environ",
                 "CreateTextFile", ".CreateTextFile", "Eval", ".Eval", "Run",
                 "SetExpandedStringValue", "WinExec", "URLDownloadToFile", "Print",
                 "Split"]
    log_funcs.extend(local_funcs)
    for func in log_funcs:
        if (func in line):
            return True

    # Are we calling an external function?
    for ext_func_decl in external_funcs:
        if (("Function" in ext_func_decl) and ("Lib" in ext_func_decl)):
            start = ext_func_decl.index("Function") + len("Function")
            end = ext_func_decl.index("Lib")
            ext_func = ext_func_decl[start:end].strip()
            if (ext_func in line):
                return True
        
    # Not a call we are tracking.
    return False

def is_useless_call(line):
    """
    See if the given line contains a useless do-nothing function call.
    """

    # These are the functions that do nothing if they appear on a line by themselves.
    # TODO: Add more functions as needed.
    useless_funcs = set(["Cos", "Log", "Cos", "Exp", "Sin", "Tan", "DoEvents"])

    # Is this an assignment line?
    if ("=" in line):
        return False

    # Nothing is being assigned. See if a useless function is called and the
    # return value is not used.
    line = line.replace(" ", "")
    called_func = line
    if ("(" in line):
        called_func = line[:line.index("(")]
    called_func = called_func.strip()
    for func in useless_funcs:
        if (called_func == func):
            return True
    return False

def collapse_macro_if_blocks(vba_code):
    """
    When emulating we only pick a single block from a #if statement. Speed up parsing
    by picking the largest block and strip out the rest.
    """

    # Pick out the largest #if blocks.
    log.debug("Collapsing macro blocks...")
    curr_blocks = None
    curr_block = None
    r = ""
    for line in vba_code.split("\n"):

        # Are we tracking an #if block?
        strip_line = line.strip()
        if (curr_blocks is None):

            # Is this the start of an #if block?
            if (strip_line.startswith("#If")):

                # Yes, start tracking blocks.
                log.debug("Start block " + strip_line)
                curr_blocks = []
                curr_block = []
                r += "' STRIPPED LINE\n"
                continue

            # Not the start of an #if. Save the line.
            r += line + "\n"
            continue

        # If we get here we are tracking an #if statement.

        # Is this the start of another block in the #if?
        if ((strip_line.startswith("#Else")) or
            (strip_line.startswith("Else"))):

            # Save the current block.
            curr_blocks.append(curr_block)
            log.debug("Else if " + strip_line)
            log.debug("Save block " + str(curr_block))

            # Start a new block.
            curr_block = []
            r += "' STRIPPED LINE\n"
            continue

        # Have we finished the #if?
        if (strip_line.startswith("#End")):

            log.debug("End if " + strip_line)

            # Save the current block.
            curr_blocks.append(curr_block)
            
            # Add back in the largest block and skip the rest.
            biggest_block = []
            for block in curr_blocks:
                if (len(block) > len(biggest_block)):
                    biggest_block = block
            for block_line in biggest_block:
                r += block_line + "\n"
            log.debug("Pick block " + str(biggest_block))
                
            # Done processing #if.
            curr_blocks = None
            curr_block = None
            continue

        # We have a block line. Save it.
        curr_block.append(line)

    # Return the stripped VBA.
    return r
    
def strip_useless_code(vba_code, local_funcs):
    """
    Strip statements that have no usefull effect from the given VB. The
    stripped statements are commented out.
    """

    # Track data change callback function names.
    change_callbacks = set()    
    
    # Find all assigned variables and track what line the variable was assigned on.
    assign_re = re.compile("\s*(\w+(\.\w+)*)\s*=\s*")
    assigns = {}
    line_num = 0
    bool_statements = set(["If", "For", "Do"])
    external_funcs = []
    for line in vba_code.split("\n"):

        # Save external function declarations lines so we can avoid stripping
        # calls to external functions.
        if (("Declare" in line) and ("Lib" in line)):
            external_funcs.append(line.strip())
        
        # Is this a change function callback?
        if (("Sub " in line) and ("_Change(" in line)):

            # Pull out the name of the data item with the current change callback.
            # ex: Private Sub besstirp_Change()
            data_name = line.replace("Sub ", "").\
                        replace("Private ", "").\
                        replace(" ", "").\
                        replace("()", "").\
                        replace("_Change", "").strip()
            change_callbacks.add(data_name)
        
        # Is there an assignment on this line?
        line_num += 1
        match = assign_re.findall(line)
        if (len(match) > 0):

            log.debug("SKIP: Assign line: " + line)

            # Skip function definitions.
            if (line.strip().startswith("Function ")):
                log.debug("SKIP: Function decl. Keep it.")
                continue

            # Skip const definitions.
            if (line.strip().startswith("Const ")):
                log.debug("SKIP: Const decl. Keep it.")
                continue
                
            # Skip lines that end with a continuation character.
            if (line.strip().endswith("_")):
                log.debug("SKIP: Continuation line. Keep it.")
                continue

            # Skip function definitions.
            if (("Sub " in line) or ("Function " in line)):
                log.debug("SKIP: Function definition. Keep it.")
                continue

            # Skip calls to GetObject() or Shell().
            if (("GetObject" in line) or ("Shell" in line)):
                log.debug("SKIP: GetObject()/Shell() call. Keep it.")
                continue

            # Skip calls to various interesting calls.
            if (is_interesting_call(line, external_funcs, local_funcs)):
                continue
            
            # Skip lines where the '=' is part of a boolean expression.
            strip_line = line.strip()            
            skip = False
            for bool_statement in bool_statements:
                if (strip_line.startswith(bool_statement + " ")):
                    skip = True
                    break
            if (skip):
                continue

            # Skip lines assigning variables in a with block.
            if (strip_line.startswith(".") or (strip_line.lower().startswith("let ."))):
                continue

            # Skip lines where the '=' might be in a string.
            if ('"' in line):
                eq_index = line.index("=")
                qu_index1 =  line.index('"')
                qu_index2 =  line.rindex('"')
                if ((qu_index1 < eq_index) and (qu_index2 > eq_index)):
                    continue
            
            # Yes, there is an assignment. Save the assigned variable and line #
            log.debug("SKIP: Assigned vars = " + str(match))
            for var in match:

                # Keep lines where we may be running a command via an object.
                val = line[line.rindex("=") + 1:]
                if ("." in val):
                    continue

                # Keep object creations.
                if ("CreateObject" in val):
                    continue
                
                # It does not look like we are running something. Track the variable.
                var = var[0]
                if (var not in assigns):
                    assigns[var] = set()
                assigns[var].add(line_num)

    # Now do a very loose check to see if the assigned variable is referenced anywhere else.
    refs = {}
    for var in assigns.keys():
        # Keep assignments to variables in other streams since we cannot
        # tell based on the current stream whether the assignment is used.
        refs[var] = ("." in var)
    line_num = 0
    for line in vba_code.split("\n"):

        # Mark all the variables that MIGHT be referenced on this line.
        line_num += 1
        for var in assigns.keys():

            # Skip variable references on the lines where the current variable was assigned.
            if (line_num in assigns[var]):
                continue

            # Could the current variable be used on this line?
            if (var in line):

                # Maybe. Count this as a reference.
                log.debug("STRIP: Var '" + str(var) + "' referenced in line '" + line + "'.")
                refs[var] = True

    # Keep assignments that have change callbacks.
    for change_var in change_callbacks:
        for var in assigns.keys():
            refs[var] = ((change_var in var) or (var in change_var) or refs[var])
                
    # Figure out what assignments to strip and keep.
    comment_lines = set()
    keep_lines = set()
    for var in refs.keys():
        if (not refs[var]):
            for num in assigns[var]:
                comment_lines.add(num)
        else:
            for num in assigns[var]:
                keep_lines.add(num)

    # Multiple variables can be assigned on 1 line (a = b = 12). If any of the variables
    # on this assignment line are used, keep it.
    tmp = set()
    for l in comment_lines:
        if (l not in keep_lines):
            tmp.add(l)
    comment_lines = tmp
    
    # Now strip out all useless assignments.
    r = ""
    line_num = 0
    if_count = 0
    in_func = False
    for line in vba_code.split("\n"):

        # Are we in a function?
        if (("End Sub" in line) or ("End Function" in line)):
            in_func = False
        elif (("Sub " in line) or ("Function " in line)):
            in_func = True
        
        # Keep track of if starts so we can match up end ifs.
        line_num += 1
        if (line.strip().startswith("If ")):
            if_count += 1

        # Do we have an unmatched 'end if'? If so, replace it with an
        # 'end function' to handle some Carbanak maldocs.
        if (line.strip().startswith("End If")):
            if_count -= 1
            if (if_count < 0):
                r += "End Function\n"
                if_count = 0
                continue
        
        # Does this line get stripped based on variable usage?
        if ((line_num in comment_lines) and
            (not line.strip().startswith("Function ")) and
            (not line.strip().startswith("Sub ")) and
            (not line.strip().startswith("End Sub")) and
            (not line.strip().startswith("End Function"))):
            log.debug("STRIP: Stripping Line (1): " + line)
            r += "' STRIPPED LINE\n"
            continue

        # Does this line get stripped based on a useless function call?
        if (is_useless_call(line)):
            log.debug("STRIP: Stripping Line (2): " + line)
            r += "' STRIPPED LINE\n"
            continue

        # Does this line get stripped based on being a Dim that we will not use
        # when emulating?
        if ((in_func) and (is_useless_dim(line))):
            log.debug("STRIP: Stripping Line (3): " + line)
            r += "' STRIPPED LINE\n"
            continue
        
        # The line is useful. Keep it.

        # At least 1 maldoc builder is not putting a newline before the
        # 'End Function' closing out functions. Rather than changing the
        # parser to deal with this we just fix those lines here.
        if ((line.endswith("End Function")) and
            (len(line) > len("End Function"))):
            r += line.replace("End Function", "") + "\n"
            r += "End Function\n"
            continue

        # Fix Application.Run "foo, bar baz" type expressions by removing
        # the quotes.
        if (line.strip().startswith("Application.Run") and
            (line.count('"') == 2) and
            (line.strip().endswith('"'))):

            # Just directly run the command in the string.
            line = line.replace('"', '').replace("Application.Run", "")

            # Fix cases where the function to run is the 1st argument in the arg string.
            fields = line.split(",")
            if ((len(fields) > 1) and (" " not in fields[0].strip())):
                line = "WScript.Shell " + line
        
        # This is a regular valid line. Add it.
        r += line + "\n"

    # Now collapse down #if blocks.
    r = collapse_macro_if_blocks(r)
        
    return r
    
def parse_stream(subfilename,
                 stream_path=None,
                 vba_filename=None,
                 vba_code=None,
                 strip_useless=False,
                 local_funcs=[]):

    # Check for timeouts.
    vba_object.limits_exceeded(throw_error=True)
    
    # Are the arguments all in a single tuple?
    if (stream_path is None):
        subfilename, stream_path, vba_filename, vba_code = subfilename

    # Collapse long lines.
    vba_code = vba_collapse_long_lines(vba_code)
        
    # Filter cruft from the VBA.
    vba_code = filter_vba(vba_code)
    if (strip_useless):
        vba_code = strip_useless_code(vba_code, local_funcs)
    print '-'*79
    print 'VBA MACRO %s ' % vba_filename
    print 'in file: %s - OLE stream: %s' % (subfilename, repr(stream_path))
    print '- '*39

    # Parse the macro.
    m = None
    if vba_code.strip() == '':
        print '(empty macro)'
        m = "empty"
    else:
        print '-'*79
        print 'VBA CODE (with long lines collapsed):'
        print vba_code
        print '-'*79
        print 'PARSING VBA CODE:'
        try:
            m = module.parseString(vba_code + "\n", parseAll=True)[0]
            ParserElement.resetCache()
            m.code = vba_code
        except ParseException as err:
            print err.line
            print " "*(err.column-1) + "^"
            print err
            print "Parse Error. Processing Aborted."
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
def process_file (container,
                  filename,
                  data,
                  altparser=False,
                  strip_useless=False,
                  entry_points=None,
                  time_limit=None):

    if not data:
        #TODO: replace print by writing to a provided output file (sys.stdout by default)
        if container:
            display_filename = '%s in %s' % (filename, container)
        else:
            display_filename = filename
        print '='*79
        print 'FILE:', display_filename
        f=open(filename,'r')
        data=f.read()
        f.close()
    return _process_file(filename,data,altparser=altparser,strip_useless=strip_useless,entry_points=entry_points,time_limit=time_limit)

# Wrapper for original function; from here out, only data is a valid variable.
# filename gets passed in _temporarily_ to support dumping to vba_context.out_dir = out_dir.
def _process_file (filename, data,
                  altparser=False,
                  strip_useless=False,
                  entry_points=None,
                  time_limit=None):
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
    
    vm = ViperMonkey()
    if (entry_points is not None):
        for entry_point in entry_points:
            vm.entry_points.append(entry_point)
    try:
        #TODO: handle olefile errors, when an OLE file is malformed
        if (isinstance(data, Exception)):
            data = None
        vba = VBA_Parser('', data, relaxed=True)
        if vba.detect_vba_macros():

            # Read in document metadata.
            try:
                ole = olefile.OleFileIO(data)
                vba_library.meta = ole.get_metadata()
                vba_object.meta = vba_library.meta
            except Exception as e:
                log.error("Reading in metadata failed. " + str(e))
                vba_library.meta = {}

            # If this is an Excel spreadsheet, read it in with xlrd.
            try:
                log.debug("Trying to load with xlrd...")
                vm.loaded_excel = xlrd.open_workbook(file_contents=data)
            except Exception as e:
                log.error("Reading in file as Excel failed. " + str(e))
                
            # Set the output directory in which to put dumped files generated by
            # the macros.
            out_dir = filename + "_artifacts"
            if ("/" in out_dir):
                start = out_dir.rindex("/") + 1
                out_dir = out_dir[start:]
            out_dir = out_dir.replace(".", "").strip()
            out_dir = "./" + out_dir + "/"
            vba_context.out_dir = out_dir
            del filename # We already have this in memory, we don't need to read it again.
                
            # Parse the VBA streams.
            comp_modules = parse_streams(vba, strip_useless)
            if (comp_modules is None):
                return None
            for m in comp_modules:
                if (m != "empty"):
                    vm.add_compiled_module(m)

            # Pull out document variables.
            for (var_name, var_val) in _read_doc_vars(data):
                vm.doc_vars[var_name.lower()] = var_val
                log.debug("Added potential VBA doc variable %r = %r to doc_vars." % (var_name, var_val))

            # Pull text associated with Shapes() objects.
            got_it = False
            for (var_name, var_val) in _get_shapes_text_values(data, 'worddocument'):
                got_it = True
                vm.doc_vars[var_name.lower()] = var_val
                log.debug("Added potential VBA Shape text %r = %r to doc_vars." % (var_name, var_val))
            if (not got_it):
                for (var_name, var_val) in _get_shapes_text_values(data, '1table'):
                    vm.doc_vars[var_name.lower()] = var_val
                    log.debug("Added potential VBA Shape text %r = %r to doc_vars." % (var_name, var_val))

            # Pull out embedded OLE form textbox text.
            for (var_name, var_val) in _get_ole_textbox_values(data, 'worddocument'):
                vm.doc_vars[var_name.lower()] = var_val
                log.debug("Added potential VBA OLE form textbox text %r = %r to doc_vars." % (var_name, var_val))
                var_name = "ActiveDocument." + var_name
                vm.doc_vars[var_name.lower()] = var_val
                log.debug("Added potential VBA OLE form textbox text %r = %r to doc_vars." % (var_name, var_val))
                var_name = var_name + ".Text"
                vm.doc_vars[var_name.lower()] = var_val
                log.debug("Added potential VBA OLE form textbox text %r = %r to doc_vars." % (var_name, var_val))
                    
            # Pull out custom document properties.
            for (var_name, var_val) in _read_custom_doc_props(data):
                vm.doc_vars[var_name.lower()] = var_val
                log.debug("Added potential VBA custom doc prop variable %r = %r to doc_vars." % (var_name, var_val))

            # Pull text associated with embedded objects.
            for (var_name, caption_val, tag_val) in _get_embedded_object_values(data):
                tag_name = var_name.lower() + ".tag"
                vm.doc_vars[tag_name] = tag_val
                log.debug("Added potential VBA object tag text %r = %r to doc_vars." % (tag_name, tag_val))
                caption_name = var_name.lower() + ".caption"
                vm.doc_vars[caption_name] = caption_val
                log.debug("Added potential VBA object caption text %r = %r to doc_vars." % (caption_name, caption_val))
                
            # Pull out the document text.
            vm.doc_text = _read_doc_text('', data=data)
                
            try:
                # Pull out form variables.
                for (subfilename, stream_path, form_variables) in vba.extract_form_strings_extended():
                    if form_variables is not None:
                        var_name = form_variables['name']
                        macro_name = stream_path
                        if ("/" in macro_name):
                            start = macro_name.rindex("/") + 1
                            macro_name = macro_name[start:]
                        global_var_name = (macro_name + "." + var_name).encode('ascii', 'ignore').replace("\x00", "")
                        tag = form_variables['tag']
                        if (tag is None):
                            tag = ''
                        tag = tag.replace('\xb1', '').replace('\x03', '')
                        caption = form_variables['caption']
                        if (caption is None):
                            caption = ''
                        caption = caption.replace('\xb1', '').replace('\x03', '')
                        val = form_variables['value']
                        if (val is None):
                            val = caption
                        control_tip_text = form_variables['control_tip_text']
                        if (control_tip_text is None):
                            control_tip_text = ''
                        control_tip_text = control_tip_text.replace('\xb1', '').replace('\x03', '')
                            
                        # Save full form variable names.
                        name = global_var_name.lower()
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
                
            except Exception as e:

                # We are not getting variable names this way. Assign wildcarded names that we can use
                # later to try to heuristically guess form variables.
                log.warning("Cannot read form strings. " + str(e) + ". Trying fallback method.")
                try:
                    count = 0
                    skip_strings = ["Tahoma"]
                    for (subfilename, stream_path, form_string) in vba.extract_form_strings():
                        # Skip default strings.
                        if (form_string in skip_strings):
                            continue
                        global_var_name = stream_path
                        if ("/" in global_var_name):
                            tmp = global_var_name.split("/")
                            if (len(tmp) == 3):
                                global_var_name = tmp[1]
                        global_var_name += "*" + str(count)
                        count += 1
                        vm.globals[global_var_name.lower()] = form_string
                        log.debug("Added VBA form variable %r = %r to globals." % (global_var_name, form_string))
                except Exception as e:
                    log.error("Cannot read form strings. " + str(e) + ". Fallback method failed.")
                
            print '-'*79
            print 'TRACING VBA CODE (entrypoint = Auto*):'
            if (entry_points is not None):
                log.info("Starting emulation from function(s) " + str(entry_points))
            vm.trace()
            # print table of all recorded actions
            print('Recorded Actions:')
            print(vm.dump_actions())
            print('')
            print('VBA Builtins Called: ' + str(vm.external_funcs))
            print('')
            return (vm.actions, vm.external_funcs)

        else:
            print 'No VBA macros found.'
            print ''
            return ([], [])
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
    print '='*79
    print 'FILE:', display_filename
    all_code = ''
    try:
        #TODO: handle olefile errors, when an OLE file is malformed
        vba = VBA_Parser(filename, data, relaxed=True)
        print 'Type:', vba.type
        if vba.detect_vba_macros():

            # Read in document metadata.
            ole = olefile.OleFileIO(filename)
            vba_library.meta = ole.get_metadata()
            
            #print 'Contains VBA Macros:'
            for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
                # hide attribute lines:
                #TODO: option to disable attribute filtering
                vba_code = filter_vba(vba_code)
                print '-'*79
                print 'VBA MACRO %s ' % vba_filename
                print 'in file: %s - OLE stream: %s' % (subfilename, repr(stream_path))
                print '- '*39
                # detect empty macros:
                if vba_code.strip() == '':
                    print '(empty macro)'
                else:
                    # TODO: option to display code
                    print vba_code
                    vba_code = vba_collapse_long_lines(vba_code)
                    all_code += '\n' + vba_code
            print '-'*79
            print 'EVALUATED VBA EXPRESSIONS:'
            t = prettytable.PrettyTable(('Obfuscated expression', 'Evaluated value'))
            t.align = 'l'
            t.max_width['Obfuscated expression'] = 36
            t.max_width['Evaluated value'] = 36
            for expression, expr_eval in scan_expressions(all_code):
                t.add_row((repr(expression), repr(expr_eval)))
            print t


        else:
            print 'No VBA macros found.'
    except: #TypeError:
        #raise
        #TODO: print more info if debug mode
        #print sys.exc_value
        # display the exception with full stack trace for debugging, but do not stop:
        traceback.print_exc()
    print ''



def main():
    """
    Main function, called when vipermonkey is run from the command line
    """

    # Increase recursion stack depth.
    sys.setrecursionlimit(13000)
    
    # print banner with version
    # Generated with http://www.patorjk.com/software/taag/#p=display&f=Slant&t=ViperMonkey
    print(''' _    ___                 __  ___            __             
| |  / (_)___  ___  _____/  |/  /___  ____  / /_____  __  __
| | / / / __ \/ _ \/ ___/ /|_/ / __ \/ __ \/ //_/ _ \/ / / /
| |/ / / /_/ /  __/ /  / /  / / /_/ / / / / ,< /  __/ /_/ / 
|___/_/ .___/\___/_/  /_/  /_/\____/_/ /_/_/|_|\___/\__, /  
     /_/                                           /____/   ''')
    print ('vmonkey %s - https://github.com/decalage2/ViperMonkey' % __version__)
    print ('THIS IS WORK IN PROGRESS - Check updates regularly!')
    print ('Please report any issue at https://github.com/decalage2/ViperMonkey/issues')
    print ('')

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
    # parser.add_option('-o', '--outfile', dest='outfile',
    #     help='output file')
    # parser.add_option('-c', '--csv', dest='csv',
    #     help='export results to a CSV file')
    parser.add_option("-r", action="store_true", dest="recursive",
        help='find files recursively in subdirectories.')
    parser.add_option("-z", "--zip", dest='zip_password', type='str', default=None,
        help='if the file is a zip archive, open first file from it, using the provided password (requires Python 2.6+)')
    parser.add_option("-f", "--zipfname", dest='zip_fname', type='str', default='*',
        help='if the file is a zip archive, file(s) to be opened within the zip. Wildcards * and ? are supported. (default:*)')
    parser.add_option("-e", action="store_true", dest="scan_expressions",
        help='Extract and evaluate/deobfuscate constant expressions')
    parser.add_option('-l', '--loglevel', dest="loglevel", action="store", default=DEFAULT_LOG_LEVEL,
                      help="logging level debug/info/warning/error/critical (default=%default)")
    parser.add_option("-a", action="store_true", dest="altparser",
        help='Use the alternate line parser (experimental)')
    parser.add_option("-s", '--strip', action="store_true", dest="strip_useless_code",
        help='Strip useless VB code from macros prior to parsing.')
    parser.add_option('-i', '--init', dest="entry_points", action="store", default=None,
                      help="Emulate starting at the given function name(s). Use comma seperated list for multiple entries.")
    parser.add_option('-t', '--time-limit', dest="time_limit", action="store", default=None,
                      type='int', help="Time limit (in minutes) for emulation.")

    (options, args) = parser.parse_args()

    # Print help if no arguments are passed
    if len(args) == 0:
        print __doc__
        parser.print_help()
        sys.exit()
        
    # setup logging to the console
    # logging.basicConfig(level=LOG_LEVELS[options.loglevel], format='%(levelname)-8s %(message)s')
    colorlog.basicConfig(level=LOG_LEVELS[options.loglevel], format='%(log_color)s%(levelname)-8s %(message)s')

    for container, filename, data in xglob.iter_files(args, recursive=options.recursive,
        zip_password=options.zip_password, zip_fname=options.zip_fname):
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
                         time_limit=options.time_limit)

if __name__ == '__main__':
    main()

# Soundtrack: This code was developed while listening to The Pixies "Monkey Gone to Heaven"
