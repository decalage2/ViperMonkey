"""@package read_ole_fields
Read in data values from OLE items like shapes and text boxes.
"""

"""
ViperMonkey is a specialized engine to parse, analyze and interpret Microsoft
VBA macros (Visual Basic for Applications), mainly for malware analysis.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

Project Repository:
https://github.com/decalage2/ViperMonkey
"""

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

import io
import json
import subprocess
import struct
import logging
import zipfile
import tempfile
import re
import random
import os
import sys
from collections import Counter
import string

import olefile

from logger import log
import filetype

_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))

def is_garbage_vba(vba, test_all=False, bad_pct=.6):
    """Check to see if the given supposed VBA is actually just a bunch of
    non-ASCII characters.

    @param vba (str) The VBA code to check.
    
    @param test_all (boolean) A flag indicating whether to look at all
    the code (True) or just the first part of the code (False).

    @param bad_pct (float) The max ratio of bad code to all code for
    this to be considered to be bad (i.e. percent bad divided by
    100).

    """

    # PE files are not analyzable.
    if filetype.is_pe_file(vba, True):
        return True

    # Pull out the 1st % of the string.
    total_len = len(vba)
    if ((total_len > 50000) and (not test_all)):
        total_len = int(len(vba) * .25)
    if (total_len == 0):
        return False
    substr = vba[:total_len]

    # Remove comment lines since garbage characters in those
    # lines will be ignored.
    if ("\n'" in substr):
        tmp = ""
        for line in substr.split("\n"):
            if (not line.strip().startswith("'")):
                tmp += line + "\n"
        substr = tmp
    
    # See if the 1st % of the string is mostly bad or mostly good.
    num_bad = 0.0
    in_string = False
    for c in substr:
        if (c == '"'):
            in_string = not in_string
        # Don't count garbage in strings.
        if in_string:
            continue
        if (c not in string.printable):
            num_bad += 1

    # It's bad if > NN% of the 1st % of the string is garbage.
    return ((num_bad/total_len) > bad_pct)

def pull_base64(data):
    """Pull base64 strings from some data.

    @param data (str) The data from which to extract base64 strings.
    
    @return (list) A list of base64 strings found in the input.

    """

    # Pull out strings that might be base64.
    base64_pat_loose = r"[A-Za-z0-9+/=]{40,}"
    r = set(re.findall(base64_pat_loose, data))
    return r

def unzip_data(data):
    """Unzip zipped data in memory.

    @param data (str) The data to unzip.

    @return (tuple) A 2 element tuple where the 1st element is the
    unzipped data and the 2nd element is the name of a temp file used
    in the unzipping process. Someone will need to clean this file
    up.

    """

    # Unzip the data.
    # PKZip magic #: 50 4B 03 04
    zip_magic = chr(0x50) + chr(0x4B) + chr(0x03) + chr(0x04)
    delete_file = False
    fname = None
    if data.startswith(zip_magic):
        #raise ValueError("get_shapes_text_values_2007() currently does not support in-memory Office files.")
        # TODO: Fix this. For now just save to a tmp file.
        # we use tempfile.NamedTemporaryFile to create a temporary file in a platform-independent
        # and secure way. The file needs to be accessible with a filename until it is explicitly
        # deleted (hence the option delete=False).
        # TODO: [Phil] I think we could avoid this and use a bytes buffer in memory instead, zipfile supports it
        f = tempfile.NamedTemporaryFile(delete=False)
        fname = f.name
        f.write(data)
        f.close()
        delete_file = True
    else:
        return (None, None)
        
    # Is this a ZIP file?
    try:
        if (not zipfile.is_zipfile(fname)):
            if (delete_file):
                os.remove(fname)
            return (None, None)
    except OSError:
        if (delete_file):
            os.remove(fname)
        return (None, None)
        
    # This is a ZIP file. Unzip it.
    # TODO: [Phil] here we could just pass the bytes buffer, no need for a file on disk
    unzipped_data = zipfile.ZipFile(fname, 'r')

    # Return the unzipped data and temp file name.
    return (unzipped_data, fname)

def _clean_2007_text(s):
    """Replace special 2007 formatting strings (XML escaped, etc.) with
    actual text.

    @param s (str) The string to clean.

    @return (str) The cleaned string.

    """    
    s = s.replace("&amp;", "&")\
         .replace("&gt;", ">")\
         .replace("&lt;", "<")\
         .replace("&apos;", "'")\
         .replace("&quot;", '"')\
         .replace("_x000d_", "\r")
    
    return s

def get_drawing_titles(data):
    """Read custom Drawing element title values from an Office 2007+
    file.
    
    @param data (str) The read in Office 2007+ file (data).

    @return (list) A list of 2 element tuples where the 1st tuple
    element is the name of the drawing element and the 2nd element is
    the title of the drawing element.

    """

    # We can only do this with 2007+ files.
    if (not filetype.is_office2007_file(data, True)):
        return []

    # Unzip the file contents.
    unzipped_data, fname = unzip_data(data)
    delete_file = (fname is not None)
    if (unzipped_data is None):
        return []

    # Pull out word/document.xml, if it is there.
    zip_subfile = 'word/document.xml'
    if (zip_subfile not in unzipped_data.namelist()):
        if (delete_file):
            # Need to close the zipfile first, otherwise os.remove fails on Windows
            unzipped_data.close()
            os.remove(fname)
        return []

    # Read word/document.xml.
    f1 = unzipped_data.open(zip_subfile)
    contents = f1.read()
    f1.close()

    # Delete the temporary Office file.
    if (delete_file):
        # Need to close the zipfile first, otherwise os.remove fails on Windows
        unzipped_data.close()
        os.remove(fname)
    
    # <wp:docPr id="1" name="the name" title="the title text"/>
    # Find all the drawing titles.
    pat = r"<wp\:docPr id=\"(\d+)\" name=\"([^\"]*)\" title=\"([^\"]*)\""
    if (re.search(pat, contents) is None):
        return []
    drawings = re.findall(pat, contents)

    # Return the text as Shapes(NN) variables.
    r = []
    for drawing_info in drawings:
        drawing_id = drawing_info[0]
        drawing_text = _clean_2007_text(drawing_info[2])
        var_name = "Shapes('" + drawing_id + "')"
        r.append((var_name, drawing_text))

    # Done.
    return r

def get_defaulttargetframe_text(data):
    """Read custom DefaultTargetFrame value from an Office 2007+ file.

    @param data (str) The read in Office 2007+ file (data).

    @return (str) On success return the DefaultTargetFrame value. On
    error return None.

    """

    # We can only do this with 2007+ files.
    if (not filetype.is_office2007_file(data, True)):
        return None

    # Unzip the file contents.
    unzipped_data, fname = unzip_data(data)
    delete_file = (fname is not None)
    if (unzipped_data is None):
        return None

    # Pull out docProps/custom.xml, if it is there.
    zip_subfile = 'docProps/custom.xml'
    if (zip_subfile not in unzipped_data.namelist()):
        if (delete_file):
            # Need to close the zipfile first, otherwise os.remove fails on Windows
            unzipped_data.close()
            os.remove(fname)
        return None

    # Read docProps/custom.xml.
    f1 = unzipped_data.open(zip_subfile)
    contents = f1.read()
    f1.close()

    # Delete the temporary Office file.
    if (delete_file):
        # Need to close the zipfile first, otherwise os.remove fails on Windows
        unzipped_data.close()
        os.remove(fname)
    
    # <vt:lpwstr>custom value</vt:lpwstr>
    # Pull out the DefaultTargetFrame string value. This assumes that DefaultTargetFrame
    # is the only value stored in custom.xml.
    pat = r"<vt:lpwstr>([^<]+)</vt:lpwstr>"
    if (re.search(pat, contents) is None):
        return None
    r = _clean_2007_text(re.findall(pat, contents)[0])
    return r

def get_customxml_text(data):
    """Read custom CustomXMLParts text values from an Office 2007+ file.

    @param data (str) The read in Office 2007+ file (data).

    @return (list) A list of 2 element tuples where the 1st tuple
    element is the name of the custom XML part and the 2nd element is
    the text of the part.

    """

    # We can only do this with 2007+ files.
    if (not filetype.is_office2007_file(data, True)):
        return []

    # Unzip the file contents.
    unzipped_data, fname = unzip_data(data)
    delete_file = (fname is not None)
    if (unzipped_data is None):
        return []

    # ActiveDocument.CustomXMLParts(ActiveDocument.CustomXMLParts.Count).SelectNodes("//Items")(1).ChildNodes(2).Text
    
    # Process each customXml/itemNN.xml file.
    r = []
    for nn in range(1, 6):

        # Does customXml/itemNN.xml exist?
        zip_subfile = 'customXml/item' + str(nn) + ".xml"
        if (zip_subfile not in unzipped_data.namelist()):
            continue

        # Read customXml/itemNN.xml.
        f1 = unzipped_data.open(zip_subfile)
        contents = f1.read()
        f1.close()
    
        # <Item1>VALUE HERE</Item1>
        # Pull out the string value.
        pat = r"<Item\d+>([^<]+)</Item\d+>"
        if (re.search(pat, contents) is None):
            continue
        txt_val = _clean_2007_text(re.findall(pat, contents)[0])

        # Save it.
        # This var name may need to be generalized.
        # customxmlparts('activedocument.customxmlparts.count').selectnodes('//items')(1).childnodes('2').text
        var_name = "customxmlparts('activedocument.customxmlparts.count').selectnodes('//items')(" + str(nn) + ").childnodes('2').text"
        r.append((var_name, txt_val))

    # Delete the temporary Office file.
    if (delete_file):
        # Need to close the zipfile first, otherwise os.remove fails on Windows
        unzipped_data.close()
        os.remove(fname)

    # Return the results.
    return r
    
def get_msftedit_variables_97(data):
    """Looks for variable/text value pairs stored in an embedded rich
    edit control from an Office 97 doc. See
    https://docs.microsoft.com/en-us/windows/win32/controls/about-rich-edit-controls.

    @param data (str) The read in Office 97 file (data).

    @return (list) A list of 2 element tuples where the 1st tuple
    element is the name of the rich edit control variable and the 2nd
    element is the variable value.

    """

    # Pattern for the object data
    pat = r"'\x01\xff\xff\x03.+?\x5c\x00\x70\x00\x61\x00\x72\x00\x0d\x00\x0a\x00\x7d"
    r = []
    for chunk in re.findall(pat, data, re.DOTALL):

        # Names and values are wide character strings. Strip out the null bytes.
        chunk = chunk.replace("\x00", "")
    
        # Pull out the name of the current thing .

        # Marker 1
        name_pat = r"'\x01\xff\xff\x03\x92\x03\x04([A-Za-z0-9_]+)"
        names = re.findall(name_pat, chunk)

        # Punt if no names found and just pull out everything that looks like it might be a name.
        if (len(names) != 1):
            name_pat = r"([A-Za-z0-9_]+)"
            tmp = re.findall(name_pat, chunk)
            names = []
            for poss_name in tmp:
                if (len(poss_name) < 30):
                    names.append(poss_name)
        
        # Pull out the data for the current thing.
        data_pat = r"\\fs\d{1,3} (.+)\\par"
        chunk_data = re.findall(data_pat, chunk, re.DOTALL)
        if (len(chunk_data) != 1):
            continue
        chunk_data = chunk_data[0]

        # Save the variable/value pairs.
        for chunk_name in names:
            r.append((chunk_name, chunk_data))

    # Done.
    return r

def get_msftedit_variables(obj):
    """Looks for variable/text value pairs stored in an embedded rich edit
    control from an Office 97 or 2007+ doc.  See
    https://docs.microsoft.com/en-us/windows/win32/controls/about-rich-edit-controls.

    @param data (str) The read in Office 97 or 2007+ file (data).

    @return (list) A list of 2 element tuples where the 1st tuple
    element is the name of the rich edit control variable and the 2nd
    element is the variable value.

    """

    # Figure out if we have been given already read in data or a file name.
    if obj[0:4] == '\xd0\xcf\x11\xe0':
        #its the data blob
        data = obj
    else:
        fname = obj
        try:
            f = open(fname, "rb")
            data = f.read()
            f.close()
        except IOError:
            data = obj
        except TypeError:
            data = obj

    # Is this an Office 97 file?
    if (filetype.is_office97_file(data, True)):
        return get_msftedit_variables_97(data)

    # This is an Office 2007+ file.
    return []

def remove_duplicates(lst):
    """Remove duplicate subsequences from a list. Taken from
    https://stackoverflow.com/questions/49833528/python-identifying-and-deleting-duplicate-sequences-in-list/49835215.

    @param lst (list) The list from which to remove duplicate
    subsequences.
    
    @return (list) The list with duplicate subsequences removed.

    """

    # Want to delete all but last subsequence, so reverse list.
    lst = list(lst)
    lst.reverse()
    
    dropped_indices = set()
    counter = Counter(tuple(lst[i:i+2]) for i in range(len(lst) - 1))

    for i in range(len(lst) - 2, -1, -1):
        sub = tuple(lst[i:i+2])
        if counter[sub] > 1:
            dropped_indices |= {i, i + 1}
            counter[sub] -= 1

    r = [x for i, x in enumerate(lst) if i not in dropped_indices]
    r.reverse()
    return r

def entropy(text):
    """
    Compute the entropy of a string. Taken from
    https://rosettacode.org/wiki/Entropy#Uses_Python_2.
    
    @param text (str) The string for which to compute the entropy.
    """
    import math
    log2=lambda x:math.log(x)/math.log(2)
    exr={}
    infoc=0
    for each in text:
        try:
            exr[each]+=1
        except KeyError:
            exr[each]=1
    textlen=len(text)
    for _,v in exr.items():
        freq  =  1.0*v/textlen
        infoc+=freq*log2(freq)
    infoc*=-1
    return infoc


# There is some MS cruft strings that should be eliminated from the
# strings pulled from the chunk.
cruft_pats = [r'Microsoft Forms 2.0 Form',
              r'Embedded Object',
              r'CompObj',
              r'VBFrame',
              r'VERSION [\d\.]+\r\nBegin {[\w\-]+} \w+ \r\n\s+Caption\s+=\s+"UserForm1"\r\n\s+ClientHeight\s+=\s+\d+\r\n' + \
              r'\s+ClientLeft\s+=\s+\d+\r\n\s+ClientTop\s+=\s+\d+\r\n\s+ClientWidth\s+=\s+\d+\r\n' + \
              r'\s+StartUpPosition\s+=\s+\d+\s+\'CenterOwner\r\n\s+TypeInfoVer\s+=\s+\d+\r\nEnd\r\n',
              r'DEFAULT',
              r'InkEdit\d+',
              r'MS Sans Serif',
              r'\{\\rtf1\\ansi\\ansicpg\d+\\deff\d+\\deflang\d+\{\\fonttbl\{\\f\d+\\f\w+\\fcharset\d+.+;\}\}',
              r'{\\\*\\generator [\w\d\. ]+;}\\[\d\w]+\\[\d\w]+\\[\d\w]+\\[\d\w]+\\[\d\w]+ ',
              r'\\par',
              r'HelpContextID="\d+"',
              r'VersionCompatible\d+="\d+"',
              r'CMG="[A-Z0-9]+"',
              r'DPB="[A-Z0-9]+"',
              r'GC="[A-Z0-9]+"',
              r'\[Host Extender Info\]',
              r'&H\d+=\{[A-Z0-9]+\-[A-Z0-9]+\-[A-Z0-9]+\-[A-Z0-9]+\-[A-Z0-9]+\};VBE;&H\d+',
              r'&H\d+=\{[A-Z0-9]+\-[A-Z0-9]+\-[A-Z0-9]+\-[A-Z0-9]+\-[A-Z0-9]+\};Word\d.\d;&H\d+',
              r'\[Workspace\]',
              r'http://schemas.openxmlformats.org/\w+/\w+/\w+',
              r'Root Entry',
              r'Data',
              r'WordDocument',
              r'ObjectPool',
]

def _read_chunk(anchor, pat, data):
    """Read in delimited chunks of data based on an anchor at the start
    of the chunk and a pattern for recognizing a chunk.

    @param anchor (str) The anchor string at the start of the chunk to
    identify.

    @param pat (str) The regex pattern for identifying a chunk.

    @param data (str) The data from which to pull chunks.

    @return (list) A list of recognized chunks (str).

    """
    
    if (anchor not in data):
        return None
    data = data[data.index(anchor):]
    if (re.search(pat, data, re.DOTALL) is not None):
        return re.findall(pat, data, re.DOTALL)
    return None

def _get_field_names(vba_code, debug):
    """Get the names of object fields referenced in the given VBA code.

    @param vba_code (str) The VBA code to scan.

    @param debug (boolean) A flag indicating whether to print debug
    information.

    @return (list) A list of the names (str) of the object fields
    referenced in the VBA code.

    """

    # Pull out the object text value references from the VBA code.
    object_names = set(re.findall(r"(?:ThisDocument|ActiveDocument|\w+)\.(\w+(?:\.ControlTipText)?)", vba_code))
    object_names.update(re.findall(r"(\w+)\.Caption", vba_code))
    
    # Are we refering to Page objects by index?
    page_pat = r"(?:ThisDocument|ActiveDocument|\w+)\.(Pages\(.+\))"
    if (re.search(page_pat, vba_code) is not None):

        # Add some Page objects to look for.
        for i in range(1, 10):
            object_names.add("Page" + str(i))

    # Eliminate any obviously bad names.
    object_names = clean_names(object_names)            
    if debug:
        print "\nget_ole_textbox_values2()"
        print "\nNames from VBA code:"
        print object_names
            
    # Break out the variables from which we want control tip text and non-control tip text variables.
    control_tip_var_names = set()
    for name in object_names:

        # Getting control tip text for this object?
        if (name.endswith(".ControlTipText")):
            fields = name.split(".")[:-1]
            short_name = fields[-1]
            control_tip_var_names.add(short_name)

    # Done.
    return object_names, control_tip_var_names

def _read_large_chunk(data, debug):
    """
    Pull out a chunk of raw data containing mappings from object names to
    object text values.

    @param data (str) The Office 97 file data from which to pull an
    object name/value chunk.

    @param debug (boolean) A flag indicating whether to print debug
    information.

    @return (str) A chunk of data.
    """

    # Read in the large chunk of data with the object names and string values.
    # chunk_pats are (anchor string, full chunk regex).
    chunk_pats = [('ID="{',
                   r'ID="\{.{20,}(?:UserForm\d{1,10}=\d{1,10}, \d{1,10}, \d{1,10}, \d{1,10}, ' + \
                   r'\w{1,10}, \d{1,10}, \d{1,10}, \d{1,10}, \d{1,10}, \r\n){1,10}(.+?)Microsoft Forms '),
                  ('\x05\x00\x00\x00\x17\x00',
                   r'\x05\x00\x00\x00\x17\x00(.*)(?:(?:Microsoft Forms 2.0 Form)|(?:ID="{))'),
                  ('\xd7\x8c\xfe\xfb',
                   r'\xd7\x8c\xfe\xfb(.*)(?:(?:Microsoft Forms 2.0 Form)|(?:ID="{))'),
                  ('\x00V\x00B\x00F\x00r\x00a\x00m\x00e\x00',
                   r'\x00V\x00B\x00F\x00r\x00a\x00m\x00e\x00(.*)(?:(?:Microsoft Forms 2.0 (?:Form|Frame))|(?:ID="\{))')]
    for anchor, chunk_pat in chunk_pats:
        chunk = _read_chunk(anchor, chunk_pat, data)
        if (chunk is not None):
            if debug:
                print "\nCHUNK ANCHOR: '" + anchor + "'"
                print "CHUNK PATTERN: '" + chunk_pat + "'"
            break

    # Did we find the value chunk?
    if (chunk is None):                
        if debug:
            print "\nNO VALUES"
        return None

    # Get the actual chunk.
    chunk = chunk[0]

    # Strip some red herring strings from the chunk.
    chunk = chunk.replace("\x02$", "").replace("\x01@", "")
    #if (re.search(r'[\x20-\x7f]{5,}(?:\x00[\x20-\x7f]){5,}', chunk) is not None):
    #    chunk = re.sub(r'[\x20-\x7f]{5,1000}(?:\x00[\x20-\x7f]){5,1000}', "", chunk, re.IGNORECASE)

    # Normalize Page object naming.
    page_name_pat = r"Page(\d+)(?:(?:\-\d+)|[a-zA-Z]+)"
    chunk = re.sub(page_name_pat, r"Page\1", chunk)
    
    if debug:
        print "\nChunk:"
        print chunk

    # Done.
    return chunk

def _read_raw_strs(chunk, stream_names, debug):
    """Pull out all the ASCII strings from a given chunk of data.

    @param chunk (str) The data chunk from which to pull strings.
    
    @param stream_names (list) A list of the names of OLE streams in
    the Office OLE file. OLE stream names will not be counted as
    strings in the chunk.

    @return (list) A list of strings from the chunk.

    @param debug (boolean) A flag indicating whether to print debug
    information.

    """

    # Pull out the strings from the value chunk.
    ascii_pat = r"(?:[\x09\x20-\x7f]|\x0d\x0a){4,}|(?:(?:[\x09\x20-\x7f]\x00|\x0d\x00\x0a\x00)){4,}"
    vals = re.findall(ascii_pat, chunk)
    vals = vals[:-1]
    tmp_vals = []
    for val in vals:

        # No wide char strings.
        val = val.replace("\x00", "")
        
        # Eliminate cruft.
        for cruft_pat in cruft_pats:
            val = re.sub(cruft_pat, "", val)
            
        # Skip strings that were pure cruft.
        if (len(val) == 0):
            continue
            
        # Skip fonts and other things.
        if ((val.startswith("Taho")) or
            (val.startswith("PROJECT")) or
            (val.startswith("_DELETED_NAME_"))):
            continue

        # No stream names.
        if (val in stream_names):
            continue
        
        # Save modified string.
        tmp_vals.append(val)

    # Work with the modified list of strings.
    vals = tmp_vals
    if debug:
        print "\nORIG RAW VALS:"
        print vals

    # Done.
    return vals

def _handle_control_tip_text(control_tip_var_names, vals, debug):
    """Find the text for each named control tip object.

    @param control_tip_var_names (list) The names (str) of the control
    tip objects.

    @param vals (list) Potential control tip text values (str).

    @param debug (boolean) A flag indicating whether to print debug
    information.

    @return (list) A list of 2 element tuples where the 1st element is
    the control tip object name and the 2nd is the control tip text.

    """

    # Looks like control tip text goes right after var names in the string
    # list.
    r = []
    if debug:
        print "\nCONTROL TIP PROCESSING:"
    for name in control_tip_var_names:
        pos = -1
        for str_val in vals:
            pos += 1
            if ((str_val.startswith(name)) and ((pos + 1) < len(vals))):

                # Skip values that are not valid.
                if (vals[pos + 1].startswith("ControlTipText")):
                    continue
                
                # Save the current name/value pair.
                if debug:
                    print (name, vals[pos + 1])
                r.append((name, vals[pos + 1]))

                # Some extra characters sometimes are on the end of the names. Brute force this
                # by just returning multiple name variants with characters chopped off the end.
                n = name
                if (len(n) > 2):
                    n = n[:-1]
                    r.append((n, vals[pos + 1]))
                if (len(n) > 2):
                    n = n[:-1]
                    r.append((n, vals[pos + 1]))
                if (len(n) > 2):
                    n = n[:-1]
                    r.append((n, vals[pos + 1]))

    # Done.
    return r

def _get_specific_values(chunk, stream_names, debug):
    """Get possible OLE object text values.

    @param chunk (str) A chunk of OLE data containing OLE object names
    and text values.

    @param stream_names (list) A list of the names of OLE streams in
    the Office OLE file. OLE stream names will not be counted as
    potential object values in the chunk.

    @param debug (boolean) A flag indicating whether to print debug
    information.

    @return (list) Potential OLE object text values (str).

    """

    # Get values.
    val_pat = r"(?:[\x02\x10]\x00\x00([\x09\x20-\x7f]{2,}))|" + \
              r"((?:\x00[\x09\x20-\x7f]|\x00\x0d\x00\x0a){2,})|" + \
              r"(?:\x05\x80([\x09\x20-\x7f]{2,}))|" + \
              r"(?:[\x15\x0c\x0b]\x00\x80([\x09\x20-\x7f]{2,}(?:\x01\x00C\x00o\x00m\x00p\x00O\x00b\x00j.+[\x09\x20-\x7f]{5,})?))"
    vals = re.findall(val_pat, chunk.replace("\x19 ", "`\x00"))
    if debug:
        print "\nORIG SPECIFIC VALS:"
        print vals
    
    tmp_vals = []
    rev_vals = list(vals)
    rev_vals.reverse()
    seen = set()
    for val in rev_vals:

        if (len(val[0]) > 0):
            val = val[0]
        elif (len(val[1]) > 0):
            val = val[1]            
        else:
            val = val[2]

        # Replace any wide char CompObj data items that appear in the middle of a chunk of text.
        compobj_pat = r"\x01\x00C\x00o\x00m\x00p\x00O\x00b\x00j"
        if (re.search(compobj_pat, val) is not None):
            tmp_val = ""
            ascii_pat = r"[\x20-\x7f]{5,}"
            for s in re.findall(ascii_pat, val):
                tmp_val += s
            val = tmp_val
            
        # No wide char strings.
        val = val.replace("\x00", "")
        
        # Eliminate cruft.
        for cruft_pat in cruft_pats:
            val = re.sub(cruft_pat, "", val)
            
        # Skip strings that were pure cruft.
        if (len(val) == 0):
            continue
            
        # Skip fonts and other things.
        if ((val.startswith("Taho")) or
            (val.startswith("PROJECT")) or
            (val.startswith("_DELETED_NAME_")) or
            ("Normal.ThisDocument" in val)):
            continue

        # Skip duplicates.
        if (val in seen):
            continue
        seen.add(val)

        # No stream names.
        if (val in stream_names):
            continue
        
        # Save modified string.
        tmp_vals.append(val)

    # Work with the modified list of values.
    tmp_vals.reverse()
    #var_vals = tmp_vals[1:]
    var_vals = tmp_vals

    if debug:
        print "\nORIG VAR_VALS:"
        print var_vals
    
    # There may be an extra piece of randomly generated data at the start of the
    # value list. See if there are 4 strings that appear random at the start of the
    # list.
    if (len(var_vals) > 4):
        num_random = 0
        for s in var_vals[:5]:
            if (entropy(s) > 3.0):
                num_random += 1
            elif (s[0].isupper() and s[1:].islower()):
                num_random += 1
        if (num_random >= 3):
            var_vals = var_vals[1:]

    # Looks like duplicate subsequences of values can appear in the extracted
    # strings. Remove those.
    var_vals = remove_duplicates(var_vals)
    
    # Find longest value.
    longest_val = ""
    tmp_vals = []
    for v in var_vals:
        if (v not in tmp_vals):
            tmp_vals.append(v)
        if (len(v) > len(longest_val)):
            longest_val = v
    var_vals = tmp_vals

    # Done.
    return var_vals, longest_val

def _get_specific_names(object_names, chunk, control_tip_var_names, debug):
    """Get possible OLE object names.

    @param object_names (list) A list of the names (str) of the object fields
    referenced in the VBA code.

    @param chunk (str) A chunk of OLE data containing OLE object names
    and text values.

    @param control_tip_var_names (list) The names (str) of the control
    tip objects.

    @param debug (boolean) A flag indicating whether to print debug
    information.

    @return (list) OLE object names (str) that appear in the given
    chunk.

    """

    # Get names.
    name_pat1 = r"(?:(?:\x17\x00)|(?:\x00\x80))(\w{2,})"
    name_pat = r"(?:" + name_pat1 + ")|("
    first = True
    for object_name in object_names:
        if (not first):
            name_pat += "|"
        first = False
        if ("." in object_name):
            object_name = object_name[:object_name.index(".")]
        name_pat += object_name
    name_pat += ")"
    names = re.findall(name_pat, chunk)
    if debug:
        print "\nORIG NAMES:"
        print names

    # Get rid of control tip text names, we have already handled those.
    tmp_names = []
    for name in names:
        if (len(name[0]) > 0):
            name = name[0]
        else:
            name = name[1]
        if (name in control_tip_var_names):
            continue
        # Skip duplicates.
        if (name in tmp_names):
            continue
        tmp_names.append(name)
    var_names = tmp_names

    # Done.
    return var_names

def get_ole_textbox_values2(data, debug, vba_code, stream_names):
    """Read in the text associated with embedded OLE form textbox
    objects (hack!). NOTE: This currently is a really NASTY hack.

    @param data (str) The read in Office 97 file (data).

    @param debug (boolean) A flag indicating whether to print debug
    information.

    @param vba_code (str) The VBA macro code from the Office file.

    @param stream_names (list) A list of the names of OLE streams in
    the Office OLE file.

    @return (list) A list of 2 element tuples where the 1st element is
    the object name and the 2nd is the object text.

    """

    # Pull out the object text value references from the VBA code.
    object_names, control_tip_var_names = _get_field_names(vba_code, debug)
    
    # Read in the large chunk of data with the object names and string values.
    chunk = _read_large_chunk(data, debug)
    if (chunk is None):                
        return []
    
    # Pull out the raw strings from the value chunk.
    vals = _read_raw_strs(chunk, stream_names, debug)

    # Match control tip names with control tip text.
    r = _handle_control_tip_text(control_tip_var_names, vals, debug)

    # Now use detailed regexes to pull out the var names and values.

    # Get names.
    var_names = _get_specific_names(object_names, chunk, control_tip_var_names, debug)

    # Get values.        
    var_vals, longest_val = _get_specific_values(chunk, stream_names, debug)
    
    # Make sure the # of names = # of values.
    if (len(var_names) > len(var_vals)):
        # TODO: How to intelligently pick whether to knock a name off the front or end.
        #var_names = var_names[-len(var_vals):]
        var_names = var_names[:len(var_vals)]
        
    if debug:
        print "\nROUND 2:\nNAMES:"
        print var_names
        print "\nVALS:"
        print var_vals
    
    # Match up the names and values.
    pos = -1
    hack_names = set(["Page1", "Label1"])
    for name in var_names:

        # Hack for Pages objects.
        pos += 1
        if ((name in hack_names) and (len(longest_val) > 30)):
            val = longest_val

        # Real processing.
        else:
            val = var_vals[pos]
            if (val.endswith('o')):
                val = val[:-1]
            elif (val.endswith("oe")):
                val = val[:-2]

        # Save name/value mapping.
        r.append((name, val))

        # Some extra characters sometimes are on the end of the names. Brute force this
        # by just returning multiple name variants with characters chopped off the end.
        n = name
        if (len(n) > 2):
            n = n[:-1]
            r.append((n, val))
        if (len(n) > 2):
            n = n[:-1]
            r.append((n, val))
        if (len(n) > 2):
            n = n[:-1]
            r.append((n, val))

    # Done.
    if debug:
        print "\nRESULTS VALUES2:"
        print r
    return r

def get_ole_textbox_values1(data, debug, stream_names):
    """Read in the text associated with embedded OLE form textbox
    objects (hack!). NOTE: This currently is a really NASTY hack. 

    @param data (str) The read in Office 97 file (data).

    @param debug (boolean) A flag indicating whether to print debug
    information.

    @param stream_names (list) A list of the names of OLE streams in
    the Office OLE file.

    @return (list) A list of 2 element tuples where the 1st element is
    the object name and the 2nd is the object text.

    """

    # This handles some form of ActiveX object embedding where the list of object names
    # appears in a different file location than the text values associated with the
    # object names.

    # Find the object text values.
    if debug:
        print "\nget_ole_textbox_values1"

    # Pull out the chunk of data with the object values.
    chunk_pat = r'DPB=".*"\x0d\x0aGC=".*"\x0d\x0a(.*;Word8.0;&H00000000)'
    chunk = re.findall(chunk_pat, data, re.DOTALL)

    # Did we find the value chunk?
    if (len(chunk) == 0):
        if debug:
            print "\nNO VALUES"
        return []
    chunk = chunk[0]

    # Clear out some cruft that appears in the value chunk.
    ignore_pat = r"\[Host Extender Info\]\x0d\x0a&H\d+={[A-Z0-9\-]+};VBE;&H\d+\x0d\x0a&H\d+={[A-Z0-9\-]+}?"
    chunk = re.sub(ignore_pat, "", chunk)
    if ("\x00\x01\x01\x40\x80\x00\x00\x00\x00\x1b\x48\x80" in chunk):
        start = chunk.index("\x00\x01\x01\x40\x80\x00\x00\x00\x00\x1b\x48\x80")
        chunk = chunk[start+1:]

    # Normalize Page object naming.
    page_name_pat = r"Page(\d+)(?:(?:\-\d+)|[a-zA-Z]+)"
    chunk = re.sub(page_name_pat, r"Page\1", chunk)
        
    # Pull out the strings from the value chunk.
    ascii_pat = r"(?:[\x20-\x7f]|\x0d\x0a){5,}"
    vals = re.findall(ascii_pat, chunk)
    vals = vals[:-1]
    tmp_vals = []
    for val in vals:

        # Skip fonts.
        if (val.startswith("Taho")):
            continue
        # Skip stream names.
        if (val in stream_names):
            continue
        tmp_vals.append(val)
    vals = tmp_vals
    if debug:
        print "\n---------------"
        print "Values:"
        print chunk
        print vals
        print len(vals)

    # Pull out the object names.

    # Pull out the data chunk with the object names.
    name_pat = r"\\MSForms.exd(.*)Microsoft Forms 2.0 Form\x00\x10\x00\x00\x00Embedded Object"
    chunk = re.findall(name_pat, data, re.DOTALL)

    # Did we find the name chunk?
    if (len(chunk) == 0):
        if debug:
            print "\nNO NAMES"
        return []
    chunk_orig = chunk[0]

    # Can we narrow it down?
    if ("C\x00o\x00m\x00p\x00O\x00b\x00j" not in chunk_orig):
        if debug:
            print "\nNO NARROWED DOWN CHUNK"
        return []
    
    # Narrow the name chunk down.
    start = chunk_orig.index("C\x00o\x00m\x00p\x00O\x00b\x00j")
    chunk = chunk_orig[start + len("C\x00o\x00m\x00p\x00O\x00b\x00j"):]
    if debug:
        print "\n---------------"
        print "Names:"
        print chunk

    # Pull the names from the name chunk (ASCII strings).
    names = re.findall(ascii_pat, chunk)
    if (len(names) > 0):
        names = names[:-1]
    if (len(names) == 0):
        if ("Document" not in chunk_orig):
            if debug:
                print "\nNO NAMES, NO Document IN CHUNK"
            return []
        start = chunk_orig.index("Document")
        chunk = chunk_orig[start + len("Document"):]
        names = re.findall(ascii_pat, chunk)
        names = names[:-1]
    if debug:
        print names
        print len(names)

    # If we have more names than values skip the first few names.
    if (len(names) > len(vals)):
        if debug:
            print "\nNOT SAME # NAMES/VALS"
        names = names[len(names) - len(vals):]

    # Collect up and return the name -> value mappings.
    pos = -1
    r = []
    for n in names:
        pos += 1
        r.append((n, vals[pos]))

        # Some extra characters sometimes are on the end of the names. Brute force this
        # by just returning multiple name variants with characters chopped off the end.
        if (len(n) > 2):
            n = n[:-1]
            r.append((n, vals[pos]))
        if (len(n) > 2):
            n = n[:-1]
            r.append((n, vals[pos]))
        if (len(n) > 2):
            n = n[:-1]
            r.append((n, vals[pos]))

    # Done.
    if debug:
        print "\n-----------\nResult:"
        print r
    return r

def get_vbaprojectbin(data):
    """Pull the vbaProject.bin file from a 2007+ Office (ZIP) file.

    @param data (str) Already read in 2007+ file contents.

    @return (str) On success return the read in contents of
    vbaProject.bin. On error return None.

    """
    # TODO: [Phil] olevba already extracts vbaProject.bin in a safer way, so we should not have to do it here

    # We can only do this with 2007+ files.
    if (not filetype.is_office2007_file(data, True)):
        return None

    # Unzip the file contents.
    unzipped_data, fname = unzip_data(data)
    delete_file = (fname is not None)
    if (unzipped_data is None):
        return None

    # Pull out word/vbaProject.bin, if it is there.
    subfile_names = ['word/vbaProject.bin', 'xl/vbaProject.bin']
    zip_subfile = None
    for subfile in subfile_names:
        if (subfile in unzipped_data.namelist()):
            zip_subfile = subfile
            break
    if (zip_subfile is None):
        if (delete_file):
            os.remove(fname)
        return None

    # Read vbaProject.bin.
    f1 = unzipped_data.open(zip_subfile)
    r = f1.read()
    f1.close()

    # Done.
    if (delete_file):
        # Need to close the zipfile first, otherwise os.remove fails on Windows
        unzipped_data.close()
        os.remove(fname)
    return r

def strip_name(poss_name):
    """Remove bad characters from a potential OLE object name.

    @param poss_name (str) The potential object name.

    @return (str) The given name with bad characters stripped out.

    """
    
    # Remove sketchy characters from name.
    name = re.sub(r"[^A-Za-z\d_]", r"", poss_name)
    return name.strip()

def is_name(poss_name):
    """Check a given string to see if it could be an OLE object name.

    @param poss_name (str) The string to check.

    @return (boolean) True if the given string could be an object
    name, False if not.

    """
    
    # Sanity check.
    if (poss_name is None):
        return False

    # Basic check first. Must start with an alphabetic character and
    # be followed with regular printable characters.
    name_pat = r"[a-zA-Z]\w*"
    if (re.match(name_pat, poss_name) is None):
        return False

    # Now see how many non-name garbage characters are in the string.
    bad_chars = re.findall(r"[^A-Za-z0-9_]", poss_name)
    return (len(bad_chars) < 5)
    
def clean_names(names):
    """Strip out bad characters from the given OLE object names.

    @param names (list) A list of object names (str) to clean.

    @return (set) A set of cleaned names.

    """
    
    r = set()    
    for poss_name in names:
        poss_name = poss_name.strip()
        if (is_name(poss_name)):
            r.add(poss_name)
    return r

def _get_stream_names(vba_code):
    """Pull the names of OLE streams from olevba output.

    @param vba_code (str) The olevba output for the Office file being
    analyzed.

    @return (list) The names of the OLE streams pulled from the olevba
    output.

    """
    stream_pat = r'Attribute VB_Name = "([\w_]+)"'
    return re.findall(stream_pat, vba_code)    

def _find_name_in_data(object_names, found_names, strs, debug):
    """Look for a VBA name in the string values pulled from a chunk of an
    Office 97 file.

    @param object_names (list) A list of the names (str) of the object
    fields referenced in the Office file's VBA code. These are the
    names being looked for.

    @param found_names (set) Names that we have already found.

    @param strs (list) All of the ASCII strings found in the current
    file chunk being analyzed.

    @param debug (boolean) A flag indicating whether to print debug
    information.

    @return (tuple) A 3 element tuple where the 1st element is the
    last checked position in the string list, the 2nd element is the
    position in the string list where the name was found, and the 3rd
    element is the name that was found.

    """

    # Look through the strings in reverse to get the last referenced name.
    curr_pos = 0
    name_pos = 0
    name = None
    page_pat = r"(Page\d+)(?:[A-Za-z]+[A-Za-z0-9]*)?"
    for field in strs[::-1]:
        poss_name = field.replace("\x00", "").replace("\xff", "").strip()
        # Fix strings like "Page2M3A"
        if (re.search(page_pat, poss_name) is not None):
            poss_name = re.findall(page_pat, poss_name)[0]
        # Found unhandled name?
        if ((poss_name in object_names) and (poss_name not in found_names)):

            # Looks like this is one of the objects we are looking for.
            name = poss_name
            name_pos = curr_pos
            if debug:
                print "\nFound referenced name: " + name
            break
        curr_pos += 1

    # If we found a name, see if it shows up multiple times and pick the one
    # with the largest value.
    curr_pos = len(strs) - curr_pos - 1 # handle reversed list.
    name_pos = len(strs) - name_pos - 1 # handle reversed list.
    if (name is not None):
        curr_pos = -1
        max_val = ""
        for field in strs:
            curr_pos += 1
            if ((field == name) and
                ((curr_pos + 1) < len(strs)) and
                (len(strs[curr_pos + 1]) > len(max_val))):
                max_val = strs[curr_pos + 1]
                name_pos = curr_pos
        
    return (curr_pos, name_pos, name)

def _find_repeated_substrings(s, chunk_size, min_str_size):
    """Find all of the repeated substrings in a given string that are longer
    than a certain length. This assumes that repeated substrings of interest
    show up in a prefix of a given size.

    @param s (str) The string to check for repeated substrings. Only
    a prefix of the string will be checked.

    @param chunk_size (int) The size of the string prefix to check for
    repeated substrings. If bigger than the given string length an
    empty set will be returned.

    @param min_str_size (int) The minimum substring size to
    track. Shorter repeated substrings will not be reported.

    @return (set) A set of repeated substrings.

    """
    
    # If there is a repeated string it will show up in the 1st NN characters
    # of the string.
    if (chunk_size > len(s)):
        return set()
    chunk = s[:chunk_size]

    # Start looking for repeats of substrings of length 2 in the chunk.
    pos = -1
    window_size = 2
    r = set()
    while ((pos + window_size) < len(chunk)):

        # Is this 2 character chunk repeated?
        pos += 1
        curr_str = chunk[pos:pos + window_size]
        if (s.count(curr_str) > 1):

            # Start adding 1 character at at time to the substring until
            # we find no more repeats. This should give us the longest
            # repeated substring with the current prefix.
            tmp_window_size = 3
            old_curr_str = None
            while ((s.count(curr_str) > 1) and
                   ((pos + tmp_window_size) < len(chunk))):
                old_curr_str = curr_str
                curr_str = chunk[pos:pos + tmp_window_size]
                tmp_window_size += 1

            # Found an acceptable repeated substring?
            if ((old_curr_str is not None) and
                (len(old_curr_str.strip()) >= min_str_size)):

                # Save the full string.
                r.add(old_curr_str)

                # If this is a large string some substrings may be more
                # common repeats. Add some of those.
                if (len(old_curr_str) > min_str_size*3):
                    for i in range(1, len(old_curr_str) - min_str_size*3):
                        r.add(old_curr_str[:i*-1])

    # Done
    return r

def _find_most_repeated_substring(strs):
    """Find the most common repeated substring in a given list of strings.

    @param strs (list) The strings to check for the most common
    repeated substring.

    @return (str) The most common repeated substring if any were
    found. If no repeats are found None will be returned.

    """
    
    # Find all the repeated substrings in all the given strings.
    all_substs = set()
    for s in strs:
        all_substs = all_substs.union(_find_repeated_substrings(s, 300, 4))
    #print all_substs
        
    # Found any repeated substrings?
    if (len(all_substs) == 0):
        return None
        
    # Find the substring that is repeated the most.
    max_repeats = -1
    max_subst = ""
    #print "FIND MAX REPEATS!!"
    for curr_subst in all_substs:
        curr_repeats = 0
        for s in strs:
            curr_repeats += s.count(curr_subst)
        if (curr_repeats < 5):
            continue
        #print "############"
        #print curr_subst
        #print curr_repeats
        #print max_subst
        #print max_repeats
        if (curr_repeats * len(curr_subst) > max_repeats * len(max_subst)):
            max_repeats = curr_repeats
            max_subst = curr_subst

    # Return the most repeated substring.
    if (max_subst == ""):
        max_subst = None
    return max_subst

def _find_str_with_most_repeats(strs):
    """Find the string in the given list of strings that contains the most
    instances of some repeated substring. In more detail, this finds
    the most commonly repeated substring in all the given strings and
    then finds the given string that contains the most repeats of the
    most common repeated substring.

    @param strs (list) The strings to check.

    @return (str) If repeated substrings were found return the given
    string that has the most repeats of the most common repeated
    substring. If no repeated substrings were found None is returned.

    """
    
    # Find the substring that is repeated most overall. This substring
    # could show up in multiple strings.
    max_subst = _find_most_repeated_substring(strs)
    if (max_subst is None):
        return (None, None)
    
    # Now find which given string has the most instances of the reported
    # substring.
    max_count = -1
    max_str = None
    for s in strs:
        curr_count = s.count(max_subst)
        if (curr_count > max_count):
            max_count = curr_count
            max_str = s

    # Done.
    return (max_str, max_subst)

def get_ole_text_method_1(vba_code, data, debug=False):
    """Pull OLE object name/value pairs from given OLE data using
    heuristic method 1.

    @param vba_code (str) The VBA macro code from the Office file.

    @param data (str) The read in Office 97 file (data).

    @param debug (boolean) A flag indicating whether to print debug
    information.

    @return (list) A list of 2 element tuples where the 1st element is
    the object name and the 2nd is the object text.

    """
    
    # Debug this thing.
    debug1 = debug
    #debug1 = True
    
    # Strip some red herring strings from the data.
    if debug1:
        print "\n\nSTART get_ole_text_method_1 !!!!"
    data = data.replace("\x1f\x22", '"\x00')
    data = re.sub(r"[\x20-\x7e]\x00(?:\xe5|\xd5)", "", data)
    data = data.replace("\x02$", "").\
           replace("\x01@", "").\
           replace("0\x00\xe5", "").\
           replace("\xfc", "").\
           replace("\x19 ", "").\
           replace("_epx" + chr(223), "").\
           replace("R\x00o\x00o\x00t\x00 \x00E\x00n\x00t\x00r\x00y", "").\
           replace("Embedded Object", "").\
           replace("mbedded Object", "").\
           replace("bedded Object", "").\
           replace("edded Object", "").\
           replace("dded Object", "").\
           replace("ded Object", "").\
           replace("ed Object", "").\
           replace("d Object", "").\
           replace("jd\x00\x00", "\x00").\
           replace("\x00\x00", "\x00").\
           replace("\x0c%", "")
    if (re.search(r"\x00.%([^\x00])\x00", data) is not None):
        data = re.sub(r"\x00.%([^\x00])\x00", "\x00\\1\x00", data)
    data = data.replace("\r", "__CARRIAGE_RETURN__")
    data = data.replace("\n", "__LINE_FEED__")
    if (re.search(r"\x00([ -~])[^ -~\x00]([ -~])\x00", data) is not None):
        data = re.sub(r"\x00([ -~])[^ -~\x00]([ -~])\x00", "\x00\\1\x00\\2\x00", data)
    if (re.search(r"\x00[ -~]{2}([ -~])\x00", data) is not None):
        data = re.sub(r"\x00[ -~]{2}([ -~])\x00", "\x00\\1\x00", data)
    data = re.sub(r"\x00[^ -~]", "", data)
    if (re.search(r"\x00([ -~])[^ -~\x00]([ -~])\x00", data) is not None):
        data = re.sub(r"\x00([ -~])[^ -~\x00]([ -~])\x00", "\x00\\1\x00\\2\x00", data)
    data = data.replace("__CARRIAGE_RETURN__", "\r")
    data = data.replace("__LINE_FEED__", "\n")
    if debug1:
        print data
        print "\n\n\n"

    # Pull out the strings from the data.
    ascii_pat = r"(?:[\r\n\x09\x20-\x7f]|\x0d\x0a){4,}|(?:(?:[\r\n\x09\x20-\x7f]\x00|\x0d\x00\x0a\x00)){4,}"
    vals = re.findall(ascii_pat, data)
    tmp_vals = []
    for val in vals:
        
        # No wide char strings.
        val = val.replace("\x00", "")
        
        # Eliminate cruft.
        for cruft_pat in cruft_pats:
            val = re.sub(cruft_pat, "", val)
            
        # Skip strings that were pure cruft.
        if (len(val) == 0):
            continue
            
        # Skip fonts and other things.
        if ((val.startswith("Taho")) or
            (val.startswith("PROJECT")) or
            (val.startswith("_DELETED_NAME_"))):
            continue

        # No HTML.
        if (val.strip().startswith("<!DOCTYPE html")):
            continue
        
        # Save modified string.
        tmp_vals.append(val)
        if debug1:
            print "+++++++++++++++"
            print val

    # Find the string with the most repeated substrings.
    max_substs, repeated_subst = _find_str_with_most_repeats(tmp_vals)
    if (max_substs is None):
        if debug1:
            print "DONE!! NO REPEATED SUBSTRINGS!!"
        return None
    if debug1:
        print "\n"
        print "*************"
        print "MAX SUBSTS"
        print max_substs
        print "\n"
        print "*************"
        print "REPEATED SUBST"
        print repeated_subst
    
    # Is this big enough to be interesting?
    if debug1:
        print "LEN MAX STR: " + str(len(max_substs))
        print "MAX REPEATS IN 1 STR: " + str(max_substs.count(repeated_subst))
        print "REPEATED STR: '" + repeated_subst + "'"
    if ((len(max_substs) < 100) or (max_substs.count(repeated_subst) < 20)):
        if debug1:
            print "DONE!! TOO FEW REPEATED SUBSTRINGS!!"
        return None

    # Tack together all the substrings that have the repeated substring as a large
    # percentage of their string.
    aggregate_str = ""
    obj_pat = r'VERSION \d\.\d{1,5}\r\n' + \
              r'Begin \{\w{2,20}\-\w{2,20}\-\w{2,20}\-\w{2,20}\-\w{2,20}\} \w{2,20} \r\n' + \
              r' {1,10}Caption {1,30}= {1,30}"\w{1,20}"\r\n' + \
              r' {1,10}ClientHeight {1,30}= {1,30}\d{1,20}\r\n' + \
              r' {1,10}ClientLeft {1,30}= {1,30}\d{1,20}\r\n' + \
              r' {1,10}ClientTop {1,30}=? {0,30}(?:\d{3})?'
    for val in tmp_vals:

        # Ignore empty strings.
        val = val.replace("\x00", "")
        if (len(val) == 0):
            continue

        # Is a large percentage of the current string the repeated substring?
        pct = (val.count(repeated_subst) * len(repeated_subst)) / float(len(val)) * 100
        if (pct > 30):

            # Yes it is. Add it to the payload.

            # The repeated substring may be split between the new substring and
            # the previous string. Make sure the strings are properly glued in this
            # case with the substring.

            # Find the portion of the repeated string in the 1st half of the string.
            # 112345
            # foo11
            # 2345bar
            first_half_rep = None
            second_half_rep = None
            matched_agg_str = ""
            # Might have extra characters on the end of the aggregate string.
            # Walk back from the end of the string trying to match up the
            # repeated string chunks.
            for end_pos in range(0, 3):
                if debug1:
                    print "CHECK !!!!!!!!!!!!!"
                    print "chopping off " + str(end_pos)
                curr_agg_str = aggregate_str[:-end_pos]
                for i in range(1, len(repeated_subst) + 1):
                    curr_first_half = repeated_subst[:i]
                    if debug1:
                        print "++++"
                        print "curr 1st half"
                        print curr_first_half
                        print "curr 1st half string end"
                        print curr_agg_str[-len(curr_first_half):]
                    if (curr_agg_str.endswith(curr_first_half) and
                        (len(curr_agg_str) > len(matched_agg_str))):
                        if debug1:
                            print "MATCH!!"
                        matched_agg_str = curr_agg_str
                        first_half_rep = curr_first_half
                        second_half_rep = repeated_subst[i:]

            # Repeated string not split up (1st string ends with repeated string)?
            if (first_half_rep == repeated_subst):
                first_half_rep = None
                second_half_rep = None

            # Handle chopping garbage characters from the end of the aggregate string.
            if (matched_agg_str != ""):
                aggregate_str = matched_agg_str
                
            # There could be extra characters in front of the 2nd half of the string.
            if (first_half_rep is not None):

                if debug1:
                    print "FIRST HALF!!"
                    print first_half_rep
                    print "SECOND HALF!!"
                    print second_half_rep
                
                # Figure out characters to skip in the 2nd half.
                start_pos = 0
                while (start_pos < len(val)):
                    if (val[start_pos:].startswith(second_half_rep)):
                        break
                    start_pos += 1
                if debug1:
                    print "SKIP 2nd HALF!!"
                    print val[:start_pos]
                val = val[start_pos:]

            # The repeated string was not split.
            else:

                # Clear some stupid Office 97 cruft from the 2nd half of the string.
                if (repeated_subst in val):
                    start_pos = val.index(repeated_subst)                    
                    while (((start_pos - 1) >= 0) and
                           (re.match("[A-Za-z]", val[start_pos - 1]) is not None)):
                        start_pos -= 1
                    val = val[start_pos:]
                else:
                    val = re.sub(obj_pat, "", val)
                
            # Add in another payload piece.
            aggregate_str += val
        if debug1:
            print "-------"
            print val.strip()
            print pct
    if (len(aggregate_str) == 0):
        aggregate_str = max_substs
        
    # Get the names of ActiveX/OLE items accessed in the VBA.
    object_names = set(re.findall(r"(?:ThisDocument|ActiveDocument|\w+)\.(\w+)", vba_code))
    object_names.update(re.findall(r"(\w+)\.Caption", vba_code))
    object_names.update(re.findall(r"(\w+) *_? *(?:\r?\n)? *\. *_? *(?:\r?\n)? *Content", vba_code))
    
    # Are we refering to Page or Tab or InlineShape objects by index?
    page_pat = r"((?:Pages|Tabs|InlineShapes|Item).?\(.+\))"
    if (re.search(page_pat, vba_code) is not None):

        # Add some Page objects to look for.
        for i in range(1, 10):
            object_names.add("Page" + str(i))

    # How about StoryRanges items?
    if (".StoryRanges" in vba_code):

        # Add some StoryRanges objects to look for.
        for i in range(1, 10):
            object_names.add("StoryRanges.Items('" + str(i) + "')")
            object_names.add("StoryRanges('" + str(i) + "')")
            object_names.add("StoryRanges.Items(" + str(i) + ")")
            object_names.add("StoryRanges(" + str(i) + ")")
            
    # Eliminate any obviously bad names.
    object_names = clean_names(object_names)
    if debug1:
        print "\nFINAL:"
        print aggregate_str
        print object_names
        sys.exit(0)

    
    # Just assign every item accessed in the VBA to this value and hope for the best.
    r = []
    for curr_object in object_names:
        r.append((curr_object, aggregate_str))
    return r

def _get_next_chunk(data, index, form_str, form_str_pat, end_object_marker):
    """Get the next chunk of OLE object name/value information from the
    given OLE data.

    @param data (str) The read in Office 97 file (data).

    @param index (int) The position in the OLE data from which to
    start looking for the next chunk.

    @param form_str (str) A string marking the start of the data for
    an OLE form.

    @param form_str_pat (str) A regex for recognizing strings marking
    the start of an OLE form.

    @param end_object_marker (str) The string marking the end of a
    chunk.

    @return (tuple) A 3 element tuple where the 1st element is the
    next chunk, the 2nd element is the index of the start of the chunk
    and the 3rd element is the index of the end of the chunk.

    """

    # Move to the end of specific versions of the form string.
    # "Microsoft Forms 2.0 TextBox", "Microsoft Forms 2.0 ComboBox", etc.
    search_r = re.search(form_str_pat, data[index:])
    index = search_r.start() + index
    start = index + len(search_r.group(0))
    while ((start < len(data)) and (ord(data[start]) in range(32, 127))):
        start += 1

    # More textbox forms?
    if ((form_str in data[start:]) and
        (end_object_marker in data[start:]) and
        (data[start:].index(end_object_marker) < data[start:].index(form_str))):

        # Other form chunks appear later in the file, but this is the end of
        # the current group of form chunks.
        end = data[start:].index(end_object_marker) + start

    # Not at end of current group of form chunks.
    elif (form_str in data[start:]):

        # Just look at the current form chunk.
        end = data[start:].index(form_str) + start

    # No more textbox forms. Look for end object marker.
    elif (end_object_marker in data[start:]):

        # Just look at the current form chunk.
        end = data[start:].index(end_object_marker) + start

    # No more textbox forms and no end marker. Punt.
    else:

        # Jump an arbitrary amount ahead.
        end = index + 2500000
        if (end > len(data)):
            end = len(data) - 1

    # Pull out the current form data chunk.
    chunk = data[index : end]

    # Return the chunk and updated index.
    return (chunk, index, end)

def _pull_object_names(vba_code):
    """Pull out the names of object fields referenced in the given VBA
    code.

    @param vba_code (str) The VBA macro code from the Office file.

    @return (tuple) A 2 element tuple, where the 1st element is a set
    of object field names and the 2nd element is a set of page
    (PageNN) object field names.

    """

    # Pull out the names of forms the VBA is accessing. We will use that later to try to
    # guess the names of ActiveX forms parsed from the raw Office file.
    object_names = set(re.findall(r"(?:ThisDocument|ActiveDocument|\w+)\.(\w+)", vba_code))
    object_names.update(re.findall(r"(\w+)\.Caption", vba_code))
    
    # Are we refering to Page objects by index?
    page_pat = r"(?:ThisDocument|ActiveDocument|\w+)\.(Pages\(.+\))"
    page_names = set()
    if (re.search(page_pat, vba_code) is not None):

        # Add some Page objects to look for.
        for i in range(1, 10):
            object_names.add("Page" + str(i))
            page_names.add("Page" + str(i))

    # Eliminate any obviously bad names.
    object_names = clean_names(object_names)

    # Done.
    return (object_names, page_names)

def _guess_name_from_data(strs, field_marker, debug):
    """Use heuristics to guess the object name in the given list of
    strings pulled from a chunk of OLE data.

    @param strs (list) The strings pulled from the OLE chunk.

    @param field_marker (str) A string that marks the start of an
    object text value.

    @param debug (boolean) A flag indicating whether to print debug
    information.

    @return (tuple) A 2 element tuple where the 1st element is the
    position in the given list of strings where the name was found and
    the 2nd element is the name. If a name was not found the 2nd
    element will be None.

    """

    # Pull out the variable name (and maybe part of the text).
    name_pos = None
    name = None
    curr_pos = 0
    for field in strs:
    
        # It might come after the 'Forms.TextBox.1' tag.
        if (field.startswith(field_marker)):
    
            # If the next field does not look something like '_1619423091' the
            # next field is the name. CompObj does not count either.
            poss_name = None
            if ((curr_pos + 1) < len(strs)):
                poss_name = strs[curr_pos + 1].replace("\x00", "").replace("\xff", "").strip()
            skip_names = set(["contents", "ObjInfo", "CompObj"])
            if ((poss_name is not None) and
                ((not poss_name.startswith("_")) or
                 (not poss_name[1:].isdigit())) and
                (poss_name not in skip_names)):
    
                # We have found the name.
                name = poss_name
                name_pos = curr_pos + 1
    
            # Seems like there is only 1 'Forms.TextBox.1', so we are
            # done with this loop.
            break

        # Move to the next field.
        curr_pos += 1

    # Did we find the name?
    if (name is None):

        # No. The name comes after an 'OCXNAME' or 'OCXPROPS' field. Figure out
        # which one.
        name_marker = "OCXNAME"
        for field in strs:
            if (field.replace("\x00", "") == 'OCXPROPS'):
                name_marker = "OCXPROPS"

        # Now look for the name after the name marker.
        curr_pos = 0
        if debug:
            print "\nName Marker: " + name_marker
        for field in strs:

            # No name marker?
            if debug:
                print "\nField: '" + field.replace("\x00", "") + "'"
            if (field.replace("\x00", "") != name_marker):
                # Move to the next field.
                curr_pos += 1
                continue
                
            # It might come after the name marker tag.

            # If the next field looks something like '_1619423091' the
            # next field is not the name.                
            poss_name = strs[curr_pos + 1].replace("\x00", "")
            if debug:
                print "\nTry: '" + poss_name + "'"
            if (poss_name.startswith("_") and poss_name[1:].isdigit()):

                # Move to the next field.
                curr_pos += 1
                continue

            # Got the name now?
            if (poss_name != 'contents'):

                # We have found the name.
                name = poss_name
                break

            # If the string after 'OCXNAME' is 'contents' the actual name comes
            # after 'contents'
            name_pos = curr_pos + 1
            poss_name = strs[curr_pos + 2].replace("\x00", "")
            if debug:
                print "\nTry: '" + poss_name + "'"
                            
            # Does the next field does not look something like '_1619423091'?
            if ((not poss_name.startswith("_")) or
                (not poss_name[1:].isdigit())):

                # We have found the name.
                name = poss_name
                name_pos = curr_pos + 2
                break

            # Try the next field.
            if ((curr_pos + 3) < len(strs)):                                    
                poss_name = strs[curr_pos + 3].replace("\x00", "")
                if debug:
                    print "\nTry: '" + poss_name + "'"

                # CompObj is not an object name.
                if (poss_name != "CompObj"):
                    name = poss_name
                    name_pos = curr_pos + 3
                    break

            # And try the next field.
            if ((curr_pos + 4) < len(strs)):
                poss_name = strs[curr_pos + 4].replace("\x00", "")
                if debug:
                    print "\nTry: '" + poss_name + "'"

                # ObjInfo is not an object name.
                if (poss_name != "ObjInfo"):
                    name = poss_name
                    name_pos = curr_pos + 4
                    break

            # Heaven help us all. Try the next one.
            if ((curr_pos + 5) < len(strs)):
                poss_name = strs[curr_pos + 5].replace("\x00", "")
                if debug:
                    print "\nTry: '" + poss_name + "'"

                # ObjInfo is not an object name.
                if (poss_name != "ObjInfo"):
                    name = poss_name
                    name_pos = curr_pos + 5
                    break

            # Move to the next field.
            curr_pos += 1

    # Done.
    return (name_pos, name)

def _get_raw_text_for_name(name_pos, strs, chunk, debug):
    """Use heuristics to get the potential text value for the object with
    the name at the given name position.

    @param name_pos (int) The position in the given list of strings
    where the name was found.

    @param strs (list) A list of strings pulled from the OLE chunk
    being analyzed.

    @param chunk (str) The OLE chunk being analyzed.

    @param debug (boolean) A flag indicating whether to print debug
    information.
    
    @return (str) The text associated with the object with the name at
    the given position. This will be an empty string if no associated
    text value is found.

    """

    # Get a text value after the name if it looks like the following field
    # is not a font.
    text = ""
    # This is not working quite right.
    if (name_pos + 1 < len(strs)):
        asc_str = strs[name_pos + 1].replace("\x00", "").strip()
        skip_names = set(["contents", "ObjInfo", "CompObj", None])
        if (("Calibr" not in asc_str) and
            ("OCXNAME" not in asc_str) and
            (asc_str not in skip_names) and
            (not asc_str.startswith("_DELETED_NAME_")) and
            (re.match(r"_\d{10}", asc_str) is None)):
            if debug:
                print "\nValue: 1"
                print strs[name_pos + 1]
                
            # Only used with large text values?
            if (len(strs[name_pos + 1]) > 3):
                text = strs[name_pos + 1]
                if debug:
                    print "\nValue: 2"
                    print strs[name_pos + 1]

    # Break out the (possible additional) value.
    val_pat = r"(?:\x00|\xff)[\x20-\x7e]+[^\x00]*\x00+\x02\x18"
    vals = re.findall(val_pat, chunk)
    if (len(vals) > 0):
        empty_pat = r"(?:\x00|\xff)#[^\x00]*\x00+\x02\x18"
        if (len(re.findall(empty_pat, vals[0])) == 0):
            poss_val = re.findall(r"[\x20-\x7e]+", vals[0][1:-2])[0]
            if ((poss_val != text) and (len(poss_val) > 1)):
                text += poss_val.replace("\x00", "")
                if debug:
                    print "\nValue: 3"
                    print poss_val.replace("\x00", "")

    # Pattern 2                    
    val_pat = r"\x00#\x00\x00\x00[^\x02]+\x02"
    vals = re.findall(val_pat, chunk)
    if (len(vals) > 0):
        tmp_text = re.findall(r"[\x20-\x7e]+", vals[0][2:-2])
        if (len(tmp_text) > 0):
            poss_val = tmp_text[0]
            if (poss_val != text):
                if debug:
                    print "\nValue: 4"
                    print poss_val
                text += poss_val

    # Pattern 3
    val_pat = r"([\x20-\x7e]{5,})\x00\x02\x0c\x00\x34"
    vals = re.findall(val_pat, chunk)
    if (len(vals) > 0):
        for v in vals:
            text += v
            if debug:
                print "\nValue: 5"
                print v

    # Pattern 4
    val_pat = r"([\x20-\x7e]{5,})\x00{2,4}\x02\x0c"
    vals = re.findall(val_pat, chunk)
    if (len(vals) > 0):
        for v in vals:
            text += v
            if debug:
                print "\nValue: 6"
                print v
                
    # Maybe big chunks of text after the name are part of the value?
    for pos in range(name_pos + 2, len(strs)):
        curr_str = strs[pos].replace("\x00", "")
        if ((len(curr_str) > 40) and (not curr_str.startswith("Microsoft "))):
            text += curr_str

    # Done.
    return text

def _clean_text_for_name(chunk, name, text, object_names, stream_names, longest_str, orig_strs, debug):
    """Clean up the text value associated with an object with a given
    name.

    @param chunk (str) The OLE chunk being analyzed.

    @param name (str) The name of the object.

    @param text (str) The raw text associated with the object.

    @param object_names (list) The names of objects referenced in the
    VBA code of the Office file being analyzed.

    @param stream_names (list) The names of the OLE streams in the
    Office file being analyzed.

    @param longest_str (str) The longest string associated with an
    object (so far).

    @param orig_strs (list) The ASCII strings pulled from the OLE
    chunk.

    @param debug (boolean) A flag indicating whether to print debug
    information.

    @return (str) The cleaned up text value.

    """

    # Pull out the size of the text.
    # Try version 1.
    size_pat = r"\x48\x80\x2c\x03\x01\x02\x00(.{2})"
    tmp = re.findall(size_pat, chunk)
    if (len(tmp) == 0):
        # Try version 2.
        size_pat = r"\x48\x80\x2c(.{2})"
        tmp = re.findall(size_pat, chunk)
    if (len(tmp) == 0):
        # Try version 3.
        size_pat = r"\xf8\x00\x28\x00\x00\x00(.{2})"
        tmp = re.findall(size_pat, chunk)
    if (len(tmp) == 0):
        # Try version 4.
        size_pat = r"\x2c\x00\x00\x00\x1d\x00\x00\x00(.{2})"
        tmp = re.findall(size_pat, chunk)
    if (len(tmp) > 0):
        size_bytes = tmp[0]
        size = ord(size_bytes[1]) * 256 + ord(size_bytes[0])
        if (debug):
            print "SIZE: "
            print size
        if ((len(text) > size) and (not name.startswith("Page"))):
            text = text[:size]

    # Eliminate text values that look like variable names.
    if ((strip_name(text) in object_names) or
        (strip_name(text) in stream_names)):
        if debug:
            print "\nBAD: Val is name '" + text + "'"

        # Hack. If the bad value is a Page* name and we have a really long strings from
        # the chunk, use those as the value.
        if ((text.startswith("Page")) and (len(longest_str) > 30)):
            tmp_str = ""
            for field in orig_strs:
                if ((len(field) > 20) and
                    (not field.startswith("Microsoft "))):
                    tmp_field = ""
                    for s in re.findall(r"[\x20-\x7f]{5,}", field):
                        tmp_field += s
                    tmp_str += tmp_field
            text = tmp_str
        else:
            text = ""
        if debug:
            print len(longest_str)
            print "BAD: Set Val to '" + text + "'"

    # Eliminate text values that look like binary chunks.
    text = text.replace("\x00", "")
    if (len(re.findall(r"[^\x20-\x7f]", text)) > 2):
        if debug:
            print "\nBAD: Binary in Val. Set to ''"
        text = ""

    # Eliminate form references.
    if ((text.startswith("Forms.")) and (len(text) < 20)):
        text = ""

    # Done.
    return text

def _find_longest_strs_form_results(long_strs, r):
    """Find various longest strings from a general list of extracted
    strings and text values assigned to object names.

    @param long_strs (list) A list of pretty long strings encountered
    during processing.

    @param r (list) A list of 2 element tuples where the 1st tuple
    element is the name of an object and the 2nd element is the object's
    associated text value.

    @return (tuple) A 3 element tuple where the 1st element is the
    longest string found in the longish string list, the 2nd element
    is the longest text value associated with an object name, and the
    3rd element is the longest text value associated with a PageNN
    object.

    """

    # Find the longest string value overall.
    longest_val = ""
    longest_str = ""
    page_val = ""
    for s in long_strs:
        if (len(s) > len(longest_str)):
            longest_str = s
    
    # Find the longest string assigned to Page1.
    for pair in r:
        name = pair[0]
        val = pair[1]
        if (name.startswith("Page")):
            #page_names.add(name)
            if (len(val) > len(page_val)):
                page_val = val
        if (name != "Page1"):
            continue
        if (len(val) > len(longest_val)):
            longest_val = val

    # Done.
    return (longest_str, longest_val, page_val)

def _merge_ole_form_results(r, v1_vals, v1_1_vals):
    """Merge the results of various heuristic methods used to find the
    text values of OLE objects.

    @param r (list) Value results as a list of 2 element tuples where
    the 1st element is the name (str) of an object and the 2nd element
    is the text value (str) of the object.

    @param v1_vals (list) Value results as a list of 2 element tuples
    where the 1st element is the name (str) of an object and the 2nd
    element is the text value (str) of the object.

    @param v1_1_vals (list) Value results as a list of 2 element
    tuples where the 1st element is the name (str) of an object and
    the 2nd element is the text value (str) of the object.

    @return (list) The merged results as a list of 2 element tuples
    where the 1st element is the name (str) of an object and the 2nd
    element is the text value (str) of the object.

    """

    # Merge in the variable/value pairs from the 1st alternate method. Override method 2
    # results with method 1 results.
    tmp = []
    v2_vals = r
    for v1_pair in v1_vals:
        tmp.append(v1_pair)
        for v2_pair in v2_vals:
            if (v1_pair[0] != v2_pair[0]):
                tmp.append(v2_pair)
    r = tmp
    if (len(r) == 0):
        r = v2_vals

    # Merge in the variable/value pairs from the 2nd alternate method. Override method 2
    # results with method 1 results.
    tmp = []
    v2_vals = r
    for v1_pair in v1_1_vals:
        tmp.append(v1_pair)
        for v2_pair in v2_vals:
            if (v1_pair[0] != v2_pair[0]):
                tmp.append(v2_pair)
    r = tmp
    if (len(r) == 0):
        r = v2_vals

    # Eliminate cruft in values.
    tmp = []
    for old_pair in r:
        name = old_pair[0]
        val = old_pair[1]
        for cruft_pat in cruft_pats:
            val = re.sub(cruft_pat, "", val)
        tmp.append((name, val))
    r = tmp

    # Done.
    return r

def _clean_up_ole_form_results(r, long_strs, v1_vals, v1_1_vals, object_names, debug):
    """Clean up the object name/value results computed in various ways,
    merge the various results, and return the merged and cleaned
    results.
    
    @param r (list) Value results as a list of 2 element tuples where
    the 1st element is the name (str) of an object and the 2nd element
    is the text value (str) of the object.

    @param long_strs (list) A list of pretty long strings encountered
    during processing.

    @param v1_vals (list) Value results as a list of 2 element tuples
    where the 1st element is the name (str) of an object and the 2nd
    element is the text value (str) of the object.

    @param v1_1_vals (list) Value results as a list of 2 element
    tuples where the 1st element is the name (str) of an object and
    the 2nd element is the text value (str) of the object.

    @param object_names (list) A list of the names (str) of the object fields
    referenced in the VBA code.

    @param debug (boolean) A flag indicating whether to print debug
    information.

    """

    # Fix variable names that are the same as previously seen variable values.
    last_val = None
    tmp = []
    for dat in r:

        # Skip this var/value pair if the current variable name is the same as
        # the previous variable value.
        if (dat[0].strip() != last_val):
            tmp.append(dat)
        else:
            if debug:
                print "\nSkip 1: " + str(dat)
        last_val = dat[1].strip()
    r = tmp

    if debug:
        print "\nFirst result:"
        print r
    
    # Fix data that is showing up as a variable name.
    tmp = []
    last_var = None
    last_val = None
    for dat in r:

        # Does the current variable name look like it is probably data?
        if (len(dat[0]) > 50):

            # Try this out as the data for the previous variable.
            last_val = dat[0]

        # Add the previous variable to the results.
        if (last_var is not None):
            tmp.append((last_var, last_val))

        # Save the current variable and value.
        last_var = dat[0]
        last_val = dat[1]

    # Add in the final result.
    if ((last_var is not None) and (len(last_var) < 50)):
        tmp.append((last_var, last_val))
    r = tmp

    # Fix objects that have no values. This assumes they get the value of an object
    # that follows them.
    tmp = []
    pos = -1
    last_val = ""
    if debug:
        print "\nLONG STRS!!"
        print long_strs
    for dat in r:

        # Does the current variable have no value?
        pos += 1
        curr_var = dat[0]
        curr_val = dat[1]        
        if debug:
            print curr_var
            print pos
            print len(curr_val)
        if ((curr_val is None) or (len(curr_val) == 0)):
            
            # Set the current variable to the value of the next variable with a long value and
            # hope for the best.
            replaced = False
            for i in range(pos + 1, len(r)):
                poss_val = long_strs[i]
                if (len(r[i][1]) > len(poss_val)):
                    poss_val = r[i][1]
                if (len(poss_val) > 15):
                    if debug:
                        print "\nREPLACE (1)"
                    curr_val = poss_val
                    replaced = True
                    break

            # If we found nothing going forward, try the previous value?
            if ((not replaced) and (len(last_val) > 15)):
                if debug:
                    print "\nREPLACE (2)"
                curr_val = last_val

        # Update the result list.
        tmp.append((curr_var, curr_val))
        last_val = curr_val
    r = tmp

    # Merge in the variable/value pairs from various methods.
    r = _merge_ole_form_results(r, v1_vals, v1_1_vals)
    
    # Get the longest string value overall and the longest string assigned
    # to a PageNN variable.
    longest_str, longest_val, page_val = _find_longest_strs_form_results(long_strs, r)

    # Fix Page1 values.
    
    # Just have 1 var/val assignment pair assigning Page1 to the longest val.
    page_names = set()
    if (longest_val != ""):
        tmp_r = []
        updated_page1 = False
        for pair in r:
            name = pair[0]
            # Super specific hack.
            if (name == "Page2"):
                tmp_r.append((name, longest_str))
                continue
            if (name != "Page1"):
                tmp_r.append(pair)
                continue
            if (not updated_page1):
                tmp_r.append((name, longest_val))
                updated_page1 = True
        r = tmp_r

    # If we have nothing assigned to Page1, just pick the longest string seen
    # to assign to missing PageNN variables and hope for the best.
    if debug:
        print "\nPAGE VAL!!"
        print page_val
    if (page_val == ""):
        page_val = longest_str
        
    # Fill in missing PageNN variables.
    for i in range(1, 5):
        curr_name = "Page" + str(i)
        if ((curr_name not in page_names) and (page_val != "")):
            r.append((curr_name, page_val))

    # Fill in other missing variables referred to in the VBA.
    handled_names = set()
    for mapping in r:
        handled_names.add(mapping[0])
    for curr_name in object_names:
        if ((curr_name not in handled_names) and (longest_str != "")):
            r.append((curr_name, longest_str))

    # Done.
    return r
            
def get_ole_textbox_values(obj, vba_code):
    """Read in the text associated with embedded OLE form textbox
    objects. NOTE: This currently is a NASTY hack.

    @param obj (str) The read in Office file to analyze or the name
    of the Office file to analyze. The file will be read in if a file
    name is given.

    @param vba_code (str) The VBA macro code from the Office file.

    @return (list) The results as a list of 2 element tuples where the
    1st element is the name (str) of an object and the 2nd element is
    the text value (str) of the object.

    """

    # Figure out if we have been given already read in data or a file name.
    if obj[0:4] == '\xd0\xcf\x11\xe0':

        #its the data blob
        data = obj
    else:

        # Probably a file name?
        try:
            f = open(obj, "rb")
            data = f.read()
            f.close()
        except IOError:
            data = obj
        except TypeError:
            data = obj

    # Is this an Office97 file?
    if (not filetype.is_office97_file(data, True)):

        # See if we can pul vbaProject.bin from a 2007+ Office file.
        data = get_vbaprojectbin(data)
        if (data is None):
            return []

    # Set to True to print lots of debugging.
    #debug = True
    debug = False
    if debug:
        print "\nExtracting OLE/ActiveX TextBox strings..."
        
    # Pull out the stream names so we don't treat those as data values.
    stream_names = _get_stream_names(vba_code)
    if debug:
        print "\nStream Names: " + str(stream_names) + "\n"
        
    # Clear out some troublesome byte sequences.
    data = data.replace("R\x00o\x00o\x00t\x00 \x00E\x00n\x00t\x00r\x00y", "")
    data = data.replace("o" + "\x00" * 40, "\x00" * 40)
    data = re.sub("Tahoma\w{0,5}", "\x00", data)

    # Try a method specific to a certain maldoc campaign first.
    r = get_ole_text_method_1(vba_code, data, debug=debug)
    if (r is not None):
        return r
    
    # And try alternate method of pulling data. These will be merged in later.
    v1_vals = get_ole_textbox_values1(data, debug, stream_names)

    # And try another alternate method of pulling data. These will be merged in later.
    v1_1_vals = get_ole_textbox_values2(data, debug, vba_code, stream_names)

    if debug:
        print "\nget_ole_textbox_values()\n"

    # Pull out the names of forms the VBA is accessing. We will use that later to try to
    # guess the names of ActiveX forms parsed from the raw Office file.        
    object_names, page_names = _pull_object_names(vba_code)
    if debug:
        print "\nNames from VBA code:"
        print object_names
            
    # Sanity check.
    if (data is None):
        if debug:
            print "\nNO DATA"
            sys.exit(0)
        return []

    # Make sure some special fields are seperated.
    data = data.replace("c\x00o\x00n\x00t\x00e\x00n\x00t\x00s", "\x00c\x00o\x00n\x00t\x00e\x00n\x00t\x00s\x00")
    data = re.sub("(_(?:\x00\d){10})", "\x00" + r"\1", data)

    # Normalize Page object naming.
    # Page1M3A
    page_name_pat = r"Page(\d+)(?:(?:\-\d+)|[a-zA-Z\.]+[a-zA-Z0-9]*)"
    data = re.sub(page_name_pat, r"Page\1", data)
    
    # Set the general marker for Form data chunks and fields in the Form chunks.
    form_str = "Microsoft Forms 2.0"
    form_str_pat = r"Microsoft Forms 2.0 [A-Za-z]{2,30}(?!Form)"
    field_marker = "Forms."
    if (re.search(form_str_pat, data) is None):
        if debug:
            print "\nNO FORMS"
            sys.exit(0)
        return []

    pat = r"(?:(?:[\x20-\x7e]|\r?\n){3,})|(?:(?:(?:\x00|\xff)(?:[\x20-\x7e]|\r?\n)){3,})"
    index = 0
    r = []
    found_names = set()
    long_strs = []
    end_object_marker = "D\x00o\x00c\x00u\x00m\x00e\x00n\x00t\x00S\x00u\x00m\x00m\x00a\x00r\x00y\x00I\x00n\x00f\x00o\x00r\x00m\x00a\x00t\x00i\x00o\x00n"
    while (re.search(form_str_pat, data[index:]) is not None):

        # Break out the data for an embedded OLE textbox form.

        chunk, index, end = _get_next_chunk(data, index, form_str, form_str_pat, end_object_marker)

        # Pull strings from the chunk.
        strs = re.findall(pat, chunk)
        if debug:
            print "\n\n-------------- CHUNK ---------------"
            print chunk
            print str(strs).replace("\\x00", "").replace("\\xff", "")

        # Save long strings. Maybe they are the value of a previous variable?
        longest_str = ""
        orig_strs = strs
        for field in strs:
            if ((len(field) > 30) and
                (len(field) > len(longest_str)) and
                (not field.startswith("Microsoft "))):
                longest_str = field
        long_strs.append(longest_str)

        # We want to handle Page objects first.
        curr_pos, name_pos, name = _find_name_in_data(page_names, found_names, strs, debug)

        # No Page names?
        if (name is None):

            # Does this look like it might be 1 of the objects referenced in the VBA code?
            curr_pos, name_pos, name = _find_name_in_data(object_names, found_names, strs, debug)

        # Use some heuristics to guess the name if we have not found
        # it yet.
        if (name is None):        
            name_pos, name = _guess_name_from_data(strs, field_marker, debug)
            
        # Move to the next chunk if we cannot find a name.
        if (not is_name(name)):
            index = end
            if debug:
                print "\nNo name found. Moving to next chunk."
            r.append(("no name found", "placeholder"))
            continue

        # Remove sketchy characters from name.
        name = strip_name(name)
        if debug:
            print "\nPossible Name: '" + name + "'"
        
        # Get a text value after the name if it looks like the following field
        # is not a font.
        text = _get_raw_text_for_name(name_pos, strs, chunk, debug)
        if debug:
            print "\nORIG:"
            print name
            print text
            print len(text)

        # Clean up the text value.
        text = _clean_text_for_name(chunk, name, text, object_names, stream_names, longest_str, orig_strs, debug)
                    
        # Save the form name and text value.
        if ((text != "") or (not name.startswith("Page"))):
            if debug:
                print "\nSET '" + name + "' = '" + text + "'"
            r.append((name, text))

        # Save that we found something for this variable.
        if (text != ""):
            found_names.add(name)

        # Move to next chunk.
        index = end

    # The results are approximate. Fix some obvious errors.
    r = _clean_up_ole_form_results(r, long_strs, v1_vals, v1_1_vals, object_names, debug)
                
    # Return the OLE form textbox information.
    if debug:
        print "\nFINAL RESULTS:" 
        print r
        sys.exit(0)
        
    return r

def read_form_strings(vba):
    """Read in the form strings in order as a lists of tuples like
    (stream name, form string).

    @param vba (str) The VBA code to analyze, generated with
    olevba. Note that olevba includes the form strings in the output.

    @return (list) A list of 2 element tuples where the 1st element is
    the name of the stream holding the form and the 2nd element is the
    form text.

    """

    try:
        r = []
        skip_strings = ["Tahoma", "Tahomaz"]
        for (_, stream_path, form_string) in vba.extract_form_strings():

            # Skip default strings.
            if (form_string in skip_strings):
                continue
            # Skip unprintable strings.
            if (not all((ord(c) > 31 and ord(c) < 127) for c in form_string)):
                continue

            # Save the stream name.
            stream_name = stream_path.replace("Macros/", "")
            if ("/" in stream_name):
                stream_name = stream_name[:stream_name.index("/")]

            # Save the stream name and form string.
            r.append((stream_name, form_string))

        # Done.
        return r

    except Exception as e:
        log.error("Cannot read form strings. " + str(e))
        return []
    
def get_shapes_text_values_xml(fname):
    """Read in the text associated with Shape objects in a document saved
    as Flat OPC XML files. NOTE: This currently is a hack.

    @param fname (str) The OPC XML file contents (already read in) or
    the name of the file to analyze. If a file name is given it will
    be read in.

    @return (list) The results as a list of 2 element tuples where the
    1st element is the name (str) of an object and the 2nd element is
    the text value (str) of the object.

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
        except IOError:
            contents = fname
        except TypeError:
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

def get_shapes_text_values_direct_2007(data):
    """Read in shapes name/value mappings directly from word/document.xml
    from an unzipped Word 2007+ file.

    @param data (str) The contents of the document.xml file to
    analyze.

    @return (list) The results as a list of 2 element tuples where the
    1st element is the name (str) of an object and the 2nd element is
    the text value (str) of the object.

    """

    # TODO: This only handles a single Shapes object.
    
    # Get the name of the Shape element.
    pat1 = r'<v:shape\s+id="(\w+)".+<w:txbxContent>'
    name = re.findall(pat1, data)
    if (len(name) == 0):
        return []
    name = name[0]

    # Get the text value(s) for the Shape.
    pat2 = r'<w:t[^<]*>([^<]+)</w:t[^<]*>'
    vals = re.findall(pat2, data)
    if (len(vals) == 0):
        return []

    # Reassemble the values.
    val = ""
    for v in vals:
        val += v
    val = _clean_2007_text(val)
    
    # Return the Shape name and text value.
    r = [(name, val)]
    return r

def get_shapes_text_values_direct_2007_1(data):
    """Read in shapes name/value mappings directly from word/document.xml
    from an unzipped Word 2007+ file another way.

    @param data (str) The contents of the document.xml file to
    analyze.

    @return (list) The results as a list of 2 element tuples where the
    1st element is the name (str) of an object and the 2nd element is
    the text value (str) of the object.

    """

    # TODO: This only handles a single Shapes object.
    
    # Get the shape text from a docPr element.
    # <wp:docPr id="1" name="Picture 1" descr="h95tb8tccpa0:02/d7/15n10ld2xdb68838ao28o10.95c9co0cmf9/3ex4cea1m93cdal39/a5i7db13abd.b8p93h64pdd?53la5=66u61n2dt831e7462.0acfea1dbc7"/>
    pat1 = r'<wp\:docPr +id="(\d+)" +name="[^"]*" +descr="([^"]*)"'
    shape_info = re.findall(pat1, data)
    if (len(shape_info) == 0):
        return []
    shape_info = shape_info[0]
    name = shape_info[0]
    val = _clean_2007_text(shape_info[1])
        
    # Return the Shape name and text value.
    r = [(name, val)]
    return r

def _parse_activex_chunk(data):
    """Parse out ActiveX text values from 2007+ activeXN.bin file
    contents.

    @param data (str) The contents of the activeXN.bin to analyze
    (already read in).

    @return (str) The ActiveX text value if found, None if not found.

    """

    # Pull out the text associated with the object.
    anchor = None
    pad = 0
    if (b"\x1a\x00\x00\x00\x23" in data):
        anchor = b"\x1a\x00\x00\x00\x23"
        pad = 3
    elif (b"\x05\x00\x00\x00\x01\x00\x00\x80" in data):
        anchor = b"\x05\x00\x00\x00\x01\x00\x00\x80"
        pad = 16
    elif (b"\x30\x01\x00\x00" in data):
        anchor = b"\x30\x01\x00\x00"
    if (anchor is None):
        return None
    start = data.rindex(anchor) + len(anchor) + pad
    pat = r"([\x20-\x7e]+)"
    text = re.findall(pat, data[start:])
    if (len(text) == 0):
        return None
    text = text[0]

    # Pull out the size of the text.
    # Try version 1.
    size_pat = r"\x48\x80\x2c\x03\x01\x02\x00(.{2})"
    tmp = re.findall(size_pat, data)
    if (len(tmp) == 0):
        # Try version 2.
        size_pat = r"\x48\x80\x2c(.{2})"
        tmp = re.findall(size_pat, data)
    if (len(tmp) == 0):
        # Try version 3.
        size_pat = r"\x00\x01\x00\x00\x80(.{2})"
        tmp = re.findall(size_pat, data)
    if (len(tmp) > 0):
        size_bytes = tmp[0]
        size = ord(size_bytes[1]) * 256 + ord(size_bytes[0])
        #print "size: " + str(size)
        if (len(text) > size):
            text = text[:size]
        
    # Debug.
    #print "---------"
    #print shape
    #print "^^^^^^^"
    #print data
    #print "^^^^^^^"
    #print text

    return text

def _parse_activex_rich_edit(data):
    """Parse out Rich Edit control text values from 2007+ activeXN.bin
    file contents.

    @param data (str) The contents of the activeXN.bin to analyze
    (already read in).

    @return (str) The ActiveX text value if found, None if not found.

    """

    # No wide char null padding.
    data = data.replace("\x00", "")

    # Pull out the data.
    pat = r"\\fs\d{1,4} (.+)\\par"
    val = re.findall(pat, data)
    if (len(val) == 0):
        return None
    return _clean_2007_text(val[0])

def _get_comments_docprops_2007(unzipped_data):
    """
    Read in the comments in a document saved in the 2007+ format.
    Gets comments from docProps/core.xml.
    """

    # Comments with are in docProps/core.xml. Does that file exist?
    zip_subfile = 'docProps/core.xml'
    if (zip_subfile not in unzipped_data.namelist()):
        zip_subfile = 'docProps\\core.xml'
        if (zip_subfile not in unzipped_data.namelist()):
            return []

    # Read the contents of core.xml.
    f1 = unzipped_data.open(zip_subfile)
    data = f1.read()
    f1.close()

    # Looks like the comments are in the <dc:description>...</dc:description> block.
    comm_pat = r"<dc:description>(.*)</dc:description>"
    comment_blocks = re.findall(comm_pat, data, re.DOTALL)
    if (len(comment_blocks) == 0):
        return []

    # Pack up the comment blocks and give them arbitrary IDs.
    pos = 1
    r = []
    for text in comment_blocks:
        r.append((pos, _clean_2007_text(text)))
        pos += 1

    # Done.
    return r
        
def _get_comments_2007(fname):
    """Read in the comments in a document saved in the 2007+ format.
    Gets comments from word/comments.xml.

    @param fname (str) The name of the Office 2007+ file to analyze.

    @return (list) A list of 2 element tuples where the 1st tuple
    element is the ID of the comment and the 2nd element is the
    comment text.

    """
        
    # This might be a 2007+ Office file. Unzip it.
    unzipped_data, fname = unzip_data(fname)
    delete_file = (fname is not None)
    if (unzipped_data is None):
        return []

    # Comments with are in word/comments.xml. Does that file exist?
    zip_subfile = 'word/comments.xml'
    if (zip_subfile not in unzipped_data.namelist()):
        zip_subfile = 'word\\comments.xml'
        if (zip_subfile not in unzipped_data.namelist()):

            # See if comments are defined in docProps/core.xml.
            r = _get_comments_docprops_2007(unzipped_data)
            unzipped_data.close()
            if (delete_file):
                os.remove(fname)
            return r

    # Read the contents of comments.xml.
    r = []
    f1 = unzipped_data.open(zip_subfile)
    data = f1.read()
    f1.close()

    # Read in all the individual comment XML blocks.

    # Comment blocks begin with '<w:comment' and end with '</w:comment>'.
    comm_pat = r"<w:comment.*</w:comment>"
    comment_blocks = re.findall(comm_pat, data)
    if (len(comment_blocks) == 0):
        unzipped_data.close()
        if (delete_file):
            os.remove(fname)
        return []

    # Process each comment block.
    r = []
    for block in comment_blocks:

        # Pull out the ID for this comment block.
        # <w:comment w:id="1"
        id_pat = r"<w:comment\s+w:id=\"(\d+)\""
        ids = re.findall(id_pat, block)
        if (len(ids) == 0):
            continue
        curr_id = ids[0]

        # Pull out the comment text.
        text_pat = r"<w:t[^>]*>([^<]+)</w:t>"
        texts = re.findall(text_pat, block)
        if (len(texts) == 0):
            continue

        block_text = ""

        for text in texts:
            block_text += _clean_2007_text(text)

        # Save the comment.
        r.append((curr_id, block_text))
        
    # Done.
    unzipped_data.close()
    if (delete_file):
        os.remove(fname)
    #print r
    #sys.exit(0)
    return r

def get_comments(fname):
    """Read the comments from an Office file.

    @param fname (str) The name of the Office file to analyze.

    @return (list) A list of 2 element tuples where the 1st tuple
    element is the ID of the comment and the 2nd element is the
    comment text.

    """

    # Currently only 2007+ Office files are supported.
    if (not filetype.is_office2007_file(fname, (len(fname) > 2000))):
        return []

    # Read comments from 2007+ file.
    return _get_comments_2007(fname)

def get_shapes_text_values_2007(fname):
    """Read in the text associated with Shape objects in a document saved
    in the 2007+ format.

    @param fname (str) The name of the Office 2007+ file to analyze.

    @return (list) The results as a list of 2 element tuples where the
    1st element is the name (str) of an object and the 2nd element is
    the text value (str) of the object.

    """
        
    # This might be a 2007+ Office file. Unzip it.
    unzipped_data, fname = unzip_data(fname)
    delete_file = (fname is not None)
    if (unzipped_data is None):
        return []

    # Shapes with internal IDs are in word/document.xml. Does that file exist?
    zip_subfile = 'word/document.xml'
    if (zip_subfile not in unzipped_data.namelist()):
        zip_subfile = 'word\\document.xml'
        if (zip_subfile not in unzipped_data.namelist()):
            if (delete_file):
                os.remove(fname)
            return []

    # Read the contents of document.xml.
    r = []
    f1 = unzipped_data.open(zip_subfile)
    data = f1.read()
    f1.close()

    # First see if the shapes text is stored directly in document.xml.
    r = get_shapes_text_values_direct_2007(data)
    if (len(r) > 0):
        return r
    r = get_shapes_text_values_direct_2007_1(data)
    if (len(r) > 0):
        #print r
        return r
    
    # Pull out any shape name to internal ID mappings.
    # <w:control r:id="rId10" w:name="ziPOVJ5" w:shapeid="_x0000_i1028"/>
    pat = r'<w\:control[^>]+r\:id="(\w+)"[^>]+w\:name="(\w+)"'
    var_info = re.findall(pat, data)
    id_name_map = {}
    for shape in var_info:
        id_name_map[shape[0]] = shape[1]
    #print id_name_map

    # Get the ID to active X object mapping. This is in word/_rels/document.xml.rels.
    zip_subfile = 'word/_rels/document.xml.rels'
    if (zip_subfile not in unzipped_data.namelist()):
        zip_subfile = 'word\\_rels\\document.xml.rels'
        if (zip_subfile not in unzipped_data.namelist()):
            if (delete_file):
                os.remove(fname)
            return []

    # Read the contents of document.xml.rels.
    r = []
    f1 = unzipped_data.open(zip_subfile)
    data = f1.read()
    #print data
    f1.close()

    # Pull out any shape name to activeX object ID mappings.
    # <Relationship Id="rId10" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/control" Target="activeX/activeX3.xml"/>
    pat = r'<Relationship[^>]+Id="(\w+)"[^>]+Target="([^"]+)"'
    var_info = re.findall(pat, data)
    #print var_info
    id_activex_map = {}
    for shape in var_info:
        if (shape[0] not in id_name_map):
            continue
        id_activex_map[shape[0]] = shape[1].replace(".xml", ".bin")
    #print id_activex_map

    # Read in the activeX objects.
    for shape in id_activex_map:

        # Do we have this object file?
        path = "word/" + id_activex_map[shape]
        if (path not in unzipped_data.namelist()):
            path = "word\\" + id_activex_map[shape].replace("/", "\\")
            if (path not in unzipped_data.namelist()):
                continue

        # Read in the activeX data.
        f1 = unzipped_data.open(path)
        data = f1.read()
        f1.close()

        # Is this a regular ActiveX object?
        text = _parse_activex_chunk(data)

        # Is this a Rich Edit control?
        if (text is None):
            text = _parse_activex_rich_edit(data)
        if (text is None):
            continue
            
        # Save the text associated with the variable name.
        r.append((id_name_map[shape], _clean_2007_text(text)))
    
    # Done.
    unzipped_data.close()
    if (delete_file):
        os.remove(fname)
    #print r
    #sys.exit(0)
    return r

def get_shapes_text_values(fname, stream):
    """Read in the text associated with Shape objects in the
    document. NOTE: This currently is a hack.

    @param fname (str) The name of the Office file to analyze.

    @return (list) The results as a list of 2 element tuples where the
    1st element is the name (str) of an object and the 2nd element is
    the text value (str) of the object.

    """

    # Maybe 2007+ file?
    r = get_shapes_text_values_2007(fname)
    if (len(r) > 0):
        return r
    
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
        #print "STREAM: " + str(stream)
        #print data
        #print "^^^^^^^^^^^"
        #print strs
        
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
        if ("not an OLE2 structured storage file" not in str(e)):
            log.error("Cannot read associated Shapes text. " + str(e))

        # See if we can read Shapes() info from an XML file.
        if ("not an OLE2 structured storage file" in str(e)):
            r = get_shapes_text_values_xml(fname)

    return r


URL_REGEX = r'(http[s]?://(?:(?:[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-\.]+(?::[0-9]+)?)+(?:/[/\?&\~=a-zA-Z0-9_\-\.]+)))'
def pull_urls_from_comments(vba):
    """Pull out URLs that just appear in VBA comments.

    @param vba (VBA_Parser object) The olevba VBA_Parser object for
    reading the Office file being analyzed.

    @return (set) URLs (str) that just appear in VBA comment
    statements.

    """

    # Get the VBA source code.
    macros = ""
    for (_, _, _, vba_code) in vba.extract_macros():
        if (vba_code is None):
            continue
        macros += vba_code + "\n"

    # Pull URLs from each comment line.
    urls = set()
    for line in macros.split("\n"):
        line = line.strip()
        if ((not line.startswith("'")) and (not line.lower().startswith("rem "))):
            continue
        for url in re.findall(URL_REGEX, line):
            urls.add(url.strip())

    # Return the URLs that appear in comments.
    return urls

def pull_urls_office97(fname, is_data, vba):
    """Pull URLs directly from an Office97 file.

    @param fname (str) The name of the file from which to scrape
    URLs or the raw file contents.

    @param is_data (boolean) A flag indicating whether fname is a file
    name (False) or the raw file contents (True).

    @param vba (str) The decompressed VBA macro code.

    @return (set) The URLs scraped from the file. This will be empty
    if there are no URLs.

    """

    # Is this an Office97 file?
    if (not filetype.is_office97_file(fname, is_data)):
        return []
    
    # Read in the Office97 file.
    data = None
    if (not is_data):
        with open(fname, 'rb') as f:
            data = f.read()
    else:
        data = fname

    # Skip URLs that appear in comments.
    comment_urls = set()
    if (vba is not None):
        comment_urls = pull_urls_from_comments(vba)
    file_urls = re.findall(URL_REGEX, data)
    r = set()
    for url in file_urls:
        url = url.strip()
        not_comment_url = True
        for comment_url in comment_urls:
            if ((url.startswith(comment_url)) or (comment_url.startswith(url))):
                not_comment_url = False
                break
        if (not_comment_url):
            r.add(url)
        
    # Return URLs.
    return r

def _read_doc_vars_zip(fname):
    """Read doc vars from an Office 2007+ file.

    @param fname (str) The name of the Office file to analyze.

    @return (list) A list of 2 element tuples where the 1st element is
    the document variable name and the 2nd element is the value.

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
    """Use a heuristic to try to read in document variable names and
    values from the 1Table OLE stream. Note that this heuristic is
    kind of hacky and is not close to being a general solution for
    reading in document variables, but it serves the need for
    ViperMonkey emulation.

    TODO: Replace this when actual support for reading doc vars is
    added to olefile.

    @param fname (str) The name of the Office file to analyze.

    @return (list) A list of 2 element tuples where the 1st element is
    the document variable name and the 2nd element is the value.

    """

    try:

        # Pull out all of the wide character strings from the 1Table OLE data.
        #
        # TODO: Check the FIB to see if we should read from 0Table or 1Table.
        ole = olefile.OleFileIO(fname, write_mode=False)
        var_offset, var_size = _get_doc_var_info(ole)
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
    """Read document variables from Office 97 or 2007+ files.

    @param data (str) The read in Office file data. Can be None if data
    should be read from a file (fname).

    @param fname (str) The name of the Office file to analyze. Can be
    None if data is given (data).

    @return (list) A list of 2 element tuples where the 1st element is
    the document variable name and the 2nd element is the value.

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

def _get_inlineshapes_text_values(data):
    """Read in the text associated with InlineShape objects in the
    document. NOTE: This currently is a hack.

    @param data (str) The read in Office file (data).

    @return (list) The results as a list of 2 element tuples where the
    1st element is the name (str) of an object and the 2nd element is
    the text value (str) of the object.

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
            var = "InlineShapes('" + str(pos) + "').AlternativeText$"
            r.append((var, shape_text))
            
            # Move to next shape.
            pos += 1
            
    except Exception as e:

        # Report the error.
        log.error("Cannot read associated InlineShapes text. " + str(e))

        # See if we can read Shapes() info from an XML file.
        if ("not an OLE2 structured storage file" in str(e)):
            r = get_shapes_text_values_xml(data)

    return r

def _read_custom_doc_props(fname):
    """Use a heuristic to try to read in custom document property names
    and values from the DocumentSummaryInformation OLE stream. Note
    that this heuristic is kind of hacky and is not close to being a
    general solution for reading in document properties, but it serves
    the need for ViperMonkey emulation.

    TODO: Replace this when actual support for reading doc properties
    is added to olefile.

    @param fname (str) The name of the Office file to analyze.

    @return (list) A list of 2 element tuples where the 1st element is
    the document property name and the 2nd element is the value.

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
        if ("not an OLE2 structured storage file" not in str(e)):
            log.error("Cannot read custom doc properties. " + str(e))
        return []

def _get_embedded_object_values(fname):
    """Read in the tag and caption associated with Embedded Objects in
    the document.  NOTE: This currently is a hack.

    @param fname (str) The name of the Office file to analyze.

    @return (list) List of tuples of the form (var name, caption
    value, tag value)

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
            pat =  r"Begin \{[A-Z0-9\-]{36}\} (\w{1,50})\s*(?:\r?\n)\s{1,10}" + \
                   r"Caption\s+\=\s+\"(\w+)\"[\w\s\='\n\r]+Tag\s+\=\s+\"(.+)\"[\w\s\='\n\r]+End"
            obj_text = re.findall(pat, data)

            # Save any information we find.
            for i in obj_text:
                r.append(i)
        
    except Exception as e:
        if ("not an OLE2 structured storage file" not in str(e)):
            log.error("Cannot read tag/caption from embedded objects. " + str(e))

    return r

def _read_doc_text_libreoffice(data):
    """Read in the document text and tables from a Word file (already
    read in) using LibreOffice.

    @param data (str) The read in Office file (data).

    @return (tuple) Returns a tuple containing the doc text and a list
    of tuples containing dumped tables.

    """
    
    # Don't try this if it is not an Office file.
    if (not filetype.is_office_file(data, True)):
        log.warning("The file is not an Office file. Not extracting document text with LibreOffice.")
        return None
    
    # Pick an unused temporary file name.
    out_dir = None
    while True:
        out_dir = "/tmp/tmp_word_file_" + str(random.randrange(0, 10000000000))
        try:
            f = open(out_dir, "r")
            # Already exists.
            f.close()
        except IOError:
            # Does not exist.
            break

    # Save the Word data to the temporary file.
    f = open(out_dir, 'wb')
    f.write(data)
    f.close()
    
    # Dump all the text using soffice.
    output = None
    try:
        output = subprocess.check_output(["timeout", "30", "python3", _thismodule_dir + "/../export_doc_text.py",
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
        output = subprocess.check_output(["python3", _thismodule_dir + "/../export_doc_text.py",
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
    """Use a heuristic to read in the document text. This is used as a
    fallback if reading the text with libreoffice fails.

    @param data (str) The read in Office file (data).

    @return (tuple) A 2 element tuple where the 1st element is the
    strings grabbed from the raw Word file data and the 2nd element is
    an empty list (no table data).

    """

    # Pull strings from doc.
    str_list = re.findall("[^\x00-\x1F\x7F-\xFF]{4,}", data)
    r = []
    for s in str_list:
        r.append(s)
    
    # Return all the doc text strings and an empty list of table data.
    return (r, [])

def _read_doc_text(fname, data=None):
    """Read in text from the given document.

    @param data (str) The read in Office file (data).

    @return (tuple) Returns a tuple containing the doc text and a list
    of tuples containing dumped tables.

    """

    # Read in the file.
    if (data is None):
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

def _get_doc_var_info(ole):
    """Get the byte offset and size of the chunk of data containing the
    document variables. This information is read from the FIB
    (https://msdn.microsoft.com/en-us/library/dd944907(v=office.12).aspx). The
    doc vars appear in the 1Table or 0Table stream.

    @param ole (OLE object) The olevba OLE object for the file being
    analyzed.

    @return (tuple) A 2 element tuple where the 1st element is the
    byte offset os the document variables and the 2nd element is the
    size of the document variable data chunk.

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

def _read_payload_default_target_frame(data, vm):
    """Read and save the custom DefaultTargetFrame value from an Office
    file.

    @param data (str) The read in Office file (data).

    @param vm (ViperMonkey object) The ViperMonkey emulation engine
    object that will do the emulation. The read values will be saved
    in the given emulation engine.

    """

    # Save DefaultTargetFrame value. This only works for 2007+ files.
    def_targ_frame_val = get_defaulttargetframe_text(data)
    if (def_targ_frame_val is not None):
        vm.globals["DefaultTargetFrame"] = def_targ_frame_val
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Added DefaultTargetFrame = " + str(def_targ_frame_val) + " to globals.")
    
def _read_payload_form_strings(vba, vm):
    """Read in and save the text values of OLE forms as given by the
    output of olevba.

    @param vba (str) The VBA code to analyze, generated with
    olevba. Note that olevba includes the form strings in the output.

    @param vm (ViperMonkey object) The ViperMonkey emulation engine
    object that will do the emulation. The read values will be saved
    in the given emulation engine.

    """

    # Save the form strings.

    # First group the form strings for each stream in order.
    tmp_form_strings = read_form_strings(vba)
    stream_form_map = {}
    for string_info in tmp_form_strings:
        stream_name = string_info[0]
        if (stream_name not in stream_form_map):
            stream_form_map[stream_name] = []
        curr_form_string = string_info[1]
        stream_form_map[stream_name].append(curr_form_string)

    # Now add the form strings as a list for each stream to the global
    # variables.
    for stream_name in stream_form_map:
        tmp_name = (stream_name + ".Controls").lower()
        form_strings = stream_form_map[stream_name]
        vm.globals[tmp_name] = form_strings
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Added VBA form Control values %r = %r to globals." % (tmp_name, form_strings))

def _get_form_var_val(var_name, form_vars):
    """Fix the raw value of the text associated with a given OLE form variable.

    @param var_name (str) The name of the form variable whose value is
    to be fixed.

    @param form_vars (dict) A map from form variable names to raw
    values.

    @return (str) The fixed formm variable value. '' will be returned
    if the form variable is not found in form_vars.

    """

    # Get a reasonable value for the form variable.
    r = form_vars[var_name] if (var_name in form_vars and form_vars[var_name] is not None) else ''
    r = r.replace('\xb1', '').replace('\x03', '')
    return r
    
def _read_payload_form_vars(vba, vm):
    """Read and save the text values associated with OLE form variables.

    @param vba (str) The VBA code to analyze, generated with
    olevba. Note that olevba includes the form strings in the output.

    @param vm (ViperMonkey object) The ViperMonkey emulation engine
    object that will do the emulation. The read values will be saved
    in the given emulation engine.

    """

    # Read text from form variables.
    log.info("Reading form variables...")
    try:

        # Pull out form variables.
        for (_, stream_path, form_variables) in vba.extract_form_strings_extended():
            if form_variables is not None:

                # Get the sanitized field values for the current form var.

                # Var name.
                var_name = form_variables['name']
                if (var_name is None):
                    continue

                # Where var is defined.
                macro_name = stream_path
                if ("/" in macro_name):
                    start = macro_name.rindex("/") + 1
                    macro_name = macro_name[start:]

                # Absolute var name.
                global_var_name = (macro_name + "." + var_name).encode('ascii', 'ignore').replace("\x00", "")
                tag = _get_form_var_val('tag', form_variables)

                # Caption for form var.
                caption = _get_form_var_val('caption', form_variables)
                if 'value' in form_variables:
                    val = form_variables['value']
                else:
                    val = caption

                # Control tip text for form var.
                control_tip_text = _get_form_var_val('control_tip_text', form_variables)

                # Group name for form var.
                group_name = _get_form_var_val('group_name', form_variables)
                if (len(group_name) > 10):
                    group_name = group_name[3:]
                
                # Maybe the caption is used for the text when the text is not there?
                if (val is None):
                    val = caption

                # Skip form vars for which we have no interesting text.
                if ((val == '') and (tag == '') and (caption == '')):
                    continue

                # We will not skip variables for which we already have a value.
                # The form variables in this loop are picked out by olevba based
                # on the actual Office file spec, not heuristics, so these values
                # take precedence.

                # Save full form variable names.
                name = global_var_name.lower()                        
                vm.globals[name] = val
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("1. Added VBA form variable %r = %r to globals." % \
                              (global_var_name, val))
                vm.globals[name + ".tag"] = tag
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("1. Added VBA form variable %r = %r to globals." % \
                              (global_var_name + ".Tag", tag))
                vm.globals[name + ".caption"] = caption
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("1. Added VBA form variable %r = %r to globals." % \
                              (global_var_name + ".Caption", caption))
                vm.globals[name + ".controltiptext"] = control_tip_text
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("1. Added VBA form variable %r = %r to globals." % \
                              (global_var_name + ".ControlTipText", control_tip_text))
                vm.globals[name + ".text"] = val
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("1. Added VBA form variable %r = %r to globals." % \
                              (global_var_name + ".Text", val))
                vm.globals[name + ".value"] = val
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("1. Added VBA form variable %r = %r to globals." % \
                              (global_var_name + ".Value", val))
                vm.globals[name + ".groupname"] = group_name
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("1. Added VBA form variable %r = %r to globals." % \
                              (global_var_name + ".GroupName", group_name))

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
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Added index VBA form control data " + control_name + \
                                  "(" + str(len(vm.globals[control_name])) + ") = " + str(control_data))
                    vm.globals[control_name].append(control_data)
                        
                # Save short form variable names.
                short_name = global_var_name.lower()
                if ("." in short_name):
                    short_name = short_name[short_name.rindex(".") + 1:]
                    vm.globals[short_name] = val
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("1. Added VBA form variable %r = %r to globals." % \
                                  (short_name, val))
                    vm.globals[short_name + ".tag"] = tag
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("1. Added VBA form variable %r = %r to globals." % \
                                  (short_name + ".Tag", tag))
                    vm.globals[short_name + ".caption"] = caption
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("1. Added VBA form variable %r = %r to globals." % \
                                  (short_name + ".Caption", caption))
                    vm.globals[short_name + ".controltiptext"] = control_tip_text
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("1. Added VBA form variable %r = %r to globals." % \
                                  (short_name + ".ControlTipText", control_tip_text))
                    vm.globals[short_name + ".text"] = val
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("1. Added VBA form variable %r = %r to globals." % \
                                  (short_name + ".Text", val))
                        vm.globals[short_name + ".groupname"] = group_name
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("1. Added VBA form variable %r = %r to globals." % \
                                  (short_name + ".GroupName", group_name))
                
    except Exception as e:

        # We are not getting variable names this way. Assign wildcarded names that we can use
        # later to try to heuristically guess form variables.
        log.warning("Cannot read form strings. " + str(e) + ". Trying fallback method.")
        #traceback.print_exc()
        #sys.exit(0)
        try:
            count = 0
            skip_strings = ["Tahoma", "Tahomaz"]
            for (_, stream_path, form_string) in vba.extract_form_strings():
                # Skip strings that are large and almost all the same character.
                if ((len(form_string) > 100) and (entropy(form_string) < 1)):
                    continue
                # Skip default strings.
                if (form_string.startswith("\x80")):
                    form_string = form_string[1:]
                if (form_string in skip_strings):
                    continue
                # Skip unprintable strings. Accept < 10% bad chars.
                bad_char_count = 0
                for c in form_string:
                    if (not (ord(c) > 31 and ord(c) < 127)):
                        bad_char_count += 1
                if (((bad_char_count + 0.0) / len(form_string)) > .1):
                    continue

                # String looks good. Keep it.
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
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("2. Added VBA form variable %r = %r to globals." % (global_var_name.lower(), form_string))
                tmp_name = global_var_name_orig.lower() + ".*"
                #if ((tmp_name not in vm.globals.keys()) or
                #    (len(form_string) > len(vm.globals[tmp_name]))):
                if (tmp_name not in vm.globals.keys()):
                    vm.globals[tmp_name] = form_string
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("2. Added VBA form variable %r = %r to globals." % (tmp_name, form_string))
                    # Probably not right, but needed to handle some maldocs that break olefile.
                    # 16555c7d12dfa6d1d001927c80e24659d683a29cb3cad243c9813536c2f8925e
                    # 99f4991450003a2bb92aaf5d1af187ec34d57085d8af7061c032e2455f0b3cd3
                    # 17005731c750286cae8fa61ce89afd3368ee18ea204afd08a7eb978fd039af68
                    # a0c45d3d8c147427aea94dd15eac69c1e2689735a9fbd316a6a639c07facfbdf
                    specific_names = ["textbox1", "label1"]
                    for specific_name in specific_names:
                        tmp_name = specific_name
                        vm.globals[tmp_name] = form_string
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug("2. Added VBA form variable %r = %r to globals." % (tmp_name, form_string))
                        tmp_name = specific_name + ".caption"
                        vm.globals[tmp_name] = form_string
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug("2. Added VBA form variable %r = %r to globals." % (tmp_name, form_string))
                        tmp_name = global_var_name_orig.lower() + "." + specific_name + ".caption"
                        vm.globals[tmp_name] = form_string
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug("2. Added VBA form variable %r = %r to globals." % (tmp_name, form_string))
                        tmp_name = specific_name + ".text"
                        vm.globals[tmp_name] = form_string
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug("2. Added VBA form variable %r = %r to globals." % (tmp_name, form_string))
                        tmp_name = global_var_name_orig.lower() + "." + specific_name + ".text"
                        vm.globals[tmp_name] = form_string
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug("2. Added VBA form variable %r = %r to globals." % (tmp_name, form_string))
        except Exception as e:
            log.error("Cannot read form strings. " + str(e) + ". Fallback method failed.")

    
def _read_payload_embedded_obj_text(data, vm):
    """Read in and save the tag and caption associated with Embedded OLE
    Objects in an Office document.

    @param data (str) The read in Office file (data).

    @param vm (ViperMonkey object) The ViperMonkey emulation engine
    object that will do the emulation. The read values will be saved
    in the given emulation engine.

    """

    # Pull text associated with embedded objects.
    log.info("Reading embedded object text fields...")
    for (var_name, caption_val, tag_val) in _get_embedded_object_values(data):
        tag_name = var_name.lower() + ".tag"
        vm.doc_vars[tag_name] = tag_val
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Added potential VBA object tag text %r = %r to doc_vars." % \
                      (tag_name, tag_val))
        caption_name = var_name.lower() + ".caption"
        vm.doc_vars[caption_name] = caption_val
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Added potential VBA object caption text %r = %r to doc_vars." % \
                      (caption_name, caption_val))    

def _read_payload_custom_doc_props(data, vm):
    """Read in and save custom document property names and values from
    the DocumentSummaryInformation OLE stream.

    @param data (str) The read in Office file (data).

    @param vm (ViperMonkey object) The ViperMonkey emulation engine
    object that will do the emulation. The read values will be saved
    in the given emulation engine.

    """

    # Pull out custom document properties.
    log.info("Reading custom document properties...")
    for (var_name, var_val) in _read_custom_doc_props(data):
        vm.doc_vars[var_name.lower()] = var_val
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Added potential VBA custom doc prop variable %r = %r to doc_vars." % (var_name, var_val))
    
def _read_payload_textbox_text(data, vba_code, vm):
    """Read in and save text hidden in TextBox and RichText objects.

    @param data (str) The read in Office file (data).

    @param vba_code (str) The VBA macro code from the Office file.

    @param vm (ViperMonkey object) The ViperMonkey emulation engine
    object that will do the emulation. The read values will be saved
    in the given emulation engine.

    """

    # Pull out embedded OLE form textbox text.
    log.info("Reading TextBox and RichEdit object text fields...")
    object_data = get_ole_textbox_values(data, vba_code)
    tmp_data = get_msftedit_variables(data)
    object_data.extend(tmp_data)
    tmp_data = get_customxml_text(data)
    object_data.extend(tmp_data)
    tmp_data = get_drawing_titles(data)
    object_data.extend(tmp_data)
    for (var_name, var_val) in object_data:
        var_name_variants = [var_name,
                             "ActiveDocument." + var_name,
                             var_name + ".Tag",
                             var_name + ".Text",
                             var_name + ".AlternativeText",
                             var_name + ".Title",
                             var_name + ".Value",
                             var_name + ".Caption",
                             var_name + ".Content",
                             var_name + ".ControlTipText",
                             "me." + var_name,
                             "me." + var_name + ".Tag",
                             "me." + var_name + ".Text",
                             "me." + var_name + ".AlternativeText",
                             "me." + var_name + ".Title",
                             "me." + var_name + ".Value",
                             "me." + var_name + ".Caption",
                             "me." + var_name + ".Content",
                             "me." + var_name + ".ControlTipText"]
        for tmp_var_name in var_name_variants:

            # Skip big values that are basically just repeats of the
            # same character.
            if ((isinstance(var_val, str)) and
                (len(var_val) > 1000)):
                num_1st = float(var_val.count(var_val[0]))
                pct = num_1st/len(var_val) * 100
                if (pct > 95):
                    log.warning("Not assigning " + tmp_var_name + " value '" + var_val[:15] + "...'. " +\
                                "Too many repeated characters.")
                    continue

            # Save the value as a global variable.
            tmp_var_val = var_val
            if ((tmp_var_name == 'ActiveDocument.Sections') or
                (tmp_var_name == 'Sections')):
                tmp_var_val = [var_val, var_val]
            if ((tmp_var_name.lower() in vm.doc_vars) and
                (len(str(vm.doc_vars[tmp_var_name.lower()])) > len(str(tmp_var_val)))):
                continue
            vm.doc_vars[tmp_var_name.lower()] = tmp_var_val
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Added potential VBA OLE form textbox text (1) %r = %r to doc_vars." % (tmp_var_name, tmp_var_val))

        # Handle Pages(NN) and Tabs(NN) references.
        page_pat = r"Page(\d+)"
        if (re.match(page_pat, var_name)):
            page_index = str(int(re.findall(page_pat, var_name)[0]) - 1)
            page_var_name = "Pages('" + page_index + "')"
            tab_var_name = "Tabs('" + page_index + "')"
            var_name_variants = [page_var_name,
                                 "ActiveDocument." + page_var_name,
                                 page_var_name + ".Tag",
                                 page_var_name + ".Text",
                                 page_var_name + ".Caption",
                                 page_var_name + ".ControlTipText",
                                 "me." + page_var_name,
                                 "me." + page_var_name + ".Tag",
                                 "me." + page_var_name + ".Text",
                                 "me." + page_var_name + ".Caption",
                                 "me." + page_var_name + ".ControlTipText",
                                 tab_var_name,
                                 "ActiveDocument." + tab_var_name,
                                 tab_var_name + ".Tag",
                                 tab_var_name + ".Text",
                                 tab_var_name + ".Caption",
                                 tab_var_name + ".ControlTipText",
                                 "me." + tab_var_name,
                                 "me." + tab_var_name + ".Tag",
                                 "me." + tab_var_name + ".Text",
                                 "me." + tab_var_name + ".Caption",
                                 "me." + tab_var_name + ".ControlTipText"]

            # Handle InlineShapes.                    
            if (not got_inline_shapes):
                # InlineShapes().Item(1).AlternativeText
                var_name_variants.extend(["InlineShapes('" + page_index + "').TextFrame.TextRange.Text",
                                          "InlineShapes('" + page_index + "').TextFrame.ContainingRange",
                                          "InlineShapes('" + page_index + "').AlternativeText",
                                          "InlineShapes('" + page_index + "').AlternativeText$",
                                          "InlineShapes.Item('" + page_index + "').TextFrame.TextRange.Text",
                                          "InlineShapes.Item('" + page_index + "').TextFrame.ContainingRange",
                                          "InlineShapes.Item('" + page_index + "').AlternativeText",
                                          "InlineShapes.Item('" + page_index + "').AlternativeText$",
                                          "StoryRanges.Item('" + page_index + "')",
                                          "me.StoryRanges.Item('" + page_index + "')"])
            for tmp_var_name in var_name_variants:
                vm.doc_vars[tmp_var_name.lower()] = var_val
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Added potential VBA OLE form textbox text (2) %r = %r to doc_vars." % (tmp_var_name, var_val))

                    
got_inline_shapes = False                    
def _read_payload_inline_shape_text(data, vm):
    """Read in and save the text associated with InlineShape objects in
    the document.

    @param data (str) The read in Office file (data).

    @param vm (ViperMonkey object) The ViperMonkey emulation engine
    object that will do the emulation. The read values will be saved
    in the given emulation engine.

    """

    # Pull text associated with InlineShapes() objects.
    log.info("Reading InlineShapes object text fields...")
    global got_inline_shapes
    got_inline_shapes = False
    for (var_name, var_val) in _get_inlineshapes_text_values(data):
        got_inline_shapes = True
        vm.doc_vars[var_name.lower()] = var_val
        log.info("Added potential VBA InlineShape text %r = %r to doc_vars." % (var_name, var_val))
    
def _read_payload_shape_text(data, vm):
    """Read in and save the text associated with Shape objects in a
    document saved as Flat OPC XML files.

    @param data (str) The read in Office file (data).

    @param vm (ViperMonkey object) The ViperMonkey emulation engine
    object that will do the emulation. The read values will be saved
    in the given emulation engine.

    """

    # Pull text associated with Shapes() objects.
    log.info("Reading Shapes object text fields...")
    got_it = False
    shape_text = get_shapes_text_values(data, 'worddocument')
    pos = 1
    for (var_name, var_val) in shape_text:
        got_it = True
        var_name = var_name.lower()
        vm.doc_vars[var_name] = var_val
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Added potential VBA Shape text %r = %r to doc_vars." % (var_name, var_val))
        vm.doc_vars["thisdocument."+var_name] = var_val
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Added potential VBA Shape text %r = %r to doc_vars." % ("thisdocument."+var_name, var_val))
        vm.doc_vars["thisdocument."+var_name+".caption"] = var_val
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Added potential VBA Shape text %r = %r to doc_vars." % ("thisdocument."+var_name+".caption", var_val))
        vm.doc_vars["activedocument."+var_name] = var_val
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Added potential VBA Shape text %r = %r to doc_vars." % ("activedocument."+var_name, var_val))
        vm.doc_vars["activedocument."+var_name+".caption"] = var_val
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Added potential VBA Shape text %r = %r to doc_vars." % ("activedocument."+var_name+".caption", var_val))
        tmp_name = "shapes('" + var_name + "').textframe.textrange.text"
        vm.doc_vars[tmp_name] = var_val
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Added potential VBA Shape text %r = %r to doc_vars." % (tmp_name, var_val))
        tmp_name = "shapes('" + str(pos) + "').textframe.textrange.text"
        vm.doc_vars[tmp_name] = var_val
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Added potential VBA Shape text %r = %r to doc_vars." % (tmp_name, var_val))
        tmp_name = "me.storyranges('" + str(pos) + "')"
        vm.doc_vars[tmp_name] = var_val
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Added potential VBA StoryRange text %r = %r to doc_vars." % (tmp_name, var_val))
        # activedocument.shapes('1').alternativetext
        tmp_name = "ActiveDocument.shapes('" + str(pos) + "').AlternativeText"
        vm.doc_vars[tmp_name] = var_val
        vm.doc_vars[tmp_name.lower()] = var_val
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Added potential VBA Shape text %r = %r to doc_vars." % (tmp_name, var_val))
        pos += 1
    if (not got_it):
        shape_text = get_shapes_text_values(data, '1table')
        for (var_name, var_val) in shape_text:
            vm.doc_vars[var_name.lower()] = var_val
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Added potential VBA Shape text %r = %r to doc_vars." % (var_name, var_val))
    
def _read_payload_doc_comments(data, vm):
    """Read in and save the comments in an Office document.

    @param data (str) The read in Office file (data).

    @param vm (ViperMonkey object) The ViperMonkey emulation engine
    object that will do the emulation. The read values will be saved
    in the given emulation engine.

    """

    # Pull text associated with document comments.
    log.info("Reading document comments...")
    comments = get_comments(data)
    if (len(comments) > 0):
        vm.comments = []
        for (_, comment_text) in comments:
            # TODO: Order the comments based on the IDs or actually track them.
            vm.comments.append(comment_text)

def _read_payload_doc_vars(data, orig_filename, vm):
    """Read and save document variables from Office 97 or 2007+ files.

    @param data (str) The read in Office file data. Can be None if data
    should be read from a file (orig_fname).

    @param orig_fname (str) The name of the Office file to analyze. Can be
    None if data is given (data).

    @param vm (ViperMonkey object) The ViperMonkey emulation engine
    object that will do the emulation. The read values will be saved
    in the given emulation engine.

    """

    # Pull out document variables.
    log.info("Reading document variables...")
    for (var_name, var_val) in _read_doc_vars(data, orig_filename):
        vm.doc_vars[var_name] = var_val
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Added potential VBA doc variable %r = %r to doc_vars." % (var_name, var_val))
        vm.doc_vars[var_name.lower()] = var_val
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Added potential VBA doc variable %r = %r to doc_vars." % (var_name.lower(), var_val))


def read_payload_hiding_places(data, orig_filename, vm, vba_code, vba):
    """
    Read in text values from all of the various places in Office
    97/2000+ that text values can be hidden. This reads values from
    things like ActiveX captions, embedded image alternate text,
    document variables, form variables, etc.

    @param (data) The contents (bytes) of the Office file being
    analyzed.

    @param orig_filename (str) The name of the Office file being
    analyzed.

    @param vm (ViperMonkey object) The ViperMonkey emulation engine
    object that will do the emulation. The read values will be saved
    in the given emulation engine.

    @param vba_code (str) The VB code that will be emulated.

    @param vba (VBA_Parser object) The olevba VBA_Parser object for
    reading the Office file being analyzed.
    """

    # Pull out document variables.
    _read_payload_doc_vars(data, orig_filename, vm)

    # Pull text associated with document comments.
    _read_payload_doc_comments(data, vm)
                
    # Pull text associated with Shapes() objects.
    _read_payload_shape_text(data, vm)

    # Pull text associated with InlineShapes() objects.
    _read_payload_inline_shape_text(data, vm)
                    
    # Pull out embedded OLE form textbox text.
    _read_payload_textbox_text(data, vba_code, vm)
                            
    # Pull out custom document properties.
    _read_payload_custom_doc_props(data, vm)

    # Pull text associated with embedded objects.
    _read_payload_embedded_obj_text(data, vm)
                
    # Pull out the document text.
    log.info("Reading document text and tables...")
    vm.doc_text, vm.doc_tables = _read_doc_text('', data=data)

    # Read text from form variables.
    _read_payload_form_vars(vba, vm)

    # Save the form strings.
    #sys.exit(0)
    _read_payload_form_strings(vba, vm)

    # Save DefaultTargetFrame value. This only works for 2007+ files.
    _read_payload_default_target_frame(data, vm)

    
###########################################################################
## Main Program
###########################################################################
if __name__ == '__main__':
    print get_shapes_text_values(sys.argv[1], "worddocument")
    print get_shapes_text_values(sys.argv[1], '1table')
