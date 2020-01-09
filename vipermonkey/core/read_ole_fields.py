"""
read_ole_fields.py - Read in data values from OLE items like shapes and text boxes.

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

import zipfile
import re
import random
import os
import sys
from collections import Counter

import olefile

from logger import log
import filetype

def pull_base64(data):
    """
    Pull base64 strings from some data.
    """

    # Pull out strings that might be base64.
    base64_pat_loose = r"[A-Za-z0-9+/=]{40,}"
    r = set(re.findall(base64_pat_loose, data))
    return r

def unzip_data(data):
    """
    Unzip zipped data in memory.
    """

    # Unzip the data.
    # PKZip magic #: 50 4B 03 04
    zip_magic = chr(0x50) + chr(0x4B) + chr(0x03) + chr(0x04)
    contents = None
    delete_file = False
    fname = None
    if data.startswith(zip_magic):
        #raise ValueError("_get_shapes_text_values_2007() currently does not support in-memory Office files.")
        # TODO: Fix this. For now just save to a tmp file.
        tmp_name = "/tmp/" + str(random.randrange(0, 10000000000)) + ".office"
        f = open(tmp_name, 'wb')
        f.write(data)
        f.close()
        fname = tmp_name
        delete_file = True
    else:
        return (None, None)
        
    # Is this a ZIP file?
    try:
        if (not zipfile.is_zipfile(fname)):
            if (delete_file):
                os.remove(fname)
            return (None, None)
    except:
        if (delete_file):
            os.remove(fname)
        return (None, None)
        
    # This is a ZIP file. Unzip it.
    unzipped_data = zipfile.ZipFile(fname, 'r')

    # Return the unzipped data and temp file name.
    return (unzipped_data, fname)
    
def get_msftedit_variables_97(data):
    """
    Looks for variable/text value pairs stored in an embedded rich edit control from an Office 97 doc.
    See https://docs.microsoft.com/en-us/windows/win32/controls/about-rich-edit-controls.
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
    """
    Looks for variable/text value pairs stored in an embedded rich edit control from an Office 97 or 2007+ doc.
    See https://docs.microsoft.com/en-us/windows/win32/controls/about-rich-edit-controls.
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
        except:
            data = obj

    # Is this an Office 97 file?
    if (filetype.is_office97_file(data, True)):
        return get_msftedit_variables_97(data)

    # This is an Office 2007+ file.
    return []

def remove_duplicates(lst):
    """
    Remove duplicate subsequences from a list.
    
    Taken from https://stackoverflow.com/questions/49833528/python-identifying-and-deleting-duplicate-sequences-in-list/49835215
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
    Compute the entropy of a string.
    Taken from https://rosettacode.org/wiki/Entropy#Uses_Python_2
    """
    import math
    log2=lambda x:math.log(x)/math.log(2)
    exr={}
    infoc=0
    for each in text:
        try:
            exr[each]+=1
        except:
            exr[each]=1
    textlen=len(text)
    for k,v in exr.items():
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
              r'VERSION [\d\.]+\r\nBegin {[\w\-]+} \w+ \r\n\s+Caption\s+=\s+"UserForm1"\r\n\s+ClientHeight\s+=\s+\d+\r\n\s+ClientLeft\s+=\s+\d+\r\n\s+ClientTop\s+=\s+\d+\r\n\s+ClientWidth\s+=\s+\d+\r\n\s+StartUpPosition\s+=\s+\d+\s+\'CenterOwner\r\n\s+TypeInfoVer\s+=\s+\d+\r\nEnd\r\n',
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
    
def get_ole_textbox_values2(data, debug, vba_code):
    """
    Read in the text associated with embedded OLE form textbox objects.
    NOTE: This currently is a really NASTY hack.
    """

    # Pull out the object text value references from the VBA code.
    object_names = set(re.findall(r"(?:ThisDocument|ActiveDocument|\w+)\.(\w+(?:\.ControlTipText)?)", vba_code))
    if debug:
        print "\nget_ole_textbox_values2()"
        print "\nNames from VBA code:"
        print object_names
    
    # Break out the variables from which we want control tip text and non-control tip text variables.
    control_tip_var_names = set()
    other_var_names = set()
    for name in object_names:

        # Getting control tip text for this object?
        if (name.endswith(".ControlTipText")):
            fields = name.split(".")[:-1]
            short_name = fields[-1]
            control_tip_var_names.add(short_name)

        # Not getting control tip text.
        else:
            fields = name.split(".")
            short_name = fields[-1]
            other_var_names.add(short_name)

    # Read in the large chunk of data with the object names and string values.
    chunk_pat = r'\xd7\x8c\xfe\xfb(.*)(?:(?:Microsoft Forms 2.0 Form)|(?:ID="{))'
    chunk = re.findall(chunk_pat, data, re.DOTALL)

    # Did we find the value chunk?
    if (len(chunk) == 0):

        # Try a different chunk start marker.
        chunk_pat = r'\x00V\x00B\x00F\x00r\x00a\x00m\x00e\x00(.*)(?:(?:Microsoft Forms 2.0 (?:Form|Frame))|(?:ID="{))'
        chunk = re.findall(chunk_pat, data, re.DOTALL)

        # Did we find the value chunk?
        if (len(chunk) == 0):
            if debug:
                print "NO VALUES"
            return []
    chunk = chunk[0]

    # Strip some red herring strings from the chunk.
    chunk = chunk.replace("\x02$", "").replace("\x01@", "")
    chunk = re.sub(r'[\x20-\x7f]{5,}(?:\x00[\x20-\x7f]){5,}', "", chunk)
    
    if debug:
        print "\nChunk:"
        print chunk
    
    # Pull out the strings from the value chunk.
    ascii_pat = r"(?:(?:[\x20-\x7f]|\x0d\x0a){4,})|(?:(?:[\x20-\x7f]\x00){4,})"
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

        # Save modified string.
        tmp_vals.append(val)

    # Work with the modified list of strings.
    vals = tmp_vals

    # Looks like control tip text goes right after var names in the string
    # list.
    r = []
    updated_vals = []
    skip = set()
    if debug:
        print "CONTROL TIP PROCESSING:"
    for name in control_tip_var_names:
        pos = -1
        for str_val in vals:
            pos += 1
            if ((str_val.startswith(name)) and ((pos + 1) < len(vals))):

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
                
                # We've handled with name and value, so skip them.
                skip.add(pos)
                skip.add(pos + 1)

    # Now use detailed regexes to pull out the var names and values.

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

    # Get values.
    val_pat = r"(?:\x02\x00\x00([\x20-\x7f]{2,}))|((?:(?:\x00)[\x20-\x7f]){2,})"
    vals = re.findall(val_pat, chunk)

    tmp_vals = []
    rev_vals = list(vals)
    rev_vals.reverse()
    seen = set()
    for val in rev_vals:

        if (len(val[0]) > 0):
            val = val[0]
        else:
            val = val[1]
            
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

        # Skip duplicates.
        if (val in seen):
            continue
        seen.add(val)
        
        # Save modified string.
        tmp_vals.append(val)

    # Work with the modified list of values.
    tmp_vals.reverse()
    #var_vals = tmp_vals[1:]
    var_vals = tmp_vals

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
            
    # Get rid of control tip text names, we have already handled those.
    tmp_names = []
    for name in names:
        if (len(name[0]) > 0):
            name = name[0]
        else:
            name = name[1]
        if (name in control_tip_var_names):
            continue
        tmp_names.append(name)
    var_names = tmp_names

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
    for name in var_names:
        pos += 1
        val = var_vals[pos]
        if (val.endswith('o')):
            val = val[:-1]
        elif (val.endswith("oe")):
            val = val[:-2]
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

def get_ole_textbox_values1(data, debug):
    """
    Read in the text associated with embedded OLE form textbox objects.
    NOTE: This currently is a really NASTY hack.
    """

    # This handles some form of ActiveX object embedding where the list of object names
    # appears in a different file location than the text values associated with the
    # object names.

    # Find the object text values.
    if debug:
        print "Looking for other form of ActiveX embedding..."

    # Pull out the chunk of data with the object values.
    chunk_pat = r'DPB=".*"\x0d\x0aGC=".*"\x0d\x0a(.*;Word8.0;&H00000000)'
    chunk = re.findall(chunk_pat, data, re.DOTALL)

    # Did we find the value chunk?
    if (len(chunk) == 0):
        if debug:
            print "NO VALUES"
        return []
    chunk = chunk[0]

    # Clear out some cruft that appears in the value chunk.
    ignore_pat = r"\[Host Extender Info\]\x0d\x0a&H\d+={[A-Z0-9\-]+};VBE;&H\d+\x0d\x0a&H\d+={[A-Z0-9\-]+}?"
    chunk = re.sub(ignore_pat, "", chunk)
    if ("\x00\x01\x01\x40\x80\x00\x00\x00\x00\x1b\x48\x80" in chunk):
        start = chunk.index("\x00\x01\x01\x40\x80\x00\x00\x00\x00\x1b\x48\x80")
        chunk = chunk[start+1:]

    # Pull out the strings from the value chunk.
    ascii_pat = r"(?:[\x20-\x7f]|\x0d\x0a){5,}"
    vals = re.findall(ascii_pat, chunk)
    vals = vals[:-1]
    tmp_vals = []
    for val in vals:

        # Skip fonts.
        if (val.startswith("Taho")):
            continue
        tmp_vals.append(val)
    vals = tmp_vals
    if debug:
        print "---------------"
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
            print "NO NAMES"
        return []
    chunk_orig = chunk[0]

    # Can we narrow it down?
    if ("C\x00o\x00m\x00p\x00O\x00b\x00j" not in chunk_orig):
        if debug:
            print "NO NARROWED DOWN CHUNK"
        return []
    
    # Narrow the name chunk down.
    start = chunk_orig.index("C\x00o\x00m\x00p\x00O\x00b\x00j")
    chunk = chunk_orig[start + len("C\x00o\x00m\x00p\x00O\x00b\x00j"):]
    if debug:
        print "---------------"
        print "Names:"
        print chunk

    # Pull the names from the name chunk (ASCII strings).
    names = re.findall(ascii_pat, chunk)
    if (len(names) > 0):
        names = names[:-1]
    if (len(names) == 0):
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
            print "NOT SAME # NAMES/VALS"
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

def get_ole_textbox_values(obj, vba_code):
    """
    Read in the text associated with embedded OLE form textbox objects.
    NOTE: This currently is a NASTY hack.
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
        except:
            data = obj

    # Is this an Office97 file?
    if (not filetype.is_office97_file(data, True)):
        return []

    # Set to True to print lots of debugging.
    #debug = True
    debug = False
    if debug:
        print "Extracting OLE/ActiveX TextBox strings..."

    # First try alternate method of pulling data. These will be merged in later.
    v1_vals = get_ole_textbox_values1(obj, debug)

    # And try another alternate method of pulling data. These will be merged in later.
    v1_1_vals = get_ole_textbox_values2(data, debug, vba_code)
        
    # Pull out the names of forms the VBA is accessing. We will use that later to try to
    # guess the names of ActiveX forms parsed from the raw Office file.
    object_names = set(re.findall(r"(?:ThisDocument|ActiveDocument|\w+)\.(\w+)", vba_code))
    if debug:
        print "Names from VBA code:"
        print object_names
            
    # Sanity check.
    if (data is None):
        if debug:
            print "NO DATA"
            sys.exit(0)
        return []

    # Make sure some special fields are seperated.
    data = data.replace("c\x00o\x00n\x00t\x00e\x00n\x00t\x00s", "\x00c\x00o\x00n\x00t\x00e\x00n\x00t\x00s\x00")
    data = re.sub("(_(?:\x00\d){10})", "\x00" + r"\1", data)
    
    # Set the general marker for Form data chunks and fields in the Form chunks.
    form_str = "Microsoft Forms 2.0"
    form_str_pat = r"Microsoft Forms 2.0 [A-Za-z]{2,30}(?!Form)"
    field_marker = "Forms."
    if (re.search(form_str_pat, data) is None):
        if debug:
            print "NO FORMS"
            sys.exit(0)
        return []

    pat = r"(?:[\x20-\x7e]{3,})|(?:(?:(?:\x00|\xff)[\x20-\x7e]){3,})"
    index = 0
    r = []
    found_names = set()
    long_strs = []
    end_object_marker = "D\x00o\x00c\x00u\x00m\x00e\x00n\x00t\x00S\x00u\x00m\x00m\x00a\x00r\x00y\x00I\x00n\x00f\x00o\x00r\x00m\x00a\x00t\x00i\x00o\x00n"
    while (re.search(form_str_pat, data[index:]) is not None):

        # Break out the data for an embedded OLE textbox form.

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
            end = index + 25000
            if (end > len(data)):
                end = len(data) - 1

        # Pull out the current form data chunk.
        chunk = data[index : end]
        strs = re.findall(pat, chunk)
        if debug:
            print "\n\n-----------------------------"
            print chunk
            print str(strs).replace("\\x00", "").replace("\\xff", "")

        # Easy case first. Does this look like it might be 1 of the objects
        # referenced in the VBA code?
        curr_pos = 0
        name_pos = 0
        name = None
        for field in strs:
            poss_name = field.replace("\x00", "").replace("\xff", "").strip()
            if ((poss_name in object_names) and (poss_name not in found_names)):

                # Looks like this is one of the objects we are looking for.
                name = poss_name
                found_names.add(name)
                name_pos = curr_pos
                if debug:
                    print "Found referenced name: " + name
                break
            curr_pos += 1

        # Did we find the name?
        if (name is None):
            
            # Pull out the variable name (and maybe part of the text).
            curr_pos = 0
            for field in strs:
    
                # It might come after the 'Forms.TextBox.1' tag.
                if (field.startswith(field_marker)):
    
                    # If the next field does not look something like '_1619423091' the
                    # next field is the name. CompObj does not count either.
                    poss_name = None
                    if ((curr_pos + 1) < len(strs)):
                        poss_name = strs[curr_pos + 1].replace("\x00", "").replace("\xff", "").strip()
                    if ((poss_name is not None) and
                        ((not poss_name.startswith("_")) or
                         (not poss_name[1:].isdigit())) and
                        (poss_name != "CompObj") and
                        (poss_name != "ObjInfo") and
                        (poss_name != "contents")):
    
                        # We have found the name.
                        name = poss_name
                        found_names.add(name)
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
                print "Name Marker: " + name_marker
            for field in strs:

                # It might come after the name marker tag.
                if debug:
                    print "Field: '" + field.replace("\x00", "") + "'"
                if (field.replace("\x00", "") == name_marker):

                    # If the next field does not look something like '_1619423091' the
                    # next field might be the name.
                    poss_name = strs[curr_pos + 1].replace("\x00", "")
                    if debug:
                        print "Try: '" + poss_name + "'"
                    if ((not poss_name.startswith("_")) or
                        (not poss_name[1:].isdigit())):

                        # If the string after 'OCXNAME' is 'contents' the actual name comes
                        # after 'contents'
                        name_pos = curr_pos + 1
                        if (poss_name == 'contents'):
                            poss_name = strs[curr_pos + 2].replace("\x00", "")
                            if debug:
                                print "Try: '" + poss_name + "'"
                            
                            # Does the next field does not look something like '_1619423091'?
                            if ((not poss_name.startswith("_")) or
                                (not poss_name[1:].isdigit())):

                                # We have found the name.
                                name = poss_name
                                found_names.add(name)
                                name_pos = curr_pos + 2
                                break

                            # Try the next field.
                            else:
                                if ((curr_pos + 3) < len(strs)):                                    
                                    poss_name = strs[curr_pos + 3].replace("\x00", "")
                                    if debug:
                                        print "Try: '" + poss_name + "'"

                                    # CompObj is not an object name.
                                    if (poss_name != "CompObj"):
                                        name = poss_name
                                        found_names.add(name)
                                        name_pos = curr_pos + 3
                                        break

                                    # And try the next field.
                                    else:

                                        if ((curr_pos + 4) < len(strs)):
                                            poss_name = strs[curr_pos + 4].replace("\x00", "")
                                            if debug:
                                                print "Try: '" + poss_name + "'"

                                            # ObjInfo is not an object name.
                                            if (poss_name != "ObjInfo"):
                                                name = poss_name
                                                found_names.add(name)
                                                name_pos = curr_pos + 4
                                                break

                                            # Heaven help us all. Try the next one.
                                            if ((curr_pos + 5) < len(strs)):
                                                poss_name = strs[curr_pos + 5].replace("\x00", "")
                                                if debug:
                                                    print "Try: '" + poss_name + "'"

                                                # ObjInfo is not an object name.
                                                if (poss_name != "ObjInfo"):
                                                    name = poss_name
                                                    found_names.add(name)
                                                    name_pos = curr_pos + 5
                                                    break

                        else:

                            # We have found the name.
                            name = poss_name
                            found_names.add(name)
                            break

                # Move to the next field.
                curr_pos += 1

        # Move to the next chunk if we cannot find a name.
        if (name is None):
            index = end
            continue

        # Get a text value after the name if it looks like the following field
        # is not a font.
        if debug:
            print "Possible Name: '" + name + "'"
        text = ""
        # This is not working quite right.
        asc_str = None
        if (name_pos + 1 < len(strs)):
            asc_str = strs[name_pos + 1].replace("\x00", "").strip()
        if ((asc_str is not None) and
            ("Calibr" not in asc_str) and
            ("OCXNAME" not in asc_str) and
            ("contents" != asc_str) and
            ("ObjInfo" != asc_str) and
            ("CompObj" != asc_str) and
            (not asc_str.startswith("_DELETED_NAME_")) and
            (re.match(r"_\d{10}", asc_str) is None)):
            if debug:
                print "Value: 1"
                print strs[name_pos + 1]
                
            # Only used with large text values?
            if (len(strs[name_pos + 1]) > 3):
                text = strs[name_pos + 1]
                if debug:
                    print "Value: 2"
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
                        print "Value: 3"
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
                        print "Value: 4"
                        print poss_val
                    text += poss_val

        # Pattern 3
        val_pat = r"([\x20-\x7e]{5,})\x00\x02\x0c\x00\x34"
        vals = re.findall(val_pat, chunk)
        if (len(vals) > 0):
            for v in vals:
                text += v
                if debug:
                    print "Value: 5"
                    print v

        # Pattern 4
        val_pat = r"([\x20-\x7e]{5,})\x00{2,4}\x02\x0c"
        vals = re.findall(val_pat, chunk)
        if (len(vals) > 0):
            for v in vals:
                text += v
                if debug:
                    print "Value: 6"
                    print v
                
        # Maybe big chunks of text after the name are part of the value?
        for pos in range(name_pos + 2, len(strs)):
            curr_str = strs[pos].replace("\x00", "")
            if ((len(curr_str) > 40) and (not curr_str.startswith("Microsoft "))):
                text += curr_str

        if debug:
            print "ORIG:"
            print name
            print text
            print len(text)
                
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
            if (len(text) > size):
                text = text[:size]

        # Save the form name and text value.
        r.append((name, text))

        # Save long strings. Maybe they are the value of a previous variable?
        longest_str = ""
        for field in strs:
            if ((len(field) > 30) and
                (len(field) > len(longest_str)) and
                (not field.startswith("Microsoft "))):
                longest_str = field
        long_strs.append(longest_str)

        # Move to next chunk.
        index = end

    # The results are approximate. Fix some obvious errors.

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
                print "Skip 1: " + str(dat)
            pass
        last_val = dat[1].strip()
    r = tmp

    if debug:
        print "First result:"
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
        print "&&&&&&&&&&&&"
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
                poss_val1 = r[i][1]
                poss_val2 = long_strs[i]
                poss_val = poss_val2
                if (len(poss_val1) > len(poss_val2)):
                    poss_val = poss_val1
                if (len(poss_val) > 15):
                    if debug:
                        print "REPLACE (1)"
                    curr_val = poss_val
                    replaced = True
                    break

            # If we found nothing going forward, try the previous value?
            if ((not replaced) and (len(last_val) > 15)):
                if debug:
                    print "REPLACE (2)"
                curr_val = last_val

        # Update the result list.
        tmp.append((curr_var, curr_val))
        last_val = curr_val
    r = tmp

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
    tmp_r = []
    for old_pair in r:
        name = old_pair[0]
        val = old_pair[1]
        for cruft_pat in cruft_pats:
            val = re.sub(cruft_pat, "", val)
        tmp_r.append((name, val))
    r = tmp_r
        
    # Return the OLE form textbox information.
    if debug:
        print "\nFINAL RESULTS:" 
        print r
        sys.exit(0)
        
    return r

def _read_form_strings(vba):
    """
    Read in the form strings in order as a lists of tuples like (stream name, form string).
    """

    try:
        r = []
        skip_strings = ["Tahoma", "Tahomaz"]
        for (subfilename, stream_path, form_string) in vba.extract_form_strings():

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

def _get_shapes_text_values_direct_2007(data):
    """
    Read in shapes name/value mappings directly from word/document.xml from an 
    unzipped Word 2007+ file.
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
    val = val.replace("&amp", "&")
        
    # Return the Shape name and text value.
    r = [(name, val)]
    return r

def _parse_activex_chunk(data):
    """
    Parse out ActiveX text values from 2007+ activeXN.bin file contents.
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
    """
    Parse out Rich Edit control text values from 2007+ activeXN.bin file contents.
    """

    # No wide char null padding.
    data = data.replace("\x00", "")

    # Pull out the data.
    pat = r"\\fs\d{1,4} (.+)\\par"
    val = re.findall(pat, data)
    if (len(val) == 0):
        return None
    return val[0]

def _get_comments_2007(fname):
    """
    Read in the comments in a document saved in the 2007+ format.
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
            if (delete_file):
                os.remove(fname)
            return []

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
        text_pat = r"<w:t>([^<]+)</w:t>"
        texts = re.findall(text_pat, block)
        if (len(texts) == 0):
            continue

        block_text = ""

        for text in texts:
            text = text.replace("&amp;", "&")
            text = text.replace("&gt;", ">")
            text = text.replace("&lt;", "<")
            text = text.replace("&apos;", "'")
            text = text.replace("&quot;", '"')
            block_text += text


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
    """
    Read the comments from an Office file.
    """

    # Currently only 2007+ Office files are supported.
    if (not filetype.is_office2007_file(fname, (len(fname) > 2000))):
        return []

    # Read comments from 2007+ file.
    return _get_comments_2007(fname)

def _get_shapes_text_values_2007(fname):
    """
    Read in the text associated with Shape objects in a document saved
    in the 2007+ format.
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
    r = _get_shapes_text_values_direct_2007(data)
    if (len(r) > 0):
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
    f1.close()

    # Pull out any shape name to activeX object ID mappings.
    # <Relationship Id="rId10" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/control" Target="activeX/activeX3.xml"/>
    pat = r'<Relationship[^>]+Id="(\w+)"[^>]+Target="([^"]+)"'
    var_info = re.findall(pat, data)
    id_activex_map = {}
    for shape in var_info:
        if (shape[0] not in id_name_map):
            continue
        id_activex_map[shape[0]] = shape[1].replace(".xml", ".bin")
    #print id_activex_map

    # Read in the activeX objects.
    for shape in id_activex_map.keys():

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
        r.append((id_name_map[shape], text))
    
    # Done.
    unzipped_data.close()
    if (delete_file):
        os.remove(fname)
    #print r
    #sys.exit(0)
    return r

def _get_shapes_text_values(fname, stream):
    """
    Read in the text associated with Shape objects in the document.
    NOTE: This currently is a hack.
    """

    # Maybe 2007+ file?
    r = _get_shapes_text_values_2007(fname)
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
        log.error("Cannot read associated Shapes text. " + str(e))

        # See if we can read Shapes() info from an XML file.
        if ("not an OLE2 structured storage file" in str(e)):
            r = _get_shapes_text_values_xml(fname)

    return r

URL_REGEX = r'(http[s]?://(?:(?:[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-\.]+(?::[0-9]+)?)+(?:/[/\?&\~=a-zA-Z0-9_\-\.]+)))'
def pull_urls_from_comments(vba):
    """
    Pull out URLs that just appear in VBA comments.
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
    """
    Pull URLs directly from an Office97 file.
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

###########################################################################
## Main Program
###########################################################################
if __name__ == '__main__':
    print _get_shapes_text_values(sys.argv[1], "worddocument")
    print _get_shapes_text_values(sys.argv[1], '1table')
