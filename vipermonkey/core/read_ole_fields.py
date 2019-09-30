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

import olefile

from logger import log
import filetype

def get_ole_textbox_values(obj, vba_code):
    """
    Read in the text associated with embedded OLE form textbox objects.
    NOTE: This currently is a NASTY hack.
    """

    # Set to True to print lots of debugging.
    #debug = True
    debug = False
    if debug:
        print "Extracting OLE/ActiveX TextBox strings..."
    
    # Pull out the names of forms the VBA is accessing. We will use that later to try to
    # guess the names of ActiveX forms parsed from the raw Office file.
    object_names = set(re.findall(r"(?:ThisDocument|ActiveDocument|\w+)\.(\w+)", vba_code))
    if debug:
        print "Names from VBA code:"
        print object_names
    
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
    field_marker = "Forms."
    if (form_str not in data):
        if debug:
            print "NO FORMS"
            sys.exit(0)
        return []

    pat = r"(?:[\x20-\x7e]{5,})|(?:(?:(?:\x00|\xff)[\x20-\x7e]){5,})"
    index = 0
    r = []
    found_names = set()
    long_strs = []
    while (form_str in data[index:]):

        # Break out the data for an embedded OLE textbox form.

        # Move to the end of specific versions of the form string.
        # "Microsoft Forms 2.0 TextBox", "Microsoft Forms 2.0 ComboBox", etc.
        index = data[index:].index(form_str) + index
        start = index + len(form_str)
        while ((start < len(data)) and (ord(data[start]) in range(32, 127))):
            start += 1

        # More textbox forms?
        if (form_str in data[start:]):

            # Just look at the current form chunk.
            end = data[start:].index(form_str) + start

        # No more textbox forms.
        else:

            # Jump an arbitrary amount ahead.
            end = index + 5000
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
                    poss_name = strs[curr_pos + 1].replace("\x00", "").replace("\xff", "").strip()
                    if (((not poss_name.startswith("_")) or
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
            (re.match(r"_\d{10}", asc_str) is None)):
            if debug:
                print "Value: 1"
                print strs[name_pos + 1]
                
            # Only used with large text values?
            if (len(strs[name_pos + 1]) > 20):
                text = strs[name_pos + 1]

        # Break out the (possible additional) value.
        val_pat = r"(?:\x00|\xff)[\x20-\x7e]+[^\x00]*\x00+\x02\x18"
        vals = re.findall(val_pat, chunk)
        if (len(vals) > 0):
            empty_pat = r"(?:\x00|\xff)#[^\x00]*\x00+\x02\x18"
            if (len(re.findall(empty_pat, vals[0])) == 0):
                poss_val = re.findall(r"[\x20-\x7e]+", vals[0][1:-2])[0]
                if (poss_val != text):
                    text += poss_val.replace("\x00", "")

        # Pattern 2                    
        val_pat = r"\x00#\x00\x00\x00[^\x02]+\x02"
        vals = re.findall(val_pat, chunk)
        if (len(vals) > 0):
            tmp_text = re.findall(r"[\x20-\x7e]+", vals[0][2:-2])
            if (len(tmp_text) > 0):
                poss_val = tmp_text[0]
                if (poss_val != text):
                    if debug:
                        print "Value: 3"
                        print poss_val
                    text += poss_val

        # Pattern 3
        val_pat = r"([\x20-\x7e]{5,})\x00\x02\x0c\x00\x34"
        vals = re.findall(val_pat, chunk)
        if (len(vals) > 0):
            for v in vals:
                text += v

        # Pattern 4
        val_pat = r"([\x20-\x7e]{5,})\x00{2,4}\x02\x0c"
        vals = re.findall(val_pat, chunk)
        if (len(vals) > 0):
            for v in vals:
                text += v
                
        # Pull out the size of the text.
        # Try version 1.
        size_pat = r"\x48\x80\x2c\x03\x01\x02\x00(.{2})"
        tmp = re.findall(size_pat, chunk)
        if (len(tmp) == 0):
            # Try version 2.
            size_pat = r"\x48\x80\x2c(.{2})"
            tmp = re.findall(size_pat, chunk)
        if (len(tmp) > 0):
            size_bytes = tmp[0]
            size = ord(size_bytes[1]) * 256 + ord(size_bytes[0])
            if debug:
                print "ORIG:"
                print name
                print text
                print len(text)
                print size
            if (len(text) > size):
                text = text[:size]

        # Save the form name and text value.
        r.append((name, text))

        # Save long strings. Maybe they are the value of a previous variable?
        longest_str = ""
        for field in strs:
            if ((len(field) > 30) and (len(field) > len(longest_str))):
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
    
    # Return the OLE form textbox information.
    if debug:
        print "" 
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

def _get_shapes_text_values_2007(fname):
    """
    Read in the text associated with Shape objects in a document saved
    in the 2007+ format.
    """

    # Unzip the file.
    # PKZip magic #: 50 4B 03 04
    zip_magic = chr(0x50) + chr(0x4B) + chr(0x03) + chr(0x04)
    contents = None
    delete_file = False
    if fname.startswith(zip_magic):
        #raise ValueError("_get_shapes_text_values_2007() currently does not support in-memory Office files.")
        # TODO: Fix this. For now just save to a tmp file.
        tmp_name = "/tmp/" + str(random.randrange(0, 10000000000)) + ".office"
        f = open(tmp_name, 'wb')
        f.write(fname)
        f.close()
        fname = tmp_name
        delete_file = True

    # Is this a ZIP file?
    try:
        if (not zipfile.is_zipfile(fname)):
            if (delete_file):
                os.remove(fname)
            return []
    except:
        if (delete_file):
            os.remove(fname)
        return []
        
    # This is a 2007+ Office file. Unzip it.
    unzipped_data = zipfile.ZipFile(fname, 'r')

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
            continue
        start = data.rindex(anchor) + len(anchor) + pad
        pat = r"([\x20-\x7e]+)"
        text = re.findall(pat, data[start:])
        if (len(text) == 0):
            continue
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

        # Save the text associated with the variable name.
        r.append((id_name_map[shape], text))
    
    # Done.
    unzipped_data.close()
    if (delete_file):
        os.remove(fname)
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

def pull_urls_office97(fname, is_data):
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

    # Pull URLs.
    URL_REGEX = r'(http[s]?://(?:(?:[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-\.]+(?::[0-9]+)?)+(?:/[/\?&\~=a-zA-Z0-9_\-\.]+)))'
    pat = r"(/[/\?&\~=a-zA-Z0-9_\-\.]+)"
    return re.findall(URL_REGEX, data)

###########################################################################
## Main Program
###########################################################################
if __name__ == '__main__':
    print _get_shapes_text_values(sys.argv[1], "worddocument")
    print _get_shapes_text_values(sys.argv[1], '1table')
