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

from core.logger import log

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
    if ('word/document.xml' not in unzipped_data.namelist()):
        if (delete_file):
            os.remove(fname)
        return []

    # Read the contents of document.xml.
    r = []
    f1 = unzipped_data.open('word/document.xml')
    data = f1.read()
    f1.close()

    # Pull out any shape name to internal ID mappings.
    # <w:control r:id="rId10" w:name="ziPOVJ5" w:shapeid="_x0000_i1028"/>
    pat = r'<w\:control[^>]+r\:id="(\w+)"[^>]+w\:name="(\w+)"'
    var_info = re.findall(pat, data)
    id_name_map = {}
    for shape in var_info:
        id_name_map[shape[0]] = shape[1]
    #print id_name_map

    # Get the ID to active X object mapping. This is in word/_rels/document.xml.rels.
    if ('word/_rels/document.xml.rels' not in unzipped_data.namelist()):
        if (delete_file):
            os.remove(fname)
        return []

    # Read the contents of document.xml.rels.
    r = []
    f1 = unzipped_data.open('word/_rels/document.xml.rels')
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
            continue

        # Read in the activeX data.
        f1 = unzipped_data.open(path)
        data = f1.read()
        f1.close()

        # Pull out the text associated with the object.
        if ("#" not in data):
            continue
        start = data.rindex("   #") + len("   #") + 3
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
        if (len(tmp) > 0):
            size_bytes = tmp[0]
            size = ord(size_bytes[1]) * 256 + ord(size_bytes[0])
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

###########################################################################
## Main Program
###########################################################################
if __name__ == '__main__':
    print _get_shapes_text_values(sys.argv[1], "worddocument")
