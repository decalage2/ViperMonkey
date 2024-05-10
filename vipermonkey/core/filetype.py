"""@package vipermonkey.core.filetype Check for Office file types
"""

# pylint: disable=pointless-string-statement
"""
Check for Office file types

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

import logging
import subprocess

from logger import log

# Office magic numbers.
magic_nums = {
    "office97" : "D0 CF 11 E0 A1 B1 1A E1",    # Office 97
    "office2007" : "50 4B 3 4",                # Office 2007+ (PKZip)
}

# PE magic number.
pe_magic_num = "4D 5A"

def get_1st_8_bytes(fname, is_data):
    """Get the first 8 bytes of a file (or data).

    @param fname (str) The name of the file or the already read in
    file data. The data will be read in if a file name is given.

    @param is_data (boolean) True if fname contains the file data,
    False if it is a file name.

    @return (str) The 1st 8 bytes of the file.

    """
    
    info = None
    is_data = (is_data or (len(fname) > 200))
    if (not is_data):
        try:
            tmp = open(fname, 'rb')
            tmp.close()
        except IOError:
            is_data = True
    if (not is_data):
        with open(fname, 'rb') as f:
            info = f.read(8)
    else:
        info = fname[:9]

    curr_magic = ""
    for b in info:
        curr_magic += hex(ord(b)).replace("0x", "").upper() + " "
        
    return curr_magic

def is_pe_file(fname, is_data):
    """Check to see if the given file is a PE executable.

    @param fname (str) The name of the file or the already read in
    file data. The data will be read in if a file name is given.

    @param is_data (boolean) True if fname contains the file data,
    False if it is a file name.

    @return (boolean) True if it is a PE file, False if not.

    """

    # Read the 1st 8 bytes of the file.
    curr_magic = get_1st_8_bytes(fname, is_data)

    # See if we the known magic #.
    return (curr_magic.startswith(pe_magic_num))

def is_office_xml_file(fname, is_data):
    """Check to see if the given file is a MS Office XML file.

    @param fname (str) The name of the file or the already read in
    file data. The data will be read in if a file name is given.

    @param is_data (boolean) True if fname contains the file data,
    False if it is a file name.

    @return (boolean) True if it is an Office XML file, False if not.

    """

    # Get the file contents.
    contents = None
    if is_data:
        contents = fname
    else:
        try:
            f = open(fname, "r")
            contents = f.read()
            f.close()
        except IOError as e:
            log.error("Cannot read file " + fname + ". " + str(e))
            return False

    # Return whether this is an Office XML file.
    # TODO: Currently only checks for Word files.
    return (('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' in contents) and
            ('<?mso-application progid="Word.Document"?>' in contents))

def is_office_file(fname, is_data):
    """Check to see if the given file is a MS Office (97 or 2007+) file.

    @param fname (str) The name of the file or the already read in
    file data. The data will be read in if a file name is given.

    @param is_data (boolean) True if fname contains the file data,
    False if it is a file name.

    @return (boolean) True if it is an Office file, False if not.

    """

    # Read the 1st 8 bytes of the file.
    curr_magic = get_1st_8_bytes(fname, is_data)

    # See if we have 1 of the known magic #s.
    for typ in magic_nums:
        magic = magic_nums[typ]
        if (curr_magic.startswith(magic)):
            return True

    # See if it is an Office file saved as XML.
    return is_office_xml_file(fname, is_data)

def is_office97_file(fname, is_data):
    """Check to see if the given file is a MS Office 97 file.

    @param fname (str) The name of the file or the already read in
    file data. The data will be read in if a file name is given.

    @param is_data (boolean) True if fname contains the file data,
    False if it is a file name.

    @return (boolean) True if it is an Office 97 file, False if not.

    """
    
    # Read the 1st 8 bytes of the file.
    curr_magic = get_1st_8_bytes(fname, is_data)

    # See if we have the Office97 magic #.
    return (curr_magic.startswith(magic_nums["office97"]))

def is_office2007_file(fname, is_data):
    """Check to see if the given file is a MS Office 2007+ file.

    @param fname (str) The name of the file or the already read in
    file data. The data will be read in if a file name is given.

    @param is_data (boolean) True if fname contains the file data,
    False if it is a file name.

    @return (boolean) True if it is an Office 2007+ file, False if not.

    """
    
    # Read the 1st 8 bytes of the file.
    curr_magic = get_1st_8_bytes(fname, is_data)

    # See if we have the Office 2007 magic #.
    return (curr_magic.startswith(magic_nums["office2007"]))
