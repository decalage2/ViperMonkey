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

# Office magic numbers.
magic_nums = {
    "office97" : "D0 CF 11 E0 A1 B1 1A E1",    # Office 97
    "office2007" : "50 4B 3 4",                # Office 2007+ (PKZip)
}

def get_1st_8_bytes(fname, is_data):

    info = None
    is_data = (is_data or (len(fname) > 200))
    if (not is_data):
        try:
            tmp = open(fname, 'rb')
            tmp.close()
        except:
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
    
def is_office_file(fname, is_data):
    """
    Check to see if the given file is a MS Office file format.

    return - True if it is an Office file, False if not.
    """

    # Read the 1st 8 bytes of the file.
    curr_magic = get_1st_8_bytes(fname, is_data)

    # See if we have 1 of the known magic #s.
    for typ in magic_nums.keys():
        magic = magic_nums[typ]
        if (curr_magic.startswith(magic)):
            return True
    return False

def is_office97_file(fname, is_data):

    # Read the 1st 8 bytes of the file.
    curr_magic = get_1st_8_bytes(fname, is_data)

    # See if we have the Office97 magic #.
    return (curr_magic.startswith(magic_nums["office97"]))

def is_office2007_file(fname, is_data):

    # Read the 1st 8 bytes of the file.
    curr_magic = get_1st_8_bytes(fname, is_data)

    # See if we have the Office 2007 magic #.
    return (curr_magic.startswith(magic_nums["office2007"]))
