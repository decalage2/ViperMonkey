"""
ViperMonkey: Class for representing VBA strings that contain a mix of ASCII and
wide character characters.

ViperMonkey is a specialized engine to parse, analyze and interpret Microsoft
VBA macros (Visual Basic for Applications), mainly for malware analysis.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

Project Repository:
https://github.com/decalage2/ViperMonkey
"""

# === LICENSE ==================================================================

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

__version__ = '0.08'

def is_mixed_wide_ascii_str(the_str):
    """
    Test a string to see if it is a mix of wide and ASCII chars.
    """
    for c in the_str:
        if (ord(c) > 127):
            return True
    return False

str_to_ascii_map = None
def get_ms_ascii_value(the_str):
    """
    Get the VBA ASCII value of a given string. This handles VBA using a different
    extended ASCII character set than everyone else in the world.

    This handles both retgular Python strings and VbStr objects.
    """

    # Sanity check.
    if ((not isinstance(the_str, str)) and (not isinstance(the_str, VbStr))):
        return ValueError("'" + str(the_str) + "' is not a string.")    
    
    # Initialize the map from wide char strings to MS ascii value if needed.
    global str_to_ascii_map
    if (str_to_ascii_map is None):
        str_to_ascii_map = {}
        for code in VbStr.ascii_map.keys():
            for bts in VbStr.ascii_map[code]:
                chars = ""
                for bt in bts:
                    chars += chr(bt)
                str_to_ascii_map[chars] = code

    # Convert the string to a Python string if we were given a VB string.
    if (isinstance(the_str, VbStr)):
        the_str = the_str.to_python_str()

    # Sanity check.
    if (len(the_str) == 0):
        #raise ValueError("String length is 0.")
        return 0
    
    # Look up the MS extended ASCII code.
    if (the_str not in str_to_ascii_map):

        # Punt and just return the code for the 1st char in the string.
        return ord(the_str[0])

    # MS wide char. Return MS extended ASCII code.
    return str_to_ascii_map[the_str]
    
class VbStr(object):

    # VBA uses a different extended ASCII character set for byte values greater than 127
    # (https://bettersolutions.com/vba/strings-characters/ascii-characters.htm). These
    # are seen by ViperMonkey as multi-byte characters. To handle this we have a map that
    # maps from the "special" VBA ASCII code for a character to the byte arrays representing
    # the unicode representation of the character that the rest of the world uses.
    ascii_map = {
        128: [[226, 130, 172]],
        129: [[239, 191, 189], [208, 131]],
        130: [[226, 128, 154]],
        131: [[198, 146], [209, 147]],
        132: [[226, 128, 158]],
        133: [[226, 128, 166]],
        134: [[226, 128, 160]],
        135: [[226, 128, 161]],
        136: [[203, 134]],
        137: [[226, 128, 176]],
        138: [[197, 160]],
        139: [[226, 128, 185]],
        140: [[197, 146]],
        # TODO: Figure out actual bytes for the commented out characters.
        #141: [[239, 191, 189]],
        142: [[197, 189]],
        #143: [[239, 191, 189]],
        #144: [[239, 191, 189]],
        145: [[226, 128, 152]],
        146: [[226, 128, 153]],
        147: [[226, 128, 156]],
        148: [[226, 128, 157]],
        149: [[226, 128, 162]],
        150: [[226, 128, 147]],
        151: [[226, 128, 148]],
        152: [[203, 156]],
        153: [[226, 132, 162]],
        154: [[197, 161]],
        155: [[226, 128, 186]],
        156: [[197, 147]],
        #157: [[239, 191, 189]],
        158: [[197, 190]],
        159: [[197, 184]],
        160: [[194, 160]],
        161: [[194, 161]],
        162: [[194, 162]],
        163: [[194, 163]],
        164: [[194, 164]],
        165: [[194, 165]],
        166: [[194, 166]],
        167: [[194, 167]],
        168: [[194, 168]],
        169: [[194, 169]],
        170: [[194, 170]],
        171: [[194, 171]],
        172: [[194, 172]],
        173: [[194, 173]],
        174: [[194, 174]],
        175: [[194, 175]],
        176: [[194, 176]],
        177: [[194, 177]],
        178: [[194, 178]],
        179: [[194, 179]],
        180: [[194, 180]],
        181: [[194, 181]],
        182: [[194, 182]],
        183: [[194, 183]],
        184: [[194, 184]],
        185: [[194, 185]],
        186: [[194, 186]],
        187: [[194, 187]],
        188: [[194, 188]],
        189: [[194, 189]],
        190: [[194, 190]],
        191: [[194, 191]],
        192: [[195, 128]],
        193: [[195, 129]],
        194: [[195, 130]],
        195: [[195, 131]],
        196: [[195, 132]],
        197: [[195, 133]],
        198: [[195, 134]],
        199: [[195, 135]],
        200: [[195, 136]],
        201: [[195, 137]],
        202: [[195, 138]],
        203: [[195, 139]],
        204: [[195, 140]],
        205: [[195, 141]],
        206: [[195, 142]],
        207: [[195, 143]],
        208: [[195, 144]],
        209: [[195, 145]],
        210: [[195, 146]],
        211: [[195, 147]],
        212: [[195, 148]],
        213: [[195, 149]],
        214: [[195, 150]],
        215: [[195, 151]],
        216: [[195, 152]],
        217: [[195, 153]],
        218: [[195, 154]],
        219: [[195, 155]],
        220: [[195, 156]],
        221: [[195, 157]],
        222: [[195, 158]],
        223: [[195, 159]],
        224: [[195, 160]],
        225: [[195, 161]],
        226: [[195, 162]],
        227: [[195, 163]],
        228: [[195, 164]],
        229: [[195, 165]],
        230: [[195, 166]],
        231: [[195, 167]],
        232: [[195, 168]],
        233: [[195, 169]],
        234: [[195, 170]],
        235: [[195, 171]],
        236: [[195, 172]],
        237: [[195, 173]],
        238: [[195, 174]],
        239: [[195, 175]],
        240: [[195, 176]],
        241: [[195, 177]],
        242: [[195, 178]],
        243: [[195, 179]],
        244: [[195, 180]],
        245: [[195, 181]],
        246: [[195, 182]],
        247: [[195, 183]],
        248: [[195, 184]],
        249: [[195, 185]],
        250: [[195, 186]],
        251: [[195, 187]],
        252: [[195, 188]],
        253: [[195, 189]],
        254: [[195, 190]],
        255: [[195, 191]],
    }
    
    def __init__(self, orig_str, is_vbscript=False):
        """
        Create a new VBA string object.

        orig_str - The raw Python string.
        is_vbscript - VBScript handles mixed ASCII/wide char strings differently than
        VBA. Set this to True if VBScript is being analyzed, False if VBA is being 
        analyzed.

        NOTE: This just handles characters from Microsoft's special extended ASCII set.

        """

        # Copy contructor? (sort of).
        if (isinstance(orig_str, list)):
            self.vb_str = orig_str
            return
        
        # If this is VBScript each character will be a single byte (like the Python
        # string).
        self.vb_str = []
        if (is_vbscript):
            for c in orig_str:
                self.vb_str.append(c)

        # This is a VBA string.
        else:

            # Break out ASCII characters and multi-byte wide chars as individual "characters".

            # Replace the multi-byte wide chars with special strings. We will break these out
            # later.
            tmp_str = orig_str
            for code in self.ascii_map.keys():
                chars = ""
                for bts in self.ascii_map[code]:
                    pos = 0
                    for bval in bts:
                        chars += chr(bval)
                    tmp_str = tmp_str.replace(chars, "MARK!@#$%%$#@!:.:.:.:.:.:." + str(code) + "_" + str(pos) + "MARK!@#$%%$#@!")

            # Split the string up into ASCII char chunks and individual wide chars.
            for val in tmp_str.split("MARK!@#$%"):

                # Remove additonal markings.
                val = val.replace("%$#@!", "")

                # Sanity check.
                if (len(val) == 0):
                    continue

                # Is this a special MS extended ASCII char?
                if (val.startswith(":.:.:.:.:.:.")):

                    # Yes, break this out as a single "wide char".
                    val = val.replace(":.:.:.:.:.:.", "")
                    pos = int(val.split("_")[1])
                    val = int(val.split("_")[0])
                    chars = ""
                    for bt in self.ascii_map[val][pos]:
                        chars += chr(bt)
                    self.vb_str.append(chars)

                # ASCII char chunk.
                else:
                    for c in val:
                        self.vb_str.append(c)
                
    def __repr__(self):
        r = ""
        for vb_c in self.vb_str:
            if (len(r) > 0):
                r += ":"
            if (len(vb_c) == 1):
                if (ord(vb_c) == 127):
                    r += str(hex(ord(vb_c)))
                else:
                    r += vb_c
            else:
                first = True
                for c in vb_c:
                    if (not first):
                        r += " "
                    first = False
                    r += hex(ord(c))
                
        return r

    def len(self):
        return len(self.vb_str)

    def to_python_str(self):
        """
        Return the VB string as a raw Python str.
        """
        r = ""
        for c in self.vb_str:
            r += c
        return r

    def get_chunk(self, start, end):
        """
        Return a chunk of the string as a vb_string object.
        """

        # Sanity check.
        if ((start < 0) or (start > len(self.vb_str))):
            raise ValueError("start index " + str(start) + " out of bounds.")
        if ((end < 0) or (end > len(self.vb_str))):
            raise ValueError("end index " + str(start) + " out of bounds.")
        if (start > end):
            raise ValueError("start index (" + str(start) + ") > end index (" + str(end) + ").")

        # Return the chunk.
        return VbStr(self.vb_str[start:end])

    def update_chunk(self, start, end, new_str):
        """
        Return a new copy of the current string updated with the given chunk
        replaced with the given string (can be a VbStr or a raw Python string).

        The current VB string object is not changed.
        """

        # Sanity check.
        if ((start < 0) or (start >= len(self.vb_str))):
            raise ValueError("start index " + str(start) + " out of bounds.")
        if ((end < 0) or (end > len(self.vb_str))):
            raise ValueError("end index " + str(start) + " out of bounds.")
        if (start > end):
            raise ValueError("start index (" + str(start) + ") > end index (" + str(end) + ").")

        # Pull out the unchanged prefix and suffix.
        prefix = self.get_chunk(0, start).to_python_str()
        suffix = self.get_chunk(end + 1, self.len()).to_python_str()

        # Put string together as a Python string.
        if (isinstance(new_str, VbStr)):
            new_str = new_str.to_python_str()
        updated_str = VbStr(prefix + new_str + suffix)

        # Done. Return as a VbStr.
        return updated_str
    
