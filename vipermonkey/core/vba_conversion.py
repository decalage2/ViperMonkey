"""@package vba_conversions Functions for doing VBScript/VBA type coercion.

"""

# pylint: disable=pointless-string-statement
"""
ViperMonkey - Functions for doing VBScript/VBA type coercion.

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

import re
import string

import logging
from logger import log

from utils import safe_str_convert

def int_convert(arg, leave_alone=False):
    """Convert a VBA expression to an int, handling VBA NULL.

    @param arg (str, int, or float) The thing to convert to an int.

    @param leave_alone (boolean) If True return the original argument
    if integer conversion fails, if False return 0 if conversion
    fails.

    @return (int) The given item converted to an int.

    """

    # Easy case.
    if (isinstance(arg, int)):
        return arg
    
    # NULLs are 0.
    if (arg == "NULL"):
        return 0

    # Empty strings are NULL.
    if (arg == ""):
        return "NULL"
    
    # Leave the wildcard matching value alone.
    if (arg == "**MATCH ANY**"):
        return arg

    # Convert float to int?
    if (isinstance(arg, float)):
        arg = int(round(arg))

    # Convert hex to int?
    if (isinstance(arg, str) and (arg.strip().lower().startswith("&h"))):
        hex_str = "0x" + arg.strip()[2:]
        try:
            return int(hex_str, 16)
        except Exception as e:
            log.error("Cannot convert hex '" + str(arg) + "' to int. Defaulting to 0. " + str(e))
            return 0
            
    arg_str = str(arg)
    if ("." in arg_str):
        arg_str = arg_str[:arg_str.index(".")]
    try:
        return int(arg_str)
    except Exception as e:
        if (not leave_alone):
            log.error("Cannot convert '" + str(arg_str) + "' to int. Defaulting to 0. " + str(e))
            return 0
        log.error("Cannot convert '" + str(arg_str) + "' to int. Leaving unchanged. " + str(e))
        return arg_str

def str_convert(arg):
    """Convert a VBA expression to an str, handling VBA NULL.

    @param arg (any) The thing to convert to a string.
    
    @return (str) The thing as a string.

    """
    if (arg == "NULL"):
        return ''
    import excel
    if (excel.is_cell_dict(arg)):
        arg = arg["value"]
    try:
        return str(arg)
    except Exception as e:
        if (isinstance(arg, unicode)):
            return ''.join(filter(lambda x:x in string.printable, arg))
        log.error("Cannot convert given argument to str. Defaulting to ''. " + str(e))
        return ''

def coerce_to_int_list(obj):
    """Coerce a VBA object to a list of ASCII codes. The object is
    converted to a string and then each character in the string is
    converted to its ASCII code.

    @param obj (VBA_Object object) The VBA object to convert to ASCII
    codes.

    @return (list) List of ASCII codes (int).

    """

    # Already have a list?
    if (isinstance(obj, list)):
        return obj
    
    # Make sure we have a string.
    s = coerce_to_str(obj)

    # Convert this to a list of ASCII char codes.
    r = []
    for c in s:
        r.append(ord(c))
    return r

def coerce_to_str(obj, zero_is_null=False):
    """Coerce a VBA object (integer, Null, etc) to a string.

    @param obj (VBA_Object object) The VBA object to convert to a
    string.

    @param zero_is_null (boolean) If True treat integer 0 as a zero
    length string, if False just convert 0 to '0'.

    @return (str) The given VBA object as a string.

    """

    # in VBA, Null/None is equivalent to an empty string
    if ((obj is None) or (obj == "NULL")):
        return ''

    # 0 can be a NULL also.
    if (zero_is_null and (obj == 0)):
        return ''
    
    # Not NULL. We have data.

    # Easy case. Is this already some sort of a string?
    if (isinstance(obj, basestring)):

        # Convert to a regular str if needed.
        return safe_str_convert(obj)
    
    # Do we have a list of byte values? If so convert the bytes to chars.
    if (isinstance(obj, list)):
        r = ""
        bad = False
        for c in obj:

            # Skip null bytes.
            if (c == 0):
                continue
            try:
                r += chr(c)
            except (TypeError, ValueError):

                # Invalid character value. Don't do string
                # conversion of array.
                bad = True
                break

        # Return the byte array as a string if it makes sense.
        if (not bad):
            return r

    # Is this an Excel cell dict?
    if (isinstance(obj, dict) and ("value" in obj)):

        # Return the value as a string.
        return (coerce_to_str(obj["value"]))
        
    # Not a character byte array. Just convert to a string.
    return safe_str_convert(obj)

def coerce_args_to_str(args):
    """Coerce a list of arguments to strings.

    @param args (list) The items to convert to strings.
    
    @return (list) A list where each given item has been coerced to a
    string.

    """
    # TODO: None should be converted to "", not "None"
    return [coerce_to_str(arg) for arg in args]
    # return map(lambda arg: str(arg), args)

def coerce_to_int(obj):
    """Coerce a VBA object (integer, Null, etc) to a int.

    @param obj (VBA_Object) The item to coerce to an integer.

    @return (int) The given item as an int. 0 is returned on error (or
    if the actual converted value is 0).

    """

    # in VBA, Null/None is equivalent to 0
    if ((obj is None) or (obj == "NULL")):
        return 0

    # Already have int?
    if (isinstance(obj, int)):
        return obj
    
    # Do we have a float string?
    if (isinstance(obj, str)):

        # Do we have a null byte string?
        if (obj.count('\x00') == len(obj)):
            return 0
        
        # No NULLS.
        obj = obj.replace("\x00", "")
        
        # Float string?
        if ("." in obj):
            try:
                obj = float(obj)
                return int(obj)
            except ValueError:
                pass
            
        # Hex string?
        hex_pat = r"&h[0-9a-f]+"
        if (re.match(hex_pat, obj.lower()) is not None):
            return int(obj.lower().replace("&h", "0x"), 16)

    # Is this an Excel cell dict?
    if (isinstance(obj, dict) and ("value" in obj)):

        # Return the value as an int.
        return (coerce_to_int(obj["value"]))
        
    # Try regular int.
    try:
        return int(obj)
    except ValueError as e:

        # Punt and just return NULL.
        log.error("int conversion failed. Returning NULL. " + safe_str_convert(e))
        return 0

def coerce_to_num(obj):
    """Coerce a VBA object (integer, Null, etc) to a int or float.

    @param obj (VBA_Object) The item to coerce to a number.

    @return (float, int) The given item as some sort of number. 

    @throws ValueError This is thrown if the given item cannot be
    converted to a number.

    """
    # in VBA, Null/None is equivalent to 0
    if ((obj is None) or (obj == "NULL")):
        return 0

    # Already have float or int?
    if isinstance(obj, (float, int)):
        return obj
    
    # Do we have a string?
    if (isinstance(obj, str)):

        # Stupid "123,456,7890" string where everything after the
        # 1st comma is ignored?
        dumb_pat = r"(?:\d+,)+\d+"
        if (re.match(dumb_pat, obj) is not None):
            obj = obj[:obj.index(",")]
        
        # Float string?
        if ("." in obj):
            try:
                obj = float(obj)
                return obj
            except ValueError:
                pass

        # Do we have a null byte string?
        if (obj.count('\x00') == len(obj)):
            return 0

        # Hex string?
        hex_pat = r"&h[0-9a-f]+"
        if (re.match(hex_pat, obj.lower()) is not None):
            return int(obj.lower().replace("&h", "0x"), 16)

    # Is this an Excel cell dict?
    if (isinstance(obj, dict) and ("value" in obj)):

        # Return the value as a number.
        return (coerce_to_num(obj["value"]))
        
    # Try regular int.
    return int(obj)

def coerce_args_to_int(args):
    """Coerce a list of arguments to ints.  
    
    @param args (list) The items (VBA_Object) to convert to ints.
    
    @return (list) The given items converted to ints.

    """
    return [coerce_to_int(arg) for arg in args]

def coerce_args(orig_args, preferred_type=None):
    """Coerce all of the arguments to either str or int based on the most
    common arg type.

    @param args (list) The items (VBA_Object) to convert to int or
    str.
    
    @param preferred_type (str) Preferred type to coerce things if
    possible ("str" or "int").

    @return (list) The given items converted to ints.

    """

    # Sanity check.
    if (len(orig_args) == 0):
        return orig_args

    # Convert args with None value to 'NULL'.
    args = []
    for arg in orig_args:
        if (arg is None):
            args.append("NULL")
        else:
            args.append(arg)
            
    # Find the 1st type in the arg list.
    first_type = None
    have_other_type = False
    all_null = True
    all_types = set()
    for arg in args:

        # Skip NULL values since they can be int or str based on context.
        if (arg == "NULL"):
            continue
        all_null = False
        if (isinstance(arg, str)):
            all_types.add("str")
            if (first_type is None):
                first_type = "str"
            continue
        elif (isinstance(arg, int)):
            all_types.add("int")
            if (first_type is None):
                first_type = "int"
            continue
        else:
            have_other_type = True
            break

    # If everything is NULL lets treat this as an int.
    if (all_null):
        first_type = "int"
        
    # Leave things alone if we have any non-int or str args.
    if (have_other_type):
        return args

    # Leave things alone if we cannot figure out the type to which to coerce.
    if (first_type is None):
        return args

    # If we have more than 1 possible type and one of these types is the
    # preferred type, use that type.
    if (preferred_type in all_types):
        first_type = preferred_type
    
    # Do conversion based on type of 1st arg in the list.
    if (first_type == "str"):

        # Replace unititialized values.
        new_args = []
        for arg in args:
            if (args == "NULL"):
                new_args.append('')
            else:
                new_args.append(arg)

        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Coerce to str " + safe_str_convert(new_args))
        return coerce_args_to_str(new_args)

    else:

        # Replace unititialized values.
        new_args = []
        for arg in args:
            if (args == "NULL"):
                new_args.append(0)
            else:
                new_args.append(arg)
                
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Coerce to int " + safe_str_convert(new_args))
        return coerce_args_to_int(new_args)
