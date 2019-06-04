#!/usr/bin/env python
"""
ViperMonkey: VBA Grammar - Base class for all VBA objects

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


# ------------------------------------------------------------------------------
# CHANGELOG:
# 2015-02-12 v0.01 PL: - first prototype
# 2015-2016        PL: - many updates
# 2016-06-11 v0.02 PL: - split vipermonkey into several modules

__version__ = '0.08'

# ------------------------------------------------------------------------------
# TODO:

# --- IMPORTS ------------------------------------------------------------------

import base64
from logger import log
import re
from curses_ascii import isprint

from inspect import getouterframes, currentframe
import sys
from datetime import datetime
import pyparsing

from meta import read_metadata_item
import expressions

max_emulation_time = None

class VbaLibraryFunc(object):
    """
    Marker class to tell if a class implements a VBA function.
    """
    pass

def excel_col_letter_to_index(x): 
    return (reduce(lambda s,a:s*26+ord(a)-ord('A')+1, x, 0) - 1)

def limits_exceeded(throw_error=False):
    """
    Check to see if we are about to exceed the maximum recursion depth. Also check to 
    see if emulation is taking too long (if needed).
    """

    # Check to see if we are approaching the recursion limit.
    level = len(getouterframes(currentframe(1)))
    recursion_exceeded = (level > (sys.getrecursionlimit() * .50))
    time_exceeded = False

    # Check to see if we have exceeded the time limit.
    if (max_emulation_time is not None):
        time_exceeded = (datetime.now() > max_emulation_time)

    if (recursion_exceeded):
        log.error("Call recursion depth approaching limit.")
        if (throw_error):
            raise RuntimeError("The ViperMonkey recursion depth will be exceeded. Aborting analysis.")
    if (time_exceeded):
        log.error("Emulation time exceeded.")
        if (throw_error):
            raise RuntimeError("The ViperMonkey emulation time limit was exceeded. Aborting analysis.")
        
    return (recursion_exceeded or time_exceeded)

class VBA_Object(object):
    """
    Base class for all VBA objects that can be evaluated.
    """

    # Upper bound for loop iterations. 0 or less means unlimited.
    loop_upper_bound = 10000000
    
    def __init__(self, original_str, location, tokens):
        """
        VBA_Object constructor, to be called as a parse action by a pyparsing parser

        :param original_str: original string matched by the parser
        :param location: location of the match
        :param tokens: tokens extracted by the parser
        :return: nothing
        """
        self.original_str = original_str
        self.location = location
        self.tokens = tokens
        self._children = None
        self.is_useless = False
        
    def eval(self, context, params=None):
        """
        Evaluate the current value of the object.

        :param context: Context for the evaluation (local and global variables)
        :return: current value of the object
        """
        log.debug(self)
        # raise NotImplementedError

    def get_children(self):
        """
        Return the child VBA objects of the current object.
        """

        # Check for timeouts.
        limits_exceeded(throw_error=True)
        
        # The default behavior is to count any VBA_Object attribute as
        # a child.
        if (self._children is not None):
            return self._children
        r = []
        for _, value in self.__dict__.iteritems():
            if (isinstance(value, VBA_Object)):
                r.append(value)
            if ((isinstance(value, list)) or
                (isinstance(value, pyparsing.ParseResults))):
                for i in value:
                    if (isinstance(i, VBA_Object)):
                        r.append(i)
            if (isinstance(value, dict)):
                for i in value.values():
                    if (isinstance(i, VBA_Object)):
                        r.append(i)
        self._children = r
        return r
                        
    def accept(self, visitor):
        """
        Visitor design pattern support. Accept a visitor.
        """

        # Check for timeouts.
        limits_exceeded(throw_error=True)
        
        # Visit the current item.
        if (not visitor.visit(self)):
            return

        # Visit all the children.
        for child in self.get_children():
            child.accept(visitor)

def _read_from_excel(arg, context):
    """
    Try to evaluate an argument by reading from the loaded Excel spreadsheet.
    """

    # Try handling reading value from an Excel spreadsheet cell.
    arg_str = str(arg)
    if (("thisworkbook." in arg_str.lower()) and
        ('("thisworkbook.' not in arg_str.lower()) and
        ("sheets(" in arg_str.lower()) and
        ("range(" in arg_str.lower())):
        
        log.debug("Try as Excel cell read...")
        
        # Pull out the sheet name.
        tmp_arg_str = arg_str.lower()
        start = tmp_arg_str.index("sheets(") + len("sheets(")
        end = start + tmp_arg_str[start:].index(")")
        sheet_name = arg_str[start:end].strip().replace('"', "").replace("'", "").replace("//", "")
        
        # Pull out the cell index.
        start = tmp_arg_str.index("range(") + len("range(")
        end = start + tmp_arg_str[start:].index(")")
        cell_index = arg_str[start:end].strip().replace('"', "").replace("'", "").replace("//", "")
        log.debug("Sheet name = '" + sheet_name + "', cell index = " + cell_index)
        
        try:
            
            # Load the sheet.
            sheet = context.loaded_excel.sheet_by_name(sheet_name)
            
            # Pull out the cell column and row.
            col = ""
            row = ""
            for c in cell_index:
                if (c.isalpha()):
                    col += c
                else:
                    row += c
                    
            # Convert the row and column to numeric indices for xlrd.
            row = int(row) - 1
            col = excel_col_letter_to_index(col)
            
            # Pull out the cell value.
            val = str(sheet.cell_value(row, col))
            
            # Return the cell value.
            log.info("Read cell (" + str(cell_index) + ") from sheet " + str(sheet_name))
            log.debug("Cell value = '" + str(val) + "'")
            return val
        
        except Exception as e:
            log.error("Cannot read cell from Excel spreadsheet. " + str(e))

def _read_from_object_text(arg, context):
    """
    Try to read in a value from the text associated with a object like a Shape.
    """

    # Do we have an object text access?
    arg_str = str(arg)
    arg_str_low = arg_str.lower().strip()

    # Shapes('test33').      TextFrame.TextRange.text
    # Shapes('FrXXBbPlWaco').TextFrame.TextRange
    #
    # Make sure not to pull out Shapes() references that appear as arguments to function
    # calls.
    if (("shapes(" in arg_str_low) and (not isinstance(arg, expressions.Function_Call))):

        # Yes we do. 
        log.debug("eval_arg: Try to get as ....TextFrame.TextRange.Text value: " + arg_str.lower())

        # Handle member access?
        lhs = "Shapes('1')"
        if ("inlineshapes" in arg_str_low):
            lhs = "InlineShapes('1')"
        if ("MemberAccessExpression" in str(type(arg))):

            # Drop off ActiveDocument prefix.
            lhs = arg.lhs
            if ((str(lhs) == "ActiveDocument") or (str(lhs) == "ThisDocument")):
                lhs = arg.rhs[0]
        
            # Eval the leftmost prefix element of the member access expression first.
            log.debug("eval_obj_text: Old member access lhs = " + str(lhs))
            if (hasattr(lhs, "eval")):
                lhs = lhs.eval(context)
            else:

                # Look this up as a variable name.
                var_name = str(lhs)
                try:
                    lhs = context.get(var_name)
                except KeyError:
                    lhs = var_name

            if (lhs == "NULL"):
                lhs = "Shapes('1')"
            if ("inlineshapes" in arg_str_low):
                lhs = "InlineShapes('1')"
            log.debug("eval_obj_text: Evaled member access lhs = " + str(lhs))
        
        # Try to get this as a doc var.
        doc_var_name = str(lhs) + ".TextFrame.TextRange.Text"
        doc_var_name = doc_var_name.replace(".TextFrame.TextFrame", ".TextFrame")
        if (("InlineShapes(" in doc_var_name) and (not doc_var_name.startswith("InlineShapes("))):
            doc_var_name = doc_var_name[doc_var_name.index("InlineShapes("):]
        elif (("Shapes(" in doc_var_name) and
              (not doc_var_name.startswith("Shapes(")) and
              ("InlineShapes(" not in doc_var_name)):
            doc_var_name = doc_var_name[doc_var_name.index("Shapes("):]
        log.debug("eval_obj_text: Looking for object text " + str(doc_var_name))
        val = context.get_doc_var(doc_var_name.lower())
        if (val is not None):
            log.debug("eval_obj_text: Found " + str(doc_var_name) + " = " + str(val))
            return val

        # Not found. Try looking for the object with index 1.
        lhs_str = str(lhs)
        if ("'" not in lhs_str):
            return None
        new_lhs = lhs_str[:lhs_str.index("'") + 1] + "1" + lhs_str[lhs_str.rindex("'"):]
        doc_var_name = new_lhs + ".TextFrame.TextRange.Text"
        doc_var_name = doc_var_name.replace(".TextFrame.TextFrame", ".TextFrame")
        if (("InlineShapes(" in doc_var_name) and (not doc_var_name.startswith("InlineShapes("))):
            doc_var_name = doc_var_name[doc_var_name.index("InlineShapes("):]
        elif (("Shapes(" in doc_var_name) and
              (not doc_var_name.startswith("Shapes(")) and
              ("InlineShapes(" not in doc_var_name)):
            doc_var_name = doc_var_name[doc_var_name.index("Shapes("):]
        log.debug("eval_arg: Fallback, looking for object text " + str(doc_var_name))
        val = context.get_doc_var(doc_var_name.lower())
        return val
    
meta = None

def eval_arg(arg, context, treat_as_var_name=False):
    """
    evaluate a single argument if it is a VBA_Object, otherwise return its value
    """

    # pypy seg faults sometimes if the recursion depth is exceeded. Try to
    # avoid that. Also check to see if emulation has taken too long.
    limits_exceeded(throw_error=True)

    log.debug("try eval arg: %s (%s, %s, %s)" % (arg, type(arg), isinstance(arg, VBA_Object), treat_as_var_name))
    
    # Try handling reading value from an Excel spreadsheet cell.
    excel_val = _read_from_excel(arg, context)
    if (excel_val is not None):
        return excel_val

    # Short circuit the checks and see if we are accessing some object text first.
    obj_text_val = _read_from_object_text(arg, context)
    if (obj_text_val is not None):
        return obj_text_val
    
    # Not reading from an Excel cell. Try as a VBA object.
    if ((isinstance(arg, VBA_Object)) or (isinstance(arg, VbaLibraryFunc))):

        # Handle cases where wscriptshell.run() is being called and there is a local run() function.
        if ((".run(" in str(arg).lower()) and (context.contains("run"))):

            # Resolve the run() call.
            if ("MemberAccessExpression" in str(type(arg))):
                arg_evaled = arg.eval(context)
                return arg_evaled

        # Handle as a regular VBA object.
        log.debug("eval_arg: eval as VBA_Object %s" % arg)
        r = arg.eval(context=context)

        # Is this a Shapes() access that still needs to be handled?
        poss_shape_txt = ""
        try:
            poss_shape_txt = str(r)
        except:
            pass
        if ((poss_shape_txt.startswith("Shapes(")) or (poss_shape_txt.startswith("InlineShapes("))):
            log.debug("eval_arg: Handling intermediate Shapes() access for " + str(r))
            return eval_arg(r, context)
        
        # Regular VBA object.
        return r

    # Not a VBA object.
    else:
        log.debug("eval_arg: not a VBA_Object: %r" % arg)

        # Might this be a special type of variable lookup?
        if (isinstance(arg, str)):

            # Simple case first. Is this a variable?
            try:
                log.debug("eval_arg: Try as variable name: %r" % arg)
                r = context.get(arg)
                log.debug("eval_arg: Got %r = %r" % (arg, r))
                return r
            except:
                    
                # No it is not. Try more complicated cases.
                log.debug("eval_arg: Not found as variable name: %r" % arg)
                pass
            else:
                log.debug("eval_arg: Do not try as variable name: %r" % arg)

            # This is a hack to get values saved in the .text field of objects.
            # To do this properly we need to save "FOO.text" as a variable and
            # return the value of "FOO.text" when getting "FOO.nodeTypedValue".
            if (".nodetypedvalue" in arg.lower()):
                try:
                    tmp = arg.lower().replace(".nodetypedvalue", ".text")
                    log.debug("eval_arg: Try to get as " + tmp + "...")
                    val = context.get(tmp)
    
                    # It looks like maybe this magically does base64 decode? Try that.
                    try:
                        log.debug("eval_arg: Try base64 decode of '" + val + "'...")
                        base64_str = filter(isprint, str(base64_str).strip())
                        val_decode = base64.b64decode(str(val)).replace(chr(0), "")
                        log.debug("eval_arg: Base64 decode success: '" + val_decode + "'...")
                        return val_decode
                    except Exception as e:
                        log.debug("eval_arg: Base64 decode fail. " + str(e))
                        return val
                except KeyError:
                    log.debug("eval_arg: Not found as .text.")
                    pass

            # This is a hack to get values saved in the .rapt.Value field of objects.
            elif (".selecteditem" in arg.lower()):
                try:
                    tmp = arg.lower().replace(".selecteditem", ".rapt.value")
                    log.debug("eval_arg: Try to get as " + tmp + "...")
                    val = context.get(tmp)
                    return val

                except KeyError:
                    log.debug("eval_arg: Not found as .rapt.value.")
                    pass

            # Is this trying to access some VBA form variable?
            elif ("." in arg.lower()):

                # Try easy button first. See if this is just a doc var.
                doc_var_val = context.get_doc_var(arg)
                if (doc_var_val is not None):
                    return doc_var_val

                # Peel off items seperated by a '.', trying them as functions.
                arg_peeled = arg
                while ("." in arg_peeled):
                
                    # Try it as a form variable.
                    curr_var_attempt = arg_peeled.lower()
                    try:
                        log.debug("eval_arg: Try to load as variable " + curr_var_attempt + "...")
                        val = context.get(curr_var_attempt)
                        if (val != str(arg)):
                            return val

                    except KeyError:
                        log.debug("eval_arg: Not found as variable")
                        pass

                    arg_peeled = arg_peeled[arg_peeled.index(".") + 1:]

                # Try it as a function
                func_name = arg.lower()
                func_name = func_name[func_name.rindex(".")+1:]
                try:

                    # Lookp and execute the function.
                    log.debug("eval_arg: Try to run as function '" + func_name + "'...")
                    func = context.get(func_name)
                    r = func
                    if (isinstance(func, Function) or isinstance(func, Sub)):
                        r = eval_arg(func, context, treat_as_var_name=True)

                    # Did the function resolve to a value?
                    if (r != func):

                        # Yes it did. Return the function result.
                        return r

                    # The function did to resolve to a value. Return as the
                    # original string.
                    return arg

                except KeyError:
                    log.debug("eval_arg: Not found as function")

                except Exception as e:
                    log.debug("eval_arg: Failed. Not a function. " + str(e))

                # Are we trying to load some document meta data?
                tmp = arg.lower().strip()
                if (tmp.startswith("activedocument.item(")):

                    # Try to pull the result from the document meta data.
                    prop = tmp.replace("activedocument.item(", "").replace(")", "").replace("'","").strip()

                    # Make sure we read in the metadata.
                    if (meta is None):
                        log.error("BuiltInDocumentProperties: Metadata not read.")
                        return ""
                
                    # See if we can find the metadata attribute.
                    if (not hasattr(meta, prop.lower())):
                        log.error("BuiltInDocumentProperties: Metadata field '" + prop + "' not found.")
                        return ""

                    # We have the attribute. Return it.
                    r = getattr(meta, prop.lower())
                    log.debug("BuiltInDocumentProperties: return %r -> %r" % (prop, r))
                    return r

                # Are we trying to load some document data?
                if ((tmp.startswith("thisdocument.builtindocumentproperties(")) or
                    (tmp.startswith("activeworkbook.builtindocumentproperties("))):

                    # Try to pull the result from the document data.
                    var = tmp.replace("thisdocument.builtindocumentproperties(", "").replace(")", "").replace("'","").strip()
                    var = var.replace("activeworkbook.builtindocumentproperties(", "")
                    val = context.get_doc_var(var)
                    if (val is not None):
                        return val

                    # Try getting from meta data.
                    val = read_metadata_item(var)
                    if (val is not None):
                        return val
                    
                # Are we loading a document variable?
                if (tmp.startswith("activedocument.variables(")):

                    # ActiveDocument.Variables("ER0SNQAWT").Value
                    # Try to pull the result from the document variables.
                    log.debug("eval_arg: handle expression as doc var lookup '" + tmp + "'")
                    var = tmp.replace("activedocument.variables(", "").\
                          replace(")", "").\
                          replace("'","").\
                          replace('"',"").\
                          replace('.value',"").\
                          replace("(", "").\
                          strip()
                    log.debug("eval_arg: look for '" + var + "' as document variable...")
                    val = context.get_doc_var(var)
                    if (val is not None):
                        log.debug("eval_arg: got it as document variable.")
                        return val
                    else:
                        log.debug("eval_arg: did NOT get it as document variable.")

                # Are we loading a custom document property?
                if (tmp.startswith("activedocument.customdocumentproperties(")):

                    # ActiveDocument.CustomDocumentProperties("l3qDvt3B53wxeXu").Value
                    # Try to pull the result from the custom properties.
                    var = tmp.replace("activedocument.customdocumentproperties(", "").\
                          replace(")", "").\
                          replace("'","").\
                          replace('"',"").\
                          replace('.value',"").\
                          replace("(", "").\
                          strip()
                    val = context.get_doc_var(var)
                    if (val is not None):
                        return val
                    
                # As a last resort try reading it as a wildcarded form variable.
                wild_name = tmp[:tmp.index(".")] + "*"
                for i in range(0, 11):
                    tmp_name = wild_name + str(i)
                    try:
                        val = context.get(tmp_name)
                        log.debug("eval_arg: Found '" + tmp + "' as wild card form variable '" + tmp_name + "'")
                        return val
                    except:
                        pass


        # Should this be handled as a variable? Must be a valid var name to do this.
        if (treat_as_var_name and (re.match(r"[a-zA-Z_][\w\d]*", str(arg)) is not None)):

            # We did not resolve the variable. Treat it as unitialized.
            log.debug("eval_arg: return 'NULL'")
            return "NULL"

        # Are we referring to a form element that we cannot find?
        if ((str(arg).lower().endswith(".tag")) or
            (str(arg).lower().endswith(".boundvalue")) or
            (str(arg).lower().endswith(".column")) or
            (str(arg).lower().endswith(".caption")) or
            (str(arg).lower().endswith(".groupname")) or
            (str(arg).lower().endswith(".seltext")) or
            (str(arg).lower().endswith(".controltiptext")) or
            (str(arg).lower().endswith(".passwordchar")) or
            (str(arg).lower().endswith(".controlsource")) or
            (str(arg).lower().endswith(".value"))):
            return ""
        
        # The .text hack did not work.
        log.debug("eval_arg: return " + str(arg))
        return arg

def eval_args(args, context, treat_as_var_name=False):
    """
    Evaluate a list of arguments if they are VBA_Objects, otherwise return their value as-is.
    Return the list of evaluated arguments.
    """
    r = map(lambda arg: eval_arg(arg, context=context, treat_as_var_name=treat_as_var_name), args)
    return r

def coerce_to_str(obj):
    """
    Coerce a constant VBA object (integer, Null, etc) to a string.
    :param obj: VBA object
    :return: string
    """
    # in VBA, Null/None is equivalent to an empty string
    if ((obj is None) or (obj == "NULL")):
        return ''

    # Not NULL. We have data.
    else:

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
                except:

                    # Invalid character value. Don't do string
                    # conversion of array.
                    bad = True
                    break

            # Return the byte array as a string if it makes sense.
            if (not bad):
                return r

        # Not a character byte array. Punt.
        try:
            return str(obj)
        except:
            return ''

def coerce_args_to_str(args):
    """
    Coerce a list of arguments to strings.
    Return the list of evaluated arguments.
    """
    # TODO: None should be converted to "", not "None"
    return [coerce_to_str(arg) for arg in args]
    # return map(lambda arg: str(arg), args)

def coerce_to_int(obj):
    """
    Coerce a constant VBA object (integer, Null, etc) to a int.
    :param obj: VBA object
    :return: int
    """
    # in VBA, Null/None is equivalent to 0
    if ((obj is None) or (obj == "NULL")):
        return 0

    # Do we have a float string?
    if (isinstance(obj, str)):

        # Float string?
        if ("." in obj):
            try:
                obj = float(obj)
            except:
                pass

        # Do we have a null byte string?
        if (obj.count('\x00') == len(obj)):
            return 0

        # Hex string?
        if ((obj.startswith("&H")) and (len(obj) <= 4)):
            return int(obj.replace("&H", "0x"), 16)

    # Try regular int.
    return int(obj)

def coerce_args_to_int(args):
    """
    Coerce a list of arguments to ints.
    Return the list of evaluated arguments.
    """
    return [coerce_to_int(arg) for arg in args]

def coerce_args(orig_args, preferred_type=None):
    """
    Coerce all of the arguments to either str or int based on the most
    common arg type.

    preferred_type = Preferred type to coerce things if possible.
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

        log.debug("Coerce to str " + str(new_args))
        return coerce_args_to_str(new_args)

    else:

        # Replace unititialized values.
        new_args = []
        for arg in args:
            if (args == "NULL"):
                new_args.append(0)
            else:
                new_args.append(arg)
                
        log.debug("Coerce to int " + str(new_args))
        return coerce_args_to_int(new_args)

def int_convert(arg):
    """
    Convert a VBA expression to an int, handling VBA NULL.
    """
    if (arg == "NULL"):
        return 0
    arg_str = str(arg)
    if ("." in arg_str):
        arg_str = arg_str[:arg_str.index(".")]
    try:
        return int(arg_str)
    except Exception as e:
        log.error("Cannot convert '" + str(arg_str) + "' to int. " + str(e))
        return 0

def str_convert(arg):
    """
    Convert a VBA expression to an str, handling VBA NULL.
    """
    if (arg == "NULL"):
        return ''
    return str(arg)

def strip_nonvb_chars(s):
    """
    Strip invalid VB characters from a string.
    """

    # Sanity check.
    if (not isinstance(s, str)):
        return s

    # Strip non-ascii printable characters.
    r = ""
    for c in s:
        if ((ord(c) > 8) and (ord(c) < 127)):
            r += c
    return r
