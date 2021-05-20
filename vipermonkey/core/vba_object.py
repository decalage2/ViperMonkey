"""@package vba_object Base class for all VBA objects and top level
functions for evaluating ViperMonkey VBA objects.

"""

# pylint: disable=pointless-string-statement
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

import logging
from logger import log
import re
from curses_ascii import isprint
import traceback
import hashlib

from inspect import getouterframes, currentframe
import sys
from datetime import datetime
import pyparsing

#import expressions
from var_in_expr_visitor import var_in_expr_visitor
from function_call_visitor import function_call_visitor
from lhs_var_visitor import lhs_var_visitor
from utils import safe_print
import utils
from utils import safe_str_convert
from let_statement_visitor import let_statement_visitor
from vba_context import Context
import excel

max_emulation_time = None

class VbaLibraryFunc(object):
    """Marker class to tell if a class emulates a VBA function.

    """

    def eval(self, context, params=None):
        """Emulate the VBScript/VBA function.
        
        @param context (Context object) The current program
        state. This will be updated.

        @param params (list) The function call parameters.

        @return (any) The result of emulating the function call.
        """
        context = context # pylint
        params = params # pylint
        
        raise ValueError("eval() method not implemented.")
        
    def num_args(self):
        """Get the # of arguments (minimum) required by the function.

        @return (int) The number of required arguments for the
        emulated function.

        """
        log.warning("Using default # args of 1 for " + safe_str_convert(type(self)))
        return 1

    def return_type(self):
        """Get the type returned from the emulated function ('INTEGER' or
        'STRING').

        @return (str) The function return type.

        """
        log.warning("Using default return type of 'INTEGER' for " + safe_str_convert(type(self)))
        return "INTEGER"

def limits_exceeded(throw_error=False):
    """Check to see if we are about to exceed the maximum recursion
    depth. Also check to see if emulation is taking too long (if
    needed).

    @param throw_error (boolean) If True throw an exception if the
    recursion depth or runtime has been exceeded.
    
    @return (boolean) True if the recursion depth or runtime has been
    exceeded, False if not.

    @throws RuntimeError This is thrown if throw_error is True and
    processing limits have been exceeded.

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
    """Base class for all VBA objects that can be evaluated.

    """

    # Upper bound for loop iterations. 0 or less means unlimited.
    loop_upper_bound = 10000000
    
    def __init__(self, original_str, location, tokens):
        """VBA_Object constructor, to be called as a parse action by a
        pyparsing parser

        @param original_str (str) original string matched by the
        parser.

        @param location (int) location of the match.

        @param tokens (PyParsing tokens thing) tokens extracted by the
        parser

        """
        self.original_str = original_str
        self.location = location
        self.tokens = tokens
        self._children = None
        self.is_useless = False
        self.is_loop = False
        self.exited_with_goto = False
        
    def eval(self, context, params=None):
        """Evaluate the current value of the object.

        @param context (Context object) Context for the evaluation
        (local and global variables). State updates will be reflected
        in the given context.

        @param params (list) Any parameters provided to the object.

        @return (any) The result of emulating the current object.

        """
        context = context # pylint
        params = params # pylint
        
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug(self)
        # raise NotImplementedError

    def __repr__(self):
        """Full string representation of the object.

        @return (str) Object as a string.

        """
        raise NotImplementedError("__repr__() not implemented in " + safe_str_convert(type(self)))
    
    def full_str(self):
        """Full string representation of the object.

        @return (str) Object as a string.

        """
        return safe_str_convert(self)
        
    def get_children(self):
        """Return the child VBA objects of the current object.

        @return (list) The children (VBA_Object objects) of the
        current object.

        """

        # Check for timeouts.
        limits_exceeded(throw_error=True)
        
        # The default behavior is to count any VBA_Object attribute as
        # a child.
        if ((hasattr(self, "_children")) and (self._children is not None)):
            return self._children
        r = []
        for _, value in self.__dict__.iteritems():
            if (isinstance(value, VBA_Object)):
                r.append(value)
            if isinstance(value, (list, pyparsing.ParseResults)):
                for i in value:
                    if (isinstance(i, VBA_Object)):
                        r.append(i)
            if (isinstance(value, dict)):
                for i in value.values():
                    if (isinstance(i, VBA_Object)):
                        r.append(i)
        self._children = r
        return r
                        
    def accept(self, visitor, no_embedded_loops=False):
        """Visitor design pattern support, Accept a visitor.
        
        @param visitor (visitor object) The visitor object to use to
        visit the current object and it's children.

        @param no_embedded_loops (boolean) Whether to skip visiting
        loops (While, For, etc.) in the current object.

        """

        # Check for timeouts.
        limits_exceeded(throw_error=True)
        
        # Skipping visiting embedded loops? Check to see if we are already
        # in a loop and the current VBA object is a loop.
        if (no_embedded_loops and
            hasattr(visitor, "in_loop") and
            visitor.in_loop and
            self.is_loop):
            #print "SKIPPING LOOP!!"
            #print self
            return

        # Set initial in loop status of visitor if needed.
        if (not hasattr(visitor, "in_loop")):
            visitor.in_loop = self.is_loop

        # Have we moved into a loop?
        if ((not visitor.in_loop) and (self.is_loop)):
            visitor.in_loop = True

        # Visit the current item.
        visit_status = visitor.visit(self)
        if (not visit_status):
            return

        # Save the in loop status so we can restore it after visiting the children.
        old_in_loop = visitor.in_loop
        
        # Visit all the children.
        for child in self.get_children():
            child.accept(visitor, no_embedded_loops=no_embedded_loops)

        # Back in current VBA object. Restore the in loop status.
        visitor.in_loop = old_in_loop

    def to_python(self, context, params=None, indent=0):
        """JIT compile this VBA object to Python code for direct emulation.

        @param context (Context object) Context for the Python code
        generation (local and global variables). Current program state
        will be read from the context.

        @param params (list) Any parameters provided to the object.
        
        @param indent (int) The number of spaces of indent to use at
        the beginning of the generated Python code.

        @return (str) The current object with it's emulation
        implemented as Python code.

        """
        raise NotImplementedError("to_python() not implemented in " + safe_str_convert(type(self)))

def _read_from_excel(arg, context):
    """Try to evaluate an argument by reading from the loaded Excel
    spreadsheet.

    @param arg (VBA_Object object) The argument to evaluate.

    @param context (Context object) The current program state.
    
    @return (any) The result of the evaluation on success, None on
    failure.

    """

    # Try handling reading value from an Excel spreadsheet cell.
    # ThisWorkbook.Sheets('YHRPN').Range('J106').Value
    if ("MemberAccessExpression" not in safe_str_convert(type(arg))):
        return None        
    arg_str = safe_str_convert(arg)
    if (("sheets(" in arg_str.lower()) and
        (("range(" in arg_str.lower()) or ("cells(" in arg_str.lower()))):
        
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Try as Excel cell read...")

        return arg.eval(context)

    # Not handled.
    return None

def _read_from_object_text(arg, context):
    """Try to read in a value from the text associated with a object like
    a Shape.

    @param arg (VBA_Object object) The argument to evaluate.

    @param context (Context object) The current program state.
    
    @return (any) The result of the evaluation on success, None on
    failure.

    """

    # Do we have an object text access?
    arg_str = safe_str_convert(arg)
    arg_str_low = arg_str.lower().strip()

    # Shapes('test33').      TextFrame.TextRange.text
    # Shapes('FrXXBbPlWaco').TextFrame.TextRange
    #
    # Make sure not to pull out Shapes() references that appear as arguments to function
    # calls.
    import expressions
    if (("shapes(" in arg_str_low) and (not isinstance(arg, expressions.Function_Call))):

        # Yes we do. 
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("eval_arg: Try to get as ....TextFrame.TextRange.Text value: " + arg_str.lower())

        # Handle member access?
        lhs = "Shapes('1')"
        if ("inlineshapes" in arg_str_low):
            lhs = "InlineShapes('1')"
        if ("MemberAccessExpression" in safe_str_convert(type(arg))):

            # Drop off ActiveDocument prefix.
            lhs = arg.lhs
            if ((safe_str_convert(lhs) == "ActiveDocument") or (safe_str_convert(lhs) == "ThisDocument")):
                lhs = arg.rhs[0]
        
            # Eval the leftmost prefix element of the member access expression first.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_obj_text: Old member access lhs = " + safe_str_convert(lhs))
            if ((hasattr(lhs, "eval")) and
                (not isinstance(lhs, pyparsing.ParseResults))):
                lhs = lhs.eval(context)
            else:

                # Look this up as a variable name.
                var_name = safe_str_convert(lhs)
                try:
                    lhs = context.get(var_name)
                except KeyError:
                    lhs = var_name

            if (lhs == "NULL"):
                lhs = "Shapes('1')"
            if ("inlineshapes" in arg_str_low):
                lhs = "InlineShapes('1')"
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_obj_text: Evaled member access lhs = " + safe_str_convert(lhs))
        
        # Try to get this as a doc var.
        doc_var_name = safe_str_convert(lhs) + ".TextFrame.TextRange.Text"
        doc_var_name = doc_var_name.replace(".TextFrame.TextFrame", ".TextFrame")
        if (("InlineShapes(" in doc_var_name) and (not doc_var_name.startswith("InlineShapes("))):
            doc_var_name = doc_var_name[doc_var_name.index("InlineShapes("):]
        elif (("Shapes(" in doc_var_name) and
              (not doc_var_name.startswith("Shapes(")) and
              ("InlineShapes(" not in doc_var_name)):
            doc_var_name = doc_var_name[doc_var_name.index("Shapes("):]
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("eval_obj_text: Looking for object text " + safe_str_convert(doc_var_name))
        val = context.get_doc_var(doc_var_name.lower())
        if (val is not None):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_obj_text: Found " + safe_str_convert(doc_var_name) + " = " + safe_str_convert(val))
            return val

        # Not found. Try looking for the object with index 1.
        lhs_str = safe_str_convert(lhs)
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
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("eval_arg: Fallback, looking for object text " + safe_str_convert(doc_var_name))
        val = context.get_doc_var(doc_var_name.lower())
        return val

    # Not handled.
    return None

def contains_excel(arg):
    """See if a given expression contains Excel book or sheet objects.

    @param arg (VBA_Object object) The argument to check.

    @return (boolean) True if the given VBA expression contains Excel
    book or sheet objects, False if not.

    """

    # Got actual Excel objects?
    if isinstance(arg, (excel.ExcelBook, excel.ExcelSheet)):
        return True
    
    # Got a function call?
    import expressions
    if (not isinstance(arg, expressions.Function_Call)):
        return False

    # Is this an Excel function call?
    excel_funcs = set(["usedrange", "sheets", "specialcells"])
    return (safe_str_convert(arg.name).lower() in excel_funcs)
    

constant_expr_cache = {}

def get_cached_value(arg):
    """Get the cached value of an all constant numeric expression if we
    have it.

    @param arg (VBA_Object object) The argument to check.

    @return (int or VBA_Object) The cached value of the all constant
    numeric expression if it is in the cache, the original given
    argument if not.

    """

    # Don't do any more work if this is already a resolved value.
    if isinstance(arg, (dict, int)):
        return arg

    # If it is something that may be hard to convert to a string, no cached value.
    if contains_excel(arg):
        return None

    # This is not already resolved to an int. See if we computed this before.
    arg_str = safe_str_convert(arg)
    if (arg_str not in constant_expr_cache.keys()):
        return None
    return constant_expr_cache[arg_str]

def set_cached_value(arg, val):
    """Set the cached value of an all constant numeric expression.

    @param arg (VBA_Object object) The unresolved expression to
    cache. 

    @param val (int, float, complex) The value of the resolved
    expression.

    """

    # We should be setting this to a numeric expression
    if ((not isinstance(val, int)) and
        (not isinstance(val, float)) and
        (not isinstance(val, complex))):
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.warning("Expression '" + safe_str_convert(val) + "' is a " + safe_str_convert(type(val)) + ", not an int. Not caching.")
        return

    # Don't cache things that contain Excel sheets or workbooks.
    if contains_excel(arg):
        return
        
    # We have a number. Cache it.
    arg_str = safe_str_convert(arg)
    try:
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Cache value of " + arg_str + " = " + safe_str_convert(val))
    except UnicodeEncodeError:
        pass
    constant_expr_cache[arg_str] = val
    
def is_constant_math(arg):
    """See if a given expression is a simple math expression with all
    literal numbers.

    @param arg (VBA_Object object) The expression to check.

    @return (boolean) True if this is a simple math expression with
    all numeric literals, False if not.

    """

    # Sanity check. If there are variables in the expression it is not all literals.
    if (isinstance(arg, VBA_Object)):
        var_visitor = var_in_expr_visitor()
        arg.accept(var_visitor)
        if (len(var_visitor.variables) > 0):
            return False

    # Some things are not math expressions.
    if (isinstance(arg, dict) or
        contains_excel(arg)):
        return False
        
    # Speed this up with the rure regex library if it is installed.
    try:
        import rure as local_re
    except ImportError:
        # Renaming of failed to import rure package.
        # pylint: disable=reimported
        import re as local_re

    # Use a regex to see if this is an all constant expression.
    base_pat = "(?:\\s*\\d+(?:\\.\\d+)?\\s*[+\\-\\*/]\\s*)*\\s*\\d+"
    paren_pat = base_pat + "|(?:\\((?:\\s*" + base_pat + "\\s*[+\\-\\*\\\\]\\s*)*\\s*" + base_pat + "\\))"
    arg_str = safe_str_convert(arg).strip()
    try:
        arg_str = unicode(arg_str)
    except UnicodeDecodeError:
        arg_str = filter(isprint, arg_str)
        arg_str = unicode(arg_str)
    return (local_re.match(unicode(paren_pat), arg_str) is not None)

def _handle_wscriptshell_run(arg, context, got_constant_math):
    """Handle cases where wscriptshell.run() is being called and there is
    a local run() function.

    @param arg (VBA_Object object) The item being evaluated.

    @param context (Context object) The current program state.
    
    @param got_constant_math (boolean) If True the given arg is an all
    numeric literal expression, if False it is not.
    
    @return (??) On success the evaluated item is returned, None is
    returned on error.

    """

    # Handle cases where wscriptshell.run() is being called and there is a local run() function.
    if ((".run(" in safe_str_convert(arg).lower()) and (context.contains("run"))):

        # Resolve the run() call.
        if ("MemberAccessExpression" in safe_str_convert(type(arg))):
            arg_evaled = arg.eval(context)
            if got_constant_math: set_cached_value(arg, arg_evaled)
            return arg_evaled

    # Not handled.
    return None

def _handle_shapes_access(r, arg, context, got_constant_math):
    """Finish handling a partially handled Shapes() access.

    @param arg (VBA_Object object) The item being evaluated.

    @param context (Context object) The current program state.
    
    @param got_constant_math (boolean) If True the given arg is an all
    numeric literal expression, if False it is not.
    
    @return (??) On success the evaluated item is returned, None is
    returned on error.

    """

    # Is this a Shapes() access that still needs to be handled?
    poss_shape_txt = ""
    if isinstance(r, (VBA_Object, str)):
        poss_shape_txt = safe_str_convert(r)
    if ((poss_shape_txt.startswith("Shapes(")) or (poss_shape_txt.startswith("InlineShapes("))):
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("eval_arg: Handling intermediate Shapes() access for " + safe_str_convert(r))
        r = eval_arg(r, context)
        if got_constant_math: set_cached_value(arg, r)
        return r

    # Not handled.
    return None

def _handle_nodetypedvalue_read(arg, context, got_constant_math):
    """Handle reads of the nodeTypedValue field of an object.

    @param arg (VBA_Object object) The item being evaluated.

    @param context (Context object) The current program state.
    
    @param got_constant_math (boolean) If True the given arg is an all
    numeric literal expression, if False it is not.
    
    @return (??) On success the evaluated item is returned, None is
    returned on error.

    """

    # This is a hack to get values saved in the .text field of objects.
    # To do this properly we need to save "FOO.text" as a variable and
    # return the value of "FOO.text" when getting "FOO.nodeTypedValue".
    if ("nodetypedvalue" in arg.lower()):
        try:
            tmp = arg.lower().replace("nodetypedvalue", "text")
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_arg: Try to get as " + tmp + "...")
            val = context.get(tmp)
    
            # It looks like maybe this magically does base64 decode? Try that.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_arg: Try base64 decode of '" + safe_str_convert(val) + "'...")
            val_decode = utils.b64_decode(val)
            if (val_decode is not None):
                if got_constant_math: set_cached_value(arg, val_decode)
                return val_decode
        except KeyError:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_arg: Not found as .text.")    

    # Not handled.
    return None                

def _handle_selected_item_read(arg, context, got_constant_math):
    """Handle reads of the selectedItem field of an object.

    @param arg (VBA_Object object) The item being evaluated.

    @param context (Context object) The current program state.
    
    @param got_constant_math (boolean) If True the given arg is an all
    numeric literal expression, if False it is not.
    
    @return (??) On success the evaluated item is returned, None is
    returned on error.
    """

    # This is a hack to get values saved in the .rapt.Value field of objects.
    if (".selecteditem" in arg.lower()):
        try:
            tmp = arg.lower().replace(".selecteditem", ".rapt.value")
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_arg: Try to get as " + tmp + "...")
            val = context.get(tmp)
            if got_constant_math: set_cached_value(arg, val)
            return val

        except KeyError:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_arg: Not found as .rapt.value.")    

    # Not handled.
    return None

# Read in Office file metadata.
meta = None

def _handle_form_variable_read(arg, context, got_constant_math):
    """Handle reading some VBA form variable (looks like reading a field
    of an object).

    @param arg (VBA_Object object) The item being evaluated.

    @param context (Context object) The current program state.
    
    @param got_constant_math (boolean) If True the given arg is an all
    numeric literal expression, if False it is not.
    
    @return (??) On success the evaluated item is returned, None is
    returned on error.

    """

    # Is this trying to access some VBA form variable?
    if ("." in arg.lower()):

        # Try easy button first. See if this is just a doc var.
        doc_var_val = context.get_doc_var(arg)
        if (doc_var_val is not None):
            if got_constant_math: set_cached_value(arg, doc_var_val)
            return doc_var_val

        # Peel off items seperated by a '.', trying them as functions.
        arg_peeled = arg
        while ("." in arg_peeled):
                
            # Try it as a form variable.
            curr_var_attempt = arg_peeled.lower()
            try:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("eval_arg: Try to load as variable " + curr_var_attempt + "...")
                val = context.get(curr_var_attempt)
                if (val != safe_str_convert(arg)):
                    if got_constant_math: set_cached_value(arg, val)
                    return val

            except KeyError:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("eval_arg: Not found as variable")

            arg_peeled = arg_peeled[arg_peeled.index(".") + 1:]

        # Try it as a function
        func_name = arg.lower()
        func_name = func_name[func_name.rindex(".")+1:]
        try:

            # Lookp and execute the function.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_arg: Try to run as function '" + func_name + "'...")
            func = context.get(func_name)
            r = func
            import procedures
            if (isinstance(func, (procedures.Function, procedures.Sub)) or
                ('vipermonkey.core.vba_library.' in safe_str_convert(type(func)))):
                r = eval_arg(func, context, treat_as_var_name=True)
                        
            # Did the function resolve to a value?
            if (r != func):

                # Yes it did. Return the function result.
                if got_constant_math: set_cached_value(arg, r)
                return r

            # The function did to resolve to a value. Return as the
            # original string.
            if got_constant_math: set_cached_value(arg, arg)
            return arg

        except KeyError:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_arg: Not found as function")

        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_arg: Failed. Not a function. " + safe_str_convert(e))
            traceback.print_exc()

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
            if (log.getEffectiveLevel() == logging.DEBUG):
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
            val = context.read_metadata_item(var)
            if (val is not None):
                return val
                    
        # Are we loading a document variable?
        if (tmp.startswith("activedocument.variables(")):

            # ActiveDocument.Variables("ER0SNQAWT").Value
            # Try to pull the result from the document variables.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_arg: handle expression as doc var lookup '" + tmp + "'")
            var = tmp.replace("activedocument.variables(", "").\
                  replace(")", "").\
                  replace("'","").\
                  replace('"',"").\
                  replace('.value',"").\
                  replace("(", "").\
                  strip()
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_arg: look for '" + var + "' as document variable...")
            val = context.get_doc_var(var)
            if (val is not None):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("eval_arg: got it as document variable.")
                return val
            else:
                if (log.getEffectiveLevel() == logging.DEBUG):
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
            tmp_name = wild_name + safe_str_convert(i)
            try:
                val = context.get(tmp_name)
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("eval_arg: Found '" + tmp + "' as wild card form variable '" + tmp_name + "'")
                return val
            except KeyError:
                pass    

    # Not handled.
    return None

def eval_arg(arg, context, treat_as_var_name=False):
    """Evaluate a single argument if it is a VBA_Object, otherwise return
    its value.

    @param arg (VBA_Object object) The item being evaluated.

    @param context (Context object) The current program state.
    
    @param treat_as_var_name (boolean) If True try to look up a
    variable with the given name, if False try to directly evaluate
    the given item.

    @return (??) On success the evaluated item is returned, None is
    returned on error.

    """

    # pypy seg faults sometimes if the recursion depth is exceeded. Try to
    # avoid that. Also check to see if emulation has taken too long.
    limits_exceeded(throw_error=True)

    if (log.getEffectiveLevel() == logging.DEBUG):
        log.debug("try eval arg: %s (%s, %s, %s)" % (arg, type(arg), isinstance(arg, VBA_Object), treat_as_var_name))

    # Is this a constant math expression?
    got_constant_math = is_constant_math(arg)
    
    # Do we have the cached value of this expression?
    cached_val = get_cached_value(arg)
    if (cached_val is not None):
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("eval_arg: Got cached value %r = %r" % (arg, cached_val))
        return cached_val
    
    # Try handling reading value from an Excel spreadsheet cell.
    excel_val = _read_from_excel(arg, context)
    if (excel_val is not None):
        if got_constant_math: set_cached_value(arg, excel_val)
        return excel_val

    # Short circuit the checks and see if we are accessing some object text first.
    obj_text_val = _read_from_object_text(arg, context)
    if (obj_text_val is not None):
        if got_constant_math: set_cached_value(arg, obj_text_val)
        return obj_text_val
    
    # Not reading from an Excel cell. Try as a VBA object.
    if isinstance(arg, (VBA_Object, VbaLibraryFunc)):

        # Handle cases where wscriptshell.run() is being called and there is a local run() function.
        tmp_r = _handle_wscriptshell_run(arg, context, got_constant_math)
        if (tmp_r is not None):
            return tmp_r

        # Handle as a regular VBA object.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("eval_arg: eval as VBA_Object %s" % arg)
        r = arg.eval(context=context)
        
        # Is this a Shapes() access that still needs to be handled?
        tmp_r = _handle_shapes_access(r, arg, context, got_constant_math)
        if (tmp_r is not None):
            return tmp_r

        # Regular VBA object.
        if got_constant_math: set_cached_value(arg, r)
        return r

    # Not a VBA object.
    else:
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("eval_arg: not a VBA_Object: %r" % arg)

        # Might this be a special type of variable lookup?
        if (isinstance(arg, str)):

            # Simple case first. Is this a variable?
            try:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("eval_arg: Try as variable name: %r" % arg)
                r = context.get(arg)
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("eval_arg: Got %r = %r" % (arg, r))
                if got_constant_math: set_cached_value(arg, r)
                return r
            except KeyError:
                    
                # No it is not. Try more complicated cases.
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("eval_arg: Not found as variable name: %r" % arg)
            else:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("eval_arg: Do not try as variable name: %r" % arg)

            # This is a hack to get values saved in the .text field of objects.
            # To do this properly we need to save "FOO.text" as a variable and
            # return the value of "FOO.text" when getting "FOO.nodeTypedValue".
            tmp_r = _handle_nodetypedvalue_read(arg, context, got_constant_math)
            if (tmp_r is not None):
                return tmp_r

            # This is a hack to get values saved in the .rapt.Value field of objects.
            tmp_r = _handle_selected_item_read(arg, context, got_constant_math)
            if (tmp_r is not None):
                return tmp_r

            # Is this trying to access some VBA form variable?
            tmp_r = _handle_form_variable_read(arg, context, got_constant_math)
            if (tmp_r is not None):
                return tmp_r

        # Should this be handled as a variable? Must be a valid var name to do this.
        if (treat_as_var_name and (re.match(r"[a-zA-Z_][\w\d]*", safe_str_convert(arg)) is not None)):

            # We did not resolve the variable. Treat it as unitialized.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_arg: return 'NULL'")
            return "NULL"

        # Are we referring to a form element that we cannot find?
        form_fields = [".tag", ".boundvalue", ".column", ".caption",
                       ".groupname", ".seltext", ".controltiptext",
                       ".passwordchar", ".controlsource", ".value"]
        for form_field in form_fields:
            if (safe_str_convert(arg).lower().endswith(form_field)):
                return ""
        
        # The .text hack did not work.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("eval_arg: return " + safe_str_convert(arg))
        return arg

def eval_args(args, context, treat_as_var_name=False):
    """Evaluate a list of arguments if they are VBA_Objects, otherwise
    return their value as-is.  

    @param args (list) The list of items (VBA_Object object) being
    evaluated.

    @param context (Context object) The current program state.
    
    @param treat_as_var_name (boolean) If True try to look up variable
    with the given names in the args list, if False try to directly
    evaluate the given items.

    @return (list) Return the list of evaluated arguments on success,
    the original args on failure.

    """

    # Punt if we can't iterate over the args.
    try:
        _ = iter(args)
    except TypeError:
        return args

    # Short circuit check to see if there are any VBA objects.
    got_vba_objects = False
    for arg in args:
        if (isinstance(arg, VBA_Object)):
            got_vba_objects = True
    if (not got_vba_objects):
        return args
    r = map(lambda arg: eval_arg(arg, context=context, treat_as_var_name=treat_as_var_name), args)
    return r

def update_array(old_array, indices, val):
    """Add an item to a Python list. This is called from Python JIT
    code.
    
    @param old_array (list) The Python list to update.
    
    @param indices (list) The indices of the array element to
    add/update.

    @param val (??) The value to write into the array.

    @return (list) The updated array.

    """

    # Sanity check.
    if (not isinstance(old_array, list)):
        old_array = []

    # 1-d array?
    if (len(indices) == 1):
        
        # Do we need to extend the length of the list to include the indices?
        index = int(indices[0])
        if (index >= len(old_array)):
            old_array.extend([0] * (index - len(old_array) + 1))
        old_array[index] = val

    # 2-d array?
    elif (len(indices) == 2):

        # Do we need to extend the length of the list to include the indices?
        index = int(indices[0])
        index1 = int(indices[1])
        if (index >= len(old_array)):
            # NOTE: Don't do 'old_array.extend([[]] * (index - len(old_array) + 1))' here.
            # The [] added with extend refers to the same list so any modification
            # to 1 sublist shows up in all of them.
            for _ in range(0, (index - len(old_array) + 1)):
                old_array.append([])
        if (index1 >= len(old_array[index])):
            old_array[index].extend([0] * (index1 - len(old_array[index]) + 1))
        old_array[index][index1] = val
        
    # Done.
    return old_array

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
