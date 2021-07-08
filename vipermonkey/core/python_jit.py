"""@package vipermonkey.core.python_jit Core functions for converting
VBScript/VBA to Python and for executing the Python JIT code.

"""

# pylint: disable=pointless-string-statement
"""
ViperMonkey: Core functions for converting VBScript/VBA to Python.

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

__version__ = '0.03'

# --- IMPORTS ------------------------------------------------------------------
import hashlib
import traceback
import re
import sys

from curses_ascii import isprint
import pyparsing
import logging
from logger import log

from utils import safe_print, safe_str_convert
from vba_context import Context
from vba_object import VBA_Object, VbaLibraryFunc
from function_call_visitor import function_call_visitor
import utils
from lhs_var_visitor import lhs_var_visitor
from var_in_expr_visitor import var_in_expr_visitor
from let_statement_visitor import let_statement_visitor

def _boilerplate_to_python(indent):
    """Get starting boilerplate code for VB to Python JIT code.

    @param indent (int) The number of spaces to indent the generated
    Python code.
    
    @return (str) The boilerplate Python code for the beginning of a
    Python JIT code block.

    """
    indent_str = " " * indent
    boilerplate = indent_str + "import core.vba_library\n"
    boilerplate = indent_str + "import core.vba_context\n"
    boilerplate += indent_str + "from core.utils import safe_print\n"
    boilerplate += indent_str + "from core.utils import safe_str_convert\n"
    boilerplate += indent_str + "from core.utils import plus\n"
    boilerplate += indent_str + "from core.utils import eq\n"
    boilerplate += indent_str + "from core.utils import neq\n"
    boilerplate += indent_str + "import core.utils\n"
    boilerplate += indent_str + "from core.python_jit import update_array\n"
    boilerplate += indent_str + "from core.vba_conversion import coerce_to_num\n"
    boilerplate += indent_str + "from core.vba_conversion import coerce_to_int\n"
    boilerplate += indent_str + "from core.vba_conversion import coerce_to_str\n"
    boilerplate += indent_str + "from core.vba_conversion import coerce_to_int_list\n\n"
    boilerplate += indent_str + "try:\n"
    boilerplate += indent_str + " " * 4 + "vm_context\n"
    boilerplate += indent_str + "except (NameError, UnboundLocalError):\n"
    boilerplate += indent_str + " " * 4 + "vm_context = context\n"
    return boilerplate

def _get_local_func_type(expr, context):
    """Get the return type of a locally defined funtion given a call to
    the function.

    @param expr (VBA_Object object) The call of the function that will
    be used to infer the function return type.

    @param context (Context object) The current program state.
    
    @return (str) The function return type if known, None if not
    known.

    """

    # Sanity check.
    import expressions
    if (not isinstance(expr, expressions.Function_Call)):
        return None

    # Do we have the function definition?
    func_def = None
    try:
        func_def = context.get(expr.name)
    except KeyError:
        return None

    # Return the return type of the called function.
    if (hasattr(func_def, "return_type")):
        return func_def.return_type
    return None
        
def _infer_type_of_expression(expr, context):
    """Try to determine if a given expression is an "INTEGER" or "STRING"
    expression.

    @param expr (VBA_Object object) The expression for which to infer
    the type.
    
    @param context (Context object) The current program state.

    @return (str) The type of the expression if known ("STRING" or
    "INTEGER"), None if not known.

    """

    import operators
    import vba_library

    #print "LOOK FOR TYPE"
    #print expr
    #print type(expr)

    # Function with a hard coded type?
    if (hasattr(expr, "return_type")):
        #print "POSSIBLE TYPE (1) '" + safe_str_convert(expr) + "' == " + safe_str_convert(expr.return_type())
        return expr.return_type()

    # Call of function?
    import expressions
    if (isinstance(expr, expressions.Function_Call)):

        # Call of builtin function?
        if (expr.name.lower() in vba_library.VBA_LIBRARY):
            builtin = vba_library.VBA_LIBRARY[expr.name.lower()]
            if (hasattr(builtin, "return_type")):
                #print "POSSIBLE TYPE (2.1) '" + safe_str_convert(expr) + "' == " + safe_str_convert(builtin.return_type())
                return builtin.return_type()

        # Call of locally defined function.
        r = _get_local_func_type(expr, context)
        #print "POSSIBLE TYPE (2.2) '" + safe_str_convert(expr) + "' == " + safe_str_convert(r)
        return r
        
    # Easy cases. These have to be integers.
    if isinstance(expr, (operators.And,
                         operators.Division,
                         operators.FloorDivision,
                         operators.Mod,
                         operators.MultiDiv,
                         operators.Multiplication,
                         operators.Neg, operators.Not,
                         operators.Or,
                         operators.Power,
                         operators.Subtraction,
                         operators.Xor)):
        #print "POSSIBLE TYPE (3) '" + safe_str_convert(expr) + "' == " + "INTEGER"
        return "INTEGER"

    # Must be a string.
    if (isinstance(expr, operators.Concatenation)):
        #print "POSSIBLE TYPE (4) '" + safe_str_convert(expr) + "' == " + "STRING"
        return "STRING"
    
    # Harder case. This could be an int or a str (or some other numeric type, but
    # we're not handling that).
    if isinstance(expr, (expressions.BoolExpr, expressions.BoolExprItem, operators.AddSub)):

        # If we are doing subtraction we need numeric types.
        if ((hasattr(expr, "operators")) and ("-" in expr.operators)):
            #print "POSSIBLE TYPE (5) '" + safe_str_convert(expr) + "' == " + "INTEGER"
            return "INTEGER"
        
        # We have only '+'. Try to figure out the type based on the parts of the expression.
        r_type = None
        for child in expr.get_children():
            child_type = _infer_type_of_expression(child, context)
            if (child_type is not None):
                r_type = child_type
                #print "POSSIBLE TYPE (6) '" + safe_str_convert(child) + "' == " + safe_str_convert(r_type)
        return r_type

    # Can't figure out the type.
    #print "POSSIBLE TYPE (7) '" + safe_str_convert(expr) + "' == " + "UNKNOWN!!"
    return None
    
def _infer_type(var, code_chunk, context):
    """Try to infer the type of an undefined variable based on how it is
    used ("STRING" or "INTEGER").

    This is currently purely a heuristic.

    @param var (str) The name of the variable for which to infer the
    type.

    @param code_chunk (VBA_Object object) The chunk of code to scan to
    infer the type of the variable.

    @param context (Context object) The current program state.

    @return (tuple) A 2 element tuple, 1st element is the inferred
    type ("STRING" or "INTEGER") and the 2nd element is a flag
    indicating if we are sure of the type (True) or just guessing
    (False).

    """

    # Get all the assignments in the code chunk.
    visitor = let_statement_visitor(var)
    code_chunk.accept(visitor)

    # Look at each assignment statement and check out the ones where the current
    # variable is assigned.
    str_funcs = ["cstr(", "chr(", "left(", "right(", "mid(", "join(", "lcase(",
                 "replace(", "trim(", "ucase(", "chrw(", " & "]
    for assign in visitor.let_statements:

        # Try to infer the type somewhat logically.
        poss_type = _infer_type_of_expression(assign.expression, context)
        if ((poss_type is not None) and (poss_type != "UNKNOWN")):
            return (poss_type, True)
        
        # Does a VBA function that returns a string appear on the RHS?
        rhs = safe_str_convert(assign.expression).lower()
        for str_func in str_funcs:
            if (str_func in rhs):
                return ("STRING", True)

    # Does not look like a string, assume int.
    return ("INTEGER", False)

def _get_var_vals(item, context, global_only=False):
    """Get the current values for all of the referenced VBA variables
    that appear in the given VBA object.

    @param item (VBA_Object object) The chunk of code to scan to find
    referenced variables.

    @param context (Context object) The current program state.

    @param global_only (boolean) If True only return global variables,
    if False get all variables (local and global).
    
    @return (dict) Returns a dict mapping var names to values.

    """

    import procedures
    import statements

    # Get all the variables.

    # Vars on RHS.
    var_visitor = var_in_expr_visitor(context)
    item.accept(var_visitor, no_embedded_loops=False)
    var_names = var_visitor.variables

    # Vars on LHS.
    lhs_visitor = lhs_var_visitor()
    item.accept(lhs_visitor, no_embedded_loops=False)
    lhs_var_names = lhs_visitor.variables
    
    # Handle member access expressions.
    var_names = var_names.union(lhs_var_names)
    tmp = set()
    for var in var_names:
        tmp.add(var)
        if ("." in var):
            tmp.add(var[:var.index(".")])
    var_names = tmp

    # Handle With variables if needed.
    if (context.with_prefix_raw is not None):
        var_names.add(safe_str_convert(context.with_prefix_raw))
    
    # Get a value for each variable.
    r = {}
    zero_arg_funcs = set()
    for var in var_names:

        # Don't try to convert member access expressions that involve
        # method calls to Python variables. These should be handled
        # later as actual calls.
        if ("(" in var):
            continue

        # Do we already know the variable value?        
        val = None
        orig_val = None
        try:

            # Try to get the current value.
            val = context.get(var, global_only=global_only)
            orig_val = val
            
            # We have been kind of fuzzing the distinction between global and
            # local variables, so tighten down on globals only by just picking
            # up global variables that appear on the RHS but not LHS.
            if (global_only and (var in lhs_var_names)):
                continue
            
            # Do not set function arguments to new values.
            # Do not set loop index variables to new values.
            if ((val == "__FUNC_ARG__") or
                (val == "__ALREADY_SET__") or
                (val == "__LOOP_VAR__")):
                continue
            
            # Function definitions are not valid values.
            if isinstance(val, (VbaLibraryFunc, procedures.Function, procedures.Sub, statements.External_Function)):

                # Don't use the function definition as the value.
                val = None
                
                # 0 arg func calls should only appear on the RHS
                if (var not in lhs_var_names):
                    zero_arg_funcs.add(var)

                    # Don't treat these function calls as variables and
                    # assign initial values to them.
                    context.set("__ORIG__" + var, orig_val, force_local=True)
                    context.set("__ORIG__" + var, orig_val, force_global=True)
                    continue

            # 'inf' is not a valid value.
            val_str = None
            try:
                val_str = safe_str_convert(val).strip()
            except UnicodeEncodeError:
                val_str = filter(isprint, val).strip()
            if ((val_str == "inf") or
                (val_str == "-inf")):
                val = None

            # 'NULL' is not a valid value.
            if (val_str == "NULL"):
                val = None

            # Weird bug.
            if ("core.vba_library.run_function" in val_str):
                val = 0
            
        # Unedfined variable.
        except KeyError:
            if global_only:
                continue

        # Got a valid value for the variable?
        if (val is None):

            # Variable is not defined. Try to infer the type based on how it is used.
            #print "TOP LOOK TYPE: " + safe_str_convert(var)
            var_type, certain_of_type = _infer_type(var, item, context)
            #print (var_type, certain_of_type)
            if (var_type == "INTEGER"):
                val = "NULL"
                if certain_of_type:
                    #print "SET TYPE INT"
                    #print var
                    val = 0
                    context.set_type(var, "Integer")
            elif (var_type == "STRING"):
                val = ""
                if certain_of_type:
                    context.set_type(var, "String")
            else:
                log.warning("Type '" + safe_str_convert(var_type) + "' of var '" + safe_str_convert(var) + "' not handled." + \
                            " Defaulting initial value to \"NULL\".")
                val = "NULL"

        # Rename some vars that overlap with python builtins.
        var = utils.fix_python_overlap(var)
            
        # Save the variable value.
        r[var] = val

        # Save the regex pattern if this is a regex object.
        if (safe_str_convert(val) == "RegExp"):
            if (context.contains("RegExp.pattern")):
                pval = to_python(context.get("RegExp.pattern"), context)
                if (pval.startswith('"')):
                    pval = pval[1:]
                if (pval.endswith('"')):
                    pval = pval[:-1]
                r[var + ".Pattern"] = pval
            if (context.contains("RegExp.global")):
                gval = to_python(context.get("RegExp.global"), context)
                gval = gval.replace('"', "")
                if (gval == "True"):
                    gval = True
                if (gval == "False"):
                    gval = False
                r[var + ".Global"] = gval
        
        # Mark this variable as being set in the Python code to avoid
        # embedded loop Python code generation stomping on the value.
        context.set(var, "__ALREADY_SET__", force_local=True)
        context.set(var, "__ALREADY_SET__", force_global=True)
        
        # Save the original value so we know it's data type for later use in JIT
        # code generation.
        if (orig_val is None):
            orig_val = val
        context.set("__ORIG__" + var, orig_val, force_local=True)
        context.set("__ORIG__" + var, orig_val, force_global=True)
        
    # Done.
    return (r, zero_arg_funcs)

def _loop_vars_to_python(loop, context, indent):
    """Set up initialization of variables used in a loop in Python.

    @param loop (VBA_Object object) The loop for which to generate
    Python JIT variable initialization code.
    
    @param context (Context object) The current program state.

    @param indent (int) The number of spaces to indent the generated
    Python code.

    @return (str) Python JIT code initializing variables referenced in
    the given loop.

    """
    indent_str = " " * indent
    loop_init = ""
    init_vals, _ = _get_var_vals(loop, context)
    init_vals["got_vb_error"] = False
    sorted_vars = list(init_vals.keys())
    sorted_vars.sort()
    for var in sorted_vars:
        val = to_python(init_vals[var], context)
        var_name = safe_str_convert(var)
        if ((not var_name.endswith(".Pattern")) and
            (not var_name.endswith(".Global"))):
            var_name = var_name.replace(".", "")
        loop_init += indent_str + var_name + " = " + val + "\n"
    try:
        hash_object = hashlib.md5(safe_str_convert(loop).encode())
    except UnicodeDecodeError:
        hash_object = hashlib.md5(filter(isprint, safe_str_convert(loop)).encode())

    prog_var = "pct_" + hash_object.hexdigest()
    loop_init += indent_str + prog_var + " = 0\n"
    loop_init = indent_str + "# Initialize variables read in the loop.\n" + loop_init
    return (loop_init, prog_var)

# Track whether we are generating JIT code for a loop body or not.
in_loop = False

# Stack for saving old values of whether we are processing a loop body
# or not.
in_loop_stack = []

def enter_loop():
    """Track that we have started generating Python code for a loop body.

    """

    # Save whether we are currently in a loop or not.
    global in_loop
    in_loop_stack.append(in_loop)

    # We are now processing a loop body.
    in_loop = True

def exit_loop():
    """Track that we have stopped generating Python code for the current
    loop body. Note that loops can be nested so once the current loop body is
    done we can still be in a loop.

    """
    global in_loop
    if (len(in_loop_stack) > 0):
        in_loop = in_loop_stack.pop()
    else:
        log.warning("exit_loop() called with no matching enter_loop() call.")
        in_loop = False    

def to_python(arg, context, params=None, indent=0, statements=False):
    """Call arg.to_python() if arg is a VBAObject, otherwise just return
    arg as a str.

    @param arg (VBA_Object object) The code for which to generate
    Python JIT code.

    @param context (Context object) The current program state.

    @param params (list) Any VB params used by the given VBA_Object.

    @param indent (int) The number of spaces to indent the generated
    Python code.

    @param statements (boolean) If True the value given in the arg
    parameter is a list of VB statements (VBA_Object) to convert to
    Python, if False arg is just a single item to convert as a unit.

    """
        
    # VBA Object?
    r = None
    if (hasattr(arg, "to_python") and
        ((safe_str_convert(type(arg.to_python)) == "<type 'method'>") or
         (safe_str_convert(type(arg.to_python)) == "<type 'instancemethod'>"))):
        r = arg.to_python(context, params=params, indent=indent)

    # String literal?
    elif (isinstance(arg, str)):

        # Escape some characters.
        the_str = safe_str_convert(arg)
        the_str = safe_str_convert(the_str).\
                  replace("\\", "\\\\").\
                  replace('"', '\\"').\
                  replace("\n", "\\n").\
                  replace("\t", "\\t").\
                  replace("\r", "\\r")
        for i in range(0, 9):
            repl = hex(i).replace("0x", "")
            if (len(repl) == 1):
                repl = "0" + repl
            repl = "\\x" + repl
            the_str = the_str.replace(chr(i), repl)
        for i in range(11, 13):
            repl = hex(i).replace("0x", "")
            if (len(repl) == 1):
                repl = "0" + repl
            repl = "\\x" + repl
            the_str = the_str.replace(chr(i), repl)
        for i in range(14, 32):
            repl = hex(i).replace("0x", "")
            if (len(repl) == 1):
                repl = "0" + repl
            repl = "\\x" + repl
            the_str = the_str.replace(chr(i), repl)
        for i in range(127, 255):
            repl = hex(i).replace("0x", "")
            if (len(repl) == 1):
                repl = "0" + repl
            repl = "\\x" + repl
            the_str = the_str.replace(chr(i), repl)
        r = " " * indent + '"' + the_str + '"'

    # List of statements?
    elif (isinstance(arg, (list, pyparsing.ParseResults)) and statements):
        r = ""
        indent_str = " " * indent
        for statement in arg:
            r += indent_str + "try:\n"
            try:
                r += to_python(statement, context, indent=indent+4) + "\n"
            except Exception as e:
                #print statement
                #print e
                #traceback.print_exc(file=sys.stdout)
                #sys.exit(0)
                return "ERROR! to_python failed! " + safe_str_convert(e)
            r += indent_str + "except IndexError as e:\n"
            r += indent_str + " " * 4 + "safe_print(\"VB ERROR: \" + safe_str_convert(e))\n"
            if in_loop:
                # If we are in a loop break out of the loop and track that we have an error.
                r += indent_str + " " * 4 + "got_vb_error = True\n"
                r += indent_str + " " * 4 + "break\n"
            else:
                # If we are not in a loop pass the exception along.
                r += indent_str + " " * 4 + "raise(e)\n"
            r += indent_str + "except Exception as e:\n"
            if (log.getEffectiveLevel() == logging.DEBUG):
                r += indent_str + " " * 4 + "safe_print(\"ERROR: \" + safe_str_convert(e))\n"
            else:
                r += indent_str + " " * 4 + "pass\n"

    # Some other literal?
    else:
        arg_str = None
        try:
            arg_str = safe_str_convert(arg)
        except UnicodeEncodeError:
            arg_str = filter(isprint, arg)
        r = " " * indent + arg_str

    #print "--- to_python() ---"
    #print arg
    #print type(arg)
    #print r
        
    # Done.
    return r

def _check_for_iocs(loop, context, indent):
    """Generate Python JIT code for checking the variables modified in a
    loop to see if they were set to interesting IOCs.

    @param loop (VBA_Object object) The loop for which to generate
    Python JIT code.

    @param context (Context object) The current program state.

    @param indent (int) The number of spaces to indent the generated
    Python code.

    @return (str) Python JIT code checking variables modified in the
    loop for potential IOCs.

    """
    context = context # pylint
    
    indent_str = " " * indent
    lhs_visitor = lhs_var_visitor()
    loop.accept(lhs_visitor)
    lhs_var_names = lhs_visitor.variables
    ioc_str = indent_str + "# Check for IOCs in intermediate variables.\n"
    for var in lhs_var_names:
        py_var = utils.fix_python_overlap(var)
        ioc_str += indent_str + "try:\n"
        ioc_str += indent_str + " "*4 + "vm_context.save_intermediate_iocs(" + py_var + ")\n"
        ioc_str += indent_str + "except:\n"
        ioc_str += indent_str + " "* 4 + "pass\n"
    return ioc_str

def _updated_vars_to_python(loop, context, indent):
    """Generate Python JIT code for saving the variables updated in a loop
    in Python. These updates are saved in the Python var_updates
    variable.

    @param loop (VBA_Object object) The loop for which to generate
    Python JIT code.

    @param context (Context object) The current program state.

    @param indent (int) The number of spaces to indent the generated
    Python code.

    @return (str) Python JIT code.

    """
    import statements
    
    indent_str = " " * indent
    lhs_visitor = lhs_var_visitor()
    loop.accept(lhs_visitor)
    lhs_var_names = lhs_visitor.variables
    # Handle With variables if needed.
    if (context.with_prefix_raw is not None):
        lhs_var_names.add(safe_str_convert(context.with_prefix_raw))
    # Handle For loop index variables if needed.
    if (isinstance(loop, statements.For_Statement)):
        lhs_var_names.add(safe_str_convert(loop.name))
    var_dict_str = "{"
    first = True
    for var in lhs_var_names:
        py_var = utils.fix_python_overlap(var)
        if (not first):
            var_dict_str += ", "
        first = False
        var = var.replace(".", "")
        var_dict_str += '"' + var + '" : ' + py_var
    var_dict_str += "}"
    save_vals = indent_str + "try:\n"
    save_vals += indent_str + " " * 4 + "var_updates\n"
    save_vals += indent_str + " " * 4 + "var_updates.update(" + var_dict_str + ")\n"
    save_vals += indent_str + "except (NameError, UnboundLocalError):\n"
    save_vals += indent_str + " " * 4 + "var_updates = " + var_dict_str + "\n"
    save_vals += indent_str + 'var_updates["__shell_code__"] = core.vba_library.get_raw_shellcode_data()\n'
    save_vals = indent_str + "# Save the updated variables for reading into ViperMonkey.\n" + save_vals
    if (log.getEffectiveLevel() == logging.DEBUG):
        save_vals += indent_str + "print \"UPDATED VALS!!\"\n"
        save_vals += indent_str + "print var_updates\n"
    return save_vals

def _get_all_called_funcs(item, context):
    """Get all of the local functions called in the given VBA object.

    @param item (VBA_Object item) The code chunk to check for function
    calls.

    @param context (Context object) The current program state.

    @return (list) List of the function definitions (VBA_Object) of
    all the functions called in the code chunk.

    """

    # Get all the functions called in the VBA object.
    call_visitor = function_call_visitor()
    item.accept(call_visitor)
    func_names = call_visitor.called_funcs

    # Get all of the 0 argument functions called in the VBA object.
    tmp_context = Context(context=context, _locals=context.locals, copy_globals=True)
    _, zero_arg_funcs = _get_var_vals(item, tmp_context)
    func_names.update(zero_arg_funcs)
    
    # Get the definitions for all local functions called.
    local_funcs = []
    for func_name in func_names:
        if (context.contains(func_name)):
            curr_func = context.get(func_name)
            if (isinstance(curr_func, VBA_Object)):
                local_funcs.append(curr_func)

    # Done. Return the definitions of all the local functions
    # that were called.
    return local_funcs

def _called_funcs_to_python(loop, context, indent):
    """Convert all the functions called in the given loop to Python JIT
    code.

    @param loop (VBA_Object object) The loop for which to generate
    Python JIT code.

    @param context (Context object) The current program state.

    @param indent (int) The number of spaces to indent the generated
    Python code.

    @return (str) Python JIT code.

    """
    
    # Get the definitions for all local functions called directly in the loop.
    local_funcs = _get_all_called_funcs(loop, context)
    local_func_hashes = set()
    for curr_func in local_funcs:
        curr_func_hash = hashlib.md5(safe_str_convert(curr_func).encode()).hexdigest()
        local_func_hashes.add(curr_func_hash)
        
    # Now get the definitions of all the local functions called by the local
    # functions.
    seen_funcs = set()
    funcs_to_handle = list(local_funcs)
    while (len(funcs_to_handle) > 0):

        # Get the current function definition to check for calls.
        curr_func = funcs_to_handle.pop()
        curr_func_hash = hashlib.md5(safe_str_convert(curr_func).encode()).hexdigest()
        
        # Already looked at this one?
        if (curr_func_hash in seen_funcs):
            continue
        seen_funcs.add(curr_func_hash)

        # Get the functions called in the current function.
        curr_local_funcs = _get_all_called_funcs(curr_func, context)

        # Save the new functions for processing.
        for new_func in curr_local_funcs:
            new_func_hash = hashlib.md5(safe_str_convert(new_func).encode()).hexdigest()
            if (new_func_hash not in local_func_hashes):
                local_func_hashes.add(new_func_hash)
                local_funcs.append(new_func)
                funcs_to_handle.append(new_func)
                
    # Convert each local function to Python.
    r = ""
    for local_func in local_funcs:
        r += to_python(local_func, context, indent=indent) + "\n"

    # Done.
    indent_str = " " * indent
    r = indent_str + "# VBA Local Function Definitions\n" + r
    return r


# Cache JIT loop results to avoid emulating the exact same loop
# multiple times.
jit_cache = {}

def _eval_python(loop, context, params=None, add_boilerplate=False, namespace=None):
    """Convert the given loop to Python and emulate the loop directly in
    Python.

    @param loop (VBA_Object object) The loop for which to generate
    Python JIT code.

    @param context (Context object) The current program state.

    @param params (list) Any VB params used by the given loop.
    
    @param add_boilerplate (boolean) If True add setup boilerplate
    code (imports, etc.) to the start of the generated Python JIT
    code. Don't add boilerplate if False.

    @param namespace (dict) The Python namespace in which to evaluate
    the generated Python JIT code. If None the locals() namespace will
    be used.

    """
    params = params # pylint
    
    # Are we actually doing this?
    if (not context.do_jit):
        return False

    # Emulating full VB programs in Python is difficult, so for now skip loops
    # that Execute() dynamic VB.
    code_vba = safe_str_convert(loop).replace("\n", "\\n")[:20]
    if (not context.throttle_logging):
        log.info("Starting JIT emulation of '" + code_vba + "...' ...")
    if (("Execute(" in safe_str_convert(loop)) or
        ("ExecuteGlobal(" in safe_str_convert(loop)) or
        ("Eval(" in safe_str_convert(loop))):
        log.warning("Loop Execute()s dynamic code. Not JIT emulating.")
        return False
    
    # Generate the Python code for the VB code and execute the generated Python code.
    # TODO: Remove dangerous functions from what can be exec'ed.
    code_python = ""
    try:

        # For JIT handling we modify the values of certain variables to
        # handle recursive python code generation, so make a copy of the
        # original context.
        tmp_context = Context(context=context, _locals=context.locals, copy_globals=True)
        
        # Get the Python code for the loop.
        if (not context.throttle_logging):
            log.info("Generating Python JIT code...")
        code_python = to_python(loop, tmp_context)
        if add_boilerplate:
            var_inits, _ = _loop_vars_to_python(loop, tmp_context, 0)
            func_defns = _called_funcs_to_python(loop, tmp_context, 0)
            code_python = _boilerplate_to_python(0) + "\n" + \
                          func_defns + "\n" + \
                          var_inits + "\n" + \
                          code_python + "\n" + \
                          _check_for_iocs(loop, tmp_context, 0) + "\n" + \
                          _updated_vars_to_python(loop, tmp_context, 0)
        if (log.getEffectiveLevel() == logging.DEBUG):
            safe_print("JIT CODE!!")
            safe_print(code_python)
            #print "REMOVE THIS!!!"
            #sys.exit(0)
        if (not context.throttle_logging):
            log.info("Done generating Python JIT code.")

        # Extended ASCII strings are handled differently in VBScript and VBA.
        # Punt if we are emulating VBA and we have what appears to be extended ASCII
        # strings. For performance we are not handling the MS VBA extended ASCII in the python
        # JIT code.
        if (not context.is_vbscript):
            
            # Look for non-ASCII strings.
            non_ascii_pat = r'"[^"]*[\x7f-\xff][^"]*"'
            non_ascii_pat1 = r'"[^"]*(?:\\x7f|\\x[89a-f][0-9a-f])[^"]*"'
            if ((re.search(non_ascii_pat1, code_python) is not None) or
                (re.search(non_ascii_pat, code_python) is not None)):
                log.warning("VBA code contains Microsoft specific extended ASCII strings. Not JIT emulating.")
                return False

        # Check for dynamic code execution in called functions.
        if (('"Execute", ' in code_python) or
            ('"ExecuteGlobal", ' in code_python) or
            ('"Eval", ' in code_python)):
            log.warning("Functions called by loop Execute() dynamic code. Not JIT emulating.")
            return False
        
        # Run the Python code.
        
        # Have we already run this exact loop?
        if (code_python in jit_cache):
            var_updates = jit_cache[code_python]
            if (not context.throttle_logging):
                log.info("Using cached JIT loop results.")
            if (var_updates == "ERROR"):
                log.error("Previous run of Python JIT loop emulation failed. Using fallback emulation for loop.")
                return False

        # No cached results. Run the loop.
        elif (namespace is None):

            # JIT code execution goes not involve emulating VB GOTOs.
            context.goto_executed = False
        
            # Magic. For some reason exec'ing in locals() makes the dynamically generated
            # code recognize functions defined in the dynamic code. I don't know why.
            if (not context.throttle_logging):
                log.info("Evaluating Python JIT code...")
            exec code_python in locals()
        else:

            # JIT code execution goes not involve emulating VB GOTOs.
            context.goto_executed = False

            # Run the JIT code in the given namespace.
            exec(code_python, namespace)
            var_updates = namespace["var_updates"]
        if (not context.throttle_logging):
            log.info("Done JIT emulation of '" + code_vba + "...' .")

        # Cache the loop results.
        jit_cache[code_python] = var_updates
        
        # Update the context with the variable values from the JIT code execution.
        try:
            for updated_var in var_updates.keys():
                if (updated_var == "__shell_code__"):
                    continue
                context.set(updated_var, var_updates[updated_var])
        except (NameError, UnboundLocalError):
            log.warning("No variables set by Python JIT code.")

        # Update shellcode bytes from the JIT emulation.
        import vba_context
        vba_context.shellcode = var_updates["__shell_code__"]

    except NotImplementedError as e:
        log.error("Python JIT emulation of loop failed. " + safe_str_convert(e) + ". Using fallback emulation method for loop...")
        #safe_print("REMOVE THIS!!")
        #raise e
        return False

    except Exception as e:

        # Cache the error.
        jit_cache[code_python] = "ERROR"
        
        # If we bombed out due to a potential infinite loop we
        # are done.
        if ("Infinite Loop" in safe_str_convert(e)):
            log.warning("Detected infinite loop. Terminating loop.")
            return True

        # We had some other error. Emulating the loop in Python failed.
        log.error("Python JIT emulation of loop failed. " + safe_str_convert(e) + ". Using fallback emulation method for loop...")
        if (log.getEffectiveLevel() == logging.DEBUG):
            traceback.print_exc(file=sys.stdout)
            safe_print("-*-*-*-*-\n" + code_python + "\n-*-*-*-*-")
        return False

    # Done.
    return True

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
