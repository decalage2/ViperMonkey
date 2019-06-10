"""
ViperMonkey - Strip useles lines from Visual Basic code.

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


#------------------------------------------------------------------------------
# CHANGELOG:
# 2015-02-12 v0.01 PL: - first prototype
# 2015-2016        PL: - many changes
# 2016-10-06 v0.03 PL: - fixed vipermonkey.core import
# 2016-12-11 v0.04 PL: - fixed relative import for core package (issue #17)
# 2018-01-12 v0.05 KS: - lots of bug fixes and additions by Kirk Sayre (PR #23)
# 2018-06-20 v0.06 PL: - fixed issue #28, import prettytable
# 2018-08-17 v0.07 KS: - lots of bug fixes and additions by Kirk Sayre (PR #34)
#                  PL: - added ASCII art banner

#------------------------------------------------------------------------------
# TODO:
# TODO: detect subs/functions with same name (in different modules)
# TODO: can several projects call each other?
# TODO: Word XML with several projects?
# - cleanup main, use optionparser
# - option -e to extract and evaluate constant expressions
# - option -t to trace execution
# - option --entrypoint to specify the Sub name to use as entry point
# - use olevba to get all modules from a file
# Environ => VBA object
# vbCRLF, etc => Const (parse to string)
# py2vba: convert python string to VBA string, e.g. \" => "" (for olevba to scan expressions) - same thing for ints, etc?
#TODO: expr_int / expr_str
#TODO: eval(parent) => for statements to set local variables into parent functions/procedures + main VBA module
#TODO: __repr__ for printing
#TODO: Environ('str') => '%str%'
#TODO: determine the order of Auto subs for Word, Excel

# TODO later:
# - add VBS support (two modes?)

import sys
import re
from logger import log
import vba_context
from random import randint

def is_useless_dim(line):
    """
    See if we can skip this Dim statement and still successfully emulate.
    We only use Byte type information when emulating.
    """

    # Is this dimming a variable with a type we want to save? Also
    # keep Dim statements that set an initial value.
    line = line.strip()
    if (not line.startswith("Dim ")):
        return False
    r = (("Byte" not in line) and
         ("Long" not in line) and
         ("Integer" not in line) and
         (":" not in line) and
         ("=" not in line) and
         (not line.strip().endswith("_")))

    # Does the variable name collide with a builtin VBA function name? If so,
    # keep the Dim statement.
    line = line.lower()
    for builtin in vba_context.VBA_LIBRARY.keys():
        if (builtin in line):
            r = False

    # Done.
    return r

def is_interesting_call(line, external_funcs, local_funcs):

    # Is this an interesting function call?
    log_funcs = ["CreateProcessA", "CreateProcessW", ".run", "CreateObject",
                 "Open", "CreateMutex", "CreateRemoteThread", "InternetOpen",
                 ".Open", "GetObject", "Create", ".Create", "Environ",
                 "CreateTextFile", ".CreateTextFile", "Eval", ".Eval", "Run",
                 "SetExpandedStringValue", "WinExec", "URLDownloadToFile", "Print",
                 "Split"]
    log_funcs.extend(local_funcs)
    for func in log_funcs:
        if (func in line):
            return True

    # Are we calling an external function?
    for ext_func_decl in external_funcs:
        if (("Function" in ext_func_decl) and ("Lib" in ext_func_decl)):
            start = ext_func_decl.index("Function") + len("Function")
            end = ext_func_decl.index("Lib")
            ext_func = ext_func_decl[start:end].strip()
            if (ext_func in line):
                return True
        
    # Not a call we are tracking.
    return False

def is_useless_call(line):
    """
    See if the given line contains a useless do-nothing function call.
    """

    # These are the functions that do nothing if they appear on a line by themselves.
    # TODO: Add more functions as needed.
    useless_funcs = set(["Cos", "Log", "Cos", "Exp", "Sin", "Tan", "DoEvents"])

    # Is this an assignment line?
    if ("=" in line):
        return False

    # Nothing is being assigned. See if a useless function is called and the
    # return value is not used.
    line = line.replace(" ", "")
    called_func = line
    if ("(" in line):
        called_func = line[:line.index("(")]
    called_func = called_func.strip()
    for func in useless_funcs:
        if (called_func == func):
            return True
    return False

def collapse_macro_if_blocks(vba_code):
    """
    When emulating we only pick a single block from a #if statement. Speed up parsing
    by picking the largest block and strip out the rest.
    """

    # Pick out the largest #if blocks.
    log.debug("Collapsing macro blocks...")
    curr_blocks = None
    curr_block = None
    r = ""
    for line in vba_code.split("\n"):

        # Are we tracking an #if block?
        strip_line = line.strip()
        if (curr_blocks is None):

            # Is this the start of an #if block?
            if (strip_line.startswith("#If")):

                # Yes, start tracking blocks.
                log.debug("Start block " + strip_line)
                curr_blocks = []
                curr_block = []
                r += "' STRIPPED LINE\n"
                continue

            # Not the start of an #if. Save the line.
            r += line + "\n"
            continue

        # If we get here we are tracking an #if statement.

        # Is this the start of another block in the #if?
        if (strip_line.startswith("#Else")):

            # Save the current block.
            curr_blocks.append(curr_block)
            log.debug("Else if " + strip_line)
            log.debug("Save block " + str(curr_block))

            # Start a new block.
            curr_block = []
            r += "' STRIPPED LINE\n"
            continue

        # Have we finished the #if?
        if (strip_line.startswith("#End")):

            log.debug("End if " + strip_line)

            # Save the current block.
            curr_blocks.append(curr_block)
            
            # Add back in the largest block and skip the rest.
            biggest_block = []
            for block in curr_blocks:
                if (len(block) > len(biggest_block)):
                    biggest_block = block
            for block_line in biggest_block:
                r += block_line + "\n"
            log.debug("Pick block " + str(biggest_block))
                
            # Done processing #if.
            curr_blocks = None
            curr_block = None
            continue

        # We have a block line. Save it.
        curr_block.append(line)

    # Return the stripped VBA.
    return r

def fix_unbalanced_quotes(vba_code):
    """
    Fix lines with missing double quotes.
    """

    # Fix invalid string assignments.
    vba_code = re.sub(r"(\w+)\s+=\s+\"\r?\n", r'\1 = ""\n', vba_code)
    vba_code = re.sub(r"(\w+\s+=\s+\")(:[^\"]+)\r?\n", r'\1"\2\n', vba_code)
    vba_code = re.sub(r"([=>])\s*\"\s+[Tt][Hh][Ee][Nn]", r'\1 "" Then', vba_code)
    
    # See if we have lines with unbalanced double quotes.
    r = ""
    for line in vba_code.split("\n"):
        num_quotes = 0
        for c in line:
            if (c == '"'):
                num_quotes += 1
        if ((num_quotes % 2) != 0):
            last_quote = line.rindex('"')
            line = line[:last_quote] + '"' + line[last_quote:]
        r += line + "\n"

    # Return the balanced code.
    return r

def fix_multiple_assignments(line):

    # Pull out multiple assignments and the final assignment value.
    pat = r"((?:\w+\s*=\s*){2,})(.+)"
    items = re.findall(pat, line)
    if (len(items) == 0):
        return line
    items = items[0]
    assigns = items[0].replace(" ", "").split("=")
    val = items[1]

    # Break out each assignment into multiple lines.
    r = ""
    for var in assigns:
        var = var.strip()
        if (len(var) == 0):
            continue
        r += var + " = " + val + "\n"
    return r

def fix_skipped_1st_arg(vba_code):
    """
    Replace calls like foo(, 1, ...) with foo(SKIPPED_ARG, 1, ...).
    """

    # We don't want to replace things like this in string literals. Temporarily
    # pull out the string literals from the line.

    # Find all the string literals and make up replacement names.
    strings = {}
    in_str = False
    curr_str = None
    for c in vba_code:

        # Start/end of string?
        if (c == '"'):

            # Start of string?
            if (not in_str):
                curr_str = ""
                in_str = True

            # End of string.
            else:

                # Map a temporary name to the current string.
                str_name = "A_STRING_LITERAL_" + str(randint(0, 100000000))
                while (str_name in strings):
                    str_name = "A_STRING_LITERAL_" + str(randint(0, 100000000))
                curr_str += c
                strings[str_name] = curr_str
                in_str = False
                curr_str = None

        # Save the character if we are in a string.
        if (in_str):
            curr_str += c

    # Temporarily replace the string literals.
    tmp_code = vba_code
    for str_name in strings.keys():
        tmp_code = tmp_code.replace(strings[str_name], str_name)
            
    # Replace the skipped 1st arguments in calls.
    vba_code = re.sub(r"([0-9a-zA-Z_])\(\s*,", r"\1(SKIPPED_ARG,", tmp_code)

    # Put the string literals back.
    for str_name in strings.keys():
        vba_code = vba_code.replace(str_name, strings[str_name])

    # Return the modified code.
    return vba_code
    
def fix_vba_code(vba_code):
    """
    Fix up some substrings that ViperMonkey has problems parsing.
    """

    # Clear out lines broken up on multiple lines.
    vba_code = re.sub(r" _ *\r?\n", "", vba_code)
    vba_code = re.sub(r"\(_ *\r?\n", "(", vba_code)
    vba_code = re.sub(r":\s*[Ee]nd\s+[Ss]ub", r"\nEnd Sub", vba_code)

    # Clear out some garbage characters.
    vba_code = vba_code.replace('\x0b', '')
    #vba_code = vba_code.replace('\x88', '')
    
    # Fix function calls with a skipped 1st argument.
    vba_code = fix_skipped_1st_arg(vba_code)

    # Fix lines with missing double quotes.
    vba_code = fix_unbalanced_quotes(vba_code)

    # Change things like 'If+foo > 12 ..." to "If foo > 12 ...".
    r = ""
    for line in vba_code.split("\n"):

        # Fix up assignments like 'cat = dog = frog = 12'.
        line = fix_multiple_assignments(line)
        
        # Do we have an "if+..."?
        if ("if+" not in line.lower()):
            
            # No. No change.
            r += line + "\n"
            continue

        # Yes we do. Figure out if it is in a string.
        in_str = False
        window = "   "
        new_line = ""
        for c in line:

            # Start/End of string?
            if (c == '"'):
                in_str = not in_str

            # Have we seen an if+ ?
            if ((not in_str) and (c == "+") and (window.lower() == " if")):

                # Replace the '+' with a ' '.
                new_line += " "

            # No if+ .
            else:
                new_line += c
                
            # Advance the viewing window.
            window = window[1:] + c

        # Save the updated line.
        r += new_line + "\n"
        
    # Return the updated code.
    return r

def strip_line_nums(line):
    """
    Strip line numbers from the start of a line.
    """

    # Find the end of a number at the start of the line, if there is one.
    pos = 0
    for c in line:
        if (not c.isdigit()):
            break
        pos += 1
    return line[pos:]

def strip_useless_code(vba_code, local_funcs):
    """
    Strip statements that have no usefull effect from the given VB. The
    stripped statements are commented out.
    """

    # Preprocess the code to make it easier to parse.
    vba_code = fix_vba_code(vba_code)
        
    # Track data change callback function names.
    change_callbacks = set()    
    
    # Find all assigned variables and track what line the variable was assigned on.
    assign_re = re.compile("\s*(\w+(\.\w+)*)\s*=\s*")
    assigns = {}
    line_num = 0
    bool_statements = set(["If", "For", "Do"])
    external_funcs = []
    for line in vba_code.split("\n"):

        # Skip comment lines.
        if (line.strip().startswith("'")):
            log.debug("SKIP: Comment. Keep it.")
            continue
        
        # Save external function declarations lines so we can avoid stripping
        # calls to external functions.
        if (("Declare" in line) and ("Lib" in line)):
            external_funcs.append(line.strip())
        
        # Is this a change function callback?
        if (("Sub " in line) and ("_Change(" in line)):

            # Pull out the name of the data item with the current change callback.
            # ex: Private Sub besstirp_Change()
            data_name = line.replace("Sub ", "").\
                        replace("Private ", "").\
                        replace(" ", "").\
                        replace("()", "").\
                        replace("_Change", "").strip()
            change_callbacks.add(data_name)
        
        # Is there an assignment on this line?
        line_num += 1
        tmp_line = line
        if ("=" in line):
            tmp_line = line[:line.index("=") + 1]
        match = assign_re.findall(tmp_line)
        if (len(match) > 0):

            log.debug("SKIP: Assign line: " + line)
                
            # Skip starts of while loops.
            if (line.strip().startswith("While ")):
                log.debug("SKIP: While loop. Keep it.")
                continue

            # Skip multistatement lines.
            if (":" in line):
                log.debug("SKIP: Multi-statement line. Keep it.")
                continue

            # Skip function definitions.
            if ((line.strip().lower().startswith("if ")) or
                (line.strip().lower().startswith("elseif "))):
                log.debug("SKIP: If statement. Keep it.")
                continue
            
            # Skip function definitions.
            if (line.strip().lower().startswith("function ")):
                log.debug("SKIP: Function decl. Keep it.")
                continue

            # Skip const definitions.
            if (line.strip().lower().startswith("const ")):
                log.debug("SKIP: Const decl. Keep it.")
                continue
                
            # Skip lines that end with a continuation character.
            if (line.strip().endswith("_")):
                log.debug("SKIP: Continuation line. Keep it.")
                continue

            # Skip function definitions.
            if (("sub " in line.lower()) or ("function " in line.lower())):
                log.debug("SKIP: Function definition. Keep it.")
                continue

            # Skip calls to GetObject() or Shell().
            if (("GetObject" in line) or ("Shell" in line)):
                log.debug("SKIP: GetObject()/Shell() call. Keep it.")
                continue

            # Skip calls to various interesting calls.
            if (is_interesting_call(line, external_funcs, local_funcs)):
                continue
            
            # Skip lines where the '=' is part of a boolean expression.
            strip_line = line.strip()            
            skip = False
            for bool_statement in bool_statements:
                if (strip_line.startswith(bool_statement + " ")):
                    skip = True
                    break
            if (skip):
                continue

            # Skip lines assigning variables in a with block.
            if (strip_line.startswith(".") or (strip_line.lower().startswith("let ."))):
                continue

            # Skip lines where the '=' might be in a string.
            if ('"' in line):
                eq_index = line.index("=")
                qu_index1 =  line.index('"')
                qu_index2 =  line.rindex('"')
                if ((qu_index1 < eq_index) and (qu_index2 > eq_index)):
                    continue
            
            # Yes, there is an assignment. Save the assigned variable and line #
            log.debug("SKIP: Assigned vars = " + str(match))
            for var in match:

                # Skip empty.
                var = var[0]
                if (len(var.strip()) == 0):
                    continue
                
                # Keep lines where we may be running a command via an object.
                val = line[line.rindex("=") + 1:]
                if ("." in val):
                    continue

                # Keep object creations.
                if ("CreateObject" in val):
                    continue

                # Keep updates of the LHS where the LHS appears on the RHS
                # (ex. a = a + 1).
                if (var.lower() in val.lower()):
                    continue
                
                # It does not look like we are running something. Track the variable.
                if (var not in assigns):
                    assigns[var] = set()
                assigns[var].add(line_num)

    # Now do a very loose check to see if the assigned variable is referenced anywhere else.
    refs = {}
    for var in assigns.keys():
        # Keep assignments to variables in other streams since we cannot
        # tell based on the current stream whether the assignment is used.
        refs[var] = ("." in var)
    line_num = 0
    for line in vba_code.split("\n"):

        # Mark all the variables that MIGHT be referenced on this line.
        line_num += 1
        for var in assigns.keys():

            # Skip variable references on the lines where the current variable was assigned.
            if (line_num in assigns[var]):
                continue

            # Could the current variable be used on this line?
            if (var.lower() in line.lower()):

                # Maybe. Count this as a reference.
                log.debug("STRIP: Var '" + str(var) + "' referenced in line '" + line + "'.")
                refs[var] = True

    # Keep assignments that have change callbacks.
    for change_var in change_callbacks:
        for var in assigns.keys():
            refs[var] = ((change_var in var) or (var in change_var) or refs[var])
                
    # Figure out what assignments to strip and keep.
    comment_lines = set()
    keep_lines = set()
    for var in refs.keys():
        if (not refs[var]):
            for num in assigns[var]:
                comment_lines.add(num)
        else:
            for num in assigns[var]:
                keep_lines.add(num)

    # Multiple variables can be assigned on 1 line (a = b = 12). If any of the variables
    # on this assignment line are used, keep it.
    tmp = set()
    for l in comment_lines:
        if (l not in keep_lines):
            tmp.add(l)
    comment_lines = tmp
    
    # Now strip out all useless assignments.
    r = ""
    line_num = 0
    if_count = 0
    in_func = False
    for line in vba_code.split("\n"):

        # Strip line numbers from starts of lines.
        line = strip_line_nums(line)
        
        # Are we in a function?
        if (("End Sub" in line) or ("End Function" in line)):
            in_func = False
        elif (("Sub " in line) or ("Function " in line)):
            in_func = True
        
        # Keep track of if starts so we can match up end ifs.
        line_num += 1
        if (line.strip().startswith("If ")):
            if_count += 1

        # Do we have an unmatched 'end if'? If so, replace it with an
        # 'end function' to handle some Carbanak maldocs.
        #if (line.strip().startswith("End If")):
        #    if_count -= 1
        #    if (if_count < 0):
        #        r += "End Function\n"
        #        if_count = 0
        #        continue
        
        # Does this line get stripped based on variable usage?
        if ((line_num in comment_lines) and
            (not line.strip().startswith("Function ")) and
            (not line.strip().startswith("Sub ")) and
            (not line.strip().startswith("End Sub")) and
            (not line.strip().startswith("End Function"))):
            log.debug("STRIP: Stripping Line (1): " + line)
            r += "' STRIPPED LINE\n"
            continue

        # Does this line get stripped based on a useless function call?
        if (is_useless_call(line)):
            log.debug("STRIP: Stripping Line (2): " + line)
            r += "' STRIPPED LINE\n"
            continue

        # Does this line get stripped based on being a Dim that we will not use
        # when emulating?
        # TODO: Some of these are needed. Comment this out for now.
        #if ((in_func) and (is_useless_dim(line))):
        #    log.debug("STRIP: Stripping Line (3): " + line)
        #    r += "' STRIPPED LINE\n"
        #    continue

        # For now we are just stripping out class declarations. Need to actually
        # emulate classes somehow.
        if ((line.strip().startswith("Class ")) or (line.strip() == "End Class")):
            log.warning("Classes not handled. Stripping '" + line.strip() + "'.")
            continue

        # Also not handling Attribute statements at all.
        if (line.strip().startswith("Attribute ")):
            log.warning("Attribute statements not handled. Stripping '" + line.strip() + "'.")
            continue
            
        # The line is useful. Keep it.

        # At least 1 maldoc builder is not putting a newline before the
        # 'End Function' closing out functions. Rather than changing the
        # parser to deal with this we just fix those lines here.
        if ((line.endswith("End Function")) and
            (not line.strip().startswith("'")) and
            (len(line) > len("End Function"))):
            r += line.replace("End Function", "") + "\n"
            r += "End Function\n"
            continue

        # Fix Application.Run "foo, bar baz" type expressions by removing
        # the quotes.
        if (line.strip().startswith("Application.Run") and
            (line.count('"') == 2) and
            (line.strip().endswith('"'))):

            # Just directly run the command in the string.
            line = line.replace('"', '').replace("Application.Run", "")

            # Fix cases where the function to run is the 1st argument in the arg string.
            fields = line.split(",")
            if ((len(fields) > 1) and (" " not in fields[0].strip())):
                line = "WScript.Shell " + line
        
        # This is a regular valid line. Add it.
        r += line + "\n"

    # Now collapse down #if blocks.
    r = collapse_macro_if_blocks(r)

    return r
