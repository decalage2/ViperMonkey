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

import logging
import sys
import re
try:
    # sudo pypy -m pip install rure
    import rure as re2
except:
    import re as re2
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

aggressive_strip = True
def is_interesting_call(line, external_funcs, local_funcs):

    # Is this an interesting function call?
    log_funcs = ["CreateProcessA", "CreateProcessW", ".run", "CreateObject",
                 "Open", "CreateMutex", "CreateRemoteThread", "InternetOpen",
                 ".Open", "GetObject", "Create", ".Create", "Environ",
                 "CreateTextFile", ".CreateTextFile", "Eval", ".Eval", "Run",
                 "SetExpandedStringValue", "WinExec", "URLDownloadToFile", "Print",
                 "Split", "Exec"]
    if (not aggressive_strip):
        log_funcs.extend(local_funcs)
    for func in log_funcs:
        if (func in line):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Line '" + line + "' contains interesting call (1) ('" + func + "').")
            return True

    # Are we calling an external function?
    for ext_func_decl in external_funcs:
        if (("Function" in ext_func_decl) and ("Lib" in ext_func_decl)):
            start = ext_func_decl.index("Function") + len("Function")
            end = ext_func_decl.index("Lib")
            ext_func = ext_func_decl[start:end].strip()
            if (ext_func in line):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Line '" + line + "' contains interesting call (2).")
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
    if (log.getEffectiveLevel() == logging.DEBUG):
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
                if (log.getEffectiveLevel() == logging.DEBUG):
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
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Else if " + strip_line)
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Save block " + str(curr_block))

            # Start a new block.
            curr_block = []
            r += "' STRIPPED LINE\n"
            continue

        # Have we finished the #if?
        if (strip_line.startswith("#End")):

            if (log.getEffectiveLevel() == logging.DEBUG):
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
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Pick block " + str(biggest_block))
                
            # Done processing #if.
            curr_blocks = None
            curr_block = None
            continue

        # We have a block line. Save it.
        curr_block.append(line)

    # Handle nested macro blocks.
    if (r.strip() != vba_code.strip()):
        r = collapse_macro_if_blocks(r)
        
    # Return the stripped VBA.
    return r

def fix_unbalanced_quotes(vba_code):
    """
    Fix lines with missing double quotes.
    """

    # Fix invalid string assignments.
    uni_vba_code = None
    try:
        uni_vba_code = vba_code.decode("utf-8")
    except UnicodeDecodeError:
        # Punt.
        return vba_code

    if (re2.search(u"(\w+)\s+=\s+\"\r?\n", uni_vba_code) is not None):
        vba_code = re.sub(r"(\w+)\s+=\s+\"\r?\n", r'\1 = ""\n', vba_code)
    if (re2.search(u"(\w+\s+=\s+\")(:[^\"]+)\r?\n", uni_vba_code) is not None):
        vba_code = re.sub(r"(\w+\s+=\s+\")(:[^\"]+)\r?\n", r'\1"\2\n', vba_code)
    if (re2.search(u"^\"[^=]*([=>])\s*\"\s+[Tt][Hh][Ee][Nn]", uni_vba_code) is not None):
        vba_code = re.sub(r"^\"[^=]*([=>])\s*\"\s+[Tt][Hh][Ee][Nn]", r'\1 "" Then', vba_code)
    
    # Fix ambiguous EOL comment lines like ".foo '' A comment". "''" could be parsed as
    # an argument to .foo or as an EOL comment. Here we change things like ".foo '' A comment"
    # to ".foo ' A comment" so it is not ambiguous (parse as comment).
    vba_code += "\n"
    vba_code = re.sub(r"'('[^'^\"]+\n)", r"\1", vba_code, re.DOTALL)

    # More ambiguous EOL comments. Something like "a = 12 : 'stuff 'more stuff" could have
    # 'stuff ' potentially parsed as a string. Just wipe out the comments in this case
    # (ex. "a = 12 : 'stuff 'more stuff" => "a = 12 :").
    vba_code = re.sub(r"(\n[^'^\n]+)'[^'^\"^\n]+'[^'^\"^\n]+\n", r"\1\n", vba_code, re.DOTALL)
    
    # Fix Execute statements with no space between the execute and the argument.
    vba_code = re.sub(r"\n\s*([Ee][Xx][Ee][Cc][Uu][Tt][Ee])\"", r'\nExecute "', vba_code)
    
    # See if we have lines with unbalanced double quotes.
    r = ""
    lines = vba_code.split("\n")
    pos = -1
    synthetic_line = False
    while (pos < (len(lines) - 1)):

        # Get the current line and next line.
        pos += 1
        if (not synthetic_line):
            line = lines[pos]
        synthetic_line = False
        next_line = ""
        if ((pos + 1) < len(lines)):
            next_line = lines[pos + 1]
            # Skip processing blank lines.
            while ((len(next_line.strip()) == 0) and
                   ((pos + 2) < len(lines))):
                r += next_line
                pos += 1
                next_line = lines[pos + 1]
        #print "---"
        #print str(pos) + ": " + line
        #print str(pos + 1) + ": " + next_line
        #print "***"
        if ('"' not in line):
            r += line + "\n"
            continue

        # Unmatched quotes?
        num_quotes = line.count('"')
        if ((num_quotes % 2) != 0):
            
            # Handle the special case of a misgenerated "\n" in a string.
            if (line.strip().endswith('"') and next_line.strip().startswith('"')):
                tmp_line = line + "\\n" + next_line
                #print "SYNTH:"
                #print tmp_line
                line = tmp_line
                synthetic_line = True
                continue
            
            first_quote = line.index('"')
            line = line[:first_quote] + '"' + line[first_quote:]
        r += line + "\n"

    # Return the balanced code.
    return r

MULT_ASSIGN_RE = r"((?:\w+\s*=\s*){2,})(.+)"
def fix_multiple_assignments(line):

    # Skip comments.
    if ("'" in line):
        line = line[:line.index("'")]
    
    # Pull out multiple assignments and the final assignment value.
    items = re.findall(MULT_ASSIGN_RE, line)
    if (len(items) == 0):
        return line

    # Don't count '=' that show up in strings.
    in_str = False
    new_line = ""
    for c in line:

        # Move in or out of strings.
        if (c == '"'):
            in_str = not in_str

        # Temporarily replace '=' in strings with 'IN_STR_EQUAL'.
        if ((c == '=') and (in_str)):
            new_line += 'IN_STR_EQUAL'
        else:
            new_line += c
            
    # Split into multiple assignments.
    items = re.findall(MULT_ASSIGN_RE, new_line)
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

    # Put back in the '=' that show up in strings.
    r.replace('IN_STR_EQUAL', '=')
    return r

def fix_skipped_1st_arg1(vba_code):
    """
    Replace calls like foo(, 1, ...) with foo(SKIPPED_ARG, 1, ...).
    """

    # Skipped this if unneeded.
    if (re.match(r".*[0-9a-zA-Z_\.]+\(\s*,.*", vba_code, re.DOTALL) is None):
        return vba_code
    
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
    vba_code = re.sub(r"([0-9a-zA-Z_\.]+)\(\s*,", r"\1(SKIPPED_ARG,", tmp_code)

    # Put the string literals.
    for str_name in strings.keys():
        vba_code = vba_code.replace(str_name, strings[str_name])
        
    # Return the modified code.
    return vba_code

def fix_skipped_1st_arg2(vba_code):
    """
    Replace calls like \nfoo, 1, ... with \nfoo SKIPPED_ARG, 1, ... .
    """

    # Skipped this if unneeded.
    if (re.match(r".*\n\s*([0-9a-zA-Z_\.\(\)]+)\s*,.*", vba_code, re.DOTALL) is None):
        #print "SKIPPED!!"
        return vba_code
    
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
    #print "HERE: 1"
    #print tmp_code
        
    # Find all paren exprs and make up replacement names.
    in_paren = False
    paren_count = 0
    parens = {}
    curr_paren = None
    for c in tmp_code:

        # Start/end of parenthesized expression?
        #print c
        if (c == '('):

            # Start of paren expr?
            paren_count += 1
            if (paren_count > 0):
                curr_paren = ""
                in_paren = True

        if (c == ')'): 

            # Out of parens?
            paren_count -= 1
            if (paren_count <= 0):
                
                # Map a temporary name to the current string.
                paren_count = 0
                in_paren = False
                if (curr_paren is not None):
                    paren_name = "A_PAREN_EXPR_" + str(randint(0, 100000000))
                    while (paren_name in parens):
                        str_name = "A_PAREN_EXPR_" + str(randint(0, 100000000))
                    curr_paren += c
                    parens[paren_name] = curr_paren
                    curr_paren = None

        # Save the character if we are in a paren expr.
        if (in_paren):
            curr_paren += c

    # Replace the paren exprs.
    for paren_name in parens.keys():
        tmp_code = tmp_code.replace(parens[paren_name], paren_name)
    #print "HERE: 2"
    #print tmp_code
        
    # Replace the skipped 1st arguments in calls.
    vba_code = re.sub(r"\n\s*([0-9a-zA-Z_\.]+)\s*,", r"\n\1 SKIPPED_ARG,", tmp_code)

    # Put the string literals and paren exprs back.
    for paren_name in parens.keys():
        vba_code = vba_code.replace(paren_name, parens[paren_name])
    for str_name in strings.keys():
        vba_code = vba_code.replace(str_name, strings[str_name])
        
    # Return the modified code.
    return vba_code

def fix_unhandled_array_assigns(vba_code):
    """
    Currently things like 'foo(1, 2, 3) = 1' are not handled.
    Comment them out.
    """

    uni_vba_code = None
    try:
        uni_vba_code = vba_code.decode("utf-8")
    except UnicodeDecodeError:
        # Punt.
        return vba_code
    
    pat = "\n(\s*\w+\((?:\w+\s*,\s*){2,}\w+\)\s*=)"
    if (re2.search(unicode(pat), uni_vba_code) is not None):
        vba_code = re.sub(pat, r"\n' UNHANDLED ARRAY ASSIGNMENT \1", vba_code) + "\n"
        fix_pat = r"' UNHANDLED ARRAY ASSIGNMENT\s+Mid\("
        vba_code = re.sub(fix_pat, r"Mid(", vba_code)
    return vba_code

def fix_unhandled_event_statements(vba_code):
    """
    Currently things like 'Event ...' are not handled.
    Comment them out.
    """

    uni_vba_code = None
    try:
        uni_vba_code = u"\n" + vba_code.decode("utf-8") + u"\n"
    except UnicodeDecodeError:
        # Punt.
        return vba_code
    
    pat = "\n( *Event[^\n]{10,})"
    if (re2.search(unicode(pat), uni_vba_code) is not None):
        vba_code = "\n" + vba_code + "\n"
        vba_code = re.sub(pat, r"\n' UNHANDLED EVENT STATEMENT \1", vba_code) + "\n"
    return vba_code

def fix_unhandled_raiseevent_statements(vba_code):
    """
    Currently things like 'RaiseEvent ...' are not handled.
    Comment them out.
    """

    uni_vba_code = None
    try:
        uni_vba_code = u"\n" + vba_code.decode("utf-8") + u"\n"
    except UnicodeDecodeError:
        # Punt.
        return vba_code
    
    pat = "\n( *RaiseEvent[^\n]{10,})"
    if (re2.search(unicode(pat), uni_vba_code) is not None):
        vba_code = "\n" + vba_code + "\n"
        vba_code = re.sub(pat, r"\n' UNHANDLED RAISEEVENT STATEMENT \1", vba_code) + "\n"
    return vba_code

def hide_string_content(s):
    """
    Replace contents of string literals with '____'.
    """
    if (not isinstance(s, str)):
        return s
    r = ""
    in_str = False
    for c in s:
        if (in_str):
            r += "_"
        else:
            r += c
        if (c == '"'):
            if (in_str):
                r += '"'
            in_str = not in_str
    return r

def convert_colons_to_linefeeds(vba_code):
    """
    Convert things like 'a=1:b=2' to 'a=1\n:b=2'
    """

    # Track the characters that start and end blocks of text we won't change.
    marker_chars = [('"', '"'), ('[', ']'), ("'", '\n')]

    # Loop through the text leaving some blocks unchanged and others with ':' changed to '\n'.
    pos = 0
    r = ""
    while (pos < (len(vba_code) - 1)):

        # Do we have any blocks of text coming up that we should not change?
        found_marker = False
        for marker, end_marker in marker_chars:

            # Do we have an unchangeable block?
            if (marker in vba_code[pos:]):
                
                # Find the chunk of text we should modify.
                found_marker = True
                marker_pos1 = vba_code[pos:].index(marker) + pos
                change_chunk = vba_code[pos:marker_pos1+1]
                change_chunk = change_chunk.replace(":", "\n")

                # Find the chunk of text to leave alone.
                marker_pos2 = len(vba_code)
                if (end_marker in vba_code[marker_pos1+1:]):
                    marker_pos2 = vba_code[marker_pos1+1:].index(end_marker) + marker_pos1 + 2
                leave_chunk = vba_code[marker_pos1+1:marker_pos2]
                
                # Save the modified chunk and the unmodified chunk.
                r += change_chunk + leave_chunk
                pos = marker_pos2
                break

        # If the whole remaining text string is modifiable just do the ':' -> '\n' on the
        # whole remaining string.
        if (not found_marker):
            r += vba_code[pos:].replace(":", "\n")
            pos = len(vba_code)

    # If the whole text string is modifiable just do the ':' -> '\n' on the
    # whole string.
    if (r == ""):
        r = vba_code

    # Done
    #print "******************"
    #print r
    #print "******************"
    #sys.exit(0)
    return r
    
def fix_difficult_code(vba_code):
    """
    Replace characters whose ordinal value is > 128 with dNNN, where NNN
    is the ordinal value.

    Also change things like "a!b!c" to "a.b.c".

    Also break up multiple statements seperated with '::' or ':' onto different lines.

    Also change assignments like "a =+ 1 + 2" to "a = 1 + 2".
    """

    # Targeted fix for some maldocs.
    #print "HERE: 1"
    vba_code = vba_code.replace("spli.tt.est", "splittest").replace("Mi.d", "Mid")
    vba_code = fix_unhandled_array_assigns(vba_code)
    vba_code = fix_unhandled_event_statements(vba_code)
    vba_code = fix_unhandled_raiseevent_statements(vba_code)
    # Bad double quotes.
    #print "HERE: 2"
    #vba_code = vba_code.replace("\xe2\x80", '"')
    #vba_code = vba_code.replace('\234"', '"')
    #vba_code = vba_code.replace('"\235', '"')

    # Not handling array accesses more than 2 deep.
    uni_vba_code = u""
    try:
        uni_vba_code = vba_code.decode("utf-8")
    except UnicodeDecodeError:
        log.warning("Converting VB code to unicode failed.")
    #print "HERE: 3"
    array_acc_pat = r'(\w+\([\d\w_\+\*/\-"]+\))(?:\([\d\w_\+\*/\-"]+\)){2,50}'
    if (re2.search(unicode(array_acc_pat), uni_vba_code) is not None):
        vba_code = re.sub(array_acc_pat, r"\1", vba_code)
    
    # Not handling this weird CopyHere() call.
    # foo.NameSpace(bar).CopyHere(baz), fubar
    uni_vba_code = u""
    try:
        uni_vba_code = vba_code.decode("utf-8")
    except UnicodeDecodeError:
        log.warning("Converting VB code to unicode failed.")
    #print "HERE: 4"
    namespace_pat = r"(\w+\.NameSpace\(.+\)\.CopyHere\(.+\)),\s*[^\n]+"
    if (re2.search(unicode(namespace_pat), uni_vba_code) is not None):
        vba_code = re.sub(namespace_pat, r"\1", vba_code)
    # CreateObject(foo).Namespace(bar).CopyHere baz, fubar
    uni_vba_code = u""
    try:
        uni_vba_code = vba_code.decode("utf-8")
    except UnicodeDecodeError:
        log.warning("Converting VB code to unicode failed.")
    #print "HERE: 5"
    namespace_pat = r"(CreateObject\(.+\).[Nn]ame[Ss]pace\(.+\)\.CopyHere\s+.+),\s*[^\n]+"
    if (re2.search(unicode(namespace_pat), uni_vba_code) is not None):
        vba_code = re.sub(namespace_pat, r"\1", vba_code)
    # foo.Run(bar) & baz, fubar    
    uni_vba_code = u""
    try:
        uni_vba_code = vba_code.decode("utf-8")
    except UnicodeDecodeError:
        log.warning("Converting VB code to unicode failed.")
    #print "HERE: 6"
    namespace_pat = r"(\w+\.Run\(.+\)[^,]*),\s*[^\n]+"
    if (re2.search(unicode(namespace_pat), uni_vba_code) is not None):
        #print "HERE: 6.1"
        vba_code = re.sub(namespace_pat, r"\1", vba_code)
    
    # We don't handle boolean expressions treated as integers. Comment them out.
    uni_vba_code = u""
    try:
        uni_vba_code = vba_code.decode("utf-8")
    except UnicodeDecodeError:
        log.warning("Converting VB code to unicode failed.")
    #print "HERE: 7"
    bad_bool_pat = r"\n\s*(?:(?:\w+(?:\(.+\))?(?:\.\w+)?\s*=)|Call)\s*[^" + r'"' + r"][^\n:']+[<>=]"
    if (re2.search(unicode(bad_bool_pat), uni_vba_code) is not None):
        bad_exps = re.findall(bad_bool_pat, vba_code)
        for bad_exp in bad_exps:

            # Don't count matches where the [<>=] is in a string literal.
            if ('"' in bad_exp):
                tmp_exp = hide_string_content(bad_exp)
                if (re.search(bad_bool_pat, tmp_exp) is None):
                    continue

            # Don't count multi-variable assignments.
            multi_pat = r"(?:\w+ *= *){2,}"
            if (re.search(multi_pat, bad_exp) is not None):
                continue
                
            # This is actually an integer expression with boolean logic.
            # Not handled.
            vba_code = vba_code.replace(bad_exp, "\n' UNHANDLED BOOLEAN INT EXPRESSION " + bad_exp[1:])

    # Comments like 'ddffd' at the end of an Else line are hard to parse.
    # Get rid of them.
    uni_vba_code = u""
    try:
        uni_vba_code = vba_code.decode("utf-8")
    except UnicodeDecodeError:
        log.warning("Converting VB code to unicode failed.")
    #print "HERE: 8"
    bad_else_pat = r"\n\s*Else\s*'.*\n"
    if (re2.search(unicode(bad_else_pat), uni_vba_code) is not None):
        bad_exps = re.findall(bad_else_pat, vba_code)
        for bad_exp in bad_exps:
            vba_code = vba_code.replace(bad_exp, "\nElse\n")
        
    # Skip this if it is not needed.
    #print "HERE: 9"
    if (("!" not in vba_code) and
        (":" not in vba_code) and
        ("&;" not in vba_code) and
        ("^" not in vba_code) and
        ("Rem " not in vba_code) and
        ("MultiByteToWideChar" not in vba_code) and
        (re.match(r".*[\x7f-\xff].*", vba_code, re.DOTALL) is None) and
        (re.match(r".*=\+.*", vba_code, re.DOTALL) is None)):
        return vba_code

    # Modify MultiByteToWideChar() calls so ViperMonkey can emulate them.
    # Orig: lSize = MultiByteToWideChar(CP_UTF8, 0, baValue(0), UBound(baValue) + 1, StrPtr(sValue), Len(sValue))
    # Desired: lSize = MultiByteToWideChar(CP_UTF8, 0, baValue, UBound(baValue) + 1, StrPtr("&sValue"), Len(sValue))
    #if ("MultiByteToWideChar" in vba_code):
    #    mbyte_pat = r"(MultiByteToWideChar\(\s*[^,]+,\s*[^,]+,\s+)([A-Za-z0-9_]+)\(\s*[^\)]+\s*\)(,\s*[^,]+,\s*StrPtr\(\s*)([^\)]+)(\s*\),\s*[^\)]+\))"
    #    vba_code = re.sub(mbyte_pat, r'\1\2\3"&\4"\5', vba_code)
    #
    # We are now handling the 'baValue(0)' part in expressions.Function_Call.__init__()
    # Now just do a general replace for StrPtr()
    #print "HERE: 10"
    if ("StrPtr" in vba_code):
        strptr_pat = r"(StrPtr\s*\(\s*)(\w+)(\s*\))"
        vba_code = re.sub(strptr_pat, r'\1"&\2"\3', vba_code)

    # Break out labels that are not on their own line.
    #print "HERE: 11"
    if (":" in vba_code):
        label_pat = r"(\n\s*\w+:)([^\n])"
        vba_code = re.sub(label_pat, r'\1\n\2', vba_code)

        # Replace colons in labels so they don't get broken up.
        label_pat = r"(\n\s*\w+):\s*\n"
        vba_code = re.sub(label_pat, r'\1__LABEL_COLON__\n', vba_code)
        
    # Temporarily replace macro #if, etc. with more unique strings. This is needed
    # to handle tracking '#...#' delimited date strings in the next loop.
    #print "HERE: 12"
    vba_code = vba_code.replace("#if", "HASH__if")
    vba_code = vba_code.replace("#If", "HASH__if")
    vba_code = vba_code.replace("#else", "HASH__else")    
    vba_code = vba_code.replace("#Else", "HASH__else")
    vba_code = vba_code.replace("#end if", "HASH__endif")
    vba_code = vba_code.replace("#End If", "HASH__endif")

    # Same thing with Put and Close of file descriptors.
    #print "HERE: 13"
    vba_code = re.sub(r"[Aa]s\s+#", "as__HASH", vba_code)
    vba_code = re.sub(r"[Pp]ut\s+#", "put__HASH", vba_code)
    vba_code = re.sub(r"[Gg]et\s+#", "get__HASH", vba_code)
    vba_code = re.sub(r"[Cc]lose\s+#", "close__HASH", vba_code)

    # Rewrite some weird single line if statements.
    # If utc_NegativeOffset Then: utc_Offset = -utc_Offset
    uni_vba_code = u""
    try:
        uni_vba_code = vba_code.decode("utf-8")
    except UnicodeDecodeError:
        log.warning("Converting VB code to unicode failed.")
    #print "HERE: 14"
    pat = r"(?i)If\s+.{1,100}\s+Then\s*:[^\n]{1,100}\n"
    if (re2.search(unicode(pat), uni_vba_code) is not None):
        for curr_if in re.findall(pat, vba_code):
            new_if = curr_if.replace("Then:", "Then ")
            vba_code = vba_code.replace(curr_if, new_if)
    
    # Replace the ':' in single line if statements so they don't get broken up.
    # If ip < ILen Then i2 = IBuf(ip): ip = ip + 1 Else i2 = Asc("A")
    # If op < OLen Then Out(op) = o1: op = op + 1
    #print "HERE: 15"
    uni_vba_code = u""
    try:
        uni_vba_code = vba_code.decode("utf-8")
    except UnicodeDecodeError:
        log.warning("Converting VB code to unicode failed.")
    #pat = r"(?i)^(?:Print)\s*If\s+.{1,100}\s+Then.{1,100}:.{1,100}(?:\s+Else.{1,100})?\n"
    pat = r"(?i)\n\s*If\s+.{1,100}\s+Then.{1,100}:.{1,100}(?:\s*Else.{1,100})?\n"
    single_line_ifs = []
    if (re2.search(unicode(pat), uni_vba_code) is not None):
        pos = 0
        for curr_if in re.findall(pat, vba_code):
            if_name = "HIDE_THIS_IF" + "_" * len(str(pos)) + str(pos)
            pos += 1
            vba_code = vba_code.replace(curr_if, "\n" + if_name + "\n")
            single_line_ifs.append((if_name, curr_if))
            
    # Replace ':=' so they don't get modified.
    #print "HERE: 16"
    vba_code = vba_code.replace(":=", "__COLON_EQUAL__")
        
    # Replace 'Rem fff' style comments with "' fff" comments.
    vba_code = vba_code.replace("\nRem ", "\n' ")
    vba_code = vba_code.replace(" Rem ", " ' ")

    # Replace ':' with new lines.
    #print "HERE: 17"
    vba_code = convert_colons_to_linefeeds(vba_code)
    
    # Characters that change how we modify the code.
    interesting_chars = [r'"', r'\#', r"'", r"!", r"\+",
                         r"PAT:[\x7f-\xff]", r"\^", ";",
                         r"\[", r"\]"]
    
    # Replace bad characters unless they appear in a string.
    in_str = False
    in_comment = False
    in_date = False    
    in_square_bracket = False
    num_square_brackets = 0
    prev_char = ""
    next_char = ""
    r = ""
    pos = -1
    #print "HERE: 18"
    while (pos < (len(vba_code) - 1)):

        #print "DONE: " + str((0.0 + pos)/len(vba_code)*100)
        # Are we looking at an interesting character?
        pos += 1
        c = vba_code[pos]
        if (pos > 1):
            prev_char = vba_code[pos - 1]
        if (pos < (len(vba_code) - 1)):
            next_char = vba_code[pos + 1]
        got_interesting = False
        curr_interesting_chars = interesting_chars
        if (in_comment):
            curr_interesting_chars.append("\n")
        for interesting_c in curr_interesting_chars:

            # Regex comparison?
            index = None
            if (interesting_c.startswith("PAT:")):
                interesting_c = interesting_c[len("PAT:"):]
                index = re.search(interesting_c, c)
                
            # Regular character comparison.
            else:
                if (c == interesting_c):
                    index = 0

            # Do we have an interesting character?
            if (index is None):

                # No, try the next one.
                continue

            # If we get here we have an interesting character.
            got_interesting = True
            break

        #print "--------"
        #print pos
        #print c
        #print prev_char
        #print next_char
        if (not got_interesting):

            # We are not. Fast forward to the nearest interesting character.
            next_pos = len(vba_code)

            # If we are in a string, we are only interested in getting out of the
            # string.
            curr_interesting_chars = interesting_chars
            if (in_str):
                curr_interesting_chars = [r'"']
            if (in_comment):
                curr_interesting_chars = ["\n"]

            # Find the next interesting character.
            for interesting_c in curr_interesting_chars:

                # Regex comparison?
                index = None
                if (interesting_c.startswith("PAT:")):
                    interesting_c = interesting_c[len("PAT:"):]
                    index = re.search(interesting_c, vba_code[pos:])
                    if (index is not None):
                        index = index.start()
                    
                # Looking for a single character.
                else:
                    if (interesting_c in vba_code[pos:]):
                        index = vba_code[pos:].index(interesting_c)

                # Is there an interesting character in the part of the string
                # left to process?
                if (index is None):

                    # No, try the next interesting character.
                    continue

                # Process the string starting at the interesting character we found.
                poss_pos = index + pos
                #print interesting_c
                #print pos
                #print poss_pos
                if (poss_pos < next_pos):
                    next_pos = poss_pos

            # Add in the chunk of characters that don't affect what we are doing.
            r += vba_code[pos:next_pos]
            #print "ADDED: '" + vba_code[pos:next_pos] + "'"

            # Jump to the position of the interesting character.
            pos = next_pos - 1
            continue
        
        # Handle entering/leaving strings.        
        if ((not in_comment) and (c == '"')):
            if (in_str):
                r += '"'
            in_str = not in_str
            #print "IN_STR: " + str(in_str)

        # Handle entering/leaving [] expressions.
        if ((not in_comment) and (not in_str)):
            if (c == '['):
                num_square_brackets += 1
            if (c == ']'):
                num_square_brackets -= 1
            in_square_bracket = (num_square_brackets > 0)
            
        # Handle entering/leaving date constants.
        if ((not in_comment) and (not in_str) and (c == '#')):

            # Entering date constant?
            if (not in_date):

                # Is this a # at the end of a variable decl?
                end = pos + 1
                if ((end < len(vba_code)) and (vba_code[end] != ",") and (vba_code[end] != "\n")):

                    # A date should be relatively short. See if the matching # is close.
                    end = pos + 60
                    if (end > len(vba_code)):
                        end = len(vba_code)
                    got_hash = False
                    for i in range(pos + 1, end):
                        if (vba_code[i] == "#"):
                            got_hash = True
                            break

                    # Only count entering a date constant if the closing # is close.
                    if (got_hash):
                        in_date = True

            # Leaving date constant?
            else:
                in_date = False

        # Handle entering/leaving comments.
        if ((not in_str) and (c == "'")):
            #print "IN COMMENT"
            in_comment = True
        if (c == "\n"):
            #print "OUT COMMENT"
            in_comment = False
            r += "\n"

        # Don't change things in strings or comments or dates.
        if (in_str or in_comment or in_date):
            #print "ADDED: '" + c + "'"
            r += c
            continue

        # Need to change "!" member access to "."?
        if ((c == "!") and (next_char.isalpha())):
            r += "."
            continue

        # Add spaces areound "^" operators.
        if (c == "^"):
            r += " ^ "
            continue

        # Need to eliminate bogus =+ assignments.
        if ((c == "+") and (prev_char == "=")):

            # Skip the '+'.
            continue

        # Need to eliminate bogus &; string concatenations.
        if ((c == ";") and (prev_char == "&")):

            # Skip the ';'.
            continue
            
        # Non-ASCII character that is not in a string?
        if (ord(c) > 127):
            r += "d" + str(ord(c))

    # Put the #if macros back.
    r = r.replace("HASH__if", "#If")
    r = r.replace("HASH__else", "#Else")
    r = r.replace("HASH__endif", "#End If")

    # Put the As, Put and Close statements back.
    r = r.replace("as__HASH", "As #")
    r = r.replace("put__HASH", "Put #")
    r = r.replace("get__HASH", "Get #")
    r = r.replace("close__HASH", "Close #")

    # Put the single line ifs back.
    for if_info in single_line_ifs:
        r = r.replace(if_info[0], if_info[1])

    # Put the colons for label statements back.
    r = r.replace("__LABEL_COLON__", ":")

    # Put ':=' back.
    r = r.replace("__COLON_EQUAL__", ":=")
    
    # Replace function calls being treated as labels.
    vba_code = "\n" + vba_code
    known_funcs = ["Randomize"]
    for func in known_funcs:
        r = r.replace("\n" + func + ":", "\n" + func)
    
    #print "******************"
    #print r
    #print "******************"
    #sys.exit(0)
    #print "HERE: 19"
    return r

def strip_comments(vba_code):
    """
    Strip comment lines from the VBA code.
    """

    # Sanity check.
    if ("'" not in vba_code):
        return vba_code

    # We have comments. Remove them.
    r = ""
    for curr_line in vba_code.split("\n"):

        # Save non-comment lines.
        if (not curr_line.strip().startswith("'")):
            r += curr_line + "\n"

    # Return extra newlines.
    r = r.replace("\n\n\n", "\n")
        
    # Return stripped code.
    return r

def fix_vba_code(vba_code):
    """
    Fix up some substrings that ViperMonkey has problems parsing.
    """

    # Strip comment lines from the code.
    vba_code = strip_comments(vba_code)
    
    # Fix dumb typo in some maldocs VBA.
    vba_code = vba_code.replace("End SubPrivate", "End Sub\nPrivate")

    # No null bytes in VB to process.
    vba_code = vba_code.replace("\x00", "")
    
    # Make "End Try" in try/catch blocks easier to parse.
    vba_code = re.sub(r"End\s+Try", "##End ##Try", vba_code)
    
    # We don't handle Line Input constructs for now. Delete them.
    # TODO: Actually handle Line Input consructs.
    linputs = re.findall(r"Line\s+Input\s+#\d+\s*,\s*\w+", vba_code, re.DOTALL)
    if (len(linputs) > 0):
        log.warning("VB Line Input constructs are not currently handled. Stripping them from code...")
    for linput in linputs:
        vba_code = vba_code.replace(linput, "")
    
    # We don't handle Property constructs for now. Delete them.
    # TODO: Actually handle Property consructs.
    props = re.findall(r"(?:Public\s+|Private\s+|Friend\s+)?Property\s+.+?End\s+Property", vba_code, re.DOTALL)
    if (len(props) > 0):
        log.warning("VB Property constructs are not currently handled. Stripping them from code...")
    for prop in props:
        vba_code = vba_code.replace(prop, "")

    # We don't handle Implements constructs for now. Delete them.
    # TODO: Figure out if we need to worry about Implements.
    implements = re.findall(r"Implements \w+", vba_code, re.DOTALL)
    if (len(implements) > 0):
        log.warning("VB Implements constructs are not currently handled. Stripping them from code...")
    for imp in implements:
        vba_code = vba_code.replace(imp, "")
        
    # We don't handle Enum constructs for now. Delete them.
    # TODO: Actually handle Enum consructs.
    enums = re.findall(r"(?:(?:Public|Private)\s+)?Enum\s+.+?End\s+Enum", vba_code, re.DOTALL)
    if (len(enums) > 0):
        log.warning("VB Enum constructs are not currently handled. Stripping them from code...")
    for enum in enums:
        vba_code = vba_code.replace(enum, "")

    # We don't handle ([a1]) constructs for now. Delete them.
    # TODO: Actually handle these things.
    brackets = re.findall(r"\(\[[^\]]+\]\)", vba_code, re.DOTALL)
    if (len(brackets) > 0):
        log.warning("([a1]) style constructs are not currently handled. Rewriting them...")
    for bracket in brackets:
        vba_code = vba_code.replace(bracket, "(" + bracket[2:-2] + ")")
    
    # Clear out lines broken up on multiple lines.
    vba_code = re.sub(r" _ *\r?\n", "", vba_code)
    vba_code = re.sub(r"&_ *\r?\n", "&", vba_code)
    vba_code = re.sub(r"\(_ *\r?\n", "(", vba_code)
    #vba_code = re.sub(r":\s*[Ee]nd\s+[Ss]ub", r"\nEnd Sub", vba_code)
    vba_code = "\n" + vba_code
    vba_code = re.sub(r"\n:", "\n", vba_code)

    # Some maldocs have single line member access expressions that end with a '.'.
    # Comment those out.
    dumb_member_exps = re.findall(r"\n(?:\w+\.)+\n", vba_code)
    for dumb_exp in dumb_member_exps:
        log.warning("Commenting out bad line '" + dumb_exp.replace("\n", "") + "'.")
        safe_exp = "\n'" + dumb_exp[1:]
        vba_code = vba_code.replace(dumb_exp, safe_exp)

    # How about maldocs with Subs with spaces in their names?
    space_subs = re.findall(r"\n\s*Sub\s*\w+\s+\w+\s*\(", vba_code)
    for space_sub in space_subs:
        start = space_sub.index("Sub") + len("Sub")
        end = space_sub.rindex("(")
        sub_name = space_sub[start:end]
        new_name = sub_name.replace(" ", "_")
        log.warning("Replacing bad sub name '" + sub_name + "' with '" + new_name + "'.")
        vba_code = vba_code.replace(sub_name, new_name)
    
    # Clear out some garbage characters.
    if (vba_code.count('\x0b') > 20):
        vba_code = vba_code.replace('\x0b', '')
    if (vba_code.count('\x88') > 20):
        vba_code = vba_code.replace('\x88', '')

    # It looks like VBA supports variable and function names containing
    # non-ASCII characters. Parsing these with pyparsing would be difficult
    # (or impossible), so convert the non-ASCII names to ASCII.
    #
    # Break up lines with multiple statements onto their own lines.
    vba_code = fix_difficult_code(vba_code)
    
    # Fix function calls with a skipped 1st argument.
    vba_code = fix_skipped_1st_arg1(vba_code)
    vba_code = fix_skipped_1st_arg2(vba_code)

    # Fix lines with missing double quotes.
    vba_code = fix_unbalanced_quotes(vba_code)

    # For each const integer defined, replace it inline in the code to reduce lookups
    vba_code = replace_constant_int_inline(vba_code)
    
    # Skip the next part if unnneeded.
    uni_vba_code = None
    try:
        uni_vba_code = vba_code.decode("utf-8")
    except UnicodeDecodeError:
        # Punt.
        return vba_code
    got_multassign = (re2.search(u"(?:\w+\s*=\s*){2}", uni_vba_code) is not None)
    if ((" if+" not in vba_code) and
        (" If+" not in vba_code) and
        ("\nif+" not in vba_code) and
        ("\nIf+" not in vba_code) and
        (not got_multassign)):
        return vba_code
    
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

def replace_constant_int_inline(vba_code):
    """
    Replace constant integer definitions inline, but leave the definition
    behind in case the regex fails.
    """

    const_pattern = re.compile("(?i)const ([a-zA-Z][a-zA-Z0-9]{0,20})\s?=\s?(\d+)")
    d_const = dict()

    for const in re.findall(const_pattern, vba_code):
        d_const[const[0]] = const[1]
        
    if len(d_const) > 0:
        log.info("Found constant integer definitions, replacing them.")
    for const in d_const:
        this_const = re.compile('(?i)(?<=(?:[(), ]))' + str(const) + '(?=(?:[(), ]))(?!\s*=)')
        vba_code = re.sub(this_const, str(d_const[const]), vba_code)
    return(vba_code)

def strip_line_nums(line):
    """
    Strip line numbers from the start of a line.
    """

    # Find the end of a number at the start of the line, if there is one.
    pos = 0
    for c in line:
        if (not c.isdigit()):
            # Don't delete numeric labels.
            if (c == ':'):
                return line
            break
        pos += 1
    return line[pos:]

external_funcs = []
def strip_useless_code(vba_code, local_funcs):
    """
    Strip statements that have no usefull effect from the given VB. The
    stripped statements are commented out.
    """

    # Preprocess the code to make it easier to parse.
    log.info("Modifying VB code...")
    vba_code = fix_vba_code(vba_code)
    
    # Don't strip lines if Execute() is called since the stripped variables
    # could be used in the execed code strings.
    exec_pat = r"execute(?:global)?\s*\("
    if (re.search(exec_pat, vba_code, re.IGNORECASE) is not None):
        return vba_code
    
    # Track data change callback function names.
    change_callbacks = set()    
    
    # Find all assigned variables and track what line the variable was assigned on.
    # Dim statements are counted as assignments.
    assign_re = re2.compile(u"(?:\s*(\w+(\.\w+)*)\s*=\s*)|(?:Dim\s+(\w+(\.\w+)*))")
    assigns = {}
    line_num = 0
    bool_statements = set(["If", "For", "Do"])
    global external_funcs
    for line in vba_code.split("\n"):

        # Skip comment lines.
        line_num += 1
        if (line.strip().startswith("'")):
            if (log.getEffectiveLevel() == logging.DEBUG):
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
        tmp_line = line
        if ("=" in line):
            tmp_line = line[:line.index("=") + 1]
        uni_tmp_line = ""
        try:
            uni_tmp_line = tmp_line.decode("utf-8")
        except UnicodeDecodeError:
            uni_tmp_line = tmp_line.decode("latin-1")
        match = assign_re.findall(uni_tmp_line)
        if (len(match) > 0):

            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("SKIP: Assign line: '" + line + "'. Line # = " + str(line_num))
                
            # Skip starts of while loops.
            if (line.strip().startswith("While ")):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("SKIP: While loop. Keep it.")
                continue

            # Skip calls to .create()
            if (".create" in line.strip().lower()):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("SKIP: .Create() call. Keep it.")
                continue

            # Skip multistatement lines.
            if (":" in line):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("SKIP: Multi-statement line. Keep it.")
                continue

            # Skip function definitions.
            if ((line.strip().lower().startswith("if ")) or
                (line.strip().lower().startswith("elseif "))):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("SKIP: If statement. Keep it.")
                continue
            
            # Skip function definitions.
            if (line.strip().lower().startswith("function ")):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("SKIP: Function decl. Keep it.")
                continue

            # Skip const definitions.
            if (line.strip().lower().startswith("const ")):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("SKIP: Const decl. Keep it.")
                continue
                
            # Skip lines that end with a continuation character.
            if (line.strip().endswith("_")):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("SKIP: Continuation line. Keep it.")
                continue

            # Skip lines that are a macro line.
            if (line.strip().startswith("#")):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("SKIP: macro line. Keep it.")
                continue

            # Skip function definitions.
            if (("sub " in line.lower()) or ("function " in line.lower())):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("SKIP: Function definition. Keep it.")
                continue

            # Skip calls to GetObject() or Shell().
            if (("GetObject" in line) or ("Shell" in line)):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("SKIP: GetObject()/Shell() call. Keep it.")
                continue

            # Skip Loop statements.
            if ("Loop " in line):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("SKIP: Loop statement. Keep it.")
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
                eq_index = -1
                if ("=" in line):
                    eq_index = line.index("=")
                qu_index1 = -1
                if ('"' in line):
                    qu_index1 =  line.index('"')
                qu_index2 = -1
                if ('"' in line):
                    qu_index2 =  line.rindex('"')
                if ((qu_index1 < eq_index) and (qu_index2 > eq_index)):
                    continue
            
            # Yes, there is an assignment. Save the assigned variable and line #
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("SKIP: Assigned vars = " + str(match) + ". Line # = " + str(line_num))
            for m in match:
                
                # Look at each matched variable.
                for var in m:

                    # Skip empty.
                    if ((var is None) or (len(var.strip()) == 0)):
                        continue

                    # Convert to ASCII.
                    var = var.encode("ascii","ignore")
                
                    # Keep lines where we may be running a command via an object.
                    val = ""
                    if ("=" in val):
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

        # Don't count actions in comments lines.
        line_num += 1
        if (line.strip().startswith("'")):
            continue
        
        # Mark all the variables that MIGHT be referenced on this line.
        for var in assigns.keys():
            
            # Skip variable references on the lines where the current variable was assigned.
            if (line_num in assigns[var]):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("STRIP: Var '" + str(var) + "' assigned in line '" + line + "'. Don't count as reference. " + " Line # = " + str(line_num))
                continue

            # Could the current variable be used on this line?
            if (var.lower() in line.lower()):

                # If we are aggressively stripping don't pay attention to debug.print.
                if (aggressive_strip and (line.lower().strip().startswith("debug.print "))):
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("STRIP: Var '" + str(var) + "' printed in '" + line + "'. Don't count as reference. " + " Line # = " + str(line_num))
                    continue
                
                # Maybe. Count this as a reference.
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("STRIP: Var '" + str(var) + "' referenced in line '" + line + "'. " + " Line # = " + str(line_num))
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

        # Does this line get stripped based on variable usage?
        if ((line_num in comment_lines) and
            (not line.strip().startswith("Function ")) and
            (not line.strip().startswith("Sub ")) and
            (not line.strip().startswith("End Sub")) and
            (not line.strip().startswith("End Function"))):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("STRIP: Stripping Line (1): " + line)
            r += "' STRIPPED LINE\n"
            continue

        # Does this line get stripped based on a useless function call?
        if (is_useless_call(line)):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("STRIP: Stripping Line (2): " + line)
            r += "' STRIPPED LINE\n"
            continue

        # For now we are just stripping out class declarations. Need to actually
        # emulate classes somehow.
        if ((line.strip().lower().startswith("class ")) or
            (line.strip().lower().startswith("end class"))):
            log.warning("Classes not handled. Stripping '" + line.strip() + "'.")
            continue

        # Also not handling Attribute statements at all.
        if (line.strip().startswith("Attribute ")):
            log.warning("Attribute statements not handled. Stripping '" + line.strip() + "'.")
            continue

        # Also not handling 'Selection.TypeText Text:="N6RF/L8ZMR3L2SZHTIC4ILCO' statements at all.
        if ('.TypeText Text:="' in line.strip()):
            log.warning("'.TypeText Text:=\"' statements not handled. Stripping '" + line.strip() + "'.")
            continue
            
        # The line is useful. Keep it.

        # Break up things like "Function foo(bar) a = 1 ..." to "Function foo(bar)\na = 1 ...".
        tmp_line = line.lower().strip()
        func_ret_pat = r"function\s+\w+\(.*\)(?:\s+as\s+\w+)?"
        if ((tmp_line.startswith("function ")) and
            (not tmp_line.endswith(")")) and
            (re.match(func_ret_pat + r"$", tmp_line) is None)):
            match_obj = re.match(func_ret_pat, tmp_line)
            if (match_obj is not None):
                pos = match_obj.span()[1]
                tmp_line = line[:pos] + "\n"
                if ((pos + 1) < len(line)):
                    tmp_line += line[pos + 1:]
                line = tmp_line
        
        # At least 1 maldoc builder is not putting a newline before the
        # 'End Function' closing out functions. Rather than changing the
        # parser to deal with this we just fix those lines here.
        if ((line.lower().endswith("end function")) and
            (not line.strip().startswith("'")) and
            (len(line) > len("End Function"))):
            tmp_line = line[:-len("End Function")]
            r += tmp_line + "\n"
            r += "End Function\n"
            continue
            
        # Fix Application.Run "foo, bar baz" type expressions by removing
        # the quotes.
        if (line.strip().startswith("Application.Run") and
            (re.match(r'Application\.Run\s+"[^"]+"', line) is not None) and
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
