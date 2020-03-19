"""
loop_transform.py - Transform certain types of loops into easier to emulate constructs.

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

import logging
import re

from logger import log
import statements

def _transform_dummy_loop1(loop):
    """
    Transform useless loops like 'y = 20:Do While x < 100:If x = 6 Then y = 30:x = x + 1:Loop' to
    'y = 30'
    """

    # Do we have this sort of loop?
    loop_pat = r"Do\s+While\s+(\w+)\s*<\s*(\d+)\r?\n.{0,500}?Loop"
    loop_str = loop.original_str
    if (re.search(loop_pat, loop_str, re.DOTALL) is None):
        return loop

    # Pull out the loop variable and loop upper bound.
    info = re.findall(loop_pat, loop_str, re.DOTALL)
    loop_var = info[0][0].strip()
    loop_ub = int(info[0][1].strip())
    
    # Pull out all the if statements that check to see if a variable is equal to
    # an integer constant.
    if_pat = r"If\s+\(?\s*(\w+)\s*=\s*(\d+)\s*\)\s+Then\s*\r?\n?(.{10,200}?)End\s+If"
    if_info = re.findall(if_pat, loop_str, re.DOTALL)
    if (len(if_info) == 0):
        return loop

    # Find all the if statements that will be taken if the loop runs to
    # completion.
    run_statements = []
    for curr_if in if_info:

        # Get the variable being tested.
        test_var = curr_if[0].strip()

        # Get the value it's being checked against.
        test_val = int(curr_if[1].strip())

        # Are we checking the loop variable?
        if (test_var != loop_var):
            continue

        # Is the value being checked less that the loop upper bound?
        if (test_val >= loop_ub):
            continue

        # The test will eventually succeed. Save the statement being executed.
        run_statement = curr_if[2].strip()
        if (run_statement.endswith("Else")):
            run_statement = run_statement[:-len("Else")]
        run_statements.append(run_statement)

    # Did we find some things that are guarenteed to run in the loop?
    if (len(run_statements) == 0):
        return loop

    # We have simple if-statements that will always execute in the loop.
    # Assume that this loop is only here to foil emulation and replace it with
    # the statements that will slways run from the loop.
    loop_repl = ""
    for run_statement in run_statements:
        loop_repl += run_statement + "\n"

    # Parse and return the loop replacement.
    import statements
    obj = statements.statement_block.parseString(loop_repl, parseAll=True)[0]
    return obj

def _transform_wait_loop(loop):
    """
    Transform useless loops like 'Do While x <> y:SomeFunctionCall():Loop' to
    'SomeFunctionCall()'
    """

    # Do we have this sort of loop?
    loop_pat = r"[Ww]hile\s+\w+\s*<>\s*\"?\w+\"?\r?\n.{0,500}?[Ww]end"
    loop_str = loop.original_str
    if (re.search(loop_pat, loop_str, re.DOTALL) is None):
        return loop

    # Is the loop body a function call?
    if ((len(loop.body) > 1) or (len(loop.body) == 0) or
        (not isinstance(loop.body[0], statements.Call_Statement))):
        return loop

    # Just do the call once.
    log.warning("Transformed possible infinite wait loop...")
    return loop.body[0]
    
def transform_loop(loop):
    """
    Transform a given VBAObject representing a loop into an easier to emulate construct.
    """

    # Sanity check.
    import statements
    if (not isinstance(loop, statements.While_Statement)):
        return loop
    
    # Try some canned transformations.
    r = _transform_dummy_loop1(loop)
    r = _transform_wait_loop(r)
    
    # Return the modified loop.
    return r
