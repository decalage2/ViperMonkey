"""@package vipermonkey.core.lhs_var_visitor Visitor for collecting
variables on the LHS of assignments in a VBA object.

"""

# pylint: disable=pointless-string-statement
"""
ViperMonkey: Visitor for collecting variables on the LHS of assignments.

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

import pyparsing

from visitor import visitor
from utils import safe_str_convert

class lhs_var_visitor(visitor):
    """Get the LHS of all Let statements. The variables on the LHSs of
    assignments are saved in the .variables field of the visitor object.

    """

    def __init__(self):
        self.variables = set()
        self.visited = set()
    
    def visit(self, item):
        if (safe_str_convert(item) in self.visited):
            return False
        self.visited.add(safe_str_convert(item))
        if ("Let_Statement" in safe_str_convert(type(item))):
            if (isinstance(item.name, str)):
                self.variables.add(item.name)
            elif (isinstance(item.name, pyparsing.ParseResults) and
                  (item.name[0].lower().replace("$", "").replace("#", "").replace("%", "") == "mid")):
                self.variables.add(safe_str_convert(item.name[1]))

        return True
