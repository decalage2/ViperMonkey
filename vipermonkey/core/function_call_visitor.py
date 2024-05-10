"""@package vipermonkey.core.function_call_visitor Visitor for
collecting the names of all called functions in a VBA object.

"""

# pylint: disable=pointless-string-statement
"""
ViperMonkey: Visitor for collecting the names of all called functions

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

from visitor import visitor
from utils import safe_str_convert

class function_call_visitor(visitor):
    """Collect the names of all called functions.

    """

    def __init__(self):
        self.called_funcs = set()
        self.visited = set()
    
    def visit(self, item):

        import statements
        import expressions
        import lib_functions

        if (item in self.visited):
            return False
        self.visited.add(item)
        if (isinstance(item, statements.Call_Statement)):
            if (not isinstance(item.name, expressions.MemberAccessExpression)):
                self.called_funcs.add(safe_str_convert(item.name))
        if (isinstance(item, expressions.Function_Call)):
            self.called_funcs.add(safe_str_convert(item.name))
        if (isinstance(item, statements.File_Open)):
            self.called_funcs.add("Open")
        if (isinstance(item, statements.Print_Statement)):
            self.called_funcs.add("Print")
        if (isinstance(item, lib_functions.Chr)):
            self.called_funcs.add("Chr")
        if (isinstance(item, lib_functions.Asc)):
            self.called_funcs.add("Asc")
        if (isinstance(item, lib_functions.StrReverse)):
            self.called_funcs.add("StrReverse")
        if (isinstance(item, lib_functions.Environ)):
            self.called_funcs.add("Environ")
        return True        
