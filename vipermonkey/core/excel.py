"""
ViperMonkey: Partial version of xlrd.book object interface.

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

class ExcelSheet(object):

    def __init__(self, cells):
        self.cells = cells

    def cell(self, row, col):
        if ((row, col) in self.cells):
            return self.cells[(row, col)]
        raise KeyError("Cell (" + str(row) + ", " + str(col) + ") not found.")

    def cell_value(self, row, col):
        return self.cell(row, col)
    
class ExcelBook(object):

    def __init__(self, cells):
        self.cells = cells

    def __repr__(self):
        r = ""
        for cell in self.cells.keys():
            r += str(cell) + "\t=\t'" + str(self.cells[cell]) + "'\n"
        return r
        
    def sheet_names(self):
        return ["Sheet1"]

    def sheet_by_index(self, index):
        return ExcelSheet(self.cells)

    def sheet_by_name(self, name):
        return ExcelSheet(self.cells)

def make_book(cell_data):
    return ExcelBook(cell_data)
