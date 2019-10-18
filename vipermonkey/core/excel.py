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

    def __init__(self, cells, name="Sheet1"):
        self.cells = cells
        self.name = name

    def __repr__(self):
        r = ""
        r += "Sheet: " + self.name + "\n\n"
        for cell in self.cells.keys():
            r += str(cell) + "\t=\t'" + str(self.cells[cell]) + "'\n"
        return r
    
    def cell(self, row, col):
        if ((row, col) in self.cells):
            return self.cells[(row, col)]
        raise KeyError("Cell (" + str(row) + ", " + str(col) + ") not found.")

    def cell_value(self, row, col):
        return self.cell(row, col)
    
class ExcelBook(object):

    def __init__(self, cells=None, name="Sheet1"):

        # Create empty workbook to fill in later?
        self.sheets = []
        if (cells is None):
            return

        # Create single sheet workbook?
        self.sheets.append(ExcelSheet(cells, name))

    def __repr__(self):
        r = ""
        for sheet in self.sheets:
            r += str(sheet) + "\n"
        return r
        
    def sheet_names(self):
        r = []
        for sheet in self.sheets:
            r.append(sheet.name)
        return r

    def sheet_by_index(self, index):
        if (index < 0):
            raise ValueError("Sheet index " + str(index) + " is < 0")
        if (index >= len(self.sheets)):
            raise ValueError("Sheet index " + str(index) + " is > num sheets (" + str(len(self.sheets)) + ")")
        return self.sheets[index]

    def sheet_by_name(self, name):
        for sheet in self.sheets:
            if (sheet.name == name):
                return sheet
        raise ValueError("Sheet name '" + str(name) + "' not found.")

def make_book(cell_data):
    return ExcelBook(cell_data)
