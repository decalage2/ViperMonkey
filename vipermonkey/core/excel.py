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

import logging
from logger import log

def is_cell_dict(x):
    return (isinstance(x, dict) and ("value" in x))

def _get_alphanum_cell_index(row, col):
    """
    Convert a (row, col) cell index to a AB123 style index.
    """

    # Convert the column number to the corresponding alphabetic index.
    # Taken from https://stackoverflow.com/questions/181596/how-to-convert-a-column-number-e-g-127-into-an-excel-column-e-g-aa
    dividend = col
    column_name = ""
    modulo = 0
    while (dividend > 0):
        modulo = (dividend - 1) % 26
        column_name = chr(65 + modulo) + column_name
        dividend = int((dividend - modulo) / 26)

    # Return the alphanumeric cell index.
    return column_name + str(row)
        
def get_largest_sheet(workbook):
    """
    Get the sheet in a workbook with the most cells.
    """

    # Have we already computed this?
    if (hasattr(workbook, "__largest_sheet__")):
        return workbook.__largest_sheet__
    
    # Look at all the sheets.
    cells = []
    big_sheet = None
    for sheet_index in range(0, len(workbook.sheet_names())):
        
        # Try the current sheet.
        sheet = None
        try:
            sheet = workbook.sheet_by_index(sheet_index)
        except:
            return None

        # Read all the cells.
        curr_cells = pull_cells_sheet(sheet)
        if (curr_cells is None):
            curr_cells = []
                    
        # Does this sheet have the most cells?
        if (len(curr_cells) > len(cells)):
            cells = curr_cells
            big_sheet = sheet

    # Done.
    workbook.__largest_sheet__ = big_sheet
    return big_sheet

def get_num_rows(sheet):
    """
    Get the number of rows in an Excel sheet.
    """

    # Internal representation?
    if (hasattr(sheet, "num_rows")):
        return sheet.num_rows()

    # xlrd sheet?
    if (hasattr(sheet, "nrows")):
        return sheet.nrows

    # Unhandled sheet object.
    return 0

def get_num_cols(sheet):
    """
    Get the number of columns in an Excel sheet.
    """

    # Internal representation?
    if (hasattr(sheet, "num_cols")):
        return sheet.num_cols()

    # xlrd sheet?
    if (hasattr(sheet, "ncols")):
        return sheet.ncols

    # Unhandled sheet object.
    return 0

def _pull_cells_sheet_xlrd(sheet):
    """
    Pull all the cells from a xlrd Sheet object.
    """

    # Find the max row and column for the cells.
    if (not hasattr(sheet, "nrows") or
        not hasattr(sheet, "ncols")):
        log.warning("Cannot read all cells from xlrd sheet. Sheet object has no 'nrows' or 'ncols' attribute.")
        return None
    max_row = sheet.nrows
    max_col = sheet.ncols

    # Cycle through all the cells in order.
    curr_cells = []
    for curr_row in range(0, max_row + 1):
        for curr_col in range(0, max_col + 1):
            try:
                curr_cell_xlrd = sheet.cell(curr_row, curr_col)
                curr_cell = { "value" : curr_cell_xlrd.value,
                              "row" : curr_row + 1,
                              "col" : curr_col + 1,
                              "index" : _get_alphanum_cell_index(curr_row, curr_col) }
                curr_cells.append(curr_cell)
            except:
                pass

    # Return the cells.
    return curr_cells
            
def _pull_cells_sheet_internal(sheet):
    """
    Pull all the cells from a Sheet object defined internally in excel.py.
    """

    # We are going to use the internal cells field to build the list of all
    # cells, so this will only work with the ExcelSheet class defined in excel.py.
    if (not hasattr(sheet, "cells")):
        log.warning("Cannot read all cells from internal sheet. Sheet object has no 'cells' attribute.")
        return None
        
    # Cycle row by row through the sheet, tracking all the cells.

    # Find the max row and column for the cells.
    max_row = -1
    max_col = -1
    for cell_index in sheet.cells.keys():
        curr_row = cell_index[0]
        curr_col = cell_index[1]
        if (curr_row > max_row):
            max_row = curr_row
        if (curr_col > max_col):
            max_col = curr_col

    # Cycle through all the cells in order.
    curr_cells = []
    for curr_row in range(0, max_row + 1):
        for curr_col in range(0, max_col + 1):
            try:
                curr_cell = { "value" : sheet.cell(curr_row, curr_col),
                              "row" : curr_row + 1,
                              "col" : curr_col + 1,
                              "index" : _get_alphanum_cell_index(curr_row, curr_col) }
                curr_cells.append(curr_cell)
            except KeyError:
                pass

    # Return the cells.
    return curr_cells

def pull_cells_sheet(sheet):
    """
    Pull all the cells from an xlrd or internal Sheet object.
    """
    curr_cells = _pull_cells_sheet_xlrd(sheet)
    if (curr_cells is None):
        curr_cells = _pull_cells_sheet_internal(sheet)
    return curr_cells
    
def pull_cells_workbook(workbook):
    """
    Pull all the cells from all sheets in the given workbook.
    """

    # Cycle over all sheets.
    all_cells = []
    for sheet_index in range(0, len(workbook.sheet_names())):
            
        # Load the current sheet.
        sheet = None
        try:
            sheet = workbook.sheet_by_index(sheet_index)
        except:
            continue

        # Load the cells from this sheet.
        curr_cells = pull_cells_sheet(sheet)
        if (curr_cells is None):
            continue
        all_cells.extend(curr_cells)

    # Done.
    return all_cells

# --- IMPORTS ------------------------------------------------------------------

class ExcelSheet(object):

    def __init__(self, cells, name="Sheet1"):
        self.cells = cells
        self.name = name
        self.__num_rows = None
        self.__num_cols = None

    def __repr__(self):
        r = ""
        r += "Sheet: " + self.name + "\n\n"
        for cell in self.cells.keys():
            r += str(cell) + "\t=\t'" + str(self.cells[cell]) + "'\n"
        return r

    def num_rows(self):
        if (self.__num_rows is not None):
            return self.__num_rows
        max_row = -1
        for cell in self.cells.keys():
            curr_row = cell[0]
            if (curr_row > max_row):
                max_row = curr_row
        self.__num_rows = max_row
        return self.__num_rows

    def num_cols(self):
        if (self.__num_cols is not None):
            return self.__num_cols
        max_col = -1
        for cell in self.cells.keys():
            curr_col = cell[1]
            if (curr_col > max_col):
                max_col = curr_col
        self.__num_cols = max_col
        return self.__num_cols
    
    def cell(self, row, col):
        if ((row, col) in self.cells):
            return self.cells[(row, col)]
        raise KeyError("Cell (" + str(row) + ", " + str(col) + ") not found.")

    def cell_value(self, row, col):
        return self.cell(row, col)

    def cell_dict(self, row, col):
        curr_cell = { "value" : self.cell(row, col),
                      "row" : row + 1,
                      "col" : col + 1,
                      "index" : _get_alphanum_cell_index(row, col) }
        return curr_cell
    
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
