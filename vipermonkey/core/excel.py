"""@package excel
Partial implementation of xlrd.book object interface and some Excel
functions.

"""

# pylint: disable=pointless-string-statement
"""
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

#import traceback
#import sys
from logger import log
import logging
import json
import os
import filetype
import random
import subprocess
try:
    import xlrd2 as xlrd
except ImportError:
    log.warning("xlrd2 Python package not installed. Falling back to xlrd.")
    import xlrd

_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
    
#debug = True
debug = False

def _read_sheet_from_csv(filename):
    """Read in an Excel sheet from a CSV file.

    @param fname (str) The name of the CSV file.

    @return (core.excel.ExceBook object) On success return the Excel
    sheet as an ExcelBook object. Returns None on error.

    """
    
    # Open the CSV file.
    f = None
    try:
        f = open(filename, 'r')
    except Exception as e:
        log.error("Cannot open CSV file. " + str(e))
        return None

    # Read in all the cells. Note that this only works for a single sheet.
    row = 0
    r = {}
    for line in f:

        # Escape ',' in cell values so the split works correctly.
        line = line.strip()
        in_str = False
        tmp = ""
        for c in line:
            if (c == '"'):
                in_str = not in_str
            if (in_str and (c == ',')):
                tmp += "#A_COMMA!!#"
            else:
                tmp += c
        line = tmp

        # Break out the individual cell values.
        cells = line.split(",")
        col = 0
        for cell in cells:

            # Add back in escaped ','.
            cell = cell.replace("#A_COMMA!!#", ",")

            # Strip " from start and end of value.
            dat = str(cell)
            if (dat.startswith('"')):
                dat = dat[1:]
            if (dat.endswith('"')):
                dat = dat[:-1]

            # LibreOffice escapes '"' as '""'. Undo that.
            dat = dat.replace('""', '"')

            # Save the cell value.
            r[(row, col)] = dat

            # Next column.
            col += 1
        row += 1

    # Close file.
    f.close()

    # Make an object with a subset of the xlrd book methods.
    r = make_book(r)
    #print("EXCEL:\n")
    #print(r)
    #sys.exit(0)
    return r

def load_excel_libreoffice(data):
    """Read in an Excel file into an ExcelBook object by using
    LibreOffice.

    @param data (str) The Excel file contents.

    @return (core.excel.ExceBook object) On success return the Excel
    spreadsheet as an ExcelBook object. Returns None on error.

    """
    
    # Don't try this if it is not an Office file.
    if (not filetype.is_office_file(data, True)):
        log.warning("The file is not an Office file. Not extracting sheets with LibreOffice.")
        return None
    
    # Save the Excel data to a temporary file.
    out_dir = "/tmp/tmp_excel_file_" + str(random.randrange(0, 10000000000))
    f = open(out_dir, 'wb')
    f.write(data)
    f.close()
    
    # Dump all the sheets as CSV files using soffice.
    output = None
    try:
        output = subprocess.check_output(["timeout", "30", "python3", _thismodule_dir + "/../export_all_excel_sheets.py", out_dir])
    except Exception as e:
        log.error("Running export_all_excel_sheets.py failed. " + str(e))
        os.remove(out_dir)
        return None

    # Get the names of the sheet files, if there are any.
    try:
        sheet_files = json.loads(output.replace("'", '"'))
    except Exception as e:
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Loading sheeti file names failed. " + str(e))
        os.remove(out_dir)
        return None
    if (len(sheet_files) == 0):
        os.remove(out_dir)
        return None

    # Load the CSV files into Excel objects.
    sheet_map = {}
    for sheet_file in sheet_files:

        # Read the CSV file into a single Excel workbook object.
        tmp_workbook = _read_sheet_from_csv(sheet_file)

        # Pull the cell data for the current sheet.
        cell_data = tmp_workbook.sheet_by_name("Sheet1").cells
        
        # Pull out the name of the current sheet.
        start = sheet_file.index("--") + 2
        end = sheet_file.rindex(".")
        sheet_name = sheet_file[start : end]

        # Pull out the index of the current sheet.
        start = sheet_file.index("-") + 1
        end = sheet_file[start:].index("-") + start
        sheet_index = int(sheet_file[start : end])
        
        # Make a sheet with the current name and data.
        tmp_sheet = ExcelSheet(cell_data, sheet_name)

        # Map the sheet to its index.
        sheet_map[sheet_index] = tmp_sheet

    # Save the sheets in the proper order into a workbook.
    result_book = ExcelBook(None)
    sorted_indices = list(sheet_map.keys())
    sorted_indices.sort()
    for index in sorted_indices:
        result_book.sheets.append(sheet_map[index])

    # Delete the temp files with the CSV sheet data.
    for sheet_file in sheet_files:
        os.remove(sheet_file)

    # Delete the temporary Excel file.
    if os.path.isfile(out_dir):
        os.remove(out_dir)
        
    # Return the workbook.
    return result_book
        
def load_excel_xlrd(data):
    """Read in an Excel file into an ExceBook object directly with the
    xlrd Excel library.

    @param data (str) The Excel file contents.

    @return (core.excel.ExceBook object) On success return the Excel
    spreadsheet as an ExcelBook object. Returns None on error.

    """
    
    # Only use this on Office 97 Excel files.
    if (not filetype.is_office97_file(data, True)):
        log.warning("File is not an Excel 97 file. Not reading with xlrd2.")
        return None

    # It is Office 97. See if we can read it with xlrd2.
    try:
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Trying to load with xlrd...")
        r = xlrd.open_workbook(file_contents=data)
        return r
    except Exception as e:
        log.error("Reading in file as Excel with xlrd failed. " + str(e))
        return None

def load_excel(data):
    """Load the cells from a given Excel spreadsheet. This first tries
    getting the sheet contents with LibreOffice if it is installed,
    and if that does not work try reading it with the Python xlrd
    package.

    @param data (str) The loaded Excel file contents.

    @return (core.excel.ExceBook object) On success return the Excel
    spreadsheet as an ExcelBook object. Returns None on error.

    """

    # Load the sheet with Libreoffice.
    wb = load_excel_libreoffice(data)
    if (wb is not None):

        # Did we load sheets with libreoffice?
        if (len(wb.sheet_names()) > 0):
            return wb

    """
    # Next try loading the sheets with xlrd2.
    wb = load_excel_xlrd(data)
    if (wb is not None):
        return wb
    """

    # Nothing worked.
    return None

def is_cell_dict(x):
    """Test to see if the given item is a dict used to represent an Excel
    cell.

    @param x (??) The item to check to see if it is an Excel cell
    dict.

    @return (boolean) True if it is a cell dict, False is not.

    """
    return (isinstance(x, dict) and ("value" in x))

def _get_alphanum_cell_index(row, col):
    """Convert a (row, col) cell index to a AB123 style index.
    
    @param row (int) The row index.

    @param col (int) The colum index.

    @return (str) The (row, col) cell index converted to a AB123 style
    index.

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
    """Get the sheet in a workbook with the most cells.

    @param workbook (ExcelBook object) The Excel workbook.

    @return (ExcelSheet object) The Excel sheet with the most
    non-empty cells. If the workbook has no sheets None will be
    returned.

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
        # pylint: disable=bare-except
        except:
            return None

        # Read all the cells.
        curr_cells = pull_cells_sheet(sheet, strip_empty=True)
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
    """Get the number of rows in an Excel sheet.

    @param sheet (ExcelSheet object) The sheet on which to count the
    rows.

    @return (int) The number of rows.

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
    """Get the number of columns in an Excel sheet.

    @param sheet (ExcelSheet object) The sheet on which to count the
    columns.

    @return (int) The number of columns.

    """

    # Internal representation?
    if (hasattr(sheet, "num_cols")):
        return sheet.num_cols()

    # xlrd sheet?
    if (hasattr(sheet, "ncols")):
        return sheet.ncols

    # Unhandled sheet object.
    return 0

def _pull_cells_sheet_xlrd(sheet, strip_empty):
    """Pull all the cells from a xlrd Sheet object.

    @param sheet (xlrd Sheet object) The xlrd sheet from which to pull
    cells.

    @param strip_empty (boolean) If True do not report cells with
    empty values, if False return all cells.

    @return (list) A list of cells from the sheet represented as a
    dict. Each cell dict is of the form { "value" : cell value, "row"
    : row index, "col" : column index, "index" : AB123 form of cell
    index }

    """

    # Find the max row and column for the cells.
    if (not hasattr(sheet, "nrows") or
        not hasattr(sheet, "ncols")):
        # This is not a xlrd sheet object.
        return None
    max_row = sheet.nrows
    max_col = sheet.ncols

    # Cycle through all the cells in order.
    curr_cells = []
    for curr_row in range(0, max_row + 1):
        for curr_col in range(0, max_col + 1):
            try:
                curr_cell_xlrd = sheet.cell(curr_row, curr_col)
                curr_val = curr_cell_xlrd.value
                if (strip_empty and (len(str(curr_val).strip()) == 0)):
                    continue
                curr_cell = { "value" : curr_val,
                              "row" : curr_row + 1,
                              "col" : curr_col + 1,
                              "index" : _get_alphanum_cell_index(curr_row, curr_col) }
                curr_cells.append(curr_cell)
            # pylint: disable=bare-except
            except:
                pass

    # Return the cells.
    return curr_cells
            
def _pull_cells_sheet_internal(sheet, strip_empty):
    """Pull all the cells from an ExcelSheet object defined internally in
    excel.py.

    @param sheet (ExcelSheet object) The ExcelSheet sheet from which
    to pull cells.

    @param strip_empty (boolean) If True do not report cells with
    empty values, if False return all cells.

    @return (list) A list of cells from the sheet represented as a
    dict. Each cell dict is of the form { "value" : cell value, "row"
    : row index, "col" : column index, "index" : AB123 form of cell
    index }

    """

    # We are going to use the internal cells field to build the list of all
    # cells, so this will only work with the ExcelSheet class defined in excel.py.
    if (not hasattr(sheet, "cells")):
        # This is not an internal sheet object.
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
                curr_val = sheet.cell(curr_row, curr_col)
                if (strip_empty and (len(str(curr_val).strip()) == 0)):
                    continue
                curr_cell = { "value" : curr_val,
                              "row" : curr_row + 1,
                              "col" : curr_col + 1,
                              "index" : _get_alphanum_cell_index(curr_row, curr_col) }
                curr_cells.append(curr_cell)
            except KeyError:
                pass

    # Return the cells.
    return curr_cells

def pull_cells_sheet(sheet, strip_empty=False):
    """Pull all the cells from an xlrd or internal ExcelSheet Sheet
    object.

    @param sheet (...) The ExcelSheet sheet or xlrd sheet from which
    to pull cells.

    @param strip_empty (boolean) If True do not report cells with
    empty values, if False return all cells.

    @return (list) A list of cells from the sheet represented as a
    dict. Each cell dict is of the form { "value" : cell value, "row"
    : row index, "col" : column index, "index" : AB123 form of cell
    index }

    """
    curr_cells = _pull_cells_sheet_xlrd(sheet, strip_empty)
    if (curr_cells is None):
        curr_cells = _pull_cells_sheet_internal(sheet, strip_empty)
    return curr_cells
    
def pull_cells_workbook(workbook):
    """Pull all the cells from all sheets in the given workbook.

    @param workbook (...) The ExcelBook workbook or xlrd book from
    which to pull cells.

    @return (list) A list of cells from the sheets in the workbook
    represented as a dict. Each cell dict is of the form { "value" :
    cell value, "row" : row index, "col" : column index, "index" :
    AB123 form of cell index }. Note that all the cells for all the
    sheets go in a single list.

    """

    # Cycle over all sheets.
    all_cells = []
    for sheet_index in range(0, len(workbook.sheet_names())):
            
        # Load the current sheet.
        sheet = None
        try:
            sheet = workbook.sheet_by_index(sheet_index)
        # Try next sheet if index invalid.
        # pylint: disable=bare-except
        except:
            continue

        # Load the cells from this sheet.
        curr_cells = pull_cells_sheet(sheet)
        if (curr_cells is None):
            continue
        all_cells.extend(curr_cells)

    # Done.
    return all_cells

class ExcelSheet(object):
    """A single sheet in an Excel workbook.

    """
    
    def __init__(self, cells, name="Sheet1"):
        """Make a new ExcelSheet.

        @param cells (dict) A map from (row index, column index)
        tuples to cells values.

        @param name (str) The name of the sheet.

        """
        self.gloss = None
        self.cells = cells
        self.name = name.replace("0x20", " ")
        self.__num_rows = None
        self.__num_cols = None

    def __repr__(self):
        """String value of sheet.

        """
        if (self.gloss is not None):
            return self.gloss
        log.info("Converting Excel sheet to str ...")
        r = ""
        if debug:
            r += "Sheet: '" + self.name + "'\n\n"
            for cell in self.cells.keys():
                r += str(cell) + "\t=\t'" + str(self.cells[cell]) + "'\n"
        else:
            r += "Sheet: '" + self.name + "'\n"
            r += str(self.cells)
        self.gloss = r
        return self.gloss

    def num_rows(self):
        """Get the number of rows in the sheet.

        @return (int) The number of rows.

        """
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
        """Get the number of columns in the sheet.

        @return (int) The number of columns.

        """
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
        """Get a cell from the sheet.

        @param row (int) The cell's row index.

        @param col (int) The cell's column index.

        @return (str) The cell value if the cell is found.

        @throws KeyError This is thrown if the cell is not found.

        """
        if ((row, col) in self.cells):
            return self.cells[(row, col)]
        raise KeyError("Cell (" + str(row) + ", " + str(col) + ") not found.")

    def cell_value(self, row, col):
        """Get a cell from the sheet.

        @param row (int) The cell's row index.

        @param col (int) The cell's column index.

        @return (str) The cell value if the cell is found.

        @throws KeyError This is thrown if the cell is not found.

        """
        return self.cell(row, col)

    def cell_dict(self, row, col):
        """Get a cell from the sheet, represented as a dict.

        @param row (int) The cell's row index.

        @param col (int) The cell's column index.

        @return (dict) The cell value if the cell is found. A cell
        dict is of the form { "value" : cell value, "row" : row index,
        "col" : column index, "index" : AB123 form of cell index }.

        @throws KeyError This is thrown if the cell is not found.

        """
        curr_cell = { "value" : self.cell(row, col),
                      "row" : row + 1,
                      "col" : col + 1,
                      "index" : _get_alphanum_cell_index(row, col) }
        return curr_cell
    
class ExcelBook(object):
    """An Excel workbook composed of ExcelSheet sheet objects.

    """
    
    def __init__(self, cells=None, name="Sheet1"):
        """Make a new ExcelBook.

        @param cells (dict) A map from (row index, column index)
        tuples to cell values. If this is given a workbook containing
        a single sheet with these cells will be created

        @param name (str) The name of the sheet. This will only be
        used if a single sheet workbook is being created.

        """
        
        # Create empty workbook to fill in later?
        self.sheets = []
        if (cells is None):
            return

        # Create single sheet workbook?
        self.sheets.append(ExcelSheet(cells, name))

    def __repr__(self):
        """String version of workbook.

        """
        log.info("Converting Excel workbook to str ...")
        r = ""
        for sheet in self.sheets:
            r += str(sheet) + "\n"
        return r
        
    def sheet_names(self):
        """Get the names of all the sheets in the workbook.

        @return (list) A list of all the sheet names (str).

        """
        r = []
        for sheet in self.sheets:
            r.append(sheet.name)
        return r

    def sheet_by_index(self, index):
        """Get a sheet based on numeric index.

        @param index (int) The index of the sheet to get.

        @return (ExcelSheet object) The sheet if found.

        @throws ValueError This is thrown if the sheet index is not
        valid.

        """
        if (index < 0):
            raise ValueError("Sheet index " + str(index) + " is < 0")
        if (index >= len(self.sheets)):
            raise ValueError("Sheet index " + str(index) + " is > num sheets (" + str(len(self.sheets)) + ")")
        return self.sheets[index]

    def sheet_by_name(self, name):
        """Get a sheet based on name.

        @param name (str) The name of the sheet to get.

        @return (ExcelSheet object) The sheet if found.

        @throws ValueError This is thrown if the sheet is not found.

        """
        for sheet in self.sheets:
            if (sheet.name == name):
                return sheet
        raise ValueError("Sheet name '" + str(name) + "' not found.")

def make_book(cell_data):
    """Make a new ExcelBook workbook.

    @param cell_data (dict) A map from (row index, column index)
    tuples to cell values.

    @return (ExcelBook object) The new workbook.

    """
    return ExcelBook(cell_data)
