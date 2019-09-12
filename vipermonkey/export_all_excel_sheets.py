#!/usr/bin/env python3

# Export all of the sheets of an Excel file as separate CSV files.
# This is Python 3.

import sys
import os

# sudo pip3 install unotools
from unotools import Socket, connect
from unotools.component.calc import Calc
from unotools.unohelper import convert_path_to_url

# Connection information for LibreOffice.
HOST = "localhost"
PORT = 2002

def get_component(fname, context):
    """
    Load the object for the Excel spreadsheet.
    """
    url = convert_path_to_url(fname)
    component = Calc(context, url)
    return component

def convert_csv(fname):
    """
    Convert all of the sheets in a given Excel spreadsheet to CSV files.

    fname - The name of the file.
    return - A list of the names of the CSV sheet files.
    """

    # Connect to the local LibreOffice server.
    context = connect(Socket(HOST, PORT))

    # Load the Excel sheet.
    component = get_component(fname, context)

    # Iterate on all the sheets in the spreadsheet.
    controller = component.getCurrentController()
    sheets = component.getSheets()
    enumeration = sheets.createEnumeration()
    r = []
    if sheets.getCount() > 0:
        while enumeration.hasMoreElements():

            # Move to next sheet.
            sheet = enumeration.nextElement()
            name = sheet.getName()
            controller.setActiveSheet(sheet)

            # Set up the output URL.
            short_name = fname
            if (os.path.sep in short_name):
                short_name = short_name[short_name.rindex(os.path.sep) + 1:]
            outfilename =  "/tmp/sheet_%s-%s.csv" % (short_name, name.replace(' ', '_SPACE_'))
            r.append(outfilename)
            url = convert_path_to_url(outfilename)

            # Export the CSV.
            component.store_to_url(url,'FilterName','Text - txt - csv (StarCalc)')

    # Close the spreadsheet.
    component.close(True)

    # Done.
    return r

print(convert_csv(sys.argv[1]))

