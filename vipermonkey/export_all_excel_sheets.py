#!/usr/bin/env python3

# Export all of the sheets of an Excel file as separate CSV files.
# This is Python 3.

import sys
import os
# sudo pip3 install psutil
import psutil
import subprocess
import time

# sudo pip3 install unotools
from unotools import Socket, connect
from unotools.component.calc import Calc
from unotools.unohelper import convert_path_to_url

# Connection information for LibreOffice.
HOST = "127.0.0.1"
PORT = 2002

def is_excel_file(maldoc):
    """
    Check to see if the given file is an Excel file..

    @param name (str) The name of the file to check.

    @return (bool) True if the file is an Excel file, False if not.
    """
    typ = subprocess.check_output(["file", maldoc])
    return (b"Excel" in typ)

def run_soffice():

    # Is soffice already running?
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name', 'username'])
        except psutil.NoSuchProcess:
            pass
        else:
            if (pinfo["name"].startswith("soffice")):

                # Already running. Don't start it again.
                return

    # soffice is not running. Run it in listening mode.
    cmd = "/usr/lib/libreoffice/program/soffice.bin --headless --invisible " + \
          "--nocrashreport --nodefault --nofirststartwizard --nologo " + \
          "--norestore " + '--accept="socket,host=127.0.0.1,port=2002,tcpNoDelay=1;urp;StarOffice.ComponentContext"'
    subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    time.sleep(5)

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

    # Make sure this is an Excel file.
    if (not is_excel_file(fname)):

        # Not Excel, so no sheets.
        return []

    # Run soffice in listening mode if it is not already running.
    run_soffice()
    
    # TODO: Make sure soffice is running in listening mode.
    # 
    
    # Connect to the local LibreOffice server.
    context = connect(Socket(HOST, PORT))

    # Load the Excel sheet.
    component = get_component(fname, context)

    # Iterate on all the sheets in the spreadsheet.
    controller = component.getCurrentController()
    sheets = component.getSheets()
    enumeration = sheets.createEnumeration()
    r = []
    pos = 0
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
            outfilename =  "/tmp/sheet_%s-%s--%s.csv" % (short_name, str(pos), name.replace(' ', '_SPACE_'))
            pos += 1
            r.append(outfilename)
            url = convert_path_to_url(outfilename)

            # Export the CSV.
            component.store_to_url(url,'FilterName','Text - txt - csv (StarCalc)')

    # Close the spreadsheet.
    component.close(True)

    # Kill soffice after done?
    # /usr/lib/libreoffice/program/soffice.bin --headless --invisible --nocrashreport --nodefault --nofirststartwizard --nologo --norestore --accept=socket,host=127.0.0.1,port=2002,tcpNoDelay=1;urp;StarOffice.ComponentContext
    
    # Done.
    return r

print(convert_csv(sys.argv[1]))

