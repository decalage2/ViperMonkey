#!/usr/bin/env python3

"""@package export_all_excel_sheets 
Export all of the sheets of an Excel file as separate CSV files. This
is Python 3.
"""

import sys
import os
import signal
# sudo pip3 install psutil
import psutil
import subprocess
import time

# sudo pip3 install unotools
# sudo apt install libreoffice-calc, python3-uno
from unotools import Socket, connect
from unotools.component.calc import Calc
from unotools.unohelper import convert_path_to_url
from unotools import ConnectionError

# Connection information for LibreOffice.
HOST = "127.0.0.1"
PORT = 2002

def is_excel_file(maldoc):
    """Check to see if the given file is an Excel file.

    @param maldoc (str) The name of the file to check.

    @return (bool) True if the file is an Excel file, False if not.

    """
    typ = subprocess.check_output(["file", maldoc])
    if ((b"Excel" in typ) or (b"Microsoft OOXML" in typ)):
        return True
    typ = subprocess.check_output(["exiftool", maldoc])
    return (b"vnd.ms-excel" in typ)

###################################################################################################
def wait_for_uno_api():
    """Sleeps until the libreoffice UNO api is available by the headless
    libreoffice process. Takes a bit to spin up even after the OS
    reports the process as running. Tries 3 times before giving up and
    throwing an Exception.

    """

    tries = 0

    while tries < 3:
        try:
            connect(Socket(HOST, PORT))
            return
        except ConnectionError:
            time.sleep(5)
            tries += 1

    raise Exception("libreoffice UNO API failed to start")

###################################################################################################
def get_office_proc():
    """Returns the process info for the headless LibreOffice
    process. None if it's not running

    @return (psutil.Process) The LibreOffice process if found, None if not found.

    """

    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name', 'username'])
        except psutil.NoSuchProcess:
            pass
        else:
            if (pinfo["name"].startswith("soffice")):
                return pinfo
    return None

###################################################################################################
def is_office_running():
    """Check to see if the headless LibreOffice process is running.

    @return (bool) True if running False otherwise

    """

    return True if get_office_proc() else False

###################################################################################################
def run_soffice():
    """Start the headless, UNO supporting, LibreOffice process to access
    the API, if it is not already running.

    """

    # start the process
    if not is_office_running():

        # soffice is not running. Run it in listening mode.
        cmd = "/usr/lib/libreoffice/program/soffice.bin --headless --invisible " + \
              "--nocrashreport --nodefault --nofirststartwizard --nologo " + \
              "--norestore " + \
              '--accept="socket,host=127.0.0.1,port=2002,tcpNoDelay=1;urp;StarOffice.ComponentContext"'
        subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        wait_for_uno_api()

def get_component(fname, context):
    """Load the object for the Excel spreadsheet.

    @param fname (str) The name of the Excel file.

    @param context (??) The UNO object connected to the local LibreOffice server.

    @return (??) UNO LibreOffice Calc object representing the loaded
    Excel file.

    """
    url = convert_path_to_url(fname)
    component = Calc(context, url)
    return component

def fix_file_name(fname):
    """
    Replace non-printable ASCII characters in the given file name.
    """
    r = ""
    for c in fname:
        if ((ord(c) < 48) or (ord(c) > 122)):
            r += hex(ord(c))
            continue
        r += c

    return r

def convert_csv(fname):
    """Convert all of the sheets in a given Excel spreadsheet to CSV
    files. Also get the name of the currently active sheet.

    @param fname (str) The name of the Excel file.
    
    @return (list) A list where the 1st element is the name of the
    currently active sheet ("NO_ACTIVE_SHEET" if no sheets are active)
    and the rest of the elements are the names (str) of the CSV sheet
    files.

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

    # Save the currently active sheet.
    r = []
    controller = component.getCurrentController()
    active_sheet = controller.ActiveSheet
    active_sheet_name = "NO_ACTIVE_SHEET"
    if (active_sheet is not None):
        active_sheet_name = fix_file_name(active_sheet.getName())
    r.append(active_sheet_name)
        
    # Iterate on all the sheets in the spreadsheet.
    sheets = component.getSheets()
    enumeration = sheets.createEnumeration()
    pos = 0
    if sheets.getCount() > 0:
        while enumeration.hasMoreElements():

            # Move to next sheet.
            sheet = enumeration.nextElement()
            name = sheet.getName()
            if (name.count(" ") > 10):
                name = name.replace(" ", "")
            name = fix_file_name(name)
            controller.setActiveSheet(sheet)

            # Set up the output URL.
            short_name = fname
            if (os.path.sep in short_name):
                short_name = short_name[short_name.rindex(os.path.sep) + 1:]
            short_name = fix_file_name(short_name)
            outfilename =  "/tmp/sheet_%s-%s--%s.csv" % (short_name, str(pos), name.replace(' ', '_SPACE_'))
            pos += 1
            r.append(outfilename)
            url = convert_path_to_url(outfilename)

            # Export the CSV.
            component.store_to_url(url,'FilterName','Text - txt - csv (StarCalc)')

    # Close the spreadsheet.
    component.close(True)

    # clean up
    os.kill(get_office_proc()["pid"], signal.SIGTERM)

    # Done.
    return r

###########################################################################
## Main Program
###########################################################################
if __name__ == '__main__':
    print(convert_csv(sys.argv[1]))
