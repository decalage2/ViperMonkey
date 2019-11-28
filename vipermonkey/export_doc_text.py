#!/usr/bin/env python3

# Export the document text of a Word document.
# This is Python 3.

import sys
import os
# sudo apt install python3-uno
# sudo pip3 install psutil
import psutil
import subprocess
import time

# sudo pip3 install unotools
# sudo apt install libreoffice-calc, python3-uno
from unotools import Socket, connect
from unotools.component.writer import Writer
from unotools.unohelper import convert_path_to_url

# Connection information for LibreOffice.
HOST = "127.0.0.1"
PORT = 2002

def is_word_file(maldoc):
    """
    Check to see if the given file is a Word file.

    @param name (str) The name of the file to check.

    @return (bool) True if the file is a Word file, False if not.
    """
    typ = subprocess.check_output(["file", maldoc])
    return ((b"Microsoft Office Word" in typ) or (b"Word 2007+" in typ))

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
    component = Writer(context, url)
    return component

def get_text(fname):
    """
    Get the document text of a given Word file.

    fname - The name of the file.
    return - The document text if found, "" if not found.
    """

    # Make sure this is a word file.
    if (not is_word_file(fname)):

        # Not Word, so no text.
        return ""

    # Run soffice in listening mode if it is not already running.
    run_soffice()
    
    # Connect to the local LibreOffice server.
    context = connect(Socket(HOST, PORT))

    # Load the document.
    component = get_component(fname, context)

    # Get the text. Add a character at the start to simulate an embedded image at start.
    r = "\x0c" + str(component.getText().getString())
    
    # Close the doc.
    component.close(True)

    # Done.
    return r

print(get_text(sys.argv[1]))

