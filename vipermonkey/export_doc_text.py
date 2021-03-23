#!/usr/bin/env python3

"""@package export_doc_text 
Export the document text/tables of a Word document via unotools.
This is Python 3.
"""

# sudo apt install python3-uno
# sudo pip3 install psutil
import psutil
import subprocess
import time
import argparse
import json
import os
import signal

# sudo pip3 install unotools
# sudo apt install libreoffice-calc, python3-uno
from unotools import Socket, connect
from unotools.component.writer import Writer
from unotools.unohelper import convert_path_to_url
from unotools import ConnectionError

# Connection information for LibreOffice.
HOST = "127.0.0.1"
PORT = 2002

###################################################################################################
def is_word_file(fname):
    """Check to see if the given file is a Word file.

    @param fname (str) The path of the file to check.

    @return (bool) True if the file is a Word file, False if not.

    """
    typ = subprocess.check_output(["file", fname])
    return ((b"Microsoft Office Word" in typ) or
            (b"Word 2007+" in typ) or
            (b"Microsoft OOXML" in typ))

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
    """
    Returns the process info for the headless libreoffice process. None if it's not running

    @return (psutil.Process)
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

###################################################################################################
def get_document(fname, connection):
    """Load the component containing the word document.

    @param connection (ScriptContext) Connection to the headless LibreOffice process

    @param fname (str) Path to the Word doc

    @return document (Writer) UNO object representing the loaded Word
    document.

    """

    url = convert_path_to_url(fname)
    document = Writer(connection, url)
    return document

###################################################################################################
def get_text(document):
    """Get the document text of a given Word file.

    @param document (Writer) LibreOffice component containing the
    document.

    @return (str) The text from the document.

    """

    # Get the text. Add a character at the start to simulate an embedded image at start.
    return "\x0c" + str(document.getText().getString())

###################################################################################################
def get_tables(document):
    """Get the text tables embedded in the Word doc.

    @param document (Writer) LibreOffice component containing the
    document.

    @return (list) List of 2D arrays containing text content of all
    cells in all text tables of the document

    """

    data_array_list = []

    text_tables = document.getTextTables()
    table_count = 0
    while table_count < text_tables.getCount():
        data_array_list.append(text_tables.getByIndex(table_count).getDataArray())
        table_count += 1

    return data_array_list


###########################################################################
## Main Program
###########################################################################
if __name__ == '__main__':
    print(convert_csv(sys.argv[1]))
    arg_parser = argparse.ArgumentParser(description="export text from various properties in a Word "
                                         "document via the LibreOffice API")
    arg_parser.add_argument("--tables", action="store_true",
                            help="export a list of 2D lists containing the cell contents"
                            "of each text table in the document")
    arg_parser.add_argument("--text", action="store_true",
                            help="export a string containing the document text")
    arg_parser.add_argument("-f", "--file", action="store", required=True,
                            help="path to the word doc")
    args = arg_parser.parse_args()

    # Make sure this is a word file.
    if (not is_word_file(args.file)):

        # Not Word, so no text.
        exit()

    # Run soffice in listening mode if it is not already running.
    run_soffice()

    # Connect to the local LibreOffice server.
    connection = connect(Socket(HOST, PORT))

    # Load the document using the connection
    document = get_document(args.file, connection)

    if args.text:
        print(get_text(document))
    elif args.tables:
        print(json.dumps(get_tables(document)))

    # clean up
    document.close(True)
    os.kill(get_office_proc()["pid"], signal.SIGTERM)
