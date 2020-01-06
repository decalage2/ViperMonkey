#!/usr/bin/env python3

# Export the document text of a Word document via unotools.
# This is Python 3.

# sudo apt install python3-uno
# sudo pip3 install psutil
import psutil
import subprocess
import time
import argparse

# sudo pip3 install unotools
# sudo apt install libreoffice-calc, python3-uno
from unotools import Socket, connect
from unotools.component.writer import Writer
from unotools.unohelper import convert_path_to_url

# Connection information for LibreOffice.
HOST = "127.0.0.1"
PORT = 2002

###################################################################################################
def is_word_file(file):
    """
    Check to see if the given file is a Word file.

    @param file (str) The path of the file to check.

    @return (bool) True if the file is a Word file, False if not.
    """
    typ = subprocess.check_output(["file", file])
    return ((b"Microsoft Office Word" in typ) or (b"Word 2007+" in typ))

###################################################################################################
def run_soffice():
    """
    Start the headless, UNO supporting, libreoffice process to access the API, if it is not already
    running.
    """

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
          "--norestore " + \
          '--accept="socket,host=127.0.0.1,port=2002,tcpNoDelay=1;urp;StarOffice.ComponentContext"'
    subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    time.sleep(5)

###################################################################################################
def get_document(file, connection):
    """
    Load the component containing the word document.

    @param connection (ScriptContext) - connection to the headless LibreOffice process

    @param file (str) - path to the Word doc

    @return document (Writer)
    """

    url = convert_path_to_url(file)
    document = Writer(connection, url)
    return document

###################################################################################################
def get_text(document):
    """
    Get the document text and text of a given Word file.

    @param document (Writer) - LibreOffice component containing the document

    @return text (str)
    """

    # Get the text. Add a character at the start to simulate an embedded image at start.
    return "\x0c" + str(document.getText().getString())

###################################################################################################
def get_tables(document):
    """
    Get the text tables embedded in the word doc.

    @param document (Writer) - LibreOffice component containing the document

    @return data_array_list (list) - list of 2D arrays containing text content of all cells in all
        text tables of the document
    """

    data_array_list = []

    text_tables = document.getTextTables()
    table_count = 0
    while table_count < text_tables.getCount():
        data_array_list.append(text_tables.getByIndex(table_count).getDataArray())
        table_count += 1

    return data_array_list


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
    print(get_tables(document))
