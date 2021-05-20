"""@package meta Functionality for reading in Office file metadata.

"""

# pylint: disable=pointless-string-statement
"""
ViperMonkey: Read in document metadata item.

ViperMonkey is a specialized engine to parse, analyze and interpret Microsoft
VBA macros (Visual Basic for Applications), mainly for malware analysis.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

Project Repository:
https://github.com/decalage2/ViperMonkey
"""

import logging
import subprocess

from logger import log

from utils import safe_str_convert

class FakeMeta(object):
    """Class used to hold Office file metadata fields and values.

    """
    pass

def get_metadata_exif(filename):
    """Get the Office metadata for a given file with the exiftool
    utility.

    @param filename (str) The name of the Office file for which to get
    metadata.

    @return (FakeMeta object) An object with a field for each piece of
    metadate.

    """
    
    # Use exiftool to get the document metadata.
    output = None
    try:
        output = subprocess.check_output(["exiftool", filename])
    except Exception as e:
        log.error("Cannot read metadata with exiftool. " + safe_str_convert(e))
        return {}

    # Sanity check results.
    if (log.getEffectiveLevel() == logging.DEBUG):
        log.debug("exiftool output: '" + safe_str_convert(output) + "'")
    if (":" not in output):
        log.warning("Cannot read metadata with exiftool.")
        return {}
    
    # Store the metadata in an object.
    lines = output.split("\n")
    r = FakeMeta()
    for line in lines:
        line = line.strip()
        if ((len(line) == 0) or (":" not in line)):
            continue        
        field = line[:line.index(":")].strip().lower()
        val = line[line.index(":") + 1:].strip().replace("...", "\r\n")
        setattr(r, field, val)

    # Done.
    return r
