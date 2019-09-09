#!/usr/bin/env python
"""
ViperMonkey: Read in document metadata item.

ViperMonkey is a specialized engine to parse, analyze and interpret Microsoft
VBA macros (Visual Basic for Applications), mainly for malware analysis.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

Project Repository:
https://github.com/decalage2/ViperMonkey
"""

import subprocess

from logger import log

class FakeMeta(object):
    pass

def get_metadata_exif(filename):

    # Use exiftool to get the document metadata.
    output = None
    try:
        output = subprocess.check_output(["exiftool", filename])
    except Exception as e:
        log.error("Cannot read metadata with exiftool. " + str(e))
        return {}

    # Sanity check results.
    if (":" not in output):
        log.warning("Cannot read metadata with exiftool.")
        return {}
    
    # Store the metadata in an object.
    lines = output.split("\n")
    r = FakeMeta()
    for line in lines:
        line = line.strip()
        if (len(line) == 0):
            continue
        field = line[:line.index(":")].strip().lower()
        val = line[line.index(":") + 1:].strip()
        setattr(r, field, val)

    # Done.
    return r
