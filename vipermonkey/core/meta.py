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

from logger import log

metadata = None

def read_metadata_item(var):

    # Make sure we read in the metadata.
    if (metadata is None):
        log.error("BuiltInDocumentProperties: Metadata not read.")
        return ""
    
    # Nomalize the variable name.
    var = var.lower()
    if ("." in var):
        var = var[:var.index(".")]
    
    # See if we can find the metadata attribute.
    if (not hasattr(metadata, var)):
        log.error("BuiltInDocumentProperties: Metadata field '" + var + "' not found.")
        return ""

    # We have the attribute. Return it.
    r = getattr(metadata, var)
    log.debug("BuiltInDocumentProperties: return %r -> %r" % (var, r))
    return r
