"""
ViperMonkey - Utility functions.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

Project Repository:
https://github.com/decalage2/ViperMonkey
"""

#=== LICENSE ==================================================================

# ViperMonkey is copyright (c) 2015-2018 Philippe Lagadec (http://www.decalage.info)
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

import re

import logging

# for logging
try:
    from core.logger import log
except ImportError:
    from logger import log
try:
    from core.logger import CappedFileHandler
except ImportError:
    from logger import CappedFileHandler
from logging import LogRecord
from logging import FileHandler

def safe_print(text):
    """
    Sometimes printing large strings when running in a Docker container triggers exceptions.
    This function just wraps a print in a try/except block to not crash ViperMonkey when this happens.
    """
    text = str(text)
    try:
        print(text)
    except Exception as e:
        msg = "ERROR: Printing text failed (len text = " + str(len(text)) + ". " + str(e)
        if (len(msg) > 100):
            msg = msg[:100]
        try:
            print(msg)
        except:
            pass

    # if our logger has a FileHandler, we need to tee this print to a file as well
    for handler in log.handlers:
        if type(handler) is FileHandler or type(handler) is CappedFileHandler:
            # set the format to be like a print, not a log, then set it back
            handler.setFormatter(logging.Formatter("%(message)s"))
            handler.emit(LogRecord(log.name, logging.INFO, "", None, text, None, None, "safe_print"))
            handler.setFormatter(logging.Formatter("%(levelname)-8s %(message)s"))

def fix_python_overlap(var_name):
    builtins = set(["str", "list"])
    if (var_name.lower() in builtins):
        var_name = "MAKE_UNIQUE_" + var_name
    var_name = var_name.replace(".", "")
    return var_name

class vb_RegExp(object):
    """
    Class to simulate a VBS RegEx object in python.
    """

    def __init__(self):
        self.Pattern = None
        self.Global = False

    def _get_python_pattern(self):
        pat = self.Pattern
        if (pat is None):
            return None
        if (pat.strip() != "."):
            pat1 = pat.replace("$", "\\$").replace("-", "\\-")
            fix_dash_pat = r"(\[.\w+)\\\-(\w+\])"
            pat1 = re.sub(fix_dash_pat, r"\1-\2", pat1)
            fix_dash_pat1 = r"\((\w+)\\\-(\w+)\)"
            pat1 = re.sub(fix_dash_pat1, r"[\1-\2]", pat1)
            pat = pat1
        return pat
        
    def Test(self, string):
        pat = self._get_python_pattern()
        if (pat is None):
            return False
        return (re.match(pat, string) is not None)

    def Replace(self, string, rep):
        pat = self._get_python_pattern()
        if (pat is None):
            return s
        rep = re.sub(r"\$(\d)", r"\\\1", rep)
        r = string
        try:
            r = re.sub(pat, rep, string)
        except Exception as e:
            pass
        return r

