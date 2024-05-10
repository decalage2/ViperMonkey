"""@package vipermonkey.core.logger Defines some logging helper
classes and functions.

"""

# pylint: disable=pointless-string-statement
"""
vipermonkey logging helper

ViperMonkey is a specialized engine to parse, analyze and interpret Microsoft
VBA macros (Visual Basic for Applications), mainly for malware analysis.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

Project Repository:
https://github.com/decalage2/ViperMonkey
"""

# === LICENSE ==================================================================

# ViperMonkey is copyright (c) 2015-2019 Philippe Lagadec (http://www.decalage.info)
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


# ------------------------------------------------------------------------------
# CHANGELOG:
# 2015-02-12 v0.01 PL: - first prototype
# 2015-2016        PL: - many updates
# 2016-06-11 v0.02 PL: - split vipermonkey into several modules

__version__ = '0.08'

# ------------------------------------------------------------------------------
# TODO:

# --- IMPORTS ------------------------------------------------------------------

import logging

# === LOGGING =================================================================

class CappedFileHandler(logging.FileHandler):
    """Logging file handler that limits the size of the log file.

    """
    
    # default size cap of 30M
    # log file is put in the working directory with the same name
    def __init__(self, filename, sizecap, mode='w', encoding=None, delay=False):
        self.size_cap = sizecap
        self.current_size = 0
        self.cap_exceeded = False
        super(CappedFileHandler, self).__init__(filename, mode, encoding, delay)

    def emit(self, record):
        if not self.cap_exceeded:
            new_size = self.current_size + len(self.formatter.format(record))
            if new_size <= self.size_cap:
                self.current_size = new_size
                super(CappedFileHandler, self).emit(record)
            # regardless of whether or not a future log could be within the size cap, cut it off here
            else:
                self.cap_exceeded = True

class DuplicateFilter(logging.Filter):
    """Filters out log messages that have been seen before.

    """
    
    def filter(self, record):
        # add other fields if you need more granular comparison, depends on your app
        current_log = (record.module, record.levelno, record.msg)
        if current_log != getattr(self, "last_log", None):
            self.last_log = current_log
            return True
        return False

def get_logger(name, level=logging.NOTSET):
    """Create a suitable logger object for a module.  The goal is not to
    change settings of the root logger, to avoid getting other
    modules' logs on the screen.  If a logger exists with same name,
    reuse it. (Else it would have duplicate handlers and messages
    would be doubled.)

    @param name (str) The name of the logger.

    @param level (int??) The level of logging to perform.

    """
    # First, test if there is already a logger with the same name, else it
    # will generate duplicate messages (due to duplicate handlers):
    if name in logging.Logger.manager.loggerDict:
        # NOTE: another less intrusive but more "hackish" solution would be to
        # use getLogger then test if its effective level is not default.
        logger = logging.getLogger(name)
        # make sure level is OK:
        logger.setLevel(level)
        # Skip duplicate log messages.
        logger.addFilter(DuplicateFilter()) 
        return logger
    # get a new logger:
    logger = logging.getLogger(name)
    # only add a NullHandler for this logger, it is up to the application
    # to configure its own logging:
    logger.addHandler(logging.NullHandler())
    logger.setLevel(level)
    # Skip duplicate log messages.
    logger.addFilter(DuplicateFilter()) 
    return logger


# a global logger object used for debugging:
log = get_logger('VMonkey')
