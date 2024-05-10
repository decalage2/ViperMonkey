"""@package vipermonkey.core.stubbed_engine Base class for
VBA/VBScript emulators. Currently only 1 emulator is implemented.

"""

# pylint: disable=pointless-string-statement
"""
ViperMonkey: Base class for VBA/VBScript emulators.

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

__version__ = '0.02'

# sudo pypy -m pip install unidecode
import unidecode
import string

import logging
from logger import log
from utils import safe_str_convert

class StubbedEngine(object):
    """Stubbed out Vipermonkey analysis engine that just supports
    tracking actions.

    """

    def __init__(self):
        self.actions = []
        self.action_count = {}
        self.action_limit = 10
        
    def report_action(self, action, params=None, description=None):
        """Save information about an interesting action.

        @param action (str) The action to save in the context.
        
        @param params (list or str) Any parameter values for the
        action. 

        @param description (str) A human readable description of the
        action.

        """

        # Make sure all the action info is a proper string.
        try:
            if (isinstance(action, str)):
                action = unidecode.unidecode(action.decode('unicode-escape'))
        except UnicodeDecodeError:
            action = ''.join(filter(lambda x:x in string.printable, action))
        if (isinstance(params, str)):
            try:
                decoded = params.replace("\\", "#ESCAPED_SLASH#").decode('unicode-escape').replace("#ESCAPED_SLASH#", "\\")
                params = unidecode.unidecode(decoded)
            except Exception as e:
                log.warn("Unicode decode of action params failed. " + str(e))
                params = ''.join(filter(lambda x:x in string.printable, params))
        try:
            if (isinstance(description, str)):
                description = unidecode.unidecode(description.decode('unicode-escape'))
        except UnicodeDecodeError as e:
            log.warn("Unicode decode of action description failed. " + str(e))
            description = ''.join(filter(lambda x:x in string.printable, description))

        # Throttle actions that happen a lot.
        action_tuple = (action, params, description)
        action_str = safe_str_convert(action_tuple)
        if (action_str not in self.action_count):
            self.action_count[action_str] = 0
        self.action_count[action_str] += 1
        if (self.action_count[action_str] < self.action_limit):
            self.actions.append(action_tuple)
            log.info("ACTION: %s - params %r - %s" % (action, params, description))
