#!/usr/bin/env python
"""
ViperMonkey: Execution context for global and local variables

ViperMonkey is a specialized engine to parse, analyze and interpret Microsoft
VBA macros (Visual Basic for Applications), mainly for malware analysis.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

Project Repository:
https://github.com/decalage2/ViperMonkey
"""

# === LICENSE ==================================================================

# ViperMonkey is copyright (c) 2015-2016 Philippe Lagadec (http://www.decalage.info)
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

__version__ = '0.02'

# ------------------------------------------------------------------------------
# TODO:

# --- IMPORTS ------------------------------------------------------------------

from logger import log
log.debug('importing vba_context')


def is_procedure(vba_object):
    """
    Check if a VBA object is a procedure, e.g. a Sub or a Function.
    This is implemented by checking if the object has a statements
    attribute
    :param vba_object: VBA_Object to be checked
    :return: True if vba_object is a procedure, False otherwise
    """
    if hasattr(vba_object, 'statements'):
        return True
    else:
        return False

# === VBA CLASSES =====================================================================================================

# global dictionary of constants, functions and subs for the VBA library
VBA_LIBRARY = {}


class Context(object):
    """
    a Context object contains the global and local named objects (variables, subs, functions)
    used to evaluate VBA statements.
    """

    def __init__(self, _globals=None, _locals=None, context=None, engine=None):
        # globals should be a pointer to the globals dict from the core VBA engine (ViperMonkey)
        # because each statement should be able to change global variables
        if _globals is not None:
            # direct copy of the pointer to globals:
            self.globals = _globals
        elif context is not None:
            self.globals = context.globals
        else:
            self.globals = {}
        # on the other hand, each Context should have its own private copy of locals
        if _locals is not None:
            # However, if locals is explicitly provided, we use a copy of it:
            self.locals = dict(_locals)
        # If a context is provided, its locals should NOT be copied
        # elif context is not None:
        #     self.locals = dict(context.locals)
        else:
            self.locals = {}
        # engine should be a pointer to the ViperMonkey engine, to provide callback features
        if engine is not None:
            self.engine = engine
        elif context is not None:
            self.engine = context.engine
        else:
            self.engine = None

        # Track whether nested loops are running with a stack of flags. If a loop is
        # running its flag will be True.
        self.loop_stack = []

        # Track whether we have exited from the current function.
        self.exit_func = False

        # Add some attributes we are handling as global variables.
        self.globals["vbDirectory"] = "vbDirectory"
        self.globals["vbKeyLButton"] = 1
        self.globals["vbKeyRButton"] = 2
        self.globals["vbKeyCancel"] = 3
        self.globals["vbKeyMButton"] = 4
        self.globals["vbKeyBack"] = 8
        self.globals["vbKeyTab"] = 9
        self.globals["vbKeyClear"] = 12
        self.globals["vbKeyReturn"] = 13
        self.globals["vbKeyShift"] = 16
        self.globals["vbKeyControl"] = 17
        self.globals["vbKeyMenu"] = 18
        self.globals["vbKeyPause"] = 19
        self.globals["vbKeyCapital"] = 20
        self.globals["vbKeyEscape"] = 27
        self.globals["vbKeySpace"] = 32
        self.globals["vbKeyPageUp"] = 33
        self.globals["vbKeyPageDown"] = 34
        self.globals["vbKeyEnd"] = 35
        self.globals["vbKeyHome"] = 36
        self.globals["vbKeyLeft"] = 37
        self.globals["vbKeyUp"] = 38
        self.globals["vbKeyRight"] = 39
        self.globals["vbKeyDown"] = 40
        self.globals["vbKeySelect"] = 41
        self.globals["vbKeyPrint"] = 42
        self.globals["vbKeyExecute"] = 43
        self.globals["vbKeySnapshot"] = 44
        self.globals["vbKeyInsert"] = 45
        self.globals["vbKeyDelete"] = 46
        self.globals["vbKeyHelp"] = 47
        self.globals["vbKeyNumlock"] = 144        
        self.globals["vbKeyA"] = 65
        self.globals["vbKeyB"] = 66
        self.globals["vbKeyC"] = 67
        self.globals["vbKeyD"] = 68
        self.globals["vbKeyE"] = 69
        self.globals["vbKeyF"] = 70
        self.globals["vbKeyG"] = 71
        self.globals["vbKeyH"] = 72
        self.globals["vbKeyI"] = 73
        self.globals["vbKeyJ"] = 74
        self.globals["vbKeyK"] = 75
        self.globals["vbKeyL"] = 76
        self.globals["vbKeyM"] = 77
        self.globals["vbKeyN"] = 78
        self.globals["vbKeyO"] = 79
        self.globals["vbKeyP"] = 80
        self.globals["vbKeyQ"] = 81
        self.globals["vbKeyR"] = 82
        self.globals["vbKeyS"] = 83
        self.globals["vbKeyT"] = 84
        self.globals["vbKeyU"] = 85
        self.globals["vbKeyV"] = 86
        self.globals["vbKeyW"] = 87
        self.globals["vbKeyX"] = 88
        self.globals["vbKeyY"] = 89
        self.globals["vbKeyZ"] = 90
        self.globals["vbKey0"] = 48
        self.globals["vbKey1"] = 49
        self.globals["vbKey2"] = 50
        self.globals["vbKey3"] = 51
        self.globals["vbKey4"] = 52
        self.globals["vbKey5"] = 53
        self.globals["vbKey6"] = 54
        self.globals["vbKey7"] = 55
        self.globals["vbKey8"] = 56
        self.globals["vbKey9"] = 57
        self.globals["vbKeyNumpad0"] = 96
        self.globals["vbKeyNumpad1"] = 97
        self.globals["vbKeyNumpad2"] = 98
        self.globals["vbKeyNumpad3"] = 99
        self.globals["vbKeyNumpad4"] = 100
        self.globals["vbKeyNumpad5"] = 101
        self.globals["vbKeyNumpad6"] = 102
        self.globals["vbKeyNumpad7"] = 103
        self.globals["vbKeyNumpad8"] = 104
        self.globals["vbKeyNumpad9"] = 105
        self.globals["vbKeyMultiply"] = 106
        self.globals["vbKeyAdd"] = 107
        self.globals["vbKeySeparator"] = 108
        self.globals["vbKeySubtract"] = 109
        self.globals["vbKeyDecimal"] = 110
        self.globals["vbKeyDivide"] = 111
        self.globals["vbKeyF1"] = 112
        self.globals["vbKeyF2"] = 113
        self.globals["vbKeyF3"] = 114
        self.globals["vbKeyF4"] = 115
        self.globals["vbKeyF5"] = 116
        self.globals["vbKeyF6"] = 117
        self.globals["vbKeyF7"] = 118
        self.globals["vbKeyF8"] = 119
        self.globals["vbKeyF9"] = 120
        self.globals["vbKeyF10"] = 121
        self.globals["vbKeyF11"] = 122
        self.globals["vbKeyF12"] = 123
        self.globals["vbKeyF13"] = 124
        self.globals["vbKeyF14"] = 125
        self.globals["vbKeyF15"] = 126
        self.globals["vbKeyF16"] = 127

    def get(self, name):
        # TODO: remove this check once everything works fine
        assert isinstance(name, basestring)
        # convert to lowercase
        name = name.lower()
        # first, search in the global VBA library:
        if name in VBA_LIBRARY:
            log.debug('Found %r in VBA Library' % name)
            return VBA_LIBRARY[name]
        # second, search in locals:
        if name in self.locals:
            log.debug('Found %r in locals' % name)
            return self.locals[name]
        # third, in globals:
        elif name in self.globals:
            log.debug('Found %r in globals' % name)
            return self.globals[name]
        else:
            raise KeyError('Object %r not found' % name)
            # NOTE: if name is unknown, just raise Python dict's exception
            # TODO: raise a custom VBA exception?

    # TODO: set_global?

    def set(self, name, value):
        # convert to lowercase
        name = name.lower()
        # raise exception if name in VBA library:
        if name in VBA_LIBRARY:
            raise ValueError('%r cannot be modified, it is part of the VBA Library.' % name)
        if name in self.locals:
            self.locals[name] = value
        # check globals, but avoid to overwrite subs and functions:
        elif name in self.globals and not is_procedure(self.globals[name]):
            self.globals[name] = value
        else:
            # new name, always stored in locals:
            self.locals[name] = value

    def report_action(self, action, params=None, description=None):
        self.engine.report_action(action, params, description)


