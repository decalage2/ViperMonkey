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

        # Track variable types, if known.
        self.types = {}
        
        # Add some attributes we are handling as global variables.
        self.globals["vbDirectory".lower()] = "vbDirectory"
        self.globals["vbKeyLButton".lower()] = 1
        self.globals["vbKeyRButton".lower()] = 2
        self.globals["vbKeyCancel".lower()] = 3
        self.globals["vbKeyMButton".lower()] = 4
        self.globals["vbKeyBack".lower()] = 8
        self.globals["vbKeyTab".lower()] = 9
        self.globals["vbKeyClear".lower()] = 12
        self.globals["vbKeyReturn".lower()] = 13
        self.globals["vbKeyShift".lower()] = 16
        self.globals["vbKeyControl".lower()] = 17
        self.globals["vbKeyMenu".lower()] = 18
        self.globals["vbKeyPause".lower()] = 19
        self.globals["vbKeyCapital".lower()] = 20
        self.globals["vbKeyEscape".lower()] = 27
        self.globals["vbKeySpace".lower()] = 32
        self.globals["vbKeyPageUp".lower()] = 33
        self.globals["vbKeyPageDown".lower()] = 34
        self.globals["vbKeyEnd".lower()] = 35
        self.globals["vbKeyHome".lower()] = 36
        self.globals["vbKeyLeft".lower()] = 37
        self.globals["vbKeyUp".lower()] = 38
        self.globals["vbKeyRight".lower()] = 39
        self.globals["vbKeyDown".lower()] = 40
        self.globals["vbKeySelect".lower()] = 41
        self.globals["vbKeyPrint".lower()] = 42
        self.globals["vbKeyExecute".lower()] = 43
        self.globals["vbKeySnapshot".lower()] = 44
        self.globals["vbKeyInsert".lower()] = 45
        self.globals["vbKeyDelete".lower()] = 46
        self.globals["vbKeyHelp".lower()] = 47
        self.globals["vbKeyNumlock".lower()] = 144        
        self.globals["vbKeyA".lower()] = 65
        self.globals["vbKeyB".lower()] = 66
        self.globals["vbKeyC".lower()] = 67
        self.globals["vbKeyD".lower()] = 68
        self.globals["vbKeyE".lower()] = 69
        self.globals["vbKeyF".lower()] = 70
        self.globals["vbKeyG".lower()] = 71
        self.globals["vbKeyH".lower()] = 72
        self.globals["vbKeyI".lower()] = 73
        self.globals["vbKeyJ".lower()] = 74
        self.globals["vbKeyK".lower()] = 75
        self.globals["vbKeyL".lower()] = 76
        self.globals["vbKeyM".lower()] = 77
        self.globals["vbKeyN".lower()] = 78
        self.globals["vbKeyO".lower()] = 79
        self.globals["vbKeyP".lower()] = 80
        self.globals["vbKeyQ".lower()] = 81
        self.globals["vbKeyR".lower()] = 82
        self.globals["vbKeyS".lower()] = 83
        self.globals["vbKeyT".lower()] = 84
        self.globals["vbKeyU".lower()] = 85
        self.globals["vbKeyV".lower()] = 86
        self.globals["vbKeyW".lower()] = 87
        self.globals["vbKeyX".lower()] = 88
        self.globals["vbKeyY".lower()] = 89
        self.globals["vbKeyZ".lower()] = 90
        self.globals["vbKey0".lower()] = 48
        self.globals["vbKey1".lower()] = 49
        self.globals["vbKey2".lower()] = 50
        self.globals["vbKey3".lower()] = 51
        self.globals["vbKey4".lower()] = 52
        self.globals["vbKey5".lower()] = 53
        self.globals["vbKey6".lower()] = 54
        self.globals["vbKey7".lower()] = 55
        self.globals["vbKey8".lower()] = 56
        self.globals["vbKey9".lower()] = 57
        self.globals["vbKeyNumpad0".lower()] = 96
        self.globals["vbKeyNumpad1".lower()] = 97
        self.globals["vbKeyNumpad2".lower()] = 98
        self.globals["vbKeyNumpad3".lower()] = 99
        self.globals["vbKeyNumpad4".lower()] = 100
        self.globals["vbKeyNumpad5".lower()] = 101
        self.globals["vbKeyNumpad6".lower()] = 102
        self.globals["vbKeyNumpad7".lower()] = 103
        self.globals["vbKeyNumpad8".lower()] = 104
        self.globals["vbKeyNumpad9".lower()] = 105
        self.globals["vbKeyMultiply".lower()] = 106
        self.globals["vbKeyAdd".lower()] = 107
        self.globals["vbKeySeparator".lower()] = 108
        self.globals["vbKeySubtract".lower()] = 109
        self.globals["vbKeyDecimal".lower()] = 110
        self.globals["vbKeyDivide".lower()] = 111
        self.globals["vbKeyF1".lower()] = 112
        self.globals["vbKeyF2".lower()] = 113
        self.globals["vbKeyF3".lower()] = 114
        self.globals["vbKeyF4".lower()] = 115
        self.globals["vbKeyF5".lower()] = 116
        self.globals["vbKeyF6".lower()] = 117
        self.globals["vbKeyF7".lower()] = 118
        self.globals["vbKeyF8".lower()] = 119
        self.globals["vbKeyF9".lower()] = 120
        self.globals["vbKeyF10".lower()] = 121
        self.globals["vbKeyF11".lower()] = 122
        self.globals["vbKeyF12".lower()] = 123
        self.globals["vbKeyF13".lower()] = 124
        self.globals["vbKeyF14".lower()] = 125
        self.globals["vbKeyF15".lower()] = 126
        self.globals["vbKeyF16".lower()] = 127
        self.globals["vbNullString".lower()] = ''
        self.globals["vbNullChar".lower()] = '\0'

        self.globals["vbUpperCase".lower()] = 1
        self.globals["vbLowerCase".lower()] = 2
        self.globals["vbProperCase".lower()] = 3
        self.globals["vbWide".lower()] = 4
        self.globals["vbNarrow".lower()] = 8
        self.globals["vbKatakana".lower()] = 16
        self.globals["vbHiragana".lower()] = 32
        self.globals["vbUnicode".lower()] = 64
        self.globals["vbFromUnicode".lower()] = 128
        
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

    def get_type(self, var):
        var = var.lower()
        if (var not in self.types):
            return None
        return self.types[var]
            
    # TODO: set_global?

    def set(self, name, value, var_type=None):
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

        # If we know the type of the variable, save it.
        if (var_type is not None):
            self.types[name] = var_type
            
    def report_action(self, action, params=None, description=None):
        self.engine.report_action(action, params, description)


