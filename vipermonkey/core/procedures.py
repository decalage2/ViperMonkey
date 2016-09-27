#!/usr/bin/env python
"""
ViperMonkey: VBA Grammar - Procedures

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

from vba_context import *
from statements import *

from logger import log
log.debug('importing procedures')

# --- SUB --------------------------------------------------------------------

class Sub(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(Sub, self).__init__(original_str, location, tokens)
        self.name = tokens.sub_name
        self.params = tokens.params
        self.statements = tokens.statements
        log.info('parsed %r' % self)

    def __repr__(self):
        return 'Sub %s (%s): %d statement(s)' % (self.name, self.params, len(self.statements))

    def eval(self, context, params=None):
        # create a new context for this execution:
        caller_context = context
        context = Context(context=caller_context)
        if params is not None:
            # TODO: handle named parameters
            for i in range(len(params)):
                param_name = self.params[i].name
                param_value = params[i]
                log.debug('Sub %s: setting param %s = %r' % (self.name, param_name, param_value))
                context.set(param_name, param_value)
        log.debug('evaluating Sub %s(%s)' % (self.name, params))
        # TODO self.call_params
        for s in self.statements:
            log.debug('Sub %s eval statement: %s' % (self.name, s))
            s.eval(context=context)


# 5.3.1.1 Procedure Scope
# procedure-scope = ["global" / "public" / "private" / "friend"]

procedure_scope = Optional(CaselessKeyword('Public') | CaselessKeyword('Private')
                           | CaselessKeyword('Global') | CaselessKeyword('Friend')).suppress()

# 5.3.1.2 Static Procedures
# initial-static = "static"
# trailing-static = "static"

static_keyword = Optional(CaselessKeyword('static'))

# TODO: 5.4 Procedure Bodies and Statements

# 5.3.1.3 Procedure Names
# subroutine-name = IDENTIFIER / prefixed-name
# function-name = TYPED-NAME / subroutine-name
# prefixed-name = event-handler-name / implemented-name / lifecycle-handler-name

# 5.3.1.8 Event Handler Declarations
# event-handler-name = IDENTIFIER

# 5.3.1.9 Implemented Name Declarations
# implemented-name = IDENTIFIER

# 5.3.1.10 Lifecycle Handler Declarations
# lifecycle-handler-name = "Class_Initialize" / "Class_Terminate"

lifecycle_handler_name = CaselessKeyword("Class_Initialize") | CaselessKeyword("Class_Terminate")
implemented_name = identifier  # duplicate, not used
event_handler_name = identifier  # duplicate, not used
prefixed_name = identifier | lifecycle_handler_name  # simplified

subroutine_name = identifier | lifecycle_handler_name  # simplified

# typed_name = identifier + optional type_suffix => simplified
# function_name = typed_name | subroutine_name
function_name = Combine(identifier + Suppress(Optional(type_suffix))) | lifecycle_handler_name

# 5.3.1 Procedure Declarations
# end-label = statement-label-definition
end_label = statement_label_definition

# procedure-tail = [WS] LINE-END / single-quote comment-body / ":" rem-statement
procedure_tail = FollowedBy(line_terminator) | comment_single_quote | Literal(":") + rem_statement
# NOTE: rem statement does NOT include the line terminator => BUG?
# TODO: here i assume that procedure tail does NOT include the line terminator

# subroutine-declaration = procedure-scope [initial-static]
#       "sub" subroutine-name [procedure-parameters] [trailing-static] EOS
#       [procedure-body EOS]
#       [end-label] "end" "sub" procedure-tail
# function-declaration = procedure-scope [initial-static]
#       "function" function-name [procedure-parameters] [function-type]
#       [trailing-static] EOS
#       [procedure-body EOS]
#       [end-label] "end" "function" procedure-tail
# property-get-declaration = procedure-scope [initial-static]
#       "Property" "Get"
#       function-name [procedure-parameters] [function-type] [trailing-static] EOS
#       [procedure-body EOS]
#       [end-label] "end" "property" procedure-tail
# property-lhs-declaration = procedure-scope [initial-static]
#       "Property" ("Let" / "Set")
#       subroutine-name property-parameters [trailing-static] EOS
#       [procedure-body EOS]
#       [end-label] "end" "property" procedure-tail


public_private = Optional(CaselessKeyword('Public') | CaselessKeyword('Private')).suppress()

params_list_paren = Suppress('(') + Optional(parameters_list('params')) + Suppress(')')

sub_start = public_private + CaselessKeyword('Sub').suppress() + lex_identifier('sub_name') \
            + Optional(params_list_paren) + EOS.suppress()
sub_end = (CaselessKeyword('End') + CaselessKeyword('Sub') + EOS).suppress()
sub = sub_start + Group(ZeroOrMore(statements_line)).setResultsName('statements') + sub_end
sub.setParseAction(Sub)


# --- FUNCTION --------------------------------------------------------------------

# TODO: Function should inherit from Sub, or use only one class for both

class Function(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(Function, self).__init__(original_str, location, tokens)
        self.name = tokens.function_name
        self.params = tokens.params
        self.statements = tokens.statements
        self.return_type = tokens.return_type
        self.vars = {}
        log.info('parsed %r' % self)

    def __repr__(self):
        return 'Function %s (%s): %d statement(s)' % (self.name, self.params, len(self.statements))

    def eval(self, context, params=None):
        # create a new context for this execution:
        caller_context = context
        context = Context(context=caller_context)
        # add function name in locals:
        context.set(self.name, None)
        if params is not None:
            # TODO: handle named parameters
            for i in range(len(params)):
                param_name = self.params[i].name
                param_value = params[i]
                log.debug('Function %s: setting param %s = %r' % (self.name, param_name, param_value))
                context.set(param_name, param_value)
        log.debug('evaluating Function %s(%s)' % (self.name, params))
        # TODO self.call_params
        for s in self.statements:
            log.debug('Function %s eval statement: %s' % (self.name, s))
            s.eval(context=context)
        # TODO: get result from context.locals
        return_value = context.get(self.name)
        log.debug('Function %s: return value = %r' % (self.name, return_value))
        return return_value


# TODO 5.3.1.4 Function Type Declarations
function_type2 = CaselessKeyword('As').suppress() + lex_identifier('return_type') \
                 + Optional(Literal('(') + Literal(')')).suppress()

function_start = public_private + CaselessKeyword('Function').suppress() + lex_identifier('function_name') \
                 + Optional(params_list_paren) + Optional(function_type2) + EOS.suppress()

function_end = (CaselessKeyword('End') + CaselessKeyword('Function') + EOS).suppress()

function = function_start + Group(ZeroOrMore(statements_line)).setResultsName('statements') + function_end
function.setParseAction(Function)


# --- EXTERNAL FUNCTION ------------------------------------------------------


class External_Function(VBA_Object):
    """
    External Function from a DLL
    """

    def __init__(self, original_str, location, tokens):
        super(External_Function, self).__init__(original_str, location, tokens)
        self.name = tokens.function_name
        self.params = tokens.params
        self.lib_name = tokens.lib_name
        # normalize lib name: remove quotes, lowercase, add .dll if no extension
        if isinstance(self.lib_name, basestring):
            self.lib_name = tokens.lib_name.strip('"').lower()
            if '.' not in self.lib_name:
                self.lib_name += '.dll'
        self.alias_name = tokens.alias_name
        if isinstance(self.alias_name, basestring):
            # TODO: this might not be necessary if alias is parsed as quoted string
            self.alias_name = self.alias_name.strip('"')
        self.return_type = tokens.return_type
        self.vars = {}
        log.debug('parsed %r' % self)

    def __repr__(self):
        return 'External Function %s (%s) from %s alias %s' % (self.name, self.params, self.lib_name, self.alias_name)

    def eval(self, context, params=None):
        # create a new context for this execution:
        caller_context = context
        context = Context(context=caller_context)
        # TODO: use separate classes for each known DLL and methods for functions?
        # TODO: use the alias name instead of the name!
        if self.alias_name:
            function_name = self.alias_name
        else:
            function_name = self.name
        log.debug('evaluating External Function %s(%r)' % (function_name, params))
        function_name = function_name.lower()
        if self.lib_name.startswith('urlmon'):
            if function_name.startswith('urldownloadtofile'):
                context.report_action('Download URL', params[1], 'External Function: urlmon.dll / URLDownloadToFile')
                context.report_action('Write File', params[2], 'External Function: urlmon.dll / URLDownloadToFile')
                # return 0 when no error occurred:
                return 0
        # TODO: return result according to the known DLLs and functions
        log.error('Unknown external function %s from DLL %s' % (function_name, self.lib_name))
        return None


# 5.2.3.5 External Procedure Declaration
lib_info = CaselessKeyword('Lib').suppress() + quoted_string('lib_name') \
           + Optional(CaselessKeyword('Alias') + quoted_string('alias_name'))

# TODO: identifier or lex_identifier
external_function = public_private + Suppress(CaselessKeyword('Declare') + Optional(CaselessKeyword('PtrSafe'))
                                              + CaselessKeyword('Function')) + lex_identifier(
    'function_name') + lib_info \
                    + Optional(params_list_paren) + Optional(function_type)
external_function.setParseAction(External_Function)


