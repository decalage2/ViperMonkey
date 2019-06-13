"""
ViperMonkey - API

ViperMonkey is a specialized engine to parse, analyze and interpret Microsoft
VBA macros (Visual Basic for Applications), mainly for malware analysis.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

Project Repository:
https://github.com/decalage2/ViperMonkey
"""

#=== LICENSE ==================================================================

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

import collections
import inspect

import pyparsing

# Enable PackRat for better performance:
# (see https://pythonhosted.org/pyparsing/pyparsing.ParserElement-class.html#enablePackrat)
pyparsing.ParserElement.enablePackrat(cache_size_limit=10000000)

from vipermonkey.core import deobfuscation
from vipermonkey.core.modules import *
from vipermonkey.core.modules import Module as _Module
from vipermonkey.core.vba_lines import vba_collapse_long_lines

# NOTE: This MUST be imported because it registers function to the VBA_LIBRARY
# dictionary in vba_context... don't ask me why.
# Make sure we populate the VBA Library:
from vipermonkey.core.vba_library import *


def _get_keywords(line, num=2):
    """Gets the first num keywords of line"""
    return line.lower().split(None, num)


class CustomVBALibraryFunc(VbaLibraryFunc):
    """Wraps a function into a VbaLibraryFunc class object."""
    def __init__(self, callback):
        self._callback = callback

    def eval(self, context, params=None):
        return self._callback(context, params=params)


class SmartDict(dict):
    """
    Smarter dictionary that handles the VBALibraryFunc types better.
    Also, the keys are case insensitive.
    """
    def __contains__(self, key):
        return super(SmartDict, self).__contains__(key.lower())

    def __getitem__(self, key):
        """Convert to case of key before retrieval."""
        return super(SmartDict, self).__getitem__(key.lower())

    def __setitem__(self, key, value):
        """Automatically convert VbaLibraryFunc classes and lambdas before setting."""
        # If a VBALibraryFunc class was passed in without being initialized, initialize it for them.
        if inspect.isclass(value) and issubclass(value, VbaLibraryFunc):
            value = value()
        # If a function was passed in, wrap it in a VbaLibraryFunc class.
        elif callable(value):
            value = CustomVBALibraryFunc(value)

        super(SmartDict, self).__setitem__(key.lower(), value)


orig_Context = Context


# MonkeyPatch Context with new features useful for a user
# FIXME: We can't just update the main context with this stuff because we can't get
#   the VbaLibraryFunc class to import there (which is needed by SmartDict).
#   This is due the complexities caused by the abundant use of wildcard imports.
class Context(orig_Context):
    """Overwrites ViperMonkey's original context to improve functionality:

        - simplify constructor
        - provide report_action callback
        - uses magic indexing
        - allows overwriting a function or sub with a custom python class.
        - allows providing a list of interesting functions to log.
            (this extends the function names already defined in Function_Call)
    """

    def __init__(self, report_action=None, **kwargs):
        """
        Initializes context

        :param report_action: Callback function used to report triggered actions.
        :param log_funcs: List of function to report as an interestting function call.
        :param kwargs: Extra options passed back to original context.
        """
        kwargs['engine'] = self  # Engine is self so that sub contexts also have report_action.
        super(Context, self).__init__(**kwargs)
        self._report_action = report_action
        self.actions = collections.defaultdict(list)

        # Replace dictionaries with "smarter" ones.
        if not isinstance(self.globals, SmartDict):
            self.globals = SmartDict(self.globals)
        if not isinstance(self.locals, SmartDict):
            self.locals = SmartDict(self.locals)

    def __contains__(self, item):
        try:
            _ = self[item]
            return True
        except KeyError:
            return False

    def __delitem__(self, key):
        """Remove item from context."""
        key = key.lower()
        if key in self.locals:
            del self.locals[key]
        elif key in self.globals:
            del self.globals[key]
        if key in self.types:
            del self.types[key]

    def __getitem__(self, item):
        """Let context['thing'] be equivalent to context.get('thing')"""
        return self.get(item)

    def __setitem__(self, key, value):
        """Let context['thing'] = 'foo' be equivalent to context.set('thing', 'foo')"""
        self.set(key, value)

    def report_action(self, action, params=None, description=None, strip_null_bytes=False):
        # NOTE: We are ignoring the strip_null_bytes parameter because that is a business logic detail.
        # Record action in context
        self.actions[description].append((action, params))
        # Perform any custom reporting.
        if self._report_action:
            self._report_action(action, params=params, description=description)


class CodeBlock(object):
    """
    Defines a block of code. This can be a function, for loop or even a single line of code.

    Each code block may also have internal code blocks within it.
    For example, in the below code, the function Execute() is a code block which has
    the internal code blocks -- the Dim statements and the For loop.
    The For loop also has internal code blocks containing the lines of code within it.

        Public Function Execute() As Variant
            Dim foo As String
            Dim counter As Integer
            For counter = 34 to 40
                foo = foo & Chr(counter)
            Next counter
        End Function

    :param pp_spec: pyparsing object used to parse the code.
    :param lines: String or list of lines representing the code.
    :param parse_all: Whether to ensure all the code will be parsed when using pp_spec
    :param deobfuscate: Whether to deobfuscate the code first which may speed up processing.
    """

    def __init__(self, pp_spec, lines, parse_all=True, deobfuscate=False):
        self._pp_spec = pp_spec
        if isinstance(lines, (bytes, str)):
            if deobfuscate:
                # vba_collapse_long_lines() is done in deobfuscate()
                lines = deobfuscation.deobfuscate(lines)
            else:
                lines = vba_collapse_long_lines(lines)
            self.lines = lines.splitlines(True)
        else:
            if deobfuscate:
                lines = deobfuscation.deobfuscate('\n'.join(lines)).splitlines(True)
            self.lines = lines
        self._obj = None
        self._parse_attempted = False
        self._parse_all = parse_all
        self._code_blocks = None

    def __str__(self):
        return ''.join(self.lines)

    def __getattr__(self, item):
        """Redirects anything that this class doesn't support back to the parsed obj."""
        # Default to None so we can avoid having to tediously check the type beforehand.
        return getattr(self.obj, item, None)

    @property
    def __class__(self):
        """
        Black magic necessary to fake the isinstance() to VBA_Objects in classes like
        SimpleNameExpression, Global_Var_Statement, and Module.
        """
        return self.obj.__class__

    @property
    def obj(self):
        """Returns VBA_Object or None on failure."""
        # TODO: Support the option of running the full grammar?
        if not self._obj:
            # Don't keep trying if we will fail.
            if self._parse_attempted:
                return None
            try:
                self._parse_attempted = True
                # parse the first line using provided pp_spec
                self._obj = self._pp_spec.parseString(self.lines[0], parseAll=self._parse_all)[0]
            except ParseException as err:
                log.warn('*** PARSING ERROR (3) ***\n{}\n{}\n{}'.format(
                    err.line, " " * (err.column - 1) + "^", err))
                return None
        return self._obj

    def _take_until(self, line_gen, end):
        """Consumes and yields lines from the given line generator until end tokens are found."""
        for line in line_gen:
            yield line
            if line.lower().split(None, len(end))[:len(end)] == end:
                return

    def _generate_code_block(self, line_gen, line, line_keywords):
        """
        Factory method for creating a CodeBlock from given line, line_keywords, and line generator
        to optional consume more lines.
        """
        # TODO: Add the other block code types like For, Switch, Case and If statements?
        if line_keywords[0] == 'for':
            log.debug('FOR LOOP')
            # NOTE: a for clause may be followed by ":" and statements on the same line
            lines = [line] + list(self._take_until(line_gen, ['next']))
            return CodeBlock(for_start, lines, parse_all=False)
        else:
            # NOTE: Needed to add EOS to fix "Expected end of text" errors. (This should be on vba_line)
            return CodeBlock(vba_line + Optional(EOS).suppress(), line)

    def _iter_code_blocks(self):
        """Iterates internal codes blocks contained within this block."""
        line_gen = iter(self.lines[1:-1])  # Iterate internal lines between the header and footer.
        for line in line_gen:
            # Parse line
            log.debug('Parsing line: {}'.format(line.rstrip()))
            # extract first two keywords in lowercase, for quick matching
            line_keywords = line.lower().split(None, 2)
            # ignore empty or comment lines
            if not line_keywords or line_keywords[0].startswith("'"):
                continue
            if line_keywords[0] in ('public', 'private'):
                # remove the public/private keyword:
                line_keywords = line_keywords[1:]

            yield self._generate_code_block(line_gen, line, line_keywords)

    @property
    def code_blocks(self):
        """Iterates internal code blocks. Caches results to speed up next request."""
        if self._code_blocks is None:
            code_blocks = []
            for code_block in self._iter_code_blocks():
                code_blocks.append(code_block)
                yield code_block
            self._code_blocks = code_blocks
        else:
            for code_block in self._code_blocks:
                yield code_block

    @property
    def type(self):
        """Returns type of VBA_Object."""
        return type(self.obj)

    def eval(self, context=None, params=None):
        """Evaluates line(s) of code. Returns evaluated value (if appropriate) or None."""
        context = context or Context()
        if not self.obj:
            log.error('Unable to evaluate "{}" due to parse error.'.format(self))
            return None
        # Before performing evaluation we need to parse all the internal code blocks
        # and add any parsed statements.
        if hasattr(self.obj, 'statements') and not self.obj.statements:
            # Even though we are passing our own class type it should still work because we have an
            # eval() function. (Duck typing and all that)
            self.obj.statements = list(self.code_blocks)
        if hasattr(self.obj, 'eval'):
            return self.obj.eval(context=context, params=params)
        else:
            return self.obj

    def load_context(self, context):
        """
        Loads context by evaluating code blocks within.
        This is a convenience function for performing the common need of trying to get the
        state of the context after a function as been run.
        """
        for code_block in self.code_blocks:
            code_block.eval(context)


class Module(CodeBlock):
    """The entry point for creating a VBA element for parsing/evaluation."""

    # List of possible entry point functions.
    _ENTRY_POINTS = ['autoopen', 'document_open', 'autoclose',
                     'document_close', 'auto_open', 'autoexec',
                     'autoexit', 'document_beforeclose', 'workbook_open',
                     'workbook_activate', 'auto_close', 'workbook_close']

    def __init__(self, lines, deobfuscate=False):
        """
        Initializes a VBA module (or collection of loose lines)

        :param lines: String or list lines representing the code.
        :param deobfuscate: Whether to deobfuscate the code first which may speed up processing.
        """

        # TODO: pp spec for module?
        # Instead of having a pyparsing spec, we are going to manually create the
        # parsed object from code blocks.
        super(Module, self).__init__(None, lines, deobfuscate=deobfuscate)
        # We are also going to include a dummy first line so that _iter_code_blocks()
        # doesn't skip the first line and last line.
        self.lines = [''] + self.lines + ['']

    def _generate_code_block(self, line_gen, line, line_keywords):
        # Overwrite, because a module can contain subs, functions, and module header lines
        # (VBA doesn't support nested functions/subs)
        if line_keywords[0] == 'attribute':
            return CodeBlock(header_statements_line, line)
        # TODO: Is dim necesary here, or can it be found via vba_line?
        elif line_keywords[0] in ('option', 'dim', 'declare'):
            log.debug('DECLARATION LINE')
            return CodeBlock(declaration_statements_line, line)
        elif line_keywords[0] == 'sub':
            log.debug('SUB')
            lines = [line] + list(self._take_until(line_gen, ['end', 'sub']))
            return CodeBlock(procedures.sub_start_line, lines)
        elif line_keywords[0] == 'function':
            log.debug('FUNCTION')
            lines = [line] + list(self._take_until(line_gen, ['end', 'function']))
            return CodeBlock(procedures.function_start_line, lines)
        else:
            return super(Module, self)._generate_code_block(line_gen, line, line_keywords)

    @property
    def functions(self):
        """Returns functions"""
        return self.obj.functions.values()

    @property
    def subs(self):
        """Returns subs"""
        return self.obj.subs.values()

    @property
    def procedures(self):
        """Returns subs and functions combined."""
        return self.functions + self.subs

    @property
    def entry_points(self):
        """Yields the entry points. (or None if not found)."""
        # Since the module VBA_Object stores its elements with case intact we can't just hash.
        for name, sub in self.obj.subs.iteritems():
            if name.lower() in self._ENTRY_POINTS:
                yield sub
        for name, function in self.obj.functions.iteritems():
            if name.lower() in self._ENTRY_POINTS:
                yield function

    def eval(self, context=None, params=None):
        """Evaluates line(s) of code. Returns evaluated value (if appropriate) or None."""
        context = context or Context()
        self.load_context(context)
        # Evaluate each loose code_block.
        # NOTE: I would have used their obj.eval() with their "loose_lines" but it seems to not
        #   detect a lot of things...
        #   It's easier and more reliable to just count anything that is not a Function/Sub as loose.
        #   (Also, it doesn't return anything)
        ret = None
        for code_block in self.code_blocks:
            if not isinstance(code_block, (Function, Sub)):
                # TODO: We are going to consider variables as local when run like this
                #   We should really have a "global" Context just be considered the parent Context object.
                #   ... That would make better scoping emulation!
                # context.global_scope = True  # must set inside encase the code changes it.
                ret = code_block.eval(context, params)
                # context.global_scope = False
        return ret

    # TODO: Rename to declare()?
    def load_context(self, context):
        # For a Module this will declare all subs and functions into the context.
        # NOTE: I am not using obj.load_context() because the functions/subs
        #   are set to locals instead of globals.
        context = context or Context()
        for name, _sub in self.obj.subs.items():
            log.debug('(3) storing sub "%s" in globals' % name)
            context.globals[name.lower()] = _sub
        for name, _function in self.obj.functions.items():
            log.debug('(3) storing function "%s" in globals' % name)
            context.globals[name.lower()] = _function
        for name, _function in self.obj.external_functions.items():
            log.debug('(3) storing external function "%s" in globals' % name)
            context.globals[name.lower()] = _function
        for name, _var in self.obj.global_vars.items():
            log.debug('(3) storing global var "%s" in globals' % name)
            if isinstance(name, str):
                context.globals[name.lower()] = _var
            if isinstance(name, list):
                context.globals[name[0].lower()] = _var
                context.types[name[0].lower()] = name[1]

    @property
    def obj(self):
        """Returns VBA_Object or None on failure."""
        # Instead of using a pyparsing spec, we are going to manually
        # call and grab all the components from code_blocks.
        # (This helps to prevent calling eval() to every code block.)
        if not self._obj:
            # TODO: Instead of blindly processing the obj for every code_block, only
            # process Sub, Function, External_Function, Attribute_Statement, and Global_Var_Statement
            # We need to replicate the initialization done in modules.Module but with code_blocks.
            self._obj = _Module(str(self), 0, list(self.code_blocks))
        return self._obj


def eval(vba_code, context=None, deobfuscate=False):
    """
    A quick helper function to evaluate a chunk of code. (Useful as an analysis or development tool.)

    :param str vba_code: VBA code to evaluate
    :param context: Context obj to fill while evaluating.
    :param deobfuscate: Whether to deobfuscate the code first which may speed up processing.

    :return: Evaluated results.
    """
    context = context or Context()
    module = Module(vba_code, deobfuscate=deobfuscate)
    return module.eval(context)
