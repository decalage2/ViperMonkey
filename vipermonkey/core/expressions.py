#!/usr/bin/env python
"""
ViperMonkey: VBA Grammar - Expressions

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

__version__ = '0.03'

# --- IMPORTS ------------------------------------------------------------------

import re
import sys
import os
import array
from hashlib import sha256

from identifiers import *
from lib_functions import *
from literals import *
from operators import *
import procedures
from vba_object import eval_arg
from vba_object import coerce_to_int
from vba_object import strip_nonvb_chars
from vba_object import int_convert
from vba_object import VbaLibraryFunc
import vba_context

from logger import log

# --- FILE POINTER -------------------------------------------------

file_pointer = Suppress('#') + (decimal_literal | lex_identifier)
file_pointer.setParseAction(lambda t: "#" + str(t[0]))

# --- SIMPLE NAME EXPRESSION -------------------------------------------------

class SimpleNameExpression(VBA_Object):
    """
    Identifier referring to a variable within a VBA expression:
    single identifier with no qualification or argument list
    """

    def __init__(self, original_str, location, tokens):
        super(SimpleNameExpression, self).__init__(original_str, location, tokens)
        self.name = tokens.name
        log.debug('parsed %r as SimpleNameExpression' % self)

    def __repr__(self):
        return '%s' % self.name

    def eval(self, context, params=None):
        log.debug('try eval variable/function %r' % self.name)
        try:
            value = context.get(self.name)
            log.debug('get variable %r = %r' % (self.name, value))
            if (isinstance(value, procedures.Function) or
                isinstance(value, procedures.Sub) or
                isinstance(value, VbaLibraryFunc)):

                # Only evaluate functions with 0 args since we have no
                # arguments at this point.
                # TODO: Need to also handle VbaLibraryFunc.
                if ((isinstance(value, procedures.Function) or
                     isinstance(value, procedures.Sub)) and
                    (len(value.params) > 0)):
                    return "NULL"

                # 0 parameter function. Evaluate it.
                log.debug('evaluating function %r' % value)
                value = value.eval(context)
                log.debug('evaluated function %r = %r' % (self.name, value))
            return value
        except KeyError:
            log.warning('Variable %r not found' % self.name)
            if (self.name.startswith("%") and self.name.endswith("%")):
                return self.name.upper()
            return "NULL"

# 5.6.10 Simple Name Expressions
# A simple name expression consists of a single identifier with no qualification or argument list.
#
# MS-GRAMMAR: simple-name-expression = name

simple_name_expression = Optional(CaselessKeyword("ByVal").suppress()) + TODO_identifier_or_object_attrib('name')
simple_name_expression.setParseAction(SimpleNameExpression)

# A placeholder representing a missing default value function call parameter.
placeholder = Keyword("***PLACEHOLDER***")
placeholder.setParseAction(lambda t: str(t[0]))

# --- INSTANCE EXPRESSIONS ------------------------------------------------------------

class InstanceExpression(VBA_Object):
    """
    An instance expression consists of the keyword "Me".
    It represents the current instance of the type defined by the
    enclosing class module and has this type as its value type.
    """

    def __init__(self, original_str, location, tokens):
        super(InstanceExpression, self).__init__(original_str, location, tokens)
        log.debug('parsed %r as InstanceExpression' % self)

    def __repr__(self):
        return 'Me'

    def eval(self, context, params=None):
        raise NotImplementedError


# 5.6.11 Instance Expressions
# An instance expression consists of the keyword Me.
#
# MS-GRAMMAR: instance-expression = "me"

# Static semantics. An instance expression is classified as a value. The declared type of an instance
# expression is the type defined by the class module containing the enclosing procedure. It is invalid
# for an instance expression to occur within a procedural module.
# Runtime semantics. The keyword Me represents the current instance of the type defined by the
# enclosing class module and has this type as its value type.

instance_expression = CaselessKeyword('Me').suppress()
instance_expression.setParseAction(InstanceExpression)

# --- MEMBER ACCESS EXPRESSIONS ------------------------------------------------------------

# 5.6.12 Member Access Expressions
# A member access expression is used to reference a member of an entity.
#
# MS-GRAMMAR: member-access-expression = l-expression NO-WS "." unrestricted-name
# MS-GRAMMAR: member-access-expression =/ l-expression LINE-CONTINUATION "." unrestricted-name

# NOTE: Here we assume that all line-continuation characters have been removed,
#       so the 2nd part of member-access-expression does not apply.
#       Moreover, there may be whitespaces before the dot, due to the removal.

# Examples: varname.attrname, varname(2).attrname, varname .attrname

class MemberAccessExpression(VBA_Object):
    """
    Handle member access expressions.
    """

    def __init__(self, original_str, location, tokens, raw_fields=None):

        # Are we manually creating a member access object?
        if (raw_fields is not None):
            self.lhs = raw_fields[0]
            self.rhs = raw_fields[1]
            self.rhs1 = raw_fields[2]
            log.debug('Manually created MemberAccessExpression %r' % self)

        # Make a member access object from parse results.
        else:
            super(MemberAccessExpression, self).__init__(original_str, location, tokens)
            tokens = tokens[0][0]
            self.rhs = tokens[1:]
            self.lhs = tokens.lhs
            self.rhs1 = ""
            if (hasattr(tokens, "rhs1")):
                self.rhs1 = tokens.rhs1
            log.debug('parsed %r as MemberAccessExpression' % self)

    def __repr__(self):
        r = str(self.lhs)
        for t in self.rhs:
            r += "." + str(t)
        if (len(self.rhs1) > 0):
            r += "." + str(self.rhs1)
        return r

    def _handle_paragraphs(self, context):
        """
        Handle references to the .Paragraphs field of the current doc.
        """
        if (str(self).lower().endswith(".paragraphs")):
            return context.get("ActiveDocument.Paragraphs".lower())
    
    def _handle_oslanguage(self, context):
        """
        Handle references to the OSlanguage field.
        """
        if (str(self).lower().endswith(".oslanguage")):
            return context.get("oslanguage")
    
    def _handle_application_run(self, context):
        """
        Handle functions called with Application.Run()
        """

        # Is this an Application.Run() instance?
        if ((not str(self).startswith("Application.Run(")) and
            (not str(self).lower().startswith("thisdocument.run("))):
            return None
        
        # Pull out the function name and arguments.
        if (len(self.rhs[0].params) == 0):
            return None

        # Full function call?
        if (isinstance(self.rhs[0].params[0], Function_Call)):
            func_name = self.rhs[0].params[0].name
            func_args = self.rhs[0].params[0].params

        # List containing function name + args?
        else:
            func_name = str(self.rhs[0].params[0])
            func_args = []
            if (len(self.rhs[0].params) > 1):
                func_args = self.rhs[0].params[1:]
            func_args = eval_args(func_args, context)

        # See if we can run the other function.
        log.debug("Try indirect run of function '" + func_name + "'")
        try:
            s = func_name
            while (isinstance(s, str)):
                s = context.get(s)
            if (s is None):
                return None
            r = s.eval(context=context, params=func_args)

            # Report actions if interesting.
            if (str(self).lower().startswith("thisdocument.run(")):
                context.report_action('Execute Command', r, 'ThisDocument.Run', strip_null_bytes=True)
            return r
        
        except KeyError:
            return None

    def _handle_set_clipboard(self, context):
        """
        Handle calls like objHTML.ParentWindow.clipboardData.setData(...).
        """

        # Is this a setData() instance?
        if (".setdata(" not in str(self).lower()):
            return None
        
        # Pull out the clipboard text.
        # objHTML.ParentWindow.clipboardData.setData(Text, hh)
        func = self.rhs[-1]
        if (not isinstance(func, Function_Call)):
            return None
        if (len(func.params) < 2):
            return None
        val = func.params[1]
        val = str(eval_arg(val, context))

        # Set the clipboard value in a synthetic variable.
        log.debug("Save clipboard text '" + val + "'")
        context.set("** CLIPBOARD **", val, force_global=True)
        return True

    def _handle_get_clipboard(self, context):
        """
        Handle calls like objHTML.ParentWindow.clipboardData.getData(...).
        """

        # Is this an getData() instance?
        if (".getdata(" not in str(self).lower()):
            return None
        
        # Retrn the clipboard text if we have it.
        if (context.contains("** CLIPBOARD **")):
            return context.get("** CLIPBOARD **")
        return None
        
    def _handle_docprops_read(self, context):
        """
        Handle data reads with ActiveDocument.BuiltInDocumentProperties(...).
        """

        # ActiveDocument.BuiltInDocumentProperties("liclrm('U1ViamVjdA==')").Value
        # Is this an ActiveDocument.BuiltInDocumentProperties() instance?
        if (not str(self).startswith("ActiveDocument.BuiltInDocumentProperties(")):
            return None

        # Pull out the name of the property to read.
        if (len(self.rhs[0].params) == 0):
            return None
        field_name = eval_arg(self.rhs[0].params[0], context)
        
        # Try to pull the result from the document data.
        return context.get_doc_var(field_name)

    def _handle_docvars_read(self, context):
        """
        Handle data reads from a document variable.
        """

        # Try an actual doc var read first.
        tmp = self.__repr__().lower()
        if (tmp.startswith("activedocument.variables(")):
            return eval_arg(self.__repr__(), context)

        # Now widen this up to more general data that can be read from the
        # doc.        
        return context.get_doc_var(tmp)

    def _handle_text_file_read(self, context):
        """
        Handle OpenTextFile(...).ReadAll() calls.
        """

        # Do we have a text file read?
        tmp = self.__repr__().lower()
        if (("opentextfile(" not in tmp) or ("readall" not in tmp)):
            return None

        # Get the name of the file being read.
        if (len(self.rhs) < 2):
            return None
        read_call = self.rhs[-2]
        if (not isinstance(read_call, Function_Call)):
            return None
        read_file = str(eval_arg(read_call.params[0], context))

        # NOTE: Disabled this because it creates inconsistencies in results.
        # # Fix the file name for emulation if needed.
        # if (read_file.startswith("C:\\")):
        #     read_file = read_file.replace("C:\\", "./")

        # TODO: Should we be actually reading files from the system?
        # Read the file contents.
        try:
            f = open(read_file, 'r')
            r = f.read()
            f.close()
            return r
        except Exception as e:
            log.error("ReadAll('" + read_file + "') failed. " + str(e))
            return None

    def _handle_docvar_value(self, lhs, rhs):
        """
        Handle reading .Name and .Value fields from doc vars.
        """

        # Pull out proper RHS.
        if ((isinstance(rhs, list)) and (len(rhs) > 0)):
            rhs = rhs[0]
        
        # Do we have a tuple representing a doc var?
        if (not isinstance(lhs, tuple)):
            return None
        if (len(lhs) < 2):
            return None
        
        # Getting .Name?
        if (rhs == "Name"):
            return lhs[0]

        # Getting .Value?
        if (rhs == "Value"):
            return lhs[1]

        # Don't know what we are getting.
        return None

    def _handle_file_close(self, context, lhs, rhs):
        """
        Handle close of file object foo like foo.Close().
        """

        # Pull out proper RHS.
        if ((isinstance(rhs, list)) and (len(rhs) > 0)):
            rhs = rhs[0]
        if (str(rhs) != "Close"):
            return None
        from vba_library import Close
        file_close = Close()
            
        # File closed.
        return file_close.eval(context, [str(lhs)])
    
    def _handle_replace(self, context, lhs, rhs):
        """
        Handle string replaces of the form foo.Replace(bar, baz). foo is a RegExp object.
        """

        # Sanity check.
        if ((isinstance(rhs, list)) and (len(rhs) > 0)):
            rhs = rhs[0]
        if (not isinstance(rhs, Function_Call)):
            return None
        if (rhs.name != "Replace"):
            return None
        if (str(lhs) != "RegExp"):
            return None

        # Do we have a pattern for the RegExp?
        pat_name = str(self.lhs) + ".pattern"
        if (not context.contains(pat_name)):
            return None
        repl = context.get(pat_name)
        
        # Run the string replace.
        # expression, find, replace
        new_replace = Function_Call(None, None, None, old_call=rhs)
        tmp = [new_replace.params[0]]
        tmp.append(repl)
        tmp.append(new_replace.params[1])
        tmp.append("<-- USE REGEX -->")
        new_replace.params = tmp
        
        # Evaluate the string replace.
        r = new_replace.eval(context)
        return r

    def _handle_add(self, context, lhs, rhs):
        """
        Handle Add() object method calls like foo.Replace(bar, baz). 
        foo is (currently) a Scripting.Dictionary object.
        """

        # Sanity check.
        log.debug("_handle_add(): lhs = " + str(lhs) + ", rhs = " + str(rhs))
        if ((isinstance(rhs, list)) and (len(rhs) > 0)):
            rhs = rhs[0]
        if (not isinstance(rhs, Function_Call)):
            return None
        if (rhs.name != "Add"):
            return None
        if (not isinstance(lhs, dict)):
            return None

        # Run the dictionary add.
        # dict, key, value
        new_add = Function_Call(None, None, None, old_call=rhs)
        tmp = [lhs]
        for p in new_add.params:
            tmp.append(p)
        new_add.params = tmp
        log.debug("Add() func = " + str(new_add))
        
        # Evaluate the dictionary add.
        new_add.eval(context)
        return "updated dict"

    def _handle_adodb_writes(self, lhs_orig, lhs, rhs, context):
        """
        Handle expressions like "foo.Write(...)" where foo = "ADODB.Stream".
        """

        # Is this a .Write() call?
        log.debug("_handle_adodb_writes(): lhs_orig = " + str(lhs_orig) + ", lhs = " + str(lhs) + ", rhs = " + str(rhs))
        rhs_str = str(rhs).strip()
        if ("write(" not in rhs_str.lower()):
            return False
        
        # Is this a Write() being called on an ADODB.Stream object?
        if (lhs != "ADODB.Stream"):

            # Maybe we need a sub field? Do we have a subfield?
            if ((not isinstance(self.rhs, list)) or (len(self.rhs) < 2)):
                return False

            # Look for ADODB.Stream in a variable from a subfield.
            for field in self.rhs[:-1]:
                lhs_orig += "." + str(field)

        # Are we referencing a stream contained in a variable?        
        if (not context.contains(str(lhs_orig))):
            return False
        
        # Pull out the text to write to the text stream.
        txt = str(eval_arg(rhs.params[0], context))

        # Set the text value of the string as a faux variable. Make this
        # global as a hacky solution to handle fields in user defined objects.
        context.set(str(lhs_orig) + ".ReadText", txt, force_global=True)
        
        # We handled the write.
        return True

    def _handle_excel_read(self, context, rhs):
        """
        Handle Excel reads like worksheets.cells(1,2).
        """

        # Evaluate the Cells() call.
        #r = eval_arg(rhs, context)
        return None

    def _handle_0_arg_call(self, context, rhs):
        """
        Handle calls to 0 argument functions.
        """

        # Got possible function name?
        if ((not isinstance(rhs, str)) or (not context.contains(rhs))):
            return None
        func = context.get(rhs)
        if ((not isinstance(func, procedures.Sub)) and
            (not isinstance(func, procedures.Function))):
            return None

        # Is this a 0 argument function?
        if (len(func.params) > 0):
            return None

        # 0 parameter function. Evaluate it.
        log.debug('evaluating function %r' % func)
        r = func.eval(context)
        log.debug('evaluated function %r = %r' % (func.name, r))
        return r

    def _handle_loadxml(self, context, load_xml_result):
        """
        Handle things like kXMeYOrbWn.LoadXML(VuvMyknuKxHFAK). This is 
        specifically targeting BASE64 XML elements used for base64 decoding.
        """

        # Is this a call to LoadXML()?
        memb_str = str(self)
        if (".LoadXML(" not in memb_str):
            return False

        # We have a call to LoadXML(). Set the value of the .text field in
        # the VBA object to the XML or base64 contents.
        var_name = memb_str[:memb_str.index(".")] + ".text"
        context.set(var_name, load_xml_result)
        var_name = memb_str[:memb_str.index(".")] + ".selectsinglenode('b64decode').text"
        context.set(var_name, load_xml_result)
        var_name = memb_str[:memb_str.index(".")] + ".nodetypedvalue"
        context.set(var_name, load_xml_result)
        var_name = memb_str[:memb_str.index(".")] + ".selectsinglenode('b64decode').nodetypedvalue"
        context.set(var_name, load_xml_result)
        
        # Done.
        return True

    def _handle_savetofile(self, context, filename):
        """
        Handle things like TvfSKqpfj.SaveToFile oFyFLFCozNUyE, 2.
        """

        # Is this a call to SaveToFile()?
        memb_str = str(self)
        if (".savetofile(" not in memb_str.lower()):
            return False

        # We have a call to SaveToFile(). Get the value to save from .ReadText
        var_name = memb_str[:memb_str.index(".")] + ".ReadText"
        val = None
        try:
            val = context.get(var_name)
        except KeyError:
            return False

        # TODO: Use context.open_file()/write_file()/close_file()

        # Make the dropped file directory if needed.
        out_dir = vba_context.out_dir
        if (not os.path.isdir(out_dir)):
            os.makedirs(out_dir)
        
        # Dump the data to a file.
        if ("/" in filename):
            filename = filename[filename.rindex("/") + 1:]
        if ("\\" in filename):
            filename = filename[filename.rindex("\\") + 1:]
        fname = out_dir + "/" + filename
        try:

            # Write out the file.
            f = open(fname, 'wb')
            f.write(val)
            f.close()
            context.report_action('Write File', filename, 'ADODB.Stream SaveToFile()', strip_null_bytes=True)

            # Save the hash of the written file.
            raw_data = array.array('B', val).tostring()
            h = sha256()
            h.update(raw_data)
            file_hash = h.hexdigest()
            context.report_action("Dropped File Hash", file_hash, 'File Name: ' + filename)

        except Exception as e:
            log.error("Writing " + fname + " failed. " + str(e))
            return False
        
        # Done.
        return True

    def _handle_path_access(self):
        """
        See if this is accessing the Path field of a file/folder object.
        """
        if (str(self.rhs).lower() == "path"):

            # Fake a path.
            return "C:\\Users\\admin\\"
    
    def eval(self, context, params=None):

        log.debug("MemberAccess eval of " + str(self))
        
        # See if this is reading the OSlanguage.
        call_retval = self._handle_oslanguage(context)
        if (call_retval is not None):
            return call_retval

        # See if this is reading the doc paragraphs.
        call_retval = self._handle_paragraphs(context)
        if (call_retval is not None):
            return call_retval
        
        # See if this is a function call like Application.Run("foo", 12, 13).
        call_retval = self._handle_application_run(context)
        if (call_retval is not None):
            return call_retval

        # See if this is a function call like ActiveDocument.BuiltInDocumentProperties("foo").
        call_retval = self._handle_docprops_read(context)
        if (call_retval is not None):
            return call_retval
        
        # Handle accessing document variables as a special case.
        call_retval = self._handle_docvars_read(context)
        if (call_retval is not None):
            return call_retval

        # Handle setting the clipboard text.
        call_retval = self._handle_set_clipboard(context)
        if (call_retval is not None):
            return call_retval

        # Handle getting the clipboard text.
        call_retval = self._handle_get_clipboard(context)
        if (call_retval is not None):
            return call_retval

        # Pull out the left hand side of the member access.
        tmp_lhs = None
        if (self.lhs is not None):
            tmp_lhs = eval_arg(self.lhs, context)
        else:
            # This is something like ".foo.bar" in a With statement. The LHS
            # is the With context item.
            tmp_lhs = eval_arg(context.with_prefix, context)
            
        # TODO: Need to actually have some sort of object model. For now
        # just treat this as a variable access.
        tmp_rhs = None
        rhs = None
        if (len(self.rhs1) > 0):
            rhs = self.rhs1
        else:
            rhs = self.rhs[len(self.rhs) - 1]
            if ((str(rhs) == "Text") and (len(self.rhs) > 1)):
                rhs = self.rhs[len(self.rhs) - 2]

        # Handle simple 0-argument function calls.
        call_retval = self._handle_0_arg_call(context, rhs)
        if (call_retval is not None):
            return call_retval
        
        # Handle reading the contents of a text file.
        call_retval = self._handle_text_file_read(context)
        if (call_retval is not None):
            return call_retval

        # Handle writes of text to ADODB.Stream variables.
        if (self._handle_adodb_writes(self.lhs, tmp_lhs, rhs, context)):
            return "NULL"

        # See if this is accessing the Path field of a file/folder object.
        call_retval = self._handle_path_access()
        if (call_retval is not None):
            return call_retval
        
        # If the final element in the member expression is a function call,
        # the result should be the result of the function call. Otherwise treat
        # it as a fancy variable access.
        if (isinstance(rhs, Function_Call)):
            log.debug('rhs {!r} is a Function_Call'.format(rhs))

            # Skip local functions that have a name collision with VBA built in functions.
            if (context.contains_user_defined(rhs.name)):
                for func in Function_Call.log_funcs:
                    if (rhs.name.lower() == func.lower()):
                        return str(self)

            # Handle things like foo.Replace(bar, baz).
            call_retval = self._handle_replace(context, tmp_lhs, self.rhs)
            if (call_retval is not None):
                return call_retval

            # Handle things like foo.Add(bar, baz).
            call_retval = self._handle_add(context, tmp_lhs, self.rhs)
            if (call_retval is not None):
                return call_retval

            # Handle Excel cells() references.
            call_retval = self._handle_excel_read(context, self.rhs)
            if (call_retval is not None):
                return call_retval
                    
            # This is not a builtin. Evaluate it
            tmp_rhs = eval_arg(rhs, context)

            # Was this a call to LoadXML()?
            if (self._handle_loadxml(context, tmp_rhs)):
                return "NULL"

            # Was this a call to SaveToFile()?
            if (self._handle_savetofile(context, tmp_rhs)):
                return "NULL"

            # It was a regular call.
            return tmp_rhs

        # Did the lhs resolve to something new?
        elif (str(self.lhs) != str(tmp_lhs)):

            # Is this a read from an Excel cell?
            # TODO: Need to do this logic based on what IS an Excel read rather
            # than what IS NOT an Excel read.
            if ((isinstance(tmp_lhs, str)) and
                (not "Shapes(" in tmp_lhs) and
                (not "Close" in str(self.rhs))):

                # Just work with the returned string value.
                return tmp_lhs

            # See if this is reading a doc var name or item.
            call_retval = self._handle_docvar_value(tmp_lhs, self.rhs)
            if (call_retval is not None):
                return call_retval

            # See if this is closing a file.
            call_retval = self._handle_file_close(context, tmp_lhs, self.rhs)
            if (call_retval is not None):
                return call_retval

            # Is the LHS a 0 argument function?
            if ((isinstance(tmp_lhs, procedures.Function)) and
                (len(tmp_lhs.params) == 0)):

                # The LHS is actually a function call. Emulate the function
                # in the current context.
                r = tmp_lhs.eval(context)
                return r
            
            # Construct a new partially resolved member access object.
            r = MemberAccessExpression(None, None, None, raw_fields=(tmp_lhs, self.rhs, self.rhs1))
            
            # See if we can now resolve this to a doc var read.
            call_retval = r._handle_docvars_read(context)
            if (call_retval is not None):
                log.debug("MemberAccess: Found " + str(r) + " = '" + str(call_retval) + "'") 
                return call_retval
            
            # Cannot resolve directly. Return the member access object.
            log.debug("MemberAccess: Return new access object " + str(r))
            return r

        # Punt and just try to eval this as a string.
        else:
            return eval_arg(self.__repr__(), context)
        
# need to use Forward(), because the definition of l-expression is recursive:
l_expression = Forward()

function_call_limited = Forward()
func_call_array_access_limited = Forward()
function_call = Forward()

member_object_limited = (
    (Suppress(Optional("[")) + unrestricted_name + Suppress(Optional("]")))
    + NotAny("(")
    + NotAny("#")
    + NotAny("$")
    + NotAny("!")
)
# If the member is a function, it cannot be the last member, otherwise this line is considered a Call_Statement.
member_object = (func_call_array_access_limited ^ function_call_limited) | member_object_limited


# TODO: Just use delimitedList is the "lhs"/"rhs" neccessary?
member_access_expression = Group(Group(member_object("lhs") + OneOrMore(Suppress(".") + member_object("rhs"))))
member_access_expression.setParseAction(MemberAccessExpression)


# Whitespace allowed before the "."
member_access_expression_loose = Group(
    Group(
        Suppress(ZeroOrMore(" "))
        + member_object("lhs")
        + OneOrMore(Suppress(".") + member_object("rhs"))
    )
    + Suppress(ZeroOrMore(" "))
)
member_access_expression_loose.setParseAction(MemberAccessExpression)


# TODO: Figure out how to have unlimited member accesses.
member_object_limited = (
    Suppress(Optional("["))
    + unrestricted_name
    + Suppress(Optional("]"))
)
member_access_expression_limited = Group(
    Group((
        member_object("lhs")
        + NotAny(White())
        + Suppress(".")
        + NotAny(White())
        + member_object_limited("rhs")
        + Optional(
              NotAny(White())
              + Suppress(".")
              + NotAny(White())
              + member_object_limited("rhs1")
        )
    ).leaveWhitespace())
)
member_access_expression_limited.setParseAction(MemberAccessExpression)

# --- ARGUMENT LISTS ---------------------------------------------------------

# 5.6.16.8   AddressOf Expressions
#
# MS-GRAMMAR: addressof-expression = "addressof" procedure-pointer-expression
# MS-GRAMMAR: procedure-pointer-expression = simple-name-expression / member-access-expression

# Examples: addressof varname, addressof varname(2).attrname

# IMPORTANT: member_access_expression must come before simple_name_expression or parsing fails.
procedure_pointer_expression = member_access_expression | simple_name_expression
addressof_expression = CaselessKeyword("addressof").suppress() + procedure_pointer_expression

# 5.6.13.1   Argument Lists
#
# An argument list represents an ordered list of positional arguments and a set of named arguments
# that are used to parameterize an expression.
#
# MS-GRAMMAR: argument-list = [positional-or-named-argument-list]
# MS-GRAMMAR: positional-or-named-argument-list = *(positional-argument ",") required-positional-argument
# MS-GRAMMAR: positional-or-named-argument-list =/   *(positional-argument ",") named-argument-list
# MS-GRAMMAR: positional-argument = [argument-expression]
# MS-GRAMMAR: required-positional-argument = argument-expression
# MS-GRAMMAR: named-argument-list = named-argument *("," named-argument)
# MS-GRAMMAR: named-argument = unrestricted-name ":""=" argument-expression
# MS-GRAMMAR: argument-expression = ["byval"] expression
# MS-GRAMMAR: argument-expression =/  addressof-expression

argument_expression = (Optional(CaselessKeyword("byval")) + expression) | addressof_expression

named_argument = unrestricted_name + Suppress(":=") + argument_expression
named_argument_list = delimitedList(named_argument)
required_positional_argument = argument_expression
positional_argument = Optional(argument_expression)
# IMPORTANT: named_argument_list must come before required_positional_argument or parsing fails.
positional_or_named_argument_list = Optional(delimitedList(positional_argument) + ",") \
                                    + (named_argument_list | required_positional_argument)
argument_list = Optional(positional_or_named_argument_list)

# --- INDEX EXPRESSIONS ------------------------------------------------------

# 5.6.13   Index Expressions
#
# An index expression is used to parameterize an expression by adding an argument list to its
# argument list queue.
#
# MS-GRAMMAR: index-expression = l-expression "(" argument-list ")"

index_expression = simple_name_expression + Suppress("(") + simple_name_expression + Suppress(")")

# --- DICTIONARY ACCESS EXPRESSIONS ------------------------------------------------------

# 5.6.14   Dictionary Access Expressions
#
# A dictionary access expression is an alternate way to invoke an object's default member with a
# String parameter.
#
# MS-GRAMMAR: dictionary-access-expression = l-expression  NO-WS "!" NO-WS unrestricted-name
# MS-GRAMMAR: dictionary-access-expression =/  l-expression  LINE-CONTINUATION "!" NO-WS unrestricted-name
# MS-GRAMMAR: dictionary-access-expression =/  l-expression  LINE-CONTINUATION "!" LINE-CONTINUATION
# MS-GRAMMAR: unrestricted-name

# NOTE: Here we assume that all line-continuation characters have been removed,
#       so the 2nd and 3rd parts of dictionary-access-expression do not apply.
#       Moreover, there may be whitespaces before and after the "!", due to the removal.

dictionary_access_expression = l_expression + Suppress("!") + unrestricted_name

# --- WITH EXPRESSIONS ------------------------------------------------------

# 5.6.15   With Expressions
#
# A With expression is a member access or dictionary access expression with its <l-expression>
# implicitly supplied by the innermost enclosing With block.
#
# MS-GRAMAR: with-expression = with-member-access-expression / with-dictionary-access-expression
# MS-GRAMMAR: with-member-access-expression = "." unrestricted-name
# MS-GRAMMAR: with-dictionary-access-expression = "!" unrestricted-name

with_member_access_expression = OneOrMore( Suppress(".") + (unrestricted_name ^ function_call_limited) )
with_member_access_expression.setParseAction(lambda t: ''.join('.%s' % u for u in t)[1:])
with_dictionary_access_expression = Suppress("!") + unrestricted_name
with_expression = with_member_access_expression | with_dictionary_access_expression

# --- EXPRESSIONS ------------------------------------------------------------

# 5.6 Expressions
#
# An expression is a hierarchy of values, identifiers and subexpressions that evaluates to a value, or
# references an entity such as a variable, constant, procedure or type. Besides its tree of
# subexpressions, an expression also has a declared type which can be determined statically, and a
# value type which may vary depending on the runtime value of its values and subexpressions. This
# section defines the syntax of expressions, their static resolution rules and their runtime evaluation
# rules.
#
# MS-GRAMMAR: expression = value-expression / l-expression
# MS-GRAMMAR: value-expression = literal-expression / parenthesized-expression / typeof-is-expression /
# MS-GRAMMAR: new-expression / operator-expression
# MS-GRAMMAR: l-expression = simple-name-expression / instance-expression / member-access-expression /
# MS-GRAMMAR: index-expression / dictionary-access-expression / with-expression

new_expression = Forward()
l_expression << (with_expression ^ member_access_expression ^ new_expression ^ member_access_expression_loose) | instance_expression | \
    dictionary_access_expression | simple_name_expression 

# --- FUNCTION CALL ---------------------------------------------------------

class Function_Call(VBA_Object):
    """
    Function call within a VBA expression
    """

    # List of interesting functions to log calls to.
    log_funcs = ["CreateProcessA", "CreateProcessW", ".run", "CreateObject",
                 "Open", ".Open", "GetObject", "Create", ".Create", "Environ",
                 "CreateTextFile", ".CreateTextFile", ".Eval", "Run",
                 "SetExpandedStringValue", "WinExec", "FileExists", "SaveAs",
                 "FileCopy", "Load", "ShellExecute"]
    
    def __init__(self, original_str, location, tokens, old_call=None):
        super(Function_Call, self).__init__(original_str, location, tokens)

        # Copy constructor?
        if (old_call is not None):
            self.name = old_call.name
            self.params = old_call.params
            return

        # Making a new one.
        self.name = str(tokens.name)
        log.debug('Function_Call.name = %r' % self.name)
        assert isinstance(self.name, basestring)
        self.params = tokens.params
        log.debug('Function_Call.params = %r' % self.params)
        log.debug('parsed %r as Function_Call' % self)

    def __repr__(self):
        parms = ""
        first = True
        for parm in self.params:
            if (not first):
                parms += ", "
            first = False
            parms += str(parm)
        return '%s(%r)' % (self.name, parms)

    def eval(self, context, params=None):

        # Save the unresolved argument values.
        import vba_library
        vba_library.var_names = self.params
        
        log.debug("Function_Call: eval params: " + str(self.params))

        # Reset the called function name if this is an alias for an imported external
        # DLL function.
        dll_func_name = context.get_true_name(self.name)
        if (dll_func_name is not None):
            self.name = dll_func_name

        # Evaluate the function arguments.
        params = None
        if (self.name == "CallByName"):
            params = eval_args(self.params[1:], context=context)
            params = [self.params[0]] + params
        else:
            params = eval_args(self.params, context=context)
        str_params = repr(params)[1:-1]
        if (len(str_params) > 80):
            str_params = str_params[:80] + "..."
            
        # Would Visual Basic have thrown an error when evaluating the arguments?
        if (context.have_error()):
            log.warn('Short circuiting function call %s(%s) due to thrown VB error.' % (self.name, str_params))
            return None
        
        # Actually emulate the function call.
        log.info('calling Function: %s(%s)' % (self.name, str_params))
        if self.name.lower() in context._log_funcs \
                or any(self.name.lower().endswith(func.lower()) for func in Function_Call.log_funcs):
            context.report_action(self.name, params, 'Interesting Function Call', strip_null_bytes=True)
        try:

            # Get the (possible) function.
            f = context.get(self.name)

            # Is this actually a hash lookup?
            if (isinstance(f, dict)):

                # Are we accessing an element?
                if (len(params) > 0):
                    log.debug('Dict Access: %r[%r]' % (f, params[0]))
                    index = params[0]
                    if (index in f):
                        return f[index]
                    else:
                        return "NULL"
            
            # Is this actually an array access?
            if (isinstance(f, list)):

                # Are we accessing an element?
                if (len(params) > 0):
                    tmp = f
                    # Try to guess whether we are accessing a character in a string.
                    # TODO: Revisit this.
                    #if ((len(f) == 1) and (isinstance(f[0], str))):
                    #    tmp = f[0]
                    log.debug('Array Access: %r[%r]' % (tmp, params[0]))
                    index = int_convert(params[0])
                    try:

                        # Return function result.
                        r = tmp[index]
                        log.debug('Returning: %r' % r)
                        return r
                    except:

                        # Return function result.
                        log.error('Array Access Failed: %r[%r]' % (tmp, params[0]))
                        context.got_error = True
                        return 0

                # Looks like we want the whole array (ex. foo()).
                else:

                    # Return function result.
                    return f
                    
            log.debug('Calling: %r' % f)
            if (f is not None):
                if (not(isinstance(f, str)) and
                    not(isinstance(f, list)) and
                    not(isinstance(f, unicode))):
                    try:

                        # Call function.
                        r = f.eval(context=context, params=params)
                        
                        # Set the values of the arguments passed as ByRef parameters.
                        if (hasattr(f, "byref_params")):
                            for byref_param_info in f.byref_params.keys():
                                arg_var_name = str(self.params[byref_param_info[1]])
                                context.set(arg_var_name, f.byref_params[byref_param_info])

                        # Return result.
                        return r

                    except AttributeError as e:

                        # Return result.
                        log.error(str(f) + " has no eval() method. " + str(e))
                        return f

                elif (len(params) > 0):

                    # Looks like this is actually an array access.
                    log.debug("Looks like array access.")
                    try:

                        # Return result.
                        i = int_convert(params[0])
                        r = f[i]
                        if (isinstance(f, str)):
                            r = ord(r)
                        log.debug("Return " + str(r))
                        return r

                    except:

                        # Return result.
                        log.error("Array access %r[%r] failed." % (f, params[0]))
                        return 0
            else:

                # Return result.
                log.error('Function %r resolves to None' % self.name)
                return None

        except KeyError:

            # If something like Application.Run("foo", 12) is called, foo(12) will be run.
            # Try to handle that.
            func_name = str(self.name)
            if ((func_name == "Application.Run") or (func_name == "Run")):

                # Pull the name of what is being run from the 1st arg.
                new_func = params[0]

                # The remaining params are passed as arguments to the other function.
                new_params = params[1:]

                # See if we can run the other function.
                log.debug("Try indirect run of function '" + new_func + "'")
                try:

                    # Return result.
                    s = context.get(new_func)
                    return s.eval(context=context, params=new_params)
                except KeyError:
                    pass
                
            # Return result.                
            log.warning('Function %r not found' % self.name)
            return None

# comma-separated list of parameters, each of them can be an expression:
boolean_expression = Forward()
expr_item = Forward()
expr_list_item = expression ^ boolean_expression ^ member_access_expression_loose
# NOTE: This helps to speed up parsing and prevent recursion loops.
expr_list_item = (expr_item + FollowedBy(',')) | expr_list_item

# Parse large array expressions quickly with a regex.
# language=PythonRegExp
expr_list_fast = Regex("(?:\s*[0-9a-zA-Z_]+\s*,\s*){10,}\s*[0-9a-zA-Z_]+\s*")
expr_list_fast.setParseAction(lambda t: [expression.parseString(i, parseAll=True)[0] for i in t[0].split(",")])

# Parse general expression lists more completely but more slowly.
expr_list_slow = delimitedList(Optional(expr_list_item, default=""))

# WARNING: This may break parsing in function calls when the 1st argument is skipped.
#expr_list = Suppress(Optional(",")) + expr_list_item + NotAny(':=') + Optional(Suppress(",") + delimitedList(Optional(expr_list_item, default="")))
expr_list = (
    expr_list_item
    + NotAny(':=')
    + Optional(Suppress(",") + (expr_list_fast | expr_list_slow))
)

# TODO: check if parentheses are optional or not. If so, it can be either a variable or a function call without params
function_call <<= (
    CaselessKeyword("nothing")
    | (
        NotAny(reserved_keywords)
        + (member_access_expression('name') ^ lex_identifier('name'))
        + Suppress(
            Optional('$')
            + Optional('#')
            + Optional('!')
            + Optional('%')
            + Optional('@')
        )
        + Suppress('(') + Optional(expr_list('params')) + Suppress(')')
    )
    | (
        Suppress('[')
        + CaselessKeyword("Shell")('name')
        + Suppress(']')
        + expr_list('params')
    )
)
function_call.setParseAction(Function_Call)

function_call_limited <<= (
    CaselessKeyword("nothing")
    | (
        NotAny(reserved_keywords)
        + lex_identifier('name')
        + Suppress(Optional('$'))
        + Suppress(Optional('#'))
        + Suppress(Optional('!'))
        + Suppress(Optional('%'))
        + Suppress(Optional('@'))
        + (
            (Suppress('(') + Optional(expr_list('params')) + Suppress(')'))
            # TODO: The NotAny(".") is a temporary fix to get "foo.bar" to not be
            # parsed as function_call_limited "foo .bar". The real way this should be
            # parsed is to require at least 1 space between the function name and the
            # 1st argument, then "foo.bar" will not match.
            | (Suppress(Optional('$')) + NotAny(".") + expr_list('params')))
    )
)
function_call_limited.setParseAction(Function_Call)

# --- ARRAY ACCESS OF FUNCTION CALL --------------------------------------------------------

class Function_Call_Array_Access(VBA_Object):
    """
    Array access of the return value of a function call.
    """

    def __init__(self, original_str, location, tokens):
        super(Function_Call_Array_Access, self).__init__(original_str, location, tokens)
        self.array = tokens.array
        self.index = tokens.index
        log.debug('parsed %r as Function_Call_Array_Access' % self)

    def __repr__(self):
        r = str(self.array) + "(" + str(self.index) + ")"
        return r

    def eval(self, context, params=None):

        # Evaluate the value of the function returing the array.
        array_val = eval_arg(self.array, context=context)
        # Evaluate the index to read.
        array_index = coerce_to_int(eval_arg(self.index, context=context))

        # Do we have a list to read from?
        if (not isinstance(array_val, list)):
            log.error("%r is not a list. Cannot perform array access." % array_val)
            return ''

        # Do we have a valid index?
        if (not isinstance(array_index, int)):
            log.error("Index %r is not an integer. Cannot perform array access." % array_index)
            return ''
        if ((array_index >= len(array_val)) or (array_index < 0)):
            log.error("Index %r is outside array bounds. Cannot perform array access." % array_index)
            return ''

        # Everything is valid. Return the array element.
        return array_val[array_index]
            
func_call_array_access = function_call("array") + Suppress("(") + expression("index") + Suppress(")")
func_call_array_access.setParseAction(Function_Call_Array_Access)

func_call_array_access_limited <<= function_call_limited("array") + Suppress("(") + expression("index") + Suppress(")")
func_call_array_access_limited.setParseAction(Function_Call_Array_Access)

# --- EXPRESSION ITEM --------------------------------------------------------

# expression item:
# - known functions first
# - then generic function call
# - then identifiers
# - finally literals (strings, integers, etc)

expr_item <<= (
    Optional(CaselessKeyword("ByVal").suppress())
    + (
        float_literal
        | named_argument
        | l_expression
        | (chr_ ^ function_call ^ func_call_array_access)
        | simple_name_expression
        | asc
        | strReverse
        | literal
        | file_pointer
        | placeholder
    )
)

# --- OPERATOR EXPRESSION ----------------------------------------------------

# 5.6.9 Operator Expressions
# see MS-VBAL 5.6.9.1 Operator Precedence and Associativity

# About operators associativity:
# https://en.wikipedia.org/wiki/Operator_associativity
# "In order to reflect normal usage, addition, subtraction, multiplication,
# and division operators are usually left-associative while an exponentiation
# operator (if present) is right-associative. Any assignment operators are
# also typically right-associative."

expression <<= (infixNotation(expr_item,
                                  [
                                      (CaselessKeyword("not"), 1, opAssoc.RIGHT, Not),
                                      # FIXME: Disabling exponentiation because it's causing recursion errors.
                                      # ("^", 2, opAssoc.RIGHT, Power),
                                      (Regex(re.compile("[*/]")), 2, opAssoc.LEFT, MultiDiv),
                                      ("\\", 2, opAssoc.LEFT, FloorDivision),
                                      (Regex(re.compile("mod", re.IGNORECASE)), 2, opAssoc.LEFT, Mod),
                                      (Regex(re.compile('[-+]')), 2, opAssoc.LEFT, AddSub),
                                      ("&", 2, opAssoc.LEFT, Concatenation),
                                      (Regex(re.compile("and", re.IGNORECASE)), 2, opAssoc.LEFT, And),
                                      (Regex(re.compile("or", re.IGNORECASE)), 2, opAssoc.LEFT, Or),
                                      (Regex(re.compile("xor", re.IGNORECASE)), 2, opAssoc.LEFT, Xor),
                                      (Regex(re.compile("eqv", re.IGNORECASE)), 2, opAssoc.LEFT, Eqv),
                                  ]))
expression.setParseAction(lambda t: t[0])

# Used in boolean expressions to limit confusion with boolean and/or and bitwise and/or.
limited_expression = (infixNotation(expr_item,
                                    [
                                        # ("^", 2, opAssoc.RIGHT), # Exponentiation
                                        # ("-", 1, opAssoc.LEFT), # Unary negation
                                        (Regex(re.compile("[*/]")), 2, opAssoc.LEFT, MultiDiv),
                                        ("\\", 2, opAssoc.LEFT, FloorDivision),
                                        (CaselessKeyword("mod"), 2, opAssoc.RIGHT, Mod),
                                        (Regex(re.compile('[-+]')), 2, opAssoc.LEFT, AddSub),
                                        ("&", 2, opAssoc.LEFT, Concatenation),
                                        (CaselessKeyword("xor"), 2, opAssoc.LEFT, Xor),
                                    ]))
expression.setParseAction(lambda t: t[0])

# constant expression: expression without variables or function calls, that can be evaluated to a literal:
expr_const = Forward()
chr_const = Suppress(
    Combine(CaselessLiteral('Chr') + Optional(Word('BbWw', max=1)) + Optional('$')) + '(') + expr_const + Suppress(')')
chr_const.setParseAction(Chr)
asc_const = Suppress(CaselessKeyword('Asc') + '(') + expr_const + Suppress(')')
asc_const.setParseAction(Asc)
strReverse_const = Suppress(CaselessLiteral('StrReverse') + Literal('(')) + expr_const + Suppress(Literal(')'))
strReverse_const.setParseAction(StrReverse)
environ_const = Suppress(CaselessKeyword('Environ') + '(') + expr_const + Suppress(')')
environ_const.setParseAction(Environ)
expr_const_item = (chr_const | asc_const | strReverse_const | environ_const | literal)
expr_const <<= infixNotation(expr_const_item,
                             [
                                 ("+", 2, opAssoc.LEFT, Sum),
                                 ("&", 2, opAssoc.LEFT, Concatenation),
                             ])

# ----------------------------- BOOLEAN expressions --------------

class BoolExprItem(VBA_Object):
    """
    A comparison expression or other item appearing in a boolean expression.
    """

    def __init__(self, original_str, location, tokens):
        super(BoolExprItem, self).__init__(original_str, location, tokens)
        assert (len(tokens) > 0)
        self.lhs = tokens[0]
        self.op = None
        self.rhs = None
        if (len(tokens) == 3):
            self.op = tokens[1]
            self.rhs = tokens[2]        
        log.debug('parsed %r as BoolExprItem' % self)

    def __repr__(self):
        if (self.op is not None):
            return self.lhs.__repr__() + " " + self.op + " " + self.rhs.__repr__()
        elif (self.lhs is not None):
            return self.lhs.__repr__()
        else:
            log.error("BoolExprItem: Improperly parsed.")
            return ""

    def eval(self, context, params=None):

        # We always have a LHS. Evaluate that in the current context.
        lhs = self.lhs
        try:
            lhs = eval_arg(self.lhs, context)
        except AttributeError:
            pass

        # Do we have an operator or just a variable reference?
        if (self.op is None):

            # Variable reference. Return its value.
            return lhs

        # We have an operator. Get the value of the RHS.
        rhs = self.rhs
        try:
            rhs = eval_arg(self.rhs, context)
        except AttributeError:
            pass

        # Handle unitialized variables. Grrr. Base their conversion on
        # the type of the initialized expression.
        if ((rhs == "NULL") or (rhs is None)):
            if (isinstance(lhs, str)):
                rhs = ''
            else:
                rhs = 0
            context.set(self.rhs, rhs)
            log.debug("Set unitinitialized " + str(self.rhs) + " = " + str(rhs))
        if ((lhs == "NULL") or (lhs is None)):
            if (isinstance(rhs, str)):
                lhs = ''
            else:
                lhs = 0
            context.set(self.lhs, lhs)
            log.debug("Set unitialized " + str(self.lhs) + " = " + str(lhs))

        # Ugh. VBA autoconverts strings and ints.
        if (isinstance(lhs, str) and isinstance(rhs, int)):

            # Convert both to ints, if possible.
            try:
                lhs = int(lhs)
            except:
                pass

        if (isinstance(rhs, str) and isinstance(lhs, int)):

            # Convert both to ints, if possible.
            try:
                rhs = int(rhs)
            except:
                pass

        # Handle unexpected types.
        if (((not isinstance(rhs, int)) and (not isinstance(rhs, str))) or
            ((not isinstance(lhs, int)) and (not isinstance(lhs, str)))):

            # Punt and compare everything as strings.
            lhs = str(lhs)
            rhs = str(rhs)
            
        # Evaluate the expression.
        if ((self.op.lower() == "=") or
            (self.op.lower() == "like") or
            (self.op.lower() == "is")):
            rhs = strip_nonvb_chars(rhs)
            lhs = strip_nonvb_chars(lhs)
            rhs_str = str(rhs)
            lhs_str = str(lhs)
            if (("**MATCH ANY**" in lhs_str) or ("**MATCH ANY**" in rhs_str)):
                return True
            return lhs == rhs
        elif (self.op == ">"):
            return lhs > rhs
        elif (self.op == "<"):
            return lhs < rhs
        elif ((self.op == ">=") or (self.op == "=>")):
            return lhs >= rhs
        elif ((self.op == "<=") or (self.op == "=<")):
            return lhs <= rhs
        elif (self.op == "<>"):
            return lhs != rhs
        elif (self.op.lower() == "like"):

            # Try as a Python regex.
            rhs = str(rhs)
            lhs = str(lhs)
            try:
                r = (re.match(rhs, lhs) is not None)
                log.debug("'" + lhs + "' Like '" + rhs + "' == " + str(r))
                return r
            except Exception as e:

                # Not a valid Pyhton regex. Just check string equality.
                return (rhs == lhs)
        else:
            log.error("BoolExprItem: Unknown operator %r" % self.op)
            return False

bool_expr_item = (limited_expression + \
                  (oneOf(">= => <= =< <> = > < <>") | CaselessKeyword("Like") | CaselessKeyword("Is")) + \
                  limited_expression) | \
                  limited_expression
bool_expr_item.setParseAction(BoolExprItem)

class BoolExpr(VBA_Object):
    """
    A boolean expression.
    """

    def __init__(self, original_str, location, tokens):
        super(BoolExpr, self).__init__(original_str, location, tokens)
        tokens = tokens[0]
        # Binary boolean operator.
        if ((not hasattr(tokens, "length")) or (len(tokens) > 2)):
            self.lhs = tokens
            try:
                self.lhs = tokens[0]
            except:
                pass
            self.op = None
            self.rhs = None
            try:
                self.op = tokens[1]
                self.rhs = BoolExpr(original_str, location, [tokens[2:], None])
            except:
                pass

        # Unary boolean operator.
        else:
            self.op = tokens[0]
            self.rhs = tokens[1]
            self.lhs = None

        if (isinstance(self.lhs, pyparsing.ParseResults)):
            self.lhs = BoolExpr(None, None, [self.lhs])
        if (isinstance(self.rhs, pyparsing.ParseResults)):
            self.rhs = BoolExpr(None, None, [self.rhs])

        log.debug('parsed %r as BoolExpr' % self)

    def __repr__(self):
        if (self.op is not None):
            if (self.lhs is not None):
                return self.lhs.__repr__() + " " + self.op + " " + self.rhs.__repr__()
            else:
                return self.op + " " + self.rhs.__repr__()
        elif (self.lhs is not None):
            return self.lhs.__repr__()
        else:
            log.error("BoolExpr: Improperly parsed.")
            return ""

    def eval(self, context, params=None):

        # Unary operator?
        if (self.lhs is None):

            # We have only a RHS. Evaluate it.
            rhs = None
            try:
                rhs = eval_arg(self.rhs, context)
            except:
                log.error("Boolxpr: Cannot eval " + self.__repr__() + ".")
                return ''

            # Bitwise operation?
            if ((isinstance(rhs, int)) and (not isinstance(rhs, bool))):
                log.debug("Bitwise boolean operation: " + str(self))
                if (self.op.lower() == "not"):
                    return (~ rhs)
                else:
                    log.error("BoolExpr: Unknown bitwise unary op " + str(self.op))
                    return 0
                
            # Evalue the unary expression.
            if (self.op.lower() == "not"):
                return (not rhs)
            else:
                log.error("BoolExpr: Unknown boolean unary op " + str(self.op))
                return ''
                
        # If we get here we always have a LHS. Evaluate that in the current context.
        lhs = self.lhs
        try:
            lhs = eval_arg(self.lhs, context)
        except AttributeError:
            pass

        # Do we have an operator or just a variable reference?
        if (self.op is None):

            # Variable reference. Return its value.
            return lhs

        # We have an operator. Get the value of the RHS.
        rhs = self.rhs
        try:
            rhs = eval_arg(self.rhs, context)
        except AttributeError as e:
            pass

        # Bitwise operation?
        if ((isinstance(lhs, int) and isinstance(rhs, int)) and
            (not isinstance(lhs, bool) and not isinstance(rhs, bool))):

            log.debug("Bitwise boolean operation: " + str(self))
            if ((self.op.lower() == "and") or (self.op.lower() == "andalso")):
                return lhs & rhs
            elif ((self.op.lower() == "or") or (self.op.lower() == "orelse")):
                return lhs | rhs
            elif (self.op.lower() == "xor"):
                return lhs ^ rhs
            else:
                log.error("BoolExpr: Unknown bitwise operator %r" % self.op)
                return 0
            
        # Evaluate the expression.
        if ((self.op.lower() == "and") or (self.op.lower() == "andalso")):
            return lhs and rhs
        elif ((self.op.lower() == "or") or (self.op.lower() == "orelse")):
            return lhs or rhs
        elif (self.op.lower() == "eqv"):
            return (lhs == rhs)
        else:
            log.error("BoolExpr: Unknown operator boolean %r" % self.op)
            return False
    
boolean_expression <<= infixNotation(bool_expr_item,
                                     [
                                         (CaselessKeyword("Not"), 1, opAssoc.RIGHT),
                                         (CaselessKeyword("And"), 2, opAssoc.LEFT),
                                         (CaselessKeyword("AndAlso"), 2, opAssoc.LEFT),
                                         (CaselessKeyword("Or"), 2, opAssoc.LEFT),
                                         (CaselessKeyword("OrElse"), 2, opAssoc.LEFT),
                                         (CaselessKeyword("Eqv"), 2, opAssoc.LEFT),
                                     ])
boolean_expression.setParseAction(BoolExpr)

# --- NEW EXPRESSION --------------------------------------------------------------

class New_Expression(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(New_Expression, self).__init__(original_str, location, tokens)
        self.obj = tokens.expression
        log.debug('parsed %r' % self)

    def __repr__(self):
        return ('New %r' % self.obj)

    def eval(self, context, params=None):
        # TODO: Not sure how to handle this. For now just return what is being created.
        return self.obj

new_expression << CaselessKeyword('New').suppress() + expression('expression')
new_expression.setParseAction(New_Expression)

any_expression = expression ^ boolean_expression

