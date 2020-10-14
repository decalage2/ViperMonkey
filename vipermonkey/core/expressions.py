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

import logging
import re
import sys
import os
import array
from hashlib import sha256
import string

import unidecode

from identifiers import *
from reserved import *
from lib_functions import *
from literals import *
from operators import *
import procedures
from vba_object import eval_arg
from vba_object import to_python
from vba_object import coerce_to_int
from vba_object import coerce_to_str
from vba_object import strip_nonvb_chars
from vba_object import int_convert
from vba_object import VbaLibraryFunc
import vba_context
import utils

from logger import log

def _vba_to_python_op(op, is_boolean):
    """
    Convert a VBA boolean operator to a Python boolean operator.
    """
    op_map = {
        "Not" : "not",
        "And" : "and",
        "AndAlso" : "and",
        "Or" : "or",
        "OrElse" : "or",
        "Eqv" : "==",
        "=" : "==",
        ">" : ">",
        "<" : "<",
        ">=" : ">=",
        "=>" : ">=",
        "<=" : "<=",
        "=<" : "<=",
        "<>" : "!=",
        "is" : "=="
    }
    if (not is_boolean):
        op_map["Not"] = "~"
        op_map["And"] = "&"
        op_map["AndAlso"] = "&"
        op_map["Or"] = "|"
        op_map["OrElse"] = "|"
    return op_map[op]

# --- FILE POINTER -------------------------------------------------

file_pointer = Suppress('#') + (decimal_literal ^ lex_identifier) + NotAny("#")
file_pointer.setParseAction(lambda t: "#" + str(t[0]))
file_pointer_loose = (decimal_literal ^ lex_identifier)
file_pointer_loose.setParseAction(lambda t: "#" + str(t[0]))

# --- SIMPLE NAME EXPRESSION -------------------------------------------------

missed_var_count = {}
class SimpleNameExpression(VBA_Object):
    """
    Identifier referring to a variable within a VBA expression:
    single identifier with no qualification or argument list
    """

    def __init__(self, original_str, location, tokens, name=None):
        super(SimpleNameExpression, self).__init__(original_str, location, tokens)
        if (name is not None):
            self.name = name
        else:
            self.name = tokens.name
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed "%r" as SimpleNameExpression' % self)

    def __repr__(self):
        return '%s' % self.name

    def to_python(self, context, params=None, indent=0):

        # VB regex object?
        if (self.name == "RegExp"):
            return "core.utils.vb_RegExp()"

        # Get the value of the variable/function.
        value = None
        try:
            value = context.get(self.name)
        except KeyError:
            pass
        # Use original value if possible.
        if (value == "__ALREADY_SET__"):
            try:
                value = context.get("__ORIG__" + str(self.name))
            except KeyError:
                pass
        
        # Is this a 0 argument builtin function call? Make sure this is not a
        # local variable shadowing the name of a VBA builtin.
        import vba_library
        if ((self.name.lower() in vba_library.VBA_LIBRARY) and
            (isinstance(value, VbaLibraryFunc)) and
            (value.num_args() == 0)):

            # Call the function in python.
            args = "[]"
            r = "core.vba_library.run_function(\"" + str(self.name) + "\", vm_context, " + args + ")"
            return r

        # Rename some vars that overlap with python builtins.
        var_name = str(self)
        var_name = utils.fix_python_overlap(var_name)
        
        # This could be a call to a 0 argument local function (thanks VB syntax :( ).
        if (isinstance(value, procedures.Function) and
            (value.min_param_length == 0)):
            return var_name + "()"
        
        # Just treat as a variable reference.
        return var_name
    
    def eval(self, context, params=None):

        import statements
        
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('try eval variable/function %r' % self.name)
        try:
            value = context.get(self.name)
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('get variable %r = %r' % (self.name, value))
            if (isinstance(value, procedures.Function) or
                isinstance(value, procedures.Sub) or
                isinstance(value, statements.External_Function) or
                isinstance(value, VbaLibraryFunc)):

                # Only evaluate functions with 0 args since we have no
                # arguments at this point.
                # TODO: Need to also handle VbaLibraryFunc.
                if ((isinstance(value, procedures.Function) or
                     isinstance(value, procedures.Sub)) and
                    (value.min_param_length > 0)):
                    return "NULL"

                # 0 parameter function. Evaluate it.
                if (not context.throttle_logging):
                    log.info("calling Function: " + str(value) + "()")
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug('evaluating function %r' % value)
                value = value.eval(context)
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug('evaluated function %r = %r' % (self.name, value))
            return value
        except KeyError:

            # Track the # of times we have failed to look up this variable. Stop reporting
            # if there are many failed lookups.
            var_name = str(self.name)
            global missed_var_count
            if (var_name not in missed_var_count.keys()):
                missed_var_count[var_name] = 0
            missed_var_count[var_name] += 1
            if (missed_var_count[var_name] < 20):
                log.warning('Variable %r not found' % self.name)
            if (self.name.startswith("%") and self.name.endswith("%")):
                return self.name.upper()
            return "NULL"

# 5.6.10 Simple Name Expressions
# A simple name expression consists of a single identifier with no qualification or argument list.
#
# MS-GRAMMAR: simple-name-expression = name

simple_name_expression = Optional(CaselessKeyword("ByVal").suppress()) + \
                         (TODO_identifier_or_object_attrib('name') | enum_val_id('name'))
simple_name_expression.setParseAction(SimpleNameExpression)

unrestricted_name_expression = unrestricted_name('name')
unrestricted_name_expression.setParseAction(SimpleNameExpression)

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
        if (log.getEffectiveLevel() == logging.DEBUG):
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
        self.is_loop = False
        if (raw_fields is not None):
            self.lhs = raw_fields[0]
            self.rhs = raw_fields[1]
            self.rhs1 = raw_fields[2]
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Manually created MemberAccessExpression %r' % self)

        # Make a member access object from parse results.
        else:
            super(MemberAccessExpression, self).__init__(original_str, location, tokens)
            tokens = tokens[0][0]
            self.rhs = tokens[1:]
            self.lhs = tokens.lhs
            if ((isinstance(self.lhs, list) or isinstance(self.lhs, pyparsing.ParseResults)) and (len(self.lhs) > 0)):
                self.lhs = self.lhs[0]
            self.rhs1 = ""
            if (hasattr(tokens, "rhs1")):
                self.rhs1 = tokens.rhs1
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('parsed %r as MemberAccessExpression' % self)

    def __repr__(self):
        r = str(self.lhs)
        for t in self.rhs:
            r += "." + str(t)
        if (len(self.rhs1) > 0):
            r += "." + str(self.rhs1)
        return r

    def _to_python_handle_add(self, context, indent):
        """
        Handle Add() object method calls like foo.Add(bar, baz). 
        foo is (currently) a Scripting.Dictionary object.
        """

        # Currently we are only supporting JIT emulation of With blocks
        # based on Scripting.Dictionary. Is that what we have?
        with_dict = None
        if ((context.with_prefix_raw is not None) and
            (context.contains(str(context.with_prefix_raw)))):
            with_dict = context.get(str(context.with_prefix_raw))
            if (with_dict == "__ALREADY_SET__"):

                # Try getting the original value.
                with_dict = context.get("__ORIG__" + str(context.with_prefix_raw))

            # Got Scripting.Dictionary?
            if (not isinstance(with_dict, dict)):                
                with_dict = None

        # Can we do JIT code for this?
        if (with_dict is None):
            return None

        # Is this a Scripting.Dictionary method call?
        expr_str = str(self)
        if (".Add(" not in expr_str):
            return None
            
        # Generate python for the dictionary method call.
        tmp_var = SimpleNameExpression(None, None, None, name=str(context.with_prefix_raw))
        new_add = Function_Call(None, None, None, old_call=self.rhs[0])
        tmp = [tmp_var]
        for p in new_add.params:
            tmp.append(p)
        new_add.params = tmp
        indent_str = " " * indent
        r = indent_str + to_python(new_add, context)        
        return r
    
    def to_python(self, context, params=None, indent=0):

        # Handle Scripting.Dictionary.Add() calls.
        add_code = self._to_python_handle_add(context, indent)
        if (add_code is not None):
            return add_code
        
        # For now just pick off the last item in the expression.
        if (len(self.rhs) > 0):

            # RegExp operations?
            raw_last_func = str(self.rhs[-1]).replace("('", "(").replace("')", ")")
            if ((raw_last_func.startswith("Test(")) or
                (raw_last_func.startswith("Replace(")) or
                (raw_last_func.startswith("Global")) or
                (raw_last_func.startswith("Pattern"))):
            
                # Use the simulated RegExp object for this.
                exp_str = str(self)
                call_str = raw_last_func
                if (isinstance(self.rhs[-1], Function_Call)):
                    the_call = self.rhs[-1]
                    call_str = str(the_call.name) + "("
                    first = True
                    for p in the_call.params:
                        if (not first):
                            call_str += ", "
                        first = False
                        call_str += to_python(p, context)
                    call_str += ")"
                r = exp_str[:exp_str.rindex(".")] + "." + call_str
                return r

            # Excel SpecialCells() method call?
            if (raw_last_func.startswith("SpecialCells(")):

                # Make the call with the cell range as the new 1st argument.
                new_special_cells = Function_Call(None, None, None, old_call=self.rhs[-1])
                cells = self._eval_cell_range(context, just_expr=True)
                tmp = [cells, new_special_cells.params[0]]
                new_special_cells.params = tmp
                
                # Convert the call with the cells as explicit parameters to python.
                r = to_python(new_special_cells, context, params)
                return r

            # Getting the Text of an object?
            if (str(self.rhs[-1]) == "Text"):

                # Just use the value of the object variable itself in python.
                r = to_python(self.lhs, context, params)
                return r
            
            # No special operations.
            last_func = to_python(self.rhs[-1], context, params)
            
            # Handle accessing name of a process from a process list.
            if (last_func.lower() == '"name"'):
                lhs_str = to_python(self.lhs, context, params)
                if (lhs_str.startswith('"')):
                    lhs_str = lhs_str[1:]
                if (lhs_str.endswith('"')):
                    lhs_str = lhs_str[:-1]
                last_func = lhs_str + "['name']"
            return last_func
        
        return ""
    
    def _handle_indexed_pages_access(self, context):
        """
        Handle getting the caption of a Page object referenced via index.
        """

        # Do we have an indexed page caption reference?
        # Bnrdytkzyupr.Feoubcbnti.Pages('0').Caption
        page_pat = r".+\.Pages\('(\d+)'\)\.Caption"
        index = re.findall(page_pat, str(self))
        if (len(index) == 0):
            return None
        index = int(index[0]) + 1

        # Try to look up a Page object variable with the desired index.
        var_name = "Page" + str(index) + ".Caption"
        if (context.contains(var_name)):
            return context.get(var_name)
        return None
    
    def _handle_table_cell(self, context):
        """
        Handle reading a value from a table cell.
        """

        # Pull out the table index and cell indices.
        # ActiveDocument.Tables(1).Cell(1, 1).Range
        pat = r"\w+\.Tables\(\s*'(\w+)'\s*\)\.Cell\(\s*'(\w+)\s*,\s*(\w+)'\s*\).*"
        indices = re.findall(pat, str(self))
        if (len(indices) == 0):
            return None
        indices = indices[0]

        # Evaluate the table and cell indices.
        table_index = None
        try:

            # Parse it. Assume this is an expression.
            obj = expressions.expression.parseString(indices[0], parseAll=True)[0]
            
            # Evaluate the expression in the current context.
            table_index = obj
            if (isinstance(table_index, VBA_Object)):
                table_index = table_index.eval(context)
            if (isinstance(table_index, str)):
                table_index = int(table_index.replace("'", ""))
            table_index -= 1

        except ParseException:
            log.error("Parse error. Cannot evaluate '" + indices[0] + "'")
            return None
        except Exception as e:
            log.error("Comment index '" + str(indices[0]) + "' not int. " + str(e))
            return None
        cell_index_row = None
        try:

            # Parse it. Assume this is an expression.
            obj = expressions.expression.parseString(indices[1], parseAll=True)[0]
            
            # Evaluate the expression in the current context.
            cell_index_row = obj
            if (isinstance(cell_index_row, VBA_Object)):
                cell_index_row = cell_index_row.eval(context)
            if (isinstance(cell_index_row, str)):
                cell_index_row = int(cell_index_row.replace("'", ""))
            cell_index_row -= 1

        except ParseException:
            log.error("Parse error. Cannot evaluate '" + indices[1] + "'")
            return None
        except Exception as e:
            log.error("Comment index '" + str(indices[1]) + "' not int. " + str(e))
            return None
        cell_index_col = None
        try:

            # Parse it. Assume this is an expression.
            obj = expressions.expression.parseString(indices[2], parseAll=True)[0]
            
            # Evaluate the expression in the current context.
            cell_index_col = obj
            if (isinstance(cell_index_col, VBA_Object)):
                cell_index_col = cell_index_col.eval(context)
            if (isinstance(cell_index_row, str)):
                cell_index_col = int(cell_index_row.replace("'", ""))
            cell_index_col -= 1

        except ParseException:
            log.error("Parse error. Cannot evaluate '" + indices[2] + "'")
            return None
        except Exception as e:
            log.error("Comment index '" + str(indices[2]) + "' not int. " + str(e))
            return None

        # Do we have that cell in a table?
        tables = context.get("__DOC_TABLE_CONTENTS__")
        if (table_index >= len(tables)):
            return None
        table = tables[table_index]
        if (cell_index_row >= len(table)):
            return None
        row = table[cell_index_row]
        if (cell_index_col >= len(row)):
            return None
        cell = str(row[cell_index_col]) + "  "
        return cell
    
    def _handle_paragraphs(self, context):
        """
        Handle references to the .Paragraphs field of the current doc.
        """

        # Get all paragraphs?
        if (str(self).lower().endswith(".paragraphs")):
            return context.get("ActiveDocument.Paragraphs".lower())

        # Get a single paragraph?
        if (len(self.rhs) == 0):
            return None
        first_rhs = self.rhs[0]
        if (not str(first_rhs).startswith("Paragraphs('")):
            return None

        # Return the single paragraph.
        r = eval_arg(first_rhs, context)
        return r

    def _handle_comments(self, context):
        """
        Handle references to the .Comments field of the current doc.
        """

        # Comments reference?
        me_str = str(self)
        if (".comments" not in me_str.lower()):
            return None

        # Simple case, get all the comments.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Try _handle_comments() eval of " + me_str)
        if (me_str.lower().endswith(".comments")):
            return context.get("ActiveDocument.Comments".lower())

        # Less simple case. Are we reading a specific comment?
        ref_pat = r".Comments\(\s*(.+)\s*\)"
        ids = re.findall(ref_pat, me_str)
        if (len(ids) == 0):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("No comment index found.")
            return None

        # We are reading a specific comment.

        # Get the comment index.
        index = None
        try:

            # Parse it. Assume this is an expression.
            obj = expressions.expression.parseString(ids[0], parseAll=True)[0]
            
            # Evaluate the expression in the current context.
            index = obj
            if (isinstance(index, VBA_Object)):
                index = index.eval(context)
            index = int(index.replace("'", "")) - 1

        except ParseException:
            log.error("Parse error. Cannot evaluate '" + str(ids[0]) + "'")
            return None
        except Exception as e:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Comment index '" + str(ids[0]) + "' not int. " + str(e))
            return None

        # We have an index. Return the comment.
        comments = context.get("ActiveDocument.Comments".lower())
        if (index >= len(comments)):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Comment index " + str(ids[0]) + " out of range")
            return None
        return comments[index]
            
    def _handle_count(self, context, curr_item):
        """
        Handle references to the .Count field of the current item.
        """
        if ((".count" in str(self).lower()) and (isinstance(curr_item, list))):
            return len(curr_item)

    def _handle_item(self, context, curr_item):
        """
        Handle accessing a list item.
        """

        # Only works for lists.
        if (not isinstance(curr_item, list)):
            return None

        # Do we have an Item() call?
        if (".item(" not in str(self).lower()):
            return None

        # Get the index.
        tmp_rhs = self.rhs
        if (isinstance(tmp_rhs, list) and (len(tmp_rhs) > 0)):
            tmp_rhs = tmp_rhs[0]
        if ((not isinstance(tmp_rhs, Function_Call)) or
            (tmp_rhs.name != "Item")):
            return None
        index = eval_arg(tmp_rhs.params[0], context)
        if (not isinstance(index, int)):
            return None
        if (index >= len(curr_item)):
            return "NULL"

        # Return the list item.
        return curr_item[index]
        
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
        func_args = None
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
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Try indirect run of function '" + func_name + "'")
        r = "NULL"
        try:

            # Drill down through layers of indirection to get the name of the function to run.
            s = func_name
            while ((isinstance(s, str)) or (isinstance(s, SimpleNameExpression))):
                s = context.get(str(s))
                if (isinstance(s, procedures.Function) or
                    isinstance(s, procedures.Sub) or
                    isinstance(s, VbaLibraryFunc)):
                    s = s.eval(context=context, params=func_args)
                    r = s

            # Report actions if interesting.
            if ((str(self).lower().startswith("thisdocument.run(")) and (r != "NULL")):
                context.report_action('Execute Command', r, 'ThisDocument.Run', strip_null_bytes=True)
            return r
        
        except KeyError:
            if (r != "NULL"):
                return r
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
        if (log.getEffectiveLevel() == logging.DEBUG):
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
        # ThisDocument.BuiltInDocumentProperties('Manager').Value
        # Is this an ActiveDocument.BuiltInDocumentProperties() instance?
        if ((not str(self).startswith("ActiveDocument.BuiltInDocumentProperties(")) and
            (not str(self).startswith("ThisDocument.BuiltInDocumentProperties("))):
            return None

        # Pull out the name of the property to read.
        if (len(self.rhs[0].params) == 0):
            return None
        field_name = eval_arg(self.rhs[0].params[0], context)

        # Try to pull the result from the document data.
        r = context.get_doc_var(field_name)
        if (r is not None):
            return r

        # Maybe this is metadata?
        return context.read_metadata_item(field_name)

    def _handle_control_read(self, context):
        """
        Handle data reads with StreamName.Controls(...).Value.
        """

        # Something like banrcboyjdipc.Controls(1).Value ?
        pat = r".+\.Controls\(\s*'([^']+)'\s*\)(?:\.Value)?"
        my_text = str(self)
        if (re.match(pat, str(self)) is None):
            return None

        # Pull out the Controls text value list.
        list_name = my_text.replace(".Value", "")
        list_name = list_name[:list_name.rindex("(")]
        list_vals = None
        if (list_name.endswith("('")):
            list_name = list_name[:-2]
        try:
            list_vals = context.get(list_name)
        except KeyError:
            return None

        # Pull out the field value.
        index = re.findall(pat, my_text)[0]

        # Evaluate the field value.
        try:

            # Parse it. Assume this is an expression.
            obj = expressions.expression.parseString(index, parseAll=True)[0]
            
            # Evaluate the expression in the current context.
            index = obj
            if (isinstance(index, VBA_Object)):
                index = index.eval(context)
            index = int(index)

        except ParseException:
            log.error("Parse error. Cannot evaluate '" + index + "'")
            return None
        except:
            return None

        # Return the control text value.
        if (index < len(list_vals)):
            return list_vals[index]
        return None

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
        if ("(" in tmp):
            tmp = tmp[:tmp.rindex("(")]
        val = context.get_doc_var(tmp, search_wildcard=False)
        
        # Are we referencing an item by index?
        # zQGGrrccT('0').Caption
        if (("(" in str(self.lhs)) and
            (isinstance(self.lhs, Function_Call)) and
            (val is not None) and
            (isinstance(val, list))):

            # Get the index.
            if (len(self.lhs.params) > 0):
                index = eval_arg(self.lhs.params[0], context)
                if ((isinstance(index, int)) and (index < len(val))):
                    if ((index >= len(val)) or (index < 0)):
                        return None
                    val = val[index]

        # Are we referencing a field?
        rhs = str(self.rhs).lower().replace("'", "").replace("[", "").replace("]", "")
        if ((isinstance(val, dict)) and (rhs in val)):
            val = val[rhs]

        # Filter out function calls, these are not document variable reads.
        if (isinstance(val, procedures.Function) or
            isinstance(val, procedures.Sub) or
            isinstance(val, VbaLibraryFunc)):
            return None
            
        # Return the value.
        return val

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

        # TODO: Should we be actually reading files from the system?
        # Read the file contents.
        try:
            f = open(read_file, 'rb')
            r = f.read()
            f.close()
            return r
        except Exception as e:

            # Fix the file name for emulation if needed.
            if (read_file.startswith("C:\\")):
                #read_file = read_file.replace("C:\\", "./")
                read_file = read_file.replace("C:\\", "")

            try:
                f = open(read_file, 'rb')
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
        if (not str(lhs).lower().endswith("regexp")):
            return None

        # Do we have a pattern for the RegExp?
        pat_name = str(self.lhs) + ".pattern"
        if (not context.contains(pat_name)):
            pat_name = ".pattern"
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
        Handle Add() object method calls like foo.Add(bar, baz). 
        foo is (currently) a Scripting.Dictionary object.
        """

        # Get the LHS as a dict if possible.
        if (isinstance(lhs, str) and
            lhs.startswith("{") and
            lhs.endswith("}")):
            try:
                lhs = eval(lhs)
            except SyntaxError:
                pass

        # Get the Dictionary if it is a With variable.
        if ((context.with_prefix_raw is not None) and
            (context.contains(str(context.with_prefix_raw)))):
            lhs = context.get(str(context.with_prefix_raw))
            
        # Sanity check.
        if (log.getEffectiveLevel() == logging.DEBUG):
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
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Add() func = " + str(new_add))
        
        # Evaluate the dictionary add.
        new_dict = new_add.eval(context)

        # Update the dict variable.
        if (context.with_prefix_raw is not None):
            context.set(str(context.with_prefix_raw), new_dict, do_with_prefix=False)
        if (context.contains(str(self.lhs))):
            context.set(str(self.lhs), new_dict, do_with_prefix=False)

        # Done with the Add().
        return new_dict

    def _handle_exists(self, context, lhs, rhs):
        """
        Handle Exists() object method calls like foo.Exists(bar). 
        foo is (currently) a Scripting.Dictionary object.
        """

        # Get the LHS as a dict if possible.
        if (isinstance(lhs, str) and
            lhs.startswith("{") and
            lhs.endswith("}")):
            try:
                lhs = eval(lhs)
            except SyntaxError:
                pass

        # Get the Dictionary if it is a With variable.
        if ((context.with_prefix_raw is not None) and
            (context.contains(str(context.with_prefix_raw)))):
            lhs = context.get(str(context.with_prefix_raw))
            
        # Sanity check.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("_handle_exists(): lhs = " + str(lhs) + ", rhs = " + str(rhs))
        if ((isinstance(rhs, list)) and (len(rhs) > 0)):
            rhs = rhs[0]
        if (not isinstance(rhs, Function_Call)):
            return None
        if (rhs.name != "Exists"):
            return None
        if (not isinstance(lhs, dict)):
            return None

        # Run the dictionary exists.
        new_exists = Function_Call(None, None, None, old_call=rhs)
        tmp = [lhs]
        for p in new_exists.params:
            tmp.append(p)
        new_exists.params = tmp
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Exists() func = " + str(new_exists))
        
        # Evaluate the dictionary exists.
        r = new_exists.eval(context)
        return r

    def _handle_adodb_writes(self, lhs_orig, lhs, rhs, context):
        """
        Handle expressions like "foo.Write(...)" where foo = "ADODB.Stream".
        """

        # Is this a .Write() call?
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("_handle_adodb_writes(): lhs_orig = " + str(lhs_orig) + ", lhs = " + str(lhs) + ", rhs = " + str(rhs))
        rhs_str = str(rhs).strip()
        if (("write(" not in rhs_str.lower()) and ("writetext(" not in rhs_str.lower())):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Not a Write() call.")
            return False
        
        # Is this a Write() being called on an ADODB.Stream object?
        if (str(lhs).lower() != "ADODB.Stream".lower()):

            # Maybe we need a sub field? Do we have a subfield?
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug(str(lhs) + " is not an ADODB.Stream")
            if ((not isinstance(self.rhs, list)) or (len(self.rhs) < 2)):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Done (1).")
                return False

            # Look for ADODB.Stream in a variable from a subfield.
            for field in self.rhs[:-1]:
                lhs_orig += "." + str(field)

            # Are we referencing a stream contained in a variable?        
            if (str(eval_arg(lhs_orig, context)) == str(lhs_orig)):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Done (2).")
                return False
        
        # Pull out the text to write to the text stream.
        txt = None
        rhs_val = eval_arg(rhs.params[0], context)
        try:
            txt = str(rhs_val)
        except UnicodeEncodeError:
            txt = ''.join(filter(lambda x:x in string.printable, rhs_val))
            
        # Set the text value of the string as a faux variable. Make this
        # global as a hacky solution to handle fields in user defined objects.
        #
        # We are appending the written data to whatever is already there.
        var_name = str(lhs_orig) + ".ReadText"
        if (not context.contains(var_name)):
            context.set(var_name, "", force_global=True)
        final_txt = context.get(var_name) + txt
        context.set(var_name, final_txt, force_global=True)
        
        # We handled the write.
        return True

    def _handle_excel_read(self, context, rhs):
        """
        Handle Excel reads like worksheets.cells(1,2).
        """

        # Evaluate the Cells() call.
        #r = eval_arg(rhs, context)
        return None

    def _handle_0_arg_call(self, context, rhs=None):
        """
        Handle calls to 0 argument functions.
        """

        # Get the last item in the member access, if needed.
        if (rhs is None):
            if (len(self.rhs1) > 0):
                rhs = self.rhs1
            else:
                rhs = self.rhs[len(self.rhs) - 1]
        
        # Got possible function name?
        if (((not isinstance(rhs, str)) and (not isinstance(rhs, SimpleNameExpression))) or
            (not context.contains(str(rhs)))):
            return None
        func = context.get(str(rhs))
        if ((not isinstance(func, procedures.Sub)) and
            (not isinstance(func, procedures.Function)) and
            (not isinstance(func, VbaLibraryFunc))):
            return None

        # Is this a 0 argument function?
        num_params = 100
        if (hasattr(func, "params")):
            num_params = len(func.params)
        if (hasattr(func, "num_args")):
            num_params = func.num_args()
        if (num_params > 0):
            return None

        # 0 parameter function. Evaluate it.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('evaluating function %r' % func)
        r = func.eval(context)
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('evaluated function %r = %r' % (str(func), r))
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
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("_handle_savetofile(): filename = " + str(filename) + ", self = " + str(self))
        memb_str = str(self)
        if (".savetofile(" not in memb_str.lower()):
            return False

        # We have a call to SaveToFile(). Get the value to save from .ReadText
        var_name = memb_str[:memb_str.lower().index(".savetofile")] + ".ReadText"
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("var_name = " + var_name)
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
        fname = fname.replace("\x00", "").replace("..", "")
        fname = ''.join(filter(lambda x:x in string.printable, fname))
        fname = re.sub(r"[^ -~]", "__", fname)
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

            # Consider this ADODB stream to be finished, so clear the ReadText variable.
            context.set(var_name, "")
            
        except Exception as e:
            log.error("Writing " + fname + " failed. " + str(e))
            return False
        
        # Done.
        return True

    def _handle_path_access(self):
        """
        See if this is accessing the Path field of a file/folder object.
        """
        tmp = str(self.rhs).lower().replace("'", "").replace("[", "").replace("]", "")
        if (tmp == "path"):

            # Fake a path.
            return "C:\\Users\\admin\\"

    def _handle_indexed_form_access(self, context):
        """
        See if this is accessing a control in a form by index.
        """

        # ex. form1.Controls('0').ControlTipText
        self_str = str(self)
        if (".Controls(" not in self_str):
            return None

        # Do we have a list of information about the controls in this form?
        controls_str = (self_str[:self_str.index(".Controls(")] + ".Controls").lower()
        control_vals = None
        try:
            control_vals = context.get(controls_str)
        except KeyError:

            # Don't have any control values for the form.
            return None

        # We have control values for the form. Get the index being accessed.
        pat = r".+\.Controls\(\s*'([^']+)'\s*\)"
        vals = re.findall(pat, self_str)
        if (len(vals) == 0):
            return None
        index = vals[0]

        # Evaluate the index.
        try:

            # Parse it. Assume this is an expression.
            obj = expressions.expression.parseString(index, parseAll=True)[0]
            
            # Evaluate the expression in the current context.
            index = obj
            if (isinstance(index, VBA_Object)):
                index = index.eval(context)
            index = int(index)

        except ParseException:
            log.error("Parse error. Cannot evaluate '" + index + "'")
            return None
        except:
            return None

        # Is the control index in bounds?
        if (index >= len(control_vals)):
            return None

        # In bounds. Get the control field value of interest.
        control_val = control_vals[index]
        if ((not isinstance(self.rhs, list)) or (len(self.rhs) < 2)):
            return None
        field = str(self.rhs[1]).lower()
        if (field not in control_val):
            return None
        r = control_val[field]
        return r

    def _handle_regex_execute(self, context, tmp_lhs):
        """
        Handle application of a RegEx object to a string via the RegEx object's Execute() method.
        """

        # Is this dealing with a RegEx object?
        if (str(tmp_lhs).lower() != "vbscript.regexp"):
            return None

        # Are we calling the Execute() method?
        if (".Execute(" not in str(self)):
            return None

        # We are doing a regex execute. Pull out the regex pattern and string
        # to which to apply the regex.

        # Get pattern.
        pat_var = str(self.lhs).lower() + ".pattern"
        pat = None
        try:
            pat = context.get(pat_var)
        except KeyError:

            # Don't have a pattern.
            return None

        # Get string.
        tmp_rhs = self.rhs
        if (isinstance(tmp_rhs, list) and (len(tmp_rhs) > 0)):
            tmp_rhs = tmp_rhs[0]
        if ((not isinstance(tmp_rhs, Function_Call)) or
            (tmp_rhs.name != "Execute")):
            return None
        mod_str = tmp_rhs.params[0]
        try:
            str_val = context.get(mod_str)
            mod_str = str_val
        except KeyError:

            # Don't have a pattern.
            return None

        # Find all the regex matches in the string.
        r = re.findall(pat, mod_str)
        return r
        
    def _read_member_expression_as_var(self, context):

        # Easiest case. Do we have this saved as a variable?
        try:
            r = context.get(str(self), search_wildcard=False)
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Member access " + str(self) + " stored as variable = " + str(r))
            return r
        except KeyError:

            # Are we reading some text from an embedded object?
            tmp_str = str(self).lower()
            if (tmp_str.endswith(".caption") or
                tmp_str.endswith(".text") or
                tmp_str.endswith(".controltiptext")):

                # See if a wildcard search can find it.
                try:
                    r = context.get(str(self), search_wildcard=True)
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Member access " + str(self) + " stored as wildcarded variable = " + str(r))
                    return r
                except KeyError:
                    pass

        # Harder case. Resolve any arguments to function calls in the member access expression
        # and try looking that up as a variable.
        expr_list = [self.lhs]
        if (isinstance(self.rhs, list)):
            expr_list += self.rhs
        if (isinstance(self.rhs1, list)):
            expr_list += self.rhs1
        memb_str = ""
        first = True
        for expr in expr_list:

            # Just add this in as-is if this piece of the member access expression is not
            # a function call.
            if (not first):
                memb_str += "."
            first = False
            if (not isinstance(expr, Function_Call)):
                memb_str += str(expr)
                continue

            # Evaluate the arguments of the function call to use in the member access string
            # representation.
            evaled_params = eval_args(expr.params, context)

            # Add in the func call with the resolved args to the member access string.
            func_str = str(expr.name) + "("
            func_first = True
            for param in evaled_params:
                if (not func_first):
                    func_str += ", "
                func_first = False
                if (isinstance(param, float)):
                    param = int(param)
                if (isinstance(param, int)):
                    param = "'" + str(param) + "'"
                func_str += coerce_to_str(param)
            func_str += ")"
            memb_str += func_str
                        
        # Now try looking up the member access expression with resolved function args as a
        # variable.
        try:
            r = context.get(memb_str, search_wildcard=False)
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Member access " + str(self) + " stored as variable = " + str(r))
            return r
        except KeyError:
            pass

        # Maybe this is a Pages() access?
        if ("Pages(" in memb_str):
            tmp_str = memb_str[memb_str.index("Pages("):]
            try:
                r = context.get(tmp_str, search_wildcard=False)
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Member access " + str(self) + " stored as variable = " + str(r))
                return r
            except KeyError:
                pass
            
        # Can't find the expression as a variable.
        return None

    def _eval_cell_range(self, context, just_expr=False):
        """
        Evaluate a member access expression that results in a range of Excel cells.
        """

        # Pull out just the cell range expression.
        range_exp_str = str(self.lhs).replace("'", "")
        for exp in self.rhs[:-1]:
            range_exp_str += "." + str(exp).replace("'", "")
        cells = None
        try:

            # Parse it. Assume this is an expression.
            obj = expressions.expression.parseString(range_exp_str, parseAll=True)[0]
            if just_expr:
                return obj

            # Evaluate it.
            cells = eval_arg(obj, context)
            return cells
        except ParseException:
            log.warning("Parse error. Cannot parse cell range expression '" + range_exp_str + "'")            
            return None
        except Exception as e:
            log.error("Cannot eval cell range expression '" + range_exp_str + "'. " + str(e))
            return None
        
    def _handle_specialcells_call(self, context):
        """
        Handle things like ActiveSheet.UsedRange.SpecialCells(xlCellTypeConstants)
        """

        # Do we have a SpecialCells() method call?
        rhs = None
        if (len(self.rhs1) > 0):
            rhs = self.rhs1
        else:
            rhs = self.rhs[len(self.rhs) - 1]
        if ((not isinstance(rhs, Function_Call)) or
            (rhs.name != "SpecialCells")):
            return None

        # We have a SpecialCells() call. Evaluate to get the range
        # of Excel cells.
        cells = self._eval_cell_range(context)
        if (cells is None):
            return None

        # Do the SpecialCells() call.
        new_special_cells = Function_Call(None, None, None, old_call=rhs)
        tmp = [cells, new_special_cells.params[0]]
        new_special_cells.params = tmp
        r = new_special_cells.eval(context)
        
        # Done
        return r
            
    def eval(self, context, params=None):

        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("MemberAccess eval of " + str(self))

        # 0 argument call to local function?
        r = self._handle_0_arg_call(context)
        if (r is not None):
            #print "OUT: 1"
            return r
            
        # Easy case. Do we have this saved as a variable?
        r = self._read_member_expression_as_var(context)
        if (r is not None):
            #print "OUT: 2"
            return r

        # TODO: Need to actually have some sort of object model. For now
        # just treat this as a variable access.
        rhs = None
        if (len(self.rhs1) > 0):
            rhs = self.rhs1
        else:
            rhs = self.rhs[len(self.rhs) - 1]
            if ((str(rhs) == "Text") and (len(self.rhs) > 1)):
                rhs = self.rhs[len(self.rhs) - 2]
                
        # Figure out if we are calling a function.
        calling_func = isinstance(rhs, Function_Call)
        if (not calling_func):
            try:
                func = context.get(str(rhs), search_wildcard=False)
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Member access " + str(self) + " got RHS = " + str(func))
                calling_func = (isinstance(func, procedures.Function) or isinstance(func, procedures.Sub))
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Member access " + str(self) + " calling function = " + str(calling_func))
            except KeyError:
                pass

        # Handle calling the SpecialCells() method of an Excel Range object.
        call_retval = self._handle_specialcells_call(context)
        if (call_retval is not None):
            #print "OUT: 2.5"
            return call_retval
        
        # Handle reading the caption of a Pages() object accessed by index.
        call_retval = self._handle_indexed_pages_access(context)
        if (call_retval is not None):
            #print "OUT: 3"
            return call_retval
            
        # Handle accessing control values from a form by index.
        call_retval = self._handle_indexed_form_access(context)
        if (call_retval is not None):
            #print "OUT: 4"
            return call_retval
        
        # See if this is reading form text by index.
        call_retval = self._handle_control_read(context)
        if (call_retval is not None):
            #print "OUT: 5"
            return call_retval        
        
        # See if this is reading the OSlanguage.
        call_retval = self._handle_oslanguage(context)
        if (call_retval is not None):
            #print "OUT: 6"
            return call_retval

        # See if this is reading the doc paragraphs.
        call_retval = self._handle_paragraphs(context)
        if (call_retval is not None):
            #print "OUT: 7"
            return call_retval

        # See if this is reading the doc comments.
        call_retval = self._handle_comments(context)
        if (call_retval is not None):
            #print "OUT: 8"
            return call_retval
        
        # See if this is a function call like Application.Run("foo", 12, 13).
        call_retval = self._handle_application_run(context)
        if (call_retval is not None):
            #print "OUT: 9"
            return call_retval

        # See if this is a function call like ActiveDocument.BuiltInDocumentProperties("foo").
        call_retval = self._handle_docprops_read(context)
        if (call_retval is not None):
            #print "OUT: 10"
            return call_retval
        
        # Handle accessing document variables as a special case.
        if (not calling_func):
            call_retval = self._handle_docvars_read(context)
            if (call_retval is not None):
                #print "OUT: 11"
                return call_retval

        # Handle setting the clipboard text.
        call_retval = self._handle_set_clipboard(context)
        if (call_retval is not None):
            #print "OUT: 12"
            return call_retval

        # Handle getting the clipboard text.
        call_retval = self._handle_get_clipboard(context)
        if (call_retval is not None):
            #print "OUT: 13"
            return call_retval
        
        # Pull out the left hand side of the member access.
        tmp_lhs = None
        if (self.lhs is not None):
            tmp_lhs = eval_arg(self.lhs, context)
        else:
            # This is something like ".foo.bar" in a With statement. The LHS
            # is the With context item.
            tmp_lhs = eval_arg(context.with_prefix, context)
            
        # See if this is reading a table cell value.
        call_retval = self._handle_table_cell(context)
        if (call_retval is not None):
            #print "OUT: 14"
            return call_retval
            
        # Is the LHS a python dict and are we looking for a field?
        if (isinstance(tmp_lhs, dict)):

            # Do we have the needed field?
            key = str(self.rhs).replace("[", "").replace("]", "").replace("'", "")
            if (key in tmp_lhs.keys()):

                # Return the field value.
                #print "OUT: 15"
                return tmp_lhs[key]
            
        # Handle getting the .Count of a data collection..
        call_retval = self._handle_count(context, tmp_lhs)
        if (call_retval is not None):
            #print "OUT: 16"
            return call_retval

        # Handle reading an item from a data collection.
        call_retval = self._handle_item(context, tmp_lhs)
        if (call_retval is not None):
            #print "OUT: 17"
            return call_retval

        # Handle Regex object applications.
        call_retval = self._handle_regex_execute(context, tmp_lhs)
        if (call_retval is not None):
            #print "OUT: 18"
            return call_retval

        # Handle simple 0-argument function calls.
        call_retval = self._handle_0_arg_call(context, rhs)
        if (call_retval is not None):
            #print "OUT: 19"
            return call_retval
        
        # Handle reading the contents of a text file.
        call_retval = self._handle_text_file_read(context)
        if (call_retval is not None):
            #print "OUT: 20"
            return call_retval

        # Handle writes of text to ADODB.Stream variables.
        if (self._handle_adodb_writes(self.lhs, tmp_lhs, rhs, context)):
            #print "OUT: 21"
            return "NULL"

        # See if this is accessing the Path field of a file/folder object.
        call_retval = self._handle_path_access()
        if (call_retval is not None):
            #print "OUT: 22"
            return call_retval
        
        # If the final element in the member expression is a function call,
        # the result should be the result of the function call. Otherwise treat
        # it as a fancy variable access.
        if (calling_func):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('rhs {!r} is a Function_Call'.format(rhs))

            # Skip local functions that have a name collision with VBA built in functions.
            rhs_name = str(rhs)
            if (hasattr(rhs, "name")):
                rhs_name = rhs.name
            if (context.contains_user_defined(rhs_name)):
                for func in Function_Call.log_funcs:
                    if (rhs_name.lower() == func.lower()):
                        #print "OUT: 23"
                        return str(self)

            # Handle things like foo.Replace(bar, baz).
            call_retval = self._handle_replace(context, tmp_lhs, self.rhs)
            if (call_retval is not None):
                #print "OUT: 24"
                return call_retval

            # Handle things like foo.Add(bar, baz).
            call_retval = self._handle_add(context, tmp_lhs, self.rhs)
            if (call_retval is not None):
                #print "OUT: 25"
                return call_retval

            # Handle things like foo.Exists(bar).
            call_retval = self._handle_exists(context, tmp_lhs, self.rhs)
            if (call_retval is not None):
                #print "OUT: 25.1"
                return call_retval

            # Handle Excel cells() references.
            call_retval = self._handle_excel_read(context, self.rhs)
            if (call_retval is not None):
                #print "OUT: 26"
                return call_retval
                    
            # This is not a builtin. Evaluate it
            tmp_rhs = eval_arg(rhs, context)

            # Was this a call to LoadXML()?
            if (self._handle_loadxml(context, tmp_rhs)):
                #print "OUT: 27"
                return "NULL"

            # Was this a call to SaveToFile()?
            if (self._handle_savetofile(context, tmp_rhs)):
                #print "OUT: 28"
                return "NULL"

            # It was a regular call.
            #print "OUT: 29"
            return tmp_rhs

        # Arracy access of function call as the RHS?
        elif (isinstance(rhs, Function_Call_Array_Access)):

            # Just evaluate and return the array access.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('rhs {!r} is a Function_Call_Array_Access'.format(rhs))
            tmp_rhs = eval_arg(rhs, context)
            #print "OUT: 30"
            return tmp_rhs
            
        # Did the lhs resolve to something new?
        elif (str(self.lhs) != str(tmp_lhs)):

            # Is this a read from an Excel cell?
            # TODO: Need to do this logic based on what IS an Excel read rather
            # than what IS NOT an Excel read.
            if (((isinstance(tmp_lhs, str)) or (isinstance(tmp_lhs, SimpleNameExpression))) and
                (str(tmp_lhs) != "NULL") and
                (not "Shapes(" in str(tmp_lhs)) and
                (not "Close" in str(self.rhs)) and
                (not context.contains(str(self.lhs)))):

                # Just work with the returned string value.
                #print "OUT: 31"
                return str(tmp_lhs)

            # See if this is reading a doc var name or item.
            call_retval = self._handle_docvar_value(tmp_lhs, self.rhs)
            if (call_retval is not None):
                #print "OUT: 32"
                return call_retval

            # See if this is closing a file.
            call_retval = self._handle_file_close(context, tmp_lhs, self.rhs)
            if (call_retval is not None):
                #print "OUT: 33"
                return call_retval

            # Is the LHS a 0 argument function?
            if ((isinstance(tmp_lhs, procedures.Function)) and
                (len(tmp_lhs.params) == 0)):

                # The LHS is actually a function call. Emulate the function
                # in the current context.
                r = tmp_lhs.eval(context)
                #print "OUT: 34"
                return r

            # Are we reading the text of an object that we resolved?
            if (((str(self.rhs) == "['Text']") or (str(self.rhs).lower() == "['value']")) and (isinstance(tmp_lhs, str))):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Returning .Text value.")
                #print "OUT: 35"
                return tmp_lhs
            
            # Construct a new partially resolved member access object.
            r = MemberAccessExpression(None, None, None, raw_fields=(tmp_lhs, self.rhs, self.rhs1))
            
            # See if we can now resolve this to a doc var read.
            call_retval = r._handle_docvars_read(context)
            if (call_retval is not None):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("MemberAccess: Found " + str(r) + " = '" + str(call_retval) + "'") 
                #print "OUT: 36"
                return call_retval

            # Do we know what the RHS variable evaluates to?
            tmp_rhs = eval_arg(rhs, context)
            var_pat = r"[A-za-z_0-9]+"
            if ((tmp_rhs != rhs) and
                ((re.match(var_pat, str(tmp_lhs)) is not None) or
                 (str(tmp_lhs).lower().endswith(".application"))) and
                (tmp_rhs != "NULL") and
                ("vipermonkey.core.vba_library" not in str(type(tmp_rhs)))):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Resolved member access variable.")
                #print "OUT: 37"
                return tmp_rhs        
            
            # Cannot resolve directly. Return the member access object.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("MemberAccess: Return new access object " + str(r))
            #print "OUT: 38"
            return r

        # Try reading as variable.
        elif (context.contains(rhs)):
            #print "OUT: 39"
            return context.get(rhs)
        
        # Punt and just try to eval this as a string.
        else:
            #print "OUT: 40"
            return eval_arg(self.__repr__(), context)
        
# need to use Forward(), because the definition of l-expression is recursive:
l_expression = Forward()

function_call_limited = Forward()
func_call_array_access_limited = Forward()
function_call = Forward()
excel_expression = Forward()

member_object_limited = (
    ((Suppress("[") + (unrestricted_name_expression | decimal_literal) + Suppress("]")) | unrestricted_name_expression | excel_expression)
    + NotAny("(")
    + NotAny("#")
    + NotAny("$")
    + NotAny("!")
)
"""
member_object_limited = (
    ((Suppress("[") + (unrestricted_name | decimal_literal) + Suppress("]")) | unrestricted_name | excel_expression)
    + NotAny("(")
    + NotAny("#")
    + NotAny("$")
    + NotAny("!")
)
"""
# If the member is a function, it cannot be the last member, otherwise this line is considered a Call_Statement.
member_object_loose = Suppress(Literal("(")) + ((func_call_array_access_limited ^ function_call_limited) | member_object_limited) + Suppress(Literal(")")) | \
                      ((func_call_array_access_limited ^ function_call_limited) | member_object_limited)
member_object_strict = Suppress(Optional(".")) + NotAny(reserved_identifier) + member_object_loose

# TODO: Just use delimitedList is the "lhs"/"rhs" neccessary?
member_access_expression = Group(Group(member_object_strict("lhs") + OneOrMore((Suppress(".") | Suppress("!")) + member_object_loose("rhs"))))
member_access_expression.setParseAction(MemberAccessExpression)


# Whitespace allowed before the "."
member_access_expression_loose = Group(
    Group(
        Suppress(ZeroOrMore(" "))
        + member_object_strict("lhs")
        + OneOrMore(Suppress(".") + member_object_loose("rhs"))
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
        member_object_strict("lhs")
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

class NamedArgument(VBA_Object):

    def __init__(self, original_str, location, tokens, name=None):
        super(NamedArgument, self).__init__(original_str, location, tokens)

        self.name = tokens.name
        self.value = tokens.value
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed "%r" as NamedArgument' % self)

    def __repr__(self):
        return '%s:=%s' % (self.name, self.value)

    def eval(self, context, params=None):
        try:
            return eval_arg(self.value, context)
        except:
            log.error("NamedArgument: Cannot eval " + self.__repr__() + ".")
            return ''
    
named_argument = unrestricted_name('name') + Suppress(":=") + argument_expression('value')
named_argument.setParseAction(NamedArgument)
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

class With_Member_Expression(VBA_Object):
    
    def __init__(self, original_str, location, tokens, old_call=None):
        super(With_Member_Expression, self).__init__(original_str, location, tokens)
        self.expr = tokens.expr
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as With_Member_Expression' % self)

    def __repr__(self):
        return "." + str(self.expr)

    def to_python(self, context, params=None, indent=0):

        # Currently we are only supporting JIT emulation of With blocks
        # based on Scripting.Dictionary. Is that what we have?
        with_dict = None
        if ((context.with_prefix_raw is not None) and
            (context.contains(str(context.with_prefix_raw)))):
            with_dict = context.get(str(context.with_prefix_raw))
            if (with_dict == "__ALREADY_SET__"):

                # Try getting the original value.
                with_dict = context.get("__ORIG__" + str(context.with_prefix_raw))

            # Got Scripting.Dictionary?
            if (not isinstance(with_dict, dict)):                
                with_dict = None

        # Can we do JIT code for this?
        if (with_dict is None):
            return "ERROR: Only doing JIT on Scripting.Dictionary With blocks."

        # Is this a Scripting.Dictionary method call?
        expr_str = str(self)
        if ((not expr_str.startswith(".Exists")) and
            (not expr_str.startswith(".Items")) and
            (not expr_str.startswith(".Item")) and
            (not expr_str.startswith(".Count"))):
            return "ERROR: Only doing JIT on Scripting.Dictionary methods in With blocks."

        # Count? Not parsed as a function call...
        if (expr_str == ".Count"):
            return "(len(" + context.with_prefix_raw + ") - 1)"

        # Generate python for the dictionary method call.
        tmp_var = SimpleNameExpression(None, None, None, name=str(context.with_prefix_raw))
        new_exists = Function_Call(None, None, None, old_call=self.expr)
        tmp = [tmp_var]
        for p in new_exists.params:
            tmp.append(p)
        new_exists.params = tmp
        r = to_python(new_exists, context, params)
        return r
        
    def _handle_method_calls(self, context):
        """
        Handle Scripting.Dictionary...() calls.
        """

        # Is this a method call?
        expr_str = str(self)
        if ((not expr_str.startswith(".Exists")) and (not expr_str.startswith(".Count"))):
            return None

        # Get the Dictionary if it is a With variable.
        if ((context.with_prefix_raw is None) or
            (not context.contains(str(context.with_prefix_raw)))):
            return None
        with_dict = context.get(str(context.with_prefix_raw))

        # Count? Not parsed as a function call...
        if (expr_str == ".Count"):
            return (len(with_dict) - 1)
        
        # Run the dictionary method call.
        new_exists = Function_Call(None, None, None, old_call=self.expr)
        tmp = [with_dict]
        for p in new_exists.params:
            tmp.append(p)
        new_exists.params = tmp
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Dictionary NNNNNN() func = " + str(new_exists))
        
        # Evaluate the dictionary exists.
        r = new_exists.eval(context)
        return r
        
    def eval(self, context, params=None):

        # Handle Scripting.Dictionary....() calls.
        call_retval = self._handle_method_calls(context)
        if (call_retval is not None):
            return call_retval

        # Plain eval.
        return self.expr.eval(context, params)

with_member_access_expression = Suppress(".") + (simple_name_expression("expr") ^ function_call_limited("expr") ^ member_access_expression("expr")) 
with_member_access_expression.setParseAction(With_Member_Expression)
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
    log_funcs = ["CreateProcessA", "CreateProcessW", "CreateProcess", ".run", "CreateObject",
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
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('Function_Call.name = %r' % self.name)
        assert isinstance(self.name, basestring)
        self.params = tokens.params

        # Do some special handling of calls to MultiByteToWideChar. It looks like the
        # 3rd parameter (the data to convert to wide char) is treated as a C-style array
        # in this call, so foo(0) of array foo is actually a pointer to the start of
        # the array.
        #
        # Handle that in ViperMonkey by removing the (0) from the end of the 3rd argument
        # so we get the whole array when emulating.
        array_pat = r"\w+\(.+\)"
        if ((self.name.lower() == "multibytetowidechar") and
            (len(self.params) == 6) and
            (re.match(array_pat, str(self.params[2])) is not None) and
            (isinstance(self.params[2], Function_Call))):

            # Turn this into just an access (hopefully) of an array variable.
            array = None
            orig_array = self.params[2]
            try:
                array = expressions.expression.parseString(self.params[2].name, parseAll=True)[0]
            except ParseException:
                pass
            if (array is not None):
                self.params[2] = array
                log.warning("Rewrote MultiByteToWideChar() array reference '" + str(orig_array) + "' to '" + str(array) + "'.")

        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('Function_Call.params = %r' % self.params)
        if (log.getEffectiveLevel() == logging.DEBUG):
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
        
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Function_Call: eval params: " + str(self.params))

        # Reset the called function name if this is an alias for an imported external
        # DLL function.
        dll_func_name = context.get_true_name(self.name)
        is_external = False
        if (dll_func_name is not None):
            is_external = True
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

        # We will not report the calls of some functions.
        skip_report_functions = set(["cos", "tan"])
        if (str(self.name).lower() not in skip_report_functions):
            if (not context.throttle_logging):
                log.info('calling Function: %s(%s)' % (self.name, str_params))
        
        # Actually emulate the function call.
        if (is_external):

            # Save the call as a reportable action.
            context.report_action("External Call", self.name + "(" + str(params) + ")", self.name, strip_null_bytes=True)

            # Emulate the call.
            try:
                s = context.get_lib_func(self.name)
                if (s is None):
                    raise KeyError("func not found")
                r = s.eval(context=context, params=params)
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("External function " + str(s.name) + " returns " + str(r))
                return r
            except KeyError:
                log.warning("External function " + str(self.name) + " not found.")
                return "NULL"
            
        if self.name.lower() in context._log_funcs \
                or any(self.name.lower().endswith(func.lower()) for func in Function_Call.log_funcs):
            if ("Scripting.Dictionary" not in str(params)):
                context.report_action(self.name, params, 'Interesting Function Call', strip_null_bytes=True)
        try:

            # Get the (possible) function.
            f = context.get(self.name)
            
            # Is this actually a hash lookup?
            if (isinstance(f, dict)):

                # Are we accessing an element?
                if (len(params) > 0):
                    if (log.getEffectiveLevel() == logging.DEBUG):
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
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug('Array Access: %r[%r]' % (tmp, str(params)))
                    index = int_convert(params[0])
                    index1 = None
                    if (len(params) > 1):
                        index1 = int_convert(params[1])
                    try:

                        # Return array access result.
                        if (index1 is None):
                            r = tmp[index]
                        else:
                            r = tmp[index][index1]
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug('Returning: %r' % r)
                        return r
                    except:

                        # Return error array access result.
                        msg = 'Array Access Failed: %r[%r]' % (tmp, str(params))
                        context.set_error(msg)
                        return 0

                # Looks like we want the whole array (ex. foo()).
                else:

                    # Return whole array result.
                    return f
                    
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Calling: %r' % f)

            # Handle indirect function calls.
            if ((isinstance(f, str)) and (context.contains(f))):
                tmp_f = context.get(f)
                if (isinstance(tmp_f, VbaLibraryFunc)):
                    f = tmp_f

            # Emulate the action.
            if (f is not None):
                if (isinstance(f, procedures.Function) or
                    isinstance(f, procedures.Sub) or
                    ("vba_library." in str(type(f)))):
                    try:

                        # Call function.
                        r = f.eval(context=context, params=params)                        
                        
                        # Set the values of the arguments passed as ByRef parameters.
                        if (hasattr(f, "byref_params")):
                            for byref_param_info in f.byref_params.keys():
                                try:
                                    arg_var_name = str(self.params[byref_param_info[1]])
                                    if (context.contains(arg_var_name)):

                                        # Don't overwrite functions.
                                        arg_var_val = context.get(arg_var_name)
                                        if (not (isinstance(f, procedures.Function) or
                                                 isinstance(f, procedures.Sub) or
                                                 isinstance(f, VbaLibraryFunc))):
                                            context.set(arg_var_name, f.byref_params[byref_param_info])
                                except IndexError:
                                    break

                        # We are out of the called function, so if we exited the called function early
                        # it does not apply to the current function.
                        context.exit_func = False
                                    
                        # Return result.
                        return r

                    except AttributeError as e:

                        # Return result.
                        log.error(str(f) + " has no eval() method. " + str(e))
                        return f

                # Misparsed addition?
                elif ((isinstance(f, int)) and
                      (len(params) == 1) and
                      (isinstance(params[0], int))):
                    return (f + params[0])

                # Array access?
                elif (len(params) > 0):

                    # Looks like this is actually an array access.
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Looks like array access.")
                    try:

                        # Return result.
                        i = int_convert(params[0])
                        r = f[i]
                        if (isinstance(f, str)):
                            r = ord(r)
                        if (log.getEffectiveLevel() == logging.DEBUG):
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
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Try indirect run of function '" + new_func + "'")
                r = "NULL"
                try:

                    # Return result, if we find a function to run.
                    s = new_func
                    while (isinstance(s, str)):

                        # Drill down through layers of indirection to get the name of the function to run.
                        s = context.get(s)
                        if (isinstance(s, procedures.Function) or
                            isinstance(s, procedures.Sub) or
                            isinstance(s, VbaLibraryFunc)):
                            s = s.eval(context=context, params=new_params)
                            r = s

                    # Report actions if interesting.
                    if ((str(self).lower().startswith("thisdocument.run(")) and (r != "NULL")):
                        context.report_action('Execute Command', r, 'ThisDocument.Run', strip_null_bytes=True)

                except KeyError:
                    pass

                # Did we run a function with Application.Run()?
                if (r != "NULL"):
                    return r

            # Could this be a misparsed addition to a variable (thanks VB grammar... :( )?
            if (context.contains(self.name) and
                (len(params) == 1) and
                (isinstance(params[0], int))):

                # Get the variable value.
                var_val = context.get(self.name)

                # Can we add an int to this?
                if (isinstance(var_val, int)):

                    # Treat this as a misparsed int addition.
                    return (var_val + params[0])
                
            # Return result.                
            context.increase_general_errors()
            log.warning('Function %r not found' % self.name)
            return None

    def to_python(self, context, params=None, indent=0):

        # Get a list of the Python expressions for each parameter.
        py_params = []
        for p in self.params:
            py_params.append(to_python(p, context, params))

        # Is this a VBA internal function?
        import vba_library
        if (self.name.lower() in vba_library.VBA_LIBRARY):
            first = True
            args = "["
            for p in py_params:
                if (not first):
                    args += ", "
                first = False
                args += p
            args += "]"
            r = "core.vba_library.run_function(\"" + str(self.name) + "\", vm_context, " + args + ")"
            return r

        # Is this an array access? We tell if this is an array access based on the
        # value of the variable or if this variable is a function argument (functions
        # not 1st class objects in VB).
        if (context.contains(self.name)):
            ref = context.get(self.name)
            ref1 = None
            try:
                ref1 = context.get("__ORIG__" + self.name)
            except KeyError:
                pass
            if ((isinstance(ref, list)) or
                (isinstance(ref1, list)) or
                (ref == "__FUNC_ARG__")):

                # Do the array access.
                acc_str = ""
                for p in py_params:
                    acc_str += "[" + p + "]"
                r = str(self.name) + acc_str
                return r
        
        # Generate the Python function call to a local function.
        r = str(self.name) + "("
        first = True
        for p in py_params:
            if (not first):
                r += ", "
            first = False
            r += p
        r += ")"

        # Done.
        return r
        
# comma-separated list of parameters, each of them can be an expression:
boolean_expression = Forward()
# TODO: Since the VB designers in their infinite wisdom decided to use the same operators
# for bitwise arithmetic as boolean logic, we somehow have to tell based on the context
# whether we are doing bitwise or boolean operations. NEEDS WORK!!
boolean_expression_bitwise = Forward()
expr_item = Forward()
expr_item_strict = Forward()
# The 'ByVal' or 'ByRef' keyword can be given when the expr_list_item appears as an
# expression given as a function call parameter. Allowing these keywords for all expressions is
# not strictly correct (invalid VB could be parsed and treated as valid), but we assume that
# ViperMonkey is working with valid VB to begin with so this should not be a problem.
#expr_list_item = Optional(Suppress(CaselessKeyword("ByVal") | CaselessKeyword("ByRef"))) + expression ^ boolean_expression_bitwise ^ member_access_expression_loose
expr_list_item = Optional(Suppress(CaselessKeyword("ByVal") | CaselessKeyword("ByRef"))) + expression ^ boolean_expression ^ member_access_expression_loose
#expr_list_item_strict = Optional(Suppress(CaselessKeyword("ByVal") | CaselessKeyword("ByRef"))) + \
#                        NotAny(CaselessKeyword("End")) + \
#                        (expression ^ boolean_expression_bitwise ^ member_access_expression_loose)
expr_list_item_strict = Optional(Suppress(CaselessKeyword("ByVal") | CaselessKeyword("ByRef"))) + \
                        NotAny(CaselessKeyword("End")) + \
                        (expression ^ boolean_expression ^ member_access_expression_loose)
# NOTE: This helps to speed up parsing and prevent recursion loops.
expr_list_item = (expr_item + FollowedBy(',')) | expr_list_item
expr_list_item_strict = (expr_item_strict + FollowedBy(',')) | expr_list_item_strict

def quick_parse_int_or_var(text):
    text = str(text).strip()

    # Integer?
    if (text.isdigit()):
        return int(text)        

    # Variable?
    if (re.match(r"[_a-zA-Z][_a-zA-Z\d]*", text) is not None):
        r = SimpleNameExpression(None, None, None, text)
        return r

    # Non-special case. Parse it.
    r = expression.parseString(text, parseAll=True)[0]
    return r
    
# Parse large array expressions quickly with a regex.
# language=PythonRegExp
# No newlines in whitespace.
expr_list_fast = Regex("(?:\s*[0-9a-zA-Z_]+[ \t\f\v]*,[ \t\f\v]*){10,}[ \t\f\v]*[0-9a-zA-Z_]+[ \t\f\v]*")
expr_list_fast.setParseAction(lambda t: [quick_parse_int_or_var(i) for i in t[0].split(",")])

# Parse general expression lists more completely but more slowly.
expr_list_slow = delimitedList(Optional(expr_list_item, default=""))

# WARNING: This may break parsing in function calls when the 1st argument is skipped.
#expr_list = Suppress(Optional(",")) + expr_list_item + NotAny(':=') + Optional(Suppress(",") + delimitedList(Optional(expr_list_item, default="")))
expr_list = (
    expr_list_item
    + NotAny(':=')
    + Optional(Suppress(",") + (expr_list_fast | expr_list_slow))
)
expr_list_strict = (
    expr_list_item_strict
    + NotAny(':=')
    + Optional(Suppress(",") + (expr_list_fast | expr_list_slow))
)

# TODO: check if parentheses are optional or not. If so, it can be either a variable or a function call without params
function_call <<= (
    CaselessKeyword("nothing")
    | (
        ~(strict_reserved_keywords + Literal("(")) +
        (
            (member_access_expression('name') ^ lex_identifier('name')) |
            (Suppress('[') + lex_identifier('name') + Suppress(']'))
        ) +
        Suppress(
            Optional('$')
            + Optional('#')
            + Optional('!')
            + Optional('%')
            + Optional('@')
        )
        + ((Suppress('(') + Optional(expr_list('params')) + Suppress(')')) |
           (Suppress('[') + Optional(expr_list('params')) + Suppress(']')))
    )
    | (
        Suppress('[') +
        CaselessKeyword("Shell")('name') +
        Suppress(']') +
        expr_list('params')
    )
    | (
        Suppress('[') + lex_identifier('name') + Suppress('(') + expr_list('params') + Suppress(')') + Suppress(']')
    )
)
function_call.setParseAction(Function_Call)

function_call_limited <<= (
    CaselessKeyword("nothing")
    | (
        #~(strict_reserved_keywords + Literal("("))
        #~(reserved_keywords + Literal("("))
        (lex_identifier('name') | (Suppress('[') + lex_identifier('name') + Suppress(']')))
        + Suppress(Optional('$'))
        + Suppress(Optional('#'))
        + Suppress(Optional('!'))
        + Suppress(Optional('%'))
        + Suppress(Optional('@'))
        + (
            (Suppress('(') + Optional(expr_list('params')) + Suppress(')'))
            | (Suppress('[') + Optional(expr_list('params')) + Suppress(']'))
            # TODO: The NotAny(".") is a temporary fix to get "foo.bar" to not be
            # parsed as function_call_limited "foo .bar". The real way this should be
            # parsed is to require at least 1 space between the function name and the
            # 1st argument, then "foo.bar" will not match.
            #
            # And the "step" expression is to keep step from being parsed as an arg to
            # a.b(step) in 'for i = 0 to a.b step 2'.
            | (Suppress(Optional('$')) + NotAny(".") + NotAny(CaselessKeyword("step")) + expr_list('params')))
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
        if (log.getEffectiveLevel() == logging.DEBUG):
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

typeof_expression = Forward()
addressof_expression = Forward()
literal_list_expression = Forward()
literal_range_expression = Forward()
limited_expression = Forward()
expr_item <<= (
    Optional(CaselessKeyword("ByVal").suppress())
    + (
        date_string
        | file_pointer
        | float_literal
        | named_argument
        | l_expression
        | (chr_ ^ function_call ^ func_call_array_access)
        | simple_name_expression
        | asc
        | strReverse
        | literal
        | placeholder
        | typeof_expression
        | addressof_expression
        | excel_expression
        | literal_range_expression
        | literal_list_expression
        #| Suppress(Literal("(")) + boolean_expression_bitwise + Suppress(Literal(")"))
        | Suppress(Literal("(")) + boolean_expression + Suppress(Literal(")"))
    )
)
expr_item_strict <<= (
    Optional(CaselessKeyword("ByVal").suppress())
    + NotAny(CaselessKeyword("End"))
    + (
        date_string
        | file_pointer
        | float_literal
        | named_argument
        | l_expression
        | (chr_ ^ function_call ^ func_call_array_access)
        | simple_name_expression
        | asc
        | strReverse
        | literal
        | placeholder
        | typeof_expression
        | addressof_expression
        | excel_expression
        | literal_range_expression
        | literal_list_expression
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
                                      ("-", 1, opAssoc.RIGHT, Neg), # Unary negation
                                      ("^", 2, opAssoc.RIGHT, Power),
                                      (Regex(re.compile("[*/]")), 2, opAssoc.LEFT, MultiDiv),
                                      ("\\", 2, opAssoc.LEFT, FloorDivision),
                                      (Regex(re.compile("mod", re.IGNORECASE)), 2, opAssoc.LEFT, Mod),
                                      (Regex(re.compile('[-+]')), 2, opAssoc.LEFT, AddSub),
                                      ("&", 2, opAssoc.LEFT, Concatenation),
                                      (";", 2, opAssoc.LEFT, Concatenation),
                                      (Regex(re.compile("and", re.IGNORECASE)), 2, opAssoc.LEFT, And),
                                      (Regex(re.compile("or", re.IGNORECASE)), 2, opAssoc.LEFT, Or),
                                      (Regex(re.compile("xor", re.IGNORECASE)), 2, opAssoc.LEFT, Xor),
                                      (Regex(re.compile("eqv", re.IGNORECASE)), 2, opAssoc.LEFT, Eqv),
                                  ]))
expression.setParseAction(lambda t: t[0])

# Used in boolean expressions to limit confusion with boolean and/or and bitwise and/or.
# Try to handle bitwise AND in boolean expressions. Needs work
limited_expression <<= (infixNotation(expr_item,
                                      [
                                          ("-", 1, opAssoc.RIGHT, Neg), # Unary negation
                                          ("^", 2, opAssoc.RIGHT, Power), # Exponentiation
                                          (Regex(re.compile("[*/]")), 2, opAssoc.LEFT, MultiDiv),
                                          ("\\", 2, opAssoc.LEFT, FloorDivision),
                                          (CaselessKeyword("mod"), 2, opAssoc.RIGHT, Mod),
                                          (Regex(re.compile('[-+]')), 2, opAssoc.LEFT, AddSub),
                                          ("&", 2, opAssoc.LEFT, Concatenation),
                                          (CaselessKeyword("xor"), 2, opAssoc.LEFT, Xor),
                                      ])) | \
                                      Suppress(Literal("(")) + expression + Suppress(")")
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
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as BoolExprItem' % self)

    def __repr__(self):
        if (self.op is not None):
            return self.lhs.__repr__() + " " + self.op + " " + self.rhs.__repr__()
        elif (self.lhs is not None):
            return self.lhs.__repr__()
        else:
            log.error("BoolExprItem: Improperly parsed.")
            return ""

    def _vba_to_python_op(self, op):
        return _vba_to_python_op(op, True)
        
    def to_python(self, context, params=None, indent=0):
        r = " " * indent
        if (self.op is not None):
            r += to_python(self.lhs, context, params) + " " + self._vba_to_python_op(self.op) + " " + to_python(self.rhs, context, params)
        elif (self.lhs is not None):
            r += to_python(self.lhs, context, params)
        else:
            log.error("BoolExprItem: Improperly parsed.")
            return ""
        return r
        
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
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Set unitinitialized " + str(self.rhs) + " = " + str(rhs))
        if ((lhs == "NULL") or (lhs is None)):
            if (isinstance(rhs, str)):
                lhs = ''
            else:
                lhs = 0
            context.set(self.lhs, lhs)
            if (log.getEffectiveLevel() == logging.DEBUG):
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

        # Blah. Handle float autoconversion.
        if (isinstance(lhs, float) and isinstance(rhs, int)):
            rhs = rhs + 0.0
        if (isinstance(rhs, float) and isinstance(lhs, int)):
            lhs = lhs + 0.0

        # Convert unicode to str by stripping non-ASCII chars. Not ideal.
        if (isinstance(lhs, unicode)):
            lhs = ''.join(filter(lambda x:x in string.printable, lhs))
        if (isinstance(rhs, unicode)):
            rhs = ''.join(filter(lambda x:x in string.printable, rhs))
            
        # Handle unexpected types.
        if (((not isinstance(rhs, int)) and (not isinstance(rhs, str)) and (not isinstance(rhs, float))) or
            ((not isinstance(lhs, int)) and (not isinstance(lhs, str)) and (not isinstance(lhs, float)))):

            # Punt and compare everything as strings.
            lhs = str(lhs)
            rhs = str(rhs)

        # Always evaluate to true if comparing against a wildcard.
        rhs = strip_nonvb_chars(rhs)
        lhs = strip_nonvb_chars(lhs)
        rhs_str = str(rhs)
        lhs_str = str(lhs)
        if (("**MATCH ANY**" in lhs_str) or ("**MATCH ANY**" in rhs_str)):
            if (self.op == "<>"):
                return False
            return True

        # Evaluate the expression.
        if ((self.op.lower() == "=") or
            (self.op.lower() == "is")):            
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
                rhs = rhs.replace("*", ".*")
                r = (re.match(rhs, lhs) is not None)
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("'" + lhs + "' Like '" + rhs + "' == " + str(r))
                return r
            except Exception as e:

                # Not a valid Pyhton regex. Just check string equality.
                return (rhs == lhs)
        else:
            log.error("BoolExprItem: Unknown operator %r" % self.op)
            return False

class BoolExprItemBitwise(BoolExprItem):

    def __init__(self, original_str, location, tokens):
        super(BoolExprItemBitwise, self).__init__(original_str, location, tokens)

        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('ACTUALLY parsed %r as BoolExprItemBitWise' % self)
        
    def _vba_to_python_op(self, op):
        return _vba_to_python_op(op, False)
        
bool_expr_item = (limited_expression + \
                  (oneOf(">= => <= =< <> = > < <>") | CaselessKeyword("Like") | CaselessKeyword("Is")) + \
                  limited_expression) | \
                  limited_expression
bool_expr_item.setParseAction(BoolExprItem)

#bool_expr_item_bitwise = bool_expr_item
bool_expr_item_bitwise = (limited_expression + \
                          (oneOf(">= => <= =< <> = > < <>") | CaselessKeyword("Like") | CaselessKeyword("Is")) + \
                          limited_expression) | \
                          limited_expression
bool_expr_item_bitwise.setParseAction(BoolExprItemBitwise)

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

        if (log.getEffectiveLevel() == logging.DEBUG):
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

    def _vba_to_python_op(self, op):
        return _vba_to_python_op(op, True)
        
    def to_python(self, context, params=None, indent=0):
        r = " " * indent + "("
        if (self.op is not None):
            if (self.lhs is not None):
                r += to_python(self.lhs, context, params) + " " + self._vba_to_python_op(self.op) + " " + to_python(self.rhs, context, params)
            else:
                r += self._vba_to_python_op(self.op) + " " + to_python(self.rhs, context, params)
        elif (self.lhs is not None):
            r += to_python(self.lhs, context, params)
        else:
            log.error("BoolExpr: Improperly parsed.")
            return ""

        # Done.
        r += ")"
        return r
        
    def eval(self, context, params=None):

        # Unary operator?
        if (self.lhs is None):

            # We have only a RHS. Evaluate it.
            rhs = None
            try:
                rhs = eval_arg(self.rhs, context)
            except:
                log.error("BoolExpr: Cannot eval " + self.__repr__() + ".")
                return ''

            # Bitwise operation?
            if ((isinstance(rhs, int)) and (not isinstance(rhs, bool))):
                if (log.getEffectiveLevel() == logging.DEBUG):
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

            if (log.getEffectiveLevel() == logging.DEBUG):
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
        elif ((self.op.lower() == "eqv") or (self.op.lower() == "=")):
            return (lhs == rhs)
        else:
            log.error("BoolExpr: Unknown operator boolean %r" % self.op)
            return False

class BoolExprBitwise(BoolExpr):

    def _vba_to_python_op(self, op):
        return _vba_to_python_op(op, False)
        
boolean_expression <<= infixNotation(bool_expr_item,
                                     [
                                         (CaselessKeyword("Not"), 1, opAssoc.RIGHT),
                                         (CaselessKeyword("And"), 2, opAssoc.LEFT),
                                         (CaselessKeyword("AndAlso"), 2, opAssoc.LEFT),
                                         (CaselessKeyword("Or"), 2, opAssoc.LEFT),
                                         (CaselessKeyword("OrElse"), 2, opAssoc.LEFT),
                                         (CaselessKeyword("Eqv"), 2, opAssoc.LEFT),
                                         (CaselessKeyword("="), 2, opAssoc.LEFT),
                                     ])
boolean_expression.setParseAction(BoolExpr)

boolean_expression_bitwise <<= infixNotation(bool_expr_item_bitwise,
                                             [
                                                 (CaselessKeyword("Not"), 1, opAssoc.RIGHT),
                                                 (CaselessKeyword("And"), 2, opAssoc.LEFT),
                                                 (CaselessKeyword("AndAlso"), 2, opAssoc.LEFT),
                                                 (CaselessKeyword("Or"), 2, opAssoc.LEFT),
                                                 (CaselessKeyword("OrElse"), 2, opAssoc.LEFT),
                                                 (CaselessKeyword("Eqv"), 2, opAssoc.LEFT),
                                                 (CaselessKeyword("="), 2, opAssoc.LEFT),
                                             ])
boolean_expression_bitwise.setParseAction(BoolExprBitwise)

# --- NEW EXPRESSION --------------------------------------------------------------

class New_Expression(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(New_Expression, self).__init__(original_str, location, tokens)
        self.obj = tokens.expression
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as New_Expression' % self)

    def __repr__(self):
        return ('New %r' % self.obj)

    def to_python(self, context, params=None, indent=0):

        # We can fake RegEx objects.
        if (str(self.obj).strip().lower() == "regexp"):
            return "core.utils.vb_RegExp()"

        # Not faking other objects at this point.
        return "ERROR: Not emulating " + str(self)
    
    def eval(self, context, params=None):
        # TODO: Not sure how to handle this. For now just return what is being created.
        return self.obj

new_expression << CaselessKeyword('New').suppress() + expression('expression')
new_expression.setParseAction(New_Expression)

any_expression = expression ^ boolean_expression

# --- TYPEOF EXPRESSION --------------------------------------------------------------

class TypeOf_Expression(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(TypeOf_Expression, self).__init__(original_str, location, tokens)
        self.item = tokens.item
        self.the_type = tokens.the_type
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as TypeOf_Expression' % self)

    def __repr__(self):
        return "TypeOf " + str(self.item) + " Is " + str(self.the_type)

    def eval(self, context, params=None):
        # TODO: Not sure how to handle this. For now just always matches.
        return True

typeof_expression <<= CaselessKeyword("TypeOf") + expression("item") + CaselessKeyword("Is") + expression("the_type")
typeof_expression.setParseAction(TypeOf_Expression)

# --- ADDRESSOF EXPRESSION --------------------------------------------------------------

class AddressOf_Expression(VBA_Object):
    def __init__(self, original_str, location, tokens):
        super(AddressOf_Expression, self).__init__(original_str, location, tokens)
        self.item = tokens.item
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as AddressOf_Expression' % self)

    def __repr__(self):
        return "AddressOf " + str(self.item)

    def eval(self, context, params=None):
        # TODO: Not sure how to handle this. For now just always matches anything.
        return "**MATCH ANY**"

addressof_expression <<= CaselessKeyword("AddressOf") + expression("item")
addressof_expression.setParseAction(AddressOf_Expression)

# --- EXCEL ROW/COLUMN EXPRESSION --------------------------------------------------------------

class Excel_Expression(VBA_Object):

    def __init__(self, original_str, location, tokens):
        super(Excel_Expression, self).__init__(original_str, location, tokens)
        self.row = tokens.row
        self.col = tokens.col
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as Excel_Expression' % self)

    def __repr__(self):
        return "[" + str(self.row) + ":" + str(self.col) + "]"

    def eval(self, context, params=None):
        # TODO: Not sure how to handle this. For now do nothing.
        return "NULL"
    
# ex. [A:B]
excel_expression <<= Suppress(Literal("[")) + lex_identifier("row") + Suppress(Literal(":")) + lex_identifier("col") + Suppress(Literal("]"))
excel_expression.setParseAction(Excel_Expression)

# --- LITERAL LIST EXPRESSION --------------------------------------------------------------

class Literal_List_Expression(VBA_Object):

    def __init__(self, original_str, location, tokens):
        super(Literal_List_Expression, self).__init__(original_str, location, tokens)
        self.item = tokens.item
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as Literal_List_Expression' % self)

    def __repr__(self):
        return "[" + str(self.item) + "]"

    def eval(self, context, params=None):
        if (isinstance(self.item, str)):
            return self.item
        return self.item.eval(context)
    
literal_list_expression <<= Suppress("[") + (unrestricted_name | decimal_literal)("item") + Suppress("]")
literal_list_expression.setParseAction(Literal_List_Expression)

# --- LITERAL RANGE EXPRESSION --------------------------------------------------------------

literal_range_expression <<= Suppress(Literal("[")) + decimal_literal + Suppress(Literal(":")) + decimal_literal + Suppress(Literal("]"))
literal_range_expression.setParseAction(lambda t: str(t[0]) + ":" + str(t[1]))
