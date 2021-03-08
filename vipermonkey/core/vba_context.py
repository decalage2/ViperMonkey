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

__version__ = '0.08'

# --- IMPORTS ------------------------------------------------------------------

import logging
import os
from hashlib import sha256
from datetime import datetime
from logger import log
import re
import random
import string
import codecs
import copy
import struct
from curses_ascii import isascii

import vba_constants
import utils

def to_hex(s):
    """
    Convert a string to a VBA hex string.
    """

    r = ""
    for c in str(s):
        r += hex(ord(c)).replace("0x", "")
    return r

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

def add_shellcode_data(index, value, num_bytes):
    """
    Save injected shellcode data.
    """

    # Sanity check.
    if ((not isinstance(index, int)) or
        (not isinstance(value, int)) or
        (not isinstance(num_bytes, int))):
        log.warning("Improperly typed argument passed to add_shellcode_data(). Skipping.")
        return

    # Currently only handling single byte values.
    if (num_bytes > 1):
        log.warning("Only handling single byte values in add_shellcode_data(). Skipping.")
        return
    
    # Track the written byte.
    shellcode[index] = value

def get_shellcode_data():
    """
    Get written shellcode bytes as a list.
    """

    # Punt if there is no shellcode data.
    if (len(shellcode) == 0):
        return []

    # Get the shellcode bytes in order. Assume any missing
    # bytes are x86 NOOP instructions.
    indices = shellcode.keys()
    indices.sort()
    last_i = None
    r = []
    for i in indices:

        # Need to fill in missing bytes?
        if ((last_i is not None) and (last_i + 1 != i)):
            last_i += 1
            while (last_i != i):
                r.append(0x90)
                last_i += 1

        # Only want unsigned integers for byte values.
        curr_val = shellcode[i]
        if (curr_val < 0):
            curr_val += 2**8
                    
        # Add in the current shellcode byte.
        r.append(curr_val)
        last_i = i

    # Return shellcode bytes, in order.
    return r
    
# === VBA CLASSES =====================================================================================================

# global dictionary of constants, functions and subs for the VBA library
VBA_LIBRARY = {}

# Output directory to save dropped artifacts.
out_dir = None  # type: str

# Track intermediate IOC values stored in variables during emulation.
intermediate_iocs = set()

# Track the # of base64 IOCs.
num_b64_iocs = 0

# Track any injected shellcode bytes written by the VBA.
# Dict mapping index to a byte.
shellcode = {}

class Context(object):
    """
    a Context object contains the global and local named objects (variables, subs, functions)
    used to evaluate VBA statements.
    """

    def __init__(self,
                 _globals=None,
                 _locals=None,
                 context=None,
                 engine=None,
                 doc_vars=None,
                 loaded_excel=None,
                 filename=None,
                 copy_globals=False,
                 log_funcs=None,
                 expand_env_vars=True,
                 metadata=None):

        # Track canonical names of variables.
        self.name_cache = {}

        # Track the name of the current function being emulated.
        self.curr_func_name = None
        
        # Track the name of the last saved file.
        self.last_saved_file = None
        
        # Track whether we are handling a non-boolean (bitwise) expression.
        self.in_bitwise_expression = False
        
        # Track whether emulation actions have been reported.
        self.got_actions = False
        
        # Track all external functions called by the program.
        self.external_funcs = []

        # Track a quick lookup of variables that have change handling functions.
        self.has_change_handler = {}
        
        # Track the current call stack. This is used to detect simple cases of
        # infinite recursion.
        self.call_stack = []
        
        # Track the maximum number of iterations to emulate in a while loop before
        # breaking out (infinite loop) due to no vars in the loop guard being
        # modified.
        self.max_static_iters = 2

        # Track whether VBScript or VBA is being analyzed.
        self.is_vbscript = False

        # JIT loop emulation?
        self.do_jit = False

        # Track whether logging should be throttled.
        self.throttle_logging = False
        
        # Allow user to provide extra function names to be reported on.
        if log_funcs:
            self._log_funcs = [func_name.lower() for func_name in log_funcs]
        else:
            self._log_funcs = []

        # Allow user to determine whether to expand environment variables.
        self.expand_env_vars = expand_env_vars
        
        # Track callback functions that should not be called. This is to handle
        # recusive change handler calls caused by modifying the element handled
        # by the change handler inside the handler.
        self.skip_handlers = set()
        
        # Track the file being analyze.
        self.filename = filename
        
        # Track whether an error was raised in an emulated statement.
        self.got_error = False

        # Track the error handler to execute when an error is raised.
        self.error_handler = None

        # Track the numebr of reported general errors.
        self.num_general_errors = 0
        
        # Track mapping from bogus alias name of DLL imported functions to
        # real names.
        self.dll_func_true_names = {}
        
        # Track a dict mapping the labels of code blocks labeled with the LABEL:
        # construct to code blocks. This will be used to evaluate GOTO statements
        # when emulating.
        self.tagged_blocks = {}

        # Track the in-memory loaded Excel workbook (xlrd workbook object).
        self.loaded_excel = loaded_excel
        
        # Track open files.
        self.open_files = {}
        self.file_id_map = {}

        # Track the final contents of written files.
        self.closed_files = {}

        # Track document metadata.
        self.metadata = metadata
        
        # Track whether variables by default should go in the global scope.
        self.global_scope = False

        # Track if this is the context of a function/sub.
        self.in_procedure = False

        # Track whether we have emulated a goto.
        self.goto_executed = False

        # Track variable types, if known.
        self.types = {}

        # Track the current with prefix for with statements. This has been evaluated
        self.with_prefix = ""
        # Track the current with prefix for with statements. This has not been evaluated
        self.with_prefix_raw = None
        
        # globals should be a pointer to the globals dict from the core VBA engine (ViperMonkey)
        # because each statement should be able to change global variables
        if _globals is not None:
            if (copy_globals):
                self.globals = copy.deepcopy(_globals)
            else:
                self.globals = _globals

            # Save intermediate IOCs if any appear.
            for var in _globals.keys():
                self.save_intermediate_iocs(_globals[var])
                
        elif context is not None:
            if (copy_globals):
                # deepcopy() can be slow.
                #self.globals = copy.deepcopy(context.globals)
                self.globals = dict(context.globals)
            else:
                self.globals = context.globals
            self.in_bitwise_expression = context.in_bitwise_expression
            self.last_saved_file = context.last_saved_file
            self.curr_func_name = context.curr_func_name
            self.do_jit = context.do_jit
            self.has_change_handler = context.has_change_handler
            self.throttle_logging = context.throttle_logging
            self.is_vbscript = context.is_vbscript
            self.doc_vars = context.doc_vars
            self.types = dict(context.types)
            self.open_files = context.open_files
            self.file_id_map = context.file_id_map
            self.closed_files = context.closed_files
            self.loaded_excel = context.loaded_excel
            self.dll_func_true_names = context.dll_func_true_names
            self.filename = context.filename
            self.skip_handlers = context.skip_handlers
            self.call_stack = context.call_stack
            self.expand_env_vars = context.expand_env_vars
            self.metadata = context.metadata
            self.external_funcs = context.external_funcs
            self.num_general_errors = context.num_general_errors
            self.with_prefix = context.with_prefix
            self.with_prefix_raw = context.with_prefix_raw
        else:
            self.globals = {}
        # on the other hand, each Context should have its own private copy of locals
        if _locals is not None:
            # However, if locals is explicitly provided, we use a copy of it:
            self.locals = dict(_locals)
        else:
            self.locals = {}
        # engine should be a pointer to the ViperMonkey engine, to provide callback features
        if engine is not None:
            self.engine = engine
        elif context is not None:
            self.engine = context.engine
        else:
            self.engine = None

        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Have xlrd loaded Excel file = " + str(self.loaded_excel is not None))
            
        # Track data saved in document variables.
        if doc_vars is not None:

            # direct copy of the pointer to globals:
            self.doc_vars = doc_vars

            # Save intermediate IOCs if any appear.
            for var in doc_vars.keys():
                self.save_intermediate_iocs(doc_vars[var])

        elif context is not None:
            self.doc_vars = context.doc_vars
        else:
            self.doc_vars = {}
            
        # Track whether nested loops are running with a stack of flags. If a loop is
        # running its flag will be True.
        self.loop_stack = []

        # Track the actual nested loops that are running on a stack. This is used to
        # handle GOTOs that jump out of the current loop body.
        self.loop_object_stack = []
        
        # Track whether we have exited from the current function.
        self.exit_func = False
        
        # Add in a global for the current time.
        self.globals["Now".lower()] = datetime.now()

        # Fake up a user name.
        rand_name = ''.join(random.choice(string.ascii_uppercase + string.digits + " ") for _ in range(random.randint(10, 50)))
        self.globals["Application.UserName".lower()] = rand_name

        # Fake a location for the template folder.
        self.globals["ActiveDocument.AttachedTemplate.Path".lower()] = "C:\\Users\\" + rand_name + "\\AppData\\Roaming\\Microsoft\\Templates"
        self.globals["ThisDocument.AttachedTemplate.Path".lower()] = "C:\\Users\\" + rand_name + "\\AppData\\Roaming\\Microsoft\\Templates"

        # Fake script name.
        if self.filename:
            self.globals["WSCRIPT.SCRIPTFULLNAME".lower()] = "C:\\" + self.filename
            self.globals["['WSCRIPT'].SCRIPTFULLNAME".lower()] = "C:\\" + self.filename
        
    def __repr__(self):
        r = ""
        r += "Locals:\n"
        r += str(self.locals) + "\n\n"
        #r += "Globals:\n"
        #r += str(self.globals) + "\n"
        return r
        
    def __eq__(self, other):
        if isinstance(other, Context):
            globals_eq = (self.globals == other.globals)
            if (not globals_eq):
                s1 = set()
                for i in self.globals.items():
                    s1.add(str(i))
                s2 = set()
                for i in other.globals.items():
                    s2.add(str(i))
                if (str(s1 ^ s2) == "set([])"):
                    globals_eq = True
            return ((self.call_stack == other.call_stack) and
                    globals_eq and
                    (self.locals == other.locals))
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result
        
    def read_metadata_item(self, var):

        # Make sure we read in the metadata.
        if (self.metadata is None):
            log.error("BuiltInDocumentProperties: Metadata not read.")
            return ""
    
        # Normalize the variable name.
        var = var.lower().replace(" ", "_")
        if ("." in var):
            var = var[:var.index(".")]
    
        # See if we can find the metadata attribute.
        if (not hasattr(self.metadata, var)):
            log.error("BuiltInDocumentProperties: Metadata field '" + var + "' not found.")
            return ""

        # We have the attribute. Return it.
        r = getattr(self.metadata, var)

        # Handle MS encoding of "\r" and "\n".
        r = r.replace("_x000d_.", "\r\n")
        r = r.replace("_x000d_", "\r")
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("BuiltInDocumentProperties: return %r -> %r" % (var, r))

        # Done.
        return r
            
    def get_error_handler(self):
        """
        Get the onerror goto error handler.
        """
        if (hasattr(self, "error_handler")):
            return self.error_handler
        return None

    def do_next_iter_on_error(self):
        """
        See if the error handler just calls Next to advance to next loop iteration.
        """

        # Do we have an error handler?
        handler = self.get_error_handler()
        if (handler is None):
            return False

        # See if the 1st statement in the handler is Next.
        if (len(handler.block) == 0):

            # If it looks like no commands, let's just go to the next loop iteration.
            return True
        first_cmd = str(handler.block[0]).strip()
        return (first_cmd == "Next")
    
    def have_error(self):
        """
        See if Visual Basic threw an error.
        """
        return (hasattr(self, "got_error") and
                self.got_error)

    def clear_error(self):
        """
        Clear out the error flag.
        """
        self.got_error = False
        
    def must_handle_error(self):
        """
        Check to see if there was are error raised during emulation and we have
        an error handler.
        """
        return (self.have_error() and
                hasattr(self, "error_handler") and
                (self.error_handler is not None))

    def handle_error(self, params):
        """
        Run the current error handler (if there is one) if there is an error.
        """

        # Run the error handler if needed.
        if (self.must_handle_error()):
            log.warning("Running On Error error handler...")
            self.got_error = False
            self.error_handler.eval(context=self, params=params)

            # The error has now been cleared. Note that if there is no
            # error handler and there is an error it will remain.
            self.got_error = False

    def set_error(self, reason):
        """
        Set that a VBA error has occurred.
        """

        self.got_error = True
        self.increase_general_errors()
        log.error("A VB error has occurred. Reason: " + str(reason))

    def report_general_error(self, reason):
        """
        Report and track general ViperMonkey errors. Note that these may not just be
        VBA errors.
        """
        self.num_general_errors += 1
        log.error(reason)

    def clear_general_errors(self):
        """
        Clear the count of general errors.
        """
        self.num_general_errors = 0

    def get_general_errors(self):
        """
        Get the number of reported general errors.
        """
        return self.num_general_errors

    def increase_general_errors(self):
        """
        Add one to the number of reported general errors.
        """
        self.num_general_errors += 1
        
    def get_true_name(self, name):
        """
        Get the true name of an aliased function imported from a DLL.
        """
        if (name in self.dll_func_true_names):
            return self.dll_func_true_names[name]
        return None

    def delete(self, name):
        """
        Delete a variable from the context.
        """

        # Punt if we don't have the variable.
        if (not self.contains(name)):
            return self

        # Delete the variable
        if name in self.locals:
            del self.locals[name]
        elif name in self.globals:
            del self.globals[name]

        return self

    def get_interesting_fileid(self):
        """
        Pick an 'interesting' looking open file and return its ID.
        """

        # Look for the longest file name and any files name on the C: drive.
        # Also look for the last saved file.
        longest = ""
        cdrive = None
        for file_id in self.open_files.keys():
            if ((self.last_saved_file is not None) and (str(file_id).lower() == self.last_saved_file.lower())):
                cdrive = file_id
                break
            if (str(file_id).lower().startswith("c:")):
                cdrive = file_id
            if (len(str(file_id)) > len(longest)):
                longest = file_id

        # Favor files on the C: drive.
        if (cdrive is not None):
            return cdrive

        # Fall back to longest.
        if (len(longest) > 0):
            return longest

        # Punt.
        return None

    def file_is_open(self, fname):
        """
        Check to see if a file is already open.
        """
        fname = str(fname)
        fname = fname.replace(".\\", "").replace("\\", "/")

        # Don't reopen already opened files.
        return (fname in self.open_files.keys())
        
    def open_file(self, fname, file_id=""):
        """
        Simulate opening a file.

        fname - The name of the file.
        file_id - The numeric ID of the file.
        """
        # Save that the file is opened.
        fname = str(fname)
        fname = fname.replace(".\\", "").replace("\\", "/")

        # Don't reopen already opened files.
        if (fname in self.open_files.keys()):
            log.warning("File " + str(fname) + " is already open.")
            return

        # Open the simulated file.
        self.open_files[fname] = b''
        if (file_id != ""):
            self.file_id_map[file_id] = fname
        log.info("Opened file " + fname)
        
    def write_file(self, fname, data):

        # Make sure the "file" exists.
        fname = str(fname)
        fname = fname.replace(".\\", "").replace("\\", "/")
        if fname not in self.open_files:

            # Are we referencing this by numeric ID.
            if (fname in self.file_id_map.keys()):
                fname = self.file_id_map[fname]
            else:

                # Is this a variable?
                got_it = False
                if fname.startswith("#"):
                    var_name = fname[1:]
                    if self.contains(var_name):
                        fname = "#" + str(self.get(var_name))
                        if (fname in self.file_id_map.keys()):
                            got_it = True
                            fname = self.file_id_map[fname]
                
                # Punt if we cannot find the open file.
                if (not got_it):
                    log.error('File {} not open. Cannot write new data.'.format(fname))
                    return False
            
        # Are we writing a string?
        if isinstance(data, str):

            # Hex string?
            if ((len(data.strip()) == 4) and (re.match('&H[0-9A-F]{2}', data, re.IGNORECASE))):
                data = chr(int(data.strip()[-2:], 16))

            self.open_files[fname] += data
            return True

        # Are we writing a list?
        elif isinstance(data, list):
            for d in data:
                if (isinstance(d, int)):
                    self.open_files[fname] += chr(d)
                else:
                    self.open_files[fname] += str(d)
            return True

        # Are we writing a byte?
        elif isinstance(data, int):

            # Convert the int to a series of bytes to write out.
            byte_list = struct.pack('<q', data)
            
            # Skip 0 bytes at the end of the sequence.
            #
            # TODO: To do this correctly we need to know the VBA
            # type of this integer (Byte, Integer, or Long) and drop bytes accordingly.
            byte_size = utils.get_num_bytes(data)
            #byte_size = 4
            #print "---"
            #print data
            #print byte_size
            #print byte_list.__repr__()
            byte_list = byte_list[:byte_size]
            #print byte_list.__repr__()
            
            # Write out each byte.
            for b in byte_list:
                self.open_files[fname] += b
            return True
        
        # Unhandled.
        else:
            log.error("Unhandled data type to write. " + str(type(data)) + ".")
            return False
        
    def dump_all_files(self, autoclose=False):
        for fname in self.open_files.keys():
            self.dump_file(fname, autoclose=autoclose)

    def get_num_open_files(self):
        """
        Get the # of currently open files being tracked.
        """
        return len(self.open_files)
            
    def close_file(self, fname):
        """
        Simulate closing a file.

        fname - The name of the file.

        Returns boolean indicating success.
        """
        global file_count
        
        # Make sure the "file" exists.
        fname = str(fname).replace(".\\", "").replace("\\", "/")
        file_id = None
        if fname not in self.open_files:

            # Are we referencing this by numeric ID.
            if (fname in self.file_id_map.keys()):
                file_id = fname
                fname = self.file_id_map[fname]
            else:
                log.error('File {} not open. Cannot close.'.format(fname))
                return

        log.info("Closing file " + fname)

        # Get the data written to the file and track it.
        data = self.open_files[fname]
        self.closed_files[fname] = data

        # Clear the file out of the open files.
        del self.open_files[fname]
        if (file_id is not None):
            del self.file_id_map[file_id]

        if out_dir:
            self.dump_file(fname)

    # FIXME: This function is too closely coupled to the CLI.
    #   Context should not contain business logic.
    def dump_file(self, fname, autoclose=False):
        """
        Save the contents of a file dumped by the VBA to disk.

        fname - The name of the file.
        """
        if fname not in self.closed_files:
            if (not autoclose):
                log.error('File {} not closed. Cannot save.'.format(fname))
                return
            else:
                log.warning('File {} not closed. Closing file.'.format(fname))
                self.close_file(fname)
                
        # Hash the data to be saved.
        raw_data = self.closed_files[fname]
        file_hash = sha256(raw_data).hexdigest()

        # TODO: Set a flag to control whether to dump file contents.

        # Make the dropped file directory if needed.
        if not os.path.isdir(out_dir):
            os.makedirs(out_dir)

        # Dump the file.
        try:
            # Get a unique name for the file.
            fname = re.sub(r"[^ -~\r\n]", "__", fname)
            if ("/" in fname):
                fname = fname[fname.rindex("/") + 1:]
            if ("\\" in fname):
                fname = fname[fname.rindex("\\") + 1:]
            fname = fname.replace("\x00", "").replace("..", "")
            if (fname.startswith(".")):
                fname = "_dot_" + fname[1:]

            # Handle really huge file names.
            if (len(fname) > 50):
                fname = "REALLY_LONG_NAME_" + str(file_hash) + ".dat"
                log.warning("Filename of dropped file is too long, replacing with " + fname)

            # Make the name truely unique.
            fname = fname.strip()
            self.report_action("Dropped File Hash", file_hash, 'File Name: ' + fname)
            file_path = os.path.join(out_dir, os.path.basename(fname))
            orig_file_path = file_path
            count = 0
            while os.path.exists(file_path):
                count += 1
                file_path = '{} ({})'.format(orig_file_path, count)

            # Write out the dropped file.
            with open(file_path, 'wb') as f:
                f.write(raw_data)
            log.info("Wrote dumped file (hash {}) to {}.".format(file_hash, file_path))
        except Exception as e:
            log.error("Writing file {} failed with error: {}".format(fname, e))

    def get_lib_func(self, name):

        if (not isinstance(name, basestring)):
            raise KeyError('Object %r not found' % name)
        
        # Search in the global VBA library:
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Looking for library function '" + name + "'...")
        name = name.lower()
        if name in VBA_LIBRARY:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Found %r in VBA Library' % name)
            return VBA_LIBRARY[name]

        # Unknown symbol.
        else:            
            raise KeyError('Library function %r not found' % name)

    def __get(self, name, case_insensitive=True, local_only=False, global_only=False):

        if (not isinstance(name, basestring)):
            raise KeyError('Object %r not found' % name)

        # Flag if this is a change handler lookup.
        is_change_handler = (str(name).strip().lower().endswith("_change"))
        change_name = str(name).strip().lower()
        if is_change_handler: change_name = change_name[:-len("_change")]
        
        # convert to lowercase if needed.
        orig_name = name
        if (case_insensitive):
            name = name.lower()
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Looking for var '" + name + "'...")

        # We will always say that a directory is not accessible.
        if (name.strip().endswith(".subfolders.count")):
            return -1
        
        # First, search in locals. This handles variables whose name overrides
        # a system function.
        if ((not global_only) and (name in self.locals)):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Found %r in locals' % name)
            if is_change_handler: self.has_change_handler[change_name] = True
            self.name_cache[orig_name] = name
            return self.locals[name]

        # second, in globals:
        elif ((not local_only) and (name in self.globals)):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Found %r in globals' % name)
            if is_change_handler: self.has_change_handler[change_name] = True
            self.name_cache[orig_name] = name
            return self.globals[name]

        # next, search in the global VBA library:
        elif ((not local_only) and (name in VBA_LIBRARY)):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Found %r in VBA Library' % name)
            if is_change_handler: self.has_change_handler[change_name] = True
            self.name_cache[orig_name] = name
            return VBA_LIBRARY[name]

        # Is it a doc var?
        elif ((not local_only) and (name in self.doc_vars)):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Found %r in VBA document variables' % name)
            if is_change_handler: self.has_change_handler[change_name] = True
            self.name_cache[orig_name] = name
            return self.doc_vars[name]

        # VBA constant?
        elif vba_constants.is_constant(name):
            return vba_constants.get_constant(name)
        
        # Unknown symbol.
        else:
            # Not found.
            if is_change_handler: self.has_change_handler[change_name] = False
            raise KeyError('Object %r not found' % name)
            # NOTE: if name is unknown, just raise Python dict's exception
            # TODO: raise a custom VBA exception?

    def _get(self, name, search_wildcard=True, case_insensitive=True, local_only=False, global_only=False):
        
        # See if this is an aliased reference to an objects .Text field.
        name = str(name)
        if (((name.lower() == "nodetypedvalue") or (name.lower() == ".nodetypedvalue")) and
            (not name in self.locals) and
            (".Text".lower() in self.locals)):
            return self.get(".Text")

        # Try to avoid attempting a bunch of variations on the variable name
        # if we already know one that worked earlier.
        if (name in self.name_cache):
            cached_name = self.name_cache[name]
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Cached name of '" + str(name) + "' is '" + str(cached_name) + "'")
            try:
                return self.__get(cached_name,
                                  case_insensitive=case_insensitive,
                                  local_only=local_only,
                                  global_only=global_only)
            except KeyError:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Cached lookup failed.")

        # Use the evaluated With prefix value only when it makes sense.
        with_prefix = self.with_prefix
        if ((self.with_prefix_raw is not None) and
            (str(self.with_prefix_raw).startswith("ActiveDocument"))):
            with_prefix = self.with_prefix_raw
                    
        # Try to get the item using the current with context.
        if (name.startswith(".")):
            
            # Add in the current With context.
            tmp_name = str(with_prefix) + str(name)
            try:
                return self.__get(tmp_name,
                                  case_insensitive=case_insensitive,
                                  local_only=local_only,
                                  global_only=global_only)
            except KeyError:

                # Try with the evaluated with context.
                tmp_name = str(self.with_prefix) + str(name)
                try:
                    return self.__get(tmp_name,
                                      case_insensitive=case_insensitive,
                                      local_only=local_only,
                                      global_only=global_only)
                except KeyError:
                    pass

        # Now try it without the current with context.
        try:
            return self.__get(str(name),
                              case_insensitive=case_insensitive,
                              local_only=local_only,
                              global_only=global_only)
        except KeyError:
            pass

        # Try to get the item using the current with context, again.
        tmp_name = str(with_prefix) + "." + str(name)
        try:
            return self.__get(tmp_name,
                              case_insensitive=case_insensitive,
                              local_only=local_only,
                              global_only=global_only)
        except KeyError:

            # If we are looking for a shapes title we may already have
            # it.
            if (isinstance(self.with_prefix, str) and
                (self.with_prefix_raw is not None) and
                ("Shapes" in str(self.with_prefix_raw)) and
                (str(name) == "Title")):
                return self.with_prefix
        
        # Are we referencing a field in an object?
        if ("." in name):

            # Look for faked object field.
            new_name = "me." + name[name.index(".")+1:]
            try:
                return self.__get(str(new_name),
                                  case_insensitive=case_insensitive,
                                  local_only=local_only,
                                  global_only=global_only)
            except KeyError:
                pass

            # Look for wild carded field value.
            if (search_wildcard):
                new_name = name[:name.index(".")] + ".*"
                try:
                    r = self.__get(str(new_name),
                                   case_insensitive=case_insensitive,
                                   local_only=local_only,
                                   global_only=global_only)
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Found wildcarded field value " + new_name + " = " + str(r))
                    return r
                except KeyError:
                    pass
            
        # See if the variable was initially defined with a trailing '$'.
        return self.__get(str(name) + "$",
                          case_insensitive=case_insensitive,
                          local_only=local_only,
                          global_only=global_only)

    def _get_all_metadata(self, name):
        """
        Return all items in something like ActiveDocument.BuiltInDocumentProperties.
        """

        # Reading all properties?
        if ((name != "ActiveDocument.BuiltInDocumentProperties") and
            (name != "ThisDocument.BuiltInDocumentProperties")):
            return None

        # Get the names of the metadata items.
        meta_names = [a for a in dir(self.metadata) if not a.startswith('__') and not callable(getattr(self.metadata, a))]

        # Add the names and values of the metadata items to the context.
        for meta_name in meta_names:
            self.set(meta_name + ".Name", meta_name, force_global=True)
            self.set(meta_name + ".Value", getattr(self.metadata, meta_name), force_global=True)
            self.save_intermediate_iocs(getattr(self.metadata, meta_name))

        # Chuck the comments in there for good measure.
        meta_names.append("Comments")
        comments = ""
        first = True
        for comment in self.get("ActiveDocument.Comments"):
            if (not first):
                comments += "\n"
            first = False
            comments += comment
        self.set("Comments.Name", "Comments", force_global=True)
        self.set("Comments.Value", comments, force_global=True)
        self.save_intermediate_iocs(comments)
        
        # Return the metadata items as a list of their names. Accesses of their .Name and
        # .Value fields will hit the synthetic variables that were just added to the
        # context.
        return meta_names
    
    def get(self, name, search_wildcard=True, local_only=False, global_only=False):

        # Sanity check.
        if ((name is None) or
            (isinstance(name, str) and (len(name.strip()) == 0))):
            raise KeyError('Object %r not found' % name)
        
        # Short circuit looking for variable change handlers if possible.
        if (str(name).strip().lower().endswith("_change")):

            # Get the original variable name.
            orig_name = str(name).strip().lower()[:-len("_change")]
            if ((orig_name in self.has_change_handler) and (not self.has_change_handler[orig_name])):
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Short circuited change handler lookup of " + name)
                raise KeyError('Object %r not found' % name)

        # Reading all of the document metadata items?
        r = self._get_all_metadata(name)
        if (r is not None):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Read all metadata items.")
            return r
            
        # First try a case sensitive search. If that fails try case insensitive.
        r = None
        try:
            r = self._get(name,
                          search_wildcard=search_wildcard,
                          case_insensitive=False,
                          local_only=local_only,
                          global_only=global_only)
        except KeyError:
            r = self._get(name,
                          search_wildcard=search_wildcard,
                          case_insensitive=True,
                          local_only=local_only,
                          global_only=global_only)

        # Did we get something useful?
        if ((r is None) or (r == "NULL")):

            # See if we have a more useful version of this variable stored as an object
            # field.
            tmp_name = "." + str(name)
            if (self.contains(tmp_name)):
                r = self._get(tmp_name)
            
        # Done.
        return r
            
    def contains(self, name, local=False):
        if (local):
            return (str(name).lower() in self.locals)
        try:
            self.get(name)
            return True
        except KeyError:
            return False

    def contains_user_defined(self, name):
        return ((name in self.locals) or (name in self.globals))

    def set_type(self, var, typ):
        var = var.lower()
        self.types[var] = typ
        
    def get_type(self, var):
        if (not isinstance(var, basestring)):
            return None
        var = var.lower()
        if (var not in self.types):
            return vba_constants.get_type(var)
        return self.types[var]

    def get_doc_var(self, var, search_wildcard=True):
        if (not isinstance(var, basestring)):
            return None

        # Normalize the variable name to lower case.
        var = var.lower()
        # strip VBA nonsense
        var = var.replace('!','').\
                    replace('^','').\
                    replace('%','').\
                    replace('&','').\
                    replace('@','').\
                    replace('#','').\
                    replace('$','')
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Looking up doc var " + var)

        # Are we pulling out all the doc vars?
        if (var == "activedocument.variables"):

            # Return these as (name, value) tuples.
            r = []
            for var_name in self.doc_vars.keys():
                r.append((var_name, self.doc_vars[var_name]))                
            return r
        
        if (var not in self.doc_vars):

            # Can't find a doc var with this name. See if we have an internal variable
            # with this name.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("doc var named " + var + " not found.")
            try:
                var_value = self.get(var, search_wildcard=search_wildcard)
                if ((var_value is not None) and
                    (str(var_value).lower() != str(var).lower())):
                    r = self.get_doc_var(var_value)
                    if (r is not None):
                        return r
                    return var_value
            except KeyError:
                pass

            # Can't find it. Do we have a wild card doc var to guess for
            # this value? Only do this if it looks like we have a valid doc var name.
            if ((re.match(r"^[a-zA-Z_][\w\d]*$", str(var)) is not None) and
                ("*" in self.doc_vars)):
                return self.doc_vars["*"]

            # See if this is in the ActiveDocument.
            if ("." in var):

                # Get the new name looking for the var in ActiveDocument.
                var = "activedocument." + var[var.index(".") + 1:]
                if (var in self.doc_vars):

                    # Found it.
                    r = self.doc_vars[var]
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Found doc var " + var + " = " + str(r))
                    return r
                
            # No variable. Return nothing.
            return None

        # Found it.
        r = self.doc_vars[var]
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Found doc var " + var + " = " + str(r))
        return r

    def save_intermediate_iocs(self, value):
        """
        Save variable values that appear to contain base64 encoded or URL IOCs.
        """

        global num_b64_iocs
        
        # Strip NULLs and unprintable characters from the potential IOC.
        from vba_object import strip_nonvb_chars
        value = strip_nonvb_chars(value)
        if (len(re.findall(r"NULL", str(value))) > 20):
            value = str(value).replace("NULL", "")
        
        # Is there a URL in the data?
        got_ioc = False
        URL_REGEX = r'.*([hH][tT][tT][pP][sS]?://(([a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-\.]+(:[0-9]+)?)+(/([/\?&\~=a-zA-Z0-9_\-\.](?!http))+)?)).*'
        try:
            value = str(value).strip()
        except:
            return
        tmp_value = value
        if (len(tmp_value) > 100):
            tmp_value = tmp_value[:100] + " ..."
        if (re.match(URL_REGEX, value) is not None):
            if (value not in intermediate_iocs):
                got_ioc = True
                log.info("Found possible intermediate IOC (URL): '" + tmp_value + "'")

        # Is there base64 in the data? Don't track too many base64 IOCs.
        if (num_b64_iocs < 200):
            B64_REGEX = r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
            b64_strs = re.findall(B64_REGEX, value)
            for curr_value in b64_strs:
                if ((value not in intermediate_iocs) and (len(curr_value) > 200)):
                    got_ioc = True
                    num_b64_iocs += 1
                    log.info("Found possible intermediate IOC (base64): '" + tmp_value + "'")

        # Did we find anything?
        if (not got_ioc):
            return

        # Is this new and interesting?
        iocs_to_delete = set()
        got_ioc = True
        for old_value in intermediate_iocs:
            if (value.startswith(old_value)):
                iocs_to_delete.add(old_value)
            if ((old_value.startswith(value)) and (len(old_value) > len(value))):
                got_ioc = False

        # Add the new IOC if it is interesting.
        if (got_ioc):
            intermediate_iocs.add(value)
            
        # Delete old IOCs if needed.
        for old_ioc in iocs_to_delete:
            intermediate_iocs.remove(old_ioc)

    def _set_excel_formula(self, name, value):
        """
        Handle setting an Excel cell to a formula.

        Sheets('dd').Cells('d, dd').FormulaLocal = ...
        """

        # Sanity check.
        if ((name is None) or
            (value is None) or
            (value == "__ALREADY_SET__")):
            return False
        
        # Are we setting a cell formula?
        import expressions
        import vba_object
        if (not isinstance(name, expressions.MemberAccessExpression)):
            return False
        tmp_rhs = str(name.rhs)
        if (isinstance(name.rhs, list)):
            tmp_rhs = str(name.rhs[-1])
        if ((tmp_rhs.lower() != "formulalocal") and
            (tmp_rhs.lower() != "value") and
            (tmp_rhs.lower() != "name")):
            return False
        typ = tmp_rhs
        if (typ.lower() == "formulalocal"):
            typ = "Formula"
        
        # Looks like we are setting a formula, name, or value. See if we can resolve the
        # row and column of the cell.
        row = "??"
        col = "??"

        # Do we have a Cells() operation?
        if (isinstance(name.rhs, list) and
            (isinstance(name.rhs[0], expressions.Function_Call)) and
            (str(name.rhs[0]).startswith("Cells("))):

            # Resolve the row and column.
            cell_call = name.rhs[0]
            row = str(vba_object.eval_arg(cell_call.params[0], self))
            col = str(vba_object.eval_arg(cell_call.params[1], self))

        # Try resolving the sheet.
        sheet = "??"
        if (isinstance(name.lhs, expressions.Function_Call) and
            (str(name.lhs).startswith("Sheets("))):

            # Resolve the sheet.
            sheet_call = name.lhs
            sheet = str(vba_object.eval_arg(sheet_call.params[0], self))
        
        # Report setting the formula, name, or value as an action.
        r = "Sheet(" + sheet + ").Cell(" + row + ", " + col + ") = '" + str(value) + "'"
        self.report_action('Set Cell ' + typ, r, tmp_rhs, strip_null_bytes=True)
        return True

    def _handle_property_assignment(self, name, value):
        """
        If this is a property asignment, call the property handler.
        """

        import procedures
        
        # Do we know the value of the variable?
        if (not self.contains(name)):
            return False

        # Is the current value a property let handler?
        handler = self.get(name)
        if (not isinstance(handler, procedures.PropertyLet)):
            return False

        # We are assigning to a property. Evaluate the handler.
        handler.eval(self, params=[value])

        # Handled property assignment.
        return True
    
    def set(self,
            name,
            value,
            var_type=None,
            do_with_prefix=True,
            force_local=False,
            force_global=False,
            no_conversion=False,
            case_insensitive=True,
            no_overwrite=False):

        # Special case. Are we setting a formula in an Excel cell?
        if (self._set_excel_formula(name, value)):
            return

        # Are we assigning a Property? If so we will call the property handler?
        if (self._handle_property_assignment(name, value)):
            return

        # We might have a vipermonkey simple name expression. Convert to a string
        # so we can use it.
        import expressions
        if (isinstance(name, expressions.SimpleNameExpression)):
            name = str(name)
        
        # Does the name make sense?
        orig_name = name
        if (not isinstance(name, basestring)):
            log.warning("context.set() " + str(name) + " is improper type. " + str(type(name)))
            name = str(name)

        # Does the value make sense?
        if (value is None):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("context.set() " + str(name) + " failed. Value is None.")
            return

        # More name fixing.
        if (".." in name):
            self.set(name.replace("..", "."), value, var_type, do_with_prefix, force_local, force_global, no_conversion=no_conversion)

        # Skip this if this variable is already set and we are not allowing value overwrites.
        if (no_overwrite and self.contains(name)):
            return
            
        # Save IOCs from intermediate values if needed.
        self.save_intermediate_iocs(value)
        
        # convert to lowercase
        if (case_insensitive):
            tmp_name = name.lower()
            self.set(tmp_name, value, var_type, do_with_prefix, force_local, force_global, no_conversion=no_conversion, case_insensitive=False)

        # Handling of special case where an array access is being stored as a variable.
        name_str = str(name)
        if (("(" in name_str) and (")" in name_str)):

            # See if this is actually referring to a global variable.
            name_str = name_str[:name_str.index("(")].strip()
            if (name_str in self.globals.keys()):
                force_global = True

        # This should be a global variable if we are not in a function.
        if ((not self.in_procedure) and (not force_global) and (not force_local)):
            self.set(name, value, force_global=True, do_with_prefix=do_with_prefix)
            return
                
        # Set the variable

        # Forced save in global context?
        if (force_global):
            try:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Set global var " + str(name) + " = " + str(value))
            except:
                pass
            self.globals[name] = value

        # Forced save in local context?
        elif ((name in self.locals) or force_local):
            try:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Set local var " + str(name) + " = " + str(value))
            except:
                pass
            self.locals[name] = value

        # Check globals, but avoid to overwrite subs and functions:
        elif name in self.globals and not is_procedure(self.globals[name]):
            self.globals[name] = value
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Set global var " + name + " = " + str(value))
            if ("." in name):
                text_name = name + ".text"
                self.globals[text_name] = value
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Set global var " + text_name + " = " + str(value))

        # New name, typically store in local scope.
        else:
            if (not self.global_scope):
                try:
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Set local var " + str(name) + " = " + str(value))
                except:
                    pass
                self.locals[name] = value
            else:
                self.globals[name] = value
                try:
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Set global var " + name + " = " + str(value))
                except:
                    pass
                if ("." in name):
                    text_name = name + ".text"
                    self.globals[text_name] = value
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Set global var " + text_name + " = " + str(value))
                    text_name = name[name.rindex("."):]
                    self.globals[text_name] = value
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("Set global var " + text_name + " = " + str(value))
                
        # If we know the type of the variable, save it.
        if (var_type is not None):
            self.types[name] = var_type

        # Also set the variable using the current With name prefix, if
        # we have one.
        if ((do_with_prefix) and (len(self.with_prefix) > 0)):
            tmp_name = str(self.with_prefix) + "." + str(name)
            self.set(tmp_name, value, var_type=var_type, do_with_prefix=False, no_conversion=no_conversion)

        # Skip automatic data conversion if needed.
        if (no_conversion):
            return
            
        # Handle base64 conversion with VBA objects.
        if (name.endswith(".text")):

            # Is this a base64 object?
            do_b64 = False
            node_type = name.replace(".text", ".datatype")
            try:

                # Is the root object something set to the "bin.base64" data type?
                val = str(self.get(node_type)).strip()
                if (val.lower() == "bin.base64"):
                    do_b64 = True

            except KeyError:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Did not find type var " + node_type)

            # Is this a general XML object?
            try:

                # Is this a Microsoft.XMLDOM object?
                import expressions
                import vba_object
                node_type = orig_name
                if (isinstance(orig_name, expressions.MemberAccessExpression)):
                    node_type = orig_name.lhs
                else:
                    node_type = str(node_type).lower().replace(".text", "")
                val = vba_object.eval_arg(node_type, self)
                if (val == "Microsoft.XMLDOM"):
                    do_b64 = True

            except KeyError:
                pass
            
            # Handle doing conversions on the data.
            if (do_b64):

                # Try converting the text from base64.
                conv_val = utils.b64_decode(value)
                if (conv_val is not None):
                    val_name = name
                    self.set(val_name, conv_val, no_conversion=True, do_with_prefix=do_with_prefix)
                    val_name = name.replace(".text", ".nodetypedvalue")
                    self.set(val_name, conv_val, no_conversion=True, do_with_prefix=do_with_prefix)

        # Handle hex conversion with VBA objects.
        if (name.lower().endswith(".nodetypedvalue")):

            # Handle doing conversions on the data.
            node_type = name[:name.rindex(".")] + ".datatype"
            try:

                # Something set to type "bin.hex"?
                val = str(self.get(node_type)).strip()
                if (val.lower() == "bin.hex"):

                    # Try converting from hex.
                    try:

                        # Set the typed value of the node to the decoded value.
                        conv_val = codecs.decode(str(value).strip(), "hex")
                        self.set(name, conv_val, no_conversion=True, do_with_prefix=do_with_prefix)
                    except Exception as e:
                        log.warning("hex conversion of '" + str(value) + "' FROM hex failed. Converting TO hex. " + str(e))
                        conv_val = to_hex(str(value).strip())
                        self.set(name, conv_val, no_conversion=True, do_with_prefix=do_with_prefix)
                        
            except KeyError:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Did not find type var " + node_type)

        # Handle after the fact data conversion with VBA objects.
        if (name.endswith(".datatype")):

            # Handle doing conversions on the existing data.
            node_value_name = name.replace(".datatype", ".nodetypedvalue")
            try:

                # Do we have data to convert from type "bin.hex"?
                node_value = self.get(node_value_name)
                if (value.lower() == "bin.hex"):

                    # Try converting from hex.
                    try:

                        # Set the typed value of the node to the decoded value.
                        conv_val = codecs.decode(str(node_value).strip(), "hex")
                        self.set(node_value_name, conv_val, no_conversion=True, do_with_prefix=do_with_prefix)
                    except Exception as e:
                        log.warning("hex conversion of '" + str(node_value) + "' FROM hex failed. Converting TO hex. " + str(e))
                        conv_val = to_hex(str(node_value).strip())
                        self.set(node_value_name, conv_val, no_conversion=True, do_with_prefix=do_with_prefix)

                # Do we have data to convert from type "bin.base64"?
                if (value.lower() == "bin.base64"):

                    
                    # Try converting the text from base64.
                    conv_val = utils.b64_decode(node_value)
                    if (conv_val is not None):
                        self.set(node_value_name, conv_val, no_conversion=True, do_with_prefix=do_with_prefix)
                        
            except KeyError:
                pass
            
    def _strip_null_bytes(self, item):
        r = item
        if (isinstance(item, str)):
            r = item.replace("\x00", "")
        if (isinstance(item, list)):
            r = []
            for s in item:
                if (isinstance(s, str)):
                    r.append(s.replace("\x00", ""))
                else:
                    r.append(s)
        return r
                    
    def report_action(self, action, params=None, description=None, strip_null_bytes=False):

        # Strip out bad characters if needed.
        if (strip_null_bytes):

            # Strip bad characters.
            from vba_object import strip_nonvb_chars

            action = strip_nonvb_chars(action)
            new_params = strip_nonvb_chars(params)
            if (isinstance(params, list)):
                new_params = []
                for p in params:
                    tmp_p = strip_nonvb_chars(p)
                    if (len(re.findall(r"NULL", str(tmp_p))) > 20):
                        tmp_p = str(tmp_p).replace("NULL", "")
                    new_params.append(tmp_p)
            params = new_params
            description = strip_nonvb_chars(description)

            # Strip repeated NULLs in the action.
            if (len(re.findall(r"NULL", action)) > 20):
                action = action.replace("NULL", "")
            
        # Save the action for reporting.
        self.got_actions = True
        self.engine.report_action(action, params, description)

