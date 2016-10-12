#!/usr/bin/env python
"""
ViperMonkey - command line interface

ViperMonkey is a specialized engine to parse, analyze and interpret Microsoft
VBA macros (Visual Basic for Applications), mainly for malware analysis.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

Project Repository:
https://github.com/decalage2/ViperMonkey
"""

#=== LICENSE ==================================================================

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


#------------------------------------------------------------------------------
# CHANGELOG:
# 2015-02-12 v0.01 PL: - first prototype
# 2015-2016        PL: - many changes
# 2016-10-06 v0.03 PL: - fixed vipermonkey.core import

__version__ = '0.03'

#------------------------------------------------------------------------------
# TODO:
# TODO: detect subs/functions with same name (in different modules)
# TODO: can several projects call each other?
# TODO: Word XML with several projects?
# - cleanup main, use optionparser
# - option -e to extract and evaluate constant expressions
# - option -t to trace execution
# - option --entrypoint to specify the Sub name to use as entry point
# - use olevba to get all modules from a file
# Environ => VBA object
# vbCRLF, etc => Const (parse to string)
# py2vba: convert python string to VBA string, e.g. \" => "" (for olevba to scan expressions) - same thing for ints, etc?
#TODO: expr_int / expr_str
#TODO: eval(parent) => for statements to set local variables into parent functions/procedures + main VBA module
#TODO: __repr__ for printing
#TODO: Environ('str') => '%str%'
#TODO: determine the order of Auto subs for Word, Excel

# TODO later:
# - add VBS support (two modes?)

#------------------------------------------------------------------------------
# REFERENCES:
# - [MS-VBAL]: VBA Language Specification
#   https://msdn.microsoft.com/en-us/library/dd361851.aspx
# - [MS-OVBA]: Microsoft Office VBA File Format Structure
#   http://msdn.microsoft.com/en-us/library/office/cc313094%28v=office.12%29.aspx


#--- IMPORTS ------------------------------------------------------------------

import optparse
import sys
import pprint
import traceback
import logging
import colorlog

from oletools.thirdparty.prettytable import prettytable
from oletools.thirdparty.xglob import xglob
from oletools.olevba import VBA_Parser, filter_vba

try:
    from vipermonkey.core import *
except:
    from core import *

log = logging.getLogger("vipermonkey.vmonkey")

# === MAIN (for tests) ===============================================================================================

def process_file (container, filename, data):
    """
    Process a single file

    :param container: str, path and filename of container if the file is within
    a zip archive, None otherwise.
    :param filename: str, path and filename of file on disk, or within the container.
    :param data: bytes, content of the file if it is in a container, None if it is a file on disk.
    """
    results = {}
    if container:
        display_filename = '%s in %s' % (filename, container)
    else:
        display_filename = filename
    results['display_filename'] = display_filename
    vm = ViperMonkey()
    try:
        #TODO: handle olefile errors, when an OLE file is malformed
        vba = VBA_Parser(filename, data)
        results['vba_type'] = vba.type
        #: results from macro extraction
        results['macros'] = []
        if vba.detect_vba_macros():
            for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
                macro_res = {}
                results['macros'].append(macro_res)
                # hide attribute lines:
                #TODO: option to disable attribute filtering
                vba_code_filtered = filter_vba(vba_code)
                macro_res['vba_filename'] = vba_filename
                macro_res['subfilename'] = subfilename
                macro_res['stream_path'] = repr(stream_path)
                # detect empty macros:
                if vba_code_filtered.strip() == '':
                    macro_res['vba_code'] = None
                else:
                    # TODO: option to display code
                    vba_code = vba_collapse_long_lines(vba_code)
                    macro_res['vba_code'] = vba_code
                    try:
                        vm.add_module(vba_code)
                    except ParseException as err:
                        # XXX never happens: exception has already been caught
                        # in vm.add_module
                        log.error(
                            "Error while parsing VBA macro %s in file: %s - "
                            "OLE stream: %s", vba_filename, subfilename,
                            repr(stream_path))
                        log.error("%s\n", err.line)
                        log.error(" %s ^\n", " " * (err.column-1))
                        log.error("%s\n", err)


            vm.trace()
            results['actions'] = vm.dump_actions()

    except: #TypeError:
        #raise
        #TODO: print more info if debug mode
        #print sys.exc_value
        # display the exception with full stack trace for debugging, but do not stop:
        traceback.print_exc()
    return results


def process_file_scanexpr (container, filename, data):
    """
    Process a single file

    :param container: str, path and filename of container if the file is within
    a zip archive, None otherwise.
    :param filename: str, path and filename of file on disk, or within the container.
    :param data: bytes, content of the file if it is in a container, None if it is a file on disk.
    """
    results = {}
    if container:
        display_filename = '%s in %s' % (filename, container)
    else:
        display_filename = filename
    results['display_filename'] = display_filename
    all_code = ''
    try:
        #TODO: handle olefile errors, when an OLE file is malformed
        vba = VBA_Parser(filename, data)
        results['vba_type'] = vba.type
        #: results from macro extraction
        results['macros'] = []
        if vba.detect_vba_macros():
            #print 'Contains VBA Macros:'
            for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
                macro_res = {}
                results['macros'].append(macro_res)
                # hide attribute lines:
                #TODO: option to disable attribute filtering
                vba_code_filtered = filter_vba(vba_code)
                macro_res['vba_filename'] = vba_filename
                macro_res['subfilename'] = subfilename
                macro_res['stream_path'] = repr(stream_path)
                # detect empty macros:
                if vba_code_filtered.strip() == '':
                    macro_res['vba_code'] = None
                else:
                    # TODO: option to display code
                    vba_code = vba_collapse_long_lines(vba_code)
                    macro_res['vba_code'] = vba_code_filtered
                    all_code += '\n' + vba_code
            t = prettytable.PrettyTable(
                ('Obfuscated expression', 'Evaluated value'))
            t.align = 'l'
            t.max_width['Obfuscated expression'] = 36
            t.max_width['Evaluated value'] = 36
            for expression, expr_eval in scan_expressions(all_code):
                t.add_row((repr(expression), repr(expr_eval)))
            results['expressions'] = t

    except: #TypeError:
        #raise
        #TODO: print more info if debug mode
        #print sys.exc_value
        # display the exception with full stack trace for debugging, but do not stop:
        traceback.print_exc()
    return results


def display_processing_results(results, out_fd=sys.stdout):
    print results
    out_fd.write('='*79 + '\n')
    out_fd.write('FILE: %s\n' % results['display_filename'])
    out_fd.write('Type: %s\n' % results['vba_type'])
    if len(results['macros']) == 0:
        out_fd.write('No VBA macros found.\n')
    for macro_res in results['macros']:
        out_fd.write('-'*79 + '\n')
        out_fd.write('VBA MACRO %s \n' % macro_res['vba_filename'])
        out_fd.write('in file: %s - OLE stream: %s\n' %
                       (macro_res['subfilename'], macro_res['stream_path']))
        out_fd.write('- '*39 + '\n')
        vba_code = macro_res['vba_code']
        if vba_code is None:
            out_fd.write('(empty macro\n')
        else:
            out_fd.write('-'*79 + '\n')
            out_fd.write('VBA CODE (with long lines collapsed):\n')
            out_fd.write('%s\n' % vba_code)
            out_fd.write('-'*79 + '\n')
            out_fd.write('PARSING VBA CODE:\n')
    if 'actions' in results:
        out_fd.write('-'*79 + '\n')
        out_fd.write('TRACING VBA CODE (entrypoint = Auto*):\n')
        # print table of all recorded actions
        out_fd.write('Recorded Actions:\n')
        out_fd.write('%s\n' % results['actions'])
    if 'expressions' in results:
            out_fd.write('-'*79 + '\n')
            out_fd.write('EVALUATED VBA EXPRESSIONS:\n')
            out_fd.write('%s\n' % t)


def main():
    """
    Main function, called when vipermonkey is run from the command line
    """
    # print banner with version
    print ('vmonkey %s - https://github.com/decalage2/ViperMonkey' % __version__)
    print ('THIS IS WORK IN PROGRESS - Check updates regularly!')
    print ('Please report any issue at https://github.com/decalage2/ViperMonkey/issues')
    print ('')

    DEFAULT_LOG_LEVEL = "info" # Default log level
    LOG_LEVELS = {
        'debug':    logging.DEBUG,
        'info':     logging.INFO,
        'warning':  logging.WARNING,
        'error':    logging.ERROR,
        'critical': logging.CRITICAL
        }

    usage = 'usage: %prog [options] <filename> [filename2 ...]'
    parser = optparse.OptionParser(usage=usage)
    # parser.add_option('-o', '--outfile', dest='outfile',
    #     help='output file')
    # parser.add_option('-c', '--csv', dest='csv',
    #     help='export results to a CSV file')
    parser.add_option("-r", action="store_true", dest="recursive",
        help='find files recursively in subdirectories.')
    parser.add_option("-z", "--zip", dest='zip_password', type='str', default=None,
        help='if the file is a zip archive, open first file from it, using the provided password (requires Python 2.6+)')
    parser.add_option("-f", "--zipfname", dest='zip_fname', type='str', default='*',
        help='if the file is a zip archive, file(s) to be opened within the zip. Wildcards * and ? are supported. (default:*)')
    parser.add_option("-e", action="store_true", dest="scan_expressions",
        help='Extract and evaluate/deobfuscate constant expressions')
    parser.add_option('-l', '--loglevel', dest="loglevel", action="store", default=DEFAULT_LOG_LEVEL,
                            help="logging level debug/info/warning/error/critical (default=%default)")

    (options, args) = parser.parse_args()

    # Print help if no arguments are passed
    if len(args) == 0:
        print __doc__
        parser.print_help()
        sys.exit()

    # setup logging to the console
    # logging.basicConfig(level=LOG_LEVELS[options.loglevel], format='%(levelname)-8s %(message)s')
    colorlog.basicConfig(level=LOG_LEVELS[options.loglevel], format='%(log_color)s%(levelname)-8s %(message)s')

    for container, filename, data in xglob.iter_files(args, recursive=options.recursive,
        zip_password=options.zip_password, zip_fname=options.zip_fname):
        # ignore directory names stored in zip files:
        if container and filename.endswith('/'):
            continue
        if options.scan_expressions:
            results = process_file_scanexpr(container, filename, data)
        else:
            results = process_file(container, filename, data)
        display_processing_results(results)




if __name__ == '__main__':
    main()

# Soundtrack: This code was developed while listening to The Pixies "Monkey Gone to Heaven"
