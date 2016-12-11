#!/usr/bin/env python
"""
ViperMonkey: VBA command line shell

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

from __future__ import print_function

# ------------------------------------------------------------------------------
# CHANGELOG:
# 2015-02-12 v0.01 PL: - first prototype
# 2015-2016        PL: - many updates
# 2016-06-11 v0.02 PL: - split vipermonkey into several modules
# 2016-12-11 v0.04 PL: - fixed relative import for vmonkey package (issue #17)

__version__ = '0.04'

# ------------------------------------------------------------------------------
# TODO:
# + use readline

# --- IMPORTS ------------------------------------------------------------------

import logging, optparse, sys, os

import colorlog

# add the vipermonkey folder to sys.path (absolute+normalized path):
_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
if not _thismodule_dir in sys.path:
    sys.path.insert(0, _thismodule_dir)

# relative import of the vmonkey module:
import vmonkey

vm = vmonkey.ViperMonkey()


def parse(filename=None):
    if filename is None:
        print('Enter VBA code, end by a line containing only ".":')
        code = ''
        line = None
        while True:
            line = raw_input()
            if line == '.':
                break
            code += line + '\n'
    else:
        print('Parsing file %r' % filename)
        code = open(filename).read()
    vm.add_module(code)

def eval_expression(e):
    print('Evaluating %s' % e)
    value = vm.eval(e)
    print('Returned value: %s' % value)
    # print table of all recorded actions
    print('Recorded Actions:')
    print(vm.dump_actions())


def main():
    """
    Main function, called when vbashell is run from the command line
    """
    # print banner with version
    print ('vbashell %s - https://github.com/decalage2/ViperMonkey' % __version__)
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
    parser.add_option('-p', '--parse', dest='parse_file',
         help='VBA text file to be parsed')
    parser.add_option('-e', '--eval', dest='eval_expr',
        help='VBA expression to be evaluated')
    parser.add_option('-l', '--loglevel', dest="loglevel", action="store", default=DEFAULT_LOG_LEVEL,
                            help="logging level debug/info/warning/error/critical (default=%default)")

    (options, args) = parser.parse_args()

    # Print help if no arguments are passed
    # if len(args) == 0:
    #     print(__doc__)
    #     parser.print_help()
    #     sys.exit()

    # setup logging to the console
    # logging.basicConfig(level=LOG_LEVELS[options.loglevel], format='%(levelname)-8s %(message)s')

    colorlog.basicConfig(level=LOG_LEVELS[options.loglevel], format='%(log_color)s%(levelname)-8s %(message)s')

    if options.parse_file:
        parse(options.parse_file)

    if options.eval_expr:
        eval_expression(options.eval_expr)

    while True:
        try:
            print("VBA> ", end='')
            cmd = raw_input()

            if cmd.startswith('exit'):
                break

            if cmd.startswith('parse'):
                parse()

            if cmd.startswith('trace'):
                args = cmd.split()
                print('Tracing %s' % args[1])
                vm.trace(entrypoint=args[1])
                # print table of all recorded actions
                print('Recorded Actions:')
                print(vm.dump_actions())

            if cmd.startswith('eval'):
                expr = cmd[5:]
                eval_expression(expr)
        except Exception:
            vmonkey.log.exception('ERROR')

if __name__ == '__main__':
    main()

# Soundtrack: This code was developed while listening to "Five Little Monkeys Jumping On The Bed"