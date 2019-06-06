"""
Utility to help deobfuscate some VBA code before it gets processed.
This can also be used by the user to help clean up code for analysis.

WARNING: The regex below are used to find and replace common VBA obfuscated code
with something similar. It makes no attempt at creating a complete/correct grammar.
That is what vipermonkey is for.

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

from functools import reduce

import regex
from operator import xor

from vipermonkey.core.vba_lines import vba_collapse_long_lines


# language=PythonRegExp
CHR = regex.compile('Chr\((?P<op>\d+)(\s+Xor\s+(?P<op>\d+))*\)', regex.IGNORECASE)
# language=PythonRegExp
STRING = regex.compile('(".*?"|\'.*?.\')')

# Long run of Chr() and "string" concatenations.
# e.g:  Chr(71 Xor 18) & "2" & Chr(82 Xor 4) + "0" & Chr(70 Xor 15) & Chr(84 Xor 19)
# NOTE: We are allowing the use of "+" because it has the same affect as "&" when dealing
#     with just strings and order precedence shouldn't matter in this case.
# language=PythonRegExp
CONCAT_RUN = regex.compile(
    '(?P<entry>{chr}|{string})(\s+[&+]\s+(?P<entry>{chr}|{string}))*'.format(
        chr=CHR.pattern, string=STRING.pattern))

# Long run of variable concatination split among lines.
# e.g.
#  a = '1'
#  a = a & '2'
#  a = a & '3'
# language=PythonVerboseRegExp
VAR_RUN = regex.compile('''
    (?P<var>[A-Za-z][A-Za-z0-9]*)\s*?=\s*(?P<entry>.*?)[\r\n]     # variable = *
    (\s*?(?P=var)\s*=\s*(?P=var)\s+&\s+(?P<entry>.*?)[\r\n])+     # variable = variable & *
''', regex.VERBOSE)


def _replace_code(code, replacements):
    """
    Replaces code with new code.
    :param str code: code to replace
    :param list replacements: list of tuples containing (start, end, replacement)
    """
    new_code = ''
    index = 0
    for start, end, code_string in sorted(replacements):
        new_code += code[index:start] + code_string
        index = end
    new_code += code[index:]
    return new_code


def _replace_var_runs(code):
    """Replace long variable runs."""
    code_replacements = []
    for match in VAR_RUN.finditer(code):
        code_string = '{var} = {value}{newline}'.format(
            var=match.group('var'),
            value=' & '.join(match.captures('entry')),
            newline=match.group(0)[-1]  # match \r or \n as used in code.
        )
        code_replacements.append((match.start(), match.end(), code_string))
    return _replace_code(code, code_replacements)



def _replace_concat_runs(code):
    """Replace long chr runs."""
    code_replacements = []
    for match in CONCAT_RUN.finditer(code):
        code_string = ''
        for entry in match.captures('entry'):
            sub_match = CHR.match(entry)
            if sub_match:
                character = chr(reduce(xor, map(int, sub_match.captures('op'))))
                # Escape if its a quote.
                if character == '"':
                    character = '""'
                code_string += character
            else:
                code_string += entry.strip('\'"')
        code_replacements.append((match.start(), match.end(), '"{}"'.format(code_string)))
    return _replace_code(code, code_replacements)


def deobfuscate(code):
    """
    Deobfuscates VBA code.

    :param code: obfuscated VBA code

    returns: deobfuscated code
    """
    code = vba_collapse_long_lines(code)
    code = _replace_var_runs(code)
    code = _replace_concat_runs(code)
    return code
