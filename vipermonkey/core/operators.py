#!/usr/bin/env python
"""
ViperMonkey: VBA Grammar - Operators

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

import sys

from vba_object import *

from logger import log

def debug_repr(op, args):
    r = "("
    first = True
    for arg in args:
        if (not first):
            r += " " + op + " "
        first = False
        r += str(arg)
    r += ")"
    return r

# --- SUM: + OPERATOR --------------------------------------------------------

class Sum(VBA_Object):
    """
    VBA Sum using the operator +
    """

    def __init__(self, original_str, location, tokens):
        super(Sum, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list [a,'&',b,'&',c,...]
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):
        # return the sum of all the arguments:
        # (Note: sum() is not applicable here, because it does not work for strings)
        # see https://docs.python.org/2/library/functions.html#reduce
        try:
            return reduce(lambda x, y: x + y, eval_args(self.arg, context))
        except TypeError:
            # NOTE: In VB you are not supposed to be able to add integers and strings.
            # However, there are maldocs that do this. If the strings are integer strings,
            # integer addition is performed.
            log.debug('Impossible to sum arguments of different types. Try converting strings to ints.')
            try:
                return reduce(lambda x, y: int(x) + int(y), eval_args(self.arg, context))
            except ValueError:
                # Punt and sum all arguments as strings.
                return reduce(lambda x, y: str(x) + str(y), eval_args(self.arg, context))
        except RuntimeError:
            log.error("overflow trying eval sum: %r" % self.arg)
            sys.exit(1)

    def __repr__(self):
        return debug_repr("+", self.arg)
        return ' + '.join(map(repr, self.arg))

# --- EQV --------------------------------------------------------

class Eqv(VBA_Object):
    """
    VBA Eqv operator.
    """

    def __init__(self, original_str, location, tokens):
        super(Eqv, self).__init__(original_str, location, tokens)
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):
        # return the eqv of all the arguments:
        try:
            return reduce(lambda a, b: (a & b) | ~(a | b), eval_args(self.arg, context))
        except TypeError:
            log.error('Impossible to Eqv arguments of different types.')
            return 0
        except RuntimeError:
            log.error("overflow trying eval Eqv: %r" % self.arg)
            sys.exit(1)

    def __repr__(self):
        return ' Eqv '.join(map(repr, self.arg))
    
# --- XOR --------------------------------------------------------

class Xor(VBA_Object):
    """
    VBA Xor operator.
    """

    def __init__(self, original_str, location, tokens):
        super(Xor, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list [a,'&',b,'&',c,...]
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):
        # return the xor of all the arguments:
        try:
            return reduce(lambda x, y: x ^ y, eval_args(self.arg, context))
        except TypeError:
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: int(x) ^ int(y), eval_args(self.arg, context))
            except:
                log.error('Impossible to xor arguments of different types.')
                return 0
        except RuntimeError:
            log.error("overflow trying eval xor: %r" % self.arg)
            sys.exit(1)

    def __repr__(self):
        return ' ^ '.join(map(repr, self.arg))

# --- AND --------------------------------------------------------

class And(VBA_Object):
    """
    VBA And operator.
    """

    def __init__(self, original_str, location, tokens):
        super(And, self).__init__(original_str, location, tokens)
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):
        # return the and of all the arguments:
        try:
            return reduce(lambda x, y: x & y, eval_args(self.arg, context))
        except TypeError:
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: int(x) & int(y), eval_args(self.arg, context))
            except:
                log.error('Impossible to and arguments of different types.')
                return 0
        except RuntimeError:
            log.error("overflow trying eval and: %r" % self.arg)
            sys.exit(1)

    def __repr__(self):
        return ' & '.join(map(repr, self.arg))

# --- OR --------------------------------------------------------

class Or(VBA_Object):
    """
    VBA Or operator.
    """

    def __init__(self, original_str, location, tokens):
        super(Or, self).__init__(original_str, location, tokens)
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):
        # return the and of all the arguments:
        try:
            return reduce(lambda x, y: x | y, eval_args(self.arg, context))
        except TypeError:
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: int(x) | int(y), eval_args(self.arg, context))
            except:
                log.error('Impossible to or arguments of different types.')
                return 0
        except RuntimeError:
            log.error("overflow trying eval or: %r" % self.arg)
            sys.exit(1)

    def __repr__(self):
        return ' | '.join(map(repr, self.arg))
    
# --- SUBTRACTION: - OPERATOR ------------------------------------------------

class Subtraction(VBA_Object):
    """
    VBA Subtraction using the binary operator -
    """

    def __init__(self, original_str, location, tokens):
        super(Subtraction, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list [a,'&',b,'&',c,...]
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):
        # return the subtraction of all the arguments:
        try:
            return reduce(lambda x, y: x - y, eval_args(self.arg, context))
        except TypeError:
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: int(x) - int(y), eval_args(self.arg, context))
            except Exception as e:

                # Are we doing math on character ordinals?
                l1 = []
                orig = eval_args(self.arg, context)
                for v in orig:
                    if (isinstance(v, int)):
                        l1.append(v)
                        continue
                    if (isinstance(v, str) and (len(v) == 1)):
                        l1.append(ord(v))
                        continue

                # Do we have something that we can do math on?
                if (len(orig) != len(l1)):                
                    log.error('Impossible to subtract arguments of different types. ' + str(e))
                    return 0

                # Try subtracting based on character ordinals.
                return reduce(lambda x, y: int(x) - int(y), l1)

    def __repr__(self):
        return debug_repr("-", self.arg)
        return ' - '.join(map(repr, self.arg))

# --- MULTIPLICATION: * OPERATOR ------------------------------------------------

class Multiplication(VBA_Object):
    """
    VBA Multiplication using the binary operator *
    """

    def __init__(self, original_str, location, tokens):
        super(Multiplication, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list [a,'&',b,'&',c,...]
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):
        # return the multiplication of all the arguments:
        try:
            return reduce(lambda x, y: x * y, eval_args(self.arg, context))
        except TypeError:
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: int(x) * int(y), eval_args(self.arg, context))
            except Exception as e:
                log.error('Impossible to multiply arguments of different types. ' + str(e))
                return 0

    def __repr__(self):
        return debug_repr("*", self.arg)
        return ' * '.join(map(repr, self.arg))

# --- DIVISION: / OPERATOR ------------------------------------------------

class Division(VBA_Object):
    """
    VBA Division using the binary operator /
    """

    def __init__(self, original_str, location, tokens):
        super(Division, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list [a,'&',b,'&',c,...]
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):
        # return the division of all the arguments:
        try:
            return reduce(lambda x, y: x / y, eval_args(self.arg, context))
        except TypeError:
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: int(x) / int(y), eval_args(self.arg, context))
            except Exception as e:
                log.error('Impossible to divide arguments of different types. ' + str(e))
                # TODO
                return 0
        except ZeroDivisionError:
            log.error("Division by 0 error. Returning ''.")
            return ''

    def __repr__(self):
        return debug_repr("/", self.arg)
        return ' / '.join(map(repr, self.arg))

# --- FLOOR DIVISION: \ OPERATOR ------------------------------------------------

class FloorDivision(VBA_Object):
    """
    VBA Floor Division using the binary operator \
    """

    def __init__(self, original_str, location, tokens):
        super(FloorDivision, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list [a,'&',b,'&',c,...]
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):
        # return the floor division of all the arguments:
        try:
            return reduce(lambda x, y: x // y, eval_args(self.arg, context))
        except TypeError:
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: int(x) // int(y), eval_args(self.arg, context))
            except Exception as e:
                log.error('Impossible to divide arguments of different types. ' + str(e))
                # TODO
                return 0

    def __repr__(self):
        return debug_repr("//", self.arg)
        return ' \\ '.join(map(repr, self.arg))

# --- CONCATENATION: & OPERATOR ----------------------------------------------

class Concatenation(VBA_Object):
    """
    VBA String concatenation using the operator &
    """

    def __init__(self, original_str, location, tokens):
        super(Concatenation, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list [a,'&',b,'&',c,...]
        self.arg = tokens[0][::2]
        log.debug('Concatenation: self.arg=%s' % repr(self.arg))

    def eval(self, context, params=None):
        # return the concatenation of all the arguments:
        # TODO: handle non-string args
        log.debug('Concatenation before eval: %r' % params)
        try:
            eval_params = eval_args(self.arg, context)
            eval_params = coerce_args_to_str(eval_params)
            log.debug('Concatenation after eval: %r' % eval_params)
            return ''.join(eval_params)
        except TypeError as e:
            log.exception('Impossible to concatenate non-string arguments. ' + str(e))
            # TODO
            return ''

    def __repr__(self):
        return debug_repr("&", self.arg)
        return ' & '.join(map(repr, self.arg))

# --- MOD OPERATOR -----------------------------------------------------------

class Mod(VBA_Object):
    """
    VBA Modulo using the operator 'Mod'
    """

    def __init__(self, original_str, location, tokens):
        super(Mod, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list [a,'mod',b,'mod',c,...]
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):
        # return the sum of all the arguments:
        # see https://docs.python.org/2/library/functions.html#reduce
        return reduce(lambda x, y: x % y, eval_args(self.arg, context))

    def __repr__(self):
        return debug_repr("mod", self.arg)
        return ' mod '.join(map(repr, self.arg))

