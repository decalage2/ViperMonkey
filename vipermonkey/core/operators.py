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
import operator

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
            log.debug("Compute sum (1) " + str(self.arg))
            r = reduce(lambda x, y: x + y, coerce_args(eval_args(self.arg, context), preferred_type="int"))
            return r
        except (TypeError, ValueError):
            # NOTE: In VB you are not supposed to be able to add integers and strings.
            # However, there are maldocs that do this. If the strings are integer strings,
            # integer addition is performed.
            log.debug('Impossible to sum arguments of different types. Try converting strings to common type.')
            try:
                r = reduce(lambda x, y: int(x) + int(y), eval_args(self.arg, context))
                return r
            except (TypeError, ValueError):
                # Punt and sum all arguments as strings.
                log.debug("Compute sum (2) " + str(self.arg))
                r = reduce(lambda x, y: str(x) + str(y), coerce_args_to_str(eval_args(self.arg, context)))
                return r
        except RuntimeError as e:
            log.error("overflow trying eval sum: %r" % self.arg)
            raise e

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
            log.debug("Compute eqv " + str(self.arg))
            return reduce(lambda a, b: (a & b) | ~(a | b), coerce_args(eval_args(self.arg, context), preferred_type="int"))
        except (TypeError, ValueError):
            log.error('Impossible to Eqv arguments of different types.')
            return 0
        except RuntimeError as e:
            log.error("overflow trying eval Eqv: %r" % self.arg)
            raise e

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
            log.debug("Compute xor " + str(self.arg))
            return reduce(lambda x, y: x ^ y, coerce_args(eval_args(self.arg, context), preferred_type="int"))
        except (TypeError, ValueError):
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: int(x) ^ int(y), eval_args(self.arg, context))
            except:
                log.error('Impossible to xor arguments of different types.')
                return 0
        except RuntimeError as e:
            log.error("overflow trying eval xor: %r" % self.arg)
            raise e

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
            log.debug("Compute and " + str(self.arg))
            return reduce(lambda x, y: x & y, coerce_args(eval_args(self.arg, context), preferred_type="int"))
        except (TypeError, ValueError):
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: int(x) & int(y), eval_args(self.arg, context))
            except:
                log.error('Impossible to and arguments of different types.')
                return 0
        except RuntimeError as e:
            log.error("overflow trying eval and: %r" % self.arg)
            raise e

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
            log.debug("Compute or " + str(self.arg))
            return reduce(lambda x, y: x | y, coerce_args(eval_args(self.arg, context), preferred_type="int"))
        except (TypeError, ValueError):
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: int(x) | int(y), eval_args(self.arg, context))
            except:
                log.error('Impossible to or arguments of different types.')
                return 0
        except RuntimeError as e:
            log.error("overflow trying eval or: %r" % self.arg)
            raise e

    def __repr__(self):
        return ' | '.join(map(repr, self.arg))

# --- NOT --------------------------------------------------------

class Not(VBA_Object):
    """
    VBA binary Not operator.
    """

    def __init__(self, original_str, location, tokens):
        super(Not, self).__init__(original_str, location, tokens)
        self.arg = tokens[0][1]
        log.debug('parsed %r as binary Not' % self)

    def eval(self, context, params=None):
        # return the and of all the arguments:
        try:
            log.debug("Compute not " + str(self.arg))
            val = self.arg
            if (isinstance(val, VBA_Object)):
                val = val.eval(context)
            return (~ int(val))
        except Exception as e:
            log.error("Cannot compute Not " + str(self.arg) + ". " + str(e))
            return "NULL"

    def __repr__(self):
        return "Not " + str(self.arg)
    
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
            log.debug("Compute subract " + str(self.arg))
            return reduce(lambda x, y: x - y, coerce_args(eval_args(self.arg, context), preferred_type="int"))
        except (TypeError, ValueError):
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: coerce_to_int(x) - coerce_to_int(y), eval_args(self.arg, context))
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
            log.debug("Compute mult " + str(self.arg))
            return reduce(lambda x, y: x * y, coerce_args(eval_args(self.arg, context), preferred_type="int"))
        except (TypeError, ValueError):
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

# --- EXPONENTIATION: ^ OPERATOR ------------------------------------------------

class Power(VBA_Object):
    """
    VBA exponentiation using the binary operator ^
    """

    def __init__(self, original_str, location, tokens):
        super(Power, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list [a,'&',b,'&',c,...]
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):
        # return the exponentiation of all the arguments:
        try:
            log.debug("Compute pow " + str(self.arg))
            return reduce(lambda x, y: pow(x, y), coerce_args(eval_args(self.arg, context), preferred_type="int"))
        except (TypeError, ValueError):
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: pow(int(x), int(y)), eval_args(self.arg, context))
            except Exception as e:
                log.error('Impossible to do exponentiation with arguments of different types. ' + str(e))
                return 0

    def __repr__(self):
        return debug_repr("^", self.arg)
        return ' ^ '.join(map(repr, self.arg))
    
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
            log.debug("Compute div " + str(self.arg))
            return reduce(lambda x, y: x / y, coerce_args(eval_args(self.arg, context), preferred_type="int"))
        except (TypeError, ValueError):
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


class MultiOp(VBA_Object):
    """
    Defines multiple operators that work within the same level of order or operations.
    """
    operator_map = {}

    def __init__(self, original_str, location, tokens):
        super(MultiOp, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list (e.g. [a,'*',b,'/',c,...])
        self.arg = tokens[0][::2]  # Keep as helper  (kept singular to keep backwards compatibility)
        self.operators = tokens[0][1::2]

    def eval(self, context, params=None):
        evaluated_args = eval_args(self.arg, context)
        try:
            args = coerce_args(evaluated_args)
            ret = args[0]
            for operator, arg in zip(self.operators, args[1:]):
                ret = self.operator_map[operator](ret, arg)
            return ret
        except (TypeError, ValueError):
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                args = map(int, evaluated_args)
                ret = args[0]
                for operator, arg in zip(self.operators, args[1:]):
                    ret = self.operator_map[operator](ret, arg)
                return ret
            except Exception as e:
                log.error('Impossible to operate on arguments of different types. ' + str(e))
                return 0
        except ZeroDivisionError:
            log.error("Division by 0 error. Returning ''.")
            return ''

    def __repr__(self):
        ret = [str(self.arg[0])]
        for operator, arg in zip(self.operators, self.arg[1:]):
            ret.append(' {} {!s}'.format(operator, arg))
        return '({})'.format(''.join(ret))


class MultiDiv(MultiOp):
    """
    VBA Multiplication/Division (used for performance)
    """
    operator_map = {'*': operator.mul, '/': operator.truediv}


class AddSub(MultiOp):
    """
    VBA Addition/Subtraction (used for performance)
    """
    operator_map = {'+': operator.add, '-': operator.sub}


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
            log.debug("Compute floor div " + str(self.arg))
            return reduce(lambda x, y: x // y, coerce_args(eval_args(self.arg, context), preferred_type="int"))
        except (TypeError, ValueError):
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
        except (TypeError, ValueError) as e:
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
        try:
            log.debug("Compute mod " + str(self.arg))
            return reduce(lambda x, y: int(x) % int(y), coerce_args(eval_args(self.arg, context), preferred_type="int"))
        except (TypeError, ValueError) as e:
            log.error('Impossible to mod arguments of different types. ' + str(e))
            return ''
        except ZeroDivisionError:
            log.error('Mod division by zero error.')
            return ''

    def __repr__(self):
        return debug_repr("mod", self.arg)
        return ' mod '.join(map(repr, self.arg))

