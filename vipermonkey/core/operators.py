"""@package vipermonkey.core.operators Parsing and emulation of
VBA/VBScript operators.

"""

# pylint: disable=pointless-string-statement
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

#import sys
import logging
from collections import Iterable

from vba_object import eval_args, VBA_Object
from python_jit import to_python
from logger import log
from utils import safe_str_convert
import vba_conversion

def debug_repr(op, args):
    """Represent an operator applied to a list of arguments as a string
    (ex. debug_repr("+", [1,2,3]) == "1 + 2 + 3").

    @param op (str) The operator.

    @param args (list) List of arguments.

    @return (str) The operator application as a string.

    """
    r = "("
    first = True
    for arg in args:
        if (not first):
            r += " " + op + " "
        first = False
        r += safe_str_convert(arg)
    r += ")"
    return r

# --- SUM: + OPERATOR --------------------------------------------------------

class Sum(VBA_Object):
    """Emulation of VBA/VBScript Sum using the operator +

    """

    def __init__(self, original_str, location, tokens):
        super(Sum, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list [a,'&',b,'&',c,...]
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):

        # The wildcard for matching propagates through operations.
        evaluated_args = eval_args(self.arg, context)
        if ((isinstance(evaluated_args, Iterable)) and ("**MATCH ANY**" in evaluated_args)):
            return "**MATCH ANY**"
        
        # return the sum of all the arguments:
        # (Note: sum() is not applicable here, because it does not work for strings)
        # see https://docs.python.org/2/library/functions.html#reduce
        try:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Compute sum (1) " + safe_str_convert(self.arg))
            r = reduce(lambda x, y: x + y, vba_conversion.coerce_args(evaluated_args, preferred_type="int"))
            return r
        except (TypeError, ValueError):
            # NOTE: In VB you are not supposed to be able to add integers and strings.
            # However, there are maldocs that do this. If the strings are integer strings,
            # integer addition is performed.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Impossible to sum arguments of different types. Try converting strings to common type.')
            try:
                r = reduce(lambda x, y: int(x) + int(y), evaluated_args)
                return r
            except (TypeError, ValueError):
                # Punt and sum all arguments as strings.
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("Compute sum (2) " + safe_str_convert(self.arg))
                r = reduce(lambda x, y: safe_str_convert(x) + safe_str_convert(y), vba_conversion.coerce_args_to_str(evaluated_args))
                return r
        except RuntimeError as e:
            log.error("overflow trying eval sum: %r" % self.arg)
            raise e

    def to_python(self, context, params=None, indent=0):
        r = ""
        first = True
        for arg in self.arg:
            if (not first):
                r += " + "
            first = False
            # Could be a str or an int, so hope for the best.
            r += to_python(arg, context, params=params)
        return "(" + r + ")"
        
    def __repr__(self):
        return debug_repr("+", self.arg)
        #return ' + '.join(map(repr, self.arg))

# --- EQV --------------------------------------------------------

class Eqv(VBA_Object):
    """Emualtion of VBA/VBScript Eqv operator.

    """

    def __init__(self, original_str, location, tokens):
        super(Eqv, self).__init__(original_str, location, tokens)
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):

        # The wildcard for matching propagates through operations.
        evaluated_args = eval_args(self.arg, context)
        if ((isinstance(evaluated_args, Iterable)) and ("**MATCH ANY**" in evaluated_args)):
            return "**MATCH ANY**"

        # return the eqv of all the arguments:
        try:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Compute eqv " + safe_str_convert(self.arg))
            return reduce(lambda a, b: (a & b) | ~(a | b), vba_conversion.coerce_args(evaluated_args, preferred_type="int"))
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
    """Emulate VBA/VBScript Xor operator.

    """

    def __init__(self, original_str, location, tokens):
        super(Xor, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list [a,'&',b,'&',c,...]
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):

        # The wildcard for matching propagates through operations.
        evaluated_args = eval_args(self.arg, context)
        if ((isinstance(evaluated_args, Iterable)) and ("**MATCH ANY**" in evaluated_args)):
            return "**MATCH ANY**"

        # return the xor of all the arguments:
        try:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Compute xor " + safe_str_convert(self.arg))
            return reduce(lambda x, y: x ^ y, vba_conversion.coerce_args(evaluated_args, preferred_type="int"))
        except (TypeError, ValueError):
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: int(x) ^ int(y), evaluated_args)
            except Exception as e:
                log.error('Impossible to xor arguments of different types. Arg list = ' + safe_str_convert(self.arg) + ". " + safe_str_convert(e))
                return 0
        except RuntimeError as e:
            log.error("overflow trying eval xor: %r" % self.arg)
            raise e

    def __repr__(self):
        return ' ^ '.join(map(repr, self.arg))

    def to_python(self, context, params=None, indent=0):
        r = ""
        first = True
        for arg in self.arg:
            if (not first):
                r += " ^ "
            first = False
            r += "coerce_to_int(" + to_python(arg, context, params=params) + ")"
        return "(" + r + ")"
    
# --- AND --------------------------------------------------------

class And(VBA_Object):
    """Emulate VBA/VBScript And operator.

    """

    def __init__(self, original_str, location, tokens):
        super(And, self).__init__(original_str, location, tokens)
        self.arg = tokens[0][::2]

    def to_python(self, context, params=None, indent=0):
        r = ""
        first = True
        for arg in self.arg:
            if (not first):
                r += " & "
            first = False
            r += "coerce_to_int(" + to_python(arg, context, params=params) + ")"
        return "(" + r + ")"
        
    def eval(self, context, params=None):

        # The wildcard for matching propagates through operations.
        evaluated_args = eval_args(self.arg, context)
        if ((isinstance(evaluated_args, Iterable)) and ("**MATCH ANY**" in evaluated_args)):
            return "**MATCH ANY**"

        # return the and of all the arguments:
        try:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Compute and " + safe_str_convert(self.arg))
            return reduce(lambda x, y: x & y, vba_conversion.coerce_args(evaluated_args, preferred_type="int"))
        except (TypeError, ValueError):
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: int(x) & int(y), evaluated_args)
            except Exception as e:
                log.error('Impossible to and arguments of different types. ' + safe_str_convert(e))
                return 0
        except RuntimeError as e:
            log.error("overflow trying eval and: %r" % self.arg)
            raise e

    def __repr__(self):
        return ' & '.join(map(repr, self.arg))

# --- OR --------------------------------------------------------

class Or(VBA_Object):
    """Emulate VBA/VBScript Or operator.

    """

    def __init__(self, original_str, location, tokens):
        super(Or, self).__init__(original_str, location, tokens)
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):

        # The wildcard for matching propagates through operations.
        evaluated_args = eval_args(self.arg, context)
        if ((isinstance(evaluated_args, Iterable)) and ("**MATCH ANY**" in evaluated_args)):
            return "**MATCH ANY**"

        # return the and of all the arguments:
        try:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Compute or " + safe_str_convert(self.arg))
            return reduce(lambda x, y: x | y, vba_conversion.coerce_args(evaluated_args, preferred_type="int"))
        except (TypeError, ValueError):
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: int(x) | int(y), evaluated_args)
            except Exception as e:
                log.error('Impossible to or arguments of different types. ' + safe_str_convert(e))
                return 0
        except RuntimeError as e:
            log.error("overflow trying eval or: %r" % self.arg)
            raise e

    def to_python(self, context, params=None, indent=0):
        r = ""
        first = True
        for arg in self.arg:
            if (not first):
                r += " | "
            first = False
            r += "coerce_to_int(" + to_python(arg, context, params=params) + ")"
        return "(" + r + ")"
        
    def __repr__(self):
        return ' | '.join(map(repr, self.arg))

# --- NOT --------------------------------------------------------

class Not(VBA_Object):
    """Emulate VBA/VBScript binary Not operator.

    """

    def __init__(self, original_str, location, tokens):
        super(Not, self).__init__(original_str, location, tokens)
        self.arg = tokens[0][1]
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as binary Not' % self)

    def eval(self, context, params=None):

        # The wildcard for matching propagates through operations.
        evaluated_args = eval_args(self.arg, context)
        if ((isinstance(evaluated_args, Iterable)) and ("**MATCH ANY**" in evaluated_args)):
            return "**MATCH ANY**"

        # return the and of all the arguments:
        try:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Compute not " + safe_str_convert(self.arg))
            val = self.arg
            if (isinstance(val, VBA_Object)):
                val = val.eval(context)
            return (~ int(val))
        except Exception as e:
            log.error("Cannot compute Not " + safe_str_convert(self.arg) + ". " + safe_str_convert(e))
            return "NULL"

    def to_python(self, context, params=None, indent=0):
        r = "~ (coerce_to_int(" + to_python(self.arg, context) + "))"
        return r
        
    def __repr__(self):
        return "Not " + safe_str_convert(self.arg)

# --- Negation --------------------------------------------------------

class Neg(VBA_Object):
    """Emulate VBA/VBScript binary Not operator.

    """

    def __init__(self, original_str, location, tokens):
        super(Neg, self).__init__(original_str, location, tokens)
        self.arg = tokens[0][1]
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('parsed %r as unary negation' % self)

    def to_python(self, context, params=None, indent=0):
        r = "- (" + "coerce_to_num(" + to_python(self.arg, context) + "))"
        return r
            
    def eval(self, context, params=None):

        # The wildcard for matching propagates through operations.
        evaluated_args = eval_args(self.arg, context)
        if ((isinstance(evaluated_args, Iterable)) and ("**MATCH ANY**" in evaluated_args)):
            return "**MATCH ANY**"

        # return the and of all the arguments:
        try:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Compute negate " + safe_str_convert(self.arg))
            val = self.arg
            if (isinstance(val, VBA_Object)):
                val = val.eval(context)
            if (not isinstance(val, float)):
                val = int(val)
            return (- val)
        except Exception as e:
            log.error("Cannot compute negation of " + safe_str_convert(self.arg) + ". " + safe_str_convert(e))
            return "NULL"

    def __repr__(self):
        return "-" + safe_str_convert(self.arg)
    
# --- SUBTRACTION: - OPERATOR ------------------------------------------------

class Subtraction(VBA_Object):
    """Emulate VBA/VBScript Subtraction using the binary operator -.

    """

    def __init__(self, original_str, location, tokens):
        super(Subtraction, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list [a,'&',b,'&',c,...]
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):

        # The wildcard for matching propagates through operations.
        evaluated_args = eval_args(self.arg, context)
        if ((isinstance(evaluated_args, Iterable)) and ("**MATCH ANY**" in evaluated_args)):
            return "**MATCH ANY**"

        # return the subtraction of all the arguments:
        try:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Compute subract " + safe_str_convert(self.arg))
            return reduce(lambda x, y: x - y, vba_conversion.coerce_args(evaluated_args, preferred_type="int"))
        except (TypeError, ValueError):
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: vba_conversion.coerce_to_int(x) - vba_conversion.coerce_to_int(y), evaluated_args)
            except Exception as e:

                # Are we doing math on character ordinals?
                l1 = []
                orig = evaluated_args
                for v in orig:
                    if (isinstance(v, int)):
                        l1.append(v)
                        continue
                    if (isinstance(v, str) and (len(v) == 1)):
                        l1.append(ord(v))
                        continue

                # Do we have something that we can do math on?
                if (len(orig) != len(l1)):                
                    log.error('Impossible to subtract arguments of different types. ' + safe_str_convert(e))
                    return 0

                # Try subtracting based on character ordinals.
                return reduce(lambda x, y: int(x) - int(y), l1)

    def __repr__(self):
        return debug_repr("-", self.arg)
        #return ' - '.join(map(repr, self.arg))

# --- MULTIPLICATION: * OPERATOR ------------------------------------------------

class Multiplication(VBA_Object):
    """Emulate VBA/VBScript Multiplication using the binary operator *.

    """

    def __init__(self, original_str, location, tokens):
        super(Multiplication, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list [a,'&',b,'&',c,...]
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):

        # The wildcard for matching propagates through operations.
        evaluated_args = eval_args(self.arg, context)
        if ((isinstance(evaluated_args, Iterable)) and ("**MATCH ANY**" in evaluated_args)):
            return "**MATCH ANY**"

        # return the multiplication of all the arguments:
        try:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Compute mult " + safe_str_convert(self.arg))
            return reduce(lambda x, y: x * y, vba_conversion.coerce_args(evaluated_args, preferred_type="int"))
        except (TypeError, ValueError):
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: int(x) * int(y), evaluated_args)
            except Exception as e:
                log.error('Impossible to multiply arguments of different types. ' + safe_str_convert(e))
                return 0

    def __repr__(self):
        return debug_repr("*", self.arg)
        #return ' * '.join(map(repr, self.arg))

# --- EXPONENTIATION: ^ OPERATOR ------------------------------------------------

class Power(VBA_Object):
    """Emulate VBA/VBScript exponentiation using the binary operator ^

    """

    def __init__(self, original_str, location, tokens):
        super(Power, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list [a,'&',b,'&',c,...]
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):

        # The wildcard for matching propagates through operations.
        evaluated_args = eval_args(self.arg, context)
        if ((isinstance(evaluated_args, Iterable)) and ("**MATCH ANY**" in evaluated_args)):
            return "**MATCH ANY**"

        # return the exponentiation of all the arguments:
        try:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Compute pow " + safe_str_convert(self.arg))
            return reduce(lambda x, y: pow(x, y), vba_conversion.coerce_args(evaluated_args, preferred_type="int"))
        except (TypeError, ValueError):
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: pow(int(x), int(y)), evaluated_args)
            except Exception as e:
                log.error('Impossible to do exponentiation with arguments of different types. ' + safe_str_convert(e))
                return 0

    def __repr__(self):
        return debug_repr("^", self.arg)
        #return ' ^ '.join(map(repr, self.arg))

    def to_python(self, context, params=None, indent=0):
        r = reduce(lambda x, y: "pow(coerce_to_num(" + to_python(x, context) + "), coerce_to_num(" + to_python(y, context) + "))", self.arg)
        return r
    
# --- DIVISION: / OPERATOR ------------------------------------------------

class Division(VBA_Object):
    """Emulate VBA/VBScript Division using the binary operator /.

    """

    def __init__(self, original_str, location, tokens):
        super(Division, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list [a,'&',b,'&',c,...]
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):

        # The wildcard for matching propagates through operations.
        evaluated_args = eval_args(self.arg, context)
        if ((isinstance(evaluated_args, Iterable)) and ("**MATCH ANY**" in evaluated_args)):
            return "**MATCH ANY**"

        # return the division of all the arguments:
        try:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Compute div " + safe_str_convert(self.arg))
            return reduce(lambda x, y: x / y, vba_conversion.coerce_args(evaluated_args, preferred_type="int"))
        except (TypeError, ValueError):
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: int(x) / int(y), evaluated_args)
            except Exception as e:
                if (safe_str_convert(e).strip() != "division by zero"):
                    log.error('Impossible to divide arguments of different types. ' + safe_str_convert(e))
                # TODO
                return 0
        except ZeroDivisionError:
            context.set_error("Division by 0 error. Returning 'NULL'.")
            return 'NULL'

    def __repr__(self):
        return debug_repr("/", self.arg)
        #return ' / '.join(map(repr, self.arg))


class MultiOp(VBA_Object):
    """Defines emulation for multiple operators that work within the same
    level of order or operations ((+, -), (*, /), etc).

    """
    operator_map = {}

    def __init__(self, original_str, location, tokens):
        super(MultiOp, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list (e.g. [a,'*',b,'/',c,...])
        self.arg = tokens[0][::2]  # Keep as helper  (kept singular to keep backwards compatibility)
        self.operators = tokens[0][1::2]

    def to_python(self, context, params=None, indent=0):

        # We are generating Python code for some string or numeric
        # expression. Therefore any boolean operators we find in the
        # expression are actually bitwise operators.
        # Track that in the context.
        set_flag = False
        if (not context.in_bitwise_expression):
            context.in_bitwise_expression = True
            set_flag = True
            
        if (self.operators[0] == "+"):
            ret = [to_python(self.arg[0], context, params=params)]
        else:
            ret = ["coerce_to_num(" + to_python(self.arg[0], context, params=params)  + ")"]
        for op, arg in zip(self.operators, self.arg[1:]):
            if (op == "+"):
                ret.append(' {} {!s}'.format("|plus|", to_python(arg, context, params=params)))
            else:
                ret.append(' {} {!s}'.format(op, "coerce_to_num(" + to_python(arg, context, params=params) + ")"))

        # Out of the string/numeric expression. Might have actual boolean
        # expressions now.
        if set_flag:
            context.in_bitwise_expression = False

        return '({})'.format(''.join(ret))
        
    def eval(self, context, params=None):

        # We are emulating some string or numeric
        # expression. Therefore any boolean operators we find in the
        # expression are actually bitwise operators.
        # Track that in the context.
        set_flag = False
        if (not context.in_bitwise_expression):
            context.in_bitwise_expression = True
            set_flag = True
        
        # The wildcard for matching propagates through operations.
        evaluated_args = eval_args(self.arg, context)
        if ((isinstance(evaluated_args, Iterable)) and ("**MATCH ANY**" in evaluated_args)):
            if set_flag:
                context.in_bitwise_expression = False
            return "**MATCH ANY**"

        try:
            args = vba_conversion.coerce_args(evaluated_args)
            ret = args[0]
            for op, arg in zip(self.operators, args[1:]):
                try:
                    ret = self.operator_map[op](ret, arg)
                except OverflowError:
                    log.error("overflow trying eval: %r" % safe_str_convert(self))
            if set_flag:
                context.in_bitwise_expression = False
            return ret
        except (TypeError, ValueError):
            # Try converting strings to numbers.
            # TODO: Need to handle floats in strings.
            try:
                args = map(vba_conversion.coerce_to_num, evaluated_args)
                ret = args[0]
                for op, arg in zip(self.operators, args[1:]):
                    ret = self.operator_map[op](ret, arg)
                if set_flag:
                    context.in_bitwise_expression = False
                return ret
            except ZeroDivisionError:
                context.set_error("Division by 0 error. Returning 'NULL'.")
                if set_flag:
                    context.in_bitwise_expression = False
                return 'NULL'
            except Exception as e:
                log.error('Impossible to operate on arguments of different types. ' + safe_str_convert(e))
                if set_flag:
                    context.in_bitwise_expression = False
                return 0
        except ZeroDivisionError:
            context.set_error("Division by 0 error. Returning 'NULL'.")
            if set_flag:
                context.in_bitwise_expression = False
            return 'NULL'

    def __repr__(self):
        ret = [safe_str_convert(self.arg[0])]
        for op, arg in zip(self.operators, self.arg[1:]):
            ret.append(' {} {!s}'.format(op, arg))
        return '({})'.format(''.join(ret))


class MultiDiv(MultiOp):
    """Emulate VBA/VBScript Multiplication/Division (used for
    performance).

    """
    operator_map = {'*': operator.mul, '/': operator.truediv}


class AddSub(MultiOp):
    """Emulate VBA/VBScript Addition/Subtraction (used for performance).

    """
    operator_map = {'+': operator.add, '-': operator.sub}


# --- FLOOR DIVISION: \ OPERATOR ------------------------------------------------

class FloorDivision(VBA_Object):
    """Emulate VBA/VBScript Floor Division using the binary operator \.

    """

    def __init__(self, original_str, location, tokens):
        super(FloorDivision, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list [a,'&',b,'&',c,...]
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):

        # The wildcard for matching propagates through operations.
        evaluated_args = eval_args(self.arg, context)
        if ((isinstance(evaluated_args, Iterable)) and ("**MATCH ANY**" in evaluated_args)):
            return "**MATCH ANY**"

        # return the floor division of all the arguments:
        try:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Compute floor div " + safe_str_convert(self.arg))
            return reduce(lambda x, y: x // y, vba_conversion.coerce_args(evaluated_args, preferred_type="int"))
        except (TypeError, ValueError):
            # Try converting strings to ints.
            # TODO: Need to handle floats in strings.
            try:
                return reduce(lambda x, y: int(x) // int(y), evaluated_args)
            except Exception as e:
                if (safe_str_convert(e).strip() != "division by zero"):
                    log.error('Impossible to divide arguments of different types. ' + safe_str_convert(e))
                # TODO
                return 0
        except ZeroDivisionError as e:
            context.set_error(safe_str_convert(e))
            
    def __repr__(self):
        return debug_repr("//", self.arg)
        #return ' \\ '.join(map(repr, self.arg))

    def to_python(self, context, params=None, indent=0):
        r = ""
        first = True
        for arg in self.arg:
            if (not first):
                r += " // "
            first = False
            r += "coerce_to_num(" + to_python(arg, context, params=params) + ")"
        return "(" + r + ")"
    
# --- CONCATENATION: & OPERATOR ----------------------------------------------

class Concatenation(VBA_Object):
    """Emulate VBA/VBScript String concatenation using the operator &.

    """

    def __init__(self, original_str, location, tokens):
        super(Concatenation, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list [a,'&',b,'&',c,...]
        self.arg = tokens[0][::2]
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('Concatenation: self.arg=%s' % repr(self.arg))

    def eval(self, context, params=None):

        # The wildcard for matching propagates through operations.
        evaluated_args = eval_args(self.arg, context)
        if ((isinstance(evaluated_args, Iterable)) and ("**MATCH ANY**" in evaluated_args)):
            return "**MATCH ANY**"

        # return the concatenation of all the arguments:
        # TODO: handle non-string args
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug('Concatenation before eval: %r' % params)
        try:
            eval_params = evaluated_args
            eval_params = vba_conversion.coerce_args_to_str(eval_params)
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug('Concatenation after eval: %r' % eval_params)
            return ''.join(eval_params)
        except (TypeError, ValueError) as e:
            log.exception('Impossible to concatenate non-string arguments. ' + safe_str_convert(e))
            # TODO
            return ''

    def __repr__(self):
        return debug_repr("&", self.arg)
        #return ' & '.join(map(repr, self.arg))

    def to_python(self, context, params=None, indent=0):
        r = ""
        first = True
        for arg in self.arg:
            if (not first):
                r += " + "
            first = False
            r += "coerce_to_str(" + to_python(arg, context, params=params) + ", zero_is_null=True)"
        return "(" + r + ")"

# --- MOD OPERATOR -----------------------------------------------------------

class Mod(VBA_Object):
    """Emulate VBA/VBScript Modulo using the operator 'Mod'.

    """

    def __init__(self, original_str, location, tokens):
        super(Mod, self).__init__(original_str, location, tokens)
        # extract argument from the tokens:
        # expected to be a tuple containing a list [a,'mod',b,'mod',c,...]
        self.arg = tokens[0][::2]

    def eval(self, context, params=None):

        # The wildcard for matching propagates through operations.
        evaluated_args = eval_args(self.arg, context)
        if ((isinstance(evaluated_args, Iterable)) and ("**MATCH ANY**" in evaluated_args)):
            return "**MATCH ANY**"

        # return the sum of all the arguments:
        # see https://docs.python.org/2/library/functions.html#reduce
        try:
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Compute mod " + safe_str_convert(self.arg))
            return reduce(lambda x, y: int(x) % int(y), vba_conversion.coerce_args(evaluated_args, preferred_type="int"))
        except (TypeError, ValueError) as e:
            log.error('Impossible to mod arguments of different types. ' + safe_str_convert(e))
            return ''
        except ZeroDivisionError:
            log.error('Mod division by zero error.')
            return ''

    def __repr__(self):
        return debug_repr("mod", self.arg)
        #return ' mod '.join(map(repr, self.arg))

    def to_python(self, context, params=None, indent=0):
        r = ""
        first = True
        for arg in self.arg:
            if (not first):
                r += " % "
            first = False
            r += "coerce_to_num(" + to_python(arg, context, params=params) + ")"
        return "(" + r + ")"
