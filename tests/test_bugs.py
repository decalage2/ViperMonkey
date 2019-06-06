"""Tests our bug fixes and tweaks to ensure future development doesn't mess anything up."""

import pytest

from vipermonkey.core import *
import vipermonkey.core.literals


def test_call_vs_member_access():
    """
    A "Call_Statement" should have a higher priority over a "MemberAccessExpression"
    """
    parsed = member_access_expression.parseString('Fileout.Close')[0]
    assert type(parsed) == MemberAccessExpression
    assert parsed.lhs == 'Fileout'
    assert parsed.rhs == ['Close']

    parsed = simple_statement.parseString('Fileout.Close')[0]
    assert type(parsed) == Call_Statement
    assert type(parsed.name) == MemberAccessExpression
    assert str(parsed.name) == 'Fileout.Close'
    assert len(parsed.params) == 0

    parsed = simple_statement.parseString('Fileout.Write final')[0]
    assert type(parsed) == Call_Statement
    assert type(parsed.name) == MemberAccessExpression
    assert str(parsed.name) == "Fileout.Write('final')"
    assert len(parsed.name.rhs) == 1
    assert type(parsed.name.rhs[0]) == Function_Call
    assert str(parsed.name.rhs[0]) == "Write('final')"
    assert len(parsed.name.rhs[0].params) == 1
    assert type(parsed.name.rhs[0].params[0]) == SimpleNameExpression
    assert str(parsed.name.rhs[0].params[0]) == 'final'

    parsed = simple_statement.parseString('doc.VBProject.VBComponents("ThisDocument").CodeModule.AddFromString "test"')[0]
    assert type(parsed) == Call_Statement
    assert type(parsed.name) == MemberAccessExpression
    assert str(parsed.name) == "doc.VBProject.VBComponents('ThisDocument').CodeModule.AddFromString('test')"
    assert parsed.name.lhs == 'doc'
    assert map(str, parsed.name.rhs) == ['VBProject', "VBComponents('ThisDocument')", 'CodeModule', "AddFromString('test')"]
    assert type(parsed.name.rhs[1]) == Function_Call
    assert parsed.name.rhs[1].name == 'VBComponents'
    # Params is a pyparsing.ParseResult, so use list() to cast as a list.
    vb_comp_params = list(parsed.name.rhs[1].params)
    assert len(vb_comp_params) == 1
    assert type(vb_comp_params[0]) == vipermonkey.core.literals.String
    assert str(vb_comp_params[0]) == 'ThisDocument'
    add_string_params = list(parsed.name.rhs[-1].params)
    assert len(add_string_params) == 1
    assert type(add_string_params[0]) == vipermonkey.core.literals.String
    assert str(add_string_params[0]) == 'test'

    parsed = simple_statement.parseString(r'fso.CreateTextFile("h" & "e" & "l" & "l" & "o", True, True)')[0]
    assert type(parsed) == Call_Statement
    assert type(parsed.name) == MemberAccessExpression
    assert str(parsed.name) == "fso.CreateTextFile('(h & e & l & l & o), True, True')"
    assert parsed.name.rhs[0].params[0].eval(Context()) == 'hello'

    # Preliminary tests to prevent recursive loop.
    parsed = expression.parseString('fso.CreateTextFile()')[0]
    assert type(parsed) == MemberAccessExpression
    assert parsed.lhs == 'fso'
    assert type(parsed.rhs[0]) == Function_Call

    # FIXME: I had to disable the Exponential operator in expression and the prop_assign_statement in simple_statement
    #   to fix a recursion error that was happening with the following line.
    # Ensure this doesn't mess up MemberAccessExpression being used in other places
    try:
        parsed = simple_statement.parseString(r'Set Fileout2 = fso.CreateTextFile("h" & "e" & "l" & "l" & "o", True, True)')[0]
    except RuntimeError as e:
        pytest.fail(e.message)
    assert type(parsed) == Let_Statement
    assert parsed.name == 'Fileout2'
    assert type(parsed.expression) == MemberAccessExpression
    assert str(parsed.expression) == "fso.CreateTextFile('(h & e & l & l & o), True, True')"
    assert parsed.expression.lhs == 'fso'
    assert len(parsed.expression.rhs) == 1
    assert type(parsed.expression.rhs[0]) == Function_Call
    assert parsed.expression.rhs[0].name == 'CreateTextFile'
    assert parsed.expression.rhs[0].params[0].eval(Context()) == 'hello'


def test_recursion_errors():
    """Tests that we have fixed the recursion errors."""
    # NOTE: Catching these exceptions help to speed up failures if they are going to occur.

    try:
        simple_statement.parseString(r'Set Fileout2 = fso.CreateTextFile("h" & "e" & "l" & "l" & "o", True, True)')
    except RuntimeError as e:
        pytest.fail(str(e))

    try:
        parsed = expr_list.parseString('a, b, c, d, e, f')
    except RuntimeError as e:
        pytest.fail(str(e))
    assert len(parsed) == 6
    assert str(parsed) == '[a, b, c, d, e, f]'

    try:
        simple_statement.parseString(r'Set Fileout = fso.CreateTextFile(url, True, True)')
    except RuntimeError as e:
        pytest.fail(str(e))

