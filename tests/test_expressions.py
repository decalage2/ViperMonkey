"""
Tests the grammars and logic in expressions.py
"""

from textwrap import dedent

import vipermonkey
from vipermonkey.core import *
import vipermonkey.core.literals


def test_paragraphs():
    """Tests references to the .Paragraphs field of the current doc."""
    context = vipermonkey.Context()
    context['ActiveDocument.Paragraphs'] = 'PARAGRAPH OBJECT'

    assert vipermonkey.eval('ActiveDocument.Paragraphs', context) == 'PARAGRAPH OBJECT'

    parsed = simple_statement.parseString('ActiveDocument.Paragraphs')[0]
    assert type(parsed) == Call_Statement
    assert type(parsed.name) == MemberAccessExpression
    assert parsed.eval(context) == 'PARAGRAPH OBJECT'

    # Having "ActiveDocument" is not required.
    parsed = simple_statement.parseString('something_else.Paragraphs')[0]
    assert type(parsed) == Call_Statement
    assert type(parsed.name) == MemberAccessExpression
    assert parsed.eval(context) == 'PARAGRAPH OBJECT'

    # Doesn't work if not last entry.
    parsed = simple_statement.parseString('ActiveDocument.Paragraphs.Count')[0]
    assert type(parsed) == Call_Statement
    assert type(parsed.name) == MemberAccessExpression
    assert parsed.name.eval(context) == 'ActiveDocument.Paragraphs.Count'

    parsed = simple_statement.parseString('r = ActiveDocument.Paragraphs')[0]
    assert type(parsed) == Let_Statement
    assert type(parsed.expression) == MemberAccessExpression
    assert parsed.expression.eval(context) == 'PARAGRAPH OBJECT'


def test_oslanguage():
    """Tests references to the OSlanguage field."""
    context = vipermonkey.Context()
    context['oslanguage'] = 'Spanish'
    assert vipermonkey.eval('OS.OSLanguage', context) == 'Spanish'


def test_application_run():
    """Tests functions called with Application.Run()"""
    context = vipermonkey.Context()
    vipermonkey.eval('Application.Run(WinExec, "powershell.exe test.ps1")', context)

    assert context.actions == {
        # FIXME: Application.Run from VBALibraryFuncs doesn't get called for some reason.
        # 'Interesting Function Call': [('Run', 'WinExec')],
        'Interesting Command Execution': [('Run', 'powershell.exe test.ps1')]
    }


def test_clipboard():
    """Tests calls to setData() and getData() clipboard."""
    context = vipermonkey.Context()

    assert '** CLIPBOARD **' not in context
    assert vipermonkey.eval('objHTML.ParentWindow.clipboardData.getData()', context) is None
    assert vipermonkey.eval('objHTML.ParentWindow.clipboardData.setData(None, "test data")', context) is True
    assert '** CLIPBOARD **' in context.globals
    assert context['** CLIPBOARD **'] == 'test data'
    assert vipermonkey.eval('objHTML.ParentWindow.clipboardData.getData()', context) == 'test data'


def test_doc_vars():
    """Tests calls to retrieve document properties."""
    context = vipermonkey.Context()
    context.doc_vars['subject'] = 'test Subject'

    assert vipermonkey.eval('ActiveDocument.BuiltInDocumentProperties("Subject")', context) == 'test Subject'
    assert vipermonkey.eval('ActiveDocument.variables("subject")', context) == 'test Subject'

    # TODO: Add test for _handle_docvar_value()


def test_text_file_read(tmpdir):
    """Tests OpenTextFile(...).ReadAll() calls."""
    test_file = tmpdir / 'test.txt'
    test_file.write('this is test data')

    assert vipermonkey.eval('fs.OpenTextFile("{!s}").ReadAll()'.format(test_file)) == 'this is test data'

    # It should also work when the drive is uppercase.
    # (see note in _handle_text_file_read())
    test_file = str(test_file)
    if test_file.startswith('c:'):
        test_file = 'C:' + test_file[2:]
    assert vipermonkey.eval('fs.OpenTextFile("{!s}").ReadAll()'.format(test_file)) == 'this is test data'


def test_file_close():
    """Tests close of file object foo.Close()"""
    context = vipermonkey.Context()
    context.open_file('test.txt')
    context.write_file('test.txt', b'data')

    assert not context.closed_files
    # vipermonkey closes the last open file
    vipermonkey.eval('foo.Close()', context)
    assert context.closed_files == {'test.txt': b'data'}


def test_replace():
    """Tests string replaces of the form foo.Replace(bar, baz)"""

    assert vipermonkey.eval('foo.Replace("replace foo with bar", "foo", "bar")') == 'replace bar with bar'

    # TODO: Add test for RegExp object.
    # context = vipermonkey.Context()
    # context['RegExp.Pattern'] = '[a-z]*!'
    #
    # assert vipermonkey.eval('RegExp.Replace("hello world!", "mars!")') == 'hello mars!'


def test_add():
    """Tests Add() function"""
    context = vipermonkey.Context()
    context['my_dict'] = {'a': 1, 'b': 2}

    vipermonkey.eval('my_dict.Add("c", 3)', context)
    assert context['my_dict'] == {'a': 1, 'b': 2, 'c': 3}


def test_adodb_writes():
    """Tests expression like "foo.Write(...)" where foo = "ADODB.Stream" """
    context = vipermonkey.Context()
    vipermonkey.eval('CreateObject("ADODB.Stream").Write("this is test data")', context)
    assert context.open_files == {'ADODB.Stream': 'this is test data'}

    # FIXME: This method fails.
    # context = vipermonkey.Context()
    # vipermonkey.eval(dedent(r'''
    #     foo = CreateObject("ADODB.Stream")
    #     foo.Write("this is test data")
    # '''), context)
    # assert context.open_files == {'ADODB.Stream': 'this is test data'}


def test_loadxml():
    # TODO
    pass
