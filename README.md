ViperMonkey
===========

ViperMonkey is a VBA Emulation engine written in Python, designed to analyze
and deobfuscate malicious VBA Macros contained in Microsoft Office files
(Word, Excel, PowerPoint, Publisher, etc).

See the article "[Using VBA Emulation to Analyze Obfuscated Macros](http://decalage.info/vba_emulation)",
for real-life examples of malware deobfucation with ViperMonkey.

ViperMonkey was also demonstrated at the Black Hat Europe 2019 conference: 
see the [slides](https://decalage.info/en/bheu2019) 
and [video](https://youtu.be/l5sMPGjtKn0?list=PLH15HpR5qRsXiPOP3gxN6ultoj0rAR6Yn&t=1118) (at 18:38).

ViperMonkey was created by [Philippe Lagadec](https://github.com/decalage2) in 2015-2016, and the project
is maintained in the repository https://github.com/decalage2/ViperMonkey. 
Since November 2017, most of the development is done by [Kirk Sayre](https://github.com/kirk-sayre-work) 
and other contributors in the repository https://github.com/kirk-sayre-work/ViperMonkey. 
The main repository is synchronised regularly, but cutting edge improvements are usually
available first in Kirk's version.

**Quick links:**
[Report Issues/Suggestions/Questions](https://github.com/decalage2/ViperMonkey/issues) -
[Contact the Author](http://decalage.info/contact) -
[Repository](https://github.com/decalage2/ViperMonkey) -
[Updates on Twitter](https://twitter.com/decalage2) -
[API Tutorial](docs/APITutorial.md)


**DISCLAIMER**:
- ViperMonkey is an experimental VBA Engine targeted at analyzing maldocs. It works on some but not all maldocs. 
- VBA parsing and emulation is *extremely* slow for now (see the speedup section for how to improve the speed).
- VBA Emulation is hard and complex, because of all the features of the VBA language, of Microsoft
Office applications, and all the DLLs and ActiveX objects that can be called from VBA.
- This open-source project is only developed on my scarce spare time, so do not expect
miracles. Any help from you will be very appreciated!

Download and Install:
---------------------

**Easy Install**

1. Install docker.
2. Run `docker/dockermonkey.sh MYFILE` to analyze file MYFILE.

dockermonkey.sh wil automatically pull down a preconfigured docker container, update ViperMonkey to
the latest version in the container, and then analyze MYFILE by running ViperMonkey in the
container. No other packages or configuration will need to be performed.

For information on using dockermonkey.sh run `docker/dockermonkey.sh -h`.

**Installation using PyPy (recommended)**

For performance reasons, it is highly recommended to use PyPy (5x faster), but it is
also possible to run Vipermonkey with the normal Python interpreter
(CPython) if you cannot use PyPy.

1. If PyPy is not installed on your system, see http://pypy.org/download.html and download **PyPy 2.7**. (not 3.x)
2. Check if pip is installed for pypy: run `pypy -m pip`
3. If pip is not installed yet, run `pypy -m ensurepip` on Windows, or `sudo -H pypy -m ensurepip` on Linux/Mac
4. Make sure pip is up-to-date, by running `pypy -m pip install -U pip`
5. Download the archive from the repository: https://github.com/decalage2/ViperMonkey/archive/master.zip
6. Extract it in the folder of your choice, and open a shell/cmd window in that folder.
7. Under Ubuntu install pypy-dev (sudo apt-get install pypy-dev).
8. Install dependencies by running `pypy -m pip install -U -r requirements.txt` on Windows, or `sudo -H pypy -m pip install -U -r requirements.txt` on Linux/Mac
9. Check that Vipermonkey runs without error: `pypy vmonkey.py`

**Installation using CPython**

1. Make sure you have the latest Python 2.7 installed: https://www.python.org/downloads/
2. If you have both Python 2 and 3 versions installed, use `pip2` instead of `pip` in the 
   following commands, to install in Python 2 and not 3.
4. Make sure pip is up-to-date, by running `pip install -U pip`
2. Use pip to download and install vipermonkey with all its dependencies,
   by running the following command on Windows:
```
pip install -U https://github.com/decalage2/ViperMonkey/archive/master.zip
```
On Linux/Mac:
```
sudo -H pip install -U https://github.com/decalage2/ViperMonkey/archive/master.zip
```
3. Check that Vipermonkey runs without error: open a shell/cmd window
   in any directory, an simply run `vmonkey`


Usage:
------

To run ViperMonkey in a Docker container with the `-s`, `--jit`, and
`--iocs` options do:

```text
docker/dockermonkey.sh <file>
```

To parse and interpret VBA macros from a document, use the vmonkey script:

```text
vmonkey.py <file>
```

To make analysis faster (see the Speedup section), do:

```text
pypy vmonkey.py -s <file>
```

*Note:* It is recommended to always use the `-s` option. When given
 the `-s` option ViperMonkey modifies some difficult to parse Visual
 Basic language constructs so that the ViperMonkey parser can
 correctly parse the input.

If the output is too verbose and too slow, you may reduce the logging level using the
-l option:

```text
vmonkey.py -l warning <file>
```

If the sample being analyzed has long running loops that are causing
emulation to be unacceptably slow, use the `--jit` option to convert
VB loops directly to Python in a JIT fashion during emulation.

```text
vmonkey.py --jit <file>
```

*Note:* ViperMonkey's Python JIT loop conversion converts VB loops to
 Python and `evals` the generated Python code. While the Python
 conversion process is based on the parsed AST (not directly on the VB
 text) and VB data values are escaped/converted/modified to become
 valid in Python, any use of `eval` in Python potentially introduces a
 security risk. If this is a concern the `dockermonkey.sh` script can be
 used to run ViperMonkey in a sandboxed manner. `dockermonkey.sh` runs
 ViperMonkey in a fresh Docker container on each run (no file system
 modifications persist between runs) and networking is turned off in
 the Docker container.

Sometimes a malicious VBScript or Office file will generate IOCs
during execution that are not used or that ViperMonkey does not see
used. These intermediate IOCs are tracked by ViperMonkey during the
emulation process and can be reported with the `--iocs` option.

```text
vmonkey --iocs <file>
```

Note that one of the intermediate IOCs reported by ViperMonkey is
injected shell code bytes. If the sample under analysis performs
process injection directly in VB, ViperMonkey will report the injected
byte values as an intermediate IOC with the `--iocs` flag. These byte
values can then be written into a raw shell code file which can be
further analyzed with a shell code emulator.

**oletools Version**

ViperMonkey requires the most recent version of
[oletools](https://github.com/decalage2/oletools), at least v0.52.3. Make sure to either install the most recent oletools
version by running `pip install -U oletools`, or make sure
the most recent oletools install directory appears in PYTHONPATH, or
install the most recent development version of oletools using pip as described
[here](https://github.com/decalage2/oletools/wiki/Install#how-to-install-the-latest-development-version). 

**Speedup**

***pypy***

The parsing library used by default in ViperMonkey can take a long
time to parse some samples. ViperMonkey can be sped up considerably (~5
times faster) by running ViperMonkey using [pypy](https://pypy.org/)
rather than the regular Python interpreter. To use pypy do the
following:

1. Install pypy following the instructions [here](https://pypy.org/download.html).
2. Install the following Python packages. This can be done by
   downloading the .tar.gz for each package and running 'sudo pypy
   setup.py install' (note the use of pypy rather than python) for
   each package.
   1. [setuptools](https://pypi.python.org/pypi/setuptools)
   2. [colorlog](https://pypi.python.org/pypi/colorlog)
   3. [olefile](https://pypi.python.org/pypi/olefile)
   4. [prettytable](https://pypi.python.org/pypi/PrettyTable)
   5. [pyparsing](https://pypi.python.org/pypi/pyparsing/2.2.0)

***Stripping Useless Statements***

The "-s" ViperMonkey command line option tells VipeMonkey to strip out
useless statements from the Visual Basic macro code prior to parsing
and emulation. For some maldocs this can significantly speed up
analysis.

**Emulating File Writes**

ViperMonkey emulates some file writing behavior. The SHA256 hash of
dropped files is reported in the ViperMonkey analysis results and the
actual dropped files are saved in the directory MALDOC_artifacts/,
where MALDOC is the name of the analyzed maldoc file.

ViperMonkey also searches Office 97 and Office 2007+ files for
embedded PE files. These are automatically extracted and reported as
dropped files in the MALDOC_artifacts/ directory.

**Emulating Specific VBA Functions**

By default ViperMonkey emulates maldoc behavior starting from standard
macro auto run function (like AutoOpen, Document_Open, Document_Close,
etc.). In some cases you may want to emulate the behavior starting
from a non-standard auto run function. This is supported via the -i
command line option. To emulate maldoc behavior starting from function
Foo, use the command line option '-i Foo'. To emulate behavior
starting from multiple non-standard entry points, use the command line
option '-i "Foo,Bar,Baz"' (note that the entry point function names
are comma seperated and must appear in a double quoted string).


[//]: # (Home page http://www.decalage.info/vipermonkey)
[//]: # (Documentation https://github.com/decalage2/ViperMonkey/wiki)
[//]: # (Download/Install https://github.com/decalage2/ViperMonkey/wiki/Install)


API Interface:
--------------

ViperMonkey also includes a Python API interface that can be used for
 finer control emulation of your sample or for integration 
 into an existing project.

Please see the [API Tutorial](docs/APITutorial.md) for more information.


News
----

- **2018-03-22 v0.06**: new features and bug fixes contributed by Kirk Sayre
- 2018-3:
  - Added support for parsing some technically invalid VBA statements.
  - Additional parsing fixes.
  - Added support for starting emulation at non-standard functions.
- 2018-2:
  - Added support for Environ, IIf, Base64DecodeString, CLng, Close, Put, Run, InStrRev,
    LCase, RTrim, LTrim, AscW, AscB, and CurDir functions.
- 2018-1
  - Added emulation support for saving dropped files.
  - Added support for For Each loops.
  - Added support for While Wend loops.
  - Handle 'Exit Do' instructions.
- 2018-01-12 v0.05: a lot of new features and bug fixes contributed by Kirk Sayre
- 2017-12-15:
  - Added support for Select and Do loops.
  - Added support for 'End Sub' and 0 argument return statements.
  - Added support for #if constructs.
  - Each VBA stream is now parsed in a separate thread (up to the # of machine cores).
- 2017-11-28:
  - Added parsing for private type declarations.
  - Report calls to CreateProcessA in final report.
  - Handle Application.Run() of locally defined methods.
- 2017-11-23:
  - Added VBA functions Abs, Fix, Hex, String, CByte, Atn, Dir, RGB, Log, Cos, Exp, Sin, Str, and Val.
  - Added support for 'Exit Function' operator.
  - Changed math operators to also work with string representations of integers.
  - Added a configurable iteration limit on loops.
- 2017-11-14:
  - Added support for InStr, Replace, Sgn, Sqr, UBound, LBound, Trim, StrConv, Split, StrReverse, and Int VB functions.
  - Added support for string character subscripting.
  - Added support for negative integer literals.
  - Added support for if-then-else statements.
  - Added support for Const and initial values for global variable declarations.
  - Handle assignments of boolean expressions to variables.
- 2017-11-03:
  - Added support for Left(), Right(), Array(), and BuiltInDocumentProperties() functions.
  - Added support for global variables.
  - Fixed some parse errors.
  - Added analysis of AutoClose() functions.
- 2016-09-26 v0.02: First published version
- 2015-02-28 v0.01: [First development version](https://twitter.com/decalage2/status/571778745222242305)
- see changelog in source code for more info.

How to Suggest Improvements, Report Issues or Contribute:
---------------------------------------------------------

This is a personal open-source project, developed on my spare time. Any contribution, suggestion, feedback or bug
report is welcome.

To suggest improvements, report a bug or any issue, please use the
[issue reporting page](https://github.com/decalage2/ViperMonkey/issues), providing all the
information and files to reproduce the problem.

You may also [contact the author](http://decalage.info/contact) directly to provide feedback.

The code is available in [a GitHub repository](https://github.com/decalage2/ViperMonkey). You may use it
to submit enhancements using forks and pull requests.

License
-------

This license applies to the ViperMonkey package, apart from the thirdparty folder which contains third-party files
published with their own license.

The ViperMonkey package is copyright (c) 2015-2020 Philippe Lagadec (http://www.decalage.info)

All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

