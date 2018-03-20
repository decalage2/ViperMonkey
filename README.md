ViperMonkey
===========

ViperMonkey is a VBA Emulation engine written in Python, designed to analyze
and deobfuscate malicious VBA Macros contained in Microsoft Office files
(Word, Excel, PowerPoint, Publisher, etc).

See my article "[Using VBA Emulation to Analyze Obfuscated Macros](http://decalage.info/vba_emulation)",
for real-life examples of malware deobfucation with ViperMonkey.

**DISCLAIMER**:
- ViperMonkey is an experimental VBA Engine targeted at analyzing maldocs. It works on some but not all maldocs. 
- VBA parsing and emulation is *extremely* slow for now (see the speedup section for how to improve the speed).
- VBA Emulation is hard and complex, because of all the features of the VBA language, of Microsoft
Office applications, and all the DLLs and ActiveX objects that can be called from VBA.
- This open-source project is only developed on my scarce spare time, so do not expect
miracles. Any help from you will be very appreciated!

**oletools Version**

ViperMonkey requires the most recent version of
[oletools](https://github.com/decalage2/oletools), not the version
downloaded by the standard pip install. Make sure to either install the most recent oletools
version by running the oletools 'setup.py install', or make sure
the most recent oletools install directory appears in PYTHONPATH, or
install the most recent version of oletools using pip as described
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

**Quick links:**
[Report Issues/Suggestions/Questions](https://github.com/decalage2/ViperMonkey/issues) -
[Contact the Author](http://decalage.info/contact) -
[Repository](https://github.com/decalage2/ViperMonkey) -
[Updates on Twitter](https://twitter.com/decalage2)

[//]: # (Home page http://www.decalage.info/vipermonkey)
[//]: # (Documentation https://github.com/decalage2/ViperMonkey/wiki)
[//]: # (Download/Install https://github.com/decalage2/ViperMonkey/wiki/Install)

***Emulating File Writes***

ViperMonkey emulates some file writing behavior. The SHA256 hash of
dropped files is reported in the ViperMonkey analysis results and the
actual dropped files are saved in the directory MALDOC_artifacts/,
where MALDOC is the name of the analyzed maldoc file.

***Emulating Specific VBA Functions***

By default ViperMonkey emulates maldoc behavior starting from standard
macro auto run function (like AutoOpen, Document_Open, Document_Close,
etc.). In some cases you may want to emulate the behavior starting
from a non-standard auto run function. This is supported via the -i
command line option. To emulate maldoc behavior starting from function
Foo, use the command line option '-i Foo'. To emulate behavior
starting from multiple non-standard entry points, use the command line
option '-i "Foo,Bar,Baz"' (note that the entry point function names
are comma seperated and must appear in a double quoted string).

News
----

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

Download and Install:
---------------------

For now, there is no package on PyPI for automated installation. It must be done manually:

- Download the archive from the repository: https://github.com/decalage2/ViperMonkey/archive/master.zip
- Extract it in the folder of your choice
- Install dependencies by running `sudo -H pip install -U -r requirements.txt` on Linux/Mac
or `pip install -U -r requirements.txt` on Windows

Usage:
------

To parse and interpret VBA macros from a document, use the vmonkey script:

```text
python vmonkey.py <file>
```

To make analysis faster (see the Speedup section), do:

```text
pypy vmonkey.py -s <file>
```

If the output is too verbose and too slow, you may reduce the logging level using the
-l option:

```text
python vmonkey.py -l warning <file>
```

Documentation:
--------------

Winter is coming.


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

The ViperMonkey package is copyright (c) 2015-2016 Philippe Lagadec (http://www.decalage.info)

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

