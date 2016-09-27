ViperMonkey
===========

ViperMonkey is a VBA Emulation engine written in Python, designed to analyze
and deobfuscate malicious VBA Macros contained in Microsoft Office files
(Word, Excel, PowerPoint, Publisher, etc).

**DISCLAIMER**:
- ViperMonkey is a *very* incomplete and experimental VBA Engine. For now it will NOT
handle most real-life macros without errors.
- VBA parsing and emulation is *extremely* slow for now.
- VBA Emulation is hard and complex, because of all the features of the VBA language, of Microsoft
Office applications, and all the DLLs and ActiveX objects that can be called from VBA.
- This open-source project is only developed on my scarce spare time, so do not expect
miracles. Any help from you will be very appreciated!


**Quick links:**
[Home page](http://www.decalage.info/vipermonkey) -
[Download/Install](https://github.com/decalage2/ViperMonkey/wiki/Install) -
[Documentation](https://github.com/decalage2/ViperMonkey/wiki) -
[Report Issues/Suggestions/Questions](https://github.com/decalage2/ViperMonkey/issues) -
[Contact the Author](http://decalage.info/contact) -
[Repository](https://github.com/decalage2/ViperMonkey) -
[Updates on Twitter](https://twitter.com/decalage2)


News
----

- **2016-09-26 v0.02**: First published version
- 2015-02-28 v0.01: [First development version](https://twitter.com/decalage2/status/571778745222242305)
- see changelog in source code for more info.



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

If the output is too verbose and too slow, you may reduce the logging level using the
-l option:

```text
python vmonkey.py -l info <file>
```


Documentation:
--------------

The latest version of the documentation can be found [online](https://github.com/decalage2/ViperMonkey/wiki), otherwise
a copy is provided in the doc subfolder of the package.


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

