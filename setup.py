#!/usr/bin/env python
"""Installs oletools using distutils

Run:
    python setup.py install

to install this package.
"""

from setuptools import setup

setup(
    name="vipermonkey",
    version="0.02",  # not compliant with PEP440, setuptools normalizes to 0.2
    description=(
        "ViperMonkey is a VBA Emulation engine written in Python, designed to "
        "analyze and deobfuscate malicious VBA Macros contained in Microsoft "
        "Office files (Word, Excel, PowerPoint, Publisher, etc)."),
    long_description=open("README.md").read(),
    install_requires=["oletools", "prettytable", "colorlog", "colorama",
                      "pyparsing"],
    packages=["vipermonkey", "vipermonkey.core"],
    scripts=["vipermonkey/vmonkey.py", "vipermonkey/vbashell.py"],
    author="Philippe Lagadec",
    url="http://decalage.info/vba_emulation",
    license="BSD",  # not explicitly mentioned on the project page - but
                    # similar "License" text as in the oletools project, which
                    # has "BSD" as license in setup.py
    download_url="https://github.com/decalage2/ViperMonkey",
)
