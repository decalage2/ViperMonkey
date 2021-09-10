#!/usr/bin/env python
"""
Installs ViperMonkey using pip, setuptools or distutils

To install this package, run:
    pip install -e .

Or:
    python setup.py install

Installation using pip is recommended, to create scripts to run vmonkey
and vbashell from any directory.
"""

#--- CHANGELOG ----------------------------------------------------------------

# 2016-12-14 v0.04 PL: - replaced scripts by entry points (issue #17)
# 2018-08-17 v0.07 PL: - added required dependency unidecode
# 2021-04-10 v1.0.3 PL: - changed oletools version to >=0.56.1

#--- TODO ---------------------------------------------------------------------


#--- IMPORTS ------------------------------------------------------------------

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

# --- ENTRY POINTS ------------------------------------------------------------

# Entry points to create convenient scripts automatically

entry_points = {
    'console_scripts': [
        'vmonkey=vipermonkey.vmonkey:main',
        'vbashell=vipermonkey.vbashell:main',
    ],
}


setup(
    name="vipermonkey",
    version="1.0.3",
    description=(
        "ViperMonkey is a VBA Emulation engine written in Python, designed to "
        "analyze and deobfuscate malicious VBA Macros contained in Microsoft "
        "Office files (Word, Excel, PowerPoint, Publisher, etc)."),
    long_description=open("README.md").read(),
    install_requires=[
        # oletools from 0.54.2 to 0.56 required cryptography, incompatible with PyPy. oletools 0.56.1+ does not require it anymore.
        # Moreover, oletools 0.56.1+ does not trigger antivirus false positives anymore
        'oletools >= 0.56.1',
        "olefile",
        "prettytable",
        "colorlog",
        "colorama",
        "pyparsing==2.2.0", # pyparsing 2.4.0 triggers a MemoryError on some samples (issue #58). pyparsing 2.3.0 parses some constructs differently and breaks things.
        "unidecode==1.2.0",
        "xlrd",
        # regex is not installable on PyPy+Windows, so we only require it if the platform is not Windows or not PyPy:
        'regex; platform_python_implementation!="PyPy" or platform_system!="Windows"',
    ],
    packages=["vipermonkey", "vipermonkey.core"],
    setup_requires=["pytest-runner"],
    tests_require=["pytest"],
    entry_points=entry_points,
    author="Philippe Lagadec",
    url="https://github.com/decalage2/ViperMonkey",
    license="BSD",
    download_url="https://github.com/decalage2/ViperMonkey",
)
