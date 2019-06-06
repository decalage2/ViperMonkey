"""Tests deobfuscation utility."""

from __future__ import print_function

from textwrap import dedent

from vipermonkey.core import deobfuscation


def test_regex():
    """Tests the regular expressions used."""
    # Chr/String concatination run.
    match = deobfuscation.CONCAT_RUN.match('Chr(71 Xor 18) & "2" & Chr(82 Xor 4) + "0" & Chr(70 Xor 15) & Chr(84 Xor 19) & "9"')
    print(match.capturesdict())
    assert match.captures('entry') == [
        'Chr(71 Xor 18)', '"2"', 'Chr(82 Xor 4)', '"0"', 'Chr(70 Xor 15)', 'Chr(84 Xor 19)', '"9"']

    # Setting variable run.
    match = deobfuscation.VAR_RUN.match(dedent('''\
        ZOOP = Chr(123 Xor 11)
        ZOOP = ZOOP & Chr(122 Xor 14)
        ZOOP = ZOOP & Chr(109 Xor 4)
        ZOOP = ZOOP & Chr(99 Xor 13)
        ZOOP = ZOOP & Chr(97 Xor 6)
        ZOOP = ZOOP & Chr(34 Xor 12)
        ZOOP = ZOOP & Chr(67 Xor 5)
        ZOOP = ZOOP & Chr(109 Xor 4)
        ZOOP = ZOOP & Chr(109 Xor 1) + Chr(69) + Chr(81 Xor 2)
        ZOOP = ZOOP & Chr(107 Xor 18)
    '''))
    print(match.capturesdict())
    assert match.group('var') == 'ZOOP'
    assert match.captures('entry') == [
        'Chr(123 Xor 11)', 'Chr(122 Xor 14)', 'Chr(109 Xor 4)', 'Chr(99 Xor 13)', 'Chr(97 Xor 6)',
        'Chr(34 Xor 12)', 'Chr(67 Xor 5)', 'Chr(109 Xor 4)', 'Chr(109 Xor 1) + Chr(69) + Chr(81 Xor 2)',
        'Chr(107 Xor 18)']

    match = deobfuscation.VAR_RUN.match(dedent('''\
        ZAP = ""
        ZAP = ZAP & Chr(80 Xor 19)
        ZAP = ZAP & ":"
        ZAP = ZAP & "\\"
        ZAP = ZAP & Chr(71 Xor 18)
    '''))
    print(match.capturesdict())
    assert match.group('var') == 'ZAP'
    assert match.captures('entry') == ['""', 'Chr(80 Xor 19)', '":"', '"\\"', 'Chr(71 Xor 18)']


def test_replace_concat_run():
    vba_code = dedent('''\
            ZOOP = Chr(123 Xor 11) & Chr(122 Xor 14) & Chr(109 Xor 4) & Chr(99 Xor 13)
            ZOOP = ZOOP & Chr(97 Xor 6) & Chr(34 Xor 12) & Chr(67 Xor 5) & Chr(109 Xor 4)
            ZOOP = ZOOP & Chr(109 Xor 1) + Chr(69) + Chr(81 Xor 2)
            ZOOP = ZOOP & Chr(107 Xor 18)
        ''')
    assert deobfuscation._replace_concat_runs(vba_code) == dedent('''\
            ZOOP = "ptin"
            ZOOP = ZOOP & "g.Fi"
            ZOOP = ZOOP & "lES"
            ZOOP = ZOOP & "y"
        ''')


def test_replace_var_run():
    vba_code = dedent('''\
        ZOOP = Chr(123 Xor 11)
        ZOOP = ZOOP & Chr(122 Xor 14)
        ZOOP = ZOOP & Chr(109 Xor 4)
        ZOOP = ZOOP & Chr(99 Xor 13)
        ZOOP = ZOOP & Chr(97 Xor 6)
        ZOOP = ZOOP & Chr(34 Xor 12)
        ZOOP = ZOOP & Chr(67 Xor 5)
        ZOOP = ZOOP & Chr(109 Xor 4)
        ZOOP = ZOOP & Chr(109 Xor 1) + Chr(69) + Chr(81 Xor 2)
        ZOOP = ZOOP & Chr(107 Xor 18)
    ''')
    print(repr(deobfuscation._replace_var_runs(vba_code)))
    assert deobfuscation._replace_var_runs(vba_code) == (
        'ZOOP = Chr(123 Xor 11) & Chr(122 Xor 14) & Chr(109 Xor 4) & '
        'Chr(99 Xor 13) & Chr(97 Xor 6) & Chr(34 Xor 12) & Chr(67 Xor 5) & Chr(109 Xor 4) '
        '& Chr(109 Xor 1) + Chr(69) + Chr(81 Xor 2) & Chr(107 Xor 18)\n')


def test_deobfucation():
    vba_code = dedent('''\
        ZOOP = Chr(123 Xor 11)
        ZOOP = ZOOP & Chr(122 Xor 14)
        ZOOP = ZOOP & Chr(109 Xor 4)
        ZOOP = ZOOP & Chr(99 Xor 13)
        ZOOP = ZOOP & Chr(97 Xor 6) & Chr(34 Xor 12) & Chr(67 Xor 5) & Chr(109 Xor 4)
        ZOOP = ZOOP & Chr(109 Xor 1) + Chr(69) + Chr(81 Xor 2)
        ZOOP = ZOOP & Chr(107 Xor 18)
    ''')
    assert deobfuscation.deobfuscate(vba_code) == dedent('''\
        ZOOP = "pting.FilESy"
    ''')

    vba_code = dedent('''\
        ZAP = ""
        ZAP = ZAP & Chr(80 Xor 19)
        ZAP = ZAP & ":"
        ZAP = ZAP & "\\"
        ZAP = ZAP & Chr(71 Xor 18)
    ''')
    assert deobfuscation.deobfuscate(vba_code) == dedent('''\
        ZAP = "C:\\U"
    ''')