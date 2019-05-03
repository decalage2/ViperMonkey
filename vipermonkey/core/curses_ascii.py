# Code borrowed from the Python standard library curses/ascii because it cannot
# be imported on Windows:
def _ctoi(c):
    if type(c) == type(""):
        return ord(c)
    else:
        return c

def isalnum(c): return isalpha(c) or isdigit(c)
def isalpha(c): return isupper(c) or islower(c)
def isascii(c): return 0 <= _ctoi(c) <= 127          # ?
def isblank(c): return _ctoi(c) in (9, 32)
def iscntrl(c): return 0 <= _ctoi(c) <= 31 or _ctoi(c) == 127
def isdigit(c): return 48 <= _ctoi(c) <= 57
def isgraph(c): return 33 <= _ctoi(c) <= 126
def islower(c): return 97 <= _ctoi(c) <= 122
def isprint(c): return 32 <= _ctoi(c) <= 126
def ispunct(c): return isgraph(c) and not isalnum(c)
def isspace(c): return _ctoi(c) in (9, 10, 11, 12, 13, 32)
def isupper(c): return 65 <= _ctoi(c) <= 90
def isxdigit(c): return isdigit(c) or \
    (65 <= _ctoi(c) <= 70) or (97 <= _ctoi(c) <= 102)
def isctrl(c): return 0 <= _ctoi(c) < 32
def ismeta(c): return _ctoi(c) > 127

