import antlr4
import sys

from vbaLexer import vbaLexer
from vbaListener import vbaListener
from vbaParser import vbaParser

class MyListener(vbaListener):
    def __init__(self):
        pass

    def enterSubStmt(self, ctx):
        for child in ctx.children:
            # Skip all children that aren't AmbiguousIdentifier
            if isinstance(child, vbaParser.AmbiguousIdentifierContext):
            # if type(child).__name__ != 'AmbiguousIdentifierContext':
                name = child.getText()
                print('Sub %r' % name)
            # self.that.globals[name.lower()] = ctx

    def exitSubStmt(self, ctx):
        print('exitSubStmt')

    def enterFunctionStmt(self, ctx):
        for child in ctx.children:
            # Skip all children that aren't AmbiguousIdentifier
            if type(child).__name__ != 'AmbiguousIdentifierContext':
                continue
            name = child.getText()
            print('Function %r' % name)
            # self.that.globals[name.lower()] = ctx

    def enterBlockStmt(self, ctx):
        print('enterBlockStmt:')
        print(ctx.getText())

    def enterLiteral(self, ctx):
        print('enterLiteral:')
        print(ctx.getText())


try:
    filename = sys.argv[1]
except:
    sys.exit('Usage: %s <VBA text file>' % sys.argv[0])

print('Parsing %s' % filename)
print('Lexer')
lexer = vbaLexer(antlr4.FileStream(sys.argv[1]))
print('Stream')
stream = antlr4.CommonTokenStream(lexer)
print('vbaParser')
parser = vbaParser(stream)
print('Parsing from startRule')
tree = parser.startRule()
print('Walking the parse tree')
listener = MyListener()
walker = antlr4.ParseTreeWalker()
walker.walk(listener, tree)
