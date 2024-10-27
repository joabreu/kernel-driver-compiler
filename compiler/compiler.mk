bin = compiler
obj-y = parser.tab.o parser.lex.o main.o stack.o syntax.o
ccflags-y = -Wno-unused-function
ldflags-y = -lz -llzma
