CC := gcc
LDFLAGS := -ldbghelp
CFLAGS := -std=c99

all: pdbparser.exe

pdbparser.exe: pdbparser.c
	$(CC) -o $@ $^ $(CFLAGS)  $(LDFLAGS)
