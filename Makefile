TARGET = wlan-daemon
LEX = lex
YACC = yacc -d
OBJS = lex.yy.o y.tab.o main.o  
LDFLAGS = -lfl -lutil
CFLAGS = -std=c99

all: $(TARGET)

$(TARGET): $(OBJS)
	gcc -o $(TARGET) $(OBJS) $(LDFLAGS)

lex.yy.o: lex.yy.c

y.tab.o: configreader.h

y.tab.c y.tab.h: configparser.y
	$(YACC) configparser.y

lex.yy.c: configreader.l y.tab.h
	$(LEX) configreader.l

clean:
	rm -f $(TARGET) $(OBJS) y.tab.* lex.yy.c
