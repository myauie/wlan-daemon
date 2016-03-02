TARGET = wlan-daemon
LEX = lex
YACC = yacc -d
OBJS = lex.yy.o y.tab.o wpa_ctrl.o os_unix.o main.o
LDFLAGS = -lfl -lutil
CFLAGS = -std=c99 -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX
SC = wlan-client
SCOBJS = client.o

all: $(TARGET) $(SC)

$(TARGET): $(OBJS)
	gcc -o $(TARGET) $(OBJS) $(LDFLAGS)
	
$(SC): $(SCOBJS)
	gcc -o $(SC) $(SCOBJS)	

lex.yy.o: lex.yy.c

y.tab.o: configreader.h

y.tab.c y.tab.h: configparser.y
	$(YACC) configparser.y

lex.yy.c: configreader.l y.tab.h
	$(LEX) configreader.l

clean:
	rm -f $(TARGET) $(OBJS) $(SC) $(SCOBJS) y.tab.* lex.yy.c
