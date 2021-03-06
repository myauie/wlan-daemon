TARGET = wlan-daemon
LEX = lex
YACC = yacc -d
OBJS = lex.yy.o y.tab.o wpa_ctrl.o os_unix.o main.o config.o network.o
OBJS += status.o supplicant.o
LDFLAGS = -lfl -lutil -g
CFLAGS = -std=c99 -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX -g
SC = wlan-client
SCOBJS = client.o

all: $(TARGET) $(SC)

$(TARGET): $(OBJS)
	gcc -o $(TARGET) $(OBJS) $(LDFLAGS)
	
$(SC): $(SCOBJS)
	gcc -o $(SC) $(SCOBJS)	

lex.yy.o: lex.yy.c

y.tab.o: config.h

y.tab.c y.tab.h: configparser.y
	$(YACC) configparser.y

lex.yy.c: configreader.l y.tab.h
	$(LEX) configreader.l

clean:
	rm -f $(TARGET) $(OBJS) $(SC) $(SCOBJS) y.tab.* lex.yy.c
