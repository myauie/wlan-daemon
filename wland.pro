TEMPLATE = app
CONFIG += console lex yacc
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    main.cpp

HEADERS += \
    configreader.h

LIBS += -lutil

QMAKE_LEX = flex
LEXSOURCES += \
    configreader.l

QMAKE_YACC = bison
YACC_FLAGS = -d
YACCSOURCES += \
    configreader.y

OTHER_FILES += \
    config


