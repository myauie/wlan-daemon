%option noyywrap
%option nounput

%{

#include <stdio.h>
#include <string.h>
#include "configreader_yacc.h"

extern YYSTYPE configreaderlval;

%}

%%

\{			return OPEN_BRACE;
\}			return CLOSE_BRACE;
autoipv6		return IPV6AUTO;
user:			return USER;
pass:			return PASS;
\".*\"			{
				configreaderlval.str = (char*)calloc(strlen(configreadertext)-1, sizeof(char));
				strncpy(configreaderlval.str, &configreadertext[1], strlen(configreadertext)-2);
				return STRING;
			}
[A-Za-z0-9_-]*		configreaderlval.str = strdup(configreadertext); return STRING;

%%


