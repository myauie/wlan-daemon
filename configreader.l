%option noyywrap
%option nounput

%{

#include <stdio.h>
#include <string.h>
#include "y.tab.h"

extern YYSTYPE yylval;

%}

%%

\{			return OPEN_BRACE;
\}			return CLOSE_BRACE;
autoipv6	return IPV6AUTO;
user:		return USER;
pass:		return PASS;
eap:        return EAP;
key-mgmt:   return KEY;
identity:   return IDENTITY;
phase2:     return PHASE2;
ping:       return PING;
\".*\"			{
				yylval.str = (char*)calloc(strlen(yytext)-1, sizeof(char));
				strncpy(yylval.str, &yytext[1], strlen(yytext)-2);
				return STRING;
			}
[A-Za-z0-9\\\[\]=._-]*		yylval.str = strdup(yytext); return STRING;

%%


