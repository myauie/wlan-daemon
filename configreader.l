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
autoipv6		return IPV6AUTO;
user:			return USER;
pass:			return PASS;
\".*\"			{
				yylval.str = (char*)calloc(strlen(yytext)-1, sizeof(char));
				strncpy(yylval.str, &yytext[1], strlen(yytext)-2);
				return STRING;
			}
[A-Za-z0-9_-]*		yylval.str = strdup(yytext); return STRING;

%%


