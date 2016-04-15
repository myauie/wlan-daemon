%option noyywrap
%option nounput
%option yylineno

%{

#include <stdio.h>
#include <string.h>
#include "y.tab.h"

extern YYSTYPE yylval;

%}

%%

\{			            return OPEN_BRACE;
\}			            return CLOSE_BRACE;
autoipv6	            return IPV6AUTO;
pass:		            return PASS;
eap:                    return EAP;
key_mgmt:               return KEY;
identity:               return IDENTITY;
anonymous_identity:     return ANONYMOUS;
phase1:                 return PHASE1;
phase2:                 return PHASE2;
group:                  return GROUP;
pairwise:               return PAIRWISE;
ca_cert:                return CA_CERT;
client_cert:            return CLIENT_CERT;
private_key:            return PRIVATE_KEY;
private_key_passwd:     return PRIVATE_KEY_PW;
ping:                   return PING;
poll:                   return POLL;
additional_auth_script: return SCRIPT;
PEAP                    return PEAP;
TLS                     return TLS;
TTLS                    return TTLS;
MD5                     return MD5;
CCMP                    return CCMP;
TKIP                    return TKIP;
WPA-EAP                 return WPA_EAP;
IEEE8021X               return IEEE8021X;
[0-9]*          {
                    sscanf(yytext, "%d", &yylval.num);
                    return NUMBER;
                }
\".*\"			{
				yylval.str = (char*)calloc(strlen(yytext)-1, sizeof(char));
				strncpy(yylval.str, &yytext[1], strlen(yytext)-2);
				return STRING;
			}
[^ \t\r\n{}]*		yylval.str = strdup(yytext); return STRING;

%%


