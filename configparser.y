%{
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "configreader.h"

void yyerror(const char *str);

// forward declarations
struct config_interfaces *cur_if = 0;
struct config_ssid *cur_ssid = 0;
int yylex();

%}

%union {
    char *str;
};

%token STRING OPEN_BRACE CLOSE_BRACE USER PASS IPV6AUTO EAP KEY IDENTITY PHASE2 PING
%type <str> STRING

%%
config: config interface_set | interface_set
    
interface_set: interface_name OPEN_BRACE ssid_set CLOSE_BRACE
    
interface_name: STRING          
	{
		struct config_interfaces *nxt = (struct config_interfaces *)
						malloc(sizeof(struct config_interfaces));
		if (!cur_if) {
			config = nxt; // obviously the first one
		} else {
			cur_if->next = nxt;
		}
		cur_if = nxt;
		cur_ssid = 0;
		strlcpy(cur_if->if_name, $1, 32);
	}
    
ssid_set: ssid_set ssid_spec | ssid_spec
    
ssid_spec: ssid_name OPEN_BRACE ssid_options CLOSE_BRACE

ssid_name: STRING
	{
		struct config_ssid *nxt = (struct config_ssid *)
					  malloc(sizeof(struct config_ssid));
		if (!cur_ssid) {
			cur_if->ssids = nxt;
		} else {
			cur_ssid->next = nxt;
		}
		cur_ssid = nxt;
                strlcpy(cur_ssid->ssid_name, $1, 32);
	}
    
ssid_options: ssid_options ssid_option | ssid_option
    
ssid_option: | user_name | password | identity | eap | key_mgmt | ipv6 | phase2 | ping

user_name: USER STRING
	{
                strlcpy(cur_ssid->ssid_user, $2, 32);
	}
	
password: PASS STRING
	{
                strlcpy(cur_ssid->ssid_pass, $2, 32);
	}

identity: IDENTITY STRING
        {
                strlcpy(cur_ssid->ssid_identity, $2, 32);
        }

eap: EAP STRING
        {
                strlcpy(cur_ssid->ssid_eap, $2, 40);
        }

key_mgmt: KEY STRING
        {
                strlcpy(cur_ssid->ssid_key_mgmt, $2, 40);
        }

ipv6: IPV6AUTO
        {
               cur_ssid->ipv6_auto = true;
        }
        
phase2: PHASE2 STRING
        {
                strlcpy(cur_ssid->ssid_phase2, $2, 40);
        }
        
ping: PING STRING
        {
                strlcpy(cur_ssid->ssid_ping, $2, 80);
        }

%%

void yyerror(const char *str) {
	printf("error: %s", str);
	exit(1);
}

struct config_interfaces *config = 0;

