%{
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "configreader.h"

void yyerror(const char *str);

// forward declarations
struct config_interfaces *cur_if = 0;
struct config_ssid *cur_ssid = 0;
extern int poll_wait;
int yylex();

%}

%union {
    char *str;
    int num;
};

%token STRING OPEN_BRACE CLOSE_BRACE USER PASS IPV6AUTO EAP KEY IDENTITY PHASE2 PING SCRIPT
%token POLL TTLS PEAP NUMBER
%type <str> STRING
%type <num> NUMBER

%%
config: config_item | config_item config

config_item: poll | ncsi | interface_set

poll: POLL NUMBER
    {
    
        poll_wait = $2;
    
    }

ncsi: PING STRING
    {
    
        strlcpy(ncsi_ping, $2, 80);           
    
    }
    
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
    
ssid_spec: ssid_name OPEN_BRACE ssid_options CLOSE_BRACE | ssid_name OPEN_BRACE CLOSE_BRACE

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
    
ssid_option: user_name | password | identity | eap | key_mgmt | ipv6 | phase2 | script

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

eap: EAP eaptypes

eaptypes: eaptypes eaptype | eaptype

eaptype: ttls | peap

ttls: TTLS
        {
        
            if(strlen(cur_ssid->ssid_eap) > 0)
                strlcat(cur_ssid->ssid_eap, " TTLS", sizeof(cur_ssid->ssid_eap));
            else
                snprintf(cur_ssid->ssid_eap, sizeof(cur_ssid->ssid_eap), "TTLS");
        
        }
        
peap: PEAP
        {
        
            if(strlen(cur_ssid->ssid_eap) > 0)
                strlcat(cur_ssid->ssid_eap, " PEAP", sizeof(cur_ssid->ssid_eap));
            else
                snprintf(cur_ssid->ssid_eap, sizeof(cur_ssid->ssid_eap), "PEAP");
        
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
        
script: SCRIPT STRING
        {
                strlcpy(cur_ssid->additional_auth_script, $2, 50);    
        }            

%%

void yyerror(const char *str) {
	printf("error: %s", str);
	exit(1);
}

struct config_interfaces *config = 0;

