%{
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "config.h"

void yyerror(const char *str);

// forward declarations
extern int poll_wait;
int yylex();
int yylineno;

// parser structures
struct config_interfaces *cur_if = 0;
struct config_ssid *cur_ssid = 0;


%}

%union {
    char *str;
    int num;
};

%token STRING OPEN_BRACE CLOSE_BRACE PASS IPV6AUTO EAP KEY IDENTITY ANONYMOUS PHASE1 PHASE2
%token GROUP PAIRWISE CA_CERT CLIENT_CERT PRIVATE_KEY PRIVATE_KEY_PW EAPOL_FLAGS PING SCRIPT POLL 
%token TLS TTLS PEAP MD5 NUMBER CCMP TKIP WPA_EAP IEEE8021X
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
		memset(nxt, 0, sizeof(*nxt));
		if (!cur_if) {
			config = nxt; // obviously the first one
		} else {
			cur_if->next = nxt;
		}
		cur_if = nxt;
		cur_ssid = 0;
		strlcpy(cur_if->if_name, $1, 32);
	}	

ssid_set: ssid_set ssid_item | ssid_item

ssid_item: ipv6 | ssid_spec

ipv6: IPV6AUTO
        {
               cur_if->ipv6_auto = 1;
        }

ssid_spec: ssid_name OPEN_BRACE ssid_options CLOSE_BRACE | ssid_name OPEN_BRACE CLOSE_BRACE

ssid_name: STRING
	{
		struct config_ssid *nxt = (struct config_ssid *)
					  malloc(sizeof(struct config_ssid));
		memset(nxt, 0, sizeof(*nxt));
		if (!cur_ssid) {
			cur_if->ssids = nxt;
		} else {
			cur_ssid->next = nxt;
		}
		cur_ssid = nxt;
                strlcpy(cur_ssid->ssid_name, $1, 32);
	}
    
ssid_options: ssid_options ssid_option | ssid_option
    
ssid_option: password | identity | anonymous | eap | key_mgmt
    | phase1 | phase2 | script | group | pairwise | ca_cert | client_cert
    | private_key | private_key_passwd | eapol_flags
	
password: PASS STRING
	{
                strlcpy(cur_ssid->ssid_pass, $2, 32);
	}

identity: IDENTITY STRING
        {
                strlcpy(cur_ssid->ssid_identity, $2, 32);
        }
        
anonymous: ANONYMOUS STRING
        {
                strlcpy(cur_ssid->ssid_anonymous, $2, 32);
        }

eap: EAP eaptypes

eaptypes: eaptypes eaptype | eaptype

eaptype: tls | ttls | peap | md5

tls: TLS
        {
            if(strlen(cur_ssid->ssid_eap) > 0)
                strlcat(cur_ssid->ssid_eap, " ", 40);
            strlcat(cur_ssid->ssid_eap, "TLS", 40);        
        }

ttls: TTLS
        {
            if(strlen(cur_ssid->ssid_eap) > 0)
                strlcat(cur_ssid->ssid_eap, " ", 40);
            strlcat(cur_ssid->ssid_eap, "TTLS", 40);
        }
        
peap: PEAP
        {
            if(strlen(cur_ssid->ssid_eap) > 0)
                strlcat(cur_ssid->ssid_eap, " ", 40);
            strlcat(cur_ssid->ssid_eap, "PEAP", 40);
        }
        
md5: MD5
        {
            if(strlen(cur_ssid->ssid_eap) > 0)
                strlcat(cur_ssid->ssid_eap, " ", 40);
            strlcat(cur_ssid->ssid_eap, "MD5", 40);
        }

key_mgmt: KEY keytypes

keytypes: keytypes keytype | keytype

keytype: wpa_eap | ieee8021x

wpa_eap: WPA_EAP
        {
            if(strlen(cur_ssid->ssid_key_mgmt) > 0)
                strlcat(cur_ssid->ssid_key_mgmt, " ", 40);
            strlcat(cur_ssid->ssid_key_mgmt, "WPA-EAP", 40);
        }
        
ieee8021x: IEEE8021X
        {
            if(strlen(cur_ssid->ssid_key_mgmt) > 0)
                strlcat(cur_ssid->ssid_key_mgmt, " ", 40);
            strlcat(cur_ssid->ssid_key_mgmt, "IEEE8021X", 40);
        }

        
phase1: PHASE1 STRING
        {
                strlcpy(cur_ssid->ssid_phase1, $2, 40);
        }        
        
phase2: PHASE2 STRING
        {
                strlcpy(cur_ssid->ssid_phase2, $2, 40);
        }
        
script: SCRIPT STRING
        {
                strlcpy(cur_ssid->additional_auth_script, $2, 50);    
        }            

group: GROUP grouptypes

grouptypes: grouptypes grouptype | grouptype

grouptype: ccmp | tkip

ccmp: CCMP
        {
            if(strlen(cur_ssid->ssid_group) > 0)
                strlcat(cur_ssid->ssid_group, " ", 15);
            strlcat(cur_ssid->ssid_group, "CCMP", 15);          
        }
        
tkip: TKIP
        {
            if(strlen(cur_ssid->ssid_group) > 0)
                strlcat(cur_ssid->ssid_group, " ", 15);
            strlcat(cur_ssid->ssid_group, "TKIP", 15);         
        }

pairwise: PAIRWISE pairwisetypes

pairwisetypes: pairwisetypes pairwisetype | pairwisetype

pairwisetype: ccmp | tkip

ccmp: CCMP
        {
            if(strlen(cur_ssid->ssid_pairwise) > 0)
                strlcat(cur_ssid->ssid_pairwise, " ", 15);
            strlcat(cur_ssid->ssid_pairwise, "CCMP", 15);        
        }

tkip: TKIP
        {
            if(strlen(cur_ssid->ssid_pairwise) > 0)
                strlcat(cur_ssid->ssid_pairwise, " ", 15);
            strlcat(cur_ssid->ssid_pairwise, "TKIP", 15);         
        }

ca_cert: CA_CERT STRING
        {
                strlcpy(cur_ssid->ssid_ca_cert, $2, 50);        
        }

client_cert: CLIENT_CERT STRING
        {
                strlcpy(cur_ssid->ssid_client_cert, $2, 50);        
        }

private_key: PRIVATE_KEY STRING
        {
                strlcpy(cur_ssid->ssid_private_key, $2, 50);        
        }

private_key_passwd: PRIVATE_KEY_PW STRING
        {
                strlcpy(cur_ssid->ssid_private_key_pwd, $2, 50);        
        }
        
eapol_flags: EAPOL_FLAGS NUMBER
        {
                cur_ssid->ssid_eapol = (int *) malloc(sizeof(int));
                *cur_ssid->ssid_eapol = $2;
        }
%%

void yyerror(const char *str) {
	printf("line %d error: %s", yylineno, str);
	exit(1);
}

struct config_interfaces *config = 0;

