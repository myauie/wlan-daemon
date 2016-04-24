#ifndef CONFIGREADER_H
#define CONFIGREADER_H

#include <stdio.h>

/* forward declarations */
extern FILE    *configreaderin;

struct config_ssid {
	char 		ssid_name[32];
	char 		ssid_user[32];
	char 		ssid_pass[32];
	char 		ssid_bssid[20];
	int8_t 		ssid_rssi;
	char 		ssid_auth[10];
	char 		ssid_eap [40];
	char 		ssid_key_mgmt[40];
	char 		ssid_identity[32];
	char 		ssid_phase1[40];
	char 		ssid_phase2[40];
	char 		ssid_group[15];
	char 		ssid_pairwise[15];
	char 		ssid_ca_cert[50];
	char 		ssid_client_cert[50];
	char 		ssid_private_key[50];
	char 		ssid_private_key_pwd[50];
    char        ssid_anonymous[50];
    int        *ssid_eapol;
	char 		additional_auth_script[50];
	struct config_ssid *next;
};

struct config_interfaces {
	char 		if_name  [32];
	struct config_ssid *ssids;
	struct config_interfaces *next;
	int 		ipv6_auto;
	int 		supplicant_pid;
	int 		additional_auth_exec;
};

pid_t 		supplicant_pid;
char 		ncsi_ping[80];

extern const char config_file[];
extern struct config_interfaces *config;

void 		clear_ssid(struct config_ssid *);
void 		clear_config(struct config_interfaces *);
int 		parse_config();
struct config_interfaces *find_config(char *);

#endif	/* CONFIGREADER_H */
