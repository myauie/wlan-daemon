#ifndef NETWORK_H
#define NETWORK_H

int open_socket(int domain);
const char * mediatype(char *interface);
void set_network_id(char *network_ssid, char * if_name);
int set_wep_key(char *wep_key, char * if_name, int toggle);
int set_psk_key(char *nwid, char *psk_key, char * if_name, int toggle);
void set_bssid(char *network_bssid, char * if_name, int toggle);
void set_wpa8021x(char * if_name, int toggle);
void set_ipv6_auto(char * if_name);

#endif
