#ifndef CONFIGREADER_H
#define CONFIGREADER_H
#include <stdbool.h>

/*forward declarations*/
extern FILE *configreaderin;

struct config_ssid {
    char ssid_name[32];
    char ssid_user[32];
    char ssid_pass[32];
    char ssid_bssid[20];
    int8_t ssid_rssi;
    char ssid_auth[10];
    char ssid_eap[40];
    char ssid_key_mgmt[40];
    char ssid_identity[32];
    char ssid_phase2[40];
    bool ipv6_auto;
    char additional_auth_script[50];    
    struct config_ssid *next;
};

struct config_interfaces {
    char if_name[32];
    struct config_ssid *ssids;
    struct config_interfaces *next;
};

    char ncsi_ping[80];

extern struct config_interfaces *config;
extern struct config_interfaces *cur_if;
extern struct config_ssid *cur_ssid;

#endif // CONFIGREADER_H

