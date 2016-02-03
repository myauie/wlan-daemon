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
    char ssid_auth[10];
    char ssid_eap[40];
    char ssid_key_mgmt[20];
    char ssid_identity[32];
    bool ipv6_auto;
    struct config_ssid *next;
};

struct config_interfaces {
    char if_name[32];
    struct config_ssid *ssids;
    struct config_interfaces *next;
};

extern struct config_interfaces *config;

#endif // CONFIGREADER_H

