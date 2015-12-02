#ifndef CONFIGREADER_H
#define CONFIGREADER_H

/*forward declarations*/
extern FILE *configreaderin;

struct config_ssid {
    char ssid_name[32];
    char ssid_user[32];
    char ssid_pass[32];
    char ssid_bssid[25];
    int ssid_8021x;
    struct config_ssid *next;
};

struct config_interfaces {
    char if_name[32];
    struct config_ssid *ssids;
    struct config_interfaces *next;
};

extern struct config_interfaces *config;

#endif // CONFIGREADER_H

