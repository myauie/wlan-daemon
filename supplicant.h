#ifndef SUPPLICANT_H
#define SUPPLICANT_H

#include "config.h"

int start_wpa_supplicant(char* if_name, pid_t supplicant_pid, int flag);
int config_wpa_supplicant(char* if_name, struct config_ssid *match, int toggle);

#endif
