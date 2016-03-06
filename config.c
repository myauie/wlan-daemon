#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "y.tab.h"

extern struct config_interfaces *cur_if;
extern struct config_ssid *cur_ssid;
FILE *yyin;
int yyparse();

// const char config_file[] = "/etc/wlan-daemon/wlan-daemon.config";
const char config_file[] = "./wlan-daemon.conf"; // debugging

void clear_ssid(struct config_ssid *ssid) {

    if(!ssid)
        return;

    clear_ssid(ssid->next);
    free(ssid);

}

void clear_config(struct config_interfaces *conf) {

    if(!conf)
        return;

    clear_ssid(conf->ssids);
    clear_config(conf->next);
    free(conf);

}

int parse_config() {

    FILE *fp = fopen(config_file, "r");

    if (!fp)
        return 1;

    config = 0;
    cur_if = 0;
    cur_ssid = 0;

    yyin = fp;
    yyparse();
    fclose(fp);
    struct config_interfaces *cur = config;

    while(cur) {

        printf("config: %s (", cur->if_name);
        struct config_ssid *c2 = cur->ssids;

        while(c2) {

            printf(" %s", c2->ssid_name);
            c2 = c2->next;

        }

        printf( " )\n");
        cur = cur->next;

    }

    return 0;

}


struct config_interfaces *find_config(char *interface) {

    struct config_interfaces *cur = config;

    while(cur) {

        if (strcmp(cur->if_name, interface) == 0)
            return cur;

        cur = cur->next;

    }

    return 0;

}
