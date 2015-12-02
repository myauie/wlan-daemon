#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <util.h>
#include <netinet/if_ether.h>

#include "configreader.h"
#include "configreader_yacc.h"

// const char config_file[] = "/etc/wlan-daemon";
const char config_file[] = "./config"; // debugging

int configreaderparse();

int parse_config()
{
    FILE *fp = fopen(config_file, "r");

    if (!fp)
        return 1;

    configreaderin = fp;
    configreaderparse();
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

int open_socket(int domain) {
    printf("socket domain: %d\n", domain);
    return socket(domain, SOCK_DGRAM, 0);
}

// based on ieee80211_listnodes() from ifconfig 
struct config_ssid *first_matching_network(struct ifaddrs *target) {
    struct config_interfaces *config = find_config(target->ifa_name);
    struct ieee80211_nodereq_all na;
    struct ieee80211_nodereq nr[512];
    struct ifreq ifr;
    char name[IEEE80211_NWID_LEN];
    int i, s, len;

    // open socket and scan for wlans
    bzero(&ifr, sizeof(ifr));
    strlcpy(ifr.ifr_name, target->ifa_name, sizeof(ifr.ifr_name));

    s = open_socket(AF_INET);

    if (s < 0)
        return NULL;

    if (ioctl(s, SIOCS80211SCAN, (caddr_t)&ifr) != 0) {
        printf("error scanning: %s\n", strerror(errno));
        close(s);
        return NULL;
    }

    bzero(&na, sizeof(na));
    bzero(&nr, sizeof(nr));
    na.na_node = nr;
    na.na_size = sizeof(nr);
    strlcpy(na.na_ifname, target->ifa_name, sizeof(na.na_ifname));
    if (ioctl(s, SIOCG80211ALLNODES, &na) != 0) {
        printf("error retrieving nodes: %s\n", strerror(errno));
        close(s);
        return NULL;
    }

    close(s);

    if (!na.na_nodes) {
        printf("no nodes\n");
        return NULL;
    }

    // if a wlan we want is found, return
    for (i = 0; i < na.na_nodes; i++) {
        len = nr[i].nr_nwid_len > IEEE80211_NWID_LEN? IEEE80211_NWID_LEN: nr[i].nr_nwid_len;
        snprintf(name, IEEE80211_NWID_LEN, "%.*s", len, nr[i].nr_nwid);
        struct config_ssid *cur = config->ssids;
        // cur->ssid_bssid =
        // cur->ssid_wpamode =
        while (cur) {
            if (strcmp(cur->ssid_name,name) == 0)
                // do all the stuff
                return cur;
            cur = cur->next;
        }
    }
    return NULL;
}

// code lifted from ifconfig
const char *get_string(const char *val, const char *sep, u_int8_t *buf, int *lenp)
{
    // converted hex value into string
    int len = *lenp, hexstr;
    u_int8_t *p = buf;

    hexstr = (val[0] == '0' && tolower((u_char)val[1]) == 'x');
    if (hexstr)
        val += 2;
    for (;;) {
        if (*val == '\0')
            break;
        if (sep != NULL && strchr(sep, *val) != NULL) {
            val++;
            break;
        }
        if (hexstr) {
            if (!isxdigit((u_char)val[0]) ||
                    !isxdigit((u_char)val[1])) {
                return NULL;
            }
        }
        if (p > buf + len) {
            if (!hexstr)
                return NULL;
        }
        if (hexstr) {
#define	tohex(x)	(isdigit(x) ? (x) - '0' : tolower(x) - 'a' + 10)
            *p++ = (tohex((u_char)val[0]) << 4) |
                    tohex((u_char)val[1]);
#undef tohex
            val += 2;
        } else {
            if (*val == '\\' &&
                    sep != NULL && strchr(sep, *(val + 1)) != NULL)
                val++;
            *p++ = *val++;
        }
    }
    len = p - buf;
    if (len < *lenp)
        memset(p, 0, *lenp - len);
    *lenp = len;
    return val;
}

// based on ifconfig code
int set_network_id(char *network_ssid, struct ifaddrs *target) {
    int s = -1, res, size;
    struct ifreq ifr;
    struct ieee80211_nwid nwid;

    if (!target)
        return 1;

    s = open_socket(AF_INET);

    if (s == -1) {
        printf("socket error: %s\n", strerror(errno));
        return 1;
    }

    size = sizeof(nwid.i_nwid);
    get_string(network_ssid, NULL, nwid.i_nwid, &size);
    nwid.i_len = size;
    strlcpy(ifr.ifr_name, target->ifa_name, sizeof(ifr.ifr_name));
    ifr.ifr_data = (caddr_t)&nwid;

    res = ioctl(s, SIOCS80211NWID, (caddr_t)&ifr);
    close(s);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));

    return res < 0;

}

int set_psk_key(char *network_ssid, char *psk_key, struct ifaddrs *target) {
    printf("%s\n", psk_key);
    int s = -1, res, size;
    struct ieee80211_wpapsk psk;
    struct ieee80211_wpaparams wpa;
    struct ifreq ifr;

    if (!target)
        return 1;

    s = open_socket(AF_INET);

    if (s == -1) {
        printf("socket error: %s\n", strerror(errno));
        return 1;
    }

    memset(&psk, 0, sizeof(psk));
    size = sizeof(psk_key);
    if(size == 2 + 2 * sizeof(psk.i_psk) && psk_key[0] == '0' && psk_key[1] == 'x') {

        // this is wpa hex key
        printf("this is a hex\n");
        get_string(psk_key, NULL, psk.i_psk, &size);

    } else {

        printf("this is a string\n");
        // this is a string
        if(size < 8 || size > 63)
            return 1;
        pkcs5_pbkdf2(psk_key, sizeof(psk_key), (uint8_t*)network_ssid, sizeof(network_ssid), psk.i_psk, sizeof(psk.i_psk), 4096);
    }

    psk.i_enabled = 1;
    //ifr.ifr_data = (caddr_t)&nwid;
    strlcpy(psk.i_name, target->ifa_name, sizeof(psk.i_name));
    ifr.ifr_data = (caddr_t)&psk;
    res = ioctl(s, SIOCS80211WPAPSK, (caddr_t)&psk);
    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));

    strlcpy(wpa.i_name, target->ifa_name, sizeof(wpa.i_name));
    ifr.ifr_data = (caddr_t)&wpa;

    res = ioctl(s, SIOCG80211WPAPARMS, (caddr_t)&wpa);
    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));
    res = ioctl(s, SIOCS80211WPAPARMS, (caddr_t)&wpa);
    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));
    wpa.i_enabled = psk.i_enabled;

    close(s);
    return res < 0;

}

int set_bssid(char *network_bssid, struct ifaddrs *target) {

    int s = -1, res;
    struct ieee80211_bssid bssid;
    struct ether_addr *ea;

    ea = ether_aton(network_bssid);
    memcpy(&bssid.i_bssid, ea->ether_addr_octet, sizeof(bssid.i_bssid));
    strlcpy(bssid.i_name, target->ifa_name, sizeof(bssid.i_name));
    s = open_socket(AF_INET);
    res = ioctl(s, SIOCS80211BSSID, &bssid);
    close(s);

    return 0;

}

int set_wpa8021x() {

    int s = -1;
    struct ieee80211_wpaparams wpa;

    s = open_socket(AF_INET);
    strlcpy(wpa.i_name, target->ifa_name, sizeof(wpa.i_name));
    ifr.ifr_data = (caddr_t)&wpa;
    res = ioctl(s, SIOCG80211WPAPARMS, (caddr_t)&wpa);
    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));
    res = ioctl(s, SIOCS80211WPAPARMS, (caddr_t)&wpa);
    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));
    wpa.i_akms = EEE80211_WPA_AKM_8021X;
    close(s);

    return 0;

}

int start_wpa_supplicant() {

    if(fork() == 0) {

        exec("/etc/wpa_supplicant");

    }

    return 0;

}

int is8021x() {

    return 0;

}

void setup_interface(struct ifaddrs *cur) {
    printf("set up interface: %s\n", cur->ifa_name);

    struct config_ssid *match = first_matching_network(cur);

    if (match) {
        set_network_id((char*)match->ssid_name, cur);
        set_psk_key((char*)match->ssid_name, (char*)match->ssid_pass, cur);

        //if (is8021x) {
        //set_bssid((char*)match->ssid_bssid, cur);
        // set_wpa8021x()
        // start_wpa_supplicant()
        //} else {
    }
}

// if interface is already running, returns 0
int check_interface(struct ifaddrs *cur) {
    //	if (cur->ifa_flags & IFF_RUNNING)
    //		return 0;

    if (find_config(cur->ifa_name))
        return 1;

    return 0;
}

int main(int count, char **options)
{

    int running = 1;

    if (parse_config()) {
        printf("error reading configuration!\n");
        return 1;
    }

    while (running) {
        struct ifaddrs *interfaces, *cur;
        
        int err = getifaddrs(&interfaces); //ask the OS what interfaces are there
        if (err) {
            printf("error getting interfaces: %d\n", err);
            printf("%s\n", strerror(err));
            return err;
        }

        cur = interfaces;
        while (cur) {
            if (check_interface(cur))
                setup_interface(cur);

            cur = cur->ifa_next;
        }
        sleep(10);

        freeifaddrs(interfaces);
    }
    return 0;
}
