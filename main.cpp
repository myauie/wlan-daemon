#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <net/if_media.h>
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
const struct ifmedia_description ifm_type_descriptions[] = IFM_TYPE_DESCRIPTIONS;

int configreaderparse();

int parse_config() {

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

        while (cur) {

            if (strcmp(cur->ssid_name,name) == 0) {

                // get data we need from scan; bssid, wpa mode
                if(is8021x(nr)) {

                    ether_ntoa((struct ether_addr*)nr->nr_bssid);

                    //bssid
                    //wpa mode

                }
                return cur;
            }
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

int set_psk_key(char *nwid, char *psk_key, struct ifaddrs *target) {

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
    size = strlen(psk_key);
    if(size == 2 + 2 * sizeof(psk.i_psk) && psk_key[0] == '0' && psk_key[1] == 'x') {

        // already a wpa hex key
        get_string(psk_key, NULL, psk.i_psk, &size);

    } else {

        // this is a string
        if(size < 8 || size > 63)
            return 1;
        pkcs5_pbkdf2(psk_key, size, (uint8_t*)nwid, strlen(nwid), psk.i_psk, sizeof(psk.i_psk), 4096);

    }

    psk.i_enabled = 1;
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

    //    int s = -1;
    //    struct ieee80211_wpaparams wpa;

    //    s = open_socket(AF_INET);
    //    strlcpy(wpa.i_name, target->ifa_name, sizeof(wpa.i_name));
    //    ifr.ifr_data = (caddr_t)&wpa;
    //    res = ioctl(s, SIOCG80211WPAPARMS, (caddr_t)&wpa);
    //    if (res)
    //        printf("res: %d (%s)\n", res, strerror(errno));
    //    res = ioctl(s, SIOCS80211WPAPARMS, (caddr_t)&wpa);
    //    if (res)
    //        printf("res: %d (%s)\n", res, strerror(errno));
    //    wpa.i_akms = EEE80211_WPA_AKM_8021X;
    //    close(s);

    return 0;

}

int start_wpa_supplicant() {

    //    if(fork() == 0) {

    //        exec("/etc/wpa_supplicant");

    //    }

    return 0;

}

void start_dhclient(struct ifaddrs *target) {

    char command[50];
    sprintf(command, "dhclient %s", target->ifa_name);
    printf("%s\n", command);
    system(command);
    printf("finished with dhclient\n");

}

void setup_wlaninterface(struct ifaddrs *cur) {

    printf("setting up interface: %s\n", cur->ifa_name);
    struct config_ssid *match = first_matching_network(cur);

    if (match) {

        printf("network found: %s\n", match->ssid_name);
        set_network_id((char*)match->ssid_name, cur);

        if (match->ssid_8021x) {

            set_bssid((char*)match->ssid_bssid, cur);
            set_wpa8021x();
            start_wpa_supplicant();

        } else {

            set_psk_key((char*)match->ssid_name, (char*)match->ssid_pass, cur);

        }

        start_dhclient(cur);

    }

}

void setup_ethernetinterface(struct ifaddrs *cur) {

    // do all the stuff

}


// if interface is already running, returns 0
int check_interface(struct ifaddrs *cur) {

    //    if (cur->ifa_flags & IFF_RUNNING) {
    //        printf("%s already running\n", cur->ifa_name);
    //        return 1;
    //    }

    if (find_config(cur->ifa_name))
        return 1;

    return 0;

}

int is8021x(ieee80211_nodereq node) {

    // check if network requires 802.1x authentication
    if (node->nr_rsnakms & IEEE80211_WPA_AKM_8021X || node->nr_rsnakms & IEEE80211_WPA_AKM_SHA256_8021X)
        return 1;

    return 0;

}

const char * mediatype(char *interface) {

    struct ifmediareq ifmr;
    const struct ifmedia_description *desc;
    int *media_list, s;

    (void) memset(&ifmr, 0, sizeof(ifmr));
    (void) strlcpy(ifmr.ifm_name, interface, sizeof(ifmr.ifm_name));
    media_list = (int*)calloc(ifmr.ifm_count, sizeof(int));
    ifmr.ifm_ulist = media_list;
    s = open_socket(AF_INET);

    if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0)
        printf("SIOCGIFMEDIA");

    close(s);
    free(media_list);

    for (desc = ifm_type_descriptions; desc->ifmt_string != NULL; desc++) {

        if (IFM_TYPE(ifmr.ifm_current) == desc->ifmt_word)
            return (desc->ifmt_string);

    }

    return ("<unknown type>");

}

int main(int count, char **options) {

    int running = 1;

    if (parse_config()) {
        printf("error reading configuration!\n");
        return 1;
    }

    while (running) {

        struct ifaddrs *interfaces, *cur;

        // ask the OS what interfaces are there
        int err = getifaddrs(&interfaces);

        if (err) {

            printf("error getting interfaces: %d\n", err);
            printf("%s\n", strerror(err));
            return err;

        }

        cur = interfaces;
        while (cur) {

            if (check_interface(cur)) {

                printf("media type: %s\n", mediatype(cur->ifa_name));

                if(strcmp(mediatype(cur->ifa_name), "Ethernet") == 0) {

                    setup_ethernetinterface(cur);

                } else if(strcmp(mediatype(cur->ifa_name), "IEEE802.11") == 0) {

                    setup_wlaninterface(cur);

                }
            }

            cur = cur->ifa_next;
        }

        printf("Sleeping...\n");
        sleep(10);
        freeifaddrs(interfaces);
        printf("restarto\n");

    }

    return 0;

}
