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
#include "y.tab.h"

// const char config_file[] = "/etc/wlan-daemon";
const char config_file[] = "./config"; // debugging

int yyparse();
FILE *yyin;
int supplicant_pid = 0;

int parse_config() {

    FILE *fp = fopen(config_file, "r");

    if (!fp)
        return 1;

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

int open_socket(int domain) {

    return socket(domain, SOCK_DGRAM, 0);

}

const char * check_wlan_mode(struct ieee80211_nodereq node) {

    // check if network requires 802.1x authentication
    if (node.nr_rsnakms & IEEE80211_WPA_AKM_8021X || node.nr_rsnakms & IEEE80211_WPA_AKM_SHA256_8021X) {

        printf("is 802.1x\n");
        return "802.1x";

    }

    // check if network requires wpa1 or wpa2 authentication
    if (node.nr_rsnciphers & IEEE80211_WPA_CIPHER_TKIP || node.nr_rsnciphers & IEEE80211_WPA_CIPHER_CCMP) {

        printf("is wpa\n");
        return "wpa";

    }

    return NULL;

}

int network_matches(struct config_interfaces *target, struct config_ssid *match) {

    struct ifreq ifr;
    struct ieee80211_nwid nwid;
    int s = -1;

    s = open_socket(AF_INET);

    if (s < 0) {

        printf("error opening socket: %s\n", strerror(errno));
        return 0;

    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_data = (caddr_t)&nwid;
    strlcpy(ifr.ifr_name, target->if_name, sizeof(ifr.ifr_name));
    ioctl(s, SIOCG80211NWID, (caddr_t)&ifr);
    printf("%s\n", nwid.i_nwid);


    close(s);
    return strcmp((const char*)nwid.i_nwid, match->ssid_name) == 0;

}


int connection_active(struct config_interfaces *target) {

    struct ifmediareq ifmr;
    int s = -1;

    s = open_socket(AF_INET);

    if(s < 0) {

        printf("error opening socket: %s\n", strerror(errno));

    }

    (void) memset(&ifmr, 0, sizeof(ifmr));
    (void) strlcpy(ifmr.ifm_name, target->if_name, sizeof(ifmr.ifm_name));

    if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {

        printf("SIOCGIFMEDIA");
        close(s);
        return 0;

    }

    close(s);

    if (ifmr.ifm_status & IFM_ACTIVE) {

        printf("network is active\n");
        return 1;

    }

    return 0;
}

// based on ieee80211_listnodes() from ifconfig
struct config_ssid *first_matching_network(struct config_interfaces *config) {
    struct ieee80211_nodereq_all na;
    struct ieee80211_nodereq nr[512];
    struct ifreq ifr;
    char name[IEEE80211_NWID_LEN];
    int i, s, len;

    // open socket and scan for wlans
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, config->if_name, sizeof(ifr.ifr_name));
    s = open_socket(AF_INET);

    if (s < 0)
        return NULL;

    if (ioctl(s, SIOCS80211SCAN, (caddr_t)&ifr) != 0) {

        printf("error scanning: %s\n", strerror(errno));
        close(s);
        char command[50];
        snprintf(command, 50, "ifconfig %s up", config->if_name);
        printf("%s\n", command);
        system(command);
        printf("try bringing up interface\n");
        return NULL;

    }

    memset(&na, 0, sizeof(na));
    memset(&nr, 0, sizeof(nr));
    na.na_node = nr;
    na.na_size = sizeof(nr);
    strlcpy(na.na_ifname, config->if_name, sizeof(na.na_ifname));

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
    for(i = 0; i < na.na_nodes; i++) {

        len = nr[i].nr_nwid_len > IEEE80211_NWID_LEN? IEEE80211_NWID_LEN: nr[i].nr_nwid_len;
        snprintf(name, IEEE80211_NWID_LEN, "%.*s", len, nr[i].nr_nwid);
        struct config_ssid *cur = config->ssids;

        while (cur) {

            if (strcmp(cur->ssid_name,name) == 0) {

                // get data we need from scan; bssid, wpa mode
				snprintf(cur->ssid_bssid, sizeof(cur->ssid_bssid), "%.*s", IEEE80211_ADDR_LEN, nr[i].nr_bssid);
				
				if (nr[i].nr_rsnciphers & IEEE80211_WPA_CIPHER_CCMP || nr[i].nr_rsnciphers & IEEE80211_WPA_CIPHER_TKIP)
					strlcpy(cur->ssid_auth, "wpa", sizeof(cur->ssid_auth));
					
				else
					strlcpy(cur->ssid_auth, "wep", sizeof(cur->ssid_auth));

				if (nr[i].nr_rsnakms & IEEE80211_WPA_AKM_8021X || nr[i].nr_rsnakms & IEEE80211_WPA_AKM_SHA256_8021X) {
				
					struct ether_addr ea;

					memcpy(&ea.ether_addr_octet, nr[i].nr_bssid, sizeof(ea.ether_addr_octet));
					strlcpy(cur->ssid_bssid, ether_ntoa(&ea), sizeof(cur->ssid_bssid));
					strlcpy(cur->ssid_auth, "802.1x", sizeof(cur->ssid_auth));
					
				}

                return cur;
            }
			
            cur = cur->next;
			
        }
		
    }

    return NULL;

}

// code lifted from ifconfig
const char *get_string(const char *val, const char *sep, u_int8_t *buf, int *lenp) {

    // convert hex value into string
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

            if (!isxdigit((u_char)val[0]) || !isxdigit((u_char)val[1])) {

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

            if (*val == '\\' && sep != NULL && strchr(sep, *(val + 1)) != NULL)
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
int set_network_id(char *network_ssid, struct config_interfaces *target) {

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
    strlcpy(ifr.ifr_name, target->if_name, sizeof(ifr.ifr_name));
    ifr.ifr_data = (caddr_t)&nwid;
    res = ioctl(s, SIOCS80211NWID, (caddr_t)&ifr);
    close(s);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));

    return res < 0;

}

int set_wep_key(char *wep_key, struct config_interfaces *target) {

    int i, s = -1, res, size;
    struct ieee80211_nwkey nwkey;
    u_int8_t keybuffer[IEEE80211_WEP_NKID][16];

    if (!target)
        return 1;

    s = open_socket(AF_INET);

    if (!s) {
        printf("socket error: %s\n", strerror(errno));
        return 1;
    }

    memset(&nwkey, 0, sizeof(nwkey));
    memset(&keybuffer, 0, sizeof(keybuffer));

    nwkey.i_wepon = IEEE80211_NWKEY_WEP;
    nwkey.i_defkid = 1;

    if (isdigit((unsigned char)wep_key[0]) && wep_key[1] == ':') {

        /* specifying a full set of four keys */
        nwkey.i_defkid = wep_key[0] - '0';
        wep_key += 2;

        for (i = 0; i < IEEE80211_WEP_NKID; i++) {

            size = sizeof(keybuffer[i]);
            get_string(wep_key, ",", keybuffer[i], &size);

            if (wep_key == NULL)
                return 1;

            nwkey.i_key[i].i_keylen = size;
            nwkey.i_key[i].i_keydat = keybuffer[i];

        }

        if (*wep_key != '\0') {

            printf("wep key error: %s\n", strerror(errno));
            return 1;

        }

    } else {

        int j;
        char *tmp = NULL;
        size_t vlen = strlen(wep_key);

        if(sizeof(vlen) == (10 || 26)) {

            // key is a hex, need to remove 0x
            j = asprintf(&tmp, "0x%s", wep_key);

            if (j == -1) {

                printf("memory allocation error: %s\n", strerror(errno));
                return 1;

            }

            wep_key = tmp;

        } else if(sizeof(vlen) == (5 || 13)) {

            // key is a 0xkey or string

        } else {

            printf("wep key length error: %s\n", strerror(errno));
            return 1;

        }

        size = sizeof(keybuffer[0]);
        get_string(wep_key, NULL, keybuffer[0], &size);
        free(tmp);

        if (wep_key == NULL)
            return 1;

        nwkey.i_key[0].i_keylen = size;
        nwkey.i_key[0].i_keydat = keybuffer[0];

    }

    strlcpy(nwkey.i_name, target->if_name, sizeof(nwkey.i_name));
    res = ioctl(s, SIOCS80211NWKEY, (caddr_t)&nwkey);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));

}

int set_psk_key(char *nwid, char *psk_key, struct config_interfaces *target) {

    int s = -1, res, size;
    struct ieee80211_wpapsk psk;
    struct ieee80211_wpaparams wpa;
    struct ifreq ifr;

    if (!target)
        return 1;

    s = open_socket(AF_INET);

    if (!s) {
        printf("socket error: %s\n", strerror(errno));
        return 1;
    }

    memset(&psk, 0, sizeof(psk));
    size = strlen(psk_key);

    if(size == 2 + 2 * sizeof(psk.i_psk) && psk_key[0] == '0' && psk_key[1] == 'x') {

        // already a wpa hex key
        get_string(psk_key, NULL, psk.i_psk, &size);

    } else {

        // this is a string, hash it
        if(size < 8 || size > 63)
            return 1;

        pkcs5_pbkdf2(psk_key, size, (uint8_t*)nwid, strlen(nwid), psk.i_psk, sizeof(psk.i_psk), 4096);

    }

    psk.i_enabled = 1;
    strlcpy(psk.i_name, target->if_name, sizeof(psk.i_name));
    ifr.ifr_data = (caddr_t)&psk;
    res = ioctl(s, SIOCS80211WPAPSK, (caddr_t)&psk);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));

    strlcpy(wpa.i_name, target->if_name, sizeof(wpa.i_name));
    ifr.ifr_data = (caddr_t)&wpa;

    res = ioctl(s, SIOCG80211WPAPARMS, (caddr_t)&wpa);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));

    wpa.i_enabled = psk.i_enabled;
    res = ioctl(s, SIOCS80211WPAPARMS, (caddr_t)&wpa);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));

    close(s);
    return res < 0;

}

int set_bssid(char *network_bssid, struct config_interfaces *target) {

    int s = -1, res;
    struct ieee80211_bssid bssid;
    struct ether_addr *ea;

	printf("set bssid: %s\n", network_bssid);
    ea = ether_aton(network_bssid);

    if (!ea) {

		printf("invalid ethernet address: %s\n", network_bssid);
        return 1;

    }

    memcpy(&bssid.i_bssid, ea->ether_addr_octet, sizeof(bssid.i_bssid));
    strlcpy(bssid.i_name, target->if_name, sizeof(bssid.i_name));
    s = open_socket(AF_INET);

    if (!s) {
        printf("error opening socket: %s\n", strerror(errno));
        return 1;
    }

    res = ioctl(s, SIOCS80211BSSID, &bssid);
    close(s);

    return res;

}

int set_wpa8021x(struct config_interfaces *target) {

    int res, s = -1;
    struct ieee80211_wpaparams wpa;
    struct ifreq ifr;

    s = open_socket(AF_INET);
    strlcpy(wpa.i_name, target->if_name, sizeof(wpa.i_name));
    ifr.ifr_data = (caddr_t)&wpa;
    res = ioctl(s, SIOCG80211WPAPARMS, (caddr_t)&wpa);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));
		
	wpa.i_akms = IEEE80211_WPA_AKM_8021X;
    res = ioctl(s, SIOCS80211WPAPARMS, (caddr_t)&wpa);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));

    close(s);

    return 0;

}

int set_ipv6_auto(struct config_interfaces *target) {
    int res, s = -1;
    struct ifreq ifr;

    s = open_socket(AF_INET6);
    strlcpy(ifr.ifr_name, target->if_name, sizeof(ifr.ifr_name));
    res = ioctl(s, SIOCGIFXFLAGS, (caddr_t)&ifr);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));

    ifr.ifr_flags |= IFXF_AUTOCONF6;
    res = ioctl(s, SIOCSIFXFLAGS, (caddr_t)&ifr);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));

    close(s);

    return 0;
}

int start_wpa_supplicant() {

	// wpa_supplicant already running
	if (supplicant_pid)
		return 0;

	supplicant_pid = fork();
	
	// parent
	if (supplicant_pid) {
	
		printf("forked, pid=%d\n", supplicant_pid);
		return 0;
		
	// child
	} else {
	
	char interface[20];
	snprintf(interface, 20, "-i %s", target->if_name);
	execl("/usr/local/sbin/wpa_supplicant", "-D openbsd", interface, "-c /etc/wpa_supplicant.conf", 0);
	printf("wpa_supplicant error\n");
	exit(1);
		
	}
	
}

void start_dhclient(struct config_interfaces *target) {

    char command[50];
    snprintf(command, 50, "dhclient %s", target->if_name);
    printf("%s\n", command);
    system(command);
    printf("finished with dhclient\n");

}

void setup_wlaninterface(struct config_interfaces *target) {

    int retries = 3;
    struct config_ssid *match = first_matching_network(target);

    if (!match)
        return;

    if(network_matches(target, match) && connection_active(target))
        return;

    printf("setting up network: %s\n", match->ssid_name);
    set_network_id((char*)match->ssid_name, target);


    printf("%s\n", match->ssid_auth);

    if (strcmp(match->ssid_auth, "802.1x") == 0) {

        printf("do 8021x stuff\n");
        set_bssid((char*)match->ssid_bssid, target);
        set_wpa8021x(target);
        start_wpa_supplicant();

    } else if(strcmp(match->ssid_auth, "wpa") == 0) {

        printf("do wpa stuff\n");
        set_psk_key((char*)match->ssid_name, (char*)match->ssid_pass, target);

    } else {

        // wep mode stuff
        set_wep_key((char*)match->ssid_pass, target);
        printf("do wep stuff\n");

    }
	
	if (match->ipv6_auto)
        set_ipv6_auto(target);

    start_dhclient(target);

    while(retries != 0) {

        if(!connection_active(target)) {

            printf("not active, waiting...\n");
            sleep(10);

        } else
            return;

        retries--;

    }

}

void setup_ethernetinterface(struct config_interfaces *cur) {

    // do all the stuff

}


// if interface is already running, returns 0
int check_interface(struct config_interfaces *cur) {

    int if_found = 0;
    int if_hasaddr = 0;
    struct ifaddrs *interfaces, *chk;

    // ask the OS what interfaces are there
    int err = getifaddrs(&interfaces);

    if (err) {

        printf("error getting interfaces: %d\n", err);
        printf("%s\n", strerror(err));
        return 0;

    }

    chk = interfaces;

    while(chk) {

        if (strcmp(cur->if_name,chk->ifa_name) != 0) {

            chk = chk->ifa_next;
            continue;

        }

        if_found = 1;

        if (chk->ifa_addr->sa_family == AF_INET || chk->ifa_addr->sa_family == AF_INET6)
            if_hasaddr = 1;

        chk = chk->ifa_next;
    }

    freeifaddrs(interfaces);
    //return if_hasaddr;
    return if_found && (!connection_active(cur) || !if_hasaddr);
}

const char * mediatype(char *interface) {

    const struct ifmedia_description ifm_type_descriptions[] = IFM_TYPE_DESCRIPTIONS;
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

    return ("Invalid interface type");

}

int main(int count, char **options) {

    int running = 1;

    if (parse_config()) {

        printf("error reading configuration!\n");
        return 1;

    }

    while (running) {

        struct config_interfaces *cur = config;

        while (cur) {

            if (check_interface(cur)) {

                printf("media type: %s\n", mediatype(cur->if_name));

                if(strcmp(mediatype(cur->if_name), "Ethernet") == 0) {

                    setup_ethernetinterface(cur);

                } else if(strcmp(mediatype(cur->if_name), "IEEE802.11") == 0) {

                    setup_wlaninterface(cur);

                }
            }

            cur = cur->next;
        }

        printf("Sleeping...\n");
        sleep(10);
        printf("restarto\n");

    }

    return 0;

}
