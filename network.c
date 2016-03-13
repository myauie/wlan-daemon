#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <util.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_media.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <arpa/inet.h>

#include "network.h"

int open_socket(int domain) {

    return socket(domain, SOCK_DGRAM, 0);

}

const char * mediatype(char *interface) {

    const struct ifmedia_description ifm_type_descriptions[] = IFM_TYPE_DESCRIPTIONS;
    struct ifmediareq ifmr;
    const struct ifmedia_description *desc;
    int *media_list, s, res;

    memset(&ifmr, 0, sizeof(ifmr));
    strlcpy(ifmr.ifm_name, interface, sizeof(ifmr.ifm_name));
    media_list = (int*)calloc(ifmr.ifm_count, sizeof(int));
    ifmr.ifm_ulist = media_list;
    s = open_socket(AF_INET);
    res = ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr);
    close(s);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));

    free(media_list);

    for (desc = ifm_type_descriptions; desc->ifmt_string != NULL; desc++) {

        if (IFM_TYPE(ifmr.ifm_current) == desc->ifmt_word)
            return (desc->ifmt_string);

    }

    return ("Invalid interface type");

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
void set_network_id(char *network_ssid, char * if_name) {

    int s = -1, res, size;
    struct ifreq ifr;
    struct ieee80211_nwid nwid;

    s = open_socket(AF_INET);

    if (s == -1)
        printf("socket error: %s\n", strerror(errno));

    size = sizeof(nwid.i_nwid);
    get_string(network_ssid, NULL, nwid.i_nwid, &size);
    nwid.i_len = size;
    strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
    ifr.ifr_data = (caddr_t)&nwid;
    res = ioctl(s, SIOCS80211NWID, (caddr_t)&ifr);
    close(s);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));

}

int set_wep_key(char *wep_key, char * if_name, int toggle) {

    int s = -1, res, len;
    struct ieee80211_nwkey nwkey;
    u_int8_t keybuffer[IEEE80211_WEP_NKID][16];

    if(toggle) {

        s = open_socket(AF_INET);

        if (!s) {

        printf("socket error: %s\n", strerror(errno));
        return 0;

        }

        memset(&nwkey, 0, sizeof(nwkey));
        memset(&keybuffer, 0, sizeof(keybuffer));
        nwkey.i_wepon = IEEE80211_NWKEY_WEP;
        nwkey.i_defkid = 1;
        len = sizeof(keybuffer[0]);

        // for 40-bit wep, length of key must be 5 char ASCII string
        //or 10 hex digits

        // for 128-bit wep, length of key must be 13 char ASCII string
        // or 26 hex digits

        if((strlen(wep_key) == 5) || (strlen(wep_key) == 13))
            printf("wep key is correct length\n");
            // string case

        else if((strlen(wep_key) == 12) || (strlen(wep_key) == 28)) {

            printf("wep key is correct length\n");

            // 0xkey case
            // hex should be +2 to include 0x
            get_string(wep_key, NULL, keybuffer[0], &len);

        } else {

	        printf("wep key is invalid length\n");
		    return 0;

	    }

        nwkey.i_key[0].i_keylen = len;
        nwkey.i_key[0].i_keydat = keybuffer[0];
        strlcpy(nwkey.i_name, if_name, sizeof(nwkey.i_name));
        res = ioctl(s, SIOCS80211NWKEY, (caddr_t)&nwkey);
        close(s);

        if (res)
            printf("res: %d (%s)\n", res, strerror(errno));

    } else
        nwkey.i_wepon = toggle;

}

int set_psk_key(char *nwid, char *psk_key, char * if_name, int toggle) {

    int s = -1, res, size;
    struct ieee80211_wpapsk psk;
    struct ieee80211_wpaparams wpa;
    struct ifreq ifr;

    s = open_socket(AF_INET);

    if (!s)
        printf("socket error: %s\n", strerror(errno));

    memset(&psk, 0, sizeof(psk));

    if(toggle) {

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

    }

    psk.i_enabled = toggle;

    strlcpy(psk.i_name, if_name, sizeof(psk.i_name));
    ifr.ifr_data = (caddr_t)&psk;
    res = ioctl(s, SIOCS80211WPAPSK, (caddr_t)&psk);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));

    strlcpy(wpa.i_name, if_name, sizeof(wpa.i_name));
    ifr.ifr_data = (caddr_t)&wpa;

    res = ioctl(s, SIOCG80211WPAPARMS, (caddr_t)&wpa);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));

    wpa.i_akms = IEEE80211_WPA_AKM_PSK;
    wpa.i_enabled = psk.i_enabled;
    res = ioctl(s, SIOCS80211WPAPARMS, (caddr_t)&wpa);
    close(s);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));

}

void set_bssid(char *network_bssid, char * if_name, int toggle) {

    int s = -1, res;
    struct ieee80211_bssid bssid;
    struct ether_addr *ea;
    
    s = open_socket(AF_INET);
    
    if(toggle) {

    // convert bssid from ascii to binary
	printf("set bssid: %s\n", network_bssid);
    ea = ether_aton(network_bssid);

    if (!ea)
        printf("invalid ethernet address: %s\n", network_bssid);

    memcpy(&bssid.i_bssid, ea->ether_addr_octet, sizeof(bssid.i_bssid));
    
    } else
        memset(&bssid.i_bssid, 0, sizeof(bssid.i_bssid));
    
    strlcpy(bssid.i_name, if_name, sizeof(bssid.i_name));    

    if (!s)
        printf("error opening socket: %s\n", strerror(errno));

    res = ioctl(s, SIOCS80211BSSID, &bssid);
    close(s);

    if(res)
        printf("res: %d (%s)\n", res, strerror(errno));

}

void set_wpa8021x(char * if_name, int toggle) {

    int res, s = -1;
    struct ieee80211_wpaparams wpa;
    struct ifreq ifr;

    s = open_socket(AF_INET);
    memset(&wpa, 0, sizeof(wpa));
    strlcpy(wpa.i_name, if_name, sizeof(wpa.i_name));
    ifr.ifr_data = (caddr_t)&wpa;
    res = ioctl(s, SIOCG80211WPAPARMS, (caddr_t)&wpa);

    if(res)
        printf("res: %d (%s)\n", res, strerror(errno));
        
    if(toggle)
        wpa.i_akms = IEEE80211_WPA_AKM_8021X;
    else
        wpa.i_akms = IEEE80211_WPA_AKM_PSK;
        
    printf("new wpa.i_akms mode is: %d\n", wpa.i_akms);

	wpa.i_enabled = toggle;
	
    res = ioctl(s, SIOCS80211WPAPARMS, (caddr_t)&wpa);
    close(s);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));

}

void set_ipv6_auto(char * if_name) {
    int res, s = -1;
    struct ifreq ifr;

    s = open_socket(AF_INET6);
    strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
    res = ioctl(s, SIOCGIFXFLAGS, (caddr_t)&ifr);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));

    ifr.ifr_flags |= IFXF_AUTOCONF6;
    res = ioctl(s, SIOCSIFXFLAGS, (caddr_t)&ifr);
    close(s);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));

}
