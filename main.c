#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_media.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <netdb.h>
#include <resolv.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "network.h"
#include "status_server.h"
#include "supplicant.h"

struct stat 	config_last_mod;
int 		poll_wait;

int 
connection_active(char *if_name, int if_type) {
        /*
        *  Returns 1 if the network status on the interface is active.
        *  if_type: 0 for ethernet, 1 for ieee80211 
        */

        struct ifmediareq ifmr;
        const struct ifmedia_status_description *ifms;
        static const int ifm_status_valid_list[] = IFM_STATUS_VALID_LIST;
        static const struct ifmedia_status_description ifm_status_descriptions[] = IFM_STATUS_DESCRIPTIONS;
        int 		bit = 0, 	s = -1, res;

        s = open_socket(AF_INET);
        if (s < 0) {
            printf("error opening socket: %s\n", strerror(errno));
        }
        memset(&ifmr, 0, sizeof(ifmr));
        strlcpy(ifmr.ifm_name, if_name, sizeof(ifmr.ifm_name));
        res = ioctl(s, SIOCGIFMEDIA, (caddr_t) & ifmr);
        close(s);
        if (res) {
            printf("res: %d (%s)\n", res, strerror(errno));
            return 0;
        }
        if (if_type) {
            /* ieee80211 check */
            if (IFM_ACTIVE) {
                printf("connection_active: ieee80211 network is active\n");
                return 1;
            }
            printf("connection_active: ieee80211 failed check\n");
            return 0;
        } else {
            /* ethernet check */
            for (ifms = ifm_status_descriptions; ifms->ifms_valid != 0; ifms++) {
                if (ifms->ifms_type == IFM_TYPE(ifmr.ifm_current))
                    if (strcmp(IFM_STATUS_DESC(ifms, ifmr.ifm_status), "active") == 0) {
                        printf("connection_active: ethernet network is active\n");
                        return 1;
                    } else {
                        printf("connection_active: ethernet failed check\n");
                        return 0;
                    }
            }
        }
}

void 
internet_connectivity_alarm() {
        printf("timed out\n");
}

int 
internet_connectivity_check(struct config_ssid * match) {
        int 		s        , res;
        char 		header   [200];
        char 		input    [100];
        char 		cmp      [10];
        struct sockaddr_in saddr;
        struct hostent *host;
        struct itimerval timeout;

        printf("auth script already run? %d\n", config->additional_auth_exec);
        printf("ncsi_ping: %s\n", ncsi_ping);
        s = socket(AF_INET, SOCK_STREAM, 0);
        if ((ncsi_ping == NULL) || (ncsi_ping[0] == '\0')) {
            printf("use default host\n");
            host = gethostbyname("www.open-ncsi.com");
        } else {
            printf("use user-defined host\n");
            host = gethostbyname(ncsi_ping);
        }
        if (!host) {
            printf("name resolution failed\n");
            return 0;
        }
        memset(&timeout, 0, sizeof(timeout));
        signal(SIGALRM, internet_connectivity_alarm);
        timeout.it_value.tv_sec = 5;
        if (setitimer(ITIMER_REAL, &timeout, NULL) != 0)
            printf("error setting timer\n");
        snprintf(header, sizeof(header), "GET /ncsi.txt HTTP/1.0\r\nHost: %s\r\n\r\n", host->h_name);
        printf("IP:%s\n", inet_ntoa(*(struct in_addr *) host->h_addr_list[0]));
        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = host->h_addrtype;
        memcpy(&saddr.sin_addr.s_addr, host->h_addr_list[0], sizeof(saddr.sin_addr.s_addr));
        saddr.sin_port = htons(80);
        printf("connecting...\n");
        if (connect(s, (struct sockaddr *) & saddr, sizeof(struct sockaddr)) == -1) {
            printf("socket failed\n");
            return 0;
        }
        timeout.it_value.tv_sec = 0;
        if (setitimer(ITIMER_REAL, &timeout, NULL) != 0)
            printf("error setting timer\n");
        signal(SIGALRM, SIG_DFL);
        printf("sending...\n");
        res = send(s, header, strlen(header), 0);
        if (res != strlen(header)) {
            printf("write failed\n");
            close(s);
            return 0;
        }
        memset(&input, 0, sizeof(input));
        printf("receiving...\n");
        res = recv(s, input, sizeof(input), 0);
        if (res)
            printf("res: %d (%s)\n", res, strerror(errno));
        /*
         *  Check if a 302 redirect response has been received.
         *  If we do, this means it is a hotspot.
         */
        printf("%s\n", input);
        strncpy(cmp, input + 9, 3);
        printf("%s\n", cmp);
        if (strcmp(cmp, "302") == 0) {
            /*
             * Network requires additional auth; execute user-defined
             * action.
             */
            printf("302 redirect\n");
            return 2;
        } else
            printf("200 OK\n");
        close(s);
        return 1;
}

int 
hotspot(struct config_ssid * match) {
        /* Use xdg-open default web browser if nothing is specified. */
        if (match->additional_auth_script[0])
            update_status(CUSTOM_AUTH, match->additional_auth_script);
        else
            update_status(AUTH_REQUIRED, "www.google.com");
        config->additional_auth_exec = 1;
        return 1;
}

int 
network_matches(char *if_name, struct config_ssid * match) {
        struct ifreq 	ifr;
        struct ieee80211_nwid nwid;
        struct ieee80211_bssid bssid;
        char 		current_bssid[20];
        int 		s = -1, 	res, ires;

        s = open_socket(AF_INET);
        if (s < 0) {
            printf("error opening socket: %s\n", strerror(errno));
            return 0;
        }
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_data = (caddr_t) & nwid;
        strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
        res = ioctl(s, SIOCG80211NWID, (caddr_t) & ifr);
        printf("current nwid on interface: %s\n", nwid.i_nwid);
        if (res)
            printf("res: %d (%s)\n", res, strerror(errno));
        /*
         * First of all, check if the SSID of the match found is the same as
         * the one the interface is using.
         */
        if (strcmp((const char *) nwid.i_nwid, match->ssid_name) == 0) {
            printf("passed nwid string cmp\n");
            /*
            *  If it is, check if the BSSID is the same as the one the
            *  interface is using (if they are the same access point).
            *  Return true if they are the same AP.
            */
            struct ether_addr ea;
            memset(&bssid, 0, sizeof(bssid));
            strlcpy(bssid.i_name, if_name, sizeof(bssid.i_name));
            res = ioctl(s, SIOCG80211BSSID, &bssid);
            if (res)
                printf("res: %d (%s)\n", res, strerror(errno));
            memcpy(&ea.ether_addr_octet, bssid.i_bssid, sizeof(ea.ether_addr_octet));
            /* Convert BSSID from binary to ASCII */
            strlcpy(current_bssid, ether_ntoa(&ea), sizeof(current_bssid));
            if (strcmp(current_bssid, match->ssid_bssid) == 0) {
                printf("passed bssid string cmp\n");
                close(s);
                /*
                *  The one we want is already on the interface.
                *  Now check if it's connected to the wlan, if it's not
                *  then we need to try dhclient again.
                */
                if (connection_active(if_name, 1)) {
                    /*
                    *  If we are successfully connected to the network
                    *  and we don't need additional auth, then we are good.
                    */
                    ires = internet_connectivity_check(match);
                    if (ires == 1)
                        return 1;
                    else if (ires == 2) {
                        /*
                        * This is a hotspot; run
                        * user-defined command or open
                        * default web browser.
                        */
                        if (!config->additional_auth_exec)
                            hotspot(match);
                        return 1;
                    } else
                        /* Try dhclient again. */
                        return 0;
                } else {
                    printf("connection not active; trying dhclient again\n");
                    return 0;
                }
            }
        }
        /* Do all the signal checking stuff. */
        struct ieee80211_nodereq nr;
        memset(&nr, 0, sizeof(nr));
        memcpy(&nr.nr_macaddr, bssid.i_bssid, sizeof(nr.nr_macaddr));
        strlcpy(nr.nr_ifname, if_name, sizeof(nr.nr_ifname));
        res = ioctl(s, SIOCG80211NODE, (caddr_t) & nr);
        int8_t 		new_rssi;
        int8_t 		old_rssi;

        if (res)
            printf("res: %d (%s)\n", res, strerror(errno));
        close(s);
        printf("rssi is: %d\n", nr.nr_rssi);
        /* No network to compare with; connect to new network. */
        if (res == -1)
            return 0;
        /*
         * Different chipsets measure RSSI values differently need to
         * accommodate when 0 is minimum value and when 0 is maximum value.
         */
        if (nr.nr_max_rssi) {
            new_rssi = match->ssid_rssi;
            old_rssi = nr.nr_rssi;
        } else {
            new_rssi = match->ssid_rssi + 100;
            old_rssi = nr.nr_rssi + 100;
        }
        /*
         * Switch over if new network is higher RSSI value than (old*1.5).
         */
        if (new_rssi > (old_rssi * 1.5)) {
            printf("switching over to new network\n");
            return 0;
        } else {
            printf("staying on old network\n");
            return 1;
        }
}

static int 
rssicmp(const void *nr1, const void *nr2) {
        const struct ieee80211_nodereq *x = nr1, *y = nr2;
        return y->nr_rssi < x->nr_rssi ? -1 : y->nr_rssi > x->nr_rssi;
}

/* Based on ieee80211_listnodes() from ifconfig. */
struct config_ssid *
all_matching_network(struct config_interfaces * config) {
        struct ieee80211_nodereq_all na;
        struct ieee80211_nodereq nr[512];
        struct ifreq 	ifr;
        char 		name     [IEEE80211_NWID_LEN];
        int 		i        , s, len, res;
        int8_t 		rssi;
        struct config_ssid *ret = 0;

        /* Open socket and scan for wlans. */
        memset(&ifr, 0, sizeof(ifr));
        strlcpy(ifr.ifr_name, config->if_name, sizeof(ifr.ifr_name));
        s = open_socket(AF_INET);
        if (s < 0)
            return NULL;
        if (ioctl(s, SIOCS80211SCAN, (caddr_t) & ifr) != 0) {
            /* Interface not available; invoking ifconfig to bring it up. */
            printf("error scanning: %s\n", strerror(errno));
            close(s);
            char 		command  [50];
            snprintf(command, sizeof(command), "ifconfig %s up\n", config->if_name);
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
        res = ioctl(s, SIOCG80211ALLNODES, &na);
        close(s);
        if (res) {
            printf("error retrieving nodes: %s\n", strerror(errno));
            return NULL;
        }
        if (!na.na_nodes) {
            printf("no access points found\n");
            return NULL;
        }
        /* Sort nodes in order of signal strength. */
        qsort(nr, na.na_nodes, sizeof(*nr), rssicmp);
        struct config_ssid *cur = config->ssids;
        while (cur) {
            for (i = 0; i < na.na_nodes; i++) {
                len = nr[i].nr_nwid_len > IEEE80211_NWID_LEN ? IEEE80211_NWID_LEN : nr[i].nr_nwid_len;
                snprintf(name, IEEE80211_NWID_LEN, "%.*s", len, nr[i].nr_nwid);
                rssi = nr[i].nr_rssi;
                printf("checking this one: %s and this one: %s, has rssi of %d\n", cur->ssid_name, name, rssi);
                if (strcmp(cur->ssid_name, name) == 0) {
                    printf("this one found\n");
                    /*
                     * get data we need from scan; BSSID, signal
                     * strength, auth mode.
                     */
                    struct ether_addr ea;
                    memcpy(&ea.ether_addr_octet, nr[i].nr_bssid, sizeof(ea.ether_addr_octet));
                    /* convert BSSID from binary to ASCII. */
                    strlcpy(cur->ssid_bssid, ether_ntoa(&ea), sizeof(cur->ssid_bssid));
                    /* Get signal strength. */
                    if (nr[i].nr_max_rssi)
                        cur->ssid_rssi = IEEE80211_NODEREQ_RSSI(&nr[i]);
                    else
                        cur->ssid_rssi = nr[i].nr_rssi;
                    printf("signal strength is: %d\n", cur->ssid_rssi);
                    if (nr[i].nr_capinfo) {
                        if ((nr[i].nr_rsnakms & IEEE80211_WPA_AKM_8021X) || (nr[i].nr_rsnakms & IEEE80211_WPA_AKM_SHA256_8021X))
                            strlcpy(cur->ssid_auth, "802.1x", sizeof(cur->ssid_auth));
                            
                        /*
                         * CCMP is WPA2 and TKIP is WPA1. The
                         * code to connect to either auth is
                         * exactly the same, they just uses
                         * different cipher. For the purposes
                         * of this program, I am
                         * consolidating them.
                         */    
                        else if ((nr[i].nr_rsnciphers & IEEE80211_WPA_CIPHER_CCMP) || (nr[i].nr_rsnciphers & IEEE80211_WPA_CIPHER_TKIP))
                            strlcpy(cur->ssid_auth, "wpa", sizeof(cur->ssid_auth));
                        /*
                         * Check if a password has been set
                         * for this access point. If there
                         * is, we use WEP.
                         */
                        else {
                            if (cur->ssid_pass[0] == '\0')
                                strlcpy(cur->ssid_auth, "none", sizeof(cur->ssid_auth));
                            else
                                strlcpy(cur->ssid_auth, "wep", sizeof(cur->ssid_auth));
						/*
						 * Unable to check for a WEP
						 * cipher with a nodereq.
						 */
                        }
                    } else
                        strlcpy(cur->ssid_auth, "none", sizeof(cur->ssid_auth));
                        /* No auth on access point. */
                    printf("%s mode found\n", cur->ssid_auth);
                    struct config_ssid *cpy = malloc(sizeof(struct config_ssid));
                    memcpy(cpy, cur, sizeof(struct config_ssid));
                    cpy->next = 0;
                    if (ret)
                        ret->next = cpy;
                    else {
                        ret = cpy;
                        ret->next = 0;
                    }
                }
            }
        cur = cur->next;
        }
        return ret;
}

int 
config_changed() {
        /*
         * Verify if config file has been modified by checking its 'last
         * modified time'.
         */
        struct stat 	current_config_mod;
        stat(config_file, &current_config_mod);

        /*
         * If config file has been modified, write the new 'last modified
         * time' to config_last_mod.
         */
        double 		diff = difftime(config_last_mod.st_mtime, current_config_mod.st_mtime);
        if (diff != 0) {
            printf("config file has been modified at %s\n", ctime(&current_config_mod.st_mtime));
            stat(config_file, &config_last_mod);
            return 1;
        }
        printf("config file not changed\n");
        return 0;
}

void 
start_dhclient(char *if_name) {
        char 		command  [50];
        snprintf(command, sizeof(command), "dhclient %s", if_name);
        printf("%s\n", command);
        system(command);
        printf("finished with dhclient\n");
        sleep(2);
}

void 
cleanup_interface(struct config_interfaces * target, int flag) {
        /*
         *  Flag: 1st bit - 8021x is set.
         *  2nd bit - WPA is set.
         *  3rd bit - WEP is set.
         *  4th bit - open auth is set.
         */
        int 		wep_res  , psk_res, wpa_res, s = -1;
        struct ifreq 	ifr;
        struct ieee80211_nwid nwid;
        struct ieee80211_nwkey nwkey;
        struct ieee80211_wpapsk psk;
        struct ieee80211_wpaparams wpa;

        s = open_socket(AF_INET);
        memset(&nwkey, 0, sizeof(nwkey));
        strlcpy(nwkey.i_name, target->if_name, sizeof(nwkey.i_name));
        wep_res = ioctl(s, SIOCG80211NWKEY, (caddr_t) & nwkey);
        printf("wep: %d\n", wep_res);
        memset(&psk, 0, sizeof(psk));
        strlcpy(psk.i_name, target->if_name, sizeof(psk.i_name));
        psk_res = ioctl(s, SIOCG80211WPAPSK, (caddr_t) & psk);
        printf("psk_res: %d\n", psk_res);
        memset(&wpa, 0, sizeof(wpa));
        strlcpy(wpa.i_name, target->if_name, sizeof(wpa.i_name));
        wpa_res = ioctl(s, SIOCG80211WPAPARMS, &wpa);
        printf("wpa_res: %d\n", wpa_res);
        close(s);
        printf("nwkey wep on: %d\n", nwkey.i_wepon);
        if (nwkey.i_wepon && flag != 2) {
            printf("removing wep stuff\n");
            set_wep_key(0, NULL, 0);
        }
        printf("psk enabled: %d\n", psk.i_enabled);
        if (psk.i_enabled && flag != 4) {
            printf("removing psk stuff\n");
            set_psk_key(0, 0, target->if_name, 0);
        }
        if ((wpa.i_akms & IEEE80211_WPA_AKM_8021X) && flag != 8) {
            printf("removing 80211x stuff\n");
            set_wpa8021x(target->if_name, 0);
            set_bssid(NULL, target->if_name, 0);
            if (target->supplicant_pid)
                kill(target->supplicant_pid, SIGTERM);
            target->supplicant_pid = 0;
        }
}

int 
setup_wlaninterface(struct config_interfaces * target) {
        int 		retries = 1, res = 0;
        struct config_ssid *match, *all = all_matching_network(target);
        char           *if_name = target->if_name;
        match = all;

        if (!match)
            return 0;
        if (network_matches(if_name, match)) {
            printf("already using matched ssid, we do nothing\n");
            clear_ssid(all);
            return 1;
        }
        while (match) {
            printf("setting up network: %s\n", match->ssid_name);
            set_network_id((char *) match->ssid_name, if_name);
            printf("%s\n", match->ssid_auth);
            update_status(CONNECTING, match->ssid_name);
            if (strcmp(match->ssid_auth, "802.1x") == 0) {
                printf("do 8021x stuff\n");
                if (!target->supplicant_pid)
                    target->supplicant_pid = start_wpa_supplicant(target->if_name, target->supplicant_pid, 1);
                cleanup_interface(target, 8);
                set_bssid((char *) match->ssid_bssid, if_name, 1);
                set_wpa8021x(if_name, 1);
                sleep(3);
                config_wpa_supplicant(if_name, match, 1);
            } else if (strcmp(match->ssid_auth, "wpa") == 0) {
                printf("do wpa stuff\n");
                cleanup_interface(target, 4);
                set_psk_key((char *) match->ssid_name, (char *) match->ssid_pass, if_name, 1);
            } else if (strcmp(match->ssid_auth, "wep") == 0) {
                printf("do wep stuff\n");
                cleanup_interface(target, 2);
                set_wep_key((char *) match->ssid_pass, if_name, 1);
            } else if (strcmp(match->ssid_auth, "none") == 0) {
                printf("no security has been set\n");
                cleanup_interface(target, 1);
            }
            if (target->ipv6_auto)
                set_ipv6_auto(if_name);
            start_dhclient(if_name);
            while (retries != 0) {
                if (connection_active(if_name, 1)) {
                    /*
		             *  If we are successfully connected to the network
		             *  and we don't need additional auth, then we are good.
		             */
		            sleep(1);
                    res = internet_connectivity_check(match);
                    if (res == 1) {
                        update_status(CONNECTED, match->ssid_name);
                        return 1;
                    } else if (res == 2) {
                        /*
		                 *  This is a hotspot; run user-defined command
		                 *  or open default web browser.
		                 */
                        if (!config->additional_auth_exec)
                            hotspot(match);
                        return 1;
                    } else {
                        printf("not active, waiting...\n");
                        sleep(5);
                        retries--;
                    }
                }
            }
            match = match->next;
            retries = 1;
        }
        clear_ssid(all);
        return res;
}

int 
setup_ethernetinterface(struct config_interfaces * cur) {
        int 		retries = 1;
        struct config_ssid *match = cur->ssids;
        /*
         *  If 8021.1X, run the supplicant stuff the same as wireless.
         *  If not using 8021.1X, just go straight to dhclient.
         */
        printf("%s\n", cur->if_name);
        if (!connection_active(cur->if_name, 0)) {
            char 		command  [50];
            snprintf(command, sizeof(command), "ifconfig %s up\n", config->if_name);
            printf("%s\n", command);
            system(command);
            printf("try bringing up interface\n");
            /*
             * Check if a password has been set; if yes, we want to use
             * the supplicant.
             */
            if (match->ssid_pass[0] == '\0')
                strlcpy(match->ssid_auth, "none", sizeof(match->ssid_auth));
            else
                strlcpy(match->ssid_auth, "802.1x", sizeof(match->ssid_auth));
            /*
             * Remove wireless settings from wireless interface before
             * trying ethernet.
             */
            cleanup_interface(cur, 1);
            if (strcmp(cur->ssids->ssid_auth, "802.1x") == 0) {
                /* Do supplicant stuff. */
                if (!cur->supplicant_pid)
                    cur->supplicant_pid = start_wpa_supplicant(cur->if_name, cur->supplicant_pid, 0);
                config_wpa_supplicant(cur->if_name, match, 1);
            }
            if (cur->ipv6_auto)
                set_ipv6_auto(cur->if_name);
            start_dhclient(cur->if_name);
            if (connection_active(cur->if_name, 0)) {
                /*
	             *  If we are successfully connected to the network
	             *  and we don't need additional auth, then we are good.
	             */
                if (internet_connectivity_check(match) == 1)
                    return 1;
                    /* All is ok, sleep. */
            }
        } else {
            /*
	         *  If we are successfully connected to the network,
	         *  then we are good. Otherwise try another connection.
	         */
            if (internet_connectivity_check(match) == 1)
                return 1;
                /* All is ok, sleep. */
        }
        return 0;
}

/* If interface is running, returns 1. */
int 
check_interface(struct config_interfaces * cur) {
        int 		if_found = 0;
        int 		if_hasaddr = 0;
        struct ifaddrs *interfaces, *chk;

        /* Ask the OS what interfaces there are. */
        int 		err = getifaddrs(&interfaces);
        if (err) {
            printf("error getting interfaces: %d\n", err);
            printf("%s\n", strerror(err));
            return 0;
        }
        chk = interfaces;
        while (chk) {
            if (strcmp(cur->if_name, chk->ifa_name) != 0) {
                chk = chk->ifa_next;
                continue;
            }
            if_found = 1;
            if (chk->ifa_addr->sa_family == AF_INET || chk->ifa_addr->sa_family == AF_INET6)
                if_hasaddr = 1;
            chk = chk->ifa_next;
        }
        freeifaddrs(interfaces);
        if (if_found)
            return 1;
        else if (if_hasaddr)
            return 1;
        else
            return 0;
}

int 
main(int count, char **options) {
        //int 		res;
        //res = daemon(0, 0);
        //printf("return value: %s\n", res);
        res_init();
        _res.retrans = 4;
        _res.retry = 2;
        int 		running = 1;
        if (parse_config()) {
            printf("error reading configuration!\n");
            return 1;
        }
        if (open_status_socket())
            printf("error opening status socket; no status will be provided\n");
        stat(config_file, &config_last_mod);
        printf("last config modified time: %s\n", ctime(&config_last_mod.st_mtime));
        while (running) {
            struct config_interfaces *cur = config;
            printf("checking if conf file has changed\n");
            if (config_changed()) {
                printf("modifying:\n");
                clear_config(config);
                cur = 0;
                if (parse_config())
                   printf("error reading configuration!\n");
                else
                    cur = config;
            }
            while (cur) {
                if (check_interface(cur)) {
                    printf("media type: %s\n", mediatype(cur->if_name));
                    if (strcmp(mediatype(cur->if_name), "Ethernet") == 0) {
                        if (setup_ethernetinterface(cur))
                            break;
                    } else if (strcmp(mediatype(cur->if_name), "IEEE802.11") == 0) {
                        if (setup_wlaninterface(cur))
                            break;
                    }
                }
                cur = cur->next;
            }
            printf("Sleeping... waiting %d seconds\n", poll_wait);
            sleep(poll_wait);
            printf("restarto\n");
        }
        return 0;
}
