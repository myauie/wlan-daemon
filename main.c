#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <ifaddrs.h>
#include <signal.h>
#include <util.h>
#include <inttypes.h>
#include <time.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <net/if_media.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <arpa/inet.h>
#include "configreader.h"
#include "y.tab.h"
#include "wpa_ctrl.h"

// const char config_file[] = "/etc/wlan-daemon/wlan-daemon.config";
const char config_file[] = "./wlan-daemon.conf"; // debugging
// default directory wpa_supplicant uses for unix domain sockets
char wpa_daemon_ctrl[] = "/var/run/wlan-daemon";
int yyparse();
FILE *yyin;

pid_t supplicant_pid = 0;
struct wpa_ctrl *wpa_client = 0;
struct stat config_last_mod;

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

int connection_active(char * if_name) {
// returns 1 if the network status on the interface
// is active

    struct ifmediareq ifmr;
    int s = -1, res;

    s = open_socket(AF_INET);

    if(s < 0) {

        printf("error opening socket: %s\n", strerror(errno));

    }

    memset(&ifmr, 0, sizeof(ifmr));
    strlcpy(ifmr.ifm_name, if_name, sizeof(ifmr.ifm_name));
    res = ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr);
    close(s);

    if (res) {
    
        printf("res: %d (%s)\n", res, strerror(errno));
        return 0;
        
    }

    //ifmr.ifm_status
    if (IFM_ACTIVE) {

        printf("connection_active: network is active\n");
        return 1;

    }

    printf("connection_active: failed check\n");
    return 0;
}

int internet_connectivity_check(struct config_ssid *match) {

	int s, res;
	char header[200];
	char input[200];
	char cmp[10];
	struct sockaddr_in saddr;
	struct hostent *host;
	
	printf("ncsi_ping: %s\n", ncsi_ping);
	
	if((ncsi_ping == NULL) || (ncsi_ping[0] == '\0')) {
	
	    printf("use default host\n");
	    host = gethostbyname("www.open-ncsi.com");	
	    
	} else {
	
	    printf("use user-defined host\n");
	    host = gethostbyname(ncsi_ping);	
	
	}
	if(!host) {
	
		printf("name resolution failed\n");
		return 0;
		
	}

	sprintf(header, "GET /ncsi.txt HTTP/1.0\r\nHost: %s\r\n\r\n", host->h_name);
	printf("IP:%s\n", inet_ntoa(*(struct in_addr *)host->h_addr_list[0]));
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = host->h_addrtype;
	memcpy(&saddr.sin_addr.s_addr, host->h_addr_list[0], sizeof(saddr.sin_addr.s_addr));
	saddr.sin_port = htons(80);
	printf("connecting...\n");
	s = socket(AF_INET, SOCK_STREAM, 0);	 

	if(connect(s, (struct sockaddr*)&saddr, sizeof(struct sockaddr)) == -1) {
	
		printf("socket failed\n");
		return 0;
		
	}
	
	printf("sending...\n");
	res = send(s, header, strlen(header), 0);
	
	if(res != strlen(header)) {
	
		printf("write failed\n");
		close(s);
		return 0;
		
	}
	
	printf("receiving...\n");
	res = recv(s, input, sizeof(input), 0);
    
    if(res)
        printf("res: %d (%s)\n", res, strerror(errno));	   

    // check if a 302 redirect response has been received
    // if we do, this means it is a hotspot

    printf("%s\n", input);
	strncpy(cmp, input+9, 3);	
	printf("%s\n", cmp);
	
	if(strcmp(cmp, "302") == 0) {
	
		// network requires additional auth; execute
	    // user-defined action
	    printf("302 redirect\n");	    
	    return 2;

	} else
		    printf("200 OK\n");

	close(s);
	return 1;

}

int hotspot() {

	// use xdg-open default web browser if is nothing specified
    system("xdg-open http://www.google.com/");
    
    return 1;

}

int network_matches(char * if_name, struct config_ssid *match) {

    struct ifreq ifr;
    struct ieee80211_nwid nwid;
    struct ieee80211_bssid bssid;
    char current_bssid[20];
    int s = -1, res;

    s = open_socket(AF_INET);

    if (s < 0) {

        printf("error opening socket: %s\n", strerror(errno));
        return 0;

    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_data = (caddr_t)&nwid;
    strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
    res = ioctl(s, SIOCG80211NWID, (caddr_t)&ifr);
    printf("current nwid on interface: %s\n", nwid.i_nwid);
    
    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));
        
    // first of all, check if the ssid of the match found is the same as
    // the one the interface is using
    if(strcmp((const char*)nwid.i_nwid, match->ssid_name) == 0) {
    
        printf("passed nwid string cmp\n");
    
        // if it is, check if the bssid is the same as the one the
        // interface is using (if they are the same access point),
        // return true if they are the same ap
                                
        struct ether_addr ea;
        memset(&bssid, 0, sizeof(bssid));
        strlcpy(bssid.i_name, if_name, sizeof(bssid.i_name));
	    res = ioctl(s, SIOCG80211BSSID, &bssid);
	    if(res)
	        printf("res: %d (%s)\n", res, strerror(errno));	    
        memcpy(&ea.ether_addr_octet, bssid.i_bssid, sizeof(ea.ether_addr_octet));
        // convert bssid from binary to ascii
        strlcpy(current_bssid, ether_ntoa(&ea), sizeof(current_bssid));
    
        if(strcmp(current_bssid, match->ssid_bssid) == 0) {
        
            printf("passed bssid string cmp\n");
            close(s);
            
            // ok, the one we want is already on the interface.
            // now check if it's connected to the wlan, if it's not
            // then we need to try dhclient again            
            if(connection_active(if_name)) {            
            
                // if we are successfully connected to the network
                // and we don't need additional auth, then we are good
                if(internet_connectivity_check(match) == 1)
                    return 1;
                    
                else if(internet_connectivity_check(match) == 2)
                    // this is a hotspot; run user-defined command
                    // or open fdeault web browser
                    hotspot();    
                    
                else
                    // try dhclient again
                    return 0;
                
            } else {
            
                printf("connection not active; trying dhclient again\n");
                return 0;
                
            }
        
        }
   
    }
    
    // do all the signal checking stuff    

    struct ieee80211_nodereq nr;
    memset(&nr, 0, sizeof(nr));
    memcpy(&nr.nr_macaddr, bssid.i_bssid, sizeof(nr.nr_macaddr));            
    strlcpy(nr.nr_ifname, if_name, sizeof(nr.nr_ifname));
    res = ioctl(s, SIOCG80211NODE, (caddr_t)&nr);
    
    if(res)
        printf("res: %d (%s)\n", res, strerror(errno));	    

    close(s);
    printf("rssi is: %d\n", nr.nr_rssi);
    
    // no network to compare with; connect to new network
    if(res == -1)
        return 0;
    
    // switch over if new network is better than (old*1.5)
    // ensure that new one is worth switching over to
    
    if((match->ssid_rssi) > (nr.nr_rssi * 1.5)) {
    
        printf("switching over to new network\n");
        return 0;
        
    } else {
    
        printf("staying on old network\n");
        return 1;
        
    }
    
}

static int rssicmp(const void *nr1, const void *nr2) {

    const struct ieee80211_nodereq *x = nr1, *y = nr2;
    return y->nr_rssi < x->nr_rssi ? -1 : y->nr_rssi > x->nr_rssi;

}

// based on ieee80211_listnodes() from ifconfig
struct config_ssid *first_matching_network(struct config_interfaces *config) {
    struct ieee80211_nodereq_all na;
    struct ieee80211_nodereq nr[512];
    struct ifreq ifr;
    char name[IEEE80211_NWID_LEN];
    int i, s, len, res;
    int8_t rssi;

    // open socket and scan for wlans
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, config->if_name, sizeof(ifr.ifr_name));
    s = open_socket(AF_INET);

    if (s < 0)
        return NULL;

    if (ioctl(s, SIOCS80211SCAN, (caddr_t)&ifr) != 0) {
        // interface not available; invoking ifconfig to bring it up

        printf("error scanning: %s\n", strerror(errno));
        close(s);
        char command[50];
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
    
    if(res) {

        printf("error retrieving nodes: %s\n", strerror(errno));
        return NULL;

    }

    if(!na.na_nodes) {

        printf("no access points found\n");
        return NULL;

    }
    
    // sort nodes in order of signal strength
    qsort(nr, na.na_nodes, sizeof(*nr), rssicmp);

    struct config_ssid *cur = config->ssids;

    while (cur) {

        // if a wlan we want is found, return
        for(i = 0; i < na.na_nodes; i++) {
        
            len = nr[i].nr_nwid_len > IEEE80211_NWID_LEN? IEEE80211_NWID_LEN: nr[i].nr_nwid_len;
            snprintf(name, IEEE80211_NWID_LEN, "%.*s", len, nr[i].nr_nwid);
        
            rssi = nr[i].nr_rssi;
            printf("checking this one: %s and this one: %s, has rssi of %d\n", cur->ssid_name, name, rssi);
            if (strcmp(cur->ssid_name,name) == 0) {
                printf("this one found\n");

                // get data we need from scan; bssid, signal strength, auth mode
                struct ether_addr ea;
                memcpy(&ea.ether_addr_octet, nr[i].nr_bssid, sizeof(ea.ether_addr_octet));
                // convert bssid from binary to ascii
                strlcpy(cur->ssid_bssid, ether_ntoa(&ea), sizeof(cur->ssid_bssid));	
		        
		        // get signal strength
			    if (nr[i].nr_max_rssi)
			        cur->ssid_rssi = nr[i].nr_max_rssi;
			    else
			        cur->ssid_rssi = nr[i].nr_rssi;
			    
			    printf("signal strength is: %d\n", cur->ssid_rssi);	 
			    
			    if(nr[i].nr_capinfo) {            
				
				    if ((nr[i].nr_rsnakms & IEEE80211_WPA_AKM_8021X) || (nr[i].nr_rsnakms & IEEE80211_WPA_AKM_SHA256_8021X))
				        strlcpy(cur->ssid_auth, "802.1x", sizeof(cur->ssid_auth));
				
				    else if ((nr[i].nr_rsnciphers & IEEE80211_WPA_CIPHER_CCMP) || (nr[i].nr_rsnciphers & IEEE80211_WPA_CIPHER_TKIP))
					    strlcpy(cur->ssid_auth, "wpa", sizeof(cur->ssid_auth));
					    // ccmp is wpa2 and tkip is wpa1; the code to connect to either auth is
					    // exactly the same, just uses different cipher. for the purposes of this
					    // program, I am consolidating them
					    
					// check if a password has been set for this access point
					// if there is, we use wep							        
					else {
					
						if((sizeof(&cur->ssid_pass) == 0) || (cur->ssid_pass[0] == '\0'))
					        strlcpy(cur->ssid_auth, "none", sizeof(cur->ssid_auth));
					
					    else
					        strlcpy(cur->ssid_auth, "wep", sizeof(cur->ssid_auth));   
   			                // unable to check for a wep cipher with a nodereq
   			        
   			        }
   			        
                }
			        
			    else 
			        strlcpy(cur->ssid_auth, "none", sizeof(cur->ssid_auth));   
				    // no auth on access point

                printf("%s mode found\n", cur->ssid_auth);
                return cur;
                
            }

        }
		
		cur = cur->next;
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

    wpa.i_enabled = psk.i_enabled;
    res = ioctl(s, SIOCS80211WPAPARMS, (caddr_t)&wpa);
    close(s);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));  

}

void set_bssid(char *network_bssid, char * if_name) {

    int s = -1, res;
    struct ieee80211_bssid bssid;
    struct ether_addr *ea;

    // convert bssid from ascii to binary
	printf("set bssid: %s\n", network_bssid);
    ea = ether_aton(network_bssid);

    if (!ea)
        printf("invalid ethernet address: %s\n", network_bssid);

    memcpy(&bssid.i_bssid, ea->ether_addr_octet, sizeof(bssid.i_bssid));
    strlcpy(bssid.i_name, if_name, sizeof(bssid.i_name));
    s = open_socket(AF_INET);

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
    
    if(toggle) {

    s = open_socket(AF_INET);
    strlcpy(wpa.i_name, if_name, sizeof(wpa.i_name));
    ifr.ifr_data = (caddr_t)&wpa;
    res = ioctl(s, SIOCG80211WPAPARMS, (caddr_t)&wpa);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));
		
	wpa.i_akms = IEEE80211_WPA_AKM_8021X;
    res = ioctl(s, SIOCS80211WPAPARMS, (caddr_t)&wpa);
    close(s);

    if (res)
        printf("res: %d (%s)\n", res, strerror(errno));
        
    } else
        wpa.i_akms = toggle;
        wpa.i_enabled = toggle;
        
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

int config_changed() {

    // verify if config file has been modified by checking its 'last
    // modified time'

    struct stat current_config_mod;
    stat(config_file, &current_config_mod);
    
    // if config file has been modified, write the new 'last modified time' to config_last_mod   
    double diff =  difftime(config_last_mod.st_mtime, current_config_mod.st_mtime);
    if(diff != 0) {
    
        printf("config file has been modified at %s\n", ctime(&current_config_mod.st_mtime));        
        stat(config_file, &config_last_mod);
        return 1;
        
    }
    
    printf("config file not changed\n");
    return 0;

}

int start_wpa_supplicant() {

    // if pid is non-zero, wpa_supplicant already running
    if (supplicant_pid)
        return 0;

    // fork wpa_supplicant as child process and assign its pid to supplicant_pid
    supplicant_pid = fork();
    
    if(supplicant_pid == -1) {
    
        printf("error forking: %s\n", strerror(errno));
        
    } else if(supplicant_pid) { // parent
    
        printf("forked, pid=%d\n", supplicant_pid);
        return 0;
    
    } else { // child
		
        int if_count = 0, arg = 0;
        char **args;
        struct config_interfaces *cur;

        for(cur = config; cur; cur = cur->next) if_count++;

        args = malloc(sizeof(char*) * ((if_count * 7 + 2)));
        args[arg++] = "wpa_supplicant";
        args[arg++] = "-d";

        for(cur = config; cur; cur = cur->next) {
            args[arg++] = "-i";
            args[arg++] = cur->if_name;        
            args[arg++] = "-D";
            args[arg++] = "openbsd";                
            args[arg++] = "-C";
            args[arg++] = wpa_daemon_ctrl;
            args[arg++] = "-N";
        }
        
        args[--arg] = 0;          
        execv("/usr/local/sbin/wpa_supplicant", args);
		printf("!!! wpa_supplicant error\n");
		
		}

}

void check_wpa_sup_died() {

    int status, pid;

    pid = waitpid(supplicant_pid, &status, WNOHANG);
    
    if(pid != supplicant_pid)
        return;
        
    if(!WIFEXITED(status) && !WIFSIGNALED(status))
        return;
    
    printf("wpa_supplicant DEADED\n");
    supplicant_pid = 0;
    start_wpa_supplicant();

}

void wpa_unsolicited(char *msg, size_t len) {

    printf("wpa_unsolicited_message: %s\n", msg);
    
}

int sup_cmd(char *result, char *cmd, ...) {

    va_list args;
    int res;
    char cmdbuf[256];
    size_t replen = 256;

    if (!wpa_client)
        return -1; // not attached

    va_start(args, cmd);
    vsnprintf(cmdbuf, 256, cmd, args);
    va_end(args);

    printf("%s (%d)\n", cmdbuf, strlen(cmdbuf));
    res = wpa_ctrl_request(wpa_client, cmdbuf, strlen(cmdbuf), result, &replen, wpa_unsolicited);
    printf("%s (%d)\n", result, res);
    
    if (res)
        return res;
    
}

int config_wpa_supplicant(char* if_name, struct config_ssid *match) {

    char unixsock[256], repbuf[256];
    int res, network_number = -1;

    snprintf(unixsock, 256, "%s/%s", wpa_daemon_ctrl, if_name);
    printf("starting wpa_supplicant conversation\n");

    if (!wpa_client)
        wpa_client = wpa_ctrl_open(unixsock);

    if (!wpa_client) {
        printf("failed to create wpa_supplicant connection\n");
        return 0;
    }
    
    res = sup_cmd(repbuf, "AP_SCAN 0");
    if(res < 0)
        return res;

    res = sup_cmd(repbuf, "ADD_NETWORK");
    if(res < 0)
        return res;

    sscanf(repbuf, "%d", &network_number);
    if(network_number < 0)
        return -1; // failed to create new network
          
    res = sup_cmd(repbuf, "SET_NETWORK %d auth_alg OPEN", network_number);
    if(res < 0)
        return res; 
        
    if (match->ssid_key_mgmt)    
        res = sup_cmd(repbuf, "SET_NETWORK %d key_mgmt %s", network_number, match->ssid_key_mgmt);

    if(res < 0)
        return res;            
        
    res = sup_cmd(repbuf, "SET_NETWORK %d pairwise CCMP TKIP", network_number);
    if(res < 0)
        return res;
        
    res = sup_cmd(repbuf, "SET_NETWORK %d group CCMP TKIP", network_number);
    if(res < 0)
        return res;    
           
    res = sup_cmd(repbuf, "SET_NETWORK %d proto WPA2", network_number);
    if(res < 0)
        return res;
        
    if(match->ssid_eap) {
    
        res = sup_cmd(repbuf, "SET_NETWORK %d eap %s", network_number, match->ssid_eap);
        if(res < 0)
            return res;
    
    }

    if(match->ssid_identity) {
    
        res = sup_cmd(repbuf, "SET_NETWORK %d identity \"%s\"", network_number, match->ssid_identity);
        if(res < 0)
            return res;
            
    }

    if(match->ssid_pass) {
    
        res = sup_cmd(repbuf, "SET_NETWORK %d password \"%s\"", network_number, match->ssid_pass);
        if (res < 0)
            return res;
            
    }

    res = sup_cmd(repbuf, "SET_NETWORK %d phase1 \"peapver=0\"", network_number);
    if (res < 0)
        return res;
        
    if(match->ssid_phase2) {
    
        res = sup_cmd(repbuf, "SET_NETWORK %d phase2 \"%s\"", network_number, match->ssid_phase2);
        if(res < 0)
            return res;
    
    }
    
    res = sup_cmd(repbuf, "SET_NETWORK %d mode 0", network_number);
    if (res < 0)
        return res;
        
    if(match->ssid_bssid) {
    
        res = sup_cmd(repbuf, "BSSID %d %s", network_number, match->ssid_bssid);
        if (res < 0)
            return res;

    }     
    
    res = sup_cmd(repbuf, "SET_NETWORK %d ssid \"%s\"", network_number, match->ssid_name);
    if (res < 0)
        return res;    
    
    res = sup_cmd(repbuf, "SELECT_NETWORK %d", network_number);
    if (res < 0)
        return res;

    res = sup_cmd(repbuf, "ENABLE_NETWORK %d", network_number);
    if (res < 0)
        return res;

    res = sup_cmd(repbuf, "REASSOCIATE");
    if(res < 0)
        return res;  

    wpa_ctrl_close(wpa_client);
    wpa_client = 0;
    sleep(10);

}

void start_dhclient(char * if_name) {

    char command[50];
    snprintf(command, sizeof(command), "dhclient %s", if_name);
    printf("%s\n", command);
    system(command);
    printf("finished with dhclient\n");

}

void cleanup_interface(char* if_name, int flag) {

    // flag: 1st bit - 8021x is set
    // 2nd bit - wpa is set
    // 3rd bit - wep is set
    // 4th bit - none set
    
    int wep_res, psk_res, wpa_res, s = -1;

    struct ifreq ifr;    
	struct ieee80211_nwid nwid;
	struct ieee80211_nwkey nwkey;
	struct ieee80211_wpapsk psk;
	struct ieee80211_wpaparams wpa;
	
	s = open_socket(AF_INET);

	memset(&nwkey, 0, sizeof(nwkey));
	strlcpy(nwkey.i_name, if_name, sizeof(nwkey.i_name));
	wep_res = ioctl(s, SIOCG80211NWKEY, (caddr_t)&nwkey);
    printf("wep: %d\n", wep_res);

	memset(&psk, 0, sizeof(psk));
	strlcpy(psk.i_name, if_name, sizeof(psk.i_name));
	psk_res = ioctl(s, SIOCG80211WPAPSK, (caddr_t)&psk);  
	printf("psk_res: %d\n", psk_res);  
    
	memset(&wpa, 0, sizeof(wpa));
	strlcpy(wpa.i_name, if_name, sizeof(wpa.i_name));
	wpa_res = ioctl(s, SIOCG80211WPAPARMS, &wpa);
    printf("psk_res: %d\n", wpa_res);  
	
	close(s);
	
	printf("%d\n", nwkey.i_wepon);
    
    if(nwkey.i_wepon && (!(flag == 2))) {

        printf("removing wep stuff\n");    
        set_wep_key(0, NULL, 0);
        
    }
    
    printf("%d\n", psk.i_enabled);

    if(psk.i_enabled && (!(flag == 4))) {
    
        printf("removing psk stuff\n");    
        set_psk_key(0, 0, if_name, 0);  
        
    }      
    
    if((wpa.i_akms & IEEE80211_WPA_AKM_8021X) && (!(flag == 8))) {

        printf("removing 80211x stuff\n");    
        set_wpa8021x(if_name, 0);
        
    }
    
}

void setup_wlaninterface(struct config_interfaces *target) {

    int retries = 3, res;
    struct config_ssid *match = first_matching_network(target);
    char * if_name = target->if_name;

    if (!match)
        return;

    if (network_matches(if_name, match)) {
    
        printf("already using matched ssid, we do nothing\n");
        return;
        
    }

    printf("setting up network: %s\n", match->ssid_name);
    set_network_id((char*)match->ssid_name, if_name);
    printf("%s\n", match->ssid_auth);
        
    if (strcmp(match->ssid_auth, "802.1x") == 0) {

        printf("do 8021x stuff\n");
        cleanup_interface(if_name, 8);
        set_bssid((char*)match->ssid_bssid, if_name);
        set_wpa8021x(if_name, 1);
        config_wpa_supplicant(if_name, match);

    } else if(strcmp(match->ssid_auth, "wpa") == 0) {

        printf("do wpa stuff\n");
        cleanup_interface(if_name, 4);
        set_psk_key((char*)match->ssid_name, (char*)match->ssid_pass, if_name, 1);

    } else if(strcmp(match->ssid_auth, "wep") == 0) {

        printf("do wep stuff\n");
        cleanup_interface(if_name, 2);
        set_wep_key((char*)match->ssid_pass, if_name, 1);

    } else if(strcmp(match->ssid_auth, "none") == 0) {

        printf("no security has been set\n");
        cleanup_interface(if_name, 1);
    
    }
	
	if (match->ipv6_auto)
        set_ipv6_auto(if_name);        

    start_dhclient(if_name);

    while(retries != 0) {
    
        if(connection_active(if_name)) {
    
            // if we are successfully connected to the network
            // and we don't need additional auth, then we are good
    
            res = internet_connectivity_check(match);
    
            if(res == 1)
                return;
                    
            else if(res == 2) {
                // this is a hotspot; run user-defined command
                // or open default web browser
                hotspot();
                return;
            
            } else {

                printf("not active, waiting...\n");
                sleep(10);
                retries--;
                
            }
                
        }

    }

}

void setup_ethernetinterface(struct config_interfaces *cur) {

    // do all the stuff

}


// if interface is running, returns 1
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
    
    if(if_found) return 1;
    else if(if_hasaddr) return 1; 
    else return 0;
    
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

int main(int count, char **options) {

    //int res;
    //res = daemon(0, 0);
    //printf("return value: %s\n", res);

    int running = 1;

    if (parse_config()) {

        printf("error reading configuration!\n");
        return 1;

    }
    
    stat(config_file, &config_last_mod);
    printf("last config modified time: %s\n", ctime(&config_last_mod.st_mtime));
    //signal(SIGCHLD, check_wpa_sup_died);
    //start_wpa_supplicant();

    while (running) {

        struct config_interfaces *cur = config;

        printf("checking if conf file has changed\n");
        if(config_changed()) {
            
            memset(&cur, 0, sizeof(cur));
            
            if (parse_config()) {

                printf("error reading configuration!\n");
                cur = NULL;

            }
    
        }

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
