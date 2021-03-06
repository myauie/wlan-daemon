#include <sys/wait.h>

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "network.h"
#include "supplicant.h"
#include "wpa_ctrl.h"

/* Default directory wpa_supplicant uses for Unix domain sockets. */ 
char 		wpa_daemon_ctrl[] = "/var/run/wlan-daemon";
struct wpa_ctrl *wpa_client = 0;

int 
start_wpa_supplicant(char *if_name, pid_t supplicant_pid, int flag) {
        /* Flag: 0 for Ethernet, 1 for wlan. */
        /* If PID is non-zero, wpa_supplicant already running. */
        if (supplicant_pid)
            return 0;
        /* Fork wpa_supplicant as child process and assign its PID to supplicant_pid. */
        supplicant_pid = fork();
        if (supplicant_pid == -1) {
            printf("error forking: %s\n", strerror(errno));
        } else if (supplicant_pid) {
            /* Parent process. */
            printf("forked, pid=%d\n", supplicant_pid);
            return supplicant_pid;
        } else {
            /* Child process. */
            int 		arg = 0;
            char          **args;
            struct config_interfaces *cur;
            
            args = malloc(sizeof(char *) * (7 + 2));
            args[arg++] = "wpa_supplicant";
            args[arg++] = "-i";
            args[arg++] = if_name;
            args[arg++] = "-D";
            if (flag)
                args[arg++] = "openbsd";
            else
                args[arg++] = "wired";
            args[arg++] = "-C";
            args[arg++] = wpa_daemon_ctrl;
            args[arg] = 0;
            execv("/usr/local/sbin/wpa_supplicant", args);
            printf("!!! wpa_supplicant error\n");
        }
}

void 
check_wpa_sup_died() {
        int 		status   , pid;

        for (struct config_interfaces * cur = config; cur; cur = cur->next) {
            pid = waitpid(cur->supplicant_pid, &status, WNOHANG);
            if (pid != supplicant_pid)
                continue;
            if (!WIFEXITED(status) && !WIFSIGNALED(status))
                continue;
            printf("wpa_supplicant DEADED\n");
            start_wpa_supplicant(cur->if_name, 0, 
                !(strcmp(mediatype(cur->if_name), "Ethernet") == 0));
        }
}

void 
wpa_unsolicited(char *msg, size_t len) {
        printf("wpa_unsolicited_message: %s\n", msg);
} 

int 
sup_cmd(char *result, char *cmd,...) {
        va_list args;
        int 		res;
        char 		cmdbuf   [256];
        size_t replen = 512;

        if (!wpa_client)
            return -1;
            /* Not attached to wpa_supplicant control interface. */ 
        va_start(args, cmd);
        vsnprintf(cmdbuf, 256, cmd, args);
        va_end(args);
        res = wpa_ctrl_request(wpa_client, cmdbuf, strlen(cmdbuf), result, &replen, wpa_unsolicited);
        if (res)
            return res;
} 

int 
connect_wpa_supplicant(char *if_name) {
        char 		unixsock [256];

        snprintf(unixsock, 256, "%s/%s", wpa_daemon_ctrl, if_name);
        printf("starting wpa_supplicant conversation\n");
        if (!wpa_client)
            wpa_ctrl_close(wpa_client);
        wpa_client = 0;
        for (int retries = 3; retries > 0; retries--) {
            wpa_client = wpa_ctrl_open(unixsock);
            if (wpa_client)
                break;
            sleep(2);	
        } 
        if (!wpa_client) {
            printf("failed to create wpa_supplicant connection\n");
            return 0;
        } 
        return 1;
} 

int 
status_wpa_supplicant(char *if_name) {
        char           *cmd = "STATUS", result[512], key[40], val[60],
                       *cur = 0;
        int 		bytes;

        if (!connect_wpa_supplicant(if_name))
            return 0;
        if (sup_cmd(result, cmd) == -1);
            return 0;
        cur = result;
        for (int i = 0; i < 13; i++) {
            sscanf(cur, "%[^=]=%[^\n]\n%n", key, val, &bytes);
            cur += bytes;
            if (strcmp(key, "suppPortStatus") == 0 && strcmp(val, "Authorized") == 0)
                return 1;
        } 
        return 0;
}

int 
config_wpa_supplicant(char *if_name, struct config_ssid * match, int toggle) {
        char 		repbuf   [256];
        int 		res      , network_number = -1, wait = 5;

        if (!connect_wpa_supplicant(if_name))
            return 0;
        if (toggle) {
            res = sup_cmd(repbuf, "AP_SCAN 0");
            if (res < 0)
                return res;
            res = sup_cmd(repbuf, "ADD_NETWORK");
            if (res < 0)
                return res;
            sscanf(repbuf, "%d", &network_number);
            if (network_number < 0)
                return -1;
                /* Failed to create new network. */
            res = sup_cmd(repbuf, "SET_NETWORK %d auth_alg OPEN", network_number);
            if (res < 0)
                return res;
            if (strlen(match->ssid_key_mgmt)) {
                res = sup_cmd(repbuf, "SET_NETWORK %d key_mgmt %s", network_number, match->ssid_key_mgmt);
                if (res < 0)
                    return res;
            } 
            if (strlen(match->ssid_pairwise)) {
                res = sup_cmd(repbuf, "SET_NETWORK %d pairwise %s", network_number, match->ssid_pairwise);
                if (res < 0)
                    return res;
            } 
            if (strlen(match->ssid_group)) {
                res = sup_cmd(repbuf, "SET_NETWORK %d group %s", network_number, match->ssid_group);
                if (res < 0)
                    return res;
            }
            res = sup_cmd(repbuf, "SET_NETWORK %d proto WPA2", network_number);
            if (res < 0)
                return res;
            if (strlen(match->ssid_eap)) {
                res = sup_cmd(repbuf, "SET_NETWORK %d eap %s", network_number, match->ssid_eap);
                if (res < 0)
                    return res;
            } 
            if (strlen(match->ssid_phase1)) {
                printf("phase 1: %s\n", match->ssid_phase1);
                res = sup_cmd(repbuf, "SET_NETWORK %d phase1 \"%s\"", network_number, match->ssid_phase1);
                if (res < 0)
                    return res;
            } 
            if (strlen(match->ssid_phase2)) {
                printf("phase 2: %s\n", match->ssid_phase2);
                res = sup_cmd(repbuf, "SET_NETWORK %d phase2 \"%s\"", network_number, match->ssid_phase2);
                if (res < 0)
                    return res;
            } 
            if (strlen(match->ssid_ca_cert)) {
                printf("ca_cert: %s\n", match->ssid_ca_cert);
                res = sup_cmd(repbuf, "SET_NETWORK %d ca_cert %s", network_number, match->ssid_ca_cert);
                if (res < 0)
                    return res;
            } 
			if (strlen(match->ssid_client_cert)) {
                printf("client_cert: %s\n", match->ssid_client_cert);
                res = sup_cmd(repbuf, "SET_NETWORK %d client_cert %s", network_number, match->ssid_client_cert);
                if (res < 0)
                    return res;
            } 
            if (strlen(match->ssid_private_key)) {
                printf("private_key: %s\n", match->ssid_private_key);
                res = sup_cmd(repbuf, "SET_NETWORK %d private_key %s", network_number, match->ssid_private_key);
                if (res < 0)
                    return res;
            }
			if (strlen(match->ssid_private_key_pwd)) {
                printf("private key password: %s\n", match->ssid_private_key_pwd);
                res = sup_cmd(repbuf, "SET_NETWORK %d private_key_passwd %s", network_number, match->ssid_private_key_pwd);
                if (res < 0)
                    return res;
            }
			if (match->ssid_eapol) {
                printf("eapol_flags: %d\n", match->ssid_eapol);
                res = sup_cmd(repbuf, "SET_NETWORK %d eapol_flags %d", network_number, *match->ssid_eapol);
                if (res < 0)
                    return res;
            }
            if (strlen(match->ssid_identity)) {
                printf("identity: %s\n", match->ssid_identity);
                res = sup_cmd(repbuf, "SET_NETWORK %d identity \"%s\"", network_number, match->ssid_identity);
                if (res < 0)
                    return res;
            }
            if (strlen(match->ssid_anonymous)) {
                printf("anonymous identity: %s\n", match->ssid_anonymous);
                res = sup_cmd(repbuf, "SET_NETWORK %d anonymous_identity \"%s\"", network_number, match->ssid_anonymous);
                if (res < 0)
                    return res;
            }                        
            if (strlen(match->ssid_pass)) {
                printf("pass: %s\n", match->ssid_pass);
                res = sup_cmd(repbuf, "SET_NETWORK %d password \"%s\"", network_number, match->ssid_pass);
                if (res < 0)
                    return res;
            }
            res = sup_cmd(repbuf, "SET_NETWORK %d mode 0", network_number);
            if (res < 0)
                return res;
            if (match->ssid_bssid) {
                res = sup_cmd(repbuf, "BSSID %d %s", network_number, match->ssid_bssid);
                if (res < 0)
                    return res;
            }
            if (match->ssid_name)
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
            if (res < 0)
                return res;
            for (wait = 5; wait > 0; wait--) {
                if (status_wpa_supplicant(if_name))
                    break;
                sleep(5);
            } 
        } else {
            res = sup_cmd(repbuf, "DISABLE_NETWORK all");
            if (res < 0)
                return res;
            res = sup_cmd(repbuf, "REMOVE_NETWORK all");
            if (res < 0)
                return res;
        }
        wpa_ctrl_close(wpa_client);
        wpa_client = 0;
        return res;
}
