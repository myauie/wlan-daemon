#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "status.h"

int
main(int argc, char **argv) {
        int 		s;
        struct sockaddr_un client;
        struct wd_event ev;
        char 		cmd      [160];

        memset(&client, 0, sizeof(client));
        unlink("/tmp/wlan-status");
        s = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (s == -1) {
            printf("error opening socket: %s\n", strerror(errno));
            return -1;
        }
        client.sun_len = snprintf(client.sun_path, sizeof(client.sun_path), "/tmp/wlan-status");
        client.sun_family = AF_UNIX;
        if (bind(s, (struct sockaddr *) & client, sizeof(client)) != 0)
            printf("error binding socket: %s\n", strerror(errno));
        while (1) {
            int 		sz = recv(s, &ev, sizeof(ev), 0);
            if (sz != sizeof(ev))
                continue;
            switch (ev.event) {
                case CONNECTING:
                    printf("connecting\n");
                    snprintf(cmd, sizeof(cmd), "notify-send \"connecting to %s\"", ev.message);
                    printf("%s\n", cmd);
                    system(cmd);
                    break;
                case CONNECTED:
                    printf("connected\n");
                    snprintf(cmd, sizeof(cmd), "notify-send \"connected to %s\"", ev.message);
                    system(cmd);
                    printf("%s\n", cmd);
                    break;
                case AUTH_REQUIRED:
                    printf("auth required: %s\n", ev.message);
                    snprintf(cmd, sizeof(cmd), "xdg-open http://%s/", ev.message);
                    system(cmd);
                    break;
                case CUSTOM_AUTH:
                    printf("custom authorisation: %s\n", ev.message);
                    system(ev.message);
                    break;
                default:
                    printf("unknown event type\n");
                    break;
            }
        }
}
