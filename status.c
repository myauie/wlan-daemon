#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "network.h"
#include "status_server.h"

int status_socket = -1;

int open_status_socket() {

    status_socket = open_socket(AF_UNIX);

    if(status_socket < 0) {

        printf("status socket could not be created\n");
        return -1;

    }

    return 0;

}

void update_status(enum wd_events stat, char *msg) {

    const char servername[] = "/tmp/wlan-status";
    struct wd_event ev;
    struct sockaddr_un server;

    server.sun_len = snprintf(server.sun_path, sizeof(server.sun_path), servername);
    server.sun_family = AF_UNIX;

    ev.event = stat;

    if(msg)
        snprintf(ev.message, sizeof(ev.message), "%s", msg);

    sendto(status_socket, &ev, sizeof(ev), 0, (struct sockaddr*)&server, sizeof(server));

}
