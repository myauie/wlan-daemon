#ifndef STATUS_SERVER_H
#define STATUS_SERVER_H

#include "status.h"

int open_status_socket();
void update_status(enum wd_events stat, char *msg);

#endif
