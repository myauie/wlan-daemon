#ifndef STATUS_H
#define STATUS_H

enum wd_events {
        CONNECTING,
        CONNECTED,
        AUTH_REQUIRED,
        CUSTOM_AUTH
};

struct wd_event {
        enum wd_events 	event;
        char 		message  [80];
};

#endif	/* STATUS_H */
