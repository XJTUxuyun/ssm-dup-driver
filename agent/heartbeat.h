#ifndef _HEARTBEAT_H
#define _HEARTBEAT_H

enum{
	HEARTBEAT_OFFLINE=0,
	HEARTBEAT_ONLINE,
	HEARTBEAT_MASTER,
	HEARTBEAT_SLAVE
};

struct host_s{
	char ip[16];
	unsigned int port;
};

struct heartbeat_group_s{

};


#endif
