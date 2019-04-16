#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <stddef.h>
#include <errno.h>

#define FREE_INIT(ptr) \
	do{ \
		free(ptr); \
		ptr = NULL; \
	} while(0)

#define MAX_MSG_LEN 1024

enum{
	NLMSG_TYPE_NONE=0,
	NLMSG_TYPE_SETPID,
	NLMSG_TYPE_KERNEL,
	NLMSG_TYPE_APP,
};

struct nlmsg{
	int type;
	int len;
	char msg[MAX_MSG_LEN];
};

#define NETLINK_TEST 25

int netlink_open(void){
	struct sockaddr_nl saddr;
 	int sockfd = -1, ret=0;
	sockfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
	if (-1 >= sockfd){
		perror("create socket error.\n");
		return -1;
	}
	memset(&saddr, 0, sizeof(saddr));
	saddr.nl_family = PF_NETLINK;
	saddr.nl_pid = getpid();
	saddr.nl_groups = 0;
	ret = bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (0 > ret){
		perror("bind socket error.\n");
		close(sockfd);
		return -1;
	}
	return sockfd;
}

int netlink_send(int sockfd, struct nlmsg *pmsg){
	struct msghdr msg;
	struct iovec iov;
	struct nlmsghdr *nlh = NULL;
	int msglen = pmsg->len;
	int totlen = NLMSG_SPACE(pmsg->len);
	int ret = 0;

	nlh = malloc(totlen);
	if (!nlh){
		printf("malloc error.\n");
		return -1;
	}

	nlh->nlmsg_len = totlen;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_pid = getpid();
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	memcpy(NLMSG_DATA(nlh), pmsg, msglen);
	ret = sendmsg(sockfd, &msg, 0);
	if (0 > ret){
		printf("sendmsg error.\n");
		FREE_INIT(nlh);
		return -1;
	}

	return 0;
}

int netlink_recv(int sockfd, struct nlmsg *pmsg){
	struct msghdr msg;
	struct iovec iov;
	struct nlmsghdr * nlh = NULL;
	
	int msglen = sizeof(*pmsg);
	int totlen = NLMSG_SPACE(sizeof(*pmsg));
	int ret = 0;
	
	nlh = malloc(totlen);
	if (!nlh){
		printf("malloc error.\n");
		return -1;
	}

	iov.iov_base = (void *)nlh;
	iov.iov_len = totlen;
	
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	memcpy(NLMSG_DATA(nlh), pmsg, msglen);
	ret = recvmsg(sockfd, &msg, 0);
	if (0 > ret){
		printf("recvmsg error.\n");
		FREE_INIT(nlh);
		return -1;
	}

	memcpy(pmsg, NLMSG_DATA(nlh), msglen);
	return 0;
}

void netlink_close(int sockfd){
	if (0 < sockfd){
		close(sockfd);
	}
}



int main(int argc, char **argv){
	int sockfd = -1, ret = 0;
	struct nlmsg msg;
	char psend[10] = {0};
	psend[0] = 'd';
	psend[1] = ':';
	psend[2] = 28;
	psend[3] = 10;
	psend[4] = 90;
	psend[5] = 99;
	memset(&msg, 0, sizeof(msg));
	sockfd = netlink_open();
	if (0 > sockfd){
		printf("netlink_open error.\n");
		return -1;
	}		

	msg.type = NLMSG_TYPE_SETPID;
	msg.len = strlen(psend) + offsetof(struct nlmsg, msg) + 1;
	memcpy(msg.msg, psend, strlen(psend));
	ret = netlink_send(sockfd, &msg);
	if (0 > ret){
		printf("netlink_send error.\n");
		return -1;
	}

	while(1){
		ret = netlink_recv(sockfd, &msg);
		if (0 > ret){
			printf("netlink_recv error.\n");
			return -1;
		}
		printf("msg %s\n", msg.msg);
	}

	netlink_close(sockfd);
	return 0;
}
