#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>

#define MAX_PAYLOAD 1024

#define NETLINK_TEST 30

int main(int argc, char **argv){
	struct sockaddr_nl dest_addr;
	struct nlmsghr *nlh = NULL;
	struct iovec iov;
	int sock_fd = -1;
	struct msghdr msg;
	int ret = 0;
	
	sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
	if(sock_fd == 0){
		perror("can not create netlink socket.\n");
		return -1;
	}

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;
	dest_addr.nl_groups = 0;
	
	ret = bind(sock_fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
	if (-1 == ret){
		perror("can not bind sockfd with sockaddr_nl.\n");
		return -1;
	}

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	if (!nlh){
		perror("alloc memory failed.\n");
		return -1;
	}

	memset(nlh, 0, MAX_PAYLOAD);
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_type = NLMSG_NOOP;
	nlh->nlmsg_flags = 0;

	strcpy(NLMSG_DATA(nlh), argv[1]);

	memset(&iov, 0, sizeof(iov));

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	
	sendmsg(sock_fd, &msg, 0);
	printf("wait message from kernel.\n");
	memset((char *)NLMSG_DATA(nlh), 0, 1024);
	recvmsg(sock_fd, &msg, 0);
	printf("got response: %s\n", NLMSG_DATA(nlh));

	close(sock_fd);
	free(nlh);
	return 0;
}
