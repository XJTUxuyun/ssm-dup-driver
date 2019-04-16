#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

char vip[256];
char ethX[256];
char gw[256];

void *arp_gratitous(void *arg){
	char cmd[1024] = {0};
	printf("\t start arp gratitous...\n");
	sprintf(cmd, "/sbin/arping -Uq -s %s -I %s %s", vip, ethX, gw);
	execl("/sbin/arping", "-Uq", "-s", vip, "-I", ethX, gw, "-c 5");
}

int main(int argc, char **argv){
	if(argc != 4){
		printf("usage: arputil vip ethX gw\n");
		exit(-1);
	}
	bzero(vip, 256);
	bzero(ethX, 256);
	bzero(gw, 256);

	strcpy(vip, argv[1]);
	strcpy(ethX, argv[2]);
	strcpy(gw, argv[3]);
	pthread_t thread;
	pthread_create(&thread, NULL, &arp_gratitous, NULL);
	pthread_join(thread, NULL);
}
