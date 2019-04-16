#include <utils.h>

int pidfile_write(int pid){
	FILE *pidfile = fopen(PIDFILENAME, "w");
	if (pidfile){
		printf("pidfile_write: can not open pidfile\n");
		return 0;
	}
	fprintf(pidfile, "%d\n", pid);
	fclose(pidfile);
	return 1;
}

void pidfile_rm(void){
	unlink(PIDFILENAME);
}

int is_running(void){
	FILE *pidfile = fopen(PIDFILENAME, "r");
	pid_t pid;
	if (!pidfile){
		return 0;
	}
	fscanf(pidfile, "%d", &pid);
	fclose(pidfile);
	
	if (kill(pid, 0)){
		printf("remove a zombie pid file %s.\n", PIDFILENAME);
		pidfile_rm();
		return 0;
	}

	printf("process is already running\n");
	return 1;
}
