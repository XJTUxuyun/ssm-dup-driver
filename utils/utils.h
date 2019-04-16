#ifndef _UTILS_H
#define _UTILS_H

#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>

#define PIDFILENAME "/var/run/netmanager.pid"

extern int pidfile_write(int pid);
extern void pidfile_rm(void);
extern int is_running(void);

#endif
