#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#define SLEEPSEC 20

int main(int argc, char *argv){
	
	int i;
	int pid;
	
	
	printf("main pid: %d\nsleep: %d sec\n", getpid(), SLEEPSEC);	

	sleep(SLEEPSEC);
	pid = fork();
	if(!pid){
		execl("/bin/ls","ls",0); 
	}
	printf("forked: %d\n", pid);
	return 0;
}
