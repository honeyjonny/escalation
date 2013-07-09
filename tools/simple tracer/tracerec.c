#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>

/* 
	Set to 1 if you want to log all process trace to stdout
	Set to 0 otherwise
						*/

#define LOGTRACE 0 

int usage(){
	puts("Usage: tracerec <pid>");
}

void trace(unsigned long ppid, int pstat, long long *counter){

	int fstat;
	struct user usr;
	struct user_regs_struct regs;
	unsigned long new_fork = 0;
	unsigned long old_fork = 0;
	long instruction;

	while(1){
				wait(&pstat);
				if(WIFEXITED(pstat)) break;
			
				if(LOGTRACE){	
					ptrace(PTRACE_GETREGS, ppid, 0, &regs);
					printf("[~] pid: %ld eip : %lx", ppid, regs.eip);
					instruction = ptrace(PTRACE_PEEKTEXT, ppid, regs.eip, 0);
					printf(" : %lx\n", instruction);
				}

				if(ptrace(PTRACE_GETEVENTMSG, ppid, 0, &new_fork) != -1){
					if(new_fork > ppid && new_fork != old_fork){
						old_fork = new_fork; 
						printf("[*] ppid: %ld forked to pid: %ld, start trace pid: %ld\n", ppid, new_fork, new_fork);
						
						trace(new_fork, fstat, counter);
				
						printf("[#] pid: %ld was exited, continue to trace ppid: %ld\n", new_fork, ppid);
						
					}
				}		

				if (ptrace(PTRACE_SINGLESTEP, ppid, 0, 0) != 0){
					printf("[!] ppid: %ld ", ppid);
					perror("tracing error");
				}
				
				/* 	
					Insert you payload here 
					It's just instruction counter now 
														*/
				(*counter)++;
			}

}


long long counter = 0;

int main(int argc, char * argv[])
{
    int pstat;           
    unsigned long root_pid;

		if(argc < 2){
			usage();
			exit(1);
		}
		
		root_pid = strtoul(argv[1], 0, 10);

		if(ptrace(PTRACE_ATTACH, root_pid, 0, 0) != 0){
			perror("[!] attach error");
			exit(1);
		}
		
		if(ptrace(PTRACE_SETOPTIONS, root_pid, 0, PTRACE_O_TRACEFORK) != 0){
			perror("[!] set trace fork error");
			exit(1);
		}
		
		printf("[|] start tracing: %ld\n", root_pid);
	
		trace(root_pid, pstat, &counter);
		
		/*
			Show result
						*/
						
        printf("counter : %lld\n", counter);
        return 0;
}
