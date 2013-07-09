#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

unsigned long count=0;

int main(int argc, char *argv){
	
	int i, j;
	int a = 7;
	int b = 3;
	int c;
	int pid, ffork;

	printf("main pid: %d\n", getpid());	
	
	sleep(20);

	while(count < 10){	

		pid = fork();

		if(!pid){
						
			for(i=0; i < 10; i++){
	
				if(i == 5){
					ffork = fork();
					if(!ffork){
						for(j = 0; j < 10; j++) printf("%d, ", j);
					}
				printf("fforked pid: %d\n", ffork);
				}				 
				c = ( a + b ) % 255;
				a = ( c + b ) % 255;
				b = ( a + c ) % 255;
				printf(" %d:%d:%d \n", c, a, b);
				sleep(2);
			}
			exit(0);
		}
		printf("forked pid: %d\n", pid);
		count += 1;
		printf("counter : %ld, sleep...\n", count);
		sleep(20);
	}

	return 0;
}
