#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]){
	int select = 0;
	char buf[256] = { 0, };

	printf("= Welcome bof program! =\n");
	printf("Select menu\n");
	printf("1. buffer overflow\n");
	printf("2. quit\n");
	printf("=-=-=-=-=-=-=-=-=-=-=-=-\n");
	printf(">> ");
	
	scanf("%d", &select);
	switch(select){
		case 1 :
			printf("Welcom bof menu!\n");
			printf(">> ");
			scanf("%s", buf);
			printf("Your input %s\n", buf);
			break;
		default :
			printf("Bye~~!\n");
			return 0;
	}
}
