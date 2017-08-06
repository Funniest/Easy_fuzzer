#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <time.h>
#include <stdlib.h>
#include <fcntl.h>

//insert data
char* insert_data(char* src, char* insert, int pos){
	int size = strlen(src) + strlen(insert);
	char *str = (char*)malloc((sizeof(char) * size) + 1);
	memset(str, 0x00, size + 1);
	
	strncpy(str, src, pos);
	strcat(str, insert);
	strcat(str, (src + pos));

	return str;
}

//random mutation data
int mutation(){
	int fd;
	char *test_case[] = {{"\%n"}, {"\%s"}, 
		                  {"\%x"}, {"\\x00"}};
	char menu[] = {'1', '2'};

	fd = open("input", O_WRONLY);
	if(fd == -1){
		printf("file not open!\n");
		return NULL;
	}
	
	int menu_rand = 0;
	srand(time(NULL));
	
	//menu select
	menu_rand = rand() % 2;
	write(fd, &menu+menu_rand, 1);
	write(fd, "\n", 1);

	int test_case_rand = 0;
	int test_case_number = 0;
	int str_lens = 0;
	test_case_rand = rand() % 4; //select test case
	str_lens = rand() % 512 + 1; //select data lens
	test_case_number = rand() % 10 + 1; //input test case number

	char *str = (char *)malloc(sizeof(char) * str_lens);
	int i = 0;
	for(i = 0; i < str_lens; i++){
		str[i] =  rand() % 26 + 'A';
	}

	char *mutation_data = str;
	char *old_data = NULL;
	//insert test case in data
	printf("insert : %s\n", *(test_case + test_case_rand));
	for(i = 0; i < test_case_number; i++){
		mutation_data = insert_data(mutation_data, *(test_case + test_case_rand), (rand() % str_lens));

		if(i != 0)
			free(old_data);

		if(i == test_case_number - 1){
			printf("mutation ok!\n");
			break;
		}

		old_data = mutation_data;
	}
	
	write(fd, mutation_data, strlen(mutation_data));

	free(mutation_data);
	close(fd);

	return 0;
}

int main(int argc, char *argv[])
{
	pid_t child;
	int status, signum;
	struct user_regs_struct regs;

	mutation();
	
	//fork child
	child = fork();
	if (child == 0)
	{
		// ./vuln < input
		const char *filename = "input";  // or "input.txt" — the question uses both
		int fd = open(filename, O_RDONLY);
		if (fd < 0){
			printf("open error!\n");
			return 0;
		}
		if (dup2(fd, STDIN_FILENO) < 0){
			printf("dup2 fails~!\n");
			return 0;
		}
		close(fd);  // In theory, it could fail, but there isn't much you can do about it

		//trace me!
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		printf("= fork() =\n");
		execlp("/home/user/Desktop/Fuzzer/clear/easy_fuzzer/buf", "/home/user/Desktop/Fuzzer/clear/easy_fuzzer/buf", (char *)NULL);
		printf("Fail fork!\n");		
		return 0;
	}
	
	wait((int*) 0);
	ptrace(PTRACE_CONT, child, NULL, NULL);
	waitpid(child, &status, 0);
	
	//buffer overflow 
	if(!WIFEXITED(status)){
		ptrace(PTRACE_GETREGS, child, NULL, &regs);
		printf ("[!]oveflow rip: 0x%llx\n", regs.rip);
		system("cp input ./crash");
	}

	//not is detach!
	if(ptrace(PTRACE_DETACH, child, NULL, NULL) == -1){
		printf("[!]No Dettach!\n");
	}

	return 0;
}
