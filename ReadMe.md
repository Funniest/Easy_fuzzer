# Fuzzer sutdy, use ptrace!
### Fuzzing?
퍼징이란, 랜덤값 또는 시퀀셜한 값을 어플리케이션의 다양한 필드에 삽입하여 밝혀지지 않은 취약점을 찾아주는 것을 도와주는 도구입니다.

랜덤값 입력의 대상은 어플리케이션 뿐만 아니라, 파일포메스 프로토콜, 환경변수, 마우스나 키보드 이벤트, API호출 등의 프로그램 입력 값에도 응용이 되고 있습니다.

### 퍼징 분류
퍼징은 크게 두가지 분류로 나뉩니다.
1. 덤프 버징
2. 스마트 퍼징

먼저 ***덤프 퍼징*** 이란, 단순히 샘플 파일의 일부를 변형하여 파일을 실행(또는 랜덤 값 무작위 대입)하고, 모니터링 하는 형태입니다.

이 때 크래쉬가 발생하면, 해당 변형 파일과 레지스터 정보 등을 저장합니다.

***스마트 퍼징*** 이란, 타겟 프로그램의 파일 포멧을 분석하여 포멧에 맞춰 변형한 샘플을 만들어야 하기 떄문에 구현 난이도가 높습니다.

덤프 퍼징은 무작위 대입으로 효율이 떨어지지만, 스마트 퍼징은 특정 프로그램에 맞춰 테스트 값을 제작하기 때문에 효율적입니다.

### 퍼져의 종류
1. 로컬 Fuzzer
2. 파일 포멧, 프로그램 실행 인자 및 환경변수.
3. 프로토콜
4. 웹 어플리케이션
5. 메모리
등의 다양한 퍼져의 종류가 있습니다.

### 퍼져 제작!
이제 간단하게 퍼져를 제작해 보도록 하겠습니다.

#### ptrace

먼저 ***ptrace*** 에 대한 설명을 먼저 드리도록 하겠습니다.

***ptrace*** 는 리눅스 기반 생성된 프로세스가 어떻게 움직이며, 어떤식으로 데이타를 읽고 쓰는지, 어떤에러를 내는지 추적을 하기위해 마련된 시스템 콜입니다.

```
#include <sys/ptrace.h>

long int ptrace(enum __ptrace_request request, pid_t pid, void * addr, void * data)  
```

먼저, request에 들어가는 인자들을 설명하겠습니다.

|request               |description| 
|:-------------------:|:------:|
|PTRACE_TRACEME                   |이 프로세스는 이 프로세스의 부모에 의해 추적되어 진다는것을 가르킵니다.                                      |
|PTRACE_PEEKTEXT, PTRACE_PEEKDATA |자식 프로세스 메모리의 addr위치의 워드(word)를 읽고 ptrace 콜의 결과로써 워드를 반환한다.                  |
|PTRACE_PEEKUSER                  |레지스터와 프로세스에 관한 다른 정보를 가지고 있는 자식 프로세스의 USER 공간에 있는 변위 addr 의 워드를 읽는다.|
|PTRACE_POKETEXT, PTRACE_POKEDATA |부모 프로세스 메모리에 있는 위치 data에서 자식 프로세스 메모리에 있는 위치 addr으로 word를 복사한다.       |
|PTRACE_POKEUSER                  |부모 프로세스 메모리에 있는 위치 data에서 자식 프로세스의 addr USER 영역으로 word를 복사한다.              |
|PTRACE_GETREGS, PTRACE_GETFPREGS |자식 프로세스의 범용 또는 부동 소수점 레지스터들을 각각 부모 프로세스의 data 위치로 복사한다.               |
|PTRACE_SETREGS, PTRACE_SETFPREGS |부모 프로세스의 data 위치에서 자식 프로세스의 범용 또는 부동 소수점 레지스터들을 각각 복사한다.              |
|PTRACE_CONT                      |중지된 자식 프로세스를 다시 시작한다.                                                                 |
|PTRACE_SYSCALL, PTRACE_SINGLESTEP|PTRACE_CONT처럼 중지된 자식의 프로세스를 다시 시작한다.                                                 |
|PTRACE_KILL                      |종료하도록 하기 위해 SIGKILL을 자식에게 보낸다.(addr와 data는 무시된다.)                                 |
|PTRACE_ATTACH                    |pid로 지정된 프로세스에 부착시키고, 현재 프로세스의 "child"를 추적하도록 만든다.                          |
|PTRACE_DETACH                    |PTRACE_CONT처럼 중지된 자식을 다시 시작한다.                                                         |

return 값의 설명은 아래와 같습니다.
```
성공시, PTRACE_PEEK* request들은 다른 request들이 0을 반환하는 동안에 요구된 데이터를 반환한다. 실패시, 모든 request들은 -1을 반환하며 errno(3)는 적당한 값으로 설정된다. PTRACE_PEEK* request가 성공시 반환되는 값이 -1일수도 있기 때문에, 호출자는 request 후에 에러가 발생했는지 아닌지를 결정하기 위해 errno 를 검사해야 한다.
```

[출저] : <http://linux4u.kr/manpage/ptrace.2.html>

#### 내가 만들 퍼져 시나리오!
취약한 vuln파일이 있다고 가정합니다.

vuln파일은 실행 시키면 두 가지 메뉴가 나오는데, 1번 bof테스트와 2번 quit입니다.

퍼져는 랜덤한 길이로 값을 무작위로 생성하고, 사이에 정해놓은 test case들을 섞어넣습니다.

만약 bof가 발생하면, input파일을 crash 폴더에 저장해 놓습니다.

### 소스코드
환경은 Ubuntu 16 64bit환경에서 진행하였습니다 '-'!

취약한 vuln에 대해서 fuzzing을 하는 간단한 소스입니다!

#### fuzzer.c
```
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

```

#### vuln.c
```
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
```
