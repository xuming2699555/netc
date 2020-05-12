#include <stdio.h>
#include <stdlib.h>
/**libFWCConnect.h**/
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
// 包含open所需要的头文件
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
// 包含close所需要的头文件
#include <unistd.h>
// 包含errno所需要的头文件
#include <errno.h>
// 包含strerror所需要的头文件
#include <string.h>

/**FWCConnect.c**/
#include "FWCConnect.h"

int FWC_client_init(int * socketfd){  //客户端初始化并connect到主控程序，成功返回0，失败返回-1,socketfd为指向socket文件描述符的指针
	
	if(( *socketfd = socket(PF_UNIX,SOCK_STREAM,0) ) < 0 )
		ERR_EXIT("socket");
	struct sockaddr_un servaddr;
	memset(&servaddr,0,sizeof(servaddr));
	servaddr.sun_family=AF_UNIX;
	strcpy(servaddr.sun_path,"/tmp/FWCConnect_socket");

	if(connect(*socketfd,(struct sockaddr*)&servaddr,sizeof(servaddr))<0)
		ERR_EXIT("connect");

	return 0;
}    

/*
客户端向主控程序报告自身进度。成功返回0，失败返回-1
level代表报告等级，详见详细设计15页
per代表百分比，整型，合法范围为0-100
desc代表描述，ASCII编码，\0结尾，长度不超过50个字节。
*/
int FWC_progress_report(int sock,int level,int per,char *desc){
	progress msg;
	msg.message_type = 0x03;
	msg.message_type = 0x01;
	msg.module_pid = getpid();
	msg.timestamp = (unsigned long)time(NULL);
	msg.level = (unsigned char)level;
	msg.progress = (unsigned char)per;
	msg.reserved = 0;
	if (strlen(desc) > 50){
		perror("message is too long");
		return -1;
	}
	memset(msg.description,0,sizeof(char)*51);
	memcpy(msg.description,desc,strlen(desc));
	msg.description[strlen(desc)] = '\0';

	if (write(sock,&msg,sizeof(msg)) < 0){
		perror("write have something wrong");
		return -1;
	}

	return 0;
}

int FWC_client_recovery(int *sock){
	close(*sock);
	return 0;
}