#ifndef FWCConnect__h
#define FWCConnect__h

#include <sys/types.h>
#include <time.h>

#define ERR_EXIT(m) \
	do \
	{ \
		perror(m); \
		return -1; \
	}while(0)

typedef struct progress{
	unsigned char protocol_type;	//规定0x03。标记协议类型。
	unsigned char message_type;	//规定0x01。规定消息类型。仅一种消息类型：进度报告。
	pid_t module_pid;	//发出报告进程的pid，以便主控程序定位到子进程的模块
	unsigned long timestamp;	//Linux时间戳，精确到毫秒。
	unsigned char level;          //报告等级，见下。
	unsigned char progress;        //进度百分数，由各采集器自行计算。合法值为0-100
	unsigned short reserved;       //保留字段。
	unsigned char description[51];	//不定长,描述，ASCII编码，\0结尾，长度不超过50个字节。
}progress;

extern int FWC_client_init(int * socketfd);       //客户端初始化并connect到主控程序，成功返回0，失败返回-1,socketfd为指向socket文件描述符的指针

/*
客户端向主控程序报告自身进度。成功返回0，失败返回-1
level代表报告等级，详见详细设计15页
per代表百分比，整型，合法范围为0-100
desc代表描述，ASCII编码，\0结尾，长度不超过50个字节。
*/
extern int FWC_progress_report(int sock,int level,int per,char *desc); 

/*
回收资源
*/
extern int FWC_client_recovery(int * sock);

#endif
