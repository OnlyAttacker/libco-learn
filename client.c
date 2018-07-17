#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#define MAXLINE 1024
int main(int argc,char **argv)
{
	char *servInetAddr = "127.0.0.1";
	int socketfd;
	struct sockaddr_in sockaddr;
	char recvline[MAXLINE], sendline[MAXLINE];
	int n;

	if(argc != 2)
	{
		printf("client <ipaddress> \n");
		exit(0);
	}

	/**
		#include <sys/socket.h>　
		int socket(int family, int type, int protocol);   //指定期望的通信协议类型，返回的文件描述符和套接字描述符类似，我们成为套接字描述符，简称sockfd  
		family:协议族
		AF_INET	IPv4协议　
		AF_INET6	IPv6
		AF_LOCAL	Unix域协议（15章）
		AF_ROUTE　	路由套接字（18章）
		AF_KEY	密钥套接字（19章）
		type:套接字的类型
		SOCK_STREAM（常用）	字节流套接字
		SOCK_DGRAM	数据报套接字
		SOCK_SEQPACKET　	有序分组套接字
		SOCK_RAW	原始套接字

		protocol：协议类型的常量或设置为0，以选择给定的family和type组合的系统默认值
		IPPROTO_TCP	TCP传输协议
		IPPROTO_UDP	UDP传输协议
		IPPROTO_SCTP	SCTP传输协议
	*/
	socketfd = socket(AF_INET,SOCK_STREAM,0);
	memset(&sockaddr,0,sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(10004);

	/**
		#include<arpa/inet.h>
		int inet_pton(int family,const char *strptr,void *addrptr);//成功返回1，格式不对返回0，出错返回-1
		//作用：p代表表达式 n代表数值  以后所写的所有代码中都有可能会需要这个函数，所以这个函数很重要
	*/
	inet_pton(AF_INET,servInetAddr,&sockaddr.sin_addr);
	/**
		#include <sys/socket.h> 
		int connect(int sockfd,const struct sockaddr* servaddr,socklen_t addrlen);//用connect函数来建立与TCP服务器的连接
	*/
	if((connect(socketfd,(struct sockaddr*)&sockaddr,sizeof(sockaddr))) < 0 )
	{
		printf("connect error %s errno: %d\n",strerror(errno),errno);
		exit(0);
	}

	printf("send message to server\n");

	fgets(sendline,1024,stdin);

	/**
		#include <sys/socket.h> 
		int send( SOCKET s, const char FAR *buf, int len, int flags );  
	*/
	// if((send(socketfd,sendline,strlen(sendline),0)) < 0)  
    //这里使用write测试  	ssize_t write(int filedes, const void *buf, size_t nbytes);

	if((write(socketfd,sendline,strlen(sendline))) < 0)
	{
		printf("send mes error: %s errno : %d",strerror(errno),errno);
		exit(0);
	}

	close(socketfd);
	printf("exit\n");
	exit(0);
}