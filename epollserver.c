#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <arpa/inet.h>

#define MAXLINE 1024
#define MAX_EPOLL_SIZE 10000
int main(int argc,char **argv)
{
	int listenfd,connfd;
	struct sockaddr_in sockaddr;
	char buff[MAXLINE];
	int n;

	memset(&sockaddr,0,sizeof(sockaddr));

	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	sockaddr.sin_port = htons(10004);


	listenfd = socket(AF_INET,SOCK_STREAM,0);

	/**
		1. int epoll_create(int size);	创建一个epoll的句柄，size用来告诉内核这个监听的数目一共有多大。这个参数不同于select()中的第一个参数，给出最大监听的fd+1的值。
	*/
	int epfd = epoll_create(MAX_EPOLL_SIZE);

	/**
	
	2. int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
	epoll的事件注册函数，它不同与select()是在监听事件时告诉内核要监听什么类型的事件，而是在这里先注册要监听的事件类型。第一个参数是epoll_create()的返回值，
	第二个参数表示动作，用三个宏来表示：
	EPOLL_CTL_ADD：注册新的fd到epfd中；
	EPOLL_CTL_MOD：修改已经注册的fd的监听事件；
	EPOLL_CTL_DEL：从epfd中删除一个fd；
	第三个参数是需要监听的fd，第四个参数是告诉内核需要监听的事件
	typedef union epoll_data {
	    void *ptr;
	    int fd;
	    __uint32_t u32;
	    __uint64_t u64;
	} epoll_data_t;

	struct epoll_event {
	    __uint32_t events; 
	    epoll_data_t data; 
	};

	*/
	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = listenfd;
	int ret = epoll_ctl(epfd,EPOLL_CTL_ADD,listenfd,&ev);
	if(ret != 0){
		printf("error\n");
		exit(0);
	}

	bind(listenfd,(struct sockaddr *) &sockaddr,sizeof(sockaddr));

	listen(listenfd,1024);

	printf("Please wait for the client information\n");
	struct epoll_event events[MAX_EPOLL_SIZE]; 

	for(;;)
	{
		/**
		3.int epoll_wait(int epfd, struct epoll_event * events, int maxevents, int timeout);
		等待事件的产生，类似于select()调用。参数events用来从内核得到事件的集合，maxevents告之内核这个events有多大，
		这个 maxevents的值不能大于创建epoll_create()时的size，参数timeout是超时时间（毫秒，0会立即返回，-1将不确定，也有说法说是永久阻塞）。
		该函数返回需要处理的事件数目，如返回0表示已超时。
		*/
		int fds = epoll_wait(epfd,events,30,1);

		if(fds < 0){  
            printf("epoll_wait error, exit\n");  
            break;  
        }  
        for(int i = 0; i < fds; i++){  
           	int fd  = events[i].data.fd;  
            if((events[i].events & EPOLLIN) && fd == listenfd) // read event  fd = listenfd 则accept
            {  
            	if((connfd = accept(listenfd,(struct sockaddr*)NULL,NULL))==-1)
				{
					printf("accpet socket error: %s errno :%d\n",strerror(errno),errno);
					continue;
				}

				struct epoll_event ev;
				ev.events = EPOLLIN | EPOLLOUT;
				ev.data.fd = connfd;
				int ret = epoll_ctl(epfd,EPOLL_CTL_ADD,connfd,&ev);
				if(ret != 0){
					printf("error\n");
					exit(0);
				}

            }else if(events[i].events & EPOLLIN){
				n = read(fd,buff,MAXLINE);
				buff[n] = '\0';
				printf("recv msg from client:%s",buff);

            } else if(events[i].events & EPOLLOUT){
            	char *str = "HTTP/1.1 200 OK\r\nx-proxy-by: SmartGate-IDC\r\nDate: Tue, 17 Jul 2018 12:21:15 GMT\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 8\r\n\r\n11111111";
            	write(fd,str,strlen(str));
				close(connfd);
            }
        }  
	}
	close(listenfd);
}