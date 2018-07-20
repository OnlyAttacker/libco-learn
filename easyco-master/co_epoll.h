#ifndef __CO_EPOLL_H__
#define __CO_EPOLL_H__
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <time.h>
#include <sys/epoll.h>
/**
    typedef union epoll_data {
        void *ptr;
         int fd;
         __uint32_t u32;
         __uint64_t u64;
     } epoll_data_t;//保存触发事件的某个文件描述符相关的数据

     tips: 由于epoll_data是union类型，所以在使用时通常定义个结构体，
     将定义的结构体放入ptr，使用epoll_data的ptr指针即可，
     这样就相当于使用magic，可以传入多个数据，事件触发时传回多个数据。

     struct epoll_event {
         __uint32_t events;
		epoll_data_t data;
	};
 */
/**
 * struct co_epoll_res 用于调用epoll_wait时将准备好的poll_event返回 co_epoll_res 跟定义epoll_events没什么区别
 */
struct co_epoll_res
{
	struct epoll_event *events;
};
int 	co_epoll_wait( int epfd,struct co_epoll_res *events,int maxevents,int timeout );
int 	co_epoll_ctl( int epfd,int op,int fd,struct epoll_event * );
int 	co_epoll_create( int size );
struct 	co_epoll_res *co_epoll_res_alloc( int n );
void 	co_epoll_res_free( struct co_epoll_res * );

#endif



