
#include "co_epoll.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int	co_epoll_wait( int epfd,struct co_epoll_res *events,int maxevents,int timeout )
{
	return epoll_wait( epfd,events->events,maxevents,timeout );
}
int	co_epoll_ctl( int epfd,int op,int fd,struct epoll_event * ev )
{
	return epoll_ctl( epfd,op,fd,ev );
}
int	co_epoll_create( int size )
{
	return epoll_create( size );
}

struct co_epoll_res *co_epoll_res_alloc( int n )
{
	struct co_epoll_res * ptr = 
		(struct co_epoll_res *)malloc( sizeof( struct co_epoll_res ) );

	ptr->events = (struct epoll_event*)calloc( 1,n * sizeof( struct epoll_event ) );

	return ptr;

}
void co_epoll_res_free( struct co_epoll_res * ptr )
{
	if( !ptr ) return;
	if( ptr->events ) free( ptr->events );
	free( ptr );
}
