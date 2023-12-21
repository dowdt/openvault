#ifndef NET_SOURCE_FILE
#define NET_SOURCE_FILE

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <sys/socket.h>
#include <resolv.h>

#include "types.h"
#include "util.c"

#ifdef __unix

#include <poll.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <threads.h>

// windows
#else

#endif


// need a basic api to cover sockets and stuff
// need to have each be abstract
// needs to work on windows and on unix

// connecting
// send data
// receive data

typedef struct
{
    void* data;
    unsigned int allocated;
    unsigned int capacity;
    mtx_t mutex;
} Arena;

typedef struct
{
    Arena arena;
    unsigned int bytes_read;
} Buffer;

void arena_init(Arena* arena, unsigned int capacity)
{
    arena->data = malloc(capacity);
    arena->capacity = capacity;
    mtx_init(&arena->mutex, 0);
}

void* arena_alloc(Arena* arena, unsigned int size)
{
    mtx_lock(&arena->mutex);
    if (arena->capacity == 0)
        arena->data = NULL;

    if (arena->allocated + size >= arena->capacity)
    {
        // grow until matching
        while (arena->allocated + size >= arena->capacity)
        {
            arena->capacity += arena->capacity / 2 + 1;
        }

        void* original = arena->data;
        arena->data = realloc(arena->data, arena->capacity);

        assert(arena->data != NULL, "Realloc failed, arena couldn't allocate");
    }

    void* res = arena->data + arena->allocated;
    arena->allocated += size;
    mtx_unlock(&arena->mutex);

    return res;
}

void* arena_calloc(Arena* arena, unsigned int size)
{
    void* ptr = arena_alloc(arena, size);
    memset(ptr, 0, size);
    return ptr;
}

void arena_append(Arena* arena, void* buf, unsigned int size)
{
    mtx_lock(&arena->mutex);
    void* addr = arena_alloc(arena, size);
    memcpy(addr, buf, size);
    mtx_unlock(&arena->mutex);
}

void arena_clear(Arena* arena)
{
    mtx_lock(&arena->mutex);
    arena->allocated = 0;
    mtx_unlock(&arena->mutex);
}
    
void arena_free(Arena* arena)
{
    mtx_lock(&arena->mutex);
    arena->capacity = 0;
    arena->allocated = 0;

    free(arena->data);
    arena->data = NULL;
    mtx_unlock(&arena->mutex);
    mtx_destroy(&arena->mutex);
}

typedef struct Socket
{
    int fd;
} Socket;


Arena net_arena;
Socket* s_last_added = NULL;
void net_init()
{
    arena_init(&net_arena, 1024);
}

void net_uninit()
{
    arena_free(&net_arena);
}


static atomic_ushort port_last = 29170;
unsigned short net_rand_port()
{
    assert(port_last < 29998, "theoretically outside of assigned range");
    return port_last++;
}

Socket* net_connect(const char* ip_addr, unsigned short port)
{
    Socket* sock;
    int fd, status;

    // actually get socket
    fd = socket(AF_INET, SOCK_STREAM, 0);

    // TODO: make this non blocking with fnctl or something else
    struct addrinfo hints, *addr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family		= AF_INET;
    hints.ai_socktype	= SOCK_STREAM;

    status = getaddrinfo(ip_addr, NULL, &hints, &addr);

    if (status != 0 || addr == NULL)
    {
        return NULL;
    }

    ((struct sockaddr_in*)addr->ai_addr)->sin_port = htons(port);

    {
        struct timeval tv;
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    }

    status = connect(sock->fd, (struct sockaddr*) addr->ai_addr, addr->ai_addrlen);

    if (status != 0)
    {
        return NULL;
    }

    sock = (Socket*) arena_calloc(&net_arena, sizeof(Socket));
    sock->fd = fd;
    return sock;
}

// what to do if someone connects to us?
Socket* net_listen(unsigned short port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
	/* setsockopt(fd, SOL_SOCKET, SO_SIGNOPIPE, &opt, sizeof(opt)); */

    struct sockaddr_in address;
	bzero(&address, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(port);

    assert(bind(fd, (struct sockaddr*) &address, sizeof(address)) == 0, "couldn't bind to port probably taken");
    printf("%s\n", strerror(errno));
    // TODO: check if there's a better number
    assert(listen(fd, 0) == 0, "couldn't listen port is probably taken");
    
    printf("%s\n", strerror(errno));

    Socket* sock = (Socket*) arena_calloc(&net_arena, sizeof(Socket));
    sock->fd = fd;

    return sock;
}

Socket* net_accept(Socket* listener, struct sockaddr* ret_addr, socklen_t* ret_addr_len)
{
    int fd = accept(listener->fd, ret_addr, ret_addr_len);

    if (fd == -1)
    {
        printf("%s", strerror(errno));
        return NULL;
    }
    else
    {
        Socket* conn = (Socket*) arena_calloc(&net_arena, sizeof(Socket));
        conn->fd = fd;
        return conn;
    }
}

void net_close(Socket* sock)
{
    /* if (sock->is_local) */
    /* { */
    /*     arena_free((Arena*) &sock->from_owner); */
    /*     arena_free((Arena*) &sock->for_owner); */
    /* } */
    /* else */
    {
        close(sock->fd);
    }

    sock = NULL;
}

int net_send(Socket* sock, void* buf, unsigned int size)
{
    /* assert(sock != NULL, "NULL socket not bound"); */
    if (sock == NULL)
    {
        return -1;
    }

    /* if (sock->is_local) */
    /* { */
    /*     Arena* dest; */
    /*     if (user_current == sock->owner_id) */
    /*     { */
    /*         dest = (Arena*) &sock->from_owner; */
    /*     } */
    /*     else */
    /*     { */
    /*         dest = (Arena*) &sock->for_owner; */
    /*     } */

    /*     // add to the ting */
    /*     arena_append(dest, buf, size); */
    /*     return size; */
    /* } */
    /* else */
    {
        // use the fds luke
        // printf("sent!\n");
        return send(sock->fd, buf, size, MSG_NOSIGNAL);
    }
}

int net_recv(Socket* sock, void* buf, unsigned int size)
{
    // assert(sock != NULL, "Current socket not bound");
    if (sock == NULL)
    {
        return -1;
    }

    /* if (sock->is_local) */
    /* { */
    /*     Buffer* dest; */
    /*     if (user_current == sock->owner_id) */
    /*     { */
    /*         dest = &sock->for_owner; */
    /*     } */
    /*     else */
    /*     { */
    /*         dest = &sock->from_owner; */
    /*     } */

    /*     int number_of_bytes_to_be_read = mini(dest->arena.allocated - dest->bytes_read, size); */
    /*     dest->bytes_read += number_of_bytes_to_be_read; */
    /*     memcpy(buf, dest->arena.data, number_of_bytes_to_be_read); */
    /*     return number_of_bytes_to_be_read; */
    /* } */
    /* else */
    {
        int res;
        // XXX: this blocks even when connection should close
        res = recv(sock->fd, buf, size, 0);
        // printf("+--------------------->res:%i\n", res);

        assert(((int*)buf)[0] != 0, "shitshittshit");

        return res;
    }
}

// a generic TCP api and an api for nodes to connect and stuff
// should i use UDP or TCP?
// UDP is obvs more appropriate but for demo TCP makes sense, plus https connections easiest with tcp
// 

/* int main() */
void net_test()
{
    /* net_init(); */

    /* Socket* s = net_listen(6969); */

    /* Socket* s2 = net_connect("0.1.1.2", 6969); */

    /* // hurray! */
    /* /1* assert(s->is_local, "otherwise none of this makes sense"); *1/ */
    /* assert(s == s2, "otherwise none of this makes sense"); */

    /* net_send(s2, "hello", 5); */

    /* /1* printf("owner %i\n", s->owner_id); *1/ */
    /* static char buf[8]; */
    /* net_recv(s, buf, 8); */
    /* printf("Received: %s\n", buf); */

    /* // connect to HTTP server */
    /* s = net_connect("lukesmith.xyz", 80); */
    /* /1* s = net_connect("205.185.115.79", 80); *1/ */
    /* net_send(s, "GET / HTTP/1.1\r\nHost: lukesmith.xyz\r\n\r\n", 45); */
    /* { */
    /*     static char buf[1024]; */
    /*     // it is blocking!! sad! */
    /*     net_recv(s, buf, 1023); */
    /*     printf("HTTP response is: %s\n", buf); */
    /* } */

    /* // send tls get requests? */

    /* // verifying system */
    /* //  - check tls cert */
    /* //  - check hashes */
    /* //  - make a whole heckin' blockchain */
    /* //    - handle transactions */
    /* //    - handle planning */
    /* //    - handle mining */
    /* //    - handle validating */
    /* //    - add tls checker */
    /* //  - verify the nodes? */
    /* //  - contest */
    /* //    - make the graphics to show what's going on in network */
    /* //  - docs */
    /* //    - explain how it all works... */
    /* //    - make a "whitepaper" lmao */
    
    /* net_uninit(); */
}
#endif
