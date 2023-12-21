#ifndef NET_SOURCE_FILE
#define NET_SOURCE_FILE

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <resolv.h>

#include <fcntl.h>
#include <sys/socket.h>

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

void ip_int_to_str(unsigned int ip, char *ret_str)
{
  byte *b = (byte *)&ip;
  sprintf(ret_str, "%i.%i.%i.%i", b[0], b[1], b[2], b[3]);
}


static atomic_ushort port_last = 29170;
unsigned short net_rand_port()
{
    assert(port_last < 29998, "theoretically outside of assigned range");
    return port_last++;
}

void net_set_blocking_fd(int fd, int should_block)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (should_block) 
        assert(fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == 0, "oh no");
    else
    {
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
        {
            printf("%s\n", strerror(errno));
            exit(-1);
        }
        /* assert(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0, "oh no"); */
    }
}

void net_set_blocking(Socket* sock, int should_block)
{
    if (sock == NULL)
    {
        return;
    }

    net_set_blocking_fd(sock->fd, should_block);
}

Socket* net_connect_ip_with_fd(int fd, unsigned int ip, char* ip_addr, unsigned short port)
{
    Socket* sock;
    char buf[12 + 4 + 1];
    int status;

    if (ip_addr == NULL)
    {
        memset(buf, 0, 17);

        ip_int_to_str(ip, buf);
        ip_addr = buf;
    }

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
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    }

    status = connect(fd, (struct sockaddr*) addr->ai_addr, addr->ai_addrlen);

    if (status != 0)
    {
        /* printf("??? %s\n", strerror(errno)); */
        close(fd);
        return NULL;
    }

    sock = (Socket*) arena_calloc(&net_arena, sizeof(Socket));
    sock->fd = fd;
    return sock;
}

Socket* net_connect(const char* ip_addr, unsigned short port, bool blocking)
{
    Socket* sock;
    int fd, status;

    // actually get socket
    fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd == -1)
    {
        printf("this happened: %s\n", strerror(errno));
        
        exit(-1);     
    }
    assert(fd != -1, "if this happened wth is going on");

    net_set_blocking_fd(fd, blocking);

    return net_connect_ip_with_fd(fd, 0, (char*) ip_addr, port);
}

int net_sock_fd(bool blocking)
{
    int fd;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    net_set_blocking_fd(fd, blocking);
    return  fd;
}

Socket* net_connect_ip(unsigned int ip, unsigned short port, bool blocking)
{
    char str[12 + 4 + 1];
    memset(str, 0, 17);

    ip_int_to_str(ip, str);
    /* printf("%s\n", str); */

    return net_connect(str, port, blocking);

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
    /* printf("%s\n", strerror(errno)); */
    // TODO: check if there's a better number
    assert(listen(fd, 0) == 0, "couldn't listen port is probably taken");
    
    /* printf("%s\n", strerror(errno)); */

    Socket* sock = (Socket*) arena_calloc(&net_arena, sizeof(Socket));
    sock->fd = fd;

    return sock;
}

Socket* net_accept(Socket* listener, struct sockaddr* ret_addr, socklen_t* ret_addr_len)
{
    int fd = accept(listener->fd, ret_addr, ret_addr_len);

    if (fd == -1)
    {
        /* printf("%s", strerror(errno)); */
        return NULL;
    }

    Socket* conn = (Socket*) arena_calloc(&net_arena, sizeof(Socket));
    conn->fd = fd;
    return conn;
}

void net_close(Socket* sock)
{
    close(sock->fd);
    sock = NULL;
}

int net_send(Socket* sock, void* buf, unsigned int size)
{
    /* assert(sock != NULL, "NULL socket not bound"); */
    if (sock == NULL)
    {
        return -1;
    }

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

    int res;
    // XXX: this blocks even when connection should close
    res = recv(sock->fd, buf, size, 0);
    // printf("+--------------------->res:%i\n", res);


    return res;
}

#endif
