#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <threads.h>

#ifdef __unix
#include <poll.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/time.h>
#endif

void _assert(int cond, const char* msg, const char* file, unsigned int line)
{
    if (!cond)
    {
        fprintf(stderr, "Assertion failed! File %s, Line: %i, Message: %s\n", file, line, msg);
        exit(-1);
    }
}

int mini(int a, int b)
{
    if (a < b)
        return a;
    else
        return b;
}

#define assert(cond, msg) _assert(cond, msg, __FILE__, __LINE__)

typedef unsigned char bool;

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
} Arena;

void arena_init(Arena* arena, unsigned int capacity)
{
    arena->capacity = capacity;
    arena->data = malloc(capacity);
}

void* arena_alloc(Arena* arena, unsigned int size)
{
    if (arena->allocated + size >= arena->capacity)
    {
        // grow until matching
        while (arena->allocated + size >= arena->capacity)
        {
            arena->capacity += arena->capacity / 2;
        }

        void* original = arena->data;
        arena->data = realloc(arena->data, arena->capacity);

        assert(arena->data != NULL, "Realloc failed, arena couldn't allocate");
    }

    void* res = arena->data + arena->allocated;
    arena->allocated += size;

    return res;
}

void arena_append(Arena* arena, void* buf, unsigned int size)
{
    void* addr = arena_alloc(arena, size);
    memcpy(addr, buf, size);
}

void arena_clear(Arena* arena)
{
    arena->allocated = 0;
}
    
void arena_free(Arena* arena)
{
    arena->capacity = 0;
    arena->allocated = 0;

    free(arena->data);
    arena->data = NULL;
}

#define LOCAL_SIM

typedef struct
{
    int fd;
#ifdef LOCAL_SIM
    bool is_local;
    Arena arena;
    unsigned int bytes_read;
    unsigned int owner_id;
#endif
} Socket;


Arena net_arena;
Socket* current = NULL;
#ifdef LOCAL_SIM
unsigned int user_count;
#endif

#ifdef LOCAL_SIM

int net_user_new()
{
    
}

void net_user_bind()
{
    
}
#endif

void net_init()
{
    arena_init(&net_arena, 1024);
}

void net_uninit()
{
    arena_free(&net_arena);
}

void net_bind(Socket* sock)
{
    current = sock;
}

Socket* net_connect(const char* ip_addr)
{
    Socket* socket = (Socket*) arena_alloc(&net_arena, sizeof(Socket));

    // internal ip addresses become local let's say
        
    
    return socket;
}

// what to do if someone connects to us?
Socket* net_listen()
{
    Socket* socket = (Socket*) arena_alloc(&net_arena, sizeof(Socket));


    return socket;
}

void net_send(void* buf, unsigned int size)
{
    assert(current != NULL, "Current socket not bound");

    if (current->is_local)
    {
        // add to the ting
        arena_append(&current->arena, buf, size);
    }
    else
    {
        // use the fds luke
        send(current->fd, buf, size, MSG_NOSIGNAL);
    }
}

int net_recv(void* buf, unsigned int size)
{
    assert(current != NULL, "Current socket not bound");

    if (current->is_local)
    {
        int number_of_bytes_to_be_read = mini(current->arena.allocated - current->bytes_read, size);
        current->bytes_read += number_of_bytes_to_be_read;
        memcpy(buf, current->arena.data, number_of_bytes_to_be_read);
        return number_of_bytes_to_be_read;
    }
    else
    {
        return recv(current->fd, buf, size, 0);
    }
}

// a generic TCP api and an api for nodes to connect and stuff
// should i use UDP or TCP?
// UDP is obvs more appropriate but for demo TCP makes sense, plus https connections easiest with tcp
// 

int main()
{
    net_init();

    printf("Hello world\n");
    
    net_uninit();
    return 0;
}
