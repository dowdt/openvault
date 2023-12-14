#include <stdio.h>
#include <stdlib.h>

#include <string.h>



#ifdef __unix

#include <poll.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <threads.h>

// windows
#else

#endif

void _assert(int cond, const char* msg, const char* file, unsigned int line)
{
    if (cond == 0)
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

typedef struct
{
    Arena arena;
    unsigned int bytes_read;
} Buffer;

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
            arena->capacity += arena->capacity / 2 + 1;
        }

        void* original = arena->data;
        arena->data = realloc(arena->data, arena->capacity);

        assert(arena->data != NULL, "Realloc failed, arena couldn't allocate");
    }

    void* res = arena->data + arena->allocated;
    arena->allocated += size;

    return res;
}

void arena_append(Arena* arena, void* buf, unsigned int size) {
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

typedef struct Socket
{
    int fd;
#ifdef LOCAL_SIM
    bool is_local;
    bool is_listening;
    unsigned int owner_id;
    Buffer from_owner;
    Buffer for_owner;

    struct Socket* prev;
    struct Socket* next;
#endif
} Socket;


Arena net_arena;
Socket* s_current = NULL;
Socket* s_last_added = NULL;
#ifdef LOCAL_SIM
unsigned int user_current = 0;
unsigned int user_count = 0;
typedef struct
{
    char* ip_addr;
} User;

User users[1024];
#endif

#ifdef LOCAL_SIM


int net_user_new(char* ip_addr)
{
    assert(user_count < 1024, "Exceeded maximum number of users");
    users[user_count].ip_addr = ip_addr;
    user_current = user_count;
    user_count++;
    return user_count - 1;
}

void net_user_bind(unsigned int i)
{
    user_current = i;
}

int net_user_from_ip(char* ip_addr)
{
    // find user from ip and get socket
    for (int i = 0; i < user_count; i++)
    {
        if (strncmp(users[i].ip_addr, ip_addr, strlen(ip_addr)) == 0)
        {
            // found match!
            return i;
        }
    }

    assert(0, "this should never be reached");

    return -1;
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
    s_current = sock;
}

Socket* net_connect(const char* ip_addr)
{
    Socket* socket;

    // internal ip addresses become local let's say
    if (ip_addr[0] == '0')
    {
        unsigned int user_who_owns_ip;

        socket = s_last_added;
        while (socket->owner_id != user_who_owns_ip && socket->is_listening)
        {
            socket = socket->prev;
            assert(socket != NULL, "someone tried connecting without there being a listener, this should work but ommitting for now");
        }

        socket->is_listening = 0;

    }
    else
    {
        socket = (Socket*) arena_alloc(&net_arena, sizeof(Socket));

        // actually get socket

        // skip for now

    }

    return socket;
}

// what to do if someone connects to us?
Socket* net_listen()
{
    Socket* socket = (Socket*) arena_alloc(&net_arena, sizeof(Socket));

    // check if it's local?
    socket->owner_id = user_current;
    socket->fd = 0;
    socket->is_local = 1;
    socket->is_listening = 1;

    if (s_last_added != NULL)
        s_last_added->next = socket;
    socket->prev = s_last_added;
    s_last_added = socket;

    return socket;
}

void net_close()
{
    s_current = NULL;
}

void net_send(void* buf, unsigned int size)
{
    assert(s_current != NULL, "Current socket not bound");

    if (s_current->is_local)
    {
        Arena* dest;
        if (user_current == s_current->owner_id)
        {
            dest = (Arena*) &s_current->from_owner;
        }
        else
        {
            dest = (Arena*) &s_current->for_owner;
        }

        // add to the ting
        arena_append(dest, buf, size);
    }
    else
    {
        // use the fds luke
        send(s_current->fd, buf, size, MSG_NOSIGNAL);
    }
}

int net_recv(void* buf, unsigned int size)
{
    assert(s_current != NULL, "Current socket not bound");

    if (s_current->is_local)
    {
        Buffer* dest;
        if (user_current == s_current->owner_id)
        {
            dest = &s_current->for_owner;
        }
        else
        {
            dest = &s_current->from_owner;
        }

        int number_of_bytes_to_be_read = mini(dest->arena.allocated - dest->bytes_read, size);
        dest->bytes_read += number_of_bytes_to_be_read;
        memcpy(buf, dest->arena.data, number_of_bytes_to_be_read);
        return number_of_bytes_to_be_read;
    }
    else
    {
        return recv(s_current->fd, buf, size, 0);
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
    int id = net_user_new("0.1.1.2");
    Socket* s = net_listen();

    id = net_user_new("0.1.1.3");
    Socket* s2 = net_connect("0.1.1.2");

    // hurray!
    assert(s->is_local, "otherwise none of this makes sense");
    assert(s == s2, "otherwise none of this makes sense");

    net_bind(s2);
    net_user_bind(1);
    net_send("hello", 5);

    net_bind(s);
    net_user_bind(0);
    printf("owner %i\n", s->owner_id);
    static char buf[8];
    net_recv(buf, 8);
    printf("%s\n", buf);
    
    net_uninit();
    return 0;
}
