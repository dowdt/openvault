#include <stdio.h>
#include <stdlib.h>

#include <string.h>
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
}

void* arena_alloc(Arena* arena, unsigned int size)
{
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

/* typedef struct Socket */
/* { */
/*     int fd; */
/* #ifdef LOCAL_SIM */
/*     bool is_local; */
/*     bool is_listening; */
/*     unsigned int owner_id; */
/*     Buffer from_owner; */
/*     Buffer for_owner; */

/*     struct Socket* prev; */
/*     struct Socket* next; */
/* #endif */
/* } Socket; */

typedef struct Socket
{
    int fd;
#ifdef LOCAL_SIM
    bool is_local;
    bool is_listening;
    unsigned short listening_port;
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

Socket* net_connect(const char* ip_addr, unsigned short port)
{
    Socket* sock;

    // internal ip addresses become local let's say
    if (ip_addr[0] == '0')
    {
        unsigned int user_who_owns_ip;

        user_who_owns_ip = net_user_from_ip((char*) ip_addr);

        sock = s_last_added;
        while (sock->owner_id != user_who_owns_ip && sock->is_listening)
        {
            sock = sock->prev;
            assert(sock != NULL, "someone tried connecting without there being a listener, this should work but ommitting for now");
        }

        sock->is_listening = 0;
    }
    else
    {
        sock = (Socket*) arena_alloc(&net_arena, sizeof(Socket));

        // actually get socket
        memset(sock, 0, sizeof(Socket));
        sock->fd = socket(AF_INET, SOCK_STREAM, 0);

        // TODO: make this non blocking with fnctl or something else

        sock->is_local = 0;

        /* struct addrinfo hints, *res; */
        /* memset(&hints, 0, sizeof(hints)); */
        /* hints.ai_family		= AF_INET; */
        /* hints.ai_socktype	= SOCK_STREAM; */

        struct hostent* he;
        struct in_addr** addr_list;
        he = gethostbyname((char*) ip_addr);

        assert(addr_list != NULL, "Invalid hostname!");
        ip_addr = he->h_addr_list[0];

        addr_list = (struct in_addr **) he->h_addr_list;

        struct sockaddr_in addr;
        addr.sin_addr.s_addr = inet_addr(inet_ntoa(*addr_list[0]));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        // LINUX
#ifdef __unix__
        struct timeval tv;
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
#else
        // WINDOWS
        DWORD timeout = timeout_in_seconds * 1000;
        setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout);
#endif

        /* char portbuf[6]; */
        /* sprintf(portbuf, "%i", port); */

        /* assert(getaddrinfo(ip_addr, "http", &hints, &res) != 0, "couldn't connect failed getaddrinfo"); */

        assert(connect(sock->fd, (struct sockaddr*) &addr, sizeof(addr)) == 0, "failed to connect");

        // should be connected now!
    }

    return sock;
}

// what to do if someone connects to us?
Socket* net_listen(unsigned short port)
{
    Socket sock = { 0 };

    // check if it's local?
    sock.owner_id = user_current;
    sock.fd = 0;
    sock.is_local = 1;
    sock.is_listening = 1;
    sock.listening_port = port;

    Socket* new_sock = (Socket*) arena_alloc(&net_arena, sizeof(Socket));
    memset(new_sock, 0, sizeof(Socket));
    *new_sock = sock;

    if (s_last_added != NULL)
        s_last_added->next = new_sock;

    new_sock->prev = s_last_added;
    s_last_added = new_sock;


    return new_sock;
}

void net_close()
{
    s_current = NULL;
}

unsigned int net_send(void* buf, unsigned int size)
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
        return size;
    }
    else
    {
        // use the fds luke
        printf("sent!\n");
        return send(s_current->fd, buf, size, MSG_NOSIGNAL);
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
        int res;
        res = recv(s_current->fd, buf, size, 0);

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
    net_init();

    int id = net_user_new("0.1.1.2");
    Socket* s = net_listen(6969);

    id = net_user_new("0.1.1.3");
    Socket* s2 = net_connect("0.1.1.2", 6969);

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
    printf("Received: %s\n", buf);

    // connect to HTTP server
    s = net_connect("lukesmith.xyz", 80);
    /* s = net_connect("205.185.115.79", 80); */
    net_bind(s);
    net_send("GET / HTTP/1.1\r\nHost: lukesmith.xyz\r\n\r\n", 45);
    {
        static char buf[1024];
        // it is blocking!! sad!
        net_recv(buf, 1023);
        printf("HTTP response is: %s\n", buf);
    }

    // send tls get requests?

    // verifying system
    //  - check tls cert
    //  - check hashes
    //  - make a whole heckin' blockchain
    //    - handle transactions
    //    - handle planning
    //    - handle mining
    //    - handle validating
    //    - add tls checker
    //  - verify the nodes?
    //  - contest
    //    - make the graphics to show what's going on in network
    //  - docs
    //    - explain how it all works...
    //    - make a "whitepaper" lmao
    
    net_uninit();
}
