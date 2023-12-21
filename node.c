#include "libhttp/http.h"
#include "block.c"
#include "tlse/tlse.h"
#include <dirent.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <threads.h>


#define WITH_TLS_13
/* #define DEBUG */
#include "tlse/tlse.c"
#include "libhttp/http.c"

#include "net.c"

// for now just handling the verification

// SPOILERS!!
//  - Blockchain node behaviour
//  - what should a node do?
//  - is a verifier and a miner the same thing?
//  - probably not right?
//  - but it could be in the same exe or changed at compile time
//  - they both have to verify all the blockchain, keep track of state, connect to peers. it makes sense to combine all that here
//  - need deterministic method to derive verifiers from rest


// first things first, do the verification
//  - wire-tapping MitM
//  - connect and get data from server
//  - verify the data WITH SCIENCE! separately
typedef struct
{
    Socket towardsClient;
    Socket towardsServer;

    unsigned short block_count;
    HashedBlock blocks[MAX_BLOCKS_PER_REQUEST];
    Address address; // you know to sign and stuff
} SnooperNode;

typedef struct
{
    unsigned int ip;
    unsigned short port;
} Peer;

// hecking load

bool load_root_certificates(struct TLSContext* context)
{
#ifdef __unix__
    DIR *dir;
    struct dirent* file;

    dir = opendir("/etc/ssl/certs");
    if (dir == NULL)
    {
        printf("Failed to open /etc/ssl/certs, can't validate certs!\n");
        return 0;
    }

    while ((file = readdir(dir)) != NULL)
    {
        if (strcmp(file->d_name, ".")  != 0 && 
            strcmp(file->d_name, "..") != 0)
        {
            size_t len = strlen(file->d_name);
            if (len >= 4 && 
                memcmp(file->d_name + len - 4, ".pem", 4) == 0)
            {
                static char full_path[1024] = "/etc/ssl/certs/";
                FILE* f;

                printf("Found PEM file: %s\n", file->d_name);

                // open file and load into context
                memset(full_path + 15, 0, 1024 - 15);
                memcpy(full_path + 15, file->d_name, strlen(file->d_name));

                // use file
                f = fopen(full_path, "r");

                static unsigned char buf[8096];
                unsigned int read_bytes = fread(buf, 1, 8096, f);

                tls_load_root_certificates(context, buf, read_bytes);
            }
        }
    }

    closedir(dir);
    return 1;
#endif
}


bool send_pending(Socket* sock, struct TLSContext* context)
{
    unsigned int out_buffer_len = 0;
    const unsigned char *out_buffer = tls_get_write_buffer(context, &out_buffer_len);
    unsigned int out_buffer_index = 0;
    int send_res = 0;
    while ((out_buffer) && (out_buffer_len > 0))
    {
        int res = net_send(sock, (char *)&out_buffer[out_buffer_index], out_buffer_len);
        if (res <= 0)
        {
            send_res = res;
            break;
        }

        out_buffer_len -= res;
        out_buffer_index += res;
    }

    tls_buffer_clear(context);
    return send_res;
}

int verify_certificate(struct TLSContext *context, struct TLSCertificate **certificate_chain, int len)
{
    return no_error;
}


long simple_hash(long* val)
{
    *val *= (2654435761);
    return *val;
}


#define DEFAULT_DNS_IP "127.0.0.1"
#define DEFAULT_DNS_PORT 1313

void ip_int_to_str(unsigned int ip, char* ret_str)
{
    byte* b = (byte*)&ip;
    sprintf(ret_str, "%i.%i.%i.%i", b[0], b[1], b[2], b[3]);
}

int dns_server(void* args)
{
    // all this will do is accept connections and forward tracked nodes
    Arena arena_peers;
    static Peer peers[16];
    int peer_current = 0;

    Socket* server;
    server = net_listen(DEFAULT_DNS_PORT);

    /* int flags = fcntl(server->fd, F_GETFL, 0); */
    /* fcntl(server->fd, F_SETFL, flags | O_NONBLOCK); */

    int connections = 0;
    struct sockaddr c_addr;
    socklen_t c_addr_len;

    for(;;)
    {
        /* printf("waiting to accept!\n"); */
        Socket* conn;
        while ((conn = net_accept(server, &c_addr, &c_addr_len)) == NULL);
        /* printf("accepted!\n"); */


        net_recv(conn, &peers[peer_current].port, sizeof(short));

        int index = (rand() ^ rand() ^ rand()) % 16;
        for (int i = 0; i < 16; i++)
        {
            net_send(conn, &peers[(index + rand() + i) % 16], sizeof(Peer));
        }
        /* printf("sent 16 peers\n"); */

        net_close(conn);


        /* for (int i = 0; i < 16; i++) */
        /* { */
        /*     static char ip_str[12 + 4 + 1]; */
        /*     memset(ip_str, 0, 17); */

        /*     ip_int_to_str(peers[i].ip, ip_str); */
        /*     printf("%i: port %hu ip %s\n", i, peers[i].port, ip_str); */
        /* } */

        peers[peer_current].ip = (((struct sockaddr_in*) &c_addr)->sin_addr.s_addr);

        connections ++;
        peer_current ++;
        peer_current %= 16;
    }
}

typedef struct
{
    Address address;
    // network connections
    int peers_connected;
    Socket* peers[5];
    Socket* listening;
} Node;

int node_init(void* arg)
{
    Node* n = arg;

    // connect to peers
    // send it a listening socket on our end
    unsigned short port = net_rand_port();
    n->listening = net_listen(port);

    fd_set leftb;

    FD_ZERO(&leftb);

    Socket* dns_sock = net_connect(DEFAULT_DNS_IP, DEFAULT_DNS_PORT, 1);

    net_send(dns_sock, &port, sizeof(short));

    Peer candidate_peers[16];
    net_recv(dns_sock, &candidate_peers, sizeof(Peer) * 16);
    net_close(dns_sock);

    while (n->peers_connected < 5)
    {

        /* printf("%i is looping\n", n->address.a); */
        FD_SET(n->listening->fd, &leftb);

        struct timeval t;
        t.tv_sec = 0;
        t.tv_usec = 10000;

        int status = select(FD_SETSIZE, &leftb, NULL, NULL, &t);
        if (status < 0)
        {
            printf("error!!!\n");
            exit(-1);
        }

        if (FD_ISSET(n->listening->fd, &leftb))
        {
            printf("%i: someone tried connecting\n", n->address.a);

            // try accepting a connection
            Socket* conn = net_accept(n->listening, NULL, NULL);
            if (conn != NULL)
            {
                n->peers[n->peers_connected] = conn;
                n->peers_connected += 1;
                printf("%i: Found %i peers!\n", n->address.a, n->peers_connected);
            }
        }

        // try to connect to one of the 12 peers
        /* net_set_blocking(); */
        for (int i = 0; i < 16; i++)
        {
            char ip_str[17];
            Socket* conn;
            memset(ip_str, 0, 17);

            ip_int_to_str(candidate_peers[i].ip, ip_str);

            if (port != candidate_peers[i].port)
            {
                // how do I check if they're already connected???
                conn = net_connect(ip_str, candidate_peers[i].port, 0);
            }

            if (conn != NULL)
            {
                n->peers[n->peers_connected] = conn;
                n->peers_connected += 1;
                printf("%i: Found %i peers!\n", n->address.a, n->peers_connected);
            }
        }
    }

    return 0;
}

void node_update(Node* node)
{
    // 1. if new block undo all work
    // 1.5 announce i've seen last block
    // 2. compute each bounty's procedure

    BlockchainShared b;
#if 0
    // determine peer
    {
        // check if i'm included in last block
        int block_id = -1;
        for (int i = 0; i < b.verifier_count; i++)
        {
            if (address_equals(b.verifiers[i].address, node->address))
            {
                // then we might be involved in this block
                block_id = i;
            }
        }

        if (block_id == -1)
        {
            // TODO: we are not involved, announce or smth
        }
        else
        {

            if (b.verifier_count < 6)
            {
                // not possible to verify the request
            }
            else
            {
                long seed = 0;
                for (int i = 0; i < b.requests_pending_count; i++)
                {
                    int n[6];
                    int s1, s2, s3;
                    int w1, w2, w3;
                    // quickly check if I am involved
                    seed ^= i;
                    seed ^= b.requests_pending[i].nonce;
                    seed ^= b.nonce;
                    n[0] = simple_hash(&seed) % b.verifier_count;
                    n[1] = simple_hash(&seed) % b.verifier_count;
                    n[2] = simple_hash(&seed) % b.verifier_count;
                    n[3] = simple_hash(&seed) % b.verifier_count;
                    n[4] = simple_hash(&seed) % b.verifier_count;
                    n[5] = simple_hash(&seed) % b.verifier_count;

                    // make sure that none are duplicated
                    bool done = 0;
                    while(!done)
                    {
                        done = 1;

                        for (int j = 0; j < 6; j++)
                        {
                            for (int k = 0; k < 6; k++)
                            {
                                // also check if it's already being used
                                if (n[j] == n[k] && k != j)
                                {
                                    n[k] += 1;
                                    n[k] %= b.verifier_count;
                                    done = 0;
                                }
                            }
                        }
                    }

                    // if this is all true then we're good, unless one of the verifier ids is already used
                    /* if () */
                    {

                    }
                }
            }
        }
    }
#endif

    struct RequestPending req = { 0 };
    req.nonce = 1;
    strcpy(req.host, "en.wikipedia.org");
    strcpy(req.path, "/wiki/Richard");

    b.requests_pending_count = 1;
    b.requests_pending = &req;

    b.verifier_count = 6;

    for (int i = 0; i < 6; i++)
    {
        b.verifiers[i].address = (Address){ i };
    }

    // 3. send message to peer and start to listen for other peer to connect
    // 4. 

    // if it's local or smth

    // this assumes we're already connected and stuff
    net_listen(6969);

    // must connect to port + ip combo
    /* net_connect(); */

    // started connection
    {
        // if snooper


        // if witness
    }
}


int main()
{

    thrd_t dns_server_thread;
    thrd_create(&dns_server_thread, dns_server, NULL);

    sleep(1);

#define N_NODES 16
    thrd_t n_threads[N_NODES];
    Node* nodes = calloc(N_NODES, sizeof(Node));

    for (int i = 0; i < N_NODES; i++)
    {
        printf("Launching Node: %i\n", i);
        nodes[i].address.a = i;
        thrd_create(&n_threads[i], node_init, &nodes[i]);
    }

    for (int i = 0; i < N_NODES; i++)
        thrd_join(n_threads[i], NULL);

    thrd_join(dns_server_thread, NULL);

    return 1;

    // TLS request coming up
    tls_init();

    
    struct TLSContext* context;

    context = tls_create_context(0, TLS_V13);

    // tls setup
    {
        tls_make_exportable(context, 1);
    }

    // send through whatever is left

    // connect + handshake

    // out going
    Socket* sock;

    if (load_root_certificates(context))
    {
    }

    printf("loaded certificates\n");

/* #define HOST "lukesmith.xyz" */
/* #define HOST "cedars.xyz" */
/* #define HOST "www.wikipedia.org" */
/* #define HOST "www.google.com" */
/* #define HOST "archlinux.org" */
/* #define HOST "suckless.org" */
/* #define HOST "odin-lang.org" */
#define HOST "www.slowernews.com"
/* #define HOST "en.wikipedia.org" */

    // TODO: there is a random segfault here occasionally, could be bind or connect
    sock = net_connect(HOST, 443, 1);

    // let's add a middle man

    tls_client_connect(context);
    send_pending(sock, context);

    // send get req and receive stuff
    {
        int read_bytes;
        byte buf[4096];
        int sent_request = 0;

        static struct http_message msg;
        while ((read_bytes = net_recv(sock, buf, 4096)) > 0)
        {
            tls_consume_stream(context, buf, read_bytes, sent_request ? tls_default_verify : NULL);

            if (tls_established(context))
            {
                // if sent probs?
                if (!sent_request)
                {
                    unsigned char request[] = "GET / HTTP/1.1\r\nHost: " HOST "\r\n\r\n";

                    tls_write(context, request, strlen((char*)request));
                    send_pending(sock, context);
                    sent_request = 1;
                }
                else
                {
                    // NOTE: DATA_SIZE has to be smaller than http buffer, so that it fits entirely within one call to http_read_from_buf
#define DATA_SIZE 512
                    unsigned char data[DATA_SIZE];

                    memset(data, 0, DATA_SIZE);

                    int ret;
                    while ((ret = tls_read(context, data, DATA_SIZE)) > 0)
                    {
                        // what happens if http reads but has nothing to write?
                        // TODO: maybe I should use the return value from this function?
                        http_read_from_buf(data, ret, &msg);


                        if (msg.length > 0)
                        {
                            /* printf("%.*s\n", msg.length, msg.content); */
                            /* printf("Got message length: %i\n", msg.length); */

                            // here is where I fill up a buffer to use later
                            // but anyways this is just the full parse, only some nodes will do this
                        }

                        if (msg.header.length == msg.state.total && msg.state.left == 0)
                        {
                            net_close(sock);
                        }
                    }
                }
            }
        }
    }

    return 0;
}
