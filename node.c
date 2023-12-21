#include "block.c"
#include "libhttp/http.h"
#include "tlse/tlse.h"
#include <bits/types/struct_timeval.h>
#include <dirent.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <threads.h>

#define WITH_TLS_13
/* #define DEBUG */
#include "libhttp/http.c"
#include "tlse/tlse.c"

#include "net.c"

typedef struct {
  unsigned int ip;
  unsigned short port;
} Peer;

// hecking load

bool load_root_certificates(struct TLSContext *context) {
#ifdef __unix__
  DIR *dir;
  struct dirent *file;

  dir = opendir("/etc/ssl/certs");
  if (dir == NULL) {
    printf("Failed to open /etc/ssl/certs, can't validate certs!\n");
    return 0;
  }

  while ((file = readdir(dir)) != NULL) {
    if (strcmp(file->d_name, ".") != 0 && strcmp(file->d_name, "..") != 0) {
      size_t len = strlen(file->d_name);
      if (len >= 4 && memcmp(file->d_name + len - 4, ".pem", 4) == 0) {
        static char full_path[1024] = "/etc/ssl/certs/";
        FILE *f;

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

bool send_pending(Socket *sock, struct TLSContext *context) {
  unsigned int out_buffer_len = 0;
  const unsigned char *out_buffer =
      tls_get_write_buffer(context, &out_buffer_len);
  unsigned int out_buffer_index = 0;
  int send_res = 0;
  while ((out_buffer) && (out_buffer_len > 0)) {
    int res =
        net_send(sock, (char *)&out_buffer[out_buffer_index], out_buffer_len);
    if (res <= 0) {
      send_res = res;
      break;
    }

    out_buffer_len -= res;
    out_buffer_index += res;
  }

  tls_buffer_clear(context);
  return send_res;
}

int verify_certificate(struct TLSContext *context,
                       struct TLSCertificate **certificate_chain, int len) {
  return no_error;
}

long simple_hash(long *val) {
  *val *= (2654435761);
  return *val;
}

#define DEFAULT_DNS_IP "127.0.0.1"
#define DEFAULT_DNS_PORT 1313

int dns_server(void *args)
{
  // all this will do is accept connections and forward tracked nodes
  Arena arena_peers;
  static Peer peers[16];
  int peer_current = 0;

  Socket *server;
  server = net_listen(DEFAULT_DNS_PORT);

  /* int flags = fcntl(server->fd, F_GETFL, 0); */
  /* fcntl(server->fd, F_SETFL, flags | O_NONBLOCK); */

  int connections = 0;
  struct sockaddr c_addr;
  socklen_t c_addr_len;

  for (;;)
  {
    /* printf("waiting to accept!\n"); */
    Socket *conn;
    while ((conn = net_accept(server, &c_addr, &c_addr_len)) == NULL);

    net_recv(conn, &peers[peer_current].port, sizeof(short));

    int index = (rand() ^ rand() ^ rand()) % 16;
    for (int i = 0; i < 16; i++) {
      net_send(conn, &peers[(index + rand() + i) % 16], sizeof(Peer));
    }

    net_close(conn);

    peers[peer_current].ip = (((struct sockaddr_in *)&c_addr)->sin_addr.s_addr);

    connections++;
    peer_current++;
    peer_current %= 16;
  }
}

typedef struct {
  Address address;
  // network connections
  int peers_connected;
  struct
  {
    Address a;
    Peer p;
  } *peers;
  Socket *listening;
  unsigned short port;

  int id;
} Node;

int node_init(void *arg) {

  return 0;
}


static BlockchainShared block;
#define N_NODES 3

static Node nodes[N_NODES];
static struct
{
    Address a;
    Peer p;
} peer_addresses[N_NODES];

void node_register_on_chain(Node* node)
{
    // should send message, instead stub to add to BlockchainShared
}

int node_update(void *in_addr)
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

  struct RequestPending req = {0};
  req.nonce = 1;
  strcpy(req.host, "en.wikipedia.org");
  strcpy(req.path, "/wiki/Richard");


  b.requests_pending_count = 1;
  b.requests_pending = &req;

  b.verifier_count = 6;

  for (int i = 0; i < 6; i++)
  {
    b.verifiers[i].address = (Address){i};
  }

  // lets cheat and have an address -> peer table

  // 3. send message to peer and start to listen for other peer to connect
  // 4.

  // if it's local or smth

  // peers

  Node* node = in_addr;
  node->listening = net_listen(node->port);

  // 1 -> 2 -> 3 -> server
  // V    V    V
  // 4    5    6

  int n[3] = { 1, 2, 3 };
  int order = 0; // first

  for (int i = 0; i < 3; i++)
  {
      if (node->id == i)
      {
        order = i;
        break;
      }
  }

  // if order 1 or 2, connect to next, listen to previous
  Socket* next = NULL;
  Socket* prev = NULL;

  if (order == 1 || order == 2)
  {
    Peer prev_peer = node->peers[order - 1].p;

    // wait for previous peer to connect
    struct sockaddr addr;
    socklen_t addr_len;

    // connect to peer and make sure that they come from right address
    assert(node->listening != NULL);

    net_set_blocking(node->listening, 1);

    printf("Node %i, starting accept loop\n", node->id);
    for (;;)
    {
      prev = net_accept(node->listening, &addr, &addr_len);
      if (prev != NULL)
      {
        struct sockaddr_in* addr_ip4 = (struct sockaddr_in*) &addr;
        
        if (addr_ip4->sin_port == prev_peer.port &&
            addr_ip4->sin_addr.s_addr == prev_peer.ip)
        {
          printf("this failed\n");
          break;
        }
        else
        {
          net_close(prev);
        }

        break;
      }
    }
    printf("Node %i, connected to prev\n", node->id);
  }

  if (order == 0 || order == 1)
  {
    Peer next_peer = node->peers[order + 1].p;

    printf("Node %i, attempting connect ip %i, port %hu\n", node->id, next_peer.ip, next_peer.port);
    for (;;)
    {
      next = net_connect_ip(next_peer.ip, next_peer.port, 1);
      if (next != NULL)
      {
        printf("Node %i, connected to next\n", node->id);
        break;
      }
    }
  }

  if (order == 2)
  {
    // connect to endpoint
    printf("Now ready to get to endpoint\n");

    // make a tls request, record all keys and encryption data
  }

  // started connection
  {
    // if snooper

    // if witness
  }
}

int main()
{
  /* thrd_t dns_server_thread; */
  /* thrd_create(&dns_server_thread, dns_server, NULL); */

  /* sleep(1); */
#if 0

  thrd_t n_threads[N_NODES];

  for (int i = 0; i < N_NODES; i++)
  {
    nodes[i].address.a = i;
    nodes[i].id = i;
    nodes[i].port = net_rand_port();
    node_init(&nodes[i]);
  }

  // simulating acquiring neighbours
  void* peers_buffer = calloc(N_NODES, (sizeof(Address) + sizeof(Peer)) * (N_NODES - 1));

  for (int i = 0; i < N_NODES; i++)
  {
    nodes[i].peers_connected = N_NODES - 1;
    nodes[i].peers = peers_buffer + ((sizeof(Address) + sizeof(Peer)) * (N_NODES - 1));

    for (int j = 0; j < N_NODES; j++)
    {
      // add the nodes
      if (j != i)
      {
        nodes[i].peers[j].a = nodes[j].address;
        memcpy(&nodes[i].peers[j].a, &nodes[j].address, sizeof(Address));
        nodes[i].peers[j].p.port = (nodes[j].port);
        nodes[i].peers[j].p.ip = (127 << 0) + (0 << 8) + (0 << 16) + (1 << 24);
      }
    }
  }

  for (int i = 0; i < N_NODES; i++)
  {
    printf("Launching Node: %i\n", i);
    thrd_create(&n_threads[i], node_update, &nodes[i]);
  }

  for (int i = 0; i < N_NODES; i++)
    thrd_join(n_threads[i], NULL);

  /* thrd_join(dns_server_thread, NULL); */

  free(peers_buffer);

  return 1;
#else

  // TLS request coming up
  tls_init();

  struct TLSContext *context;

  context = tls_create_context(0, TLS_V13);

  // tls setup
  { 
    tls_make_exportable(context, 1); 
  }

  // send through whatever is left

  // connect + handshake

  // out going
  Socket *sock;

  if (load_root_certificates(context))
  {
  }

  printf("loaded certificates\n");

/* #define HOST "lukesmith.xyz" */
/* #define HOST "cedars.xyz" */
#define HOST "www.wikipedia.org"
/* #define HOST "www.google.com" */
/* #define HOST "archlinux.org" */
/* #define HOST "suckless.org" */
/* #define HOST "odin-lang.org" */
/* #define HOST "www.slowernews.com" */
  /* #define HOST "en.wikipedia.org" */

  // TODO: there is a random segfault here occasionally, could be bind or
  // connect
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
      tls_consume_stream(context, buf, read_bytes,
                         sent_request ? tls_default_verify : NULL);

      if (tls_established(context))
      {
        // if sent probs?
        if (!sent_request)
        {
          unsigned char request[] = "GET / HTTP/1.1\r\nHost: " HOST "\r\n\r\n";

          tls_write(context, request, strlen((char *)request));
          send_pending(sock, context);
          sent_request = 1;
        }
        else 
        {
          // NOTE: DATA_SIZE has to be smaller than http buffer, so that it fits
          // entirely within one call to http_read_from_buf
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
              printf("%.*s\n", msg.length, msg.content);
              /* printf("Got message length: %i\n", msg.length); */
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
#endif
}
