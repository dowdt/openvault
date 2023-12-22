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
#include <tomcrypt.h>

/* #define HOST "localhost" */
/* #define PATH "/" */
/* #define PORT 9696 */

/* #define HOST "cedars.xyz" */
/* #define PATH "/" */
/* #define PORT 443 */

#define HOST "cedars.xyz"
#define PATH "/"
#define PORT 443

/* #define HOST "www.computerenhance.com" */
/* #define PATH "/p/a-few-quick-notes" */
/* #define PORT 443 */

/* #define HOST "api.seeip.org" */
/* #define PATH "/" */
/* #define PORT 443 */

#define WITH_TLS_13
/* #define DEBUG */
#include "libhttp/http.c"
#include "tlse/tlse.c"

#include "net.c"

#define N_NODES 5

typedef struct
{
  unsigned int ip;
  unsigned short port;
} Peer;

// hecking load

bool load_root_certificates(struct TLSContext *context)
{
#ifdef __unix__
  DIR *dir;
  struct dirent *file;

  dir = opendir("/etc/ssl/certs");
  if (dir == NULL)
  {
    printf("Failed to open /etc/ssl/certs, can't validate certs!\n");
    return 0;
  }

  while ((file = readdir(dir)) != NULL) {
    if (strcmp(file->d_name, ".") != 0 && strcmp(file->d_name, "..") != 0)
    {
      size_t len = strlen(file->d_name);
      if (len >= 4 && memcmp(file->d_name + len - 4, ".pem", 4) == 0)
      {
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


int verify_certificate(struct TLSContext *context,
                       struct TLSCertificate **certificate_chain, int len)
{
  return no_error;
}

long simple_hash(long *val) {
  *val *= (2654435761);
  return *val;
}

#define DEFAULT_DNS_IP "127.0.0.1"
#define DEFAULT_DNS_PORT 1313

int dns_server(void *args) {
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

  for (;;) {
    /* printf("waiting to accept!\n"); */
    Socket *conn;
    while ((conn = net_accept(server, &c_addr, &c_addr_len)) == NULL)
      ;

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
  struct {
    Address a;
    Peer p;
  } *peers;
  Socket *listening;
  unsigned short port;

  int id;
  FILE *fout;
  rsa_key key;
} Node;

int node_init(void *arg) { return 0; }

static BlockchainShared block;

static Node nodes[N_NODES];
static struct {
  Address a;
  Peer p;
} peer_addresses[N_NODES];

void node_register_on_chain(Node *node) {
  // should send message, instead stub to add to BlockchainShared
}

void https_request(Node* node, Socket *sock, char *host, char *path);

bool tls_send_pending(Socket *sock, struct TLSContext *context)
{
  unsigned int out_buffer_len = 0;
  const unsigned char *out_buffer =
      tls_get_write_buffer(context, &out_buffer_len);
  unsigned int out_buffer_index = 0;

  int send_res = 0;
  while ((out_buffer) && (out_buffer_len > 0))
  {
    printf("Will send %i bytes to fd %i\n", out_buffer_len, sock->fd);
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

int node_update(void *in_addr)
{
  BlockchainShared b;
#if 0
  // Determining peer
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
  strcpy(req.host, HOST);
  strcpy(req.path, PATH);

  b.requests_pending_count = 1;
  b.requests_pending = &req;

  b.verifier_count = 6;

  for (int i = 0; i < 6; i++) {
    b.verifiers[i].address = (Address){i};
  }

  // 3. send message to peer and start to listen for other peer to connect
  // 4.

  Node *node = in_addr;
  node->listening = net_listen(node->port);

  // 1 -> 2 -> 3 -> server
  // V    V    V
  // 4    5    6

  int n[3] = {1, 2, 3};
  int order = 0; // first

  for (int i = 0; i < N_NODES; i++) {
    if (node->id == i) {
      order = i;
      break;
    }
  }

  // if order 1 or 2, connect to next, listen to previous
  Socket *next = NULL;
  Socket *prev = NULL;

  if (order > 0) {
    Peer prev_peer = node->peers[node->id - 1].p;

    // wait for previous peer to connect
    struct sockaddr addr;
    socklen_t addr_len;

    // connect to peer and make sure that they come from right address
    assert(node->listening != NULL, "node is null");

    printf("Node %i at port %hu, starting accept loop want %hu\n", node->id,
           node->port, prev_peer.port);
    net_set_blocking(node->listening, 0);
    for (;;) {
      prev = net_accept(node->listening, &addr, &addr_len);

      if (prev != NULL) {
        /* struct sockaddr_in *addr_ip4 = (struct sockaddr_in *)&addr; */
        /* if (addr_ip4->sin_port == prev_peer.port && */
        /*     addr_ip4->sin_addr.s_addr == prev_peer.ip) { */
        /*   printf("this failed\n"); */
        /*   break; */
        /* } else { */
        /*   net_close(prev); */
        /* } */
        printf("Node: %i, accepted a connection\n", node->id);

        break;
      }
    }
    printf("Node %i, connected to prev %i\n", node->id, prev->fd);
  }

  if (order < N_NODES - 1) {
    Peer next_peer = node->peers[node->id + 1].p;

    printf("Node %i, attempting connect ip %i, port %hu\n", node->id,
           next_peer.ip, next_peer.port);
    for (;;) {
      next = net_connect_ip(next_peer.ip, next_peer.port, 0);
      if (next != NULL) {
        printf("Node %i, connected to next fd: %i\n", node->id, next->fd);
        break;
      }
    }
  }

  // we got to this point everything from now on will be great
  Arena session_arena;
  arena_init(&session_arena, 4096);
  byte *buffer = arena_alloc(&session_arena, 4096);
  int buffer_taken = 0;
  int buffer_allocated = 4096;

  printf("everybody said hello\n");

  if (order == 0) {
    // connect to endpoint
    printf("Now ready to get to endpoint fd %i\n", next->fd);

    char msg[] = "hello you ok";
    printf("sending message\n");

    // will do this basically
    https_request(node, next, req.host, req.path);
  }

  else {
    // listen to requests from previous and forward to server

    if (order == N_NODES - 1) {
      printf("connected to endpoint\n");
      next = net_connect(req.host, PORT, 1);
    }

    int read_bytes;

    static byte buf[2048];

    // unitil connection is up
    int is_reading_previous = 0;

    if (order > 0) {
      is_reading_previous = 1;
    }

    fd_set read_set;
    fd_set write_set;
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    for (;;) {
      FD_ZERO(&read_set);
      FD_SET(next->fd, &read_set);
      FD_SET(prev->fd, &read_set);
      /* printf("next fd %i\n", next->fd); */
      /* printf("prev fd %i\n", prev->fd); */
      /* FD_SET(next->fd, &write_set); */
      /* FD_SET(prev->fd, &write_set); */

      /* printf("got something %i\n", i); */
      int status = select(FD_SETSIZE, &read_set, NULL, NULL, &timeout);

      for (int i = 0; i < FD_SETSIZE; i++) {
        if (FD_ISSET(i, &read_set)) {
          printf("found one %i\n", status);
          Socket *s = NULL;
          Socket *r = NULL;

          if (i == next->fd) {
            // reading from next sending to prev
            r = next;
            s = prev;
          } else {
            r = prev;
            s = next;
          }

          read_bytes = net_recv(r, buf, 1024);
          net_send(s, buf, read_bytes);


          if (r == prev)
          {
            printf("-> Node %i (%i bytes) ->\n", node->id, read_bytes);
            fprintf(node->fout, "Sent (%i bytes):\n", read_bytes);

          }
          else
          {
            printf("<- Node %i (%i bytes) <-\n", node->id, read_bytes);
            fprintf(node->fout, "Received (%i bytes):\n", read_bytes);
          }
          hash_state md;
          sha512_init(&md);
          sha512_process(&md, buf, read_bytes);

          byte out[64];
          sha512_done(&md, out);

          fprintf(node->fout, "\tHash:\n\t");
          for (int i = 0; i < 64; i++)
          {
            fprintf(node->fout, "%X", out[i]);
          }

          fprintf(node->fout, "\n");

          byte out_sign[1024];
          unsigned long out_sign_len = 1024;
          rsa_sign_hash(out, 64, out_sign, &out_sign_len, NULL, find_prng("sprng"), find_hash("sha512"), 8, &node->key);

          fprintf(node->fout, "\tSignature:\n\t");
          for (int i = 0; i < out_sign_len; i++)
          {
            fprintf(node->fout, "%X", out_sign[i]);
          }
          fprintf(node->fout, "\n");
        }
      }
    }

    if (read_bytes > 0) {
      buffer_taken += read_bytes;
    } else {
      // fail
    }
  }

  // print data to terminal

  arena_free(&session_arena);

  return 0;
}

void https_request(Node* node, Socket *sock, char *host, char *path)
{
  struct TLSContext *context;
  int read_bytes;
  byte buf[4096];
  int sent_request = 0;
  Arena l_arena;
  printf("server here: %i\n", sock->fd);

  // tls setup
  tls_init();
  context = tls_create_context(0, TLS_V13);
  tls_make_exportable(context, 1);
  // load_root_certificates(context);

  arena_init(&l_arena, 1024);

  printf("connecting to: %s.\n", host);

  if (sock == NULL) {
    printf("NULL SOket\n");
    sock = net_connect(host, PORT, 1);
  }

  printf("sending connect\n");
  tls_client_connect(context);
  printf("server fd: %i\n", sock->fd);
  tls_send_pending(sock, context);
  printf("sent connect\n");

  printf("server fd: %i\n", sock->fd);

  // to do the record and parse again I need to catalogue every read and every
  // write, so I might as well just implement the darn thing normally

  static struct http_message msg;
  printf("reading bytes\n");
  while ((read_bytes = net_recv(sock, buf, 4096)) > 0) {
    printf("got data, fd: %i\n", sock->fd);

    printf("consuming stream\n");
    tls_consume_stream(context, buf, read_bytes, NULL);
    printf("consumed stream\n");
    if (!sent_request) {
      printf("sednign pending %i\n", sock->fd);
      tls_send_pending(sock, context);
      printf("sent pending\n");
    }

    if (tls_established(context)) {
      printf("handshake done\n");
      /* int size = tls_export_context(context, context_buf, 4096, 0); */
      /* printf("context size %i\n", size); */

      if (!sent_request) {
        char *request = arena_calloc(&l_arena, 4 + strlen(host) + 21 +
                                                   strlen(path) + 4 + 1);
        {
          printf("host is: %s\n", host);
          int off = 0;

          char *s1 = "GET ";
          memcpy(request + off, s1, strlen(s1));
          off += strlen(s1);

          strcpy(request + off, path);
          off += strlen(path);

          char *s2 = " HTTP/1.1\r\nHost: ";
          strcpy(request + off, s2);
          off += strlen(s2);
          strcpy(request + off, host);
          off += strlen(host);
          strcpy(request + off, " \r\n\r\n");
          printf("request: %s\n", request);
        }

        // TODO: parse request

        tls_write(context, (unsigned char *)request, strlen((char *)request));
        tls_send_pending(sock, context);
        sent_request = 1;
        printf("sent request\n");
      }
      else
      {
        // NOTE: DATA_SIZE has to be smaller than http buffer, so that it fits
        // entirely within one call to http_read_from_buf
#define DATA_SIZE 512
        unsigned char data[DATA_SIZE];

        memset(data, 0, DATA_SIZE);
        printf("checking\n");

        int ret;
        while ((ret = tls_read(context, data, DATA_SIZE)) > 0)
        {
          // what happens if http reads but has nothing to write?
          // TODO: maybe I should use the return value from this function?
          printf("got decrypted message\n");
          http_read_from_buf(data, ret, &msg);

          if (msg.length > 0)
          {
            // write raw data ?
            // what to do here
            printf("%.*s\n", ret, data);
            fprintf(node->fout, "%.*s\n", msg.length, msg.content);
          }

          if (msg.header.length == msg.state.total && msg.state.left == 0) {
            net_close(sock);
          }
        }
        printf("no plaintext to read, moving on\n");
      }
    }
  }
}

int main()
{
#if 1

  net_init();

  ltc_mp = ltm_desc;

  register_prng(&sprng_desc);
  register_hash(&sha256_desc);
  thrd_t n_threads[N_NODES];

  for (int i = 0; i < N_NODES; i++)
  {
    nodes[i].address.a = i;
    nodes[i].id = i;

    char fname[64];
    sprintf(fname, "log/node%i.txt", i);
    nodes[i].fout = fopen(fname, "w");
    printf("%s\n", strerror(errno));

    setvbuf(nodes[i].fout, NULL, _IONBF, 0);
    printf("%s\n", strerror(errno));

    rsa_make_key(NULL, find_prng("sprng"), 1024 / 8, 65537, &nodes[i].key);

    byte buf[1024];
    unsigned long len = 1024;
    rsa_export(buf, &len, PK_PUBLIC, &nodes[i].key);
    fprintf(nodes[i].fout, "Public key (%i bytes):\n\t", (int) len);

    printf("%lu\n", len);
    for (int j = 0; j < len; j++)
    {
      fprintf(nodes[i].fout, "%X", buf[j]);
    }
    fprintf(nodes[i].fout, "\n");


    nodes[i].port = net_rand_port();
    printf("%i port is: %hu\n", i, nodes[i].port);
    node_init(&nodes[i]);
  }

  // simulating acquiring neighbours
  void *peers_buffer =
      calloc(N_NODES, (sizeof(Address) + sizeof(Peer)) * (N_NODES));

  for (int i = 0; i < N_NODES; i++)
  {
    nodes[i].peers_connected = N_NODES;
    nodes[i].peers =
        peers_buffer + ((sizeof(Address) + sizeof(Peer)) * (N_NODES));

    for (int j = 0; j < N_NODES; j++)
    {
      // add the nodes
      nodes[i].peers[j].a = nodes[j].address;
      memcpy(&nodes[i].peers[j].a, &nodes[j].address, sizeof(Address));
      nodes[i].peers[j].p.port = (nodes[j].port);
      nodes[i].peers[j].p.ip = (127 << 0) + (0 << 8) + (0 << 16) + (1 << 24);
    }
  }

  for (int i = 0; i < N_NODES; i++)
  {
    printf("Launching Node: %i\n", i);
    thrd_create(&n_threads[i], node_update, &nodes[i]);
  }

  for (int i = 0; i < N_NODES; i++)
  {
    thrd_join(n_threads[i], NULL);
    fclose(nodes[i].fout);
    rsa_free(&nodes[i].key);
  }

  free(peers_buffer);


  net_uninit();
  return 1;

#else

  /* #define HOST "lukesmith.xyz" */
#define HOST "cedars.xyz"
  /* #define HOST "www.wikipedia.org" */
  /* #define HOST "www.google.com" */
  /* #define HOST "archlinux.org" */
  /* #define HOST "suckless.org" */
  /* #define HOST "odin-lang.org" */
  /* #define HOST "www.slowernews.com" */
  /* #define HOST "en.wikipedia.org" */

  // TODO: there is a random segfault here occasionally, could be bind or
  // connect
  // let's add a middle man

  byte context_buf[4096];
  struct TLSContext *c2;

  return 0;
#endif
}
