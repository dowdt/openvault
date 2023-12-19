#include "net.c"
#include "block.c"
#include "tlse/tlse.h"
#include <dirent.h>
#include <stdio.h>

#define WITH_TLS_13
// #define DEBUG
#include "tlse/tlse.c"

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

void edge_node()
{
    // ??
}


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


void send_pending(struct TLSContext* context)
{
    // send handhake
    const unsigned char* buffer;
    unsigned int left;
    buffer = tls_get_write_buffer(context, &left);
    if (buffer != NULL)
    {
        // XXX: should try and send incrementally actually
        printf("sending: %i/%i\n", net_send((void*) buffer, left), left);
    }

    tls_buffer_clear(context);
}

int verify_certificate(struct TLSContext *context, struct TLSCertificate **certificate_chain, int len)
{
    return no_error;
}

int main()
{
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
    tls_validation_function validate_function;
    Socket* sock;

    if (load_root_certificates(context))
    {
    }

    printf("loaded certificates\n");

#define HOST "wikipedia.org"
    sock = net_connect(HOST, 443);
    net_bind(sock);

    printf("connected\n");
    tls_client_connect(context);
    send_pending(context);

    // send get req and receive stuff
    {
        int read_bytes;
        byte buf[4096];

        while ((read_bytes = net_recv(buf, 4096)) > 0)
        {
            /* for (int i = 0; i < read_bytes; i++) */
            /* { */
            /*     printf("%x", buf[i]); */
            /* } */
            /* putchar('\n'); */
            printf("==>> READ: %i\n", read_bytes);
            // could be null validator
            tls_consume_stream(context, buf, read_bytes, NULL);
            send_pending(context); // bug here

            if (tls_established(context))
            {
                printf("TLS ESTABLISHED\n");
                unsigned char request[] = "GET / HTTP/1.1\r\nHost: " HOST "\r\n\r\n";

                int written = tls_write(context, request, strlen(request));
                send_pending(context);

                printf("sent data\n");

                tls_read_clear(context);

                while ((read_bytes = net_recv(buf, 2048)) > 0)
                {
                    unsigned char data[1024];

                    printf("Reading\n");
                    tls_read_clear(context);
                    tls_consume_stream(context, buf, read_bytes, NULL);

                    memset(data, 0, 1024);
                    int ret = tls_read(context, data, 1023);

                    printf("Read: %i, Got data: %s\n", ret, data);

                    if (ret == 0)
                    {
                        // no more data, so close
                        net_close();
                    }
                }

                return 1;
            }
        }
    }

    printf("send no prob!!\n");
    

    return 0;
}
