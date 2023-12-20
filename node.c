#include "net.c"
#include "block.c"
#include "tlse/tlse.h"
#include <dirent.h>
#include <stdio.h>

#define WITH_TLS_13
// #define DEBUG
#include "tlse/tlse.c"
#include "libhttp/http.c"

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


void send_pending(Socket* sock, struct TLSContext* context)
{
    // send handhake
    const unsigned char* buffer;
    unsigned int left;
    buffer = tls_get_write_buffer(context, &left);
    if (buffer != NULL)
    {
        // XXX: should try and send incrementally actually
        printf("sending: %i/%i\n", net_send(sock, (void*) buffer, left), left);
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

#define HOST "www.wikipedia.org"

    // TODO: there is a random segfault here occasionally, could be bind or connect
    sock = net_connect(HOST, 443);

    // let's add a middle man

    printf("connected\n");
    tls_client_connect(context);
    send_pending(sock, context);

    // send get req and receive stuff
    {
        int read_bytes;
        byte buf[4096];

        while ((read_bytes = net_recv(sock, buf, 4096)) > 0)
        {
            /* for (int i = 0; i < read_bytes; i++) */
            /* { */
            /*     printf("%x", buf[i]); */
            /* } */
            /* putchar('\n'); */
            printf("==>> READ: %i\n", read_bytes);
            // could be null validator
            tls_consume_stream(context, buf, read_bytes, NULL);
            send_pending(sock, context); // bug here

            if (tls_established(context))
            {
                // if sent probs?
                printf("TLS ESTABLISHED\n");
                unsigned char request[] = "GET / HTTP/1.1\r\nHost: " HOST "\r\n\r\n";

                int written = tls_write(context, request, strlen((char*)request));
                send_pending(sock, context);

                printf("sent data\n");
                sleep(1);

                tls_read_clear(context);

                while ((read_bytes = net_recv(sock, buf, 4096)) > 0)
                {
                    static bool found_content = 0;
#define DATA_SIZE 4096
                    unsigned char data[DATA_SIZE];
                    printf("Reading\n");
                    tls_read_clear(context);
                    tls_consume_stream(context, buf, read_bytes, verify_certificate);

                    memset(data, 0, DATA_SIZE);

                    // while loop to read all this also
                    int ret;
                    while ((ret = tls_read(context, data, DATA_SIZE) > 0))
                    {
                        char* off;
                        if (found_content)
                        {
                            /* if ((off = strstr((char*) data, "\r\n0\r\n\r\n")) != NULL) */
                            /* { */
                            /*     data[off - ((char*) data)] = '\0'; */
                            /*     printf("%s", data); */
                            /*     return 1; */
                            /* } */

                            printf("%s", data);
                        }
                        else if ((off = strstr((char*)data, "\r\n\r\n")) != NULL)
                        {
                            off += 4; // start of the actual stirng

                            // print header
                            printf("-----------HEADER------------\n");
                            for (int i = 0; i < off - (char*)data; i++)
                            {
                                putchar(data[i]);
                            }
                            printf("-----------------------------\n");
                            found_content = 1;
                            printf("%s", off);
                        }
                        else
                        {
                            // keep ignoring for now...
                        }
                    }
                    // instead of manual parse, parse with libhttp

                    // need to look for '\r\n\r\n'

                    // is net_close the culprit?
                    // looks like it
                    // net_close();


                    // let's only print the data in the content

                    // content is actually just everything past the HTTP header
                    // so it's "\r\n\r\n" -> "\r\n0\r\n\r\n"
                }

                return 1;
            }
        }
    }

    printf("send no prob!!\n");
    

    return 0;
}
