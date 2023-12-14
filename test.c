#include <libressl/tls.h>

#include <libressl/openssl/tls1.h>
#include <string.h>
#include <stdio.h>

void err_check(struct tls* ctx)
{
    const char* err = tls_error(ctx);
    if (err != NULL)
    {
        printf("%s\n", err);
    }
}

int main()
{
    // do all the steps!
    tls_init();

    struct tls* ctx = tls_client();

    struct tls_config* config = tls_config_new();


    // SAD! can't generate secret, have to take from somewhere else
    /* /1* unsigned char key[256] = { 'a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a' }; *1/ */
    /* unsigned char key[8] = { 0xff, 0xff, 0xff, 0xff }; */
    /* int res = tls_config_set_key_mem(config, key, 256); */
    /* const char* msg = tls_config_error(config); */
    /* if (msg != NULL) */
    /* { */
    /*     printf("Error: %s\n", msg); */
    /*     return 0; */
    /* } */


    tls_configure(ctx, config);
    tls_config_free(config);

#define HOST "nitter.net"
#define GET_REQUEST "GET / HTTP/1.1\r\nHost: " HOST "\r\n\r\n"

    printf("connecting...\n");
    int notsure = tls_connect(ctx, HOST, "443");
    err_check(ctx);

    printf("handshake...\n");
    tls_handshake(ctx);
    err_check(ctx);
    
    printf("get request...\n");
    const char* message = GET_REQUEST;
    tls_write(ctx, message, strlen(GET_REQUEST));

    printf("reading...\n");
    for (;;)
    {
#define BUFLEN 1024
        static char buf[BUFLEN];
        ssize_t len = tls_read(ctx, (void*) buf, BUFLEN - 1);

        if (len > 0 && len < BUFLEN)
        {
            printf("Got buffer size %lu, message:\n%s\n", len, buf);
            err_check(ctx);
            break;
        }
    }

    printf("closing...\n");
    tls_close(ctx);
    err_check(ctx);

    printf("%i\n", notsure);

    return 0;
}
