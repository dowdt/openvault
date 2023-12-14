#include <libressl/tls.h>

#include <libressl/openssl/tls1.h>
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

    tls_configure(ctx, config);

    printf("connecting...\n");
    int notsure = tls_connect(ctx, "lukesmith.xyz", "443");
    err_check(ctx);

    printf("handshake...\n");
    tls_handshake(ctx);
    err_check(ctx);
    
    printf("get request...\n");
    const char* message = "GET / HTTP/1.1\r\nHost: lukesmith.xyz\r\n\r\n";
    tls_write(ctx, message, 45);

    for (;;)
    {
        printf("reading...\n");
        static char buf[1024];
        ssize_t len = tls_read(ctx, (void*) buf, 1023);

        if (len > 0 && len < 1024)
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
