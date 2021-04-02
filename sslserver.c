#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Can't bind to port");
        abort();
    }
    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}
int isRoot()
{
    if (getuid() != 0) {
        return 0;
    }
    else {
        return 1;
    }
}
SSL_CTX* InitServerCTX(void)
{
    SSL_METHOD* method;
    SSL_CTX* ctx;
    OpenSSL_add_all_algorithms(); /* load & register all cryptos, etc. */
    SSL_load_error_strings(); /* load all error messages */
    method = (SSL_METHOD*)TLSv1_2_server_method(); /* create new server-method instance */
    ctx = SSL_CTX_new(method); /* create new context from method */
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* key, char* cert)
{
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
    char buf[1024] = { 0 };

    if (SSL_accept(ssl) == -1) /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else {
        int nread = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        buf[nread] = '\0';
        printf("Client msg: \n---------------------\n%s\n---------------------\n", buf);
        if (nread > 0) {
            SSL_write(ssl, "HTTP/1.1 200\n\nHello, I am a secure server.", 42); /* send reply */
        }
        else {
            ERR_print_errors_fp(stderr);
        }
    }
    int sd = SSL_get_fd(ssl); /* get socket connection */
    SSL_free(ssl); /* release SSL state */
    close(sd); /* close connection */
}

int ssl_verify_peer(int ok, X509_STORE_CTX* ctx)
{
    if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT) {
        printf("Unable to get issuer cert!\n");
        return 0;
    }

    if (!X509_verify_cert(ctx)) {
        printf("Unable to verify peer cert, depth[%d], error[%d]\n",
            X509_STORE_CTX_get_error_depth(ctx), X509_STORE_CTX_get_error(ctx));
        return 0;
    }

    char issuer[256];
    char subject[256];

    X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), issuer, 256);
    X509_NAME_oneline(X509_get_subject_name(ctx->current_cert), subject, 256);

    printf("Peer cert details: issuer[%s], subject[%s]\n", issuer, subject);

    return 1;
}

static int ssl_session_id_ctx = 1;
int main(int argv, char* argc[])
{
    if (argv != 2) {
        printf("Usage: %s <portnum>\n", argc[0]);
        exit(0);
    }

    SSL_library_init(); /* Initialize the SSL library */
    SSL_CTX* ctx = InitServerCTX(); /* initialize SSL */
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
    LoadCertificates(ctx, "private.key", "certificate.crt"); /* load certs */
    SSL_CTX_set_session_id_context(ctx, (void*)&ssl_session_id_ctx, sizeof(ssl_session_id_ctx));
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, ssl_verify_peer);

    int server = OpenListener(atoi(argc[1])); /* create server socket */
    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        int client = accept(server, (struct sockaddr*)&addr, &len); /* accept connection as usual */
        printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        SSL* ssl = SSL_new(ctx); /* get new SSL state with context */
        SSL_set_fd(ssl, client); /* set connection socket to SSL state */
        Servlet(ssl); /* service connection */
    }
    close(server); /* close server socket */
    SSL_CTX_free(ctx); /* release context */
}

// openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout private.key -out certificate.crt
// gcc -o sslserver sslserver.c -lssl -lcrypto
