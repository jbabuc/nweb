#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int OpenConnection(const char* hostname, int port)
{
    int sd;
    struct hostent* host;
    struct sockaddr_in addr;
    if ((host = gethostbyname(hostname)) == NULL) {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}
SSL_CTX* InitCTX(void)
{
    SSL_METHOD* method;
    SSL_CTX* ctx;
    OpenSSL_add_all_algorithms(); /* Load cryptos, et.al. */
    SSL_load_error_strings(); /* Bring in and register error messages */
    method = TLSv1_2_client_method(); /* Create new client-method instance */
    ctx = SSL_CTX_new(method); /* Create new context */
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void ShowCerts(SSL* ssl)
{
    X509* cert;
    char* line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if (cert != NULL) {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line); /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line); /* free the malloc'ed string */
        X509_free(cert); /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}
int main(int argv, char* argc[])
{
    char buf[256 * 1024];
    int len;
    if (argv != 3) {
        printf("usage: %s <hostname> <portnum>\n", argc[0]);
        exit(0);
    }

    SSL_library_init();
    SSL_CTX* ctx = InitCTX();
    SSL* ssl = SSL_new(ctx); /* create new SSL connection state */
    int server = OpenConnection(argc[1], atoi(argc[2]));
    SSL_set_fd(ssl, server); /* attach the socket descriptor */

    if (SSL_connect(ssl) == -1) /* perform the connection */
        ERR_print_errors_fp(stderr);
    else {
        ShowCerts(ssl); /* get any certs */
        SSL_write(ssl, "GET /\n\n", 7); /* encrypt & send message */
        len = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
        buf[len] = 0;
        printf("Received: \"%s\"\n", buf);
        SSL_free(ssl); /* release connection state */
    }
    close(server); /* close socket */
    SSL_CTX_free(ctx); /* release context */
    return 0;
}

// gcc -o sslclient sslclient.c -lssl -lcrypto