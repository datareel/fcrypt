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

int open_socket(const char *hostname, int port)
{
  int sd;
  struct hostent *host;
  struct sockaddr_in addr;
  if((host = gethostbyname(hostname)) == NULL) {
    perror(hostname);
    return -1;
  }
  sd = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long*)(host->h_addr);
  if(connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) {
    close(sd);
    perror(hostname);
    return -1;
  }
  return sd;
}

int main()
{
  SSL *ssl;
  SSL_CTX *ctx;
  const SSL_METHOD *method;
  int sd = -1;
  char HOST[1024];
  int port;

  memset(HOST, 0, 1024);
  port = 443;
  
  /* Setup open SSL init with all cryptos and register error messages */
  SSL_library_init(); 
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  method = TLS_client_method();
  ctx = SSL_CTX_new(method);   /* Create new context */
  if(ctx == NULL) {
    ERR_print_errors_fp(stderr);
    return 1;
  }
  
  ssl = SSL_new(ctx);      /* create new SSL connection state */

  printf("Connecting to %s on TCP port %d\n", HOST, port);
  
  strcpy(HOST, "google.com");
  sd = open_socket(HOST, port);
  if(sd == -1) return 1;

  SSL_set_fd(ssl, sd); /* attach the socket descriptor */
  if(SSL_connect(ssl) == -1) {   /* perform the connection */
    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 1;
  }

  printf("Connected to %s with %s encryption\n", HOST, SSL_get_cipher(ssl));
  
  close(sd);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  return 0;
}
