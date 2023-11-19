#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main()
{
  SSL *ssl;
  SSL_CTX *ctx;
  SSL_METHOD *method;

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


  SSL_free(ssl);        /* release connection state */
  SSL_CTX_free(ctx);
  return 0;
}
