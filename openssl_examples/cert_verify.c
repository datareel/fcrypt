#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <assert.h>
#include <errno.h>
#include <sys/ioctl.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#if OPENSSL_VERSION_NUMBER >= 0x00907000
#include <openssl/conf.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#endif

static char *_get_rfc2253_formatted (X509_NAME *name)
{
  int len;
  char *out = NULL;
  BIO* b;

  if ((b = BIO_new (BIO_s_mem ())))
    {
      if (X509_NAME_print_ex (b, name, 0, XN_FLAG_RFC2253) >= 0
          && (len = BIO_number_written (b)) > 0)
        {
          out = malloc (len + 1);
          BIO_read (b, out, len);
          out[len] = 0;
        }
      BIO_free (b);
    }

  return out ? out : strdup("");
}

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

int cert_verify1(SSL* ssl)
{
  X509 *cert;
  long rv;
  char *line;
  
  cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
  if(cert == NULL) {
    printf("No certificates configured.\n");
    return 1;
  }


  printf("Server certificates:\n");
  char *subject = _get_rfc2253_formatted (X509_get_subject_name (cert));
  char *issuer = _get_rfc2253_formatted (X509_get_issuer_name (cert));
  printf("Subject: %s\n", subject);
  printf("Issuer: %s\n", issuer);
  free (subject);
  free (issuer);


  //  line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
  // printf("Subject: %s\n", line);
  // free(line);       /* free the malloc'ed string */
  // line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
  // printf("Issuer: %s\n", line);
  // free(line);       /* free the malloc'ed string */
    
  rv = SSL_get_verify_result(ssl);

  if(rv == X509_V_OK) {
    printf("certificate is valid.\n"); 
  }
  
  switch(rv) {
    case X509_V_OK:
      printf("The operation was successful.\n");
      break;
    case X509_V_ERR_UNSPECIFIED:
      printf("Unspecified error; should not happen.\n");
      break;
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
      printf("The issuer certificate of a looked up certificate could not be found. This normally means the list of trusted certificates is not complete.\n");
      break;
    case X509_V_ERR_UNABLE_TO_GET_CRL:
      printf("The CRL of a certificate could not be found.\n");
      break;
    case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
      printf("The certificate signature could not be decrypted. This means that the actual signature value could not be determined rather than it not matching the expected value, this is only meaningful for RSA keys.\n");
      break;
    case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
      printf("The CRL signature could not be decrypted: this means that the actual signature value could not be determined rather than it not matching the expected value. Unused.\n");
      break;
    case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
      printf("The public key in the certificate SubjectPublicKeyInfo could not be read.\n");
      break;
    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
      printf("The signature of the certificate is invalid.\n");
      break;
    case X509_V_ERR_CRL_SIGNATURE_FAILURE:
      printf("The signature of the certificate is invalid.\n");
      break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
      printf("The certificate is not yet valid: the notBefore date is after the current time.\n");
      break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
      printf("The certificate has expired: that is the notAfter date is before the current time.\n");
      break;
    case X509_V_ERR_CRL_NOT_YET_VALID:
      printf("The CRL is not yet valid.\n");
      break;
    case X509_V_ERR_CRL_HAS_EXPIRED:
      printf("The CRL has expired.\n");
      break;
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
      printf("The certificate notBefore field contains an invalid time.\n");
      break;
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
      printf("The certificate notAfter field contains an invalid time.\n");
      break;
    case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
      printf("The CRL lastUpdate field contains an invalid time.\n");
      break;
    case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
      printf("The CRL nextUpdate field contains an invalid time.\n");
      break;
    case X509_V_ERR_OUT_OF_MEM:
      printf("An error occurred trying to allocate memory. This should never happen.\n");
      break;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
      printf("The passed certificate is self-signed and the same certificate cannot be found in the list of trusted certificates.\n");
      break;
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
      printf("The certificate chain could be built up using the untrusted certificates but the root could not be found locally.\n");
      break;
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
      printf("The issuer certificate could not be found: this occurs if the issuer certificate of an untrusted certificate cannot be found.\n");
      break;
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
      printf("No signatures could be verified because the chain contains only one certificate and it is not self signed.\n");
      break;
    case X509_V_ERR_CERT_CHAIN_TOO_LONG:
      printf("The certificate chain length is greater than the supplied maximum depth. Unused.\n");
      break;
    case X509_V_ERR_CERT_REVOKED:
      printf("The certificate has been revoked.\n");
      break;
    case X509_V_ERR_INVALID_CA:
      printf("A CA certificate is invalid. Either it is not a CA or its extensions are not consistent with the supplied purpose.\n");
      break;
    case X509_V_ERR_PATH_LENGTH_EXCEEDED:
      printf("The basicConstraints pathlength parameter has been exceeded.\n");
      break;
    case X509_V_ERR_INVALID_PURPOSE:
      printf("The supplied certificate cannot be used for the specified purpose.\n");
      break;
    case X509_V_ERR_CERT_UNTRUSTED:
      printf("The root CA is not marked as trusted for the specified purpose.\n");
      break;
    case X509_V_ERR_CERT_REJECTED:
      printf("The root CA is marked to reject the specified purpose.\n");
      break;
    case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
      printf("Not used as of OpenSSL 1.1.0 as a result of the deprecation of the -issuer_checks option.\n");
      break;
    case X509_V_ERR_AKID_SKID_MISMATCH:
      printf("Not used as of OpenSSL 1.1.0 as a result of the deprecation of the -issuer_checks option.\n");
      break;
    case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
      printf("Not used as of OpenSSL 1.1.0 as a result of the deprecation of the -issuer_checks option.\n");
      break;
    case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
      printf("Not used as of OpenSSL 1.1.0 as a result of the deprecation of the -issuer_checks option.\n");
      break;
    case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
      printf("Unable to get CRL issuer certificate.\n");
      break;
    case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
      printf("Unhandled critical extension.\n");
      break;
    case X509_V_ERR_KEYUSAGE_NO_CRL_SIGN:
      printf("Key usage does not include CRL signing.\n");
      break;
    case X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
      printf("Unhandled critical CRL extension.\n");
      break;
    case X509_V_ERR_INVALID_NON_CA:
      printf("Invalid non-CA certificate has CA markings.\n");
      break;
    case X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED:
      printf("Proxy path length constraint exceeded.\n");
      break;
      // case X509_V_ERR_PROXY_SUBJECT_INVALID:
      // printf("Proxy certificate subject is invalid. It MUST be the same as the issuer with a single CN component added.\n");
      // break;
    case X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE:
      printf("Key usage does not include digital signature.\n");
      break;
    case X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED:
      printf("Proxy certificates not allowed, please use -allow_proxy_certs.\n");
      break;
    case X509_V_ERR_INVALID_EXTENSION:
      printf("Invalid or inconsistent certificate extension.\n");
      break;
    case X509_V_ERR_INVALID_POLICY_EXTENSION:
      printf("Invalid or inconsistent certificate policy extension.\n");
      break;
    case X509_V_ERR_NO_EXPLICIT_POLICY:
      printf("No explicit policy.\n");
      break;
    case X509_V_ERR_DIFFERENT_CRL_SCOPE:
      printf("Different CRL scope.\n");
      break;
    case X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE:
      printf("Unsupported extension feature.\n");
      break;
    case X509_V_ERR_UNNESTED_RESOURCE:
      printf("RFC 3779 resource not subset of parent's resources.\n");
      break;
    case X509_V_ERR_PERMITTED_VIOLATION:
      printf("Permitted subtree violation.\n");
      break;
    case X509_V_ERR_EXCLUDED_VIOLATION:
      printf("Excluded subtree violation.\n");
      break;
    case X509_V_ERR_SUBTREE_MINMAX:
      printf("Name constraints minimum and maximum not supported.\n");
      break;
    case X509_V_ERR_APPLICATION_VERIFICATION:
      printf("Application verification failure. Unused.\n");
      break;
    case X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE:
      printf("Unsupported name constraint type.\n");
      break;
    case X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX:
      printf("Unsupported or invalid name constraint syntax.\n");
      break;
    case X509_V_ERR_UNSUPPORTED_NAME_SYNTAX:
      printf("Unsupported or invalid name syntax.\n");
      break;
    case X509_V_ERR_CRL_PATH_VALIDATION_ERROR:
      printf("CRL path validation error.\n");
      break;
    case X509_V_ERR_PATH_LOOP:
      printf("Path loop.\n");
      break;
    case X509_V_ERR_SUITE_B_INVALID_VERSION:
      printf("Suite B: certificate version invalid.\n");
      break;
    case X509_V_ERR_SUITE_B_INVALID_ALGORITHM:
      printf("Suite B: invalid public key algorithm.\n");
      break;
    case X509_V_ERR_SUITE_B_INVALID_CURVE:
      printf("Suite B: invalid ECC curve.\n");
      break;
    case X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM:
      printf("Suite B: invalid signature algorithm.\n");
      break;
    case X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED:
      printf("Suite B: curve not allowed for this LOS.\n");
      break;
    case X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256:
      printf("Suite B: cannot sign P-384 with P-256.\n");
      break;
    case X509_V_ERR_HOSTNAME_MISMATCH:
      printf("Hostname mismatch.\n");
      break;
    case X509_V_ERR_EMAIL_MISMATCH:
      printf("Email address mismatch.\n");
      break;
    case X509_V_ERR_IP_ADDRESS_MISMATCH:
      printf("IP address mismatch.\n");
      break;
    case X509_V_ERR_DANE_NO_MATCH:
      printf("DANE TLSA authentication is enabled, but no TLSA records matched the certificate chain. This error is only possible in s_client(1).\n");
      break;
    case X509_V_ERR_EE_KEY_TOO_SMALL:
      printf("EE certificate key too weak.\n");
      break;
      // case X509_ERR_CA_KEY_TOO_SMALL:
    case X509_V_ERR_CA_KEY_TOO_SMALL:
      printf("CA certificate key too weak.\n");
      break;
      // case X509_ERR_CA_MD_TOO_WEAK:
    case X509_V_ERR_CA_MD_TOO_WEAK:
      printf("CA signature digest algorithm too weak.\n");
      break;
    case X509_V_ERR_INVALID_CALL:
      printf("nvalid certificate verification context.\n");
      break;
    case X509_V_ERR_STORE_LOOKUP:
      printf("Issuer certificate lookup error.\n");
      break;
    case X509_V_ERR_NO_VALID_SCTS:
      printf("Certificate Transparency required, but no valid SCTs found.\n");
      break;
    case X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION:
      printf("Proxy subject name violation.\n");
      break;
    case X509_V_ERR_OCSP_VERIFY_NEEDED:
      printf("Returned by the verify callback to indicate an OCSP verification is needed.\n");
      break;
    case X509_V_ERR_OCSP_VERIFY_FAILED:
      printf("Returned by the verify callback to indicate OCSP verification failed.\n");
      break;
    case X509_V_ERR_OCSP_CERT_UNKNOWN:
      printf("Returned by the verify callback to indicate that the certificate is not recognized by the OCSP responder.\n");
      break;
    default :
      printf("Unspecified error; should not happen.\n");
  }

  X509_free(cert);
  if(rv != X509_V_OK) return 1;
  return 0;
}

int main(int argc, char *argv[])
{
  SSL *ssl;
  SSL_CTX *ctx;
  const SSL_METHOD *method;
  int sd = -1;
  char HOST[1024];
  char CALIST[1024];
  int port;
  int rv;
  
  memset(HOST, 0, 1024);
  memset(CALIST, 0, 1024);
  port = 443;
  strcpy(HOST, "google.com");
  strcpy(CALIST, "/etc/pki/tls/certs/ca-bundle.crt");

  if(argc >= 2) strcpy(HOST, argv[1]);
  if(argc >= 3) port = atoi(argv[2]);
  if(argc >= 4) strcpy(CALIST, argv[3]);
  
  /* Setup open SSL init with all cryptos and register error messages */
  OPENSSL_init_ssl (OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ENGINE_ALL_BUILTIN, NULL);

  //SSL_library_init(); 
  //OpenSSL_add_all_algorithms();
  //SSL_load_error_strings();
  // SSLeay_add_all_algorithms ();
  // SSLeay_add_ssl_algorithms ();

  method = TLS_client_method();
   method = SSLv23_client_method ();
  ctx = SSL_CTX_new(method);   /* Create new context */
  if(ctx == NULL) {
    ERR_print_errors_fp(stderr);
    return 1;
  }

  SSL_CTX_set_options (ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
  //  SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
  char *ciphers_string = "HIGH:!aNULL:!RC4:!MD5:!SRP:!PSK";
  //  ciphers_string = "HIGH:!aNULL:!RC4:!MD5:!SRP:!PSK:!kRSA";
  
  // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  if(!SSL_CTX_set_cipher_list(ctx, ciphers_string)) {
    printf("OpenSSL: Invalid cipher list: %s\n", ciphers_string);
    ERR_print_errors_fp(stderr);
    return 1;
  }

  SSL_CTX_set_default_verify_paths(ctx);
  
  if(!(SSL_CTX_load_verify_locations(ctx, CALIST, NULL))) {
    SSL_CTX_free(ctx);
    ERR_print_errors_fp(stderr);
    return 1;
  }

#ifdef X509_V_FLAG_PARTIAL_CHAIN
  /* Set X509_V_FLAG_PARTIAL_CHAIN to allow the client to anchor trust in                                                                              
   * a non-self-signed certificate. This defies RFC 4158 (Path Building)                                                                               
   * which defines a trust anchor in terms of a self-signed certificate.                                                                               
   * However, it substantially reduces attack surface by pruning the tree                                                                              
   * of unneeded trust points. For example, the cross-certified                                                                                        
   * Let's Encrypt X3 CA, which protects gnu.org and appears as an                                                                                     
   * intermediate CA to clients, can be used as a trust anchor without                                                                                 
   * the entire IdentTrust PKI.                                                                                                                        
   */
  X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
  if (param)
    {
      /* We only want X509_V_FLAG_PARTIAL_CHAIN, but the OpenSSL docs                                                                                  
       * say to use X509_V_FLAG_TRUSTED_FIRST also. It looks like                                                                                      
       * X509_V_FLAG_TRUSTED_FIRST applies to a collection of trust                                                                                    
       * anchors and not a single trust anchor.                                                                                                        
       */
      (void) X509_VERIFY_PARAM_set_flags (param, X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_PARTIAL_CHAIN);
      if (SSL_CTX_set1_param (ctx, param) == 0)
	//        logprintf(LOG_NOTQUIET, _("OpenSSL: Failed set trust to partial chain\n"));
      /* We continue on error */
      X509_VERIFY_PARAM_free (param);
    }
  else
    {
      //logprintf(LOG_NOTQUIET, _("OpenSSL: Failed to allocate verification param\n"));
      /* We continue on error */
    }
#endif
  
  SSL_CTX_set_verify (ctx, SSL_VERIFY_NONE, NULL);
  SSL_CTX_set_mode (ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
  SSL_CTX_set_mode (ctx, SSL_MODE_AUTO_RETRY);
  
  ssl = SSL_new(ctx);      /* create new SSL connection state */

  printf("Connecting to %s on TCP port %d\n", HOST, port);

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
  rv = cert_verify1(ssl);
  
  close(sd);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  return rv;
}
