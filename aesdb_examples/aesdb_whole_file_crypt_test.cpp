// Test AES encryption code by encrypting and decrypting a whole file

#include <iostream>
using namespace std;

#include <aesdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main(int argc, char *argv[])
{
  const char *password = "password";
  int rv = 0;

  FILE *f_src, *f_enc, *f_dec;
  char fname[256];
  memset(fname, 0, 256);
  strcpy(fname, "testfile2.txt");

  char ecfname[256];
  memset(ecfname, 0, 256);
  strcpy(ecfname, "testfile2.enc");
  
  char dcfname[256];
  memset(dcfname, 0, 256);
  strcpy(dcfname, "testfile2.dec");

  cout << "Source file: " << fname << "\n";
  f_src = fopen(fname, "rb");
  if (!f_src) {
    fprintf(stderr, "ERROR: Cannot open file : %s\n", fname);
    fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
    return errno;
  }

  cout << "Encrypted file: " << ecfname << "\n";
  f_enc = fopen(ecfname, "wb");
  if (!f_enc) {
    fprintf(stderr, "ERROR: Cannot open file : %s\n", ecfname);
    fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
    return errno;
  }

  char read_buf[AES_PLAINTEXT_BUF_SIZE];

  const unsigned input_buf_len = AES_MAX_INPUT_BUF_LEN;

  const unsigned encrypted_input_buf_len = input_buf_len + AES_file_enctryption_overhead();
  unsigned bytes_read = 0;
  unsigned new_buf_len = 0;
  int ERROR_LEVEL = 0;

  unsigned total_bytes_read = 0;
  unsigned total_encypted_bytes = 0;
  unsigned total_decypted_bytes = 0;

  cout << "Starting file read and encryption" << "\n";
  while(!feof(f_src)) {
    AES_fillrand((unsigned char *)read_buf, sizeof(read_buf));
    bytes_read = fread(read_buf, sizeof(unsigned char), input_buf_len, f_src);
    if(ferror(f_src)) {
      fprintf(stderr, "ERROR: Read error: %s\n", fname);
      fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
      ERROR_LEVEL = errno;
      break;
    }

    cout << "Bytes read = " << bytes_read << "\n";
    total_bytes_read += bytes_read;
    
    new_buf_len = bytes_read;
    rv = AES_Encrypt(read_buf, &new_buf_len, (const unsigned char *) password, strlen(password));
    if(rv != AES_NO_ERROR) {
      cout << AES_err_string(rv) << "\n";
      ERROR_LEVEL = rv;
      break;
    }

    cout << "Encrypted bytes to write = " << new_buf_len << "\n";
    total_encypted_bytes += new_buf_len;
    
    fwrite((const void*)read_buf, sizeof(unsigned char), new_buf_len, f_enc);
    if(ferror(f_enc)) {
      fprintf(stderr, "ERROR: Error writing encrypted message stream to file: %s\n", ecfname);
      fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
      ERROR_LEVEL = errno;
      break;
    }
  }

  if(ERROR_LEVEL != 0) return ERROR_LEVEL;
  
  cout << "End of file read and encryption" << "\n";
  cout << "Total input bytes = " << total_bytes_read << "\n";
  cout << "Total encrypted bytes wrote = " << total_encypted_bytes << "\n";
  
  fclose(f_src);
  fclose(f_enc);
  
  f_enc = fopen(ecfname, "rb");
  if (!f_enc) {
    fprintf(stderr, "ERROR: Cannot open file : %s\n", ecfname);
    fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
    return errno;
  }

  cout << "\n";
  cout << "Decrypted file: " << dcfname << "\n";
  f_dec = fopen(dcfname, "wb");
  if (!f_dec) {
    fprintf(stderr, "ERROR: Cannot open file : %s\n", dcfname);
    fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
    return errno;
  }

  total_bytes_read = 0;
  while(!feof(f_enc)) {
    AES_fillrand((unsigned char *)read_buf, sizeof(read_buf));
    bytes_read = fread(read_buf, sizeof(unsigned char), encrypted_input_buf_len, f_enc);
    if(ferror(f_enc)) {
      fprintf(stderr, "ERROR: Read error: %s\n", ecfname);
      fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
      ERROR_LEVEL = errno;
      break;
    }

    cout << "Encrypted bytes read = " << bytes_read << "\n";
    total_bytes_read += bytes_read;
    new_buf_len = bytes_read;

    rv = AES_Decrypt(read_buf, &new_buf_len, (const unsigned char *) password, strlen(password));
    if(rv != AES_NO_ERROR) {
      cout << AES_err_string(rv) << "\n";
      ERROR_LEVEL = rv;
      break;
    }
    cout << "Decrypted bytes to write = " << new_buf_len << "\n";
    total_decypted_bytes += new_buf_len;
    
    fwrite((const void*)read_buf, sizeof(unsigned char), new_buf_len, f_dec);
    if(ferror(f_dec)) {
      fprintf(stderr, "ERROR: Error writing encrypted message stream to file: %s\n", dcfname);
      fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
      ERROR_LEVEL = errno;
      break;
    }
  }

  if(ERROR_LEVEL != 0) return ERROR_LEVEL;
  
  cout << "Total encrypted input bytes = " << total_bytes_read << "\n";
  cout << "Total decrypted bytes wrote = " << total_decypted_bytes << "\n";
  
  
  fclose(f_dec);
  fclose(f_enc);

  return ERROR_LEVEL;
}
