// Test program used to decrypt a specified file

#include <iostream>
using namespace std;

#include <aesdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int DEBUGMODE = 0;

int main(int argc, char *argv[])
{
  // NOTE: For testing we will hard code a simple password
  // NOTE: For real usage you need to prompt or a password or supply a key
  const char *password = "password";
  unsigned password_len = strlen(password);

  unsigned int i =  0;
  int rv = 0;

  FILE *f_enc, *f_dec;

  char ecfname[256];
  memset(ecfname, 0, 256);
  
  char dcfname[256];
  memset(dcfname, 0, 256);

  if(argc < 3) {
    printf("ERROR - You must specify an input file to decrypt and the output file name for the unencrypted file\n");
    printf("Example: %s testfile.enc testfile.txt\n", argv[0]);
    return 1;
  }

  strncpy(ecfname, argv[1], (sizeof(ecfname)-1));
  strncpy(dcfname, argv[2], (sizeof(dcfname)-1));
  
  char read_buf[AES_PLAINTEXT_BUF_SIZE];
  const unsigned input_buf_len = AES_MAX_INPUT_BUF_LEN;
  const unsigned encrypted_input_buf_len = input_buf_len + AES_file_enctryption_overhead();
  unsigned bytes_read = 0;
  unsigned new_buf_len = 0;
  int ERROR_LEVEL = 0;

  unsigned total_bytes_read = 0;
  unsigned total_encypted_bytes = 0;
  unsigned total_decypted_bytes = 0;

  cout << "Encrypted file: " << dcfname << "\n";
  f_enc = fopen(ecfname, "rb");
  if (!f_enc) {
    fprintf(stderr, "ERROR: Cannot open file : %s\n", ecfname);
    fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
    return errno;
  }

  cout << "Decrypted file: " << dcfname << "\n";
  f_dec = fopen(dcfname, "wb");
  if (!f_dec) {
    fprintf(stderr, "ERROR: Cannot open file : %s\n", dcfname);
    fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
    return errno;
  }

  total_bytes_read = 0;

  cout << "Starting file read and decryption" << "\n";
  while(!feof(f_enc)) {
    AES_fillrand((unsigned char *)read_buf, sizeof(read_buf));
    bytes_read = fread(read_buf, sizeof(unsigned char), encrypted_input_buf_len, f_enc);
    if(ferror(f_enc)) {
      fprintf(stderr, "ERROR: Read error: %s\n", ecfname);
      fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
      ERROR_LEVEL = errno;
      break;
    }

    if(DEBUGMODE) cout << "Encrypted bytes read = " << bytes_read << "\n";
    total_bytes_read += bytes_read;
    new_buf_len = bytes_read;

    rv = AES_Decrypt(read_buf, &new_buf_len, (const unsigned char *) password, strlen(password));
    if(rv != AES_NO_ERROR) {
      cout << AES_err_string(rv) << "\n";
      ERROR_LEVEL = rv;
      break;
    }
    if(DEBUGMODE) cout << "Decrypted bytes to write = " << new_buf_len << "\n";
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

  cout << "End of file read and decryption" << "\n";
  cout << "Total encrypted input bytes = " << total_bytes_read << "\n";
  cout << "Total decrypted bytes wrote = " << total_decypted_bytes << "\n";
  
  fclose(f_dec);
  fclose(f_enc);

  return ERROR_LEVEL;
}
    
