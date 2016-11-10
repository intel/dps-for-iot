#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/numeric.h"
#include "crypto/ccm.h"

#include "ccm-testdata.c"

void 
dump(unsigned char *buf, size_t len) {
  size_t i = 0;
  while (i < len) {
    printf("%02x ", buf[i++]);
    if (i % 4 == 0)
      printf(" ");
    if (i % 16 == 0)
      printf("\n\t");
  }
  printf("\n");
}

int main(int argc, char **argv) {
  long int len;
  int n;

  rijndael_ctx ctx;

  for (n = 0; n < sizeof(data)/sizeof(struct test_vector); ++n) {

    if (rijndael_set_key_enc_only(&ctx, data[n].key, 8*sizeof(data[n].key)) < 0) {
      fprintf(stderr, "cannot set key\n");
      return -1;
    }

    len = dtls_ccm_encrypt_message(&ctx, data[n].M, data[n].L, data[n].nonce, 
				   data[n].msg + data[n].la, 
				   data[n].lm - data[n].la, 
				   data[n].msg, data[n].la);
    
    len +=  + data[n].la;
    printf("Packet Vector #%d ", n+1);
    if (len != data[n].r_lm || memcmp(data[n].msg, data[n].result, len))
      printf("FAILED, ");
    else 
      printf("OK, ");
    
    printf("result is (total length = %lu):\n\t", len);
    dump(data[n].msg, len);

    len = dtls_ccm_decrypt_message(&ctx, data[n].M, data[n].L, data[n].nonce, 
				   data[n].msg + data[n].la, len - data[n].la, 
				   data[n].msg, data[n].la);
    
    if (len < 0)
      printf("Packet Vector #%d: cannot decrypt message\n", n+1);
    else 
      printf("\t*** MAC verified (total length = %lu) ***\n", len + data[n].la);
  }

  return 0;
}
