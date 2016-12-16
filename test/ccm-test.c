/*
 *******************************************************************
 *
 * Copyright 2016 Intel Corporation All rights reserved.
 *
 *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ccm.h"
#include <dps/private/dps.h>

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

int main(int argc, char **argv)
{
    DPS_Buffer buf;
    DPS_Status ret;
    long int len;
    int n;

    for (n = 0; n < sizeof(data)/sizeof(struct test_vector); ++n) {

        ret = Encrypt_CCM(data[n].key,
                          data[n].M,
                          data[n].L,
                          data[n].nonce, 
                          data[n].msg + data[n].la, 
                          data[n].lm - data[n].la, 
                          data[n].msg, data[n].la);

        len = data[n].lm + data[n].M;
        printf("Packet Vector #%d ", n+1);
        if (len != data[n].r_lm || memcmp(data[n].msg, data[n].result, len))
            printf("FAILED, ");
        else 
            printf("OK, ");

        printf("result is (total length = %lu):\n\t", len);
        dump(data[n].msg, len);

        ret = Decrypt_CCM(data[n].key,
                          data[n].M,
                          data[n].L,
                          data[n].nonce, 
                          data[n].msg + data[n].la,
                          len - data[n].la, 
                          data[n].msg,
                          data[n].la);

        if (ret != DPS_OK) {
            printf("Packet Vector #%d: cannot decrypt message\n", n+1);
            return 1;
        } else {
            printf("\t*** MAC verified (total length = %lu) ***\n", len + data[n].la);
        }
    }

    return 0;
}
