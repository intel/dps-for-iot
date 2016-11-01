#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <crypto/aes.h>
#include <crypto/ccm.h>

#define mbedtls_printf printf

/*
 * AES test vectors from:
 *
 * http://csrc.nist.gov/archive/aes/rijndael/rijndael-vals.zip
 */
static const unsigned char aes_test_ecb_dec[3][16] =
{
    { 0x44, 0x41, 0x6A, 0xC2, 0xD1, 0xF5, 0x3C, 0x58,
      0x33, 0x03, 0x91, 0x7E, 0x6B, 0xE9, 0xEB, 0xE0 },
    { 0x48, 0xE3, 0x1E, 0x9E, 0x25, 0x67, 0x18, 0xF2,
      0x92, 0x29, 0x31, 0x9C, 0x19, 0xF1, 0x5B, 0xA4 },
    { 0x05, 0x8C, 0xCF, 0xFD, 0xBB, 0xCB, 0x38, 0x2D,
      0x1F, 0x6F, 0x56, 0x58, 0x5D, 0x8A, 0x4A, 0xDE }
};

static const unsigned char aes_test_ecb_enc[3][16] =
{
    { 0xC3, 0x4C, 0x05, 0x2C, 0xC0, 0xDA, 0x8D, 0x73,
      0x45, 0x1A, 0xFE, 0x5F, 0x03, 0xBE, 0x29, 0x7F },
    { 0xF3, 0xF6, 0x75, 0x2A, 0xE8, 0xD7, 0x83, 0x11,
      0x38, 0xF0, 0x41, 0x56, 0x06, 0x31, 0xB1, 0x14 },
    { 0x8B, 0x79, 0xEE, 0xCC, 0x93, 0xA0, 0xEE, 0x5D,
      0xFF, 0x30, 0xB4, 0xEA, 0x21, 0x63, 0x6D, 0xA4 }
};

/*
 * Checkup routine
 */
int mbedtls_aes_self_test( int verbose )
{
    int ret = 0, i, j, u, v;
    unsigned char key[32];
    unsigned char buf[64];
    mbedtls_aes_context ctx;

    memset( key, 0, 32 );
    mbedtls_aes_init( &ctx );

    /*
     * ECB mode
     */
    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        v = i  & 1;

        if( verbose != 0 )
            mbedtls_printf( "  AES-ECB-%3d (%s): ", 128 + u * 64,
                             ( v == MBEDTLS_AES_DECRYPT ) ? "dec" : "enc" );

        memset( buf, 0, 16 );

        if( v == MBEDTLS_AES_DECRYPT )
        {
            mbedtls_aes_setkey_dec( &ctx, key, 128 + u * 64 );

            for( j = 0; j < 10000; j++ )
                mbedtls_aes_crypt_ecb( &ctx, v, buf, buf );

            if( memcmp( buf, aes_test_ecb_dec[u], 16 ) != 0 )
            {
                if( verbose != 0 )
                    mbedtls_printf( "failed\n" );

                ret = 1;
                goto exit;
            }
        }
        else
        {
            mbedtls_aes_setkey_enc( &ctx, key, 128 + u * 64 );

            for( j = 0; j < 10000; j++ )
                mbedtls_aes_crypt_ecb( &ctx, v, buf, buf );

            if( memcmp( buf, aes_test_ecb_enc[u], 16 ) != 0 )
            {
                if( verbose != 0 )
                    mbedtls_printf( "failed\n" );

                ret = 1;
                goto exit;
            }
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    if( verbose != 0 )
        mbedtls_printf( "\n" );


    ret = 0;

exit:
    mbedtls_aes_free( &ctx );

    return( ret );
}

#define NB_TESTS 3

/*
 * The data is the same for all tests, only the used length changes
 */
static const unsigned char key[] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
};

static const unsigned char iv[] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b
};

static const unsigned char ad[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13
};

static const unsigned char msg[] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
};

static const size_t iv_len [NB_TESTS] = { 7, 8,  12 };
static const size_t add_len[NB_TESTS] = { 8, 16, 20 };
static const size_t msg_len[NB_TESTS] = { 4, 16, 24 };
static const size_t tag_len[NB_TESTS] = { 4, 6,  8  };

static const unsigned char res[NB_TESTS][32] = {
    {   0x71, 0x62, 0x01, 0x5b, 0x4d, 0xac, 0x25, 0x5d },
    {   0xd2, 0xa1, 0xf0, 0xe0, 0x51, 0xea, 0x5f, 0x62,
        0x08, 0x1a, 0x77, 0x92, 0x07, 0x3d, 0x59, 0x3d,
        0x1f, 0xc6, 0x4f, 0xbf, 0xac, 0xcd },
    {   0xe3, 0xb2, 0x01, 0xa9, 0xf5, 0xb7, 0x1a, 0x7a,
        0x9b, 0x1c, 0xea, 0xec, 0xcd, 0x97, 0xe7, 0x0b,
        0x61, 0x76, 0xaa, 0xd9, 0xa4, 0x42, 0x8a, 0xa5,
        0x48, 0x43, 0x92, 0xfb, 0xc1, 0xb0, 0x99, 0x51 }
};

int mbedtls_ccm_self_test( int verbose )
{
    mbedtls_ccm_context ctx;
    unsigned char out[32];
    size_t i;
    int ret;

    mbedtls_ccm_init( &ctx );

    if( mbedtls_ccm_setkey( &ctx, MBEDTLS_CIPHER_ID_AES, key, 8 * sizeof key ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "  CCM: setup failed" );

        return( 1 );
    }

    for( i = 0; i < NB_TESTS; i++ )
    {
        if( verbose != 0 )
            mbedtls_printf( "  CCM-AES #%u: ", (unsigned int) i + 1 );

        ret = mbedtls_ccm_encrypt_and_tag( &ctx, msg_len[i],
                                   iv, iv_len[i], ad, add_len[i],
                                   msg, out,
                                   out + msg_len[i], tag_len[i] );

        if( ret != 0 ||
            memcmp( out, res[i], msg_len[i] + tag_len[i] ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            return( 1 );
        }

        ret = mbedtls_ccm_auth_decrypt( &ctx, msg_len[i],
                                iv, iv_len[i], ad, add_len[i],
                                res[i], out,
                                res[i] + msg_len[i], tag_len[i] );

        if( ret != 0 ||
            memcmp( out, msg, msg_len[i] ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            return( 1 );
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    mbedtls_ccm_free( &ctx );

    if( verbose != 0 )
        mbedtls_printf( "\n" );

    return( 0 );
}

int main(int argc, char** argv)
{
    mbedtls_aes_self_test(1);

    mbedtls_ccm_self_test(1);

    return 0;
}
