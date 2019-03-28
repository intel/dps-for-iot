/*
 *******************************************************************
 *
 * Copyright 2019 Intel Corporation All rights reserved.
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

#include <mbedtls/sha512.h>

#if defined(DPS_USE_NASM)

#if defined(__AVX2__) || defined(__AVX__)

extern void sha512_block_avx( const void *,
                              void * );

int mbedtls_internal_sha512_process( mbedtls_sha512_context *ctx,
                                     const unsigned char data[128] )
{
    sha512_block_avx( data, ctx->state );
    return ( 0 );
}

#elif defined(__SSE__) || defined(_M_X64) || defined(_M_AMD64)

extern void sha512_block_sse( const void *,
                              void * );

int mbedtls_internal_sha512_process( mbedtls_sha512_context *ctx,
                                     const unsigned char data[128] )
{
    sha512_block_sse( data, ctx->state );
    return ( 0 );
}

#endif

#endif /* DPS_USE_NASM */
