#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "murmurhash3.h"

static uint32_t Seeds[] = {
    0xCBA13EBF,
    0xCCEC6FED,
    0xC738A54D,
    0xF7C86851,
    0xC68429AB,
    0xF664EF6B,
    0xEAEFD0FB,
    0xE3C4573B,
    0xF540EAB3,
    0xE2AA6731,
    0xE9885249,
    0xFA7614E5,
    0xEB9D87C9,
    0xCFA93CF7,
    0xF819A6A3,
    0xD9AF1677,
    0xCBC065B5
};

static void Hash(const uint8_t* data, size_t len, uint32_t* hashes, size_t numHashes)
{
    size_t i;
    for (i = 0; i < numHashes; ++i) {
        MurmurHash3_x86_32(data, len, Seeds[i], &hashes[i]);
    }
}

int main()
{
    size_t i;
    size_t n;
    char test[2];
    uint32_t hashes[16];
    for (i = 0; i < 26; ++i) {
        test[0] = 'A' + i;
        test[1] = 0;
        Hash(test, 1, hashes, 16);
        printf("%s -> ", test);
        for (n = 0; n < 16; ++n) {
            printf("%08x ", hashes[n]);
        }
        printf("\n");
    }
}

