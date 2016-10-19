#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <dps/cbor.h>

static uint8_t buf[10000];

static uint64_t Uints[] = {
    0, 1, 2, 3, 23, 24, 254, 255, 256, 65534, 65536, 65537,
    UINT32_MAX - 1, UINT32_MAX, (uint64_t)UINT32_MAX + 1, 
    UINT64_MAX - 1, UINT64_MAX
};

static uint64_t Sints[] = {
    INT64_MIN, INT64_MIN + 1,
    -1, 0, 1, -22, -23, -24, -25, -254, -255, -256, -257,
    INT64_MAX - 1, INT64_MAX

};

static const char *Strings[] = {
    "a", "bc", "def"
};

int main(int argc, char** argv)
{
    size_t i;
    DPS_Status ret;
    DPS_Buffer buffer;
    uint8_t* test;
    size_t size;

    DPS_BufferInit(&buffer, buf, sizeof(buf));

    for (i = 0; i < sizeof(Uints) / sizeof(Uints[0]); ++i) {
        CBOR_EncodeUint(&buffer, Uints[i]);
    }

    CBOR_EncodeBytes(&buffer, (uint8_t*)Uints, sizeof(Uints));

    for (i = 0; i < sizeof(Sints) / sizeof(Sints[0]); ++i) {
        CBOR_EncodeInt(&buffer, Sints[i]);
    }

    CBOR_EncodeArray(&buffer, sizeof(Strings) / sizeof(Strings[0]));

    for (i = 0; i < sizeof(Strings) / sizeof(Strings[0]); ++i) {
        CBOR_EncodeString(&buffer, Strings[i]);
    }

    printf("Encoded %zu bytes\n", DPS_BufferAvail(&buffer));

    buffer.pos = buffer.base;
    for (i = 0; i < sizeof(Uints) / sizeof(Uints[0]); ++i) {
        uint64_t n;
        CBOR_DecodeUint(&buffer, &n);
        assert(n == Uints[i]);
    }

    CBOR_DecodeBytes(&buffer, &test, &i);
    assert(i == sizeof(Uints));
    assert(memcmp(Uints, test, i) == 0);

    for (i = 0; i < sizeof(Sints) / sizeof(Sints[0]); ++i) {
        int64_t n;
        CBOR_DecodeInt(&buffer, &n);
        assert(n == Sints[i]);
    }

    CBOR_DecodeArray(&buffer, &size);
    assert(size == (sizeof(Strings) / sizeof(Strings[0])));

    for (i = 0; i < sizeof(Strings) / sizeof(Strings[0]); ++i) {
        char *str;
        size_t len;
        CBOR_DecodeString(&buffer, &str, &len);
        assert(!strcmp(str, Strings[i]));
    }

    printf("Passed\n");
}
