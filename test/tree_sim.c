#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

typedef struct _Node Node;

#define MANGLE_SIZE 8

typedef struct _Node {
    uint64_t _union;
    uint8_t mangled[MANGLE_SIZE];
    size_t count;
    Node* children[1];
} Node;

size_t PopCount(uint64_t n)
{
    size_t pop = 0;
    while (n) {
        pop += (n & 1);
        n >>= 1;
    }
    return pop;
}

#define TEST_BIT8(a, b) ((a)[(b) >> 3] &  (1 << ((b) & 0x7)))

static void DumpVector(void* vec, size_t sz)
{
    char txt[257];
    size_t i;
    size_t pop = 0;
    uint8_t* v = vec;

    assert(sz < (8 * (sizeof(txt) - 1)));

    memset(txt, '0', sz);
    txt[sz] = 0;
    for (i = 0; i < sz; ++i) {
        if (TEST_BIT8(v, i)) {
            txt[i] = '1';
            ++pop;
        }
    }
    printf("%02zu %s\n", pop, txt);
}

static void DumpTree(Node* n, size_t indent)
{
    size_t i;
    static const char* ws = "                                       ";
    printf("%.*s  ", (int)indent * 4, ws);
    DumpVector(&n->_union, 8 * sizeof(n->_union));
    for (i = 0; i < n->count; ++i) {
        DumpTree(n->children[i], indent + 1);
    }
}

static size_t numLeafs = 0;
static uint64_t leafs[100];
static uint64_t vectors[100];

static const uint64_t ExpBits[2][64] = {
    {
    /* Population count = 12 */
    0x1014649840880000, 0x1020A0004A2A0090, 0x000822C240804448, 0x04100F4018881000, 
    0x1102212009002441, 0x2B0800E020482000, 0x22024002184001B0, 0x8820020144128140, 
    0x0400414C10700280, 0x8100CB0000106028, 0x020042020A080C32, 0x80412195000E0000, 
    0xA0100C0056280040, 0x2103084012002160, 0x2144483020104800, 0x04411122C0001024, 
    0x8208082918000C40, 0x19C400040020008D, 0x0014001028072860, 0x0C00020406022219, 
    0x104004C00080107C, 0x2040288820250014, 0x0814080010323410, 0x4840082800304D00, 
    0x8110404410808501, 0x1A4A008110220001, 0xB08100030C110001, 0x6080A0601A020400, 
    0x004740050100220A, 0xCB06510000400020, 0x4818201024840048, 0xC030286224000800, 
    0xA021404041003500, 0x48820460000020E1, 0x2460402410042050, 0xA0044500000201B1, 
    0x146090008100C042, 0x0004008C0202AC22, 0x0000160C102B8200, 0x4405400580A00210, 
    0x024202210001C209, 0x0002809041010076, 0x0441081418801600, 0x4010079048050002, 
    0x11000214D8000106, 0x0008A00083501501, 0x8042100033410060, 0x80014C8010842014, 
    0x001C004481062060, 0x2211100830100540, 0x0608801200802328, 0x18B80004402A1000, 
    0x2000848484908048, 0x1492181600100010, 0x20018A1000484430, 0x20020322009001C4, 
    0x04203504A0014040, 0xA0022A4000C01300, 0x0860001014420A03, 0x2004506280002814, 
    0x0081088655000005, 0x8122240261040001, 0x9001008051000645, 0x002213C800421040, 
    },
    {
    /* Population count = 12 */
    0x90082200004A8444, 0x1480204092840300, 0x8020C00342484800, 0x0001150420600704, 
    0x0490242089020050, 0x62000000C808021B, 0x8818002208000195, 0x000160B180420410, 
    0x6042000008010D51, 0x3300148008825000, 0x00006D0D08082800, 0x00408900104060C6, 
    0x2000282006740880, 0x450810D001060010, 0x8910000C10220C04, 0x00F248014000200A, 
    0x04440802D0102042, 0xE009842020004088, 0x0001746400851000, 0xA000840008083294, 
    0x0020012C08061520, 0x21A2004900000E10, 0x218045A014000003, 0x00C0020270040826, 
    0x30082908210000B0, 0x30400221884A4000, 0x9040281148108100, 0x40108A8300302100, 
    0x4128302121040010, 0x4000060704841110, 0x410D110040800904, 0x282000A411840024, 
    0x40010A2088100A88, 0x081021020402220B, 0x03080A0420282104, 0x00209508004208D0, 
    0x4608240209022200, 0x0090581208221004, 0x0456001424408010, 0x400001306122002C, 
    0xE00000D848088002, 0x2204210401206082, 0x9085224430000002, 0xA488000701400820, 
    0x0600410608084680, 0x242A240880020880, 0x1408100080430C88, 0x0014518501009008, 
    0x211028001C280006, 0x040020400300AA43, 0x0081A08883108400, 0x20401019C0050280, 
    0x3602004100434040, 0x8000506008401960, 0x3806080292001001, 0x080D810009224010, 
    0x012001408414010D, 0x20411000C0A03011, 0xA160008118484000, 0xA0102C6004101080, 
    0x9010202008832404, 0x00A0982C40200180, 0x84300C8000A40042, 0x010809080810E880, 
    }
};

void BitMangle(uint64_t n, uint8_t* expansion)
{
    uint8_t* exp = (uint8_t*)ExpBits;
    memset(expansion, 0, MANGLE_SIZE);
    while (n) {
        if (n & 1) {
            size_t j;
            for (j = 0; j < MANGLE_SIZE; ++j) {
                expansion[j] |= *exp++;
            }
        } else {
            exp++;
        }
        n >>= 1;
    }
}

void MangleIntersect(uint8_t* x, uint8_t* y)
{
    size_t i;
    for (i = 0; i < MANGLE_SIZE; ++i) {
        x[i] &= y[i];
    }
}

int MangleMatch(uint64_t n, uint8_t* m)
{
    size_t i;
    uint8_t t[MANGLE_SIZE];

    BitMangle(n, t);
    MangleIntersect(t, m);

    for (i = 0; i < MANGLE_SIZE; ++i) {
        if (t[i] != m[i]) {
            return 0;
        }
    }
    return 1;
}

static Node* Leaf(int n)
{
    static size_t leaf = 0;
    Node* node = malloc(sizeof(Node));
    memset(node, 0, sizeof(Node));
    node->_union = vectors[leaf++];
    while (n > 0) {
        node->_union |= vectors[leaf++];
        --n;
    }
    leafs[numLeafs++] = node->_union;
    BitMangle(node->_union, node->mangled);
    return node;
}

static Node* Tree(size_t count, ...)
{
    Node* node;
    va_list ap;
    va_start(ap, count);
    node = malloc(sizeof(Node) + count * sizeof(Node*));
    memset(node, 0, sizeof(Node) + count * sizeof(Node*));
    node->count = count;
    memset(node->mangled, 0xFF, sizeof(node->mangled));
    while (count--) {
        node->children[count] = va_arg(ap,  Node*);
        node->_union |= node->children[count]->_union;
        MangleIntersect(node->mangled, node->children[count]->mangled);
    }
    va_end(ap);
    return node;
}

static Node* BuildTree()
{
    Node* t;

    t = Tree(2,
            Tree(3,
                Tree(3, Leaf(2), Leaf(2), Leaf(1)),
                Tree(4, Leaf(1), Leaf(3), Leaf(1), Leaf(1)),
                Tree(2, Leaf(1), Leaf(1))
                ),
            Tree(3,
                Tree(3, Leaf(1), Leaf(4), Leaf(1)),
                Tree(4, Leaf(2), Leaf(1), Leaf(2), Leaf(1)),
                Tree(3, Leaf(4), Leaf(1), Leaf(3))
                )
            );

    return t;
}

static void InitVectors(int population)
{
    struct timespec t;
    size_t i;

    clock_gettime(CLOCK_MONOTONIC, &t);
    srandom(t.tv_nsec);
    memset(vectors, 0, sizeof(vectors));
    for (i = 0; i < 100; ++i) {
        size_t p;
        for (p = 0; p < population; ++p) {
            vectors[i] |= 1ull << ((uint32_t)random() % 64);
        }
    }
}

int Lookup(Node* tree, uint64_t n, int* cmps)
{
    size_t i;
    int found = 0;
    uint64_t u;

    u = n & tree->_union;
    if (!u) {
        return 0;
    }
    if (!MangleMatch(u, tree->mangled)) {
        //printf("Reject by mangler\n");
        return 0;
    }
    *cmps += 1;
    if ((u == n) && (tree->count == 0)) {
        return 1;
    }
    for (i = 0; i < tree->count; ++i) {
        found += Lookup(tree->children[i], u, cmps);
    }
    return found;
}

int main(int argc, char** argv)
{
    size_t i;
    int population = 4;
    Node* tree;
    char** arg = argv + 1;

    while (--argc) {
        char* p;
        if (strcmp(*arg, "-b") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            population = strtol(*arg++, &p, 10);
            if (*p) {
                goto Usage;
            }
            continue;
        }
        goto Usage;
    }
    InitVectors(population);
    tree = BuildTree();
    DumpTree(tree, 0);
    for (i = 0; i < numLeafs; ++i) {
        int cmps = 0;
        if (Lookup(tree, leafs[i], &cmps)) {
            printf("Found leaf %zu (compared %d)\n", i, cmps);
        } else {
            printf("Missing leaf %zu\n", i);
        }
    }
    return 0;

Usage:
    printf("Usage: %s [-b <bit population>]\n", *argv);
    return 1;
}
