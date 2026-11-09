#include "devices/metallib.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}
static void put32(uint8_t *p, uint32_t v) {
    for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (i * 8));
}
static void put64(uint8_t *p, uint64_t v) {
    put32(p, (uint32_t)v);
    put32(p + 4, (uint32_t)(v >> 32));
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s AIR-bitcode\n", argv[0]);
        return 2;
    }
    FILE *file = fopen(argv[1], "rb");
    if (!file) { perror(argv[1]); return 2; }
    if (fseek(file, 0, SEEK_END) || ftell(file) < 0) return 2;
    size_t bitcode_size = (size_t)ftell(file);
    rewind(file);
    if (!bitcode_size || bitcode_size > UINT32_MAX) return 2;

    /* One synthetic MTLB function with HASH, MDSZ, OFFT, VERS and ENDT. */
    const size_t header = 88, entry_size = 104, bitcode_at = header + 4 + entry_size;
    size_t total = bitcode_at + bitcode_size;
    uint8_t *lib = calloc(1, total);
    if (!lib) return 2;
    if (fread(lib + bitcode_at, 1, bitcode_size, file) != bitcode_size) return 2;
    fclose(file);

    memcpy(lib, "MTLB", 4);
    put16(lib + 4, 0x8001); /* macOS */
    put16(lib + 6, 2);
    put16(lib + 8, 8);
    lib[11] = 0x81;
    put16(lib + 12, 15);
    put64(lib + 16, total);
    put64(lib + 24, header);
    put64(lib + 32, entry_size);
    put64(lib + 72, bitcode_at);
    put64(lib + 80, bitcode_size);

    uint8_t *f = lib + header;
    put32(f, 1); /* one function */
    f += 4;
    put32(f, entry_size);
    f += 4;
    memcpy(f, "HASH", 4); put16(f + 4, 32); f += 38;
    memcpy(f, "MDSZ", 4); put16(f + 4, 8); put64(f + 6, bitcode_size); f += 14;
    memcpy(f, "OFFT", 4); put16(f + 4, 24); put64(f + 22, 0); f += 30;
    memcpy(f, "VERS", 4); put16(f + 4, 8);
    put16(f + 6, 2); put16(f + 8, 7); put16(f + 10, 3); put16(f + 12, 2); f += 14;
    memcpy(f, "ENDT", 4);

    int triple_changes = 0;
    char before[96] = {0}, after[96] = {0};
    int fields = hv_metallib_relabel(lib, total, 2, &triple_changes,
                                     before, sizeof(before), after, sizeof(after));
    const char *expected_before = "air64_v27-apple-macosx15.0.0";
    const char *expected_after = "air64_v26-apple-ios17.000.000";
    if (fields < 0 || triple_changes != 1 ||
        strcmp(before, expected_before) || strcmp(after, expected_after)) {
        fprintf(stderr, "FAIL fields=%d triple_changes=%d before=[%s] after=[%s]\n",
                fields, triple_changes, before, after);
        free(lib);
        return 1;
    }
    printf("PASS fields=%d triple_changes=%d [%s] -> [%s]\n",
           fields, triple_changes, before, after);
    free(lib);
    return 0;
}
