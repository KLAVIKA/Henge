/* Metal libraries as macOS sends them, relabelled for an older iOS (devices/metallib.h).

   A metallib (as xcrun metallib writes it, file version 2.x) starts
     +0 "MTLB", +4 u16 platform (0x8001 macOS, 0x0001 iOS), +6 u16 file version major, +8 minor,
     +10 u8 library type, +11 u8 target OS (0x81 macOS, 0x82 iOS), +12 u16 OS version major, +14 minor,
     +16 u64 file size, +24 u64 function list offset, +32 its size, +40/+48 public metadata,
     +56/+64 private metadata, +72 u64 bitcode offset, +80 its size.
   The function list is a u32 count (not in the list size), then per function a u32 size (counted from that word) and tags
   {4-byte name, u16 length, data} up to ENDT: HASH (SHA-256 of the function's bitcode), MDSZ (its
   size), OFFT (u64 public, private and bitcode offsets, relative to the sections), VERS (u16 AIR
   major, minor, language major, minor). The same shader built for macOS 15 and iOS 17 differs in
   the header, VERS (AIR 2.7 and Metal 3.2 against 2.6 and 3.1), and the bitcode's target triple
   (air64_v27-apple-macosx15.0.0 against air64_v26-apple-ios17.0.0) and so its hash. */
#include "metallib.h"

#include <CommonCrypto/CommonDigest.h>
#include <string.h>

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | (uint64_t)rd32(p + 4) << 32; }
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v, p[1] = (uint8_t)(v >> 8); }


/* LLVM bitcode is a bitstream, not a byte string: MODULE_CODE_TRIPLE strings are
   VBR/Char6/Blob operands inside MODULE_BLOCK. Decode the bitstream and patch
   the character operands in place so their encoded lengths and block offsets
   remain unchanged. */
enum { BC_LITERAL, BC_FIXED, BC_VBR, BC_ARRAY, BC_CHAR6, BC_BLOB };
#define BC_MAX_OPS 32
#define BC_MAX_ABBREVS 128
#define BC_MAX_TRIPLE 256

typedef struct {
    unsigned kind, width;
    uint64_t literal;
} HvBCOp;

typedef struct {
    unsigned count;
    HvBCOp ops[BC_MAX_OPS];
} HvBCAbbrev;

typedef struct {
    uint8_t *bytes;
    size_t bit, limit;
    int bad;
} HvBCReader;

typedef struct {
    uint64_t value;
    size_t start, end;
    unsigned kind, width;
    int writable;
} HvBCValue;

static uint64_t bc_read_bits(HvBCReader *r, unsigned width) {
    if (width > 64 || r->bit > r->limit || width > r->limit - r->bit) {
        r->bad = 1;
        return 0;
    }
    uint64_t value = 0;
    for (unsigned i = 0; i < width; i++)
        value |= (uint64_t)((r->bytes[(r->bit + i) >> 3] >> ((r->bit + i) & 7)) & 1) << i;
    r->bit += width;
    return value;
}

static int bc_write_bits(uint8_t *bytes, size_t limit, size_t bit, unsigned width, uint64_t value) {
    if (width > 64 || bit > limit || width > limit - bit) return 0;
    for (unsigned i = 0; i < width; i++) {
        uint8_t mask = (uint8_t)(1u << ((bit + i) & 7));
        uint8_t *p = &bytes[(bit + i) >> 3];
        if ((value >> i) & 1) *p |= mask;
        else *p &= (uint8_t)~mask;
    }
    return 1;
}

static uint64_t bc_read_vbr(HvBCReader *r, unsigned width) {
    if (width < 2 || width > 32) { r->bad = 1; return 0; }
    unsigned payload = width - 1, shift = 0;
    uint64_t value = 0;
    for (unsigned groups = 0; groups < 13; groups++) {
        uint64_t part = bc_read_bits(r, width);
        if (r->bad) return 0;
        uint64_t piece = part & ((1ull << payload) - 1);
        if (shift >= 64 || (shift && piece > (UINT64_MAX >> shift))) {
            r->bad = 1;
            return 0;
        }
        value |= piece << shift;
        if (!(part & (1ull << payload))) return value;
        shift += payload;
    }
    r->bad = 1;
    return 0;
}

static void bc_align32(HvBCReader *r) {
    size_t next = (r->bit + 31u) & ~(size_t)31u;
    if (next > r->limit) r->bad = 1;
    else r->bit = next;
}

static int bc_read_abbrev(HvBCReader *r, HvBCAbbrev *a) {
    uint64_t n = bc_read_vbr(r, 5);
    if (r->bad || n == 0 || n > BC_MAX_OPS) return 0;
    memset(a, 0, sizeof(*a));
    a->count = (unsigned)n;
    for (unsigned i = 0; i < a->count; i++) {
        HvBCOp *op = &a->ops[i];
        if (bc_read_bits(r, 1)) {
            op->kind = BC_LITERAL;
            op->literal = bc_read_vbr(r, 8);
        } else {
            op->kind = (unsigned)bc_read_bits(r, 3);
            if (op->kind == BC_FIXED || op->kind == BC_VBR)
                op->width = (unsigned)bc_read_vbr(r, 5);
            if (op->kind < BC_FIXED || op->kind > BC_BLOB ||
                (op->kind == BC_FIXED && (!op->width || op->width > 32)) ||
                (op->kind == BC_VBR && (op->width < 2 || op->width > 32))) r->bad = 1;
        }
        if (r->bad) return 0;
    }
    return 1;
}

static int bc_char6(uint64_t v) {
    if (v < 26) return 'a' + (int)v;
    if (v < 52) return 'A' + (int)(v - 26);
    if (v < 62) return '0' + (int)(v - 52);
    if (v == 62) return '.';
    if (v == 63) return '_';
    return -1;
}

static int bc_char6_value(unsigned char c) {
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= 'A' && c <= 'Z') return c - 'A' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '.') return 62;
    if (c == '_') return 63;
    return -1;
}

static int bc_read_scalar(HvBCReader *r, const HvBCOp *op, HvBCValue *v) {
    memset(v, 0, sizeof(*v));
    v->kind = op->kind;
    v->width = op->width;
    v->writable = op->kind != BC_LITERAL;
    v->start = r->bit;
    if (op->kind == BC_LITERAL) v->value = op->literal;
    else if (op->kind == BC_FIXED) v->value = bc_read_bits(r, op->width);
    else if (op->kind == BC_VBR) v->value = bc_read_vbr(r, op->width);
    else if (op->kind == BC_CHAR6) {
        int c = bc_char6(bc_read_bits(r, 6));
        if (c < 0) r->bad = 1;
        else v->value = (uint64_t)c;
        v->width = 6;
    } else {
        r->bad = 1;
    }
    v->end = r->bit;
    return !r->bad;
}

static int bc_write_char(uint8_t *bytes, size_t limit, const HvBCValue *v, unsigned char c) {
    if (!v->writable) return 0;
    if (v->kind == BC_FIXED || v->kind == BC_BLOB) {
        unsigned width = v->kind == BC_BLOB ? 8 : v->width;
        if (width < 8 && c >= (1u << width)) return 0;
        return bc_write_bits(bytes, limit, v->start, width, c);
    }
    if (v->kind == BC_CHAR6) {
        int x = bc_char6_value(c);
        return x >= 0 && bc_write_bits(bytes, limit, v->start, 6, (uint64_t)x);
    }
    if (v->kind == BC_VBR) {
        unsigned width = v->width, payload = width - 1;
        size_t bits = v->end - v->start;
        if (!width || bits % width) return 0;
        size_t groups = bits / width;
        if (!groups || groups > 13 ||
            (groups * payload < 64 && ((uint64_t)c >> (groups * payload)))) return 0;
        uint64_t mask = (1ull << payload) - 1;
        for (size_t i = 0; i < groups; i++) {
            uint64_t part = ((uint64_t)c >> (i * payload)) & mask;
            if (i + 1 < groups) part |= 1ull << payload;
            if (!bc_write_bits(bytes, limit, v->start + i * width, width, part)) return 0;
        }
        return 1;
    }
    return 0;
}

static int bc_apply_triple(uint8_t *bytes, size_t limit, HvBCValue *values, size_t count,
                           char *sample_before, size_t sample_before_size,
                           char *sample_after, size_t sample_after_size) {
    if (!count || count > BC_MAX_TRIPLE) return 0;
    char text[BC_MAX_TRIPLE];
    for (size_t i = 0; i < count; i++) {
        if (values[i].value > 127) return 0;
        text[i] = (char)values[i].value;
    }
    size_t text_len = count;
    while (text_len && text[text_len - 1] == 0) text_len--;
    int changed = 0;
    static const char key[] = "-apple-macosx";
    for (size_t i = 9; i + sizeof(key) - 1 <= text_len; i++) {
        if (memcmp(text + i, key, sizeof(key) - 1) != 0) continue;
        if (memcmp(text + i - 9, "air64_v", 7) != 0 ||
            text[i - 2] < '0' || text[i - 2] > '9' ||
            text[i - 1] < '0' || text[i - 1] > '9') continue;
        size_t suffix = i + 7;
        size_t suffix_len = text_len - suffix;
        if (suffix_len < 12 || suffix_len >= 64) continue;
        char out[64];
        size_t rest = suffix_len - 6;
        memcpy(out, "ios17.", 6);
        memset(out + 6, '0', rest);
        out[6 + rest / 2] = '.';
        int can_write = values[i - 2].writable && values[i - 1].writable;
        for (size_t j = 0; j < suffix_len; j++) {
            const HvBCValue *v = &values[suffix + j];
            unsigned char ch = (unsigned char)out[j];
            if (!v->writable ||
                (v->kind == BC_CHAR6 && bc_char6_value(ch) < 0) ||
                (v->kind == BC_FIXED && v->width < 8 && ch >= (1u << v->width)))
                can_write = 0;
        }
        if (!can_write) continue;
        if (sample_before && sample_before_size && !sample_before[0]) {
            size_t n = text_len - (i - 9);
            if (n >= sample_before_size) n = sample_before_size - 1;
            memcpy(sample_before, text + i - 9, n);
            sample_before[n] = 0;
        }
        if (!bc_write_char(bytes, limit, &values[i - 2], '2') ||
            !bc_write_char(bytes, limit, &values[i - 1], '6')) continue;
        for (size_t j = 0; j < suffix_len; j++) {
            if (!bc_write_char(bytes, limit, &values[suffix + j], (unsigned char)out[j]))
                return changed;
            text[suffix + j] = out[j];
        }
        text[i - 2] = '2', text[i - 1] = '6';
        if (sample_after && sample_after_size && !sample_after[0]) {
            size_t n = text_len - (i - 9);
            if (n >= sample_after_size) n = sample_after_size - 1;
            memcpy(sample_after, text + i - 9, n);
            sample_after[n] = 0;
        }
        changed++;
    }
    return changed;
}

static int bc_read_unabbrev_record(HvBCReader *r, uint8_t *bytes,
                                   char *sample_before, size_t sample_before_size,
                                   char *sample_after, size_t sample_after_size) {
    uint64_t code = bc_read_vbr(r, 6), count = bc_read_vbr(r, 6);
    if (r->bad || count > 1000000) return -1;
    HvBCValue values[BC_MAX_TRIPLE];
    size_t kept = 0;
    for (uint64_t i = 0; i < count; i++) {
        HvBCValue v;
        memset(&v, 0, sizeof(v));
        v.kind = BC_VBR, v.width = 6, v.writable = 1, v.start = r->bit;
        v.value = bc_read_vbr(r, 6);
        v.end = r->bit;
        if (code == 2 && kept < BC_MAX_TRIPLE) values[kept++] = v;
        if (r->bad) return -1;
    }
    return code == 2 && count == kept
        ? bc_apply_triple(bytes, r->limit, values, kept, sample_before, sample_before_size, sample_after, sample_after_size)
        : 0;
}

static int bc_read_abbrev_record(HvBCReader *r, const HvBCAbbrev *a, uint8_t *bytes,
                                 char *sample_before, size_t sample_before_size,
                                 char *sample_after, size_t sample_after_size) {
    if (!a->count) return -1;
    HvBCValue first;
    if (!bc_read_scalar(r, &a->ops[0], &first)) return -1;
    int is_triple = first.value == 2;
    HvBCValue values[BC_MAX_TRIPLE];
    size_t kept = 0;
    int overflow = 0;
    for (unsigned i = 1; i < a->count; i++) {
        const HvBCOp *op = &a->ops[i];
        if (op->kind == BC_ARRAY) {
            if (++i >= a->count) return -1;
            const HvBCOp *element = &a->ops[i];
            uint64_t n = bc_read_vbr(r, 6);
            if (r->bad || element->kind == BC_ARRAY || element->kind == BC_BLOB) return -1;
            for (uint64_t j = 0; j < n; j++) {
                HvBCValue v;
                if (!bc_read_scalar(r, element, &v)) return -1;
                if (is_triple) {
                    if (kept < BC_MAX_TRIPLE) values[kept++] = v;
                    else overflow = 1;
                }
            }
            if (i + 1 != a->count) return -1;
            break;
        } else if (op->kind == BC_BLOB) {
            uint64_t n = bc_read_vbr(r, 6);
            if (r->bad || n > 1000000) return -1;
            bc_align32(r);
            for (uint64_t j = 0; j < n; j++) {
                HvBCValue v;
                memset(&v, 0, sizeof(v));
                v.kind = BC_BLOB, v.width = 8, v.writable = 1, v.start = r->bit;
                v.value = bc_read_bits(r, 8);
                v.end = r->bit;
                if (is_triple) {
                    if (kept < BC_MAX_TRIPLE) values[kept++] = v;
                    else overflow = 1;
                }
                if (r->bad) return -1;
            }
            bc_align32(r);
            if (r->bad || i + 1 != a->count) return -1;
            break;
        } else {
            HvBCValue v;
            if (!bc_read_scalar(r, op, &v)) return -1;
            if (is_triple) {
                if (kept < BC_MAX_TRIPLE) values[kept++] = v;
                else overflow = 1;
            }
        }
    }
    return is_triple && !overflow ? bc_apply_triple(bytes, r->limit, values, kept,
                                       sample_before, sample_before_size, sample_after, sample_after_size) : 0;
}

static int bc_skip_subblock(HvBCReader *r, size_t *body, size_t *end, unsigned *width) {
    (void)bc_read_vbr(r, 8); /* block id */
    *width = (unsigned)bc_read_vbr(r, 4);
    bc_align32(r);
    uint64_t words = bc_read_bits(r, 32);
    if (r->bad || *width < 2 || *width > 32 || words > (r->limit - r->bit) / 32) return 0;
    *body = r->bit;
    *end = r->bit + (size_t)words * 32;
    return 1;
}

static int bc_parse_blockinfo(HvBCReader *r, size_t end, unsigned width,
                              HvBCAbbrev *module_abbrevs, size_t *module_count) {
    int target = -1;
    while (!r->bad && r->bit + width <= end) {
        uint64_t id = bc_read_bits(r, width);
        if (id == 0) { bc_align32(r); break; }
        if (id == 1) {
            size_t body, subend;
            unsigned subwidth;
            if (!bc_skip_subblock(r, &body, &subend, &subwidth)) return 0;
            r->bit = subend;
        } else if (id == 2) {
            HvBCAbbrev a;
            if (!bc_read_abbrev(r, &a)) return 0;
            if (target == 8) {
                if (*module_count >= BC_MAX_ABBREVS) return 0;
                module_abbrevs[(*module_count)++] = a;
            }
        } else if (id == 3) {
            uint64_t code = bc_read_vbr(r, 6), n = bc_read_vbr(r, 6), first = 0;
            if (r->bad || n > 1000000) return 0;
            for (uint64_t i = 0; i < n; i++) {
                uint64_t v = bc_read_vbr(r, 6);
                if (i == 0) first = v;
            }
            if (code == 1 && n) target = (int)first; /* SETBID */
        } else {
            return 0;
        }
    }
    if (r->bad || r->bit > end) return 0;
    r->bit = end;
    return 1;
}

static int bc_parse_module(HvBCReader *r, size_t end, unsigned width,
                           const HvBCAbbrev *inherited, size_t inherited_count,
                           uint8_t *bytes, char *sample_before, size_t sample_before_size,
                           char *sample_after, size_t sample_after_size) {
    HvBCAbbrev abbrevs[BC_MAX_ABBREVS];
    size_t abbrev_count = inherited_count;
    if (abbrev_count > BC_MAX_ABBREVS) return -1;
    memcpy(abbrevs, inherited, abbrev_count * sizeof(*abbrevs));
    int changed = 0;
    while (!r->bad && r->bit + width <= end) {
        uint64_t id = bc_read_bits(r, width);
        if (id == 0) { bc_align32(r); break; }
        if (id == 1) {
            size_t body, subend;
            unsigned subwidth;
            if (!bc_skip_subblock(r, &body, &subend, &subwidth)) return -1;
            r->bit = subend;
        } else if (id == 2) {
            HvBCAbbrev a;
            if (!bc_read_abbrev(r, &a) || abbrev_count >= BC_MAX_ABBREVS) return -1;
            abbrevs[abbrev_count++] = a;
        } else if (id == 3) {
            int c = bc_read_unabbrev_record(r, bytes, sample_before, sample_before_size, sample_after, sample_after_size);
            if (c < 0) return -1;
            changed += c;
        } else {
            size_t index = (size_t)id - 4;
            if (index >= abbrev_count) return -1;
            int c = bc_read_abbrev_record(r, &abbrevs[index], bytes,
                                          sample_before, sample_before_size, sample_after, sample_after_size);
            if (c < 0) return -1;
            changed += c;
        }
        if (r->bit > end) return -1;
    }
    if (r->bad || r->bit > end) return -1;
    return changed;
}

static int relabel_triple(uint8_t *p, size_t n, char *sample_before, size_t sample_before_size,
                          char *sample_after, size_t sample_after_size) {
    /* LLVM bitcode magic. Also accept the standard 20-byte bitcode wrapper. */
    if (n >= 20 && rd32(p) == 0x0b17c0de) {
        uint32_t off = rd32(p + 8), size = rd32(p + 12);
        if (off > n || size > n - off) return -2;
        p += off, n = size;
    }
    if (n < 4 || p[0] != 'B' || p[1] != 'C' || p[2] != 0xc0 || p[3] != 0xde) return -1;
    HvBCReader r = {p, 32, n * 8, 0};
    HvBCAbbrev module_abbrevs[BC_MAX_ABBREVS];
    size_t module_count = 0, module_body = 0, module_end = 0;
    unsigned module_width = 0;
    while (!r.bad && r.bit + 2 <= r.limit) {
        uint64_t id = bc_read_bits(&r, 2);
        if (id == 0) break;
        if (id == 1) {
            uint64_t block_id = bc_read_vbr(&r, 8);
            unsigned width = (unsigned)bc_read_vbr(&r, 4);
            bc_align32(&r);
            uint64_t words = bc_read_bits(&r, 32);
            if (r.bad || width < 2 || width > 32 || words > (r.limit - r.bit) / 32) return -2;
            size_t body = r.bit, end = r.bit + (size_t)words * 32;
            if (block_id == 0) {
                if (!bc_parse_blockinfo(&r, end, width, module_abbrevs, &module_count)) return -2;
            } else if (block_id == 8) {
                module_body = body, module_end = end, module_width = width;
            }
            r.bit = end;
        } else if (id == 2) {
            HvBCAbbrev ignored;
            if (!bc_read_abbrev(&r, &ignored)) return -2;
        } else {
            (void)bc_read_vbr(&r, 6);
            uint64_t count = bc_read_vbr(&r, 6);
            if (r.bad || count > 1000000) return -2;
            for (uint64_t i = 0; i < count; i++) (void)bc_read_vbr(&r, 6);
        }
    }
    if (r.bad || !module_end || module_end > r.limit || module_body > module_end) return -2;
    r.bit = module_body, r.limit = module_end, r.bad = 0;
    return bc_parse_module(&r, module_end, module_width, module_abbrevs, module_count,
                           p, sample_before, sample_before_size, sample_after, sample_after_size);
}

int hv_metallib_relabel(uint8_t *buf, size_t len, int stage, int *triple_changes, char *sample_before, size_t sample_before_size, char *sample_after, size_t sample_after_size) {
    if (triple_changes) *triple_changes = 0;
    if (sample_before && sample_before_size) sample_before[0] = 0;
    if (sample_after && sample_after_size) sample_after[0] = 0;
    if (len < 88 || memcmp(buf, "MTLB", 4) != 0 || rd16(buf + 6) != 2) return -1;
    if (rd64(buf + 16) > len) return -1;
    int changed = 0, triples = 0, triple_status = 0;
    if (rd16(buf + 4) & 0x8000) wr16(buf + 4, rd16(buf + 4) & 0x7fff), changed++;
    if (rd16(buf + 8) > 7) wr16(buf + 8, 7), changed++;
    if (buf[11] == 0x81) buf[11] = 0x82, changed++;
    if (rd16(buf + 12) > 17) wr16(buf + 12, 17), wr16(buf + 14, 0), changed++;
    uint64_t fl = rd64(buf + 24), fls = rd64(buf + 32), bc = rd64(buf + 72), bcs = rd64(buf + 80);
    if (fl > len || fls > len - fl - 4 || bc > len || bcs > len - bc) return changed;
    const uint8_t *end = buf + fl + 4 + fls; /* the size counts the entries after the count */
    uint32_t count = rd32(buf + fl);
    uint8_t *f = buf + fl + 4;
    for (uint32_t k = 0; k < count && f + 4 <= end; k++) {
        uint32_t size = rd32(f);
        if (size < 4 || size > (size_t)(end - f)) break;
        uint8_t *hash = NULL, *t = f + 4, *fend = f + size;
        uint64_t mdsz = 0, bc_off = ~0ull;
        while (t + 6 <= fend && memcmp(t, "ENDT", 4) != 0) {
            uint16_t n = rd16(t + 4);
            uint8_t *d = t + 6;
            if (d + n > fend) break;
            if (!memcmp(t, "VERS", 4) && n >= 8) {
                if (rd16(d) == 2 && rd16(d + 2) > 6) wr16(d + 2, 6), changed++;           /* AIR 2.7 and up: 2.6 */
                if (rd16(d + 4) == 3 && rd16(d + 6) > 1) wr16(d + 6, 1), changed++;       /* Metal 3.2 and up: 3.1 */
            } else if (!memcmp(t, "HASH", 4) && n == 32) {
                hash = d;
            } else if (!memcmp(t, "MDSZ", 4) && n == 8) {
                mdsz = rd64(d);
            } else if (!memcmp(t, "OFFT", 4) && n == 24) {
                bc_off = rd64(d + 16);
            }
            t = d + n;
        }
        if (stage >= 2 && hash && bc_off != ~0ull && bc_off <= bcs && mdsz <= bcs - bc_off) {
            uint8_t *code = buf + bc + bc_off;
            int c = relabel_triple(code, (size_t)mdsz, sample_before, sample_before_size, sample_after, sample_after_size);
            if (c > 0) {
                CC_SHA256(code, (CC_LONG)mdsz, hash);
                changed += c;
                triples += c;
            } else if (c < 0 && !triple_status) {
                triple_status = c; /* -1: no LLVM bitcode magic; -2: unsupported or malformed bitstream */
            }
        }
        f += size;
    }
    if (triple_changes) *triple_changes = triples ? triples : triple_status;
    return changed;
}
