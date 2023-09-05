#ifndef MINER_H
#define MINER_H

#define REG_TEST

#ifdef REG_TEST
#define BITCOIND_URL "http://127.0.0.1:18443"
#else
#define BITCOIND_URL "http://127.0.0.1:8333"
#endif

#define HASH_LEN 256
#define STR_HASH_LEN (HASH_LEN / 8)

#define R(...) " " #__VA_ARGS__ " "

#define ARR_LEN(x) (sizeof(x) / sizeof(*(x)))
#define align(x, al) (size_t)((((x) / (al)) * (al)) + (((x) % (al)) ? (al) : 0))
#define align_down(x, al) (size_t) (((x) / (al)) * (al)) 

#define BLOCK_RAW_LEN 80

#define ret_code(x)                                                            \
  {                                                                            \
    ret = x;                                                                   \
    goto cleanup;                                                              \
  }

#define ret_label(label, x)                                              \
  {                                                                            \
    ret = x;                                                                   \
    goto label;                                                              \
  }

#define err(str) fprintf(stderr, str);
#define error(str, ...) fprintf(stderr, str, __VA_ARGS__);

#include <stdint.h>

struct block_header {
    int32_t version;
    char prev_hash[32];
    char merkle_root_hash[32];
    uint32_t time;
    uint32_t target;
    uint32_t nonce;
};

typedef union hash {
    uint8_t byte_hash[32];
    uint32_t uint_hash[8];
} hash_t;


void block_pack(const struct block_header *block, uint8_t raw[BLOCK_RAW_LEN]);

void nbits_to_target(uint32_t nbits, hash_t *target);

#endif
