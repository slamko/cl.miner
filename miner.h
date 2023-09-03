#ifndef MINER_H
#define MINER_H

#define BITCOIND_URL "http://127.0.0.1:8332"
#define HASH_LEN 256
#define STR_HASH_LEN (HASH_LEN / 8)

#define R(...) " " #__VA_ARGS__ " "

#define ARR_LEN(x) (sizeof(x) / sizeof(*(x)))
#define align(x, al) (((x) / (al)) + ((x) % (al) ? (al) : 0))

#define BLOCK_RAW_LEN 80

#define ret_code(x)                                                            \
  {                                                                            \
    ret = x;                                                                   \
    goto cleanup;                                                              \
  }

#define err(str) fprintf(stderr, str);
#define error(str, ...) fprintf(stderr, str, __VA_ARGS__);

#endif
