#define BITCOIND_URL "http://127.0.0.1:8332"
#define HASH_LEN 256
#define STR_HASH_LEN (HASH_LEN / 4)

#define R(...) " "#__VA_ARGS__" "

#define ret_code(x) \
    ret = x; \
    goto cleanup;

#define err(str) fprintf(stderr, str);
#define error(str, ...) fprintf(stderr, str, __VA_ARGS__);

