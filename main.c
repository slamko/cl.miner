#include "miner.h"
#include <curl/curl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "ocl.h"

struct best_block_hash {
    char hash[STR_HASH_LEN];
};

struct transaction {
    hash_t txid;
    hash_t hash;
};

typedef struct transaction_list {
    struct transaction *tlist;
    size_t len;
} transaction_list_t;

void build_merkle_root(struct transaction *tlist, size_t len, hash_t *merkle_root) {
    struct transaction *merkle_tree = malloc(len * sizeof *merkle_tree);
    memcpy(merkle_tree, tlist, len * sizeof *merkle_tree);
    
    size_t mod = 2;
    for (size_t i = 0; i < len; i += mod) {
        uint8_t concat_hash[64];
        memcpy(concat_hash, merkle_tree[i].txid.byte_hash, sizeof(merkle_tree[i].txid.byte_hash));
        memcpy(concat_hash + sizeof (concat_hash) / 2, merkle_tree[i + 1].txid.byte_hash, sizeof(merkle_tree[i + 1].txid.byte_hash));

        double_sha256(concat_hash, merkle_tree[i].txid.byte_hash, sizeof concat_hash);
        
        mod *= 2;
    }

    memcpy(merkle_root, &merkle_tree[0].txid, sizeof *merkle_root);
    free(merkle_tree);
}

int build_transaction_list(json_t *t_arr, transaction_list_t *tlist) {
    int ret = 0;
    size_t t_len = json_array_size(t_arr);
    if (!t_len) {
        err("Invalid transaction list\n");
        return 1;
    }
    
    tlist->tlist = calloc(t_len, sizeof *tlist->tlist);
    tlist->len = t_len;

    for (size_t i = 0; i < t_len; i++) {
        json_t *transaction = json_array_get(t_arr, i);
        struct transaction *cur_t = &tlist->tlist[i];

        char *txid = NULL, *hash = NULL;
        if ((ret = json_unpack(transaction, "{s:s, s:s}", "txid", &txid, "hash", &hash))) {
            err("Invalid transaction in a list\n");
            ret_code(ret);
        }

        if (!txid || !hash) {
            err("No transaction hash\n");
            ret_code(1);
        }

        if (strlen(txid) != 2 * STR_HASH_LEN || strlen(hash) != 2 * STR_HASH_LEN) {
            err("Invalid transaction hash\n");
            ret_code(1);
        }

        memcpy(&cur_t->txid.byte_hash, txid, sizeof cur_t->txid.byte_hash);
        memcpy(&cur_t->hash.byte_hash, hash, sizeof cur_t->hash.byte_hash);

  cleanup:
        free(txid);
        free(hash);

        break;
    }

    if (ret) {
        free(tlist);
        err("Aborting transaction list creation\n");
        return ret;
    }

    return ret;
}

void block_pack(const struct block_header *block, uint8_t raw[BLOCK_RAW_LEN]) {
    memcpy(raw, &block->version, sizeof block->version);
    memcpy(raw + 4, &block->prev_hash, sizeof block->prev_hash);
    memcpy(raw + 36, &block->merkle_root_hash, sizeof block->merkle_root_hash);
    memcpy(raw + 68, &block->target, sizeof block->target);
    memcpy(raw + 72, &block->time, sizeof block->time);
    memcpy(raw + 76, &block->nonce, sizeof block->nonce);
}

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *dest) {
    char **dest_ptr = dest;
    *dest_ptr = malloc(size * nmemb + 1);
    strcpy(*dest_ptr, ptr);
    
    return nmemb;
}

CURLcode json_rpc(CURL *curl, const char *post_data, char **dest_str) {
    struct curl_slist *headers = {0};
    char errbuf[CURL_ERROR_SIZE] = {0};

    headers = curl_slist_append(NULL, "context-type: text/plain;");

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, BITCOIND_URL);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(post_data));
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, dest_str);

    curl_easy_setopt(curl, CURLOPT_USERPWD, "slamko:VenezuellaMiner00");
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);
    
    CURLcode ret = curl_easy_perform(curl);
    if (ret) {
        error("Curl error: %s\n", errbuf);
    }
    
    curl_slist_free_all(headers);
    return ret;
}

const char *blocktemplate_post_data = R(
    {"jsonrpc": 2.0,
     "id": "cumainer",
     "method": "getblocktemplate",
     "params": [{"rules": ["segwit"]}]
    }
    );

const char *bestblock_post_data = R(
    {"jsonrpc": 2.0,
     "id": "cumainer",
     "method": "getbestblockhash",
     "params": [] 
    }
    );

CURLcode get_json(CURL *curl, const char *post, json_t **json) {
    char *json_str = NULL;
    CURLcode ret;
    json_error_t err = {0};
   
    ret = json_rpc(curl, post, &json_str);
    if (ret) {
        error("RPC error: %d\n", ret);
        ret_code(ret);
    }

    puts(json_str);
    *json = json_loads(json_str, JSON_ALLOW_NUL | JSON_DECODE_ANY, &err);

    if (!json) {
        err("RPC Method failed\n");
        ret_code(1);
    }

  cleanup:
    free(json_str);
    return ret;
}

CURLcode get_block_template(CURL *curl, struct block_header *template) {
    CURLcode ret = 1;
    json_t *json = NULL;
    json_t *result = NULL;
    char *nbits = NULL;
    json_t *transactions = NULL;

    if (get_json(curl, blocktemplate_post_data, &json)) {
        err("Json rpc failed\n");
        ret_code(1);
    }

    if ((ret = json_unpack(json, "{s:O}",
                           "result",
                           &result))) {
        err("Unknown bitcoind response format\n");
        ret_code(ret);
    }
    
    if ((ret = json_unpack(result,
                           "{s:i, s:s, s:o, s:i, s:s}",
                           "version", &template->version,
                           "previousblockhash", &template->prev_hash,
                           "transactions", &transactions,
                           "curtime", &template->time,
                           "bits", &nbits))) {

        err("Unknown bitcoind response format\n");
        ret_code(ret);
    }

    if (!transactions || !nbits) {
        err("Json decoding failed\n");
        ret_code(1);
    }

    template->target = strtoul(nbits, NULL, 16);
    printf("Nbits: %x\n", template->target);

    transaction_list_t tlist = {0};
    hash_t merkle_root = {0};

    ret = build_transaction_list(transactions, &tlist);
    if (ret) {
        err("Aborting merkle root hash calculation\n");
        ret_code(ret);
    }
    
    build_merkle_root(tlist.tlist, tlist.len, &merkle_root);

    memcpy(template->merkle_root_hash, merkle_root.byte_hash, sizeof template->merkle_root_hash);

  cleanup:
    if (json) {
        json_decref(json);
    }

    if (result) {
        json_decref(result);
    }

    return ret;
}

CURLcode get_best_block_hash(CURL *curl, struct best_block_hash *res) {
    CURLcode ret = 1;
    char *json_str = NULL;
    json_error_t err = {0};
   
    ret = json_rpc(curl, bestblock_post_data, &json_str);

    json_t *best_block_json = json_loads(json_str, JSON_ALLOW_NUL | JSON_DECODE_ANY, &err);

    if (!best_block_json) {
        err("RPC Method failed\n");
        ret_code(1);
    }

    char *result;
    if (json_unpack(best_block_json, "{s:s}", "result", &result)) {
        err("get_best_block: Unknown bitcoind response format\n");
        ret_code(1);
    }

    if (!result) {
        err("Json decoding failed\n");
        ret_code(1);
    }

    size_t res_len = strlen(result);

    if (res_len != sizeof(res->hash)) {
        error("Unmatched hash length %zu\n", res_len);
        ret_code(1);
    }

    strcpy(res->hash, result);
    
  cleanup:
    if (json_str)
        free(json_str);
    if (best_block_json) {
        json_decref(best_block_json);
    }
    return ret;
}

void test() {
    int ret;
    
    const char inp[] = "hello just testing this shit not something particullary interesting really";
    uint8_t out[STR_HASH_LEN] = {0};
    ret = sha256((uint8_t *)inp, out, sizeof(inp) - 1);

    if (ret) {
        error("Kernel failed: %d\n", ret);
    }

    uint8_t out_double[STR_HASH_LEN] = {0};
    ret = sha256(out, out_double, sizeof(out));

    if (ret) {
        error("Kernel failed: %d\n", ret);
    }
}

void hash_print(const char *name, hash_t *hash) {
    printf("\n%s\n", name);
    for (size_t i = 0; i < ARR_LEN(hash->uint_hash); i++) {
        printf("%08x", hash->uint_hash[7 - i]);
    }
    putc('\n', stdout);
    fflush(stdout);
}

void nbits_to_target(uint32_t nbits, hash_t *target) {
    uint32_t big_nbits = nbits;
    uint8_t exp = big_nbits >> 24;
    uint32_t mantissa = big_nbits & 0x00FFFFFF;

    memset(target->uint_hash, 0, sizeof target->uint_hash);
    
    size_t id = exp / sizeof(*target->uint_hash);

    switch (exp % sizeof(*target->uint_hash)) {
    case 0: {
        if (id) {
            target->uint_hash[id - 1] = mantissa << 8;
            printf("BIg: %x\n", mantissa);
        }
        break;
    }
    case 1: {
        target->uint_hash[id] = mantissa >> 16;

        if (id) {
            target->uint_hash[id - 1] = mantissa << 16;
        }
        break;
    }
    case 2: {
        target->uint_hash[id] = mantissa >> 8;

        if (id) {
            target->uint_hash[id - 1] = mantissa << 24;
        }
        break;
    }
    case 3: {
        target->uint_hash[id] = mantissa;
        break;
    }
    }
}

int main(void) {
    CURL *curl = curl_easy_init();

    if (!curl) {
        return 1;
    }

    int ret = ocl_init();
    if (ret) {
        error("OpenCL initialization failed: %d\n", ret);
    }
    
    struct block_header block;

    block.nonce = 0x1;
    block.version = 0x11;
    block.target = 0xabc1256;

    memset(block.merkle_root_hash, 0x4f, sizeof block.merkle_root_hash);
    memset(block.prev_hash, 0xb1, sizeof block.merkle_root_hash);

    uint8_t raw[80];
    block_pack(&block, raw);

    /* uint8_t out[STR_HASH_LEN] = {0}; */
    /* ret = sha256(raw, out, sizeof raw); */

    if (ret) {
        printf("Error occured: %d\n", ret);
        exit(ret);
    }
    struct block_header header;
    get_block_template(curl, &header);

    hash_t target = {0};
    nbits_to_target(header.target, &target);
    hash_print("Target: ", &target);
   
    curl_easy_cleanup(curl);
    ocl_free();
}
