#include "miner.h"
#include <curl/curl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "ocl.h"

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

const char *submitblock_template = R(
    {"jsonrpc": 2.0,
     "id": "cumainer",
     "method": "submitblock",
     "params": ["%s%02x%s"]
    }
    );


struct best_block_hash {
    char hash[STR_HASH_LEN];
};

static inline char hex_to_char(uint8_t h) {
    if (h < 10) {
        return h + 48;
    } 
    return 97 + (h % 10);
}

static inline uint8_t char_to_hex(char c) {
    if (c >= 97) {
        return ((c - 97) + 10) & 0x0F;
    } 
    return (c - 48) & 0x0F;
}

void hex_to_string(const uint8_t *hash, char *str, size_t len) {
    for_range(i, 0, len) {
        uint8_t h = hash[i] >> 4;
        uint8_t l = hash[i] & 0x0F;

        str[i * 2] = hex_to_char(h);
        str[(i * 2) + 1] = hex_to_char(l);
    }
}

void string_to_hex(const char *str, uint8_t *hash, size_t len) {
    for_range(i, 0, len / 2) {
        hash[i] = (char_to_hex(str[i * 2]) << 4) | char_to_hex (str[(i * 2) + 1]); 
    }
}

void build_merkle_root(transaction_list_t *tlist, size_t len, hash_t *merkle_root) {
    hash_t *merkle_tree = cmalloc(len * sizeof *merkle_tree);
    memcpy(merkle_tree, tlist->txid_list, len * sizeof *merkle_tree);
    
    size_t mod = 2;
    for (size_t i = 0; i < len; i += mod) {
        uint8_t concat_hash[64];
        hash_t *hasha = &merkle_tree[i];
        hash_t *hashb = hasha;

        if (i + 1 < len) {
            hashb = &merkle_tree[i + 1];
        }
        
        memcpy(concat_hash, hasha->byte_hash, sizeof(hasha->byte_hash));
        memcpy(concat_hash + sizeof (concat_hash) / 2, hashb->byte_hash, sizeof(hashb->byte_hash));

        double_sha256(concat_hash, merkle_tree[i].byte_hash, sizeof concat_hash);
        
        mod *= 2;
    }

    memcpy(merkle_root, &merkle_tree[0], sizeof *merkle_root);
    free(merkle_tree);
}

struct tx_in {
    uint32_t *hash;
    
} __attribute__((packed));

union compact_size {
    uint32_t val32;
    uint16_t val16;
    uint8_t val8;
};

struct raw_transaction {
    int32_t version;
    union compact_size tx_in_cnt;
    struct tx_in *tx_ins;
    union compact_size tx_out_cnt;
    struct tx_out *tx_outs;
    uint32_t lock_time;

} __attribute__ ((packed));

void write_coinbase(uint32_t time, uint8_t *buf) {
    size_t coinbase_size = 64;
    
    memset(buf, 0, coinbase_size);

    buf[0] = 0x1;
    buf[4] = 0x1;
    memset(buf + 37, 0xFF, 4);
    buf[45] = 0x01;
    buf[49] = 0x00;
    buf[53] = 0x0;
    memcpy(buf + 57, &time, sizeof time);
}

int build_transaction_list(json_t *t_arr, transaction_list_t *tlist) {
    int ret = 0;
    size_t t_len = json_array_size(t_arr);
    size_t tdata_size = 0;
    size_t cur_data_off = 0;

    if (!t_len) {
        uint8_t coinbase_data[64] = {0};
        tlist->txid_list = ccalloc(1, sizeof (*tlist->txid_list));

        tlist->raw_data = ccalloc(sizeof coinbase_data * 2 + 1, sizeof (*tlist->raw_data));
        write_coinbase(time(NULL), coinbase_data);
        hex_to_string(coinbase_data, tlist->raw_data, sizeof coinbase_data);
        printf("Row data: %s\n", tlist->raw_data);

        double_sha256(coinbase_data, tlist->txid_list->byte_hash, sizeof coinbase_data);
        tlist->len = 1;
        tlist->data_size = strlen(tlist->raw_data);

        err("Empty transaction list\n");
        return 0;
    }
    
    tlist->txid_list = ccalloc(t_len, sizeof(*tlist->txid_list));
    tlist->len = t_len;

    for (size_t i = 0; i < t_len; i++) {
        json_t *transaction = json_array_get(t_arr, i);
        hash_t *cur_hash = &tlist->txid_list[i + 1];
        char *data;

        char *txid = NULL, *hash = NULL;
        if ((ret = json_unpack(transaction, "{s:s, s:s, s:s}",
                               "data", &data,
                               "txid", &txid,
                               "hash", &hash))) {

            err("Invalid transaction in a list\n");
            ret_code(ret);
        }

        if (!data) {
            err("No transaction data\n");
            ret_code(1);
        }

        if (!txid || !hash) {
            err("No transaction hash\n");
            ret_code(1);
        }

        if (strlen(txid) != 2 * STR_HASH_LEN || strlen(hash) != 2 * STR_HASH_LEN) {
            err("Invalid transaction hash\n");
            ret_code(1);
        }

        size_t data_len = strlen(data);
        if (!tlist->raw_data) {
            tdata_size = data_len * 2;
            tlist->raw_data = ccalloc(t_len, tdata_size);
        }

        if (cur_data_off + data_len >= tdata_size) {
            tdata_size *= 2;
            void *new_data_list = realloc(tlist->raw_data, tdata_size);

            if (!new_data_list) {
                err("build tx list: Realloc out of memory\n");
                exit(-1);
            }

            memcpy(new_data_list, tlist->raw_data, cur_data_off);
            free(tlist->raw_data);

            tlist->raw_data = new_data_list;
        }

        memcpy(tlist->raw_data + cur_data_off, data, data_len);
        memcpy(&cur_hash->byte_hash, txid, sizeof cur_hash->byte_hash);
        cur_data_off += data_len;

  cleanup:
        free(txid);
        free(hash);

        break;
    }

    tlist->data_size = cur_data_off;
    
    if (ret) {
        free(tlist);
        err("Aborting transaction list creation\n");
        return ret;
    }

    return ret;
}

void block_pack(const struct block_header *block, uint8_t raw[BLOCK_RAW_LEN]) {
    int32_t big_version = ntohl(block->version);
    memcpy(raw, &big_version, sizeof block->version);

    memcpy(raw + 4, &block->prev_hash, sizeof block->prev_hash);
    memcpy(raw + 36, &block->merkle_root_hash, sizeof block->merkle_root_hash);

    uint32_t big_target = htonl(block->target);
    memcpy(raw + 68, &big_target, sizeof block->target);
    memcpy(raw + 72, &block->time, sizeof block->time);
    memcpy(raw + 76, &block->nonce, sizeof block->nonce);
}

void block_serialize(const struct block_header *block, char raw[BLOCK_RAW_LEN + 64]) {
    int32_t big_version = ntohl(block->version);
    memcpy(raw, &big_version, sizeof block->version);

    char prev_hash_str[64] = {0};
    hex_to_string(block->prev_hash, prev_hash_str, sizeof block->prev_hash);

    memcpy(raw + 4, prev_hash_str, sizeof block->prev_hash);

    char merkle_root_str[64] = {0};
    hex_to_string(block->merkle_root_hash, merkle_root_str, sizeof block->merkle_root_hash);

    memcpy(raw + 68, merkle_root_str, sizeof block->merkle_root_hash);

    uint32_t big_target = htonl(block->target);
    memcpy(raw + 132, &big_target, sizeof block->target);
    memcpy(raw + 136, &block->time, sizeof block->time);
    memcpy(raw + 140, &block->nonce, sizeof block->nonce);
}

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *dest) {
    char **dest_ptr = dest;
    *dest_ptr = cmalloc(size * nmemb + 1);
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

CURLcode get_block_template(CURL *curl, struct submit_block *template) {
    CURLcode ret = 1;
    json_t *json = NULL, *result = NULL;
    char *nbits = NULL, *prev_hash = NULL;
    json_t *transactions = NULL;

    struct block_header *header = &template->header;

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
                           "version", &header->version,
                           "previousblockhash", &prev_hash,
                           "transactions", &transactions,
                           "curtime", &header->time,
                           "bits", &nbits))) {

        err("Unknown bitcoind response format\n");
        ret_code(ret);
    }

    if (!transactions || !nbits || !prev_hash) {
        err("Json decoding failed\n");
        ret_code(1);
    }

    string_to_hex(prev_hash, header->prev_hash, 64);
    /* printf("PrevL %s\n", prev_hash); */
    print_buf("Prev: ", header->prev_hash, 32);
    
    header->target = strtoul(nbits, NULL, 16);
    printf("Nbits: %x\n", header->target);

    transaction_list_t *tx_list = &template->tx_list;
    hash_t merkle_root = {0};

    ret = build_transaction_list(transactions, tx_list);
    if (ret) {
        memset(header->merkle_root_hash, 0, sizeof header->merkle_root_hash);
        err("Aborting merkle root hash calculation\n");
        ret_code(ret);
    }
    
    build_merkle_root(tx_list, tx_list->len, &merkle_root);

    memcpy(header->merkle_root_hash, merkle_root.byte_hash, sizeof header->merkle_root_hash);

  cleanup:
    if (json) {
        json_decref(json);
    }

    if (result) {
        json_decref(result);
    }

    return ret;
}

CURLcode submit_block(CURL *curl, struct submit_block *block) {
    size_t ser_block_size = sizeof (block->header) * 2 + sizeof(block->tx_list.len) + block->tx_list.data_size;
    uint8_t serialized_block[80] = {0};

    char *res_str = NULL;
    CURLcode ret = 0;
    char *post_data = ccalloc(ser_block_size + strlen(submitblock_template) + 1, sizeof *post_data);
    char header_str[sizeof(serialized_block) * 2 + 1] = {0};

    block_pack(&block->header, serialized_block);
    hex_to_string(serialized_block, header_str, sizeof serialized_block);

    sprintf(post_data, submitblock_template, header_str, block->tx_list.len, block->tx_list.raw_data);

    puts("Hero what i have\n");
    puts(post_data);

    ret = json_rpc(curl, post_data, &res_str);
    if (!res_str) {
        err("submitblock: Json RPC failed\n");
        ret_code(ret);
    }

    puts("\nSubmitblock: \n");
    puts(res_str);
    
  cleanup:
    free(post_data);
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

    target->byte_hash[31] = 0;
    target->byte_hash[30] = 0;
    target->byte_hash[29] = 0xff;
    /*
    target->byte_hash[28] = 0xff;
    target->byte_hash[27] = 0xff;
    */
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

    struct submit_block submit = {0};
    get_block_template(curl, &submit);

    hash_t target = {0};
    nbits_to_target(submit.header.target, &target);
    hash_print("Target: ", &target);
    ocl_version();

    hash_t mined_hash;
    if (mine(&submit.header, &target, &mined_hash)) {
        err("Block mining failed: \n");
    }
    uint8_t new_bin[80] = {0};
    block_pack(&submit.header, new_bin);

    uint8_t ou[32];
    double_sha256(new_bin, ou, 80);
    print_buf("Proved: ", ou, 32);

    submit_block(curl, &submit);
   
    curl_easy_cleanup(curl);
    ocl_free();
}
