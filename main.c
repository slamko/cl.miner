#include "miner.h"
#include <curl/curl.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdbool.h>
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

void hton_hex(uint8_t *nhash, const uint8_t *hhash, size_t len) {
    for (size_t i = 0; i < len; i++) {
        nhash[len - i - 1] = hhash[i];
    }
}

void ntoh_hex(uint8_t *hhash, const uint8_t *nhash, size_t len) {
    for (size_t i = 0; i < len; i++) {
        hhash[len - i - 1] = nhash[i];
    }
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

int build_merkle_root(transaction_list_t *tlist, size_t len, hash_t *merkle_root) {
    hash_t *merkle_tree = NULL;

    if (!len) {
        err("merkle root: Invalid block\n");
        return 1;
    }
    
    if (len == 1) {
        printf("merkle_root: Only coinbase transaction present\n");
        uint8_t mrkl[32] =
            {0x72, 0x95, 0xc5, 0xb4, 0x43, 0xcd, 0x2a, 0x9e, 0x8d, 0x53,
             0xa3, 0x3d, 0x7f, 0x19, 0xaf, 0xa7, 0x2, 0x1, 0x43, 0x78, 0x11, 0x5a, 0xf7, 0x37, 0xef, 0x49, 0x56, 0x60, 0xba, 0xd6, 0x50,
             0x78};

        memcpy(merkle_root->byte_hash, &tlist->txid_list[0], sizeof (merkle_root->byte_hash));
        return 0;
    }
    
    merkle_tree = cmalloc(len * sizeof *merkle_tree);
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
    return 0;
}

typedef struct compact_size {
    union {
        uint32_t val32;
        uint16_t val16;
        uint8_t val8;
    };

    uint8_t size;
} compact_t;

struct cb_tx_in {
    uint8_t hash[32];
    uint32_t index;
    compact_t script_bytes;
    uint8_t *script;
    uint32_t sequence;
};

struct cb_tx_out {
    int64_t value;
    compact_t pk_script_len;
    uint8_t *pk_script;
};

struct cb_raw_tx {
    int32_t version;

    compact_t tx_in_cnt;
    struct cb_tx_in tx_ins[1];

    compact_t tx_out_cnt;
    struct cb_tx_out tx_outs[1];

    uint32_t lock_time;
};

size_t get_compact_size(compact_t compact) {
    return compact.val32 + compact.size;
}

size_t get_tx_out_size(const struct cb_tx_out *out) {
    return (sizeof (out->value) - sizeof (out->pk_script_len) + get_compact_size(out->pk_script_len));
}

size_t get_tx_in_size(const struct cb_tx_in *in) {
    return (sizeof (*in) - sizeof (in->script) - sizeof(in->script_bytes) + get_compact_size(in->script_bytes));
}

size_t get_cb_size(const struct cb_raw_tx *cb) {
    
    return (sizeof (cb->version) + sizeof (cb->lock_time) +
            (get_tx_in_size(&cb->tx_ins[0])) + cb->tx_in_cnt.size +
            (get_tx_out_size(cb->tx_outs)) + cb->tx_out_cnt.size
        );
}

bool is_valid_compact_size(const compact_t *compact) {
    return !!compact->size;
}

typedef struct serializer_stream {
    size_t cur_addr;
    size_t len;
} serializer_t;

void serialize_init(struct serializer_stream *stream, size_t len) {
    stream->cur_addr = 0;
    stream->len = len;
}

void serialize_write(serializer_t *stream, void *dest, const void *src, size_t size) {
    if (stream->cur_addr >= stream->len) {
        err("seralize write: Too short stream\n");
        return;
    }
    
    memcpy(dest + stream->cur_addr, src, size);
    stream->cur_addr += size; 
}

void write_coinbase(struct cb_raw_tx *cb, uint8_t *buf, size_t len) {
    serializer_t stream = {0};

    serialize_init(&stream, len);
    serialize_write(&stream, buf, &cb->version, sizeof cb->version);

    if (!is_valid_compact_size(&cb->tx_in_cnt) || !is_valid_compact_size(&cb->tx_out_cnt)) {
        err("Compact error\n");
        exit(1);
    }

    serialize_write(&stream, buf, &cb->tx_in_cnt.val32, cb->tx_in_cnt.size);
    serialize_write(&stream, buf, cb->tx_ins[0].hash, sizeof cb->tx_ins[0].hash);
    serialize_write(&stream, buf, &cb->tx_ins[0].index, sizeof cb->tx_ins[0].index);
    serialize_write(&stream, buf, &cb->tx_ins[0].script_bytes.val32, cb->tx_ins[0].script_bytes.size);

    if (!cb->tx_ins[0].script) {
        err("No tx in script\n");
    } else {
        serialize_write(&stream, buf, cb->tx_ins[0].script, cb->tx_ins[0].script_bytes.val32);
    }

    serialize_write(&stream, buf, &cb->tx_ins[0].sequence, sizeof cb->tx_ins[0].sequence);

    serialize_write(&stream, buf, &cb->tx_out_cnt.val32, cb->tx_out_cnt.size);

    serialize_write(&stream, buf, &cb->tx_outs[0].value, sizeof cb->tx_outs[0].value);
    serialize_write(&stream, buf, &cb->tx_outs[0].pk_script_len.val32, cb->tx_outs[0].pk_script_len.size);

    if (!cb->tx_outs[0].pk_script) {
        err("No tx out pk_script\n");
    } else {
        serialize_write(&stream, buf, cb->tx_outs[0].pk_script, cb->tx_outs[0].pk_script_len.val32);
    }

    serialize_write(&stream, buf, &cb->lock_time, sizeof cb->lock_time);
    printf("Stream size: %zu\n", stream.cur_addr);
}

void set_compact8(compact_t *compact, uint8_t val) {
    compact->val8 = val;
    compact->size = sizeof val;
}

void set_compact16(compact_t *compact, uint16_t val) {
    compact->val16 = val;
    compact->size = sizeof val;
}

void set_compact32(compact_t *compact, uint32_t val) {
    compact->val32 = val;
    compact->size = sizeof val;
}

size_t build_coinbase(transaction_list_t *tlist) {
    struct cb_raw_tx cb = {0};
    cb.lock_time = 0x00;
    cb.version = 0x01;

    set_compact8(&cb.tx_in_cnt, 1);
    struct cb_tx_in *tx_in = &cb.tx_ins[0];

    size_t script_len = 2;
    memset(tx_in->hash, 0, sizeof cb.tx_ins->hash);
    tx_in->index = 0xFFFFFFFF;
    set_compact8(&tx_in->script_bytes, script_len);

    tx_in->script = ccalloc(script_len, 1);
    tx_in->script[0] = 0x52;
    tx_in->script[1] = 0x0;
    tx_in->sequence = 0xFFFFFFFF;

    set_compact8(&cb.tx_out_cnt, 1);
    struct cb_tx_out *tx_out = cb.tx_outs;

    size_t tx_out_pk_len = 0;
    tx_out->value = 0;
    set_compact8(&tx_out->pk_script_len, tx_out_pk_len);
    tx_out->pk_script = NULL;
    
    size_t cb_size = get_cb_size(&cb);
    printf("CB size: %zu\n", cb_size);
    
    size_t rdata_size = cb_size * 2 + 1;

    uint8_t *coinbase_data = ccalloc(cb_size, 1);
    
    tlist->raw_data = ccalloc(rdata_size, sizeof (*tlist->raw_data));
    write_coinbase(&cb, coinbase_data, cb_size);

    hex_to_string(coinbase_data, tlist->raw_data, cb_size);
    printf("Raw data: %s\n", tlist->raw_data);
    
    double_sha256(coinbase_data, &tlist->txid_list->byte_hash[0], cb_size);

    free(coinbase_data);
    free(tx_in->script);

    return rdata_size;
}

int build_transaction_list(json_t *t_arr, transaction_list_t *tlist) {
    int ret = 0;
    size_t t_len = json_array_size(t_arr);
    size_t tdata_size = 0;
    size_t cur_data_off = 0;

    if (!t_len) {
        tlist->txid_list = ccalloc(1, sizeof (*tlist->txid_list));
        tlist->data_size = build_coinbase(tlist);
        tlist->len = 1;

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

            cur_data_off += build_coinbase(tlist);
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

void memcpy_be(void *dest, const void *src, size_t len) {
    char *dest_buf = dest;
    const char *src_buf = src;
    
    for (size_t i = 0; i < len; i++) {
        dest_buf[len - i - 1] = src_buf[i];
    }
}

void block_pack(const struct block_header *block, uint8_t raw[BLOCK_RAW_LEN]) {
    int32_t big_version = block->version;
    memcpy(raw, &big_version, sizeof block->version);

    memcpy_be(raw + 4, &block->prev_hash, sizeof block->prev_hash);
    memcpy(raw + 36, &block->merkle_root_hash, sizeof block->merkle_root_hash);

    uint32_t big_time = block->time;
    memcpy(raw + 68, &big_time, sizeof block->time);
    uint32_t big_target = block->target;
    memcpy(raw + 72, &big_target, sizeof block->target);
    uint32_t big_nonce = block->nonce;
    memcpy(raw + 76, &big_nonce, sizeof block->nonce);
}

void block_serialize(const struct block_header *block, uint8_t raw[BLOCK_RAW_LEN]) {

    int32_t big_version = block->version;
    memcpy(raw, &big_version, sizeof block->version);

    memcpy_be(raw + 4, &block->prev_hash, sizeof block->prev_hash);
    memcpy(raw + 36, &block->merkle_root_hash, sizeof block->merkle_root_hash);

    memcpy(raw + 68, &block->time, sizeof block->time);

    uint32_t big_target = block->target;
    memcpy(raw + 72, &big_target, sizeof block->target);

    uint32_t big_nonce = block->nonce;
    memcpy(raw + 76, &big_nonce, sizeof block->nonce);
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

    printf("Time: %x\n", header->time);

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
    
    ret = build_merkle_root(tx_list, tx_list->len, &merkle_root);
    if (ret) {
        err("Merkle root build failed\n");
        ret_code(ret);
    }

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

    block_serialize(&block->header, serialized_block);
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

    /*
    target->byte_hash[31] = 0;
    target->byte_hash[30] = 0;
    target->byte_hash[29] = 0xff;
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

    struct submit_block submit = {0};
    if (get_block_template(curl, &submit)) {
        err("Get block template failed\n");
        ret_code(1);
    }

    hash_t target = {0};
    nbits_to_target(submit.header.target, &target);
    hash_print("Target: ", &target);
    ocl_version();

    hash_t mined_hash;
    if (mine(&submit.header, &target, &mined_hash)) {
        err("Block mining failed: \n");
        ret_code(1);
    }

    uint8_t new_bin[80] = {0};
    block_pack(&submit.header, new_bin);

    uint8_t ou[32];
    double_sha256(new_bin, ou, 80);
    print_buf("Proved: ", ou, 32);

    if (submit_block(curl, &submit)) {
        err("Block submit failed\n");
        ret_code(1);
    }
    
   
  cleanup:
    curl_easy_cleanup(curl);
    ocl_free();
}
