#include "bip.h"
#include "miner.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "ocl.h"
#include "util.h"
#include <jansson.h>
#include <stdbool.h>

int build_merkle_root(transaction_list_t *tlist, size_t len, hash_t *merkle_root) {
    if (!len) {
        err("merkle root: Invalid block\n");
        return 1;
    }
    
    if (len == 1) {
        printf("merkle_root: Only coinbase transaction present\n");

        memcpy(merkle_root->byte_hash, &tlist->txid_list[0], sizeof (merkle_root->byte_hash));
        return 0;
    }

    ocl_merkle_root_hash(tlist, merkle_root);
    
    return 0;
}

void submit_block_free(struct submit_block *block) {
    free(block->tx_list.cb_out_pk_script);
    free(block->tx_list.raw_data);
    free(block->tx_list.txid_list);
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

size_t uint_byte_num(uint32_t val) {
    if (val >> 24) return 4;
    if (val >> 16) return 3;
    if (val >= 0x80) return 2;

    return 1;
}

void cb_tx_free(struct cb_raw_tx *tx) {
    free(tx->tx_ins[0].script);
    free(tx->tx_outs[0].pk_script);
}

void build_cb_tx_in(struct cb_tx_in *tx_in, transaction_list_t *tlist) {
    size_t height_byte_num = uint_byte_num(tlist->height);
    size_t script_len = height_byte_num + 1;
    memset(tx_in->hash, 0, sizeof tx_in->hash);
    tx_in->index = 0xFFFFFFFF;
    set_compact8(&tx_in->script_bytes, script_len);

    tx_in->script = ccalloc(script_len, 1);

    if (tlist->height <= 16) {
        tx_in->script[0] = (uint8_t)0x50 + (uint8_t)tlist->height;
        tx_in->script[1] = 1;
    } else {
        tx_in->script[0] = height_byte_num;
        memcpy(tx_in->script + 1, &tlist->height, height_byte_num);
    }

    tx_in->sequence = 0xFFFFFFFF;
}

void build_cb_out(struct cb_tx_out *tx_out, transaction_list_t *tlist) {
    size_t tx_out_pk_len = tlist->pk_script_bytes;
    tx_out->value = 25;
    set_compact8(&tx_out->pk_script_len, tx_out_pk_len);
    tx_out->pk_script = cmalloc(tlist->pk_script_bytes);
    memcpy(tx_out->pk_script, tlist->cb_out_pk_script, tlist->pk_script_bytes);
}

size_t build_coinbase(transaction_list_t *tlist) {
    struct cb_raw_tx cb = {0};
    cb.lock_time = 0x00;
    cb.version = 0x01;

    set_compact8(&cb.tx_in_cnt, 1);
    build_cb_tx_in(&cb.tx_ins[0], tlist);

    set_compact8(&cb.tx_out_cnt, 1);
    build_cb_out(&cb.tx_outs[0], tlist);
   
    size_t cb_size = get_cb_size(&cb);
    size_t rdata_size = cb_size * 2 + 1;
    uint8_t *coinbase_data = ccalloc(cb_size, 1);
    
    tlist->raw_data = ccalloc(rdata_size, sizeof (*tlist->raw_data));
    write_coinbase(&cb, coinbase_data, cb_size);

    hex_to_string(coinbase_data, tlist->raw_data, cb_size);
    printf("Raw data: %s\n", tlist->raw_data);
    
    double_sha256(coinbase_data, &tlist->txid_list->byte_hash[0], cb_size);

    free(coinbase_data);
    cb_tx_free(&cb);

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
