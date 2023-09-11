#include "rpc.h"
#include <stddef.h>
#include <stdint.h>
#include <curl/curl.h>
#include "miner.h"
#include <string.h>
#include <stdio.h>
#include "util.h"
#include <jansson.h>
#include "stdbool.h"
#include "bip.h"

char *bitcoind_url = BITCOIND_URL;
char *username = "username";
char *password = "password";
char *userlogin;

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
    curl_easy_setopt(curl, CURLOPT_URL, bitcoind_url);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(post_data));
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, dest_str);

    curl_easy_setopt(curl, CURLOPT_USERPWD, userlogin);
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

    if (!json_str) {
        err("RPC: no result\n");
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
    int32_t height = 0;

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
                           "{s:i, s:s, s:o, s:i, s:s, s:i}",
                           "version", &header->version,
                           "previousblockhash", &prev_hash,
                           "transactions", &transactions,
                           "curtime", &header->time,
                           "bits", &nbits,
                           "height", &height))) {

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
    tx_list->height = height;
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
    free(res_str);
    return ret;
}

CURLcode get_best_block_hash(CURL *curl, hash_t *res) {
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

    if (res_len != sizeof(res->byte_hash)) {
        error("Unmatched hash length %zu\n", res_len);
        ret_code(1);
    }

    strcpy((char *)res->byte_hash, result);
    
  cleanup:
    if (json_str)
        free(json_str);
    if (best_block_json) {
        json_decref(best_block_json);
    }
    return ret;
}


