#include <curl/curl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <stdint.h>
#include "miner.h"
#include "ocl.h"

struct best_block_hash {
    char hash[STR_HASH_LEN];
};

struct block_header {
    int32_t version;
    char prev_hash[32];
    char merkle_root_hash[32];
    int32_t time;
    int32_t target;
    int32_t nonce;
} __attribute__ ((packed));


void block_pack(struct block_header *block, uint8_t raw[BLOCK_RAW_LEN]) {
    memcpy(raw, block, BLOCK_RAW_LEN);
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
    curl_slist_free_all(headers);
    return ret;
}

const char *post_data = R(
    {"jsonrpc": 2.0,
     "id": "cumainer",
     "method": "getbestblockhash",
     "params": []
    }
    );

CURLcode get_best_block_hash(CURL *curl, struct best_block_hash *res) {
    CURLcode ret = 1;
    char *json_str = NULL;
    json_error_t err = {0};
   
    ret = json_rpc(curl, post_data, &json_str);

    json_t *best_block_json = json_loads(json_str, JSON_ALLOW_NUL | JSON_DECODE_ANY, &err);

    if (!best_block_json) {
        err("RPC Method failed\n");
        ret_code(1);
    }

    char *result;
    if (json_unpack(best_block_json, "{s:s}", "result", &result)) {
        err("Unknown bitcoind response format\n");
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

int main(void) {
    CURL *curl = curl_easy_init();

    if (!curl) {
        return 1;
    }

    int ret = ocl_init();
    if (ret) {
        error("OpenCL initialization failed: %d\n", ret);
    }
    
    struct best_block_hash best_hash = {0};
    
    /* ret = get_best_block_hash(curl, &best_hash); */

    if (ret) {
        printf("Error occured: %d\n", ret);
        exit(ret);
    }
   
    printf("Curl stat: %d \n Best hash: %s\n", ret, best_hash.hash);

    struct block_header header = {0};
    memset(header.merkle_root_hash, 0x12, sizeof(header.merkle_root_hash));
    memset(header.prev_hash, 0x56, sizeof(header.merkle_root_hash));

    header.nonce = 0x73435ab;
    header.version = 0x1;

    uint8_t raw[80];
    block_pack(&header, raw);
    ret = sha256((uint8_t *)"Hello", sizeof("Hello"));

    if (ret) {
        error("Kernel failed: %d\n", ret);
    }

    curl_easy_cleanup(curl);
    ocl_free();
}
