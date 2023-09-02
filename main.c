#include <curl/curl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>

#define BITCOIND_URL "http://127.0.0.1:8332"
#define HASH_LEN 256

#define R(...) " "#__VA_ARGS__" "

struct best_block_hash {
    char hash[HASH_LEN];
};

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *dest) {
    printf("Received: %s\n", ptr);
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
    
    return curl_easy_perform(curl);
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
    char *json_str;
    json_error_t err = {0};
   
    ret = json_rpc(curl, post_data, &json_str);

    json_t *best_block_json = json_loads(json_str, JSON_ALLOW_NUL | JSON_DECODE_ANY, &err);

    if (!best_block_json) {
        ret = 1;
        goto cleanup;
    }

    char *result;
    if (json_unpack(best_block_json, "{s:s}", "result", &result)) {
        ret = 1;
        goto cleanup;
    }

    strcpy(res->hash, result);
    
  cleanup:
    free(json_str);
    return ret;
}

int main(void) {
    CURL *curl = curl_easy_init();
    CURLcode ret = {0};

    if (!curl) {
        return 1;
    }

    struct best_block_hash best_hash = {0};
    
    ret = get_best_block_hash(curl, &best_hash);
   
    printf("Curl stat: %d \n Best hash: %s\n", ret, best_hash.hash);
}
