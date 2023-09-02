#include <curl/curl.h>
#include <string.h>

#define BITCOIND_URL "http://127.0.0.1:8332"

#define R(...) " "#__VA_ARGS__" "

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *data) {
    printf("Received: %s\n", ptr);
    return nmemb;
}

int main(void) {
    CURL *curl = curl_easy_init();

    if (!curl) {
        return 1;
    }

    const char *post_data = R(
        {"jsonrpc": 2.0,
         "id": "cumainer",
         "method": "getbestblockhash",
         "params": []
        }
      );
    
    struct curl_slist *headers = {0};
    char errbuf[CURL_ERROR_SIZE] = {0};

    headers = curl_slist_append(NULL, "context-type: text/plain;");

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, BITCOIND_URL);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(post_data));
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_callback);
    curl_easy_setopt(curl, CURLOPT_USERPWD, "slamko:VenezuellaMiner00");
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);
    
    CURLcode ret = curl_easy_perform(curl);
    
    printf("Hello world %d \n %s\n", ret, errbuf);
}
