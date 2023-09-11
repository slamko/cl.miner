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
#include "bip.h"
#include "rpc.h"

int main(void) {
    int ret = {0};
    CURL *curl = curl_easy_init();

    if (!curl) {
        err("Curl init error\n");
        return 1;
    }

    ret = ocl_init();
    if (ret) {
        error("OpenCL initialization failed: %d\n", ret);
        return ret;
    }
    
    while(1) {
        struct submit_block submit = {0};
        if (get_block_template(curl, &submit)) {
            err("Get block template failed\n");
            ret_code(1);
        }

        hash_t target = {0};
        nbits_to_target(submit.header.target, &target);
        /* hash_print("Target: ", &target); */
        
        hash_t mined_hash;
        if (mine(&submit.header, &target, &mined_hash)) {
            err("Block mining failed: \n");
            ret_code(1);
        }
        
#if 0
        // check block hash

        uint8_t new_bin[80] = {0};
        block_pack(&submit.header, new_bin);
        
        uint8_t proved[32];
        double_sha256(new_bin, proved, 80);
        print_buf("Proved: ", proved, 32);
#endif
        
        if ((ret = submit_block(curl, &submit))) {
            err("Block submit failed\n");
            ret_code(ret);
        }
    }
    
   
  cleanup:
    curl_easy_cleanup(curl);
    ocl_free();
}
