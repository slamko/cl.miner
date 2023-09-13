#include "miner.h"
#include <bits/getopt_core.h>
#include <curl/curl.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include "ocl.h"
#include "bip.h"
#include "rpc.h"

void cleanup(int sig) {
    printf("SIGINT Received: cleaning OpenCL context...\n");
    free(userlogin);
    ocl_free();
    exit(1);
}

int build_submit_block_header(CURL *curl, struct submit_block *submit) {
    int ret = 0;
    if (address) {
        ret = get_address_info(curl, address, &submit->tx_list.pk_script_bytes, &submit->tx_list.cb_out_pk_script);
        
        if (ret) {
            err("Bitcoin wallet not found\n");
            ret_code(ret);
        }
    }
    
    if (get_block_template(curl, submit)) {
        err("Get block template failed\n");
        ret_code(1);
    }
    
    nbits_to_target(submit->header.target, &submit->target);

  cleanup:
    return ret;
}

int parse_args(int argc, char **argv) {
    int opt = 0;

    while((opt = getopt(argc, argv, "u:n:p:a:")) != -1) {
        switch (opt) {
        case 'u':
            bitcoind_url = optarg;
            break;
        case 'n':
            username = optarg;
            break;
        case 'p':
            password = optarg;
            break;
        case 'a':
            address = optarg;
            break;
        default:
            error("Unknown arg %c: miner -u <bitcoind_url> -n <username> -p <password> -a <btc_address>\n", optopt);    
            return 1;
            break;
        }
    }

    return 0;
}

int main(int argc, char **argv) {
    int ret = {0};
    CURL *curl = NULL;

    if (parse_args(argc, argv)) {
        err("Invalid args\n");
        return 1;
    }

    userlogin = ccalloc(strlen(username) + strlen(password) + 2, sizeof *userlogin);
    sprintf(userlogin, "%s:%s", username, password);

    struct sigaction clean_action = {0};
    clean_action.sa_handler = &cleanup;
    clean_action.sa_flags = 0;

    sigaction(SIGINT, &clean_action, NULL);
    
    curl = curl_easy_init();

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
        if (build_submit_block_header(curl, &submit)) {
            err("Block build failed\n");
            ret_code(1);
        }

        hash_t mined_hash;
        if (mine(&submit.header, &submit.target, &mined_hash)) {
            err("Block mining failed: \n");
            ret_code(1);
        }
        
        if ((ret = submit_block(curl, &submit))) {
            err("Block submit failed\n");
            ret_code(ret);
        }

        submit_block_free(&submit);
    }
    
   
  cleanup:
    curl_easy_cleanup(curl);
    ocl_free();
}
