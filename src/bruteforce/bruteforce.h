//
// Created by aurelien on 30/09/17.
//

#ifndef SHACKER_BRUTEFORCE_H
#define SHACKER_BRUTEFORCE_H

    #include <cstring>
    #include <thread>
    #include <mutex>
    #include <future>
    #include "../crypto/sha256.h"
    #include "../producer_consumer.h"

    #define MAX_PASSWORD_SIZE 256

    std::string password_generate(char* possible_keys, bool has_to_initialize = false);
    bool password_check(std::string password, std::string password_hash);
    std::string sha256_bruteforce_parallel(std::string password_hash, char* possible_keys);
    std::string sha256_bruteforce(std::string password_hash, char* possible_keys);

#endif //SHACKER_BRUTEFORCE_H
