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

    #define MAX_PASSWORD_SIZE 256

    std::string sha256_bruteforce_parallel(std::string password_hash, char* possible_keys);
    void calculate_buffer_load_shares(uint load_shares_indexes[MAX_PASSWORD_SIZE], uint keys_length, uint max_threads);
    void password_check(std::mutex &mutex, std::condition_variable &password_found,
                        std::promise<std::string> &promise, std::string password_hash,
                        char* possible_keys, uint thread_id, uint max_thread_number);
    std::string sha256_bruteforce(std::string password_hash, char* possible_keys);

#endif //SHACKER_BRUTEFORCE_H
