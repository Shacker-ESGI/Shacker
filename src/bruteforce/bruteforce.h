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

    #define MAX_PASSWORD_SIZE 8

    std::string sha256_bruteforce_parallel(std::string password_hash, const char* possible_keys);
    void calculate_buffer_load_shares(unsigned int load_shares_indexes[MAX_PASSWORD_SIZE], unsigned int keys_length,
                                        unsigned int thread_id, unsigned int max_threads);
    void password_check(std::mutex &mutex, std::condition_variable &password_found,
                        std::promise<std::string> &promise, std::string password_hash,
                        const char* possible_keys, unsigned int load_shares_indexes[MAX_PASSWORD_SIZE],
                        unsigned int thread_id, unsigned int max_thread_number);
    std::string sha256_bruteforce(std::string password_hash, const char* possible_keys);

#endif //SHACKER_BRUTEFORCE_H
