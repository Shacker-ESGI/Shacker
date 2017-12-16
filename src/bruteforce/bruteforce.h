//
// Created by aurelien on 30/09/17.
//

#ifndef SHACKER_BRUTEFORCE_H
#define SHACKER_BRUTEFORCE_H

    #include <cstring>
    #include <vector>
    #include <functional>
    #include <thread>
    #include <mutex>
    #include <future>
    #include <algorithm>
    #include <chrono>
    #include <cmath>
    #include <iostream>
    #include "../crypto/sha256.h"

    namespace Bruteforce {
      class PasswordCracker {
      private:
        const unsigned char* password_hash;
        const std::string possible_keys;
        const unsigned int max_thread_number;
        bool is_password_found;
        std::vector<std::thread> threads;
        std::vector<unsigned int> incrementer;
        unsigned int incrementer_size;
        std::promise<std::string> promise;

        void check_password(const unsigned int thread_id);
        inline void try_password(std::string& buffer, std::vector<unsigned int>& buffer_indexes);
        inline void rescale_context(std::string& buffer, std::vector<unsigned int>& buffer_indexes);
        void configure_increment();
        void update_buffer(std::string& buffer, std::vector<unsigned int>& buffer_indexes);
        void init_buffer(std::string& buffer, std::vector<unsigned int>& buffer_indexes, unsigned int increment);
        inline void update_buffer_at_index(std::string& buffer, std::vector<unsigned int>& buffer_indexes, unsigned int& increment, unsigned int index);

      public:
        PasswordCracker(const unsigned char* password_hash, const std::string possible_keys);
        PasswordCracker(const unsigned char* password_hash, const std::string possible_keys, const unsigned int max_thread_number);

        std::string parallel_crack();

        ~PasswordCracker();
      };
    }

#endif //SHACKER_BRUTEFORCE_H
