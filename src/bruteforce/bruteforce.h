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
        std::vector<double> load_shares_indexes;
        std::mutex mutex;
        std::promise<std::string> promise;

        void calculate_buffer_load_shares();
        void check_password(const unsigned int thread_id);
        inline unsigned int get_left_bound_from_thread_id_and_index(unsigned int thread_id, unsigned int curr_index);
        inline unsigned int get_right_bound_from_thread_id_and_index(unsigned int thread_id, unsigned int curr_index);
        inline void try_password(std::string& buffer, std::vector<unsigned int>& buffer_indexes, unsigned int& curr_index);
        inline void pass_next_character(const unsigned int thread_id, std::string& buffer, std::vector<unsigned int>& buffer_indexes, unsigned int& curr_index);
        inline void rescale_context(std::string& buffer, std::vector<unsigned int>& buffer_indexes);

      public:
        PasswordCracker(const unsigned char* password_hash, const std::string possible_keys);
        PasswordCracker(const unsigned char* password_hash, const std::string possible_keys, const unsigned int max_thread_number);

        std::string parallel_crack();

        ~PasswordCracker();
      };
    }

#endif //SHACKER_BRUTEFORCE_H
