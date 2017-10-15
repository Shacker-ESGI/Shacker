#include <cmath>
#include <iostream>
#include "bruteforce.h"

void calculate_buffer_load_shares(uint load_shares_indexes[MAX_PASSWORD_SIZE], uint keys_length, uint thread_id, uint max_threads) {
    uint left_bound = thread_id * MAX_PASSWORD_SIZE / max_threads;
    uint right_bound = (thread_id + 1) * MAX_PASSWORD_SIZE / max_threads;
    uint available_shares = max_threads / pow(keys_length, left_bound);

    for(uint i = left_bound ; i < right_bound ; i++) {
        if(available_shares < 2) {
            load_shares_indexes[i] = 1;
        }
        else {
            load_shares_indexes[i] = available_shares > keys_length ? keys_length : available_shares;
            available_shares /= load_shares_indexes[i];
        }
    }
}

void password_check(std::mutex &mutex, std::condition_variable &password_found,
                    std::promise<std::string> &promise, std::string password_hash,
                    char* possible_keys, uint load_shares_indexes[MAX_PASSWORD_SIZE],
                    uint thread_id, uint max_thread_number) {
    static bool is_password_found;
    std::string proposition;
    char buffer[MAX_PASSWORD_SIZE] = "";
    uint buffer_indexes[MAX_PASSWORD_SIZE] = {0};
    uint curr_index = 0;
    uint keys_length = strlen(possible_keys);

    is_password_found = false;
    buffer_indexes[0] = thread_id;

    while(!is_password_found) {

        if(buffer_indexes[curr_index] >= (thread_id + 1) * keys_length / load_shares_indexes[curr_index]) {
            buffer_indexes[curr_index] = thread_id * keys_length / load_shares_indexes[curr_index];
            curr_index++;
        }
        else {
            buffer[curr_index] = possible_keys[buffer_indexes[curr_index]];

            proposition = sha256(std::string(buffer));

            buffer_indexes[curr_index]++;


            if(curr_index > 0) {
                curr_index--;
            }

            if (proposition == password_hash) {
                std::unique_lock<std::mutex> lock(mutex);
                promise.set_value(std::string(buffer));
                is_password_found = true;
                password_found.notify_one();
            }
        }
    }

}

std::string sha256_bruteforce_parallel(std::string password_hash, char* possible_keys) {

    uint max_threads_number = std::thread::hardware_concurrency();
    std::thread threads[max_threads_number];
    std::promise<std::string> promise;
    auto result = promise.get_future();
    std::condition_variable password_found;
    std::mutex mutex;
    uint load_shares_indexes[MAX_PASSWORD_SIZE] = {0};
    uint keys_length = strlen(possible_keys);

    for(uint i = 0 ; i < max_threads_number ; i++) {
        threads[i] = std::thread(calculate_buffer_load_shares, load_shares_indexes, keys_length, i, max_threads_number);
    }

    for(uint i = 0 ; i < max_threads_number ; i++) {
        threads[i].join();
    }

    for(uint i = 0 ; i < max_threads_number ; i++) {
        threads[i] = std::thread(password_check, std::ref(mutex), std::ref(password_found),
                                 std::ref(promise), password_hash, possible_keys, load_shares_indexes, i, max_threads_number);
    }

    {
        std::unique_lock <std::mutex> lock(mutex);
        password_found.wait(lock);
    }

    for(uint i = 0 ; i < max_threads_number ; i++) {
        threads[i].join();
    }

    return result.get();
}

std::string sha256_bruteforce(std::string password_hash, char* possible_keys) {

    std::string proposition;
    char buffer[MAX_PASSWORD_SIZE] = "";
    uint buffer_indexes[MAX_PASSWORD_SIZE] = {0};
    uint curr_index = 0;

    while(true) {
        if(possible_keys[buffer_indexes[curr_index]] == '\0') {
            buffer_indexes[curr_index] = 0;
            curr_index++;
        }
        else {
            buffer[curr_index] = possible_keys[buffer_indexes[curr_index]];

            proposition = sha256(std::string(buffer));

            buffer_indexes[curr_index]++;

            if(curr_index > 0) {
                curr_index--;
            }

            if (proposition == password_hash) {
                return std::string(buffer);
            }
        }
    }
}