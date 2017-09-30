#include "bruteforce.h"

std::string password_generate(char* possible_keys, bool has_to_initialize) {

    static char buffer[MAX_PASSWORD_SIZE] = "";
    static uint buffer_indexes[6] = {0};
    static uint curr_index = 0;
    std::string password;
    bool has_new_password = false;

    if(has_to_initialize) {
        bzero(buffer, MAX_PASSWORD_SIZE * sizeof(char));
    }

    while(!has_new_password) {

        if(possible_keys[buffer_indexes[curr_index]] == '\0') {
            buffer_indexes[curr_index] = 0;
            curr_index++;
        }
        else {
            buffer[curr_index] = possible_keys[buffer_indexes[curr_index]];

            password = std::string(buffer);

            buffer_indexes[curr_index]++;

            if(curr_index > 0) {
                curr_index--;
            }
            has_new_password = true;
        }
    }

    return password;

}

void password_check_2(std::promise<std::string> &promise, std::string password_hash, char* possible_keys) {
    static bool is_password_found = false;
    static std::mutex mutex;

    while(!is_password_found) {

        std::lock_guard<std::mutex> lock(mutex);
        std::string password = password_generate(possible_keys);
        std::string proposition = sha256(password);

        if (proposition == password_hash) {
            promise.set_value(password);
            is_password_found = true;
        }
    }

}

std::string sha256_bruteforce_parallel(std::string password_hash, char* possible_keys) {

    unsigned max_threads_number = std::thread::hardware_concurrency();
    std::thread threads[max_threads_number];
    std::promise<std::string> promise;
    auto result = promise.get_future();

    for(uint i = 0 ; i < max_threads_number ; i++) {
        threads[i] = std::thread(password_check_2, std::ref(promise), password_hash, possible_keys);
    }

    for(uint i = 0 ; i < max_threads_number ; i++) {
        threads[i].join();
    }

    return result.get();
}

std::string sha256_bruteforce(std::string password_hash, char* possible_keys) {

    std::string proposition;
    char buffer[MAX_PASSWORD_SIZE] = "";
    uint buffer_indexes[6] = {0};
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