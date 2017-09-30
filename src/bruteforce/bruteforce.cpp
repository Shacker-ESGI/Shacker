#include "bruteforce.h"

std::string password_generate(char* possible_keys, bool has_to_initialize) {

    static char buffer[MAX_PASSWORD_SIZE] = "";
    static uint buffer_indexes[6] = {0};
    static uint curr_index = 0;
    std::string password;
    bool has_new_password = false;
    static std::mutex mutex;

    if(has_to_initialize) {
        bzero(buffer, MAX_PASSWORD_SIZE * sizeof(char));
    }

    while(!has_new_password) {

        std::unique_lock<std::mutex> lock(mutex);
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

bool password_check(std::string password, std::string password_hash) {

    std::string proposition = sha256(password);

    return proposition == password_hash;

}

std::string sha256_bruteforce_parallel(std::string password_hash, char* possible_keys) {

    ProducerConsumer<std::string> producerConsumer([=]() -> std::string {
        return password_generate(possible_keys);
    }, [=](std::string password) -> bool {
        return password_check(password, password_hash);
    });

    producerConsumer.process();

    return producerConsumer.getAnswer();
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