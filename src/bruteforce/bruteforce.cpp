#include "bruteforce.h"

void password_generate(char* possible_keys, uint thread_index, uint max_threads,
                       bool &isFinished, std::condition_variable &has_available_data, std::mutex &mutex,
                        std::queue<std::string> &queue) {

    char buffer[MAX_PASSWORD_SIZE] = "";
    uint buffer_indexes[MAX_PASSWORD_SIZE] = {0};
    uint curr_index = 0;
    std::string password;

    bzero(buffer, MAX_PASSWORD_SIZE * sizeof(char));

    buffer[0] = possible_keys[thread_index];

    while(!isFinished) {

        if(possible_keys[buffer_indexes[curr_index]] == '\0') {
            buffer_indexes[curr_index] = 0;
            curr_index++;
        }
        else {
            buffer[curr_index] = possible_keys[buffer_indexes[curr_index]];

            password = std::string(buffer);

            if(curr_index > 0) {
                buffer_indexes[curr_index]++;
                curr_index--;
            }
            else {
                buffer_indexes[curr_index]+=max_threads;
            }

            {
                std::unique_lock<std::mutex> lock(mutex);
                queue.push(password);
                has_available_data.notify_one();
            }
        }
    }
}

bool password_check(std::string password, std::string password_hash) {

    std::string proposition = sha256(password);
    return proposition == password_hash;

}

std::string sha256_bruteforce_parallel(std::string password_hash, char* possible_keys) {

    ProducerConsumer<std::string> producerConsumer([=](uint thread_index, uint max_threads,
                                                       bool &isFinished, std::condition_variable &has_available_data,
                                                       std::mutex &mutex, std::queue<std::string> &queue) -> std::string {
        password_generate(possible_keys, thread_index, max_threads, isFinished, has_available_data, mutex, queue);
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