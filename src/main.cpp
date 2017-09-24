#include <cstring>
#include"log/logger.h"
#include "crypto/sha256.h"
#include "time/timer.h"

std::string sha256_bruteforce(std::string password_hash, char* possible_keys, uint possible_keys_size) {

    std::string proposition;
    char buffer[256] = "";
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

            if(curr_index > 0)
                curr_index--;

            if (proposition == password_hash) {
                return std::string(buffer);
            }
        }
    }
}

int main(int argc, char** argv) {
    Logger logger;
    std::string password_hash;
    std::string data;
    char* possible_keys = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    uint possible_keys_size = strlen(possible_keys);
    std::string proposition;

    logger.info(std::stringstream() << "Shacker initialized!");

    if(argc != 3) {
        std::string error("");;
        logger.error(std::stringstream() << "Got " << argc << " arguments, expected " << 2);
        exit(EXIT_FAILURE);
    }

    if(strcmp(argv[1], "--pass") == 0) {
        password_hash = sha256(std::string(argv[2]));
    }

    else if(strcmp(argv[1], "--hash") == 0) {
        password_hash = argv[2];
    }

    else {
        logger.error(std::stringstream() << "No such option : " << argv[1]);
        exit(EXIT_FAILURE);
    }

    clock_t start_time = timer_start();

    proposition = sha256_bruteforce(password_hash, possible_keys, possible_keys_size);

    float execution_time = timer_end(start_time);

    logger.info(std::stringstream() << "Password \"" << proposition << "\" was found in " << execution_time << "s");

	return EXIT_SUCCESS;
}
