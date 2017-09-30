#include "bruteforce/bruteforce.h"
#include"log/logger.h"
#include "time/timer.h"

int main(int argc, char** argv) {
    Logger logger;
    std::string password_hash;
    std::string data;
    char* possible_keys = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
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

    clock_t start_time_sequential = timer_start();

    proposition = sha256_bruteforce(password_hash, possible_keys);

    float execution_time = timer_end(start_time_sequential);

    logger.info(std::stringstream() << "Password \"" << proposition << "\" was found in " << execution_time << "s (sequential)");

    clock_t start_time_parallel = timer_start();

    proposition = sha256_bruteforce_parallel(password_hash, possible_keys);

    execution_time = timer_end(start_time_parallel);

    logger.info(std::stringstream() << "Password \"" << proposition << "\" was found in " << execution_time << "s (parallel)");

	return EXIT_SUCCESS;
}
