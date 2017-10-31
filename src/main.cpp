#include <sstream>
#include "bruteforce/bruteforce.h"
#include"log/logger.h"
#include "time/timer.h"

char half_hex_element_to_byte(char* ptr) {
  char byte = *ptr >= 'a' && *ptr <= 'f' ? *ptr - 'a' + 10 : 0;
  byte |= *ptr >= '0' && *ptr <= '9' ? *ptr - '0' : 0;
  return byte;
}

char hex_element_to_byte(char* ptr) {
  char byte = half_hex_element_to_byte(ptr) << 4;
  byte |= half_hex_element_to_byte(ptr + 1);
  return byte;
}

std::string hex_string_to_bytes(char* hex_string) {
  std::stringstream ss;
  unsigned int hex_string_length = strlen(hex_string);

  for(unsigned int i = 0 ; i < hex_string_length ; i+=2) {
    ss << hex_element_to_byte(hex_string + i);
  }
  return ss.str();
}

int main(int argc, char** argv) {
    Logger logger;
    std::string password_hash;
    std::string data;
    const char* possible_keys = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
    std::string proposition;

    logger.info(std::stringstream() << "Shacker initialized!");

    if(argc != 3) {
        logger.error(std::stringstream() << "Got " << argc - 1 << " arguments, expected " << 2);
        exit(EXIT_FAILURE);
    }

    if(strcmp(argv[1], "--pass") == 0) {
        password_hash = sha256(std::string(argv[2]));
        std::cout << password_hash << std::endl;
    }

    else if(strcmp(argv[1], "--hash") == 0) {
        password_hash = hex_string_to_bytes(argv[2]);
        std::cout << password_hash << std::endl;
    }

    else {
        logger.error(std::stringstream() << "No such option : " << argv[1]);
        exit(EXIT_FAILURE);
    }

    /*double start_time_sequential = timer_start();

    proposition = sha256_bruteforce(password_hash, possible_keys);

    double execution_time = timer_end(start_time_sequential);

    logger.info(std::stringstream() << "Password \"" << proposition << "\" was found in " << execution_time << "s (sequential)");*/

    double start_time_parallel = timer_start();

    proposition = sha256_bruteforce_parallel(password_hash, possible_keys);

    double execution_time = timer_end(start_time_parallel);

    logger.info(std::stringstream() << "Password \"" << proposition << "\" was found in " << execution_time << "s (parallel)");

	return EXIT_SUCCESS;
}
