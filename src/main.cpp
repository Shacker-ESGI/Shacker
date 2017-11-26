#include <sstream>
#include "bruteforce/bruteforce.h"
#include"log/logger.h"
#include "time/timer.h"

int main(int argc, char** argv) {
  Logger logger;
  const unsigned char* password_hash;
  std::string data;
  std::string possible_keys = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
  std::string proposition;
  unsigned int nb_threads;

  logger.info(std::stringstream() << "Shacker initialized!");

  if(argc != 3) {
      logger.error(std::stringstream() << "Got " << argc - 1 << " arguments, expected " << 2);
      exit(EXIT_FAILURE);
  }

  nb_threads = std::stoi(argv[1]);
  password_hash = hex_string_to_bytes(argv[2]);

  Bruteforce::PasswordCracker password_cracker(password_hash, possible_keys, nb_threads);

  double start_time_parallel = timer_start();

  proposition = password_cracker.parallel_crack();

  double execution_time = timer_end(start_time_parallel);

  logger.info(std::stringstream() << "Password \"" << proposition << "\" was found in " << execution_time << "s (parallel)");

  delete[] password_hash;
	return EXIT_SUCCESS;
}
