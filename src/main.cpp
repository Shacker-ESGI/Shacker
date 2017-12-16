#include <sstream>
#include "bruteforce/bruteforce.h"

int main(int argc, char** argv) {
  const unsigned char* password_hash;
  std::string data;
  std::string possible_keys = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
  std::string proposition;
  unsigned int nb_threads;

  if(argc != 3) {
    std::cerr << "\033[31mGot " << argc - 1 << " arguments, expected " << 2 <<  std::endl;
    exit(EXIT_FAILURE);
  }

  nb_threads = std::stoi(argv[1]);
  password_hash = hex_string_to_bytes(argv[2]);

  Bruteforce::PasswordCracker password_cracker(password_hash, possible_keys, nb_threads);

  proposition = password_cracker.parallel_crack();

  std::cout << proposition << std::endl;

  delete[] password_hash;
	return EXIT_SUCCESS;
}
