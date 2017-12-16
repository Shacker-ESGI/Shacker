#include "bruteforce.h"

using namespace Bruteforce;

PasswordCracker::PasswordCracker(const unsigned char* password_hash,
                                  const std::string possible_keys)
                                  : PasswordCracker(password_hash,
                                                    possible_keys,
                                                    std::thread::hardware_concurrency()) {
}

PasswordCracker::PasswordCracker(const unsigned char* password_hash,
                                  const std::string possible_keys,
                                  const unsigned int max_thread_number):
                                  password_hash(password_hash),
                                  possible_keys(possible_keys),
                                  max_thread_number(max_thread_number),
                                  is_password_found(false),
                                  threads(),
                                  incrementer(),
                                  incrementer_size(0)
                                  {
}

void PasswordCracker::configure_increment() {
  unsigned int available_shares = this->max_thread_number;
  const unsigned int keys_length = this->possible_keys.length();

  while(available_shares > 0) {
    this->incrementer.push_back(available_shares % keys_length);
    available_shares /= keys_length;
  }
  this->incrementer_size = this->incrementer.size();
}

inline void PasswordCracker::check_password(const unsigned int thread_id) {
  std::string buffer = "";
  std::vector<unsigned int> buffer_indexes{0};

  this->init_buffer(buffer, buffer_indexes, thread_id);

  while(!this->is_password_found) {
    this->try_password(buffer, buffer_indexes);
    this->update_buffer(buffer, buffer_indexes);
  }
}

void PasswordCracker::update_buffer(std::string& buffer, std::vector<unsigned int>& buffer_indexes) {
  unsigned int increment = 0;

  for(unsigned int i = 0 ; i < this->incrementer_size || increment != 0 ; ++i) {
    if(i < this->incrementer_size) {
      increment+= this->incrementer[i];
    }

    if(i >= buffer_indexes.size() - 1) {
      this->rescale_context(buffer, buffer_indexes);
      --increment;
    }

    this->update_buffer_at_index(buffer, buffer_indexes, increment, i);
  }
}

void PasswordCracker::init_buffer(std::string& buffer, std::vector<unsigned int>& buffer_indexes, unsigned int increment) {
  for(unsigned int i = 0 ; increment != 0 ; ++i) {
    if(i >= buffer_indexes.size() - 1) {
      this->rescale_context(buffer, buffer_indexes);
      --increment;
    }

    this->update_buffer_at_index(buffer, buffer_indexes, increment, i);
  }
}

inline void PasswordCracker::update_buffer_at_index(std::string& buffer, std::vector<unsigned int>& buffer_indexes, unsigned int& increment, unsigned int index) {
  const unsigned int keys_length = this->possible_keys.length();
  buffer_indexes[index] += increment;

  increment = buffer_indexes[index] / keys_length;
  buffer_indexes[index] %= keys_length;
  buffer[index] = this->possible_keys[buffer_indexes[index]];
}

inline void PasswordCracker::try_password(std::string& buffer, std::vector<unsigned int>& buffer_indexes) {
  const bool are_password_same = sha256_compare(buffer, this->password_hash);

  if (are_password_same) {
      this->is_password_found = true;
      this->promise.set_value(buffer);
  }
}

inline void PasswordCracker::rescale_context(std::string& buffer, std::vector<unsigned int>& buffer_indexes) {
  buffer_indexes.push_back(0);
  buffer += this->possible_keys[0];
}

std::string PasswordCracker::parallel_crack() {
  auto result = this->promise.get_future();

  this->is_password_found = false;
  this->configure_increment();

  for(unsigned int i = 0 ; i < this->max_thread_number ; ++i) {
      this->threads.push_back(std::thread(&PasswordCracker::check_password, this, i));
  }

  result.wait();

  for(unsigned int i = 0 ; i < this->max_thread_number ; ++i) {
    this->threads[i].join();
  }

  return result.get();
}

PasswordCracker::~PasswordCracker() {

}
