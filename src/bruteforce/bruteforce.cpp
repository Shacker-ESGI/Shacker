#include "bruteforce.h"
#include "../log/logger.h"

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
                                  max_thread_number(max_thread_number) {
}

void PasswordCracker::calculate_buffer_load_shares() {
  int available_shares = this->max_thread_number;
  const int keys_length = this->possible_keys.length();

  while(available_shares >= 1) {
    this->load_shares_indexes.push_back(std::min(available_shares, keys_length));
    available_shares /= keys_length;
  }
}

inline unsigned int PasswordCracker::get_left_bound_from_thread_id_and_index(unsigned int thread_id, unsigned int curr_index) {
  unsigned int result = std::ceil(thread_id * this->possible_keys.length() / this->load_shares_indexes[curr_index]);
  unsigned int keys_length = this->possible_keys.length();
  return result < keys_length ? result : 0;
}

inline unsigned int PasswordCracker::get_right_bound_from_thread_id_and_index(unsigned int thread_id, unsigned int curr_index) {
  unsigned int result = std::ceil((thread_id + 1) * this->possible_keys.length() / this->load_shares_indexes[curr_index]);
  unsigned int keys_length = this->possible_keys.length();
  return std::min(result, keys_length);
}

inline void PasswordCracker::check_password(const unsigned int thread_id) {
  std::string buffer = " ";
  std::vector<unsigned int> buffer_indexes;
  unsigned int curr_index = 0;

  buffer_indexes.push_back(this->get_left_bound_from_thread_id_and_index(thread_id, curr_index));

  while(!this->is_password_found) {

      if(buffer_indexes[curr_index] >= this->get_right_bound_from_thread_id_and_index(thread_id, curr_index)) {
          this->pass_next_character(thread_id, buffer, buffer_indexes, curr_index);
      }
      else {
          this->try_password(buffer, buffer_indexes, curr_index);
      }
  }
}

inline void PasswordCracker::try_password(std::string& buffer, std::vector<unsigned int>& buffer_indexes, unsigned int& curr_index) {
  buffer[curr_index] = this->possible_keys[buffer_indexes[curr_index]];

  const bool are_password_same = sha256_compare(buffer, this->password_hash);

  ++buffer_indexes[curr_index];

  if(curr_index > 0) {
      --curr_index;
  }

  if (are_password_same) {
      this->is_password_found = true;
      this->promise.set_value(buffer);
  }
}

inline void PasswordCracker::pass_next_character(const unsigned int thread_id, std::string& buffer, std::vector<unsigned int>& buffer_indexes, unsigned int& curr_index){
  buffer_indexes[curr_index] = this->get_left_bound_from_thread_id_and_index(thread_id, curr_index);
  ++curr_index;

  if(curr_index >= buffer.length()) {
    this->rescale_context(buffer, buffer_indexes);
  }
}

inline void PasswordCracker::rescale_context(std::string& buffer, std::vector<unsigned int>& buffer_indexes) {
  std::unique_lock<std::mutex> lock(this->mutex);
  buffer_indexes.push_back(0);
  this->load_shares_indexes.push_back(1);
  buffer += " ";
}

std::string PasswordCracker::parallel_crack() {
  auto result = this->promise.get_future();

  this->is_password_found = false;
  this->calculate_buffer_load_shares();

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
