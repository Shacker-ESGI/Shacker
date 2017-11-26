//
// Created by aurelien on 16/09/17.
//
#include <sstream>
#include <iostream>
#include "sha256.h"

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

const unsigned char* hex_string_to_bytes(char* hex_string) {
  std::stringstream ss;
  unsigned int hex_string_length = std::strlen(hex_string);
  unsigned char* bytes = new unsigned char[hex_string_length / 2];

  for(unsigned int i = 0 ; i < hex_string_length ; i+=2) {
    bytes[i / 2] = hex_element_to_byte(hex_string + i);
  }
  return bytes;
}

std::string bytes_to_hex_string(long long* bytes, unsigned int bytes_length) {
  std::stringstream ss;

  ss << std::hex << std::setfill('0');

  for (unsigned int i = 0; i < bytes_length; ++i) {
    ss << std::setw(2) << bytes[i];
  }

  return ss.str();
}

unsigned char* sha256(std::string& data) {

    const char* data_string = data.c_str();
    unsigned char* digest_string = new unsigned char[SHA256_DIGEST_LENGTH];

    SHA256((unsigned char*) data_string, data.length(), digest_string);

    return digest_string;
}

bool sha256_compare(std::string& data, const unsigned char* target) {
    bool is_password_found = true;
    const unsigned char* hash = sha256(data);
    const unsigned int loop_turns = SHA256_DIGEST_LENGTH / sizeof(unsigned long long);
    unsigned long long* hash_pointer = (unsigned long long*) hash;
    unsigned long long* target_pointer = (unsigned long long*) target;

    for(unsigned int i = 0 ; is_password_found && i < loop_turns ; ++i, ++hash_pointer, ++target_pointer) {
      is_password_found = *hash_pointer == *target_pointer;
    }
    delete[] hash;
    return is_password_found;
}
