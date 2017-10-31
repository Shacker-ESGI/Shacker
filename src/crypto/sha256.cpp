//
// Created by aurelien on 16/09/17.
//
#include <sstream>
#include "sha256.h"

std::string sha256(std::string data) {

    const char* data_string = data.c_str();
    char digest_string[SHA256_DIGEST_LENGTH + 1] = "";

    SHA256((unsigned char*) data_string, data.length(), (unsigned char*) &digest_string);

    return std::string(digest_string);
}
