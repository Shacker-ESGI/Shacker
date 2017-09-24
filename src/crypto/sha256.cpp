//
// Created by aurelien on 16/09/17.
//
#include "sha256.h"

std::string sha256(std::string data) {

    const char* data_string = data.c_str();
    const char digest_string[SHA256_DIGEST_LENGTH] = "";
    std::string output("");

    SHA256((unsigned char*) data_string, data.length(), (unsigned char*) &digest_string);

    char hex[3];

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex, "%02x", (unsigned int) digest_string[i]);
        output += hex;
    }
    return output;
}