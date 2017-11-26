//
// Created by aurelien on 16/09/17.
//

#ifndef SHACKER_SHA256_H
#define SHACKER_SHA256_H

    #include<string>
    #include <cstring>
    #include <iomanip>
    #include<openssl/sha.h>

    const unsigned char* hex_string_to_bytes(char* hex_string);
    std::string bytes_to_hex_string(long long* bytes, unsigned int bytes_length);
    unsigned char* sha256(std::string& data);
    bool sha256_compare(std::string& data, const unsigned char* target);

#endif //SHACKER_SHA256_H
