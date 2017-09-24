//
// Created by aurelien on 16/09/17.
//

#ifndef SHACKER_SHA256_H
#define SHACKER_SHA256_H

    #include<string>
    #include<openssl/sha.h>

    std::string sha256(std::string data);

#endif //SHACKER_SHA256_H
