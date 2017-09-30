cmake_minimum_required(VERSION 3.0)
project(shacker)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -g -fdiagnostics-color=auto -fmax-errors=2 -std=c++11")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -fmax-errors=2")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")

set(SOURCE_FILES src/main.cpp src/crypto/sha256.cpp src/crypto/sha256.h src/log/logger.h src/time/timer.cpp src/time/timer.h src/producer_consumer.h src/bruteforce/bruteforce.cpp src/bruteforce/bruteforce.h)

add_executable(main ${SOURCE_FILES})

find_package(Threads)

find_package(OpenSSL REQUIRED)

target_link_libraries(main ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES})
