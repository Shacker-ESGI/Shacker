cmake_minimum_required(VERSION 3.0)
project(shacker)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -g -fdiagnostics-color=auto -fmax-errors=2 -std=c++11")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -O0 -no-pie -pg")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DRELEASE -O3")

file(GLOB_RECURSE SOURCE_FILES "src/*.cpp" "src/*.h")

add_executable(main ${SOURCE_FILES})

find_package(Threads)

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

target_link_libraries(main ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES})
