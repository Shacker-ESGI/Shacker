//
// Created by aurelien on 16/09/17.
//

#ifndef SHACKER_LOGGER_H
#define SHACKER_LOGGER_H

#include <iostream>
#include <sstream>
#include <string>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>

    class Logger {
    public:
        Logger(): mutex() {}

        void error(const std::ostream &message) {
            write(std::stringstream() << "[ERROR] " << message.rdbuf());
        }

        void info(const std::ostream &message) {
            write(std::stringstream() << "[INFO] " << message.rdbuf());
        }

        void debug(const std::ostream &message) {
            #ifndef NDEBUG
                    write(std::stringstream() << "[DEBUG] " << message.rdbuf());
            #endif
        }

    private:
        std::mutex mutex;

        void write(const std::ostream &message) {
            std::lock_guard<std::mutex> lock(mutex);
            std::cout << message.rdbuf() << std::endl;
        }

    };

#endif //SHACKER_LOGGER_H
