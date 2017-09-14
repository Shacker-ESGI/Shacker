#include <iostream>
#include <sstream>
#include <string>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <cassert>

class Logger {
public: 
    Logger(): mutex() {}

    void info(const std::ostream &message) {
        std::lock_guard<std::mutex> lock(mutex);
        std::cout << message.rdbuf() << std::endl;
    }

    void debug(const std::ostream &message) {
        #ifndef NDEBUG
        info(message);
        #endif
    }

private:
    std::mutex mutex;
};


int main() {
    Logger logger;
    logger.info(std::stringstream() << "Shacker initialized!");
	return 0;
}
