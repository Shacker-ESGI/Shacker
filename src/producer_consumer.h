#include <iostream>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <cassert>
#include "log/logger.h"

template <typename T>
class ProducerConsumer {

    private:
        std::queue<T> available_data;
        std::deque<std::thread> consumer_threads;
        std::deque<std::thread> producer_threads;
        std::function<bool(T)> consumer_func;
        std::function<T()> producer_func;
        uint max_consumer_threads;
        uint max_producer_threads;
        std::promise<T> promise;
        bool hasAnswer;
        std::condition_variable has_available_data;
        std::mutex mutex;

    public:

        ProducerConsumer(std::function<T()> producer_func, std::function<bool(T)> consumer_func) {
            this->producer_func = producer_func;
            this->consumer_func = consumer_func;
            this->hasAnswer = false;
            this->max_producer_threads = std::thread::hardware_concurrency();
            this->max_consumer_threads = std::thread::hardware_concurrency();
        }

        ~ProducerConsumer() {
            for(uint i = 0 ; i < max_producer_threads ; i++) {
                producer_threads[i].join();
            }

            for(uint i = 0 ; i < max_consumer_threads ; i++) {
                consumer_threads[i].join();
            }
        }

        T getAnswer() {
            return promise.get_future().get();
        }

        void process() {
            for(uint i = 0 ; i < max_producer_threads ; i++) {
                producer_threads.emplace_front(std::thread(&ProducerConsumer::produce, this));
            }

            for(uint i = 0 ; i < max_consumer_threads ; i++) {
                consumer_threads.emplace_front(std::thread(&ProducerConsumer::consume, this));
            }
        }

        void produce() {
            static Logger logger;
            while(!hasAnswer) {
                T data = producer_func();
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    available_data.push(data);
                }
                has_available_data.notify_one();
            }
        }

        void consume() {
            static Logger logger;
            while(!hasAnswer) {
                {
                    std::unique_lock<std::mutex> lock(mutex);

                    has_available_data.wait(lock, [&] {
                        return !available_data.empty() || hasAnswer;
                    });

                    if(!hasAnswer) {
                        T data = available_data.front();

                        if (consumer_func(data)) {
                            hasAnswer = true;
                            promise.set_value(data);
                        }

                        available_data.pop();
                    }

                }
            }
        }

};