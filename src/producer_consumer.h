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
        std::function<void(uint, uint, bool&, std::condition_variable&, std::mutex&, std::queue<T>&)> producer_func;
        uint max_consumer_threads;
        uint max_producer_threads;
        std::promise<T> promise;
        bool hasAnswer;
        std::condition_variable has_available_data;
        std::mutex mutex;

    public:

        ProducerConsumer(std::function<void(uint, uint, bool&, std::condition_variable&, std::mutex&, std::queue<T>&)> producer_func,
                         std::function<bool(T)> consumer_func) {
            this->producer_func = producer_func;
            this->consumer_func = consumer_func;
            this->hasAnswer = false;
            this->max_producer_threads = std::thread::hardware_concurrency() / 4;
            this->max_consumer_threads = std::thread::hardware_concurrency() / 4;
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
                producer_threads.emplace_front(std::thread(&ProducerConsumer::produce, this, i, max_producer_threads));
            }

            for(uint i = 0 ; i < max_consumer_threads ; i++) {
                consumer_threads.emplace_front(std::thread(&ProducerConsumer::consume, this));
            }
        }

        void produce(uint thread_index, uint max_threads) {
            producer_func(thread_index, max_threads, hasAnswer, has_available_data, mutex, available_data);
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