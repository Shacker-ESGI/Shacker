#include "timer.h"

clock_t timer_start(){
    return clock();
}

// call this function to end a timer, returning nanoseconds elapsed as a long
float timer_end(clock_t start_time){
    clock_t stop_time = clock();
    return (float)(stop_time - start_time) / (float)CLOCKS_PER_SEC;
}