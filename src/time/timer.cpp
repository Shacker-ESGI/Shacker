#include "timer.h"

double timer_start(){
    return omp_get_wtime();;
}

// call this function to end a timer, returning nanoseconds elapsed as a long
double timer_end(double start_time){
    double stop_time = timer_start();
    return stop_time - start_time;
}