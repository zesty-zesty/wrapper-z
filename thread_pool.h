#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <pthread.h>

typedef struct thread_pool thread_pool;

thread_pool *thread_pool_create(int num_threads, int max_queue);
int thread_pool_enqueue(thread_pool *pool, void (*fn)(void *), void *arg);
void thread_pool_shutdown(thread_pool *pool);

#endif