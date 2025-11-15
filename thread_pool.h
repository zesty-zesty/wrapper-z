#pragma once

#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>

typedef void (*tp_task_fn)(void *arg);

typedef struct tp_task {
    tp_task_fn fn;
    void *arg;
    struct tp_task *next;
} tp_task;

typedef struct thread_pool {
    pthread_t *threads;
    size_t nthreads;

    pthread_mutex_t mtx;
    pthread_cond_t cv;

    tp_task *head;
    tp_task *tail;

    atomic_int stop;
} thread_pool;

// Create a thread pool with n worker threads. Returns NULL on failure.
thread_pool *thread_pool_create(size_t nthreads);

// Submit a task. Returns 0 on success, non-zero on failure or when stopping.
int thread_pool_submit(thread_pool *pool, tp_task_fn fn, void *arg);

// Signal shutdown; when wait is non-zero, join all workers.
void thread_pool_shutdown(thread_pool *pool, int wait);

// Destroy and free all resources. Call after shutdown(wait=1).
void thread_pool_destroy(thread_pool *pool);