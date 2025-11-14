#include "thread_pool.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    void (*fn)(void *);
    void *arg;
} pool_job;

struct thread_pool {
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    pool_job *jobs;
    int capacity;
    int size;
    int head;
    int tail;
    int shutdown;
    pthread_t *threads;
    int num_threads;
};

static void *worker_loop(void *arg) {
    struct thread_pool *pool = (struct thread_pool *)arg;
#ifdef __APPLE__
    pthread_setname_np("tp-worker");
#endif
    for (;;) {
        pthread_mutex_lock(&pool->mutex);
        while (pool->size == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->not_empty, &pool->mutex);
        }
        if (pool->shutdown && pool->size == 0) {
            pthread_mutex_unlock(&pool->mutex);
            break;
        }
        pool_job job = pool->jobs[pool->head];
        pool->head = (pool->head + 1) % pool->capacity;
        pool->size--;
        pthread_cond_signal(&pool->not_full);
        pthread_mutex_unlock(&pool->mutex);
        job.fn(job.arg);
    }
    return NULL;
}

thread_pool *thread_pool_create(int num_threads, int max_queue) {
    struct thread_pool *pool = (struct thread_pool *)malloc(sizeof(struct thread_pool));
    if (!pool) return NULL;
    memset(pool, 0, sizeof(*pool));
    pthread_mutex_init(&pool->mutex, NULL);
    pthread_cond_init(&pool->not_empty, NULL);
    pthread_cond_init(&pool->not_full, NULL);
    pool->capacity = max_queue;
    pool->jobs = (pool_job *)malloc(sizeof(pool_job) * pool->capacity);
    if (!pool->jobs) {
        free(pool);
        return NULL;
    }
    pool->threads = (pthread_t *)malloc(sizeof(pthread_t) * num_threads);
    if (!pool->threads) {
        free(pool->jobs);
        free(pool);
        return NULL;
    }
    pool->num_threads = num_threads;
    for (int i = 0; i < num_threads; ++i) {
        pthread_create(&pool->threads[i], NULL, worker_loop, pool);
    }
    return pool;
}

int thread_pool_enqueue(thread_pool *pool, void (*fn)(void *), void *arg) {
    if (!pool || !fn) return 0;
    pthread_mutex_lock(&pool->mutex);
    if (pool->shutdown) {
        pthread_mutex_unlock(&pool->mutex);
        return 0;
    }
    while (pool->size == pool->capacity && !pool->shutdown) {
        pthread_cond_wait(&pool->not_full, &pool->mutex);
    }
    if (pool->shutdown) {
        pthread_mutex_unlock(&pool->mutex);
        return 0;
    }
    pool->jobs[pool->tail].fn = fn;
    pool->jobs[pool->tail].arg = arg;
    pool->tail = (pool->tail + 1) % pool->capacity;
    pool->size++;
    pthread_cond_signal(&pool->not_empty);
    pthread_mutex_unlock(&pool->mutex);
    return 1;
}

void thread_pool_shutdown(thread_pool *pool) {
    if (!pool) return;
    pthread_mutex_lock(&pool->mutex);
    pool->shutdown = 1;
    pthread_cond_broadcast(&pool->not_empty);
    pthread_cond_broadcast(&pool->not_full);
    pthread_mutex_unlock(&pool->mutex);
    for (int i = 0; i < pool->num_threads; ++i) {
        pthread_join(pool->threads[i], NULL);
    }
    free(pool->threads);
    free(pool->jobs);
    pthread_mutex_destroy(&pool->mutex);
    pthread_cond_destroy(&pool->not_empty);
    pthread_cond_destroy(&pool->not_full);
    free(pool);
}