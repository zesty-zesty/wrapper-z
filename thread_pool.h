#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <pthread.h>

// 任务结构体
typedef struct {
    void (*function)(void *arg);
    void *argument;
} thread_task_t;

// 线程池结构体
typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t notify;
    pthread_t *threads;
    thread_task_t *queue;
    int thread_count;
    int queue_size;
    int head;
    int tail;
    int count;
    int shutdown;
    int started;
} thread_pool_t;

// 创建线程池
thread_pool_t *thread_pool_create(int thread_count, int queue_size);

// 添加任务到线程池
int thread_pool_add(thread_pool_t *pool, void (*function)(void *), void *argument);

// 销毁线程池
int thread_pool_destroy(thread_pool_t *pool);

#endif // THREAD_POOL_H