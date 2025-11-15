#include "thread_pool.h"
#include <stdlib.h>
#include <errno.h>

static void *worker_main(void *arg) {
    thread_pool *pool = (thread_pool *)arg;
    for (;;) {
        pthread_mutex_lock(&pool->mtx);
        while (pool->head == NULL && atomic_load(&pool->stop) == 0) {
            pthread_cond_wait(&pool->cv, &pool->mtx);
        }

        if (pool->head == NULL && atomic_load(&pool->stop) != 0) {
            pthread_mutex_unlock(&pool->mtx);
            break;
        }

        tp_task *task = pool->head;
        if (task) {
            pool->head = task->next;
            if (pool->head == NULL) {
                pool->tail = NULL;
            }
        }
        pthread_mutex_unlock(&pool->mtx);

        if (task) {
            tp_task_fn fn = task->fn;
            void *targ = task->arg;
            free(task);
            if (fn) {
                fn(targ);
            }
        }
    }
    return NULL;
}

thread_pool *thread_pool_create(size_t nthreads) {
    if (nthreads == 0) {
        errno = EINVAL;
        return NULL;
    }
    thread_pool *pool = (thread_pool *)calloc(1, sizeof(thread_pool));
    if (!pool) return NULL;

    pool->threads = (pthread_t *)calloc(nthreads, sizeof(pthread_t));
    if (!pool->threads) {
        free(pool);
        return NULL;
    }
    pool->nthreads = nthreads;
    pthread_mutex_init(&pool->mtx, NULL);
    pthread_cond_init(&pool->cv, NULL);
    pool->head = pool->tail = NULL;
    atomic_store(&pool->stop, 0);

    for (size_t i = 0; i < nthreads; ++i) {
        if (pthread_create(&pool->threads[i], NULL, worker_main, pool) != 0) {
            atomic_store(&pool->stop, 1);
            // join already-started threads
            for (size_t j = 0; j < i; ++j) {
                pthread_cond_broadcast(&pool->cv);
                pthread_join(pool->threads[j], NULL);
            }
            pthread_cond_destroy(&pool->cv);
            pthread_mutex_destroy(&pool->mtx);
            free(pool->threads);
            free(pool);
            return NULL;
        }
    }
    return pool;
}

int thread_pool_submit(thread_pool *pool, tp_task_fn fn, void *arg) {
    if (!pool || !fn) return EINVAL;
    if (atomic_load(&pool->stop) != 0) return EBUSY;

    tp_task *task = (tp_task *)malloc(sizeof(tp_task));
    if (!task) return ENOMEM;
    task->fn = fn;
    task->arg = arg;
    task->next = NULL;

    pthread_mutex_lock(&pool->mtx);
    if (pool->tail) {
        pool->tail->next = task;
        pool->tail = task;
    } else {
        pool->head = pool->tail = task;
    }
    pthread_cond_signal(&pool->cv);
    pthread_mutex_unlock(&pool->mtx);
    return 0;
}

void thread_pool_shutdown(thread_pool *pool, int wait) {
    if (!pool) return;
    atomic_store(&pool->stop, 1);
    pthread_mutex_lock(&pool->mtx);
    pthread_cond_broadcast(&pool->cv);
    pthread_mutex_unlock(&pool->mtx);
    if (wait) {
        for (size_t i = 0; i < pool->nthreads; ++i) {
            pthread_join(pool->threads[i], NULL);
        }
    }
}

void thread_pool_destroy(thread_pool *pool) {
    if (!pool) return;
    // free any remaining tasks
    pthread_mutex_lock(&pool->mtx);
    tp_task *t = pool->head;
    while (t) {
        tp_task *next = t->next;
        free(t);
        t = next;
    }
    pool->head = pool->tail = NULL;
    pthread_mutex_unlock(&pool->mtx);

    pthread_cond_destroy(&pool->cv);
    pthread_mutex_destroy(&pool->mtx);
    free(pool->threads);
    free(pool);
}