#include <stdint.h>
#include <stddef.h>
#include <string.h>

struct shared_ptr {
    void *obj;
    void *ctrl_blk;
};

union std_string {
    struct {
        uint8_t mark;
        char str[0];
    } short_mode;
    struct {
        size_t cap;
        size_t size;
        const char *data;
    } long_mode;
};

struct std_vector {
    void *begin;
    void *end;
    void *end_capacity;
};

static inline union std_string new_std_string(const char *s) {
    union std_string str = {
        .long_mode = {
            .cap = 1,
            .size = strlen(s),
            .data = s,
        },
    };
    return str;
}

static inline struct std_vector new_std_vector(void *begin) {
    struct std_vector vector = {
        .begin = begin,
        .end = (void *)((char *)begin + 1),
    };
    vector.end_capacity = vector.end;
    return vector;
}

static inline union std_string new_std_string_short_mode(const char *str) {
    union std_string std_str = {
        .long_mode = {
            .cap = 1,
            .size = strlen(str),
            .data = str,
        },
    };
    return std_str;
}

static inline const char *std_string_data(union std_string *str) {
    if ((str->short_mode.mark & 1) == 0) {
        return str->short_mode.str;
    }
    return str->long_mode.data;
}