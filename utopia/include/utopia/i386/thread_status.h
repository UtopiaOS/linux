/* Types for mini thread */

#include <utopia/minithread.h>

typedef struct x86_thread_state64 x86_thread_state64_t;
typedef struct x86_thread_state32 x86_thread_state32_t;

typedef struct i386_float_state x86_float_state32_t;
typedef struct x86_float_state64 x86_float_state64_t;

#define x86_THREAD_STATE64_COUNT ((uint32_t)(sizeof(x86_thread_state64_t) / sizeof(int)))
#define x86_THREAD_STATE32_COUNT ((uint32_t)(sizeof(x86_thread_state32_t) / sizeof(int)))

#define x86_FLOAT_STATE32_COUNT ((uint32_t)(sizeof(x86_float_state32_t) / sizeof(unsigned int)))
#define x86_FLOAT_STATE64_COUNT ((uint32_t)(sizeof(x86_float_state64_t) / sizeof(unsigned int)))