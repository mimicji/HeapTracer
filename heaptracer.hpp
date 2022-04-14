#ifndef __HEAPTRACER_HPP__
#define __HEAPTRACER_HPP__

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drx.h"
#include "dr_defines.h"
#include "drsyms.h"
#include "drwrap.h"
#include "drcallstack.h"


#define PROJECT_NAME "HeapTracer"

#ifdef WINDOWS
#    define IF_WINDOWS(x) x
#    define IF_UNIX_ELSE(x, y) y
#    define IF_WINDOWS_ELSE(x, y) x
#else
#    define IF_WINDOWS(x)
#    define IF_UNIX_ELSE(x, y) x
#    define IF_WINDOWS_ELSE(x, y) y
#endif

#define BUFFER_SIZE_BYTES(buf) sizeof(buf)
#define BUFFER_SIZE_ELEMENTS(buf) (BUFFER_SIZE_BYTES(buf) / sizeof(buf[0]))
#define BUFFER_LAST_ELEMENT(buf) buf[BUFFER_SIZE_ELEMENTS(buf) - 1]
#define NULL_TERMINATE_BUFFER(buf) BUFFER_LAST_ELEMENT(buf) = 0

#ifndef LOG
#define LOG(...) {printf("[%s] ", PROJECT_NAME);printf(__VA_ARGS__); printf("\n");}
#endif
#ifndef DIE
#define DIE() {printf("[%s] ", PROJECT_NAME); printf("Abort at %s:%d\n", __FILE__, __LINE__); exit(1);}
#endif

#define MAX_SYM_RESULT 256
#define MAX_FILE_PATH 256

#define MALLOC_NAME IF_WINDOWS_ELSE("HeapAlloc", "malloc")
#define FREE_NAME IF_WINDOWS_ELSE("HeapFree", "free")

typedef struct _tls_t
{
    file_t call_trace_file;
    file_t heap_trace_file;
    int64_t stack_depth;
    u_int64_t alloc_cnt;
    u_int64_t free_cnt;
} tls_t;


#endif // __HEAPTRACER_HPP__