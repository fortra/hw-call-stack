#pragma once

#include <windows.h>
#include <stdio.h>

#define PRINT(...) { \
 fprintf(stdout, __VA_ARGS__); \
 fprintf(stdout, "\n"); \
}

#define PRINT_ERR(...) { \
 fprintf(stdout, __VA_ARGS__); \
 fprintf(stdout, "\n"); \
}

#if defined(DEBUG)
 #define DPRINT(...) { \
     fprintf(stderr, "DEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     fprintf(stderr, __VA_ARGS__); \
     fprintf(stderr, "\n"); \
 }
#else
 #define DPRINT(...)
#endif

#if defined(DEBUG)
 #define DPRINT_ERR(...) { \
     fprintf(stderr, "ERROR: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     fprintf(stderr, __VA_ARGS__); \
     fprintf(stderr, "\n"); \
 }
#else
 #define DPRINT_ERR(...)
#endif

#define syscall_failed(syscall_name, status) \
    DPRINT_ERR( \
        "Failed to call %s, status: 0x%lx", \
        syscall_name, \
        status \
    )

#define function_failed(function) \
    DPRINT_ERR( \
        "Call to '%s' failed, error: %ld", \
        function, \
        GetLastError() \
    )

#define malloc_failed() function_failed("HeapAlloc")

#define api_not_found(function) \
    DPRINT_ERR( \
        "The address of '%s' was not found", \
        function \
    )
