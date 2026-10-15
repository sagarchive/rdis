"""System type library: prototypes of common libc, POSIX, CoreFoundation and Objective-C runtime APIs.

Used to type what flows into and out of calls: a parameter passed straight to `strlen` is a
`char *`, `malloc`'s result is a `void *`, `printf` takes a format then varargs. Types are written
with built-in C types only (opaque handles such as FILE * and CFTypeRef become `void *`), so the
decompiled output stays self-contained and compiles without headers.

    proto(name) -> (return type, [parameter types], variadic) or None
"""
_P = {
    # strings and memory
    "strlen": ("uint64_t", ["char *"]), "strnlen": ("uint64_t", ["char *", "uint64_t"]),
    "strcmp": ("int32_t", ["char *", "char *"]), "strncmp": ("int32_t", ["char *", "char *", "uint64_t"]),
    "strcasecmp": ("int32_t", ["char *", "char *"]), "strncasecmp": ("int32_t", ["char *", "char *", "uint64_t"]),
    "strcpy": ("char *", ["char *", "char *"]), "strncpy": ("char *", ["char *", "char *", "uint64_t"]),
    "strlcpy": ("uint64_t", ["char *", "char *", "uint64_t"]), "strlcat": ("uint64_t", ["char *", "char *", "uint64_t"]),
    "strcat": ("char *", ["char *", "char *"]), "strncat": ("char *", ["char *", "char *", "uint64_t"]),
    "strchr": ("char *", ["char *", "int32_t"]), "strrchr": ("char *", ["char *", "int32_t"]),
    "strstr": ("char *", ["char *", "char *"]), "strcasestr": ("char *", ["char *", "char *"]),
    "strdup": ("char *", ["char *"]), "strndup": ("char *", ["char *", "uint64_t"]),
    "strtok": ("char *", ["char *", "char *"]), "strtok_r": ("char *", ["char *", "char *", "char **"]),
    "strsep": ("char *", ["char **", "char *"]), "strerror": ("char *", ["int32_t"]),
    "strspn": ("uint64_t", ["char *", "char *"]), "strcspn": ("uint64_t", ["char *", "char *"]),
    "strpbrk": ("char *", ["char *", "char *"]),
    "memcpy": ("void *", ["void *", "void *", "uint64_t"]), "memmove": ("void *", ["void *", "void *", "uint64_t"]),
    "memset": ("void *", ["void *", "int32_t", "uint64_t"]), "memcmp": ("int32_t", ["void *", "void *", "uint64_t"]),
    "memchr": ("void *", ["void *", "int32_t", "uint64_t"]), "bzero": ("void", ["void *", "uint64_t"]),
    "__memcpy_chk": ("void *", ["void *", "void *", "uint64_t", "uint64_t"]),
    "__memset_chk": ("void *", ["void *", "int32_t", "uint64_t", "uint64_t"]),
    "__strcpy_chk": ("char *", ["char *", "char *", "uint64_t"]),
    "__strlcpy_chk": ("uint64_t", ["char *", "char *", "uint64_t", "uint64_t"]),
    "__strlcat_chk": ("uint64_t", ["char *", "char *", "uint64_t", "uint64_t"]),
    # conversion and ctype
    "atoi": ("int32_t", ["char *"]), "atol": ("int64_t", ["char *"]), "atof": ("double", ["char *"]),
    "strtol": ("int64_t", ["char *", "char **", "int32_t"]), "strtoul": ("uint64_t", ["char *", "char **", "int32_t"]),
    "strtoll": ("int64_t", ["char *", "char **", "int32_t"]), "strtoull": ("uint64_t", ["char *", "char **", "int32_t"]),
    "strtod": ("double", ["char *", "char **"]), "toupper": ("int32_t", ["int32_t"]), "tolower": ("int32_t", ["int32_t"]),
    "isalpha": ("int32_t", ["int32_t"]), "isdigit": ("int32_t", ["int32_t"]), "isspace": ("int32_t", ["int32_t"]),
    "isprint": ("int32_t", ["int32_t"]), "isalnum": ("int32_t", ["int32_t"]),
    # allocation and process
    "malloc": ("void *", ["uint64_t"]), "calloc": ("void *", ["uint64_t", "uint64_t"]),
    "realloc": ("void *", ["void *", "uint64_t"]), "reallocf": ("void *", ["void *", "uint64_t"]),
    "free": ("void", ["void *"]), "valloc": ("void *", ["uint64_t"]),
    "posix_memalign": ("int32_t", ["void **", "uint64_t", "uint64_t"]),
    "exit": ("void", ["int32_t"]), "_exit": ("void", ["int32_t"]), "abort": ("void", []),
    "atexit": ("int32_t", ["void *"]), "getenv": ("char *", ["char *"]),
    "setenv": ("int32_t", ["char *", "char *", "int32_t"]), "unsetenv": ("int32_t", ["char *"]),
    "system": ("int32_t", ["char *"]), "getpid": ("int32_t", []), "getuid": ("uint32_t", []),
    "geteuid": ("uint32_t", []), "fork": ("int32_t", []), "sleep": ("uint32_t", ["uint32_t"]),
    "usleep": ("int32_t", ["uint32_t"]), "qsort": ("void", ["void *", "uint64_t", "uint64_t", "void *"]),
    "bsearch": ("void *", ["void *", "void *", "uint64_t", "uint64_t", "void *"]),
    "rand": ("int32_t", []), "srand": ("void", ["uint32_t"]), "random": ("int64_t", []),
    "arc4random": ("uint32_t", []), "arc4random_uniform": ("uint32_t", ["uint32_t"]),
    "time": ("int64_t", ["int64_t *"]), "__error": ("int32_t *", []), "__errno_location": ("int32_t *", []),
    "__stack_chk_fail": ("void", []), "__assert_rtn": ("void", ["char *", "char *", "int32_t", "char *"]),
    # stdio (FILE * is opaque here)
    "printf": ("int32_t", ["char *"], True), "fprintf": ("int32_t", ["void *", "char *"], True),
    "sprintf": ("int32_t", ["char *", "char *"], True), "snprintf": ("int32_t", ["char *", "uint64_t", "char *"], True),
    "asprintf": ("int32_t", ["char **", "char *"], True), "dprintf": ("int32_t", ["int32_t", "char *"], True),
    "__sprintf_chk": ("int32_t", ["char *", "int32_t", "uint64_t", "char *"], True),
    "__snprintf_chk": ("int32_t", ["char *", "uint64_t", "int32_t", "uint64_t", "char *"], True),
    "sscanf": ("int32_t", ["char *", "char *"], True), "scanf": ("int32_t", ["char *"], True),
    "puts": ("int32_t", ["char *"]), "fputs": ("int32_t", ["char *", "void *"]), "putchar": ("int32_t", ["int32_t"]),
    "fputc": ("int32_t", ["int32_t", "void *"]), "putc": ("int32_t", ["int32_t", "void *"]),
    "getchar": ("int32_t", []), "fgetc": ("int32_t", ["void *"]), "getc": ("int32_t", ["void *"]),
    "fgets": ("char *", ["char *", "int32_t", "void *"]), "fopen": ("void *", ["char *", "char *"]),
    "fdopen": ("void *", ["int32_t", "char *"]), "fclose": ("int32_t", ["void *"]), "fflush": ("int32_t", ["void *"]),
    "fread": ("uint64_t", ["void *", "uint64_t", "uint64_t", "void *"]),
    "fwrite": ("uint64_t", ["void *", "uint64_t", "uint64_t", "void *"]),
    "fseek": ("int32_t", ["void *", "int64_t", "int32_t"]), "ftell": ("int64_t", ["void *"]),
    "fileno": ("int32_t", ["void *"]), "perror": ("void", ["char *"]), "setvbuf": ("int32_t", ["void *", "char *", "int32_t", "uint64_t"]),
    "getline": ("int64_t", ["char **", "uint64_t *", "void *"]), "remove": ("int32_t", ["char *"]),
    "rename": ("int32_t", ["char *", "char *"]),
    "err": ("void", ["int32_t", "char *"], True), "errx": ("void", ["int32_t", "char *"], True),
    "warn": ("void", ["char *"], True), "warnx": ("void", ["char *"], True),
    # POSIX files, processes, sockets
    "open": ("int32_t", ["char *", "int32_t"], True), "close": ("int32_t", ["int32_t"]),
    "read": ("int64_t", ["int32_t", "void *", "uint64_t"]), "write": ("int64_t", ["int32_t", "void *", "uint64_t"]),
    "lseek": ("int64_t", ["int32_t", "int64_t", "int32_t"]), "unlink": ("int32_t", ["char *"]),
    "access": ("int32_t", ["char *", "int32_t"]), "stat": ("int32_t", ["char *", "void *"]),
    "lstat": ("int32_t", ["char *", "void *"]), "fstat": ("int32_t", ["int32_t", "void *"]),
    "mkdir": ("int32_t", ["char *", "uint16_t"]), "rmdir": ("int32_t", ["char *"]), "chdir": ("int32_t", ["char *"]),
    "getcwd": ("char *", ["char *", "uint64_t"]), "realpath": ("char *", ["char *", "char *"]),
    "opendir": ("void *", ["char *"]), "readdir": ("void *", ["void *"]), "closedir": ("int32_t", ["void *"]),
    "dup": ("int32_t", ["int32_t"]), "dup2": ("int32_t", ["int32_t", "int32_t"]), "pipe": ("int32_t", ["int32_t *"]),
    "execv": ("int32_t", ["char *", "char **"]), "execvp": ("int32_t", ["char *", "char **"]),
    "waitpid": ("int32_t", ["int32_t", "int32_t *", "int32_t"]), "kill": ("int32_t", ["int32_t", "int32_t"]),
    "ioctl": ("int32_t", ["int32_t", "uint64_t"], True), "fcntl": ("int32_t", ["int32_t", "int32_t"], True),
    "mmap": ("void *", ["void *", "uint64_t", "int32_t", "int32_t", "int32_t", "int64_t"]),
    "munmap": ("int32_t", ["void *", "uint64_t"]), "isatty": ("int32_t", ["int32_t"]),
    "socket": ("int32_t", ["int32_t", "int32_t", "int32_t"]), "connect": ("int32_t", ["int32_t", "void *", "uint32_t"]),
    "bind": ("int32_t", ["int32_t", "void *", "uint32_t"]), "listen": ("int32_t", ["int32_t", "int32_t"]),
    "accept": ("int32_t", ["int32_t", "void *", "uint32_t *"]),
    "send": ("int64_t", ["int32_t", "void *", "uint64_t", "int32_t"]), "recv": ("int64_t", ["int32_t", "void *", "uint64_t", "int32_t"]),
    "getopt": ("int32_t", ["int32_t", "char **", "char *"]),
    "getopt_long": ("int32_t", ["int32_t", "char **", "char *", "void *", "int32_t *"]),
    "setlocale": ("char *", ["int32_t", "char *"]), "dlopen": ("void *", ["char *", "int32_t"]),
    "dlsym": ("void *", ["void *", "char *"]), "dlclose": ("int32_t", ["void *"]), "dlerror": ("char *", []),
    # threads
    "pthread_create": ("int32_t", ["void *", "void *", "void *", "void *"]),
    "pthread_join": ("int32_t", ["void *", "void **"]),
    "pthread_mutex_lock": ("int32_t", ["void *"]), "pthread_mutex_unlock": ("int32_t", ["void *"]),
    "pthread_mutex_init": ("int32_t", ["void *", "void *"]), "pthread_once": ("int32_t", ["void *", "void *"]),
    "os_unfair_lock_lock": ("void", ["void *"]), "os_unfair_lock_unlock": ("void", ["void *"]),
    "dispatch_once": ("void", ["int64_t *", "void *"]), "dispatch_async": ("void", ["void *", "void *"]),
    "dispatch_sync": ("void", ["void *", "void *"]), "dispatch_get_global_queue": ("void *", ["int64_t", "uint64_t"]),
    "dispatch_queue_create": ("void *", ["char *", "void *"]),
    # Objective-C runtime
    "objc_msgSend": ("void *", ["void *", "void *"], True), "objc_msgSendSuper2": ("void *", ["void *", "void *"], True),
    "objc_retain": ("void *", ["void *"]), "objc_release": ("void", ["void *"]),
    "objc_autorelease": ("void *", ["void *"]), "objc_retainAutorelease": ("void *", ["void *"]),
    "objc_retainAutoreleasedReturnValue": ("void *", ["void *"]),
    "objc_autoreleaseReturnValue": ("void *", ["void *"]), "objc_alloc": ("void *", ["void *"]),
    "objc_alloc_init": ("void *", ["void *"]), "objc_opt_new": ("void *", ["void *"]),
    "objc_opt_class": ("void *", ["void *"]), "objc_storeStrong": ("void", ["void **", "void *"]),
    "objc_autoreleasePoolPush": ("void *", []), "objc_autoreleasePoolPop": ("void", ["void *"]),
    "objc_enumerationMutation": ("void", ["void *"]), "objc_getClass": ("void *", ["char *"]),
    "sel_registerName": ("void *", ["char *"]), "NSLog": ("void", ["void *"], True),
    # CoreFoundation (CFTypeRef and friends are opaque pointers)
    "CFRelease": ("void", ["void *"]), "CFRetain": ("void *", ["void *"]),
    "CFStringCreateWithCString": ("void *", ["void *", "char *", "uint32_t"]),
    "CFStringGetCString": ("uint8_t", ["void *", "char *", "int64_t", "uint32_t"]),
    "CFDictionaryGetValue": ("void *", ["void *", "void *"]), "CFArrayGetCount": ("int64_t", ["void *"]),
    "CFArrayGetValueAtIndex": ("void *", ["void *", "int64_t"]), "CFGetTypeID": ("uint64_t", ["void *"]),
    "CFPreferencesGetAppBooleanValue": ("uint8_t", ["void *", "void *", "uint8_t *"]),
}


def _norm(name):
    n = (name or "").split("@")[0].split("$")[0]
    return n


def proto(name):
    """(return type, parameter types, variadic) for a known API, or None. Mach-O C symbols carry a
    leading underscore (`_strlen`); both spellings are accepted."""
    n = _norm(name)
    for k in (n, n[1:] if n.startswith("_") else None):
        if k and k in _P:
            e = _P[k]
            return e[0], list(e[1]), bool(e[2]) if len(e) > 2 else False
    return None


def _check():
    assert proto("_strlen") == ("uint64_t", ["char *"], False)
    assert proto("printf")[2] is True and proto("_malloc")[0] == "void *"
    assert proto("__stack_chk_fail")[0] == "void" and proto("nope") is None


if __name__ == "__main__":
    _check()
    print(len(_P), "prototypes")
