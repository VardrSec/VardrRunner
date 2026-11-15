/* Deterministic synthetic-path substitution at an ACL call boundary.
 * Test-only preload; never installed in runtime images. */
#define _GNU_SOURCE
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <attr/libattr.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void swap_paths(const char *operation, acl_type_t type)
{
    static int swapped;
    const char *mode = getenv("VARDR_ACL_SWAP_MODE");
    if (swapped || !mode || strcmp(mode, operation) || type != ACL_TYPE_DEFAULT)
        return;
    swapped = 1;
    const char *names[] = {"SRC", "DST"};
    for (size_t i = 0; i < 2; i++) {
        char key[64], saved[4096];
        snprintf(key, sizeof key, "VARDR_ACL_SWAP_%s", names[i]);
        const char *path = getenv(key);
        if (!path)
            continue;
        snprintf(key, sizeof key, "VARDR_ACL_OUTSIDE_%s", names[i]);
        const char *outside = getenv(key);
        if (!outside || snprintf(saved, sizeof saved, "%s.saved", path) >= (int)sizeof saved
            || rename(path, saved) || symlink(outside, path))
            _exit(90);
    }
    const char *marker = getenv("VARDR_ACL_SWAP_MARKER");
    if (!marker)
        _exit(91);
    int fd = open(marker, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0 || close(fd))
        _exit(92);
}

acl_t acl_get_file(const char *path, acl_type_t type)
{
    acl_t (*next)(const char *, acl_type_t) = dlsym(RTLD_NEXT, "acl_get_file");
    swap_paths("read", type);
    return next(path, type);
}

acl_t acl_get_file_at(int fd, const char *path, int flags, acl_type_t type)
{
    acl_t (*next)(int, const char *, int, acl_type_t) = dlsym(RTLD_NEXT, "acl_get_file_at");
    swap_paths("read", type);
    return next(fd, path, flags, type);
}

int acl_set_file(const char *path, acl_type_t type, acl_t acl)
{
    int (*next)(const char *, acl_type_t, acl_t) = dlsym(RTLD_NEXT, "acl_set_file");
    swap_paths("write", type);
    return next(path, type, acl);
}

int acl_set_file_at(int fd, const char *path, int flags, acl_type_t type, acl_t acl)
{
    int (*next)(int, const char *, int, acl_type_t, acl_t) = dlsym(RTLD_NEXT, "acl_set_file_at");
    swap_paths("write", type);
    return next(fd, path, flags, type, acl);
}

int attr_copy_file(const char *src, const char *dst,
                   int (*check)(const char *, struct error_context *),
                   struct error_context *ctx)
{
    int (*next)(const char *, const char *,
                int (*)(const char *, struct error_context *),
                struct error_context *) = dlsym(RTLD_NEXT, "attr_copy_file");
    struct stat st;
    if (stat(src, &st) == 0 && S_ISDIR(st.st_mode))
        swap_paths("read", ACL_TYPE_DEFAULT);
    return next(src, dst, check, ctx);
}

/* The fixed O_PATH path follows descriptor aliases, not the original names. */
ssize_t listxattr(const char *path, char *list, size_t size)
{
    ssize_t (*next)(const char *, char *, size_t) = dlsym(RTLD_NEXT, "listxattr");
    struct stat st;
    if (strncmp(path, "/proc/self/fd/", 14) == 0
        && path[14] && strspn(path + 14, "0123456789") == strlen(path + 14)
        && stat(path, &st) == 0 && S_ISDIR(st.st_mode))
        swap_paths("read", ACL_TYPE_DEFAULT);
    return next(path, list, size);
}
