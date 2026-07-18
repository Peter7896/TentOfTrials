#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../include/logger.h"

#define CHECK(condition, message) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", message, __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

typedef struct {
    int id;
    int iterations;
} logger_thread_args_t;

static int make_log_path(char *path, size_t path_size)
{
    int fd;

    snprintf(path, path_size, "/tmp/frailbox-logger-shutdown-%ld-XXXXXX", (long)getpid());
    fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        return -1;
    }
    close(fd);
    return 0;
}

static off_t file_size(const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0) {
        return -1;
    }
    return st.st_size;
}

static char *read_file(const char *path)
{
    FILE *fp = fopen(path, "rb");
    char *buffer;
    long size;

    if (fp == NULL) {
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    size = ftell(fp);
    if (size < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }

    buffer = calloc((size_t)size + 1, 1);
    if (buffer == NULL) {
        fclose(fp);
        return NULL;
    }
    if (size > 0 && fread(buffer, 1, (size_t)size, fp) != (size_t)size) {
        free(buffer);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    return buffer;
}

static void configure_logger_env(const char *path)
{
    setenv("LOG_FILE", path, 1);
    setenv("LOG_LEVEL", "debug", 1);
    setenv("LOG_NO_TIMESTAMPS", "1", 1);
    setenv("LOG_MODULE", "logger-shutdown-test", 1);
    unsetenv("LOG_SOURCE_INFO");
}

static int test_post_shutdown_drop_and_reinit(void)
{
    char path[256];
    char *contents;
    off_t shutdown_size;
    off_t dropped_size;
    unsigned char bytes[] = {0x00, 0x01, 0x02, 0xff};

    CHECK(make_log_path(path, sizeof(path)) == 0, "temporary log path is created");
    configure_logger_env(path);

    CHECK(log_init() == 0, "log_init succeeds");
    LOG_INFO("before-shutdown-marker");
    log_shutdown();

    shutdown_size = file_size(path);
    CHECK(shutdown_size > 0, "log-before-shutdown writes to configured file");

    LOG_ERROR("after-shutdown-marker");
    log_message(LOG_LEVEL_ERROR, __FILE__, __LINE__, "direct-after-shutdown-marker");
    log_hex_dump("hex-after-shutdown-marker", bytes, sizeof(bytes));
    dropped_size = file_size(path);
    CHECK(dropped_size == shutdown_size, "post-shutdown logging is dropped");

    log_shutdown();
    log_shutdown();
    CHECK(file_size(path) == shutdown_size, "repeated shutdown is idempotent");

    CHECK(log_init() == 0, "log_init after shutdown succeeds");
    LOG_INFO("after-reinit-marker");
    log_shutdown();
    CHECK(file_size(path) > shutdown_size, "logging resumes after re-init");

    contents = read_file(path);
    CHECK(contents != NULL, "log file can be read");
    CHECK(strstr(contents, "before-shutdown-marker") != NULL, "before-shutdown marker exists");
    CHECK(strstr(contents, "after-shutdown-marker") == NULL, "macro post-shutdown marker is absent");
    CHECK(strstr(contents, "direct-after-shutdown-marker") == NULL, "direct post-shutdown marker is absent");
    CHECK(strstr(contents, "hex-after-shutdown-marker") == NULL, "hex dump post-shutdown marker is absent");
    CHECK(strstr(contents, "after-reinit-marker") != NULL, "re-init marker exists");
    free(contents);

    unlink(path);
    return 0;
}

static void *logger_thread(void *arg)
{
    logger_thread_args_t *args = (logger_thread_args_t *)arg;

    for (int i = 0; i < args->iterations; i++) {
        LOG_INFO("thread-%d-message-%d", args->id, i);
        if ((i % 16) == 0) {
            usleep(100);
        }
    }
    return NULL;
}

static void *shutdown_thread(void *arg)
{
    (void)arg;

    usleep(1000);
    for (int i = 0; i < 10; i++) {
        log_shutdown();
        usleep(100);
    }
    return NULL;
}

static int test_concurrent_shutdown_and_logging(void)
{
    char path[256];
    pthread_t loggers[4];
    pthread_t shutdowner;
    logger_thread_args_t args[4];
    off_t size_after_threads;

    CHECK(make_log_path(path, sizeof(path)) == 0, "temporary concurrent log path is created");
    configure_logger_env(path);
    CHECK(log_init() == 0, "concurrent test log_init succeeds");

    for (int i = 0; i < 4; i++) {
        args[i].id = i;
        args[i].iterations = 500;
        CHECK(pthread_create(&loggers[i], NULL, logger_thread, &args[i]) == 0,
              "logger thread is created");
    }
    CHECK(pthread_create(&shutdowner, NULL, shutdown_thread, NULL) == 0,
          "shutdown thread is created");

    for (int i = 0; i < 4; i++) {
        CHECK(pthread_join(loggers[i], NULL) == 0, "logger thread joins");
    }
    CHECK(pthread_join(shutdowner, NULL) == 0, "shutdown thread joins");

    size_after_threads = file_size(path);
    CHECK(size_after_threads >= 0, "concurrent log file exists");
    LOG_ERROR("post-concurrent-shutdown-marker");
    CHECK(file_size(path) == size_after_threads, "post-concurrent-shutdown logging is dropped");

    unlink(path);
    return 0;
}

int main(void)
{
    if (test_post_shutdown_drop_and_reinit() != 0) {
        return 1;
    }
    if (test_concurrent_shutdown_and_logging() != 0) {
        return 1;
    }

    printf("logger shutdown tests passed\n");
    return 0;
}
