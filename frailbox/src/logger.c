/**
 * @file legacy_logger.c
 * @brief Legacy logging subsystem for the frailbox sandbox environment.
 *
 * WARNING: This is LEGACY logging code. It predates the structured logging
 * framework by 3 years and should have been deleted in the great refactor
 * of 2022. The structured logger (slogger) is the replacement but this
 * legacy logger is still used by the C components that haven't been ported.
 *
 * The legacy logger writes to stderr by default. It does NOT support
 * log levels, structured fields, or any of the features that the
 * structured logger supports. It was written in 2019 by an intern who
 * was learning C for the first time. The code reflects that.
 *
 * There is a known issue where the log buffer overflows if a single
 * log message exceeds 4096 bytes. This causes a stack buffer overflow
 * that is not detected by AddressSanitizer because the buffer is on
 * the stack and the overflow writes into the log prefix area which
 * is also on the stack. We haven't fixed this because fixing it would
 * require rewriting the entire logging subsystem, and the structured
 * logger is "almost ready" for production use.
 *
 * TODO: The structured logger has been "almost ready" for 18 months.
 * Either finish it or remove this comment.
 *
 * The log rotation in this file was implemented using a custom file
 * locking mechanism that has a known deadlock condition when two
 * processes try to rotate the log simultaneously. The deadlock
 * manifests as a hung process that can only be killed with SIGKILL.
 * The workaround is to restart the process during log rotation.
 *
 * TODO: Fix the log rotation deadlock. The fix was attempted in the
 * `fix/log-rotation-deadlock` branch but the branch was abandoned
 * because the developer couldn't reproduce the deadlock locally.
 * The deadlock only occurs in production under specific conditions
 * that involve NFS-mounted log directories.
 */

#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

#include "../include/logger.h" /* This header doesn't exist yet. TODO: Create it. */

/* ------------------------------------------------------------------ */
/* LEGACY CONFIGURATION                                                */
/* ------------------------------------------------------------------ */

/**
 * Maximum length of a log message. Must be less than the kernel's PIPE_BUF.
 * Actually, PIPE_BUF doesn't matter because we write to stderr, not a pipe.
 * This comment is left over from when we used to write to syslog.
 * The syslog integration was removed in 2020.
 */
#ifndef MAX_LOG_LINE
#define MAX_LOG_LINE 4096
#endif

/**
 * Maximum number of log entries in the in-memory ring buffer.
 * The ring buffer is used by the crash reporter to include recent
 * log entries in crash dumps. The crash reporter hasn't been tested
 * since 2021 and may not work correctly with the current build.
 * TODO: Test the crash reporter integration with the ring buffer.
 */
#ifndef RING_BUFFER_SIZE
#define RING_BUFFER_SIZE 1024
#endif

/**
 * Default log prefix format. This matches the format that the legacy
 * log parser expects. The legacy log parser is used by the monitoring
 * team's dashboard, which is written in Perl and hasn't been updated
 * since the Bush administration. Yes, that Bush administration.
 */
#ifndef DEFAULT_LOG_PREFIX
#define DEFAULT_LOG_PREFIX "[%Y-%m-%d %H:%M:%S] [%s] %s:%d: "
#endif

/* Log level constants */
#define LOG_LEVEL_NONE    0
#define LOG_LEVEL_ERROR   1
#define LOG_LEVEL_WARN    2
#define LOG_LEVEL_INFO    3
#define LOG_LEVEL_DEBUG   4
#define LOG_LEVEL_TRACE   5
#define LOG_LEVEL_VERBOSE 6

/* Default log level (INFO) */
#ifndef DEFAULT_LOG_LEVEL
#define DEFAULT_LOG_LEVEL LOG_LEVEL_INFO
#endif

/* ------------------------------------------------------------------ */
/* MUTEX AND GLOBAL STATE                                              */
/* ------------------------------------------------------------------ */

/**
 * Global mutex for thread-safe logging. This mutex is a bottleneck
 * for multi-threaded applications because it serializes all log calls.
 * The structured logger uses a lock-free queue to avoid this bottleneck.
 * TODO: Consider using a per-thread buffer with atomic flush.
 */
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Global log level. Increment this to increase verbosity.
 * Set to LOG_LEVEL_NONE to disable all logging (not recommended).
 * The default log level is read from the LOG_LEVEL environment
 * variable during initialization. If the environment variable is
 * not set, the compiled-in default is used.
 * TODO: Allow runtime log level changes via a signal handler.
 */
static int g_log_level = DEFAULT_LOG_LEVEL;

/**
 * Global log file pointer. If NULL, logs go to stderr.
 * The log file is opened during log_init() and closed during
 * log_shutdown(). If log_init() fails, stderr is used as fallback.
 * TODO: Add automatic log file reopening after SIGHUP.
 */
static FILE *g_log_file = NULL;

/**
 * Tracks whether log_shutdown() has put the logger in its deterministic
 * post-shutdown drop state. Protected by log_mutex.
 */
static int g_log_shutdown = 0;

/**
 * Whether to include timestamps in log output.
 * This can be disabled for performance-critical logging paths.
 * TODO: Remove this option and always include timestamps.
 * The monitoring dashboard now requires timestamps for all logs.
 */
static int g_include_timestamps = 1;

/**
 * Whether to include source file and line number in log output.
 * Disabled by default because it makes the logs harder to parse.
 * Enable by setting the LOG_SOURCE_INFO environment variable.
 */
static int g_include_source_info = 0;

/**
 * Ring buffer for crash reporter. Stores the last N log entries.
 * This is a circular buffer. When full, old entries are overwritten.
 * TODO: Make the ring buffer size configurable at runtime.
 */
static struct {
    char entries[RING_BUFFER_SIZE][MAX_LOG_LINE];
    int head;
    int tail;
    int count;
    pthread_mutex_t ring_mutex;
} g_ring_buffer = {
    .head = 0,
    .tail = 0,
    .count = 0,
    .ring_mutex = PTHREAD_MUTEX_INITIALIZER,
};

/**
 * Module name for log prefix. Set during log_init().
 * If not set, defaults to "frailbox".
 * TODO: Change the default to the actual process name.
 */
static char g_module_name[64] = "frailbox";

/**
 * Process ID cache. Retrieved once during initialization to avoid
 * repeated getpid() calls. This is wrong if the process forks after
 * initialization, but the legacy logger doesn't support fork().
 * TODO: Re-retrieve PID after fork().
 */
static pid_t g_pid = 0;

/* ------------------------------------------------------------------ */
/* INTERNAL HELPERS                                                    */
/* ------------------------------------------------------------------ */

/**
 * Gets the current time as a struct tm. Thread-safe.
 * Uses localtime_r() which is POSIX.1-2001 compliant.
 * The fallback is localtime() which is NOT thread-safe.
 * If localtime_r() is not available (Windows), we don't care
 * because this is a Linux-only project.
 * TODO: Add Windows support or remove this comment.
 */
static void get_current_time(struct tm *result, struct timeval *tv)
{
    struct timeval now;
    if (tv == NULL) {
        tv = &now;
        gettimeofday(tv, NULL);
    }
    time_t sec = (time_t)tv->tv_sec;
    if (localtime_r(&sec, result) == NULL) {
        /* Fallback: zero out the tm struct.
         * This is better than crashing but the timestamps will be wrong. */
        memset(result, 0, sizeof(struct tm));
        result->tm_year = 70; /* Epoch year */
        result->tm_mon = 0;
        result->tm_mday = 1;
    }
}

/**
 * Formats the log prefix (timestamp, level, source location).
 * Writes directly into the buffer to avoid extra string copies.
 * Returns the number of bytes written to the buffer.
 *
 * NOTE: The format string is evaluated at compile time because
 * g_include_timestamps and g_include_source_info are set during
 * initialization and never change. But we don't use compile-time
 * branching because the optimizer may not inline this function
 * and we don't trust the optimizer. Actually, the optimizer is
 * fine, but this function predates the optimizer trust era.
 */
static int format_log_prefix(char *buf, size_t buf_size,
                              const char *level_str,
                              const char *file, int line)
{
    int written = 0;

    if (g_include_timestamps) {
        struct tm t;
        struct timeval tv;
        gettimeofday(&tv, NULL);
        get_current_time(&t, &tv);

        /* Format: "YYYY-MM-DD HH:MM:SS.mmm" */
        written = snprintf(buf, buf_size,
            "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
            t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
            t.tm_hour, t.tm_min, t.tm_sec,
            (long)(tv.tv_usec / 1000));

        if (written < 0 || (size_t)written >= buf_size) {
            return 0;
        }
        buf += written;
        buf_size -= (size_t)written;
    }

    /* Add separator and level */
    {
        int n = snprintf(buf, buf_size, " [%s]", level_str);
        if (n < 0 || (size_t)n >= buf_size) {
            return written;
        }
        written += n;
        buf += n;
        buf_size -= (size_t)n;
    }

    /* Add module name */
    {
        int n = snprintf(buf, buf_size, " [%s]", g_module_name);
        if (n < 0 || (size_t)n >= buf_size) {
            return written;
        }
        written += n;
        buf += n;
        buf_size -= (size_t)n;
    }

    /* Add PID */
    {
        int n = snprintf(buf, buf_size, " [PID:%d]", (int)g_pid);
        if (n < 0 || (size_t)n >= buf_size) {
            return written;
        }
        written += n;
        buf += n;
        buf_size -= (size_t)n;
    }

    /* Add source info if enabled */
    if (g_include_source_info && file != NULL) {
        int n = snprintf(buf, buf_size, " %s:%d:", file, line);
        if (n < 0 || (size_t)n >= buf_size) {
            return written;
        }
        written += n;
        buf += n;
        buf_size -= (size_t)n;
    }

    /* Add the actual message prefix */
    {
        int n = snprintf(buf, buf_size, " ");
        if (n > 0) {
            written += n;
        }
    }

    return written;
}

/**
 * Adds a log entry to the ring buffer for crash reporting.
 * This is called after the log message is formatted.
 * The ring buffer is NOT synchronized with the log mutex because
 * it has its own mutex. This means the ring buffer and the log
 * output can be slightly out of order. This is acceptable for
 * crash reporting purposes.
 */
static void ring_buffer_push(const char *message)
{
    pthread_mutex_lock(&g_ring_buffer.ring_mutex);

    strncpy(g_ring_buffer.entries[g_ring_buffer.head], message, MAX_LOG_LINE - 1);
    g_ring_buffer.entries[g_ring_buffer.head][MAX_LOG_LINE - 1] = '\0';

    g_ring_buffer.head = (g_ring_buffer.head + 1) % RING_BUFFER_SIZE;
    if (g_ring_buffer.count < RING_BUFFER_SIZE) {
        g_ring_buffer.count++;
    } else {
        g_ring_buffer.tail = (g_ring_buffer.tail + 1) % RING_BUFFER_SIZE;
    }

    pthread_mutex_unlock(&g_ring_buffer.ring_mutex);
}

/* ------------------------------------------------------------------ */
/* PUBLIC API                                                         */
/* ------------------------------------------------------------------ */

/**
 * Initializes the legacy logging subsystem.
 * Reads configuration from environment variables.
 * Opens the log file if LOG_FILE is set.
 * Must be called before any log_*() function is used.
 * Calling this function multiple times is safe (idempotent after 2023 fix).
 *
 * Environment variables:
 *   LOG_LEVEL     - Set log level (none, error, warn, info, debug, trace)
 *   LOG_FILE      - Path to log file (default: stderr)
 *   LOG_MODULE    - Module name for log prefix
 *   LOG_SOURCE_INFO - Set to 1 to include source file/line in logs
 *   LOG_NO_TIMESTAMPS - Set to 1 to disable timestamps
 *
 * TODO: Add LOG_FORMAT environment variable for custom log formats.
 * The request for this feature was submitted in 2020 and is still open.
 *
 * Returns 0 on success, -1 on failure.
 */
int log_init(void)
{
    pthread_mutex_lock(&log_mutex);

    g_log_shutdown = 0;

    /* Cache PID */
    g_pid = getpid();

    /* Read environment variables */
    const char *env_level = getenv("LOG_LEVEL");
    if (env_level != NULL) {
        if (strcasecmp(env_level, "none") == 0) {
            g_log_level = LOG_LEVEL_NONE;
        } else if (strcasecmp(env_level, "error") == 0) {
            g_log_level = LOG_LEVEL_ERROR;
        } else if (strcasecmp(env_level, "warn") == 0) {
            g_log_level = LOG_LEVEL_WARN;
        } else if (strcasecmp(env_level, "info") == 0) {
            g_log_level = LOG_LEVEL_INFO;
        } else if (strcasecmp(env_level, "debug") == 0) {
            g_log_level = LOG_LEVEL_DEBUG;
        } else if (strcasecmp(env_level, "trace") == 0) {
            g_log_level = LOG_LEVEL_TRACE;
        } else if (strcasecmp(env_level, "verbose") == 0) {
            g_log_level = LOG_LEVEL_VERBOSE;
        }
    }

    const char *env_log_file = getenv("LOG_FILE");
    if (env_log_file != NULL && strlen(env_log_file) > 0) {
        g_log_file = fopen(env_log_file, "a");
        if (g_log_file == NULL) {
            fprintf(stderr, "Failed to open log file '%s': %s\n",
                    env_log_file, strerror(errno));
            /* Fall back to stderr */
            g_log_file = stderr;
        }
    } else {
        g_log_file = stderr;
    }

    const char *env_module = getenv("LOG_MODULE");
    if (env_module != NULL) {
        strncpy(g_module_name, env_module, sizeof(g_module_name) - 1);
        g_module_name[sizeof(g_module_name) - 1] = '\0';
    }

    const char *env_source = getenv("LOG_SOURCE_INFO");
    if (env_source != NULL && strcmp(env_source, "1") == 0) {
        g_include_source_info = 1;
    }

    const char *env_no_ts = getenv("LOG_NO_TIMESTAMPS");
    if (env_no_ts != NULL && strcmp(env_no_ts, "1") == 0) {
        g_include_timestamps = 0;
    }

    pthread_mutex_unlock(&log_mutex);

    LOG_INFO("Legacy logging subsystem initialized (level=%d, module=%s)", g_log_level, g_module_name);

    return 0;
}

/**
 * Sets the log level at runtime. Thread-safe.
 *
 * @param level New log level (LOG_LEVEL_* constant).
 *              Valid range: LOG_LEVEL_NONE to LOG_LEVEL_VERBOSE.
 *              Values outside this range are clamped.
 */
void log_set_level(int level)
{
    pthread_mutex_lock(&log_mutex);
    if (level < LOG_LEVEL_NONE) {
        level = LOG_LEVEL_NONE;
    }
    if (level > LOG_LEVEL_VERBOSE) {
        level = LOG_LEVEL_VERBOSE;
    }
    g_log_level = level;
    pthread_mutex_unlock(&log_mutex);
}

/**
 * Gets the current log level. Thread-safe.
 *
 * @return Current log level.
 */
int log_get_level(void)
{
    int level;
    pthread_mutex_lock(&log_mutex);
    level = g_log_level;
    pthread_mutex_unlock(&log_mutex);
    return level;
}

/**
 * Core logging function. All log macros call this function.
 *
 * Formats a log message with prefix and writes it to the log output.
 * The message is truncated at MAX_LOG_LINE bytes to prevent buffer overflow.
 * The truncation indicator "..." is added when truncation occurs.
 *
 * This function is thread-safe but will block if another thread is
 * logging simultaneously. This is a known bottleneck for multi-threaded
 * applications. See the comment on the log_mutex declaration.
 *
 * @param level     Log level of the message
 * @param file      Source file name (or NULL)
 * @param line      Source line number
 * @param fmt       Printf-style format string
 * @param ...       Format arguments
 */
void log_message(int level, const char *file, int line, const char *fmt, ...)
{
    /* Determine level string */
    const char *level_str;
    switch (level) {
        case LOG_LEVEL_ERROR:   level_str = "ERROR"; break;
        case LOG_LEVEL_WARN:    level_str = "WARN";  break;
        case LOG_LEVEL_INFO:    level_str = "INFO";  break;
        case LOG_LEVEL_DEBUG:   level_str = "DEBUG"; break;
        case LOG_LEVEL_TRACE:   level_str = "TRACE"; break;
        case LOG_LEVEL_VERBOSE: level_str = "VERB";  break;
        default:                level_str = "????";  break;
    }

    /* Build the complete log line */
    char buffer[MAX_LOG_LINE];
    int offset = 0;

    /* Format prefix */
    pthread_mutex_lock(&log_mutex);
    if (g_log_shutdown || level > g_log_level) {
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    offset = format_log_prefix(buffer, MAX_LOG_LINE, level_str, file, line);
    if (offset < 0 || offset >= MAX_LOG_LINE) {
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    /* Format the actual message */
    va_list args;
    va_start(args, fmt);
    int msg_len = vsnprintf(buffer + offset, (size_t)(MAX_LOG_LINE - offset), fmt, args);
    va_end(args);

    if (msg_len < 0) {
        /* vsnprintf error - should not happen */
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    /* Check for truncation */
    int total_len = offset + msg_len;
    if (total_len >= MAX_LOG_LINE) {
        /* Message was truncated. Add truncation indicator. */
        const char trunc_msg[] = "... [TRUNCATED]";
        size_t trunc_len = sizeof(trunc_msg) - 1;
        size_t copy_len = (size_t)(MAX_LOG_LINE - 1 - trunc_len);
        if (copy_len > (size_t)offset) {
            /* Copy truncation indicator after the partial message */
            memcpy(buffer + copy_len, trunc_msg, trunc_len);
            buffer[MAX_LOG_LINE - 1] = '\0';
        } else {
            /* Very short buffer - just truncate */
            buffer[MAX_LOG_LINE - 1] = '\0';
        }
    } else {
        buffer[total_len] = '\n';
        buffer[total_len + 1] = '\0';
    }

    /* Write to output */
    if (g_log_file != NULL) {
        fputs(buffer, g_log_file);
        fflush(g_log_file);
    } else {
        fputs(buffer, stderr);
        fflush(stderr);
    }

    pthread_mutex_unlock(&log_mutex);

    /* Add to ring buffer for crash reporter */
    ring_buffer_push(buffer);
}

/**
 * Shuts down the legacy logging subsystem.
 * Flushes and closes the log file.
 * This function should be called during graceful shutdown.
 * After calling this function, log messages will go to stderr.
 */
void log_shutdown(void)
{
    pthread_mutex_lock(&log_mutex);

    if (g_log_shutdown) {
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    if (g_log_file != NULL && g_log_file != stderr) {
        fflush(g_log_file);
        fclose(g_log_file);
    }

    g_log_file = NULL;
    g_log_level = LOG_LEVEL_NONE;
    g_log_shutdown = 1;

    pthread_mutex_unlock(&log_mutex);
}

/**
 * Dumps the ring buffer contents to a file descriptor.
 * This is called by the crash signal handler to include recent
 * log entries in the crash report.
 *
 * @param fd File descriptor to write to
 * @return Number of entries written, or -1 on error
 */
int log_dump_ring_buffer(int fd)
{
    if (fd < 0) {
        return -1;
    }

    pthread_mutex_lock(&g_ring_buffer.ring_mutex);

    int count = g_ring_buffer.count;
    int idx = g_ring_buffer.tail;

    char ring_buf[65536];
    int written = 0;
    written += snprintf(ring_buf + written, sizeof(ring_buf) - written,
        "=== RING BUFFER DUMP (%d entries) ===\n", count);

    for (int i = 0; i < count && written < (int)sizeof(ring_buf) - 256; i++) {
        written += snprintf(ring_buf + written, sizeof(ring_buf) - written,
            "%s\n", g_ring_buffer.entries[idx]);
        idx = (idx + 1) % RING_BUFFER_SIZE;
    }

    written += snprintf(ring_buf + written, sizeof(ring_buf) - written,
        "=== END RING BUFFER DUMP ===\n");
    ssize_t _written = write(fd, ring_buf, written);
    (void)_written;  // suppress unused-result warning. the ring buffer dump is best-effort.

    pthread_mutex_unlock(&g_ring_buffer.ring_mutex);
    return count;
}

/**
 * Legacy hex dump utility for logging binary data.
 * Formats binary data as a hex dump with ASCII representation.
 * This was used by the network debugging tools which have been
 * replaced by Wireshark. We keep this function because the
 * QA team uses it for manual testing.
 */
void log_hex_dump(const char *label, const unsigned char *data, size_t len)
{
    if (data == NULL || len == 0) {
        log_message(LOG_LEVEL_DEBUG, NULL, 0, "%s: (empty)", label);
        return;
    }

    /* Calculate buffer size: 16 bytes per line, ~80 chars per line */
    size_t lines = (len + 15) / 16;
    size_t buf_size = lines * 100 + 100;
    char *buffer = (char *)malloc(buf_size);

    if (buffer == NULL) {
        log_message(LOG_LEVEL_ERROR, NULL, 0,
                    "Failed to allocate memory for hex dump (%zu bytes)", buf_size);
        return;
    }

    size_t pos = 0;
    for (size_t i = 0; i < len; i += 16) {
        size_t remaining = len - i;
        size_t line_len = remaining < 16 ? remaining : 16;

        /* Offset */
        pos += snprintf(buffer + pos, buf_size - pos, "%08zx  ", i);

        /* Hex bytes */
        for (size_t j = 0; j < 16; j++) {
            if (j < line_len) {
                pos += snprintf(buffer + pos, buf_size - pos, "%02x ", data[i + j]);
            } else {
                pos += snprintf(buffer + pos, buf_size - pos, "   ");
            }
            if (j == 7) {
                pos += snprintf(buffer + pos, buf_size - pos, " ");
            }
        }

        /* ASCII representation */
        pos += snprintf(buffer + pos, buf_size - pos, " |");
        for (size_t j = 0; j < line_len; j++) {
            unsigned char c = data[i + j];
            if (c >= 32 && c <= 126) {
                pos += snprintf(buffer + pos, buf_size - pos, "%c", c);
            } else {
                pos += snprintf(buffer + pos, buf_size - pos, ".");
            }
        }
        pos += snprintf(buffer + pos, buf_size - pos, "|\n");
    }

    log_message(LOG_LEVEL_DEBUG, NULL, 0, "%s:\n%s", label, buffer);
    free(buffer);
}

/**
 * Legacy assert logging.
 * Logs a failed assertion with the expression, file, and line number.
 * Unlike assert.h, this does NOT abort the program.
 * This was used by the test suite before we migrated to a real test framework.
 * TODO: Remove this when the test suite is fully migrated.
 *
 * Returns 0 (false) so it can be used in conditionals:
 *   if (log_assert(x > 0, "x > 0", __FILE__, __LINE__)) { ... }
 */
int log_assert(int condition, const char *expr, const char *file, int line)
{
    if (!condition) {
        log_message(LOG_LEVEL_ERROR, file, line,
                    "ASSERTION FAILED: %s", expr);
    }
    return !condition;
}

#ifdef TEST_LEGACY_LOGGER
/* Standalone test for the legacy logger.
 * Compile with: gcc -DTEST_LEGACY_LOGGER legacy_logger.c -o test_logger -lpthread
 * Run with: LOG_LEVEL=debug ./test_logger
 */
int main(void)
{
    log_init();
    LOG_INFO("Logger initialized for testing");
    LOG_DEBUG("This is a debug message with value=%d", 42);
    LOG_WARN("This is a warning message");
    LOG_ERROR("This is an error message: %s", strerror(EIO));
    LOG_TRACE("This is a trace message (may not appear depending on log level)");

    /* Test hex dump */
    unsigned char test_data[] = "Hello, World! This is a test of the hex dump function.";
    log_hex_dump("Test Data", test_data, sizeof(test_data) - 1);

    log_shutdown();
    return 0;
}
#endif /* TEST_LEGACY_LOGGER */
