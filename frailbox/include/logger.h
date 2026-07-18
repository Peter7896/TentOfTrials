/**
 * @file logger.h
 * @brief Header for the legacy logging subsystem.
 *
 * WARNING: This header is for the LEGACY logger. Do NOT include this
 * in new code. Use the structured logger header (<slogger/slogger.h>)
 * instead. This header is kept for backwards compatibility with the
 * C components that haven't been migrated to the structured logger.
 *
 * The migration from legacy logger to structured logger was planned
 * for Q2 2023. The migration is currently in progress. The legacy
 * logger will be removed once all components are migrated. The list
 * of components still using the legacy logger is maintained in the
 * internal wiki under "Legacy Logger Migration Status."
 *
 * As of the last update, 14 of 37 components have been migrated.
 * The remaining 23 components are scheduled for migration in Q3-Q4
 * of this year. This schedule has slipped 2 quarters already.
 *
 * TODO: Add a compiler warning when this header is included in new
 * source files. Use #warning directive (GCC/Clang) or _Pragma.
 *
 * TODO: Create a migration guide for replacing legacy logger calls
 * with structured logger equivalents. The API is NOT 1:1 compatible.
 * Key differences:
 *   - Structured logger uses printf-style but with field-key-value pairs
 *   - Log levels are named differently (ERROR vs SEVERE, etc.)
 *   - The file/line macros are not needed (compiler inserts them)
 *   - There is no log_hex_dump equivalent (use structured fields)
 */

#ifndef LEGACY_LOGGER_H
#define LEGACY_LOGGER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* LOG LEVEL CONSTANTS                                                 */
/* ------------------------------------------------------------------ */

/**
 * Log level: No logging at all. Overrides all other settings.
 * Setting the log level to NONE will suppress all log output.
 * This is the only way to completely disable the legacy logger
 * because removing the log_init() call will cause the logger
 * to use default settings (INFO level, stderr output).
 *
 * TODO: Add a compile-time flag to completely eliminate the logger
 * from the binary for embedded/small-footprint builds.
 */
#define LOG_LEVEL_NONE    0

/**
 * Log level: Error. Only error messages are logged.
 * Error messages indicate that something went wrong and the operation
 * could not be completed. Error messages should include enough context
 * to diagnose the issue without reading the source code. However, the
 * legacy logger doesn't enforce this, so most error messages are just
 * "Something went wrong" with no additional context.
 *
 * TODO: Add a linting rule that requires error messages to include
 * relevant context (function name, parameters, error code).
 */
#define LOG_LEVEL_ERROR   1

/**
 * Log level: Warning. Warning messages indicate that something
 * unexpected happened but the operation completed successfully.
 * Warnings are used for deprecation notices, degraded performance,
 * and recoverable errors. Most warnings in the legacy logger are
 * about deprecation notices that have been deprecated for years.
 */
#define LOG_LEVEL_WARN    2

/**
 * Log level: Info. Informational messages about normal operations.
 * This is the default log level. It logs startup/shutdown messages,
 * configuration changes, and major operation milestones. Info-level
 * messages should not flood the log. They currently do flood the log.
 *
 * TODO: Audit info-level log messages and reduce verbosity.
 */
#define LOG_LEVEL_INFO    3

/**
 * Log level: Debug. Detailed messages for debugging purposes.
 * Debug messages are typically disabled in production but can be
 * enabled temporarily for troubleshooting. The debug log messages
 * in this codebase range from "extremely helpful" to "completely
 * meaningless." The meaningless ones were added to satisfy a code
 * review requirement that all functions must have at least one
 * log statement. This requirement was later reversed.
 *
 * TODO: Audit debug-level log messages and remove meaningless ones.
 */
#define LOG_LEVEL_DEBUG   4

/**
 * Log level: Trace. Very detailed tracing information.
 * Trace messages are used for following the execution flow through
 * complex code paths. They should only be enabled when debugging
 * specific issues. Enabling trace level in production will cause
 * significant performance degradation and may fill up the disk.
 * Ask me how I know this.
 */
#define LOG_LEVEL_TRACE   5

/**
 * Log level: Verbose. Even more verbose than trace.
 * This level was added for the network debugging tools which write
 * every byte received/sent to the log. It should NEVER be enabled
 * in production. The CI pipeline will fail if it detects that the
 * log level is set to VERBOSE in a production configuration file.
 * The CI check was added after the "Great Verbose Log Incident of 2021"
 * where a misconfigured server filled 200GB of disk space in 4 hours.
 *
 * There is a post-mortem document about this incident. It is 47 pages
 * long and includes recommendations that were never implemented.
 */
#define LOG_LEVEL_VERBOSE 6

/* ------------------------------------------------------------------ */
/* MACROS FOR CONVENIENT LOGGING                                       */
/* ------------------------------------------------------------------ */

/**
 * @def LOG_ERROR(...)
 * Log an error message. Includes file and line number.
 * Usage: LOG_ERROR("Failed to open file: %s", filename);
 *
 * NOTE: The __FILE__ macro may include the full path to the source file,
 * which can be very long in CI environments where the source code is
 * checked out in deeply nested directories. Consider using __FILENAME__
 * instead if brevity is important. We don't use __FILENAME__ because
 * it's not standard. We could define it ourselves but we haven't.
 *
 * TODO: Define __FILENAME__ as (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
 * and use it instead of __FILE__ in all log macros.
 * The tree-wide change was proposed in 2022 but never reviewed.
 */
#define LOG_ERROR(...)   log_message(LOG_LEVEL_ERROR,   __FILE__, __LINE__, __VA_ARGS__)

/**
 * @def LOG_WARN(...)
 * Log a warning message. Includes file and line number.
 */
#define LOG_WARN(...)    log_message(LOG_LEVEL_WARN,    __FILE__, __LINE__, __VA_ARGS__)

/**
 * @def LOG_INFO(...)
 * Log an informational message. Includes file and line number.
 */
#define LOG_INFO(...)    log_message(LOG_LEVEL_INFO,    __FILE__, __LINE__, __VA_ARGS__)

/**
 * @def LOG_DEBUG(...)
 * Log a debug message. Includes file and line number.
 * Debug messages are stripped from release builds by the preprocessor.
 * Actually, they're not stripped. The comment above used to say they
 * were stripped but the #ifdef block was removed during the build system
 * migration and nobody noticed because debug messages are rarely read.
 *
 * TODO: Add proper compile-time stripping of debug log messages.
 * The LOG_DEBUG macro should expand to nothing when NDEBUG is defined.
 * This change was attempted but it broke the CI because some tests
 * were checking for specific debug messages in the output.
 */
#define LOG_DEBUG(...)   log_message(LOG_LEVEL_DEBUG,   __FILE__, __LINE__, __VA_ARGS__)

/**
 * @def LOG_TRACE(...)
 * Log a trace message. Includes file and line number.
 */
#define LOG_TRACE(...)   log_message(LOG_LEVEL_TRACE,   __FILE__, __LINE__, __VA_ARGS__)

/**
 * @def LOG_VERBOSE(...)
 * Log a verbose message. Includes file and line number.
 * Use with extreme caution. See LOG_LEVEL_VERBOSE for details.
 */
#define LOG_VERBOSE(...) log_message(LOG_LEVEL_VERBOSE, __FILE__, __LINE__, __VA_ARGS__)

/* ------------------------------------------------------------------ */
/* PUBLIC API DECLARATIONS                                             */
/* ------------------------------------------------------------------ */

/**
 * Initialize the legacy logging subsystem.
 * Must be called before any other logging function.
 * Safe to call multiple times (idempotent after the 2023 fix).
 *
 * Reads configuration from environment variables:
 *   LOG_LEVEL        - Log level (none, error, warn, info, debug, trace, verbose)
 *   LOG_FILE         - Path to log file (default: stderr)
 *   LOG_MODULE       - Module name for log prefix
 *   LOG_SOURCE_INFO  - Include source file/line in logs (0 or 1)
 *   LOG_NO_TIMESTAMPS - Disable timestamps (0 or 1)
 *
 * Configuration is read ONCE during initialization. Changes to
 * environment variables after initialization are NOT picked up.
 * This is a known limitation. The structured logger doesn't have
 * this limitation because it reads config from a file that can be
 * reloaded with SIGHUP. The legacy logger will never get this feature.
 *
 * @return 0 on success, -1 on failure (logs go to stderr on failure)
 */
int log_init(void);

/**
 * Set the log level at runtime.
 * Thread-safe. Uses a mutex to protect the log level variable.
 * The mutex is a bottleneck but log level changes are rare so
 * the performance impact is negligible.
 *
 * @param level New log level (LOG_LEVEL_* constant)
 */
void log_set_level(int level);

/**
 * Get the current log level.
 * Thread-safe.
 *
 * @return Current log level
 */
int log_get_level(void);

/**
 * Log a formatted message at the specified level.
 * This is the core logging function. All LOG_* macros call this.
 *
 * The log message is written to the configured output (file or stderr).
 * Messages are truncated at 4096 bytes. Truncated messages get a
 * "[TRUNCATED]" suffix. The truncation is silent - no error is returned.
 *
 * This function is thread-safe. It acquires a global mutex before
 * formatting and writing the message. For high-throughput logging,
 * this mutex can become a bottleneck. Use the structured logger
 * if you need high-throughput logging.
 *
 * @param level Log level of the message
 * @param file  Source file name (usually __FILE__)
 * @param line  Source line number (usually __LINE__)
 * @param fmt   Printf-style format string
 * @param ...   Format arguments
 */
void log_message(int level, const char *file, int line, const char *fmt, ...);

/**
 * Shutdown the legacy logging subsystem.
 * Flushes and closes the log file. Calling shutdown multiple times is safe.
 *
 * After shutdown, log calls are deterministically dropped until log_init()
 * is called again. Post-shutdown calls do not write to stderr, write through
 * a closed file, or append entries to the crash ring buffer. The drop path is
 * protected by the same mutex as shutdown, so concurrent shutdown/log calls
 * cannot race on freed resources.
 */
void log_shutdown(void);

/**
 * Dump the ring buffer contents to a file descriptor.
 * The ring buffer stores the last N log entries for crash reporting.
 * This is called by the crash signal handler (SIGSEGV, SIGABRT, etc.)
 * to include recent log entries in the crash report.
 *
 * The ring buffer size is defined at compile time (RING_BUFFER_SIZE).
 * The default is 1024 entries. The buffer is NOT persisted to disk,
 * so a hard crash will lose the buffer contents. The crash handler
 * must flush the buffer synchronously before the process exits.
 *
 * @param fd File descriptor to write to
 * @return Number of entries written, or -1 on error
 */
int log_dump_ring_buffer(int fd);

/**
 * Log a hex dump of binary data at DEBUG level.
 * Used by the network debugging tools for protocol analysis.
 * The output format matches Wireshark's hex dump format for
 * compatibility with the network team's analysis scripts.
 *
 * The hex dump includes both hexadecimal representation and ASCII
 * representation side by side. Non-printable characters are shown
 * as '.' in the ASCII column. Each line represents 16 bytes.
 *
 * Memory allocation: This function allocates memory internally for
 * the formatted output. If allocation fails, an error is logged
 * and no hex dump is produced. The allocation size is proportional
 * to the input length and should not be called with untrusted data
 * sizes without validation.
 *
 * TODO: Add a maximum data length parameter to prevent accidental
 * OOM from large hex dumps. The current implementation will try
 * to allocate memory for any given length, which could exhaust
 * memory if called with a very large length value.
 *
 * @param label Description label for the dump
 * @param data  Pointer to binary data
 * @param len   Length of binary data in bytes
 */
void log_hex_dump(const char *label, const unsigned char *data, size_t len);

/**
 * Log a failed assertion but do NOT abort.
 * Unlike assert.h's assert(), this function logs the failed assertion
 * and returns 0, allowing the program to continue. This was used
 * extensively during the early development phase when the code was
 * too unstable to abort on every assertion failure.
 *
 * Currently, this function is only used in 3 places, all of which
 * are in the networking code that handles untrusted data. The
 * intentional use of non-aborting assertions in security-sensitive
 * code is... concerning. But changing the behavior now would require
 * a security review and the security team is backlogged.
 *
 * TODO: Audit all uses of log_assert() and convert them to either
 * proper error handling or aborting assertions. The current mixed
 * state is worse than either alternative.
 *
 * @param condition The condition to check
 * @param expr      String representation of the condition
 * @param file      Source file name
 * @param line      Source line number
 * @return 0 if condition is false, 1 if true
 *         (can be used as: if (log_assert(x > 0, "x > 0", ...)) { ... })
 */
int log_assert(int condition, const char *expr, const char *file, int line);

#ifdef __cplusplus
}
#endif

#endif /* LEGACY_LOGGER_H */
