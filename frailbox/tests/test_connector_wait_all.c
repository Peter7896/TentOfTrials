#define _GNU_SOURCE
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../connector/api.h"

#define CHECK(condition, message) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", message, __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

typedef struct {
    unsigned delay_ms;
    atomic_int *completed;
} callback_state_t;

static connector_config_t async_config(void)
{
    connector_config_t config;

    memset(&config, 0, sizeof(config));
    config.config_version = CONNECTOR_CONFIG_VERSION;
    config.struct_size = sizeof(config);
    config.mode = CONNECTOR_MODE_ASYNC;
    config.timeout_ms = 1000;
    config.max_concurrency = 1;
    config.receive_buffer_size = 4096;
    config.send_buffer_size = 4096;
    config.max_message_size = 4096;
    config.encoding = CONNECTOR_ENCODING_BINARY;
    config.compression = CONNECTOR_COMPRESSION_NONE;
    config.default_priority = CONNECTOR_PRIORITY_NORMAL;
    return config;
}

static void completion_callback(uint64_t operation_id,
                                connector_result_t result,
                                void *user_data)
{
    callback_state_t *state = (callback_state_t *)user_data;
    (void)operation_id;

    if (state != NULL && state->delay_ms > 0) {
        usleep(state->delay_ms * 1000);
    }
    if (state != NULL && result == CONNECTOR_SUCCESS) {
        atomic_fetch_add(state->completed, 1);
    }
}

static int init_async_connector(void)
{
    connector_config_t config = async_config();
    return connector_init(&config) == CONNECTOR_SUCCESS ? 0 : 1;
}

static connector_operation_t operation(uint64_t id, callback_state_t *state)
{
    connector_operation_t op;

    memset(&op, 0, sizeof(op));
    op.operation_id = id;
    op.operation_type = 1;
    op.direction = CONNECTOR_DIRECTION_OUTBOUND;
    op.priority = CONNECTOR_PRIORITY_NORMAL;
    op.timeout_ms = 1000;
    op.callback = completion_callback;
    op.user_data = state;
    return op;
}

static int test_wait_all_all_complete(void)
{
    atomic_int completed = 0;
    callback_state_t state = {.delay_ms = 1, .completed = &completed};
    connector_operation_t ops[3];
    connector_stats_t stats;

    CHECK(init_async_connector() == 0, "async connector initializes");
    for (int i = 0; i < 3; i++) {
        ops[i] = operation((uint64_t)i + 1, &state);
        CHECK(connector_submit(&ops[i]) == CONNECTOR_SUCCESS, "operation submits");
    }

    CHECK(connector_wait_all(1000) == CONNECTOR_SUCCESS, "wait_all completes batch");
    CHECK(atomic_load(&completed) == 3, "all callbacks complete successfully");

    memset(&stats, 0, sizeof(stats));
    stats.struct_size = sizeof(stats);
    CHECK(connector_get_stats(&stats) == CONNECTOR_SUCCESS, "stats are available");
    CHECK(stats.queue_depth == 0, "queue depth reports no unfinished operations");
    CHECK(stats.successful_operations == 3, "completed operations are reported successful");

    CHECK(connector_shutdown() == CONNECTOR_SUCCESS, "connector shuts down");
    return 0;
}

static int test_wait_all_partial_timeout(void)
{
    atomic_int completed = 0;
    callback_state_t state = {.delay_ms = 75, .completed = &completed};
    connector_operation_t ops[2];
    connector_stats_t stats;

    CHECK(init_async_connector() == 0, "async connector initializes for timeout test");
    for (int i = 0; i < 2; i++) {
        ops[i] = operation((uint64_t)i + 10, &state);
        CHECK(connector_submit(&ops[i]) == CONNECTOR_SUCCESS, "operation submits");
    }

    CHECK(connector_wait_all(1) == CONNECTOR_ERROR_TIMEOUT,
          "short wait_all timeout reports timeout");

    memset(&stats, 0, sizeof(stats));
    stats.struct_size = sizeof(stats);
    CHECK(connector_get_stats(&stats) == CONNECTOR_SUCCESS, "timeout stats are available");
    CHECK(stats.queue_depth > 0, "timeout stats report unfinished operations");
    CHECK(stats.last_error_code == CONNECTOR_ERROR_TIMEOUT, "timeout status is recorded");
    CHECK(strstr(stats.last_error_message, "unfinished operation") != NULL,
          "timeout error includes unfinished count");

    CHECK(connector_wait_all(1000) == CONNECTOR_SUCCESS, "later wait_all completes");
    CHECK(atomic_load(&completed) == 2, "timed batch eventually completes");

    CHECK(connector_shutdown() == CONNECTOR_SUCCESS, "connector shuts down after timeout test");
    return 0;
}

static int test_wait_all_zero_timeout(void)
{
    atomic_int completed = 0;
    callback_state_t state = {.delay_ms = 50, .completed = &completed};
    connector_operation_t op = operation(99, &state);
    connector_stats_t stats;

    CHECK(init_async_connector() == 0, "async connector initializes for zero-timeout test");
    CHECK(connector_submit(&op) == CONNECTOR_SUCCESS, "operation submits");
    CHECK(connector_wait_all(0) == CONNECTOR_ERROR_TIMEOUT,
          "zero-timeout wait_all does not block with unfinished work");

    memset(&stats, 0, sizeof(stats));
    stats.struct_size = sizeof(stats);
    CHECK(connector_get_stats(&stats) == CONNECTOR_SUCCESS, "zero-timeout stats are available");
    CHECK(stats.queue_depth > 0, "zero-timeout stats report unfinished operations");

    CHECK(connector_wait_all(1000) == CONNECTOR_SUCCESS, "zero-timeout operation later completes");
    CHECK(atomic_load(&completed) == 1, "zero-timeout operation completed successfully");

    CHECK(connector_shutdown() == CONNECTOR_SUCCESS, "connector shuts down after zero-timeout test");
    return 0;
}

int main(void)
{
    if (test_wait_all_all_complete() != 0) {
        return 1;
    }
    if (test_wait_all_partial_timeout() != 0) {
        return 1;
    }
    if (test_wait_all_zero_timeout() != 0) {
        return 1;
    }

    printf("connector wait_all tests passed\n");
    return 0;
}
