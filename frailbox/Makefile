CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c2x -O2 -g
CFLAGS += -D_FORTIFY_SOURCE=3
CFLAGS += -fstack-protector-strong
CFLAGS += -fPIE
LDFLAGS = -pie -z relro -z now

SRCDIR = src
INCDIR = include
BUILDDIR = build

SRCS = $(wildcard $(SRCDIR)/*.c) main.c
OBJS = $(patsubst %.c, $(BUILDDIR)/%.o, $(SRCS))
DEPS = $(OBJS:.o=.d)

TARGET = frailbox
TEST_LOGGER_SHUTDOWN = $(BUILDDIR)/tests/test_logger_shutdown
TEST_CONNECTOR_WAIT_ALL = $(BUILDDIR)/tests/test_connector_wait_all

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -I$(INCDIR) $^ -o $@ $(LDFLAGS)

$(BUILDDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(INCDIR) -MMD -MP -c $< -o $@

-include $(DEPS)

clean:
	rm -rf $(BUILDDIR) $(TARGET)

distclean: clean
	rm -rf *.o *.d

$(TEST_LOGGER_SHUTDOWN): tests/test_logger_shutdown.c $(SRCDIR)/logger.c $(INCDIR)/logger.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(INCDIR) tests/test_logger_shutdown.c $(SRCDIR)/logger.c -o $@ -pthread

$(TEST_CONNECTOR_WAIT_ALL): tests/test_connector_wait_all.c connector/api.c connector/api.h connector/protocol.c connector/protocol.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(INCDIR) -Iconnector tests/test_connector_wait_all.c connector/api.c connector/protocol.c -o $@ -pthread

test-logger-shutdown: $(TEST_LOGGER_SHUTDOWN)
	./$(TEST_LOGGER_SHUTDOWN)

test-connector-wait-all: $(TEST_CONNECTOR_WAIT_ALL)
	./$(TEST_CONNECTOR_WAIT_ALL)

test: test-logger-shutdown test-connector-wait-all

valgrind: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET)

.PHONY: all clean distclean test valgrind
