#pragma once

#include <cstdio>

using LogCallback = void (*)(const char *msg);
void set_log_callback(LogCallback cb);
void log_printf(const char *fmt, ...);

#define LOG(fmt, ...) \
    do { \
        log_printf("[rl78emu] " fmt "\n", ##__VA_ARGS__); \
    } while (0)

#define LOG_WARN(fmt, ...) \
    do { \
        log_printf("[rl78emu WARN] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#define LOG_ERR(fmt, ...) \
    do { \
        log_printf("[rl78emu ERROR] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
