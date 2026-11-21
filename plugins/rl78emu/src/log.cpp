#include "log.h"

#include <cstdarg>
#include <cstdio>

namespace {
LogCallback g_log_cb = nullptr;
}  // namespace

void set_log_callback(LogCallback cb) {
    g_log_cb = cb;
}

void log_printf(const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (g_log_cb) {
        g_log_cb(buf);
    } else {
        std::fputs(buf, stdout);
    }
}
