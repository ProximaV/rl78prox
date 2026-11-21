#include "module_path.h"

#include <cstdio>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace rl78 {

namespace {

std::string StripBasename(const std::string &path) {
    const size_t slash = path.find_last_of("\\/");
    if (slash == std::string::npos) {
        return std::string();
    }
    if (slash == 0) {
        return path.substr(0, 1);
    }
    return path.substr(0, slash);
}

}  // namespace

std::string GetModuleDirectoryForAddress(const void *addr) {
    if (!addr) {
        return std::string();
    }
#ifdef _WIN32
    HMODULE mod = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCSTR>(addr),
                            &mod) ||
        !mod) {
        return std::string();
    }
    char buf[4096] = {};
    const DWORD len = GetModuleFileNameA(mod, buf, static_cast<DWORD>(sizeof(buf)));
    if (len == 0 || len >= sizeof(buf)) {
        return std::string();
    }
    return StripBasename(std::string(buf, len));
#else
    Dl_info info{};
    if (dladdr(addr, &info) == 0 || !info.dli_fname) {
        return std::string();
    }
    return StripBasename(std::string(info.dli_fname));
#endif
}

std::string JoinPath(const std::string &dir, const std::string &filename) {
    if (dir.empty()) {
        return filename;
    }
    if (filename.empty()) {
        return dir;
    }
    const char last = dir.back();
    if (last == '\\' || last == '/') {
        return dir + filename;
    }
#ifdef _WIN32
    return dir + "\\" + filename;
#else
    return dir + "/" + filename;
#endif
}

bool FileExists(const std::string &path) {
    if (path.empty()) {
        return false;
    }
    std::FILE *fp = std::fopen(path.c_str(), "rb");
    if (!fp) {
        return false;
    }
    std::fclose(fp);
    return true;
}

}  // namespace rl78
