#pragma once

#include <string>

namespace rl78 {

// Returns the directory containing the binary module that owns `addr` (without trailing slash).
std::string GetModuleDirectoryForAddress(const void *addr);

// Joins `dir` and `filename` using the platform path separator.
std::string JoinPath(const std::string &dir, const std::string &filename);

// Returns true if `path` exists and is readable as a regular file.
bool FileExists(const std::string &path);

}  // namespace rl78
