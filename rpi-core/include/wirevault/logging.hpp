#pragma once
// wirevault/logging.hpp - small leveled stderr logger (root daemon logs there
// before systemd picks it up via journald).
#include <cstdarg>
#include <ctime>
#include <mutex>
#include <string>

namespace wv {

enum class LogLevel { Debug = 0, Info = 1, Warn = 2, Error = 3 };

class Logger {
public:
  static Logger &instance() {
    static Logger g;
    return g;
  }
  void setLevel(LogLevel l) {
    std::lock_guard<std::mutex> lk(mtx_);
    level_ = l;
  }
  void log(LogLevel l, const char *tag, const char *fmt, ...) {
    if (static_cast<int>(l) < static_cast<int>(getLevelFlag()))
      return;
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    std::lock_guard<std::mutex> lk(mtx_);
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    std::fprintf(stderr, "[%02d:%02d:%02d] [%s] [%s] %s\n", tmv.tm_hour,
                 tmv.tm_min, tmv.tm_sec, levelName(l), tag, msg);
    std::fflush(stderr);
  }

private:
  LogLevel getLevelFlag() {
    std::lock_guard<std::mutex> lk(mtx_);
    return level_;
  }
  static const char *levelName(LogLevel l) {
    switch (l) {
    case LogLevel::Debug: return "DBG";
    case LogLevel::Info: return "INF";
    case LogLevel::Warn: return "WRN";
    case LogLevel::Error: return "ERR";
    }
    return "?";
  }
  std::mutex mtx_;
  LogLevel level_ = LogLevel::Info;
};

#define WV_DEBUG(...) ::wv::Logger::instance().log(::wv::LogLevel::Debug, "wirevault", __VA_ARGS__)
#define WV_INFO(...) ::wv::Logger::instance().log(::wv::LogLevel::Info, "wirevault", __VA_ARGS__)
#define WV_WARN(...) ::wv::Logger::instance().log(::wv::LogLevel::Warn, "wirevault", __VA_ARGS__)
#define WV_ERROR(...) ::wv::Logger::instance().log(::wv::LogLevel::Error, "wirevault", __VA_ARGS__)

} // namespace wv
