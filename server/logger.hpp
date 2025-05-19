#pragma once
#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <iostream>

namespace Xianwei_logger {
std::shared_ptr<spdlog::logger> g_default_logger = nullptr;
void init_logger(bool mode, const std::string& filename, int32_t level) {
    if (mode == false) {
        g_default_logger = spdlog::stdout_color_mt(filename);
        g_default_logger->set_level((spdlog::level::level_enum)level);
        g_default_logger->flush_on((spdlog::level::level_enum)level);
    } else {
        g_default_logger = spdlog::basic_logger_mt("default-logger", filename);
        g_default_logger->set_level((spdlog::level::level_enum)level);
        g_default_logger->flush_on((spdlog::level::level_enum)level);
    }
    g_default_logger->set_pattern(
        "[%Y-%02m-%02d][%H:%M:%S][thread:%t][%-8l]%v");
}
#define LOG_TRACE(format, ...)                                                \
    Xianwei_logger::g_default_logger->trace(std::string("[{},{}] ") + format, \
                                            __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_DEBUG(format, ...)                                                \
    Xianwei_logger::g_default_logger->debug(std::string("[{},{}] ") + format, \
                                            __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_INFO(format, ...)                                                \
    Xianwei_logger::g_default_logger->info(std::string("[{},{}] ") + format, \
                                           __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_WARN(format, ...)                                                \
    Xianwei_logger::g_default_logger->warn(std::string("[{},{}] ") + format, \
                                           __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_ERROR(format, ...)                                                \
    Xianwei_logger::g_default_logger->error(std::string("[{},{}] ") + format, \
                                            __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_FATAL(format, ...)                  \
    Xianwei_logger::g_default_logger->critical( \
        std::string("[{},{}] ") + format, __FILE__, __LINE__, ##__VA_ARGS__)
}  // namespace Xianwei_logger
