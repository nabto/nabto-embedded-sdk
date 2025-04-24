#include "nabto_device_logging.h"
#include "nabto_device_logging_std_out_callback.h"
#include <nabto/nabto_device_config.h>
#include <stdio.h>

#include <platform/np_platform.h>
#include <platform/np_timestamp_wrapper.h>

static void default_log_callback(NabtoDeviceLogMessage* msg, void* data)
{
    (void)msg; (void)data;
}

static NabtoDeviceLogCallback logCallback = &default_log_callback;
static void* userData = NULL;
static uint32_t level_ = NABTO_LOG_SEVERITY_LEVEL_INFO;

static void logging_log(uint32_t severity, uint32_t module,
                        uint32_t line, const char* file,
                        const char* fmt, va_list args);

void nabto_device_logging_init(void)
{
    np_log.log = &logging_log;
}

void nabto_device_logging_set_level(uint32_t level)
{
    level_ = level;
}

void logging_log(uint32_t severity, uint32_t module,
                uint32_t line, const char* file,
                const char* fmt, va_list args)
{
    (void)module;
    if (level_ & severity) {
        NabtoDeviceLogMessage msg;
        char log[256];
        vsnprintf(log, sizeof(log)-1, fmt, args);

        log[sizeof(log) - 1] = 0; // ensure the output is null terminated.

        switch(severity) {
            case NABTO_LOG_SEVERITY_ERROR:
                msg.severity = NABTO_DEVICE_LOG_ERROR;
                break;
            case NABTO_LOG_SEVERITY_WARN:
                msg.severity = NABTO_DEVICE_LOG_WARN;
                break;
            case NABTO_LOG_SEVERITY_INFO:
                msg.severity = NABTO_DEVICE_LOG_INFO;
                break;
            case NABTO_LOG_SEVERITY_TRACE:
                msg.severity = NABTO_DEVICE_LOG_TRACE;
                break;
            default:
                msg.severity = NABTO_DEVICE_LOG_ERROR;
                break;
        }

        msg.file = file;
        // We do not have files with more lines that int
        msg.line = (int)line;
        msg.message = log;
        logCallback(&msg, userData);
    }
}

void nabto_device_logging_set_callback(NabtoDeviceLogCallback cb, void* data)
{
    userData = data;
    if (cb) {
        logCallback = cb;
    } else {
        logCallback = &default_log_callback;
    }
}

// implementation of nabto_device.h functions

const char* NABTO_DEVICE_API
nabto_device_log_severity_as_string(NabtoDeviceLogLevel severity)
{
    switch(severity) {
        case NABTO_DEVICE_LOG_ERROR:
            return "ERROR";
        case NABTO_DEVICE_LOG_WARN:
            return "WARN";
        case NABTO_DEVICE_LOG_INFO:
            return "INFO";
        case NABTO_DEVICE_LOG_TRACE:
            return "TRACE";
        default:
            // should not happen
            return "NONE";
    }
}


NabtoDeviceError NABTO_DEVICE_API nabto_device_set_log_callback(NabtoDevice* device, NabtoDeviceLogCallback cb, void* data)
{
    (void)device;
    nabto_device_logging_set_callback(cb, data);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_log_level(NabtoDevice* device, const char* level)
{
    (void)device;
    uint32_t l = 0;
    if (strcmp(level, "error") == 0) {
        l = NABTO_LOG_SEVERITY_LEVEL_ERROR;
    } else if (strcmp(level, "warn") == 0) {
        l = NABTO_LOG_SEVERITY_LEVEL_WARN;
    } else if (strcmp(level, "info") == 0) {
        l = NABTO_LOG_SEVERITY_LEVEL_INFO;
    } else if (strcmp(level, "trace") == 0) {
        l = NABTO_LOG_SEVERITY_LEVEL_TRACE;
    } else {
        return NABTO_DEVICE_EC_INVALID_ARGUMENT;
    }
    nabto_device_logging_set_level(l);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_log_std_out_callback(NabtoDevice* device)
{
    (void)device;
#ifndef NABTO_DEVICE_NO_LOG_STD_OUT_CALLBACK
    nabto_device_logging_set_callback(nabto_device_logging_std_out_callback, NULL);
    return NABTO_DEVICE_EC_OK;
#else
    return NABTO_DEVICE_EC_NOT_IMPLEMENTED;
#endif
}
