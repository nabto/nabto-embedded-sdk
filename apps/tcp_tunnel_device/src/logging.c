#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <nabto/nabto_device.h>
#include <nn/log.h>

#include <stdio.h>

const char* truncated_file_name(const char* filename)
{
    size_t len = strlen(filename);
    if (len > 24) {
        return filename + (len-24);
    } else {
        return filename;
    }
}

const char* line_as_str(int line)
{
    static char buffer[32];
    if (line < 10) {
        sprintf(buffer, "%d   ", line);
    } else if (line < 100) {
        sprintf(buffer, "%d  ", line);
    } else if (line < 1000) {
        sprintf(buffer, "%d ", line);
    } else {
        sprintf(buffer, "%d", line);
    }
    return buffer;
}

const char* device_severity_as_string(NabtoDeviceLogLevel severity)
{
    switch (severity) {
        case NABTO_DEVICE_LOG_FATAL: return "FATAL";
        case NABTO_DEVICE_LOG_ERROR: return "ERROR";
        case NABTO_DEVICE_LOG_WARN:  return "WARN ";
        case NABTO_DEVICE_LOG_INFO:  return "INFO ";
        case NABTO_DEVICE_LOG_TRACE: return "TRACE";
    }
    return "NONE ";
}



void device_log(NabtoDeviceLogMessage* msg, void* data)
{
    printf("%s:%s %s", truncated_file_name(msg->file), line_as_str(msg->line), device_severity_as_string(msg->severity));
    printf(" %s\n", msg->message);
}

void log_function(enum nn_log_severity severity, const char* module, const char* file, int line, const char* fmt, va_list args)
{
    const char* severityStr = "NONE ";
    if (severity == NN_LOG_SEVERITY_ERROR) {
        severityStr = "ERROR";
    } else if (severity == NN_LOG_SEVERITY_WARN) {
        severityStr = "WARN ";
    } else if (severity == NN_LOG_SEVERITY_INFO) {
        severityStr = "INFO ";
    } else if (severity == NN_LOG_SEVERITY_TRACE) {
        severityStr = "TRACE";
    }

    printf("%s:%04d %s ", file, line, severityStr);
    vprintf(fmt, args);
    printf("\n");
}

#endif
