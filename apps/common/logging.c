#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <nabto/nabto_device.h>
#include <nn/log.h>

#include <stdio.h>

static void device_log(NabtoDeviceLogMessage* msg, void* data);
static void nn_log_function(void* userData, enum nn_log_severity severity, const char* module, const char* file, int line, const char* fmt, va_list args);

static int logMask = 0;

void logging_init(NabtoDevice* device, struct nn_log* logger, const char* logLevel)
{
    nabto_device_set_log_callback(device, device_log, NULL);
    nabto_device_set_log_level(device, logLevel);

    nn_log_init(logger, nn_log_function, NULL);

    if (strcmp(logLevel, "error") == 0) {
        logMask = NN_LOG_SEVERITY_ERROR;
    } else if (strcmp(logLevel, "warn") == 0) {
        logMask = NN_LOG_SEVERITY_ERROR | NN_LOG_SEVERITY_WARN;
    } else if (strcmp(logLevel, "info") == 0) {
        logMask = NN_LOG_SEVERITY_ERROR | NN_LOG_SEVERITY_WARN | NN_LOG_SEVERITY_INFO;
    } else if (strcmp(logLevel, "trace") == 0) {
        logMask = NN_LOG_SEVERITY_ERROR | NN_LOG_SEVERITY_WARN | NN_LOG_SEVERITY_INFO | NN_LOG_SEVERITY_TRACE;
    }
}

const char* truncated_file_name(const char* filename)
{
    size_t len = strlen(filename);
    if (len > 24) {
        return filename + (len-24);
    }
    return filename;
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
    (void)data;
    printf("%s:%s %s - ", truncated_file_name(msg->file), line_as_str(msg->line), device_severity_as_string(msg->severity));
    printf("%s\n", msg->message);
    fflush(stdout);
}

const char* nn_log_severity_as_str(enum nn_log_severity severity)
{
    switch(severity) {
        case NN_LOG_SEVERITY_ERROR: return "ERROR";
        case NN_LOG_SEVERITY_WARN:  return "WARN ";
        case NN_LOG_SEVERITY_INFO:  return "INFO ";
        case NN_LOG_SEVERITY_TRACE: return "TRACE";
    }
    return "NONE ";
}

void nn_log_function(void* userData, enum nn_log_severity severity, const char* module, const char* file, int line, const char* fmt, va_list args)
{
    (void)userData; (void)module;
    if ((severity & logMask) != 0) {
        printf("%s:%s %s - ", truncated_file_name(file), line_as_str(line), nn_log_severity_as_str(severity));
        vprintf(fmt, args);
        printf("\n");
        fflush(stdout);
    }
}

#endif
