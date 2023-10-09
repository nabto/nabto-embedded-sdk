#pragma once
#include <boost/test/unit_test.hpp>

#include <modules/iam/nm_iam.h>
#include <modules/iam/nm_iam_serializer.h>

#include <iostream>

namespace nabto {
namespace test {


void iam_logger(void* data, enum nn_log_severity severity, const char* module,
    const char* file, int line,
    const char* fmt, va_list args);

NabtoDevice* buildIamTestDevice(std::string& confStr, std::string& stateStr, struct nm_iam* iam);

}} // namespaces
