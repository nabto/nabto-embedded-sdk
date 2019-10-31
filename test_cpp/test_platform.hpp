#pragma once

#include <memory>

struct np_platform;

namespace nabto {
namespace test {

class TestPlatform {
 public:
 /**
  * create an instance that matches the current system
  */
    static std::unique_ptr<TestPlatform> create();
    virtual ~TestPlatform() {}

    virtual void init() = 0;
    virtual void run() = 0;
    virtual void stop() = 0;
    virtual struct np_platform* getPlatform() = 0;
};

} } // namespace
