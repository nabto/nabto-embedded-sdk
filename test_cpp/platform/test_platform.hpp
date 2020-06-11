#pragma once

#include <memory>
#include <vector>
#include <boost/test/unit_test.hpp>

struct np_platform;

namespace nabto {
namespace test {

class TestPlatform;

class TestPlatformFactory {
 public:
    virtual ~TestPlatformFactory() {}
    virtual std::shared_ptr<TestPlatform> create() = 0;
    static std::vector<std::shared_ptr<TestPlatformFactory> > multi();
};

class TestPlatform {
 public:
 /**
  * create an instance that matches the current system
  */
    static std::unique_ptr<TestPlatform> create();
    virtual ~TestPlatform() {}

    virtual void run() = 0;
    virtual void stop() = 0;
    virtual void waitForStopped() = 0;
    virtual struct np_platform* getPlatform() = 0;
};

} } // namespace
