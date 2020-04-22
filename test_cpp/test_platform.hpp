#pragma once

#include <memory>
#include <vector>
#include <boost/test/unit_test.hpp>

struct np_platform;

namespace nabto {
namespace test {



class TestPlatform {
 public:
 /**
  * create an instance that matches the current system
  */
    static std::unique_ptr<TestPlatform> create();
    static std::vector<std::shared_ptr<TestPlatform> > multi();
    virtual ~TestPlatform() {}

    virtual void run() = 0;
    virtual void stop() = 0;
    virtual struct np_platform* getPlatform() = 0;
};

} } // namespace
