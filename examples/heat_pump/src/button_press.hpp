#pragma once

#include <condition_variable>
#include <thread>
#include <chrono>

namespace nabto {

std::condition_variable cv;
bool answer;

std::unique_ptr<std::thread> buttonThread_;

void readInput()
{
    for(;;) {
        char c;
        std::cin >> c;
        if (c == 'n') {
            answer = false;
            cv.notify_one();
            return;
        } else if (c == 'y') {
            answer = true;
            cv.notify_one();
            return;
        } else {
            std::cout << "valid answers y or n" << std::endl;
        }
    }
}

void questionHandler(std::chrono::seconds waitTime, std::function<void (bool accepted)> cb)
{
    std::thread t(readInput);
    t.detach();
    std::mutex mtx;
    std::unique_lock<std::mutex> lock(mtx);
    bool result = false;
    if (cv.wait_for(lock, waitTime) == std::cv_status::timeout) {
        std::cout << "No input given defaulting to n" << std::endl;
        result = false;
    } else {
        result = answer;
    }
    cb(result);
}

class ButtonPress {
 public:
    static void wait(std::chrono::seconds t, std::function<void (bool accepted)> cb)
    {
        buttonThread_ = std::make_unique<std::thread>(questionHandler, t, cb);
        buttonThread_->detach();
    }
};

} // namespace
