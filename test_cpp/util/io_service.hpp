#pragma once

#include <boost/asio/io_context.hpp>
#include <memory>
#include <thread>
#include <string>

namespace nabto {

class IoService;
typedef std::shared_ptr<IoService> IoServicePtr;

class IoService {
 private:
    IoService(const std::string& name);
 public:
    ~IoService();
    static IoServicePtr create(const std::string& name);
    void stop();
    void shutdown();
    boost::asio::io_context& getIoService();

    // return true if the thread calling this function is the thread running this io service.
    bool isThisThread();
private:
    void start();
    boost::asio::io_context io_;
    std::unique_ptr<std::thread> thread_;
    std::string name_;
    boost::asio::executor_work_guard<
        boost::asio::io_context::executor_type, void, void>
        work_;

};

} // namespace
