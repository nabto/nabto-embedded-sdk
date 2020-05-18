#include <util/io_service.hpp>

namespace nabto {

IoService::IoService(const std::string& name)
    : name_(name)
{
}

IoService::~IoService()
{
    stop();
}


IoServicePtr IoService::create(const std::string& name)
{
    IoServicePtr service = IoServicePtr(new IoService(name));
    service->start();
    return service;
}

void IoService::start()
{
    work_.reset(new boost::asio::io_context::work(io_));
    auto& io = io_;
    thread_.reset(new std::thread([&io, this](){
                std::string name = name_;
                io.run();
            }));
}

void IoService::restart()
{
    work_.reset(new boost::asio::io_context::work(io_));
    auto& io = io_;
    io.restart();
    thread_.reset(new std::thread([&io, this](){
                std::string name = name_;
                io.run();
            }));

}

void IoService::workReset()
{
    work_.reset();
}

void IoService::stop()
{
    work_.reset();         // Let all I/O operation finish gracefully

    if (thread_) {
        thread_->join();   // Wait for all threads to stop (all io_.run()'s to return)
    }
    thread_.reset();
}

void IoService::shutdown()
{
    work_.reset();         // Let all I/O operation finish gracefully
    io_.stop();

    if (thread_) {
        thread_->join();
    }
    thread_.reset();
    io_.reset();           // Reset the io service (not thread safe, requires no threads using it)
}

boost::asio::io_context& IoService::getIoService()
{
    return io_;
}

bool IoService::isThisThread()
{
    if (thread_) {
        return (thread_->get_id() == std::this_thread::get_id());
    }
    return false;
}

} // namespace
