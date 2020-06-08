#pragma once

#include <util/io_service.hpp>

#include <boost/asio.hpp>

#include <future>

namespace nabto {

class CtrlCWaiter;
typedef std::shared_ptr<CtrlCWaiter> CtrlCWaiterPtr;

class CtrlCWaiter : public std::enable_shared_from_this<CtrlCWaiter> {

 private:
    CtrlCWaiter(boost::asio::io_context& io) : signals_(io, SIGINT, SIGTERM) {}
 public:
    static CtrlCWaiterPtr create(boost::asio::io_context& io)
    {
        return CtrlCWaiterPtr(new CtrlCWaiter(io));
    }

    static void waitForTermination()
    {
        nabto::IoServicePtr io = nabto::IoService::create("waitForTermination");
        CtrlCWaiterPtr waiter = CtrlCWaiter::create(io->getIoService());
        waiter->wait();
    }


    void wait()
    {
        signals_.async_wait(std::bind(&CtrlCWaiter::handler, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
        std::future<void> f = promise_.get_future();
        f.get();
    }

 private:

    void handler(
        const boost::system::error_code& error,
        int /*signal_number*/)
    {
        if (!error)
        {
            // A signal occurred.
        }
        promise_.set_value();
    }

    std::promise<void> promise_;
    boost::asio::signal_set signals_;
};


} // namespace
