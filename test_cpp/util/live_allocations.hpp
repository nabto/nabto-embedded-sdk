#pragma once

#include <platform/np_allocator.h>

#include <mutex>
#include <set>
#include <stdlib.h>

namespace nabto {
namespace test {

/**
 * Counts the allocations made through the platform allocator which have not
 * been freed yet.
 */
class LiveAllocations {
 public:
    LiveAllocations()
    {
        original_ = *np_allocator_get();
        struct nn_allocator counting;
        counting.calloc = &LiveAllocations::callocImpl;
        counting.free = &LiveAllocations::freeImpl;
        instance() = this;
        np_allocator_set(&counting);
    }

    ~LiveAllocations()
    {
        np_allocator_set(&original_);
        instance() = nullptr;
    }

    size_t live()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return live_.size();
    }

 private:
    static void* callocImpl(size_t n, size_t size)
    {
        void* ptr = calloc(n, size);
        LiveAllocations* self = instance();
        if (self != nullptr && ptr != NULL) {
            std::lock_guard<std::mutex> lock(self->mutex_);
            self->live_.insert(ptr);
        }
        return ptr;
    }

    static void freeImpl(void* ptr)
    {
        LiveAllocations* self = instance();
        if (self != nullptr) {
            std::lock_guard<std::mutex> lock(self->mutex_);
            self->live_.erase(ptr);
        }
        free(ptr);
    }

    static LiveAllocations*& instance()
    {
        static LiveAllocations* instance = nullptr;
        return instance;
    }

    struct nn_allocator original_;
    std::mutex mutex_;
    std::set<void*> live_;
};

} } // namespace
