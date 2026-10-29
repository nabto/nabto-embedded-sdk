#pragma once

#include <platform/np_allocator.h>

#include <stdlib.h>

namespace nabto {
namespace test {

/**
 * Replaces the allocator of the platform with one which fails the allocations
 * of one given size while it is armed. The allocator is restored when the
 * object is destroyed.
 */
class FailingAllocator {
 public:
    FailingAllocator()
    {
        original_ = *np_allocator_get();
        struct nn_allocator failing;
        failing.calloc = &FailingAllocator::callocImpl;
        failing.free = &FailingAllocator::freeImpl;
        instance() = this;
        np_allocator_set(&failing);
    }

    ~FailingAllocator()
    {
        np_allocator_set(&original_);
        instance() = nullptr;
    }

    /**
     * Fail the allocations of exactly size bytes until disarm().
     */
    void failSize(size_t size)
    {
        size_ = size;
        armed_ = true;
    }

    void disarm() { armed_ = false; }

    /**
     * The number of allocations which were failed.
     */
    size_t failures() const { return failures_; }

 private:
    static void* callocImpl(size_t n, size_t size)
    {
        FailingAllocator* self = instance();
        if (self != nullptr && self->armed_ && n * size == self->size_) {
            self->failures_++;
            return NULL;
        }
        return calloc(n, size);
    }

    static void freeImpl(void* ptr) { free(ptr); }

    static FailingAllocator*& instance()
    {
        static FailingAllocator* instance = nullptr;
        return instance;
    }

    struct nn_allocator original_;
    bool armed_ = false;
    size_t size_ = 0;
    size_t failures_ = 0;
};

} } // namespace
