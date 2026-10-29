#include <boost/test/unit_test.hpp>

#include <test_platform.hpp>

#include <core/nc_packet.h>
#include <core/nc_stream_manager.h>

#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

// Copy the packet into a heap allocation of exactly its size, as the dtls
// layer hands it over, so a read past the end is caught by ASan.
uint8_t* exact_heap_copy(const std::vector<uint8_t>& packet)
{
    uint8_t* buffer = (uint8_t*)malloc(packet.size());
    memcpy(buffer, packet.data(), packet.size());
    return buffer;
}

void handle_truncated_packet(const std::vector<uint8_t>& packet)
{
    auto tp = nabto::test::TestPlatform::create();
    struct nc_stream_manager_context ctx;
    nc_stream_manager_init(&ctx, tp->getPlatform(), NULL);

    uint8_t* buffer = exact_heap_copy(packet);
    // The packet ends right after the stream id, there are no flags. It is
    // dropped before the connection is used.
    nc_stream_manager_handle_packet(&ctx, NULL, buffer, (uint16_t)packet.size());
    free(buffer);

    nc_stream_manager_deinit(&ctx);
}

} // namespace

BOOST_AUTO_TEST_SUITE(stream_demux)

BOOST_AUTO_TEST_CASE(packet_ends_after_4_byte_stream_id)
{
    // application type, 4 byte varint stream id
    handle_truncated_packet({ 0x50, 0x80, 0x00, 0x00, 0x01 });
}

BOOST_AUTO_TEST_CASE(packet_ends_after_8_byte_stream_id)
{
    // application type, 8 byte varint stream id
    handle_truncated_packet({ 0x50, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 });
}

BOOST_AUTO_TEST_CASE(var_uint_read_empty_buffer)
{
    // Reading from an empty buffer must fail without touching the buffer. The
    // empty buffer is the end of an allocation, so reading it is out of
    // bounds.
    uint8_t* allocation = (uint8_t*)malloc(1);
    uint8_t* empty = allocation + 1;
    uint64_t val = 42;
    uint8_t len = 42;
    BOOST_TEST(var_uint_read(empty, 0, &val, &len) == false);
    free(allocation);
}

BOOST_AUTO_TEST_SUITE_END()
