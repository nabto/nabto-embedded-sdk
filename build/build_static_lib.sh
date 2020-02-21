#!/bin/bash

ARCHIVE_LIBS=""

ARCHIVE_LIBS+=" nabto-common-cpp/src/stun/libnabto_stun_client.a"
ARCHIVE_LIBS+=" nabto-common-cpp/src/streaming/libnabto_stream.a"
ARCHIVE_LIBS+=" nabto-common-cpp/src/mdns/libmdns_server.a"
ARCHIVE_LIBS+=" nabto-common-cpp/src/coap/libcoap.a"
ARCHIVE_LIBS+=" src/platform/libnp_platform.a"
ARCHIVE_LIBS+=" src/modules/dtls/libnm_dtls_cli.a"
ARCHIVE_LIBS+=" src/modules/dtls/libnm_dtls_srv.a"
ARCHIVE_LIBS+=" src/modules/dns/unix/libnm_dns.a"
ARCHIVE_LIBS+=" src/modules/tcptunnel/libnm_tcptunnel.a"
ARCHIVE_LIBS+=" src/modules/communication_buffer/libnm_unix_communication_buffer.a"
ARCHIVE_LIBS+=" src/modules/logging/test/libnm_logging_test.a"
ARCHIVE_LIBS+=" src/modules/logging/unix/libnm_logging_unix.a"
ARCHIVE_LIBS+=" src/modules/logging/api/libnm_logging_api.a"
ARCHIVE_LIBS+=" src/modules/mdns/libnm_mdns.a"
ARCHIVE_LIBS+=" src/modules/epoll/libnm_epoll.a"
ARCHIVE_LIBS+=" src/modules/timestamp/unix/libnm_timestamp.a"
ARCHIVE_LIBS+=" src/modules/unix/libnm_unix.a"
ARCHIVE_LIBS+=" src/modules/select_unix/libnm_select_unix.a"
ARCHIVE_LIBS+=" src/core/libnc_core.a"
ARCHIVE_LIBS+=" src/api/libnabto_device_api.a"
ARCHIVE_LIBS+=" 3rdparty/tinycbor/lib3rdparty_tinycbor.a"
ARCHIVE_LIBS+=" 3rdparty/mbedtls/lib3rdparty_mbedtls.a"

LIB_EXCLUDE_PATTERN="test|boost_program_options|boost_timer|libcoap2_cpp|libclient_examples_common|examples|lib3rdparty_cjson|gopt"

function usage() {
    echo "Usage: $0 <build root dir> <target output file>"
    exit 1
}

# validate that libs in ARCHIVE_LIBS exist and that none are forgotten in list
function validate-archive-libs() {
    local root=$1
    for lib in $ARCHIVE_LIBS; do
        local file=$root/$lib
        if [ ! -f $file ]; then
            echo "ERROR: '$file' not found as input for archive"
            usage
        fi
    done

    pushd . > /dev/null

    cd $root
    local libs=`find . -name "*.a" | grep -v -E $LIB_EXCLUDE_PATTERN | sed "s|^\./||"`
    for actual_lib in $libs; do
        local found=0
        for requested_lib in $ARCHIVE_LIBS; do
            if [ "$requested_lib" == "$actual_lib" ]; then
                found=1
                break;
            fi
        done
        if [ "$found" != "1" ]; then
            echo "ERROR: '$actual_lib' not requested to be included in archive - either add to ARCHIVE_LIBS or update LIB_EXCLUDE_PATTERN"
            usage
        fi
    done

    popd > /dev/null
}

function build-static-lib() {
    local root=$1
    local target=$2

    validate-archive-libs $root

    local tmp=`mktemp -d`
    cd $tmp

    for lib in $ARCHIVE_LIBS; do
        local file=$root/$lib
        mkdir -p $lib
        cd $lib
        ar -x $file
        cd - > /dev/null
        ar -vq $target `find $lib -name "*.o" -or -name "*.obj"`
        rm -rf $lib
    done
}

if [ $# != 2 ]; then
    usage
fi

build-static-lib $1 $2
