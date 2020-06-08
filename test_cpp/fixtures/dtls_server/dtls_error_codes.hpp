#pragma once

#include <util/error_code.hpp>
#include <sstream>

namespace nabto {

/***************
 * DTLS ERRORS *
 ***************/
class DtlsError : public lib::error_category
{
 public:
    enum ErrorCodes {
        ok,
        set_default_config,
        cookie_setup,
        random_seeding_failed,
        init_error,
        set_config,
        set_hostname,
        hostname_not_resolved,
        handshake_failed,
        write_failed,
        invalid_state,
        recv_failed,
        parse_private_key_failed,
        parse_public_key_failed,
        missing_sni_callback,
        keep_alive_timed_out,
        closed
    };
    const char* name() const noexcept { return "DTLS errors"; }
    std::string message(int e) const {
        switch(e) {
            case ok: return "Ok";
            case set_default_config: return "Could not set default config";
            case cookie_setup: return "Cookie setup failed";
            case random_seeding_failed: return "Random Seed failed";
            case init_error: return "Could not initialize dtls module";
            case set_config: return "Set config failed";
            case set_hostname: return "Set hostname failed";
            case hostname_not_resolved: return "Hostname could not be resolved";
            case handshake_failed: return "Handshake failed";
            case write_failed: return "DTLS write failed";
            case invalid_state: return "invalid dtls state";
            case recv_failed: return "recv failed";
            case parse_private_key_failed: return "parse private key failed";
            case parse_public_key_failed: return "parse public key failed";
            case missing_sni_callback: return "dtls server is missing a sni callback";
            case closed: return "DTLS connection is closed";
            default: {
                std::stringstream ss;
                ss << "default error message " << e;
                return ss.str();
            }
        }
    }
};

class DtlsErrorCategoryContainer {
 public:
    static DtlsError& category() {
        static DtlsError category;
        return category;
    }
};

static inline lib::error_code make_error_code(DtlsError::ErrorCodes e) {
    return lib::error_code(static_cast<int>(e), DtlsErrorCategoryContainer::category());
}

} // namespace


NABTO_ERROR_CODE_ENUM_NAMESPACE_START

template<> struct is_error_code_enum<nabto::DtlsError::ErrorCodes>
{
    BOOST_STATIC_CONSTANT(bool, value = true);
};

NABTO_ERROR_CODE_ENUM_NAMESPACE_END
