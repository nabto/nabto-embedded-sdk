
#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <gopt/gopt.h>

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <signal.h>

#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <iostream>

using json = nlohmann::json;

#define MAX_KEY_PEM_SIZE 1024

struct config {
    const char* productId;
    const char* deviceId;
    const char* keyFile;
    const char* hostname;
    char keyPemBuffer[MAX_KEY_PEM_SIZE];
};

static struct config config;

struct streamContext {
    NabtoDeviceStream* stream;
    uint8_t buffer[1500];
    size_t read;
};

#ifdef _WIN32
#define NEWLINE "\r\n"
#else
#define NEWLINE "\n"
#endif

void my_handler(int s){
    printf("Caught signal %d\n",s);
}

void handle_new_stream(struct streamContext* streamContext);
void stream_read_callback(NabtoDeviceFuture* fut, NabtoDeviceError err, void* data);

class AbstractCoapHandler {
 public:
    AbstractCoapHandler(NabtoDevice* device, NabtoDeviceListener* listener) : listener_(listener), device_(device)
    {
        start();
    }
    virtual ~AbstractCoapHandler() {}
    void start() {
        NabtoDeviceFuture* future = nabto_device_future_new(device_);
        nabto_device_listener_new_coap_request(listener_, future, &request_);
        nabto_device_future_set_callback(future, &AbstractCoapHandler::called, this);
    }

    static void called(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        printf("AbstractCoapHandler::called\n");
        if (ec == NABTO_DEVICE_EC_OK) {
            AbstractCoapHandler* handler = (AbstractCoapHandler*)userData;
            handler->handleRequest(handler->request_);
            handler->start();
        }
        nabto_device_future_free(future);
    }

    virtual void handleRequest(NabtoDeviceCoapRequest* request) = 0;
    NabtoDeviceListener* listener_;
    NabtoDeviceCoapRequest* request_;
    NabtoDevice* device_;
};

class GetHandler : public AbstractCoapHandler {
 public:
    GetHandler(NabtoDevice* device, NabtoDeviceListener* listener) : AbstractCoapHandler(device, listener) {}
    void handleRequest(NabtoDeviceCoapRequest* request)
    {
        NabtoDeviceConnectionRef connectionId = nabto_device_coap_request_get_connection_ref(request);
        printf("Received CoAP GET request, connectionId: %" PRIu64 "" NEWLINE, connectionId);
        const char* responseData = "helloWorld";
        nabto_device_coap_response_set_code(request, 205);
        nabto_device_coap_response_set_content_format(request, NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8);
        // TODO: handle OOM
        nabto_device_coap_response_set_payload(request, responseData, strlen(responseData));
        // if underlying connection is gone we ignore it and free request anyway
        nabto_device_coap_response_ready(request);
        nabto_device_coap_request_free(request);
    }
};

class PostHandler : public AbstractCoapHandler {
 public:
    PostHandler(NabtoDevice* device, NabtoDeviceListener* listener) : AbstractCoapHandler(device, listener) {}
    void handleRequest(NabtoDeviceCoapRequest* request)
    {
        const char* responseData = "helloWorld";
        uint16_t contentFormat;
        nabto_device_coap_request_get_content_format(request, &contentFormat);
        if (contentFormat != NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8) {
            const char* responseData = "Invalid content format";
            printf("Received CoAP POST request with invalid content format" NEWLINE);
            nabto_device_coap_response_set_code(request, 400);
            // TODO: handle OOM
            nabto_device_coap_response_set_payload(request, responseData, strlen(responseData));
            // if underlying connection is gone we cleanup anyway
            nabto_device_coap_response_ready(request);
            nabto_device_coap_request_free(request);
        } else {
            char* payload;
            size_t payloadLength;
            nabto_device_coap_request_get_payload(request, (void**)&payload, &payloadLength);
            printf("Received CoAP POST request with a %li byte payload: " NEWLINE "%s", payloadLength, payload);
            nabto_device_coap_response_set_code(request, 205);
            // todo handle OOM
            nabto_device_coap_response_set_payload(request, responseData, strlen(responseData));
            nabto_device_coap_response_set_content_format(request, NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8);
            // if underlying connection is gone we cleanup anyway
            nabto_device_coap_response_ready(request);
            nabto_device_coap_request_free(request);
        }
    }
};

void print_help(const char* message)
{
    if (message) {
        printf("%s", message);
        printf(NEWLINE);
    }
    printf("test_device version %s" NEWLINE, nabto_device_version());
    printf(" USAGE test_device -p <productId> -d <deviceId> -k <keyfile> --hostname <hostname>" NEWLINE);
    printf(" Create a new keypair using `openssl ecparam -genkey -name prime256v1 -out <keyfile>`" NEWLINE);
}

bool parse_args(int argc, const char** argv)
{
    const char* productId;
    const char* deviceId;
    const char* keyFile;
    const char* hostname;

    const char* helpLong[] = { "help", 0 };
    const char* productLong[] = { "product", 0 };
    const char* deviceLong[] = { "device", 0 };
    const char* keyFileLong[] = { "keyfile", 0 };
    const char* hostnameLong[] = { "hostname", 0 };

    const struct { int key; int format; const char* shortName; const char*const* longNames; } opts[] = {
        { 1, GOPT_NOARG, "h", helpLong },
        { 2, GOPT_ARG, "p", productLong },
        { 3, GOPT_ARG, "d", deviceLong },
        { 4, GOPT_ARG, "k", keyFileLong },
        { 5, GOPT_ARG, "", hostnameLong },
        {0,0,0,0}
    };

    void *options = gopt_sort( & argc, argv, opts);
    if( gopt( options, 1)) {
        print_help(NULL);
        return false;
    }

    if (gopt_arg(options, 2, &productId)) {
        config.productId = productId;
    } else {
        print_help("Missing product id");
        return false;
    }

    if (gopt_arg(options, 3, &deviceId)) {
        config.deviceId = deviceId;
    } else {
        print_help("Missing device id");
        return false;
    }

    if (gopt_arg(options, 4, &keyFile)) {
        config.keyFile = keyFile;
    } else {
        print_help("Missing key filename");
        return false;
    }

    if (gopt_arg(options, 5, &hostname)) {
        config.hostname = hostname;
    } else {
        print_help("Missing hostname");
        return false;
    }

    gopt_free(options);
    return true;
}

bool file_exists(const char* filename)
{
    return (access(filename, R_OK) == 0);
}

bool load_key_from_file(const char* filename)
{
    FILE* f;
    f = fopen(filename, "r");
    if (f == NULL) {
        return false;
    }

    // if the read failed the key is invalid and we will fail later.
    fread(config.keyPemBuffer, 1, MAX_KEY_PEM_SIZE, f);

    fclose(f);
    return true;
}

/**
 * Read all incoming data until the stream is closed.  Close the
 * stream in the start to inform the other end that this handler will
 * not send any data.
 */
class RecvHandler {
 public:
    RecvHandler(NabtoDevice* device, NabtoDeviceStream* stream)
        : stream_(stream)
    {
        future_ = nabto_device_future_new(device);
    }
    ~RecvHandler() {
        nabto_device_future_free(future_);
    }
    void start()
    {
        if (future_ == NULL) {
            end();
            return;
        }
        accept();
    }

    void accept()
    {
        nabto_device_stream_accept(stream_, future_);
        nabto_device_future_set_callback(future_, &RecvHandler::accepted, this);
    }

    static void accepted(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        RecvHandler* rh = (RecvHandler*)userData;
        if (ec) {
            // Accept should not fail
            return rh->end();
        } else {
            rh->close();
        }
    }

    void close()
    {
        nabto_device_stream_close(stream_, future_);
        nabto_device_future_set_callback(future_, &RecvHandler::closed, this);
    }

    static void closed(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        RecvHandler* rh = (RecvHandler*)userData;
        if (ec) {
            // this should not fail.
            return rh->end();
        }
        rh->startRead();
    }

    void startRead()
    {
        nabto_device_stream_read_some(stream_, future_, recvBuffer_.data(), recvBuffer_.size(), &transferred_);
        nabto_device_future_set_callback(future_, &RecvHandler::read, this);
    }

    static void read(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        RecvHandler* rh = (RecvHandler*)userData;
        if (ec) {
            // probably eof
            return rh->end();
        }
        rh->totalTransferred_ += rh->transferred_;
        rh->startRead();
    }

    void end() {
        std::cout << "Recv stream end transferred: " << totalTransferred_ << std::endl;
        nabto_device_stream_free(stream_);
        free(this);
    }

 private:
    NabtoDeviceStream* stream_;
    std::array<uint8_t, 1024> recvBuffer_;
    std::size_t transferred_;
    std::size_t totalTransferred_ = 0;
    NabtoDeviceFuture* future_;
};

class EchoHandler {
 public:
    EchoHandler(NabtoDevice* device, NabtoDeviceStream* stream)
        : stream_(stream)
    {
        future_ = nabto_device_future_new(device);
    }

    ~EchoHandler() {
        nabto_device_future_free(future_);
    }
    void start() {
        if (future_ == NULL) {
            end();
            return;
        }

        accept();
    }

    void accept()
    {
        nabto_device_stream_accept(stream_, future_);
        nabto_device_future_set_callback(future_, &EchoHandler::accepted, this);
    }

    static void accepted(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        EchoHandler* eh = (EchoHandler*)userData;
        if (ec) {
            // Accept should not fail
            return eh->end();
        } else {
            eh->startRead();
        }
    }

    void startRead() {
        nabto_device_stream_read_some(stream_, future_, recvBuffer_.data(), recvBuffer_.size(), &transferred_);
        nabto_device_future_set_callback(future_, &EchoHandler::read, this);
    }

    static void read(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        EchoHandler* eh = (EchoHandler*)userData;
        if (ec) {
            // read failed probably eof, close stream
            eh->close();
        } else {
            eh->startWrite();
        }
    }

    void startWrite() {
        nabto_device_stream_write(stream_, future_, recvBuffer_.data(), transferred_);
        nabto_device_future_set_callback(future_, &EchoHandler::written, this);
    }

    static void written(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        EchoHandler* eh = (EchoHandler*)userData;
        if (ec) {
            // write should not fail, goto error
            eh->error();
            return;
        } else {
            eh->startRead();
        }
    }

    void close() {
        nabto_device_stream_close(stream_, future_);
        nabto_device_future_set_callback(future_, &EchoHandler::closed, this);
    }

    static void closed(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData) {
        EchoHandler* eh = (EchoHandler*)userData;
        if (ec) {
            // close should not fail
        }
        eh->end();
    }

    void error() {
        end();
    }

    void end() {
        nabto_device_stream_free(stream_);
        free(this);
    }

 private:
    NabtoDeviceStream* stream_;
    std::array<uint8_t, 1024> recvBuffer_;
    std::size_t transferred_;
    NabtoDeviceFuture* future_;
};

class EchoListener {
 public:
    EchoListener(NabtoDevice* device)
        : device_(device)
    {
        listener_ = nabto_device_listener_new(device_);
        nabto_device_stream_init_listener(device_, listener_, 42);
        listenFuture_ = nabto_device_future_new(device_);
    }
    ~EchoListener() {
        nabto_device_listener_free(listener_);
        nabto_device_future_free(listenFuture_);
    }
    void startListen()
    {
        nabto_device_listener_new_stream(listener_, listenFuture_, &listenStream_);
        nabto_device_future_set_callback(listenFuture_, &EchoListener::newStream, this);
    }

    static void newStream(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        EchoListener* el = (EchoListener*)userData;
        if (ec) {
            return;
        }
        EchoHandler* eh = new EchoHandler(el->device_, el->listenStream_);
        eh->start();
        // TODO: this potentially overwrites listenStream_ resource
        el->startListen();
    }

 private:
    NabtoDeviceListener* listener_;
    NabtoDeviceFuture* listenFuture_;
    NabtoDeviceStream* listenStream_;
    NabtoDevice* device_;
};

class RecvListener {
 public:
    RecvListener(NabtoDevice* device)
        : device_(device)
    {
        listener_ = nabto_device_listener_new(device_);
        nabto_device_stream_init_listener(device_, listener_, 43);
        listenFuture_ = nabto_device_future_new(device_);
    }
    ~RecvListener() {
        nabto_device_listener_free(listener_);
        nabto_device_future_free(listenFuture_);
    }
    void startListen()
    {
        nabto_device_listener_new_stream(listener_, listenFuture_, &listenStream_);
        nabto_device_future_set_callback(listenFuture_, &RecvListener::newStream, this);
    }

    static void newStream(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        RecvListener* rl = (RecvListener*)userData;
        if (ec) {
            return;
        }
        RecvHandler* rh = new RecvHandler(rl->device_, rl->listenStream_);
        rh->start();
        // TODO: this potentially overwrites listenStream_
        rl->startListen();
    }

 private:
    NabtoDeviceListener* listener_;
    NabtoDeviceFuture* listenFuture_;
    NabtoDeviceStream* listenStream_;
    NabtoDevice* device_;
};

void init_iam(NabtoDevice* device);
void run_device()
{
    NabtoDevice* dev;
    NabtoDeviceError ec;
    dev = nabto_device_new();
    nabto_device_set_log_std_out_callback(dev);
    char* logLevel = getenv("NABTO_LOG_LEVEL");
    if (logLevel != NULL) {
        ec = nabto_device_set_log_level(dev, logLevel);
        if (ec != NABTO_DEVICE_EC_OK) {
            printf("Could not set log level: %s , %s" NEWLINE, logLevel, nabto_device_error_get_message(ec));
        } else {
            printf("Log level set to %s" NEWLINE, logLevel);
        }
    }

    ec = nabto_device_set_private_key(dev, config.keyPemBuffer);
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }
    ec = nabto_device_set_server_url(dev, config.hostname);
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }

    nabto_device_set_product_id(dev, config.productId);
    nabto_device_set_device_id(dev, config.deviceId);

    ec = nabto_device_enable_mdns(dev);
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }

    char* fingerprint;
    ec = nabto_device_get_device_fingerprint_hex(dev, &fingerprint);
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }

    printf("Starting device productid: %s, deviceid: %s, fingerprint: %s" NEWLINE, config.productId, config.deviceId, fingerprint);
    nabto_device_string_free(fingerprint);

    init_iam(dev);

    ec = nabto_device_start(dev);
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }

    NabtoDeviceListener* getListener = nabto_device_listener_new(dev);
    NabtoDeviceListener* postListener = nabto_device_listener_new(dev);

    const char* coapTestGet[]  = {"test", "get", NULL};
    const char* coapTestPost[] = {"test", "post", NULL};
    nabto_device_coap_init_listener(dev, getListener, NABTO_DEVICE_COAP_GET, coapTestGet);
    nabto_device_coap_init_listener(dev, postListener, NABTO_DEVICE_COAP_POST, coapTestPost);

    auto getHandler = std::make_unique<GetHandler>(dev, getListener);
    auto postHandler = std::make_unique<PostHandler>(dev, postListener);

    auto echoListener = std::make_unique<EchoListener>(dev);
    auto recvListener = std::make_unique<RecvListener>(dev);
    echoListener->startListen();
    recvListener->startListen();

    struct sigaction sigIntHandler;

    sigIntHandler.sa_handler = my_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL);

    pause();

    printf("closing\n");
    nabto_device_free(dev);
}

int main(int argc, const char** argv)
{
    memset(&config, 0, sizeof(struct config));
    if (!parse_args(argc, argv)) {
        exit(1);
    }

    if (!load_key_from_file(config.keyFile)) {
        print_help("keyfile could not be read");
        exit(1);
    }

    run_device();
}


json addAllPolicy = R"(
{
  "Version": 1,
  "Name": "AllowAll",
  "Statements": [
    {
      "Actions": [ "Test:CoapGet", "Test:CoapPost", "P2P:Stun", "P2P:Rendezvous" ],
      "Allow": true
    }
  ]
}
)"_json;

#define CHECK_CALL(call) do { NabtoDeviceError ec; ec = call; if (ec != NABTO_DEVICE_EC_OK) { std::cout << "call failed " #call << " ec: " << nabto_device_error_get_message(ec) << std::endl; exit(1); } } while (0)

void load_policies(NabtoDevice* device)
{
    std::vector<uint8_t> cbor = json::to_cbor(addAllPolicy);
    CHECK_CALL(nabto_device_iam_policies_create(device, "All", cbor.data(), cbor.size()));
}

void init_iam(NabtoDevice* device)
{
    load_policies(device);
    CHECK_CALL(nabto_device_iam_users_create(device, "admin"));
    CHECK_CALL(nabto_device_iam_roles_create(device, "admin-role"));
    CHECK_CALL(nabto_device_iam_users_add_role(device, "admin", "admin-role"));
    CHECK_CALL(nabto_device_iam_roles_add_policy(device, "admin-role", "All"));
    CHECK_CALL(nabto_device_iam_set_default_role(device, "admin-role"));
}
