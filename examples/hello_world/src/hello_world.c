#include <nabto/nabto_device.h>

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif
#include <stdbool.h>
#include <stdio.h>

// Configuration parameters

// The product ID, device ID, and server URL picked here are not
// configured in the Nabto Basestation. Therefore, the basestation
// will reject the device when it attempts to attach to the
// basestation. This example will still work if the client is able to
// discover the device on the local network. Alternatively, replace
// these values with valid values from the Nabto Cloud Console. The
// private Key is set to NULL, this causes this code to generate a new
// private key (see function "start_device"). If the device should be able to attach
// to the basestation, the private key here should be set to a valid
// private key, and the fingerprint of the key must be configured in
// the Nabto Cloud Console.
const char* productId = "pr-abcd1234";
const char* deviceId = "de-efgh5678";
const char* serverUrl = "pr-abcd1234.devices.dev.nabto.net";
char* privateKey = NULL;

// CoAP endpoint data
const char* coapPath[] = { "hello-world", NULL };
const char* helloWorld = "Hello world";

// State variable
bool readyToStop = false;

// Helper functions
bool start_device(NabtoDevice* device);
void handle_device_error(NabtoDevice* d, NabtoDeviceListener* l, NabtoDeviceFuture* f, char* msg);
void do_important_work();
void handle_coap_request(NabtoDeviceCoapRequest* request);
void request_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data);

int main(int argc, char** argv)
{
    NabtoDeviceError ec;

    // First allocate a new device
    NabtoDevice* device = nabto_device_new();
    if (device == NULL) {
        handle_device_error(NULL, NULL, NULL, "Failed to allocate device"); return -1;
    }

    // We have to configure a few things before starting the device,
    // so we make a function not to clutter the example.
    if (!start_device(device)) {
        handle_device_error(device, NULL, NULL, "Failed to start device"); return -1;
    }

    // We need a listener to handle incoming CoAP requests. First we
    // allocate one.
    NabtoDeviceListener* listener = nabto_device_listener_new(device);
    if (listener == NULL) {
        handle_device_error(device, NULL, NULL, "Failed to allocate listener"); return -1;
    }

    // Then we initialize it for CoAP requests for our hello world
    // path. The listener is now locked for this purpose only, and we
    // must not reuse it in other listener initialization calls.
    ec = nabto_device_coap_init_listener(device, listener, NABTO_DEVICE_COAP_GET, coapPath);
    if (ec != NABTO_DEVICE_EC_OK) {
        handle_device_error(device, listener, NULL, "CoAP listener initialization failed"); return -1;
    }

    // Now that our listener is listening for CoAP requests, we need a
    // future so we can query the listener for CoAP requests. First
    // the future must be allocated.
    NabtoDeviceFuture* future = nabto_device_future_new(device);
    if (future == NULL) {
        handle_device_error(device, listener, NULL, "Failed to allocate future"); return -1;
    }

    // This CoAP request pointer will be our reference to incoming
    // requests.
    NabtoDeviceCoapRequest* request;

    ////////////////////////////////////////////////////////////////////////////////
    // example 1: blocking wait future approach

    // Query the listener for a new coap request. This call cannot
    // fail as any failures will be reported through resolving the
    // future.
    nabto_device_listener_new_coap_request(listener, future, &request);

    // We wait for the future to resolve. Since we are now in our own
    // thread, blocking is ok.
    ec = nabto_device_future_wait(future);
    if (ec != NABTO_DEVICE_EC_OK) {
        handle_device_error(device, listener, future, "Failed to get new CoAP request"); return -1;
    }

    // Now that wait has returned, the future is resolved. This means
    // request now points to the received request. We will handle a
    // few requests, so the request is handled in a seperate function.
    handle_coap_request(request);

    ////////////////////////////////////////////////////////////////////////////////
    // example 2: poll future approach

    // Now the future is resolved and ready to be reused, and we are
    // done using the request reference. This means we can now query
    // the listener for a new CoAP request. If another request has
    // arrived while we were processing the previous request, the
    // listener will resolve the future in the next cycle of the Nabto
    // core thread. Otherwise, the future resolves when the next
    // request arrives.
    nabto_device_listener_new_coap_request(listener, future, &request);

    // By polling the future we can continue to do other stuff, and
    // not worry about the concurrency issues of callback functions.
    while (nabto_device_future_ready(future) == NABTO_DEVICE_EC_FUTURE_NOT_RESOLVED) {
        do_important_work();
    }

    // The future is now resolved. If OK, we can respond to the new request.
    if (ec != NABTO_DEVICE_EC_OK) {
        handle_device_error(device, listener, future, "Failed to get new CoAP request"); return -1;
    }
    handle_coap_request(request);

    ////////////////////////////////////////////////////////////////////////////////
    // example 3: call back future approach

    // Again the future is resolved and the request pointer is freed,
    // so we can reuse.
    nabto_device_listener_new_coap_request(listener, future, &request);

    // We set a callback on the future to be called when the future
    // resolves. The callback will be invoked on the Nabto core
    // thread, so to be able to handle the request in our callback, we
    // pass the request reference as context for our callback.
    nabto_device_future_set_callback(future, &request_callback, request);

    // On second thought we don't wanna do this anymore. Let's stop
    // everything and exit. First we stop the listener. Stopping can
    // only return OK, so we ignore return value.
    nabto_device_listener_stop(listener);

    // Stopping the device directly here would also work as that would
    // block untill all futures are resolved. However, we want to
    // showcase listeners, so we wait for the future callback to tell
    // us it is okay to free the listener.
    while (!readyToStop) {
        do_important_work();
    }
    nabto_device_listener_free(listener);

    // We close the device before stopping to nicely close outstanding
    // connections. It is okay to reuse futures for new purposes and
    // since we know our future to be resolved, we reuse it to close.
    nabto_device_close(device, future);

    // If the core takes too long to close we get impatient and stop
    // it.
    ec = nabto_device_future_timed_wait(future, 200);
    if (ec == NABTO_DEVICE_EC_FUTURE_NOT_RESOLVED) {
        // we got a timeout, and the future is not resolved.
    }

    // since the future may not be resolved here, stop the device
    // before freeing the future. Stop blocks until it is okay to free
    // everything.
    nabto_device_stop(device);

    nabto_device_future_free(future);
    nabto_device_free(device);
}

void handle_coap_request(NabtoDeviceCoapRequest* request)
{
    // We do not expect a payload in this request, so we simply build
    // a response for the client. First we set the status code and
    // content format. These can only return NABTO_DEVICE_EC_OK, so we
    // ignore the return value.
    nabto_device_coap_response_set_code(request, 205);
    nabto_device_coap_response_set_content_format(request, NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8);

    // Setting the payload can fail if CoAP cannot allocate memory.
    NabtoDeviceError ec = nabto_device_coap_response_set_payload(request, helloWorld, strlen(helloWorld));
    if (ec != NABTO_DEVICE_EC_OK) {
        // On failures, we make an appropriate response for the
        // client. Since set_payload could not allocate memory, we do
        // not provide a message, as this function would likely also
        // not be able to allocate memory for the message. If this
        // call fails, we will give up trying respond nicely, so the
        // return value can be ignored.
        nabto_device_coap_error_response(request, 500, NULL);
    } else {
        // send response to the client.
        nabto_device_coap_response_ready(request);
    }
    printf("Responded to CoAP request\n");

    // The response is most likely not sent yet, however, freeing the
    // request lets the core know we are ready for the request to be
    // freed. The core will not actually free the request before it
    // too is ready for the request to be freed.
    nabto_device_coap_request_free(request);
    // Now that we have released our ownership of the request, we are
    // free to reuse the pointer for the next request.
}

void request_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data)
{
    // data is the request pointer we provided as context, let's cast
    // it.
    NabtoDeviceCoapRequest* req = (NabtoDeviceCoapRequest*)data;
    if (ec == NABTO_DEVICE_EC_STOPPED) {
        // We expected this as we stopped the listener
    } else if (ec != NABTO_DEVICE_EC_OK) {
        // An unexpected error occurred
    } else {
        // We unexpectedly received a CoAP request before we stopped
        // the listener. We must handle it. When freeing the request
        // directly, the core will send a generic error response to
        // the client.
        printf("Got unexpected CoAP request. Freeing makes auto-reply\n");
        nabto_device_coap_request_free(req);

        // we did not get our expected error code. We can query the
        // listener again, which will give us a new callback with the
        // error code set. Our context only contains the request, so
        // we do not have access to the listener here and will,
        // therefore, not query the listener

        // nabto_device_listener_new_coap_request(listener, fut, &req);
        // nabto_device_future_set_callback(future, &request_callback, data);

        // We cannot get a sencond unexpected request as this only
        // happened because the future was scheduled to be resolved
        // during the `nabto_device_listener_new_coap_request()`
        // call. When the listener is stopped, any additional requests
        // in the listeners queue will have been cancelled.
    }
    // Now that we are sure the listener does not have any outstanding
    // futures, we can signal our main thread that it is now okay to
    // free the listener.

    // We are now in a new thread! so we must be carefull not to
    // create concurrency issues. We simply switch a boolean, so
    // hopefully it is okay to access the shared memory without safe
    // guards.
    readyToStop = true;
}

bool start_device(NabtoDevice* device)
{
    NabtoDeviceError ec;
    char* fp;

    // If a private key was set in the top, use that. Otherwise we
    // create one. The fingerprint of the device must be registered in
    // the Nabto basestation before it is able to attach.
    if (!privateKey) {
        ec = nabto_device_create_private_key(device, &privateKey);
        if (ec != NABTO_DEVICE_EC_OK) {
            return false;
        }
        ec = nabto_device_set_private_key(device, privateKey);
        nabto_device_string_free(privateKey);
    } else {
        ec = nabto_device_set_private_key(device, privateKey);
    }

    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }
    ec = nabto_device_set_product_id(device, productId);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }
    ec = nabto_device_set_device_id(device, deviceId);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }
    ec = nabto_device_set_server_url(device, serverUrl);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }
    ec = nabto_device_enable_mdns(device);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }
    ec = nabto_device_set_log_std_out_callback(device);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }
    ec = nabto_device_start(device);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }
    ec = nabto_device_get_device_fingerprint_hex(device, &fp);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }

    printf("Device: %s.%s Started with fingerprint: [%s]\n", productId, deviceId, fp);
    nabto_device_string_free(fp);
    return true;
}

void do_important_work()
{
  //sleep:
  #ifdef _WIN32
  Sleep(100);
  #else
  usleep(100*1000);  /* sleep for 100 milliSeconds */
  #endif
}

void handle_device_error(NabtoDevice* d, NabtoDeviceListener* l, NabtoDeviceFuture* f, char* msg)
{
    if (d) {
        // if we already have a future we reuse for device close.
        if (!f) {
            f = nabto_device_future_new(d);
        }
        nabto_device_close(d, f);
        nabto_device_future_wait(f);
        nabto_device_stop(d);
        nabto_device_free(d);
    }
    // we are now after device_stop(). Even if we had some unresolved
    // future or unstopped listener, they cannot be invoked, and it is
    // okay to free.
    if (f) {
        nabto_device_future_free(f);
    }
    if (l) {
        nabto_device_listener_free(l);
    }
    printf("%s", msg);
}
