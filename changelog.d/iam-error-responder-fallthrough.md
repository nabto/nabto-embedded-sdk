### Security
 * Fixed the IAM CoAP handlers sending several responses to a request with an
   invalid content format or a CBOR payload which could not be parsed. Each
   extra response leaked the payload of the previous one, so a client could
   exhaust the memory of the device. Exactly one response is now sent.
