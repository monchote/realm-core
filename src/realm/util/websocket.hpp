
#ifndef REALM_UTIL_WEBSOCKET_HPP
#define REALM_UTIL_WEBSOCKET_HPP

#include <random>
#include <system_error>
#include <map>

#include <realm/util/string_view.hpp>
#include <realm/util/logger.hpp>
#include <realm/util/http.hpp>


namespace realm {
namespace util {
namespace websocket {

using WriteCompletionHandler = std::function<void(std::error_code, size_t num_bytes_transferred)>;
using ReadCompletionHandler = std::function<void(std::error_code, size_t num_bytes_transferred)>;

class Config {
public:
    virtual ~Config() {}

    /// The Socket uses the caller supplied logger for logging.
    virtual util::Logger& websocket_get_logger() noexcept = 0;

    /// The Socket needs random numbers to satisfy the Websocket protocol.
    /// The caller must supply a random number generator.
    virtual std::mt19937_64& websocket_get_random() noexcept = 0;

    //@{
    /// The three functions below are used by the Socket to read and write to the underlying
    /// stream. The functions will typically be implemented as wrappers to a TCP/TLS stream,
    /// but could also map to pure memory streams. These functions abstract away the details of
    /// the underlying sockets.
    /// The functions have the same semantics as util::Socket.
    ///
    /// FIXME: Require that implementations ensure no callback reentrance, i.e.,
    /// that the completion handler is never called from within the execution of
    /// async_write(), async_read(), or async_read_until(). This guarantee is
    /// provided by both network::Socket and network::ssl::Stream.
    virtual void async_write(const char* data, size_t size, WriteCompletionHandler handler) = 0;
    virtual void async_read(char* buffer, size_t size, ReadCompletionHandler handler) = 0;
    virtual void async_read_until(char* buffer, size_t size, char delim, ReadCompletionHandler handler) = 0;
    //@}

    /// websocket_handshake_completion_handler() is called when the websocket is connected, .i.e.
    /// after the handshake is done. It is not allowed to send messages on the socket before the
    /// handshake is done. No message_received callbacks will be called before the handshake is done.
    virtual void websocket_handshake_completion_handler(const HTTPHeaders&) = 0;

    //@{
    /// websocket_read_error_handler() and websocket_write_error_handler() are called when an
    /// error occurs on the underlying stream given by the async_read and async_write functions above.
    /// The error_code is passed through.
    ///
    /// websocket_handshake_error_handler() will be called when there is an error in the handshake
    /// such as "404 Not found".
    ///
    /// websocket_protocol_error_handler() is called when there is an protocol error in the incoming
    /// websocket messages.
    ///
    /// After calling any of these error callbacks, the Socket will move into the stopped state, and
    /// no more messages should be sent, or will be received.
    /// It is safe to destroy the WebSocket object in these handlers.
    virtual void websocket_read_error_handler(std::error_code) = 0;
    virtual void websocket_write_error_handler(std::error_code) = 0;
    virtual void websocket_handshake_error_handler(std::error_code, const HTTPHeaders*,
                                                   const util::StringView* body) = 0;
    virtual void websocket_protocol_error_handler(std::error_code) = 0;
    //@}

    //@{
    /// The five callback functions below are called whenever a full message has arrived.
    /// The Socket defragments fragmented messages internally and delivers a full message.
    /// \param data size The message is delivered in this buffer
    /// The buffer is only valid until the function returns.
    /// \return value designates whether the WebSocket object should continue
    /// processing messages. The normal return value is true. False must be returned if the
    /// websocket object is destroyed during execution of the function.
    virtual bool websocket_text_message_received(const char* data, size_t size);
    virtual bool websocket_binary_message_received(const char* data, size_t size);
    virtual bool websocket_close_message_received(std::error_code error_code, StringData message);
    virtual bool websocket_ping_message_received(const char* data, size_t size);
    virtual bool websocket_pong_message_received(const char* data, size_t size);
    //@}
};


enum class Opcode { continuation = 0, text = 1, binary = 2, close = 8, ping = 9, pong = 10 };


class Socket {
public:
    Socket(Config&);
    Socket(Socket&&) noexcept;
    ~Socket() noexcept;

    /// initiate_client_handshake() starts the Socket in client mode. The Socket
    /// will send the HTTP request that initiates the WebSocket protocol and
    /// wait for the HTTP response from the server. The HTTP request will
    /// contain the \param request_uri in the HTTP request line. The \param host
    /// will be sent as the value in a HTTP Host header line.
    /// \param sec_websocket_protocol will be set as header value for
    /// Sec-WebSocket-Protocol. Extra HTTP headers can be provided in \a headers.
    ///
    /// When the server responds with a valid HTTP response, the callback
    /// function websocket_handshake_completion_handler() is called. Messages
    /// can only be sent and received after the handshake has completed.
    void initiate_client_handshake(const std::string& request_uri, const std::string& host,
                                   const std::string& sec_websocket_protocol, HTTPHeaders headers = HTTPHeaders{});

    /// initiate_server_handshake() starts the Socket in server mode. It will
    /// wait for a HTTP request from a client and respond with a HTTP response.
    /// After sending a HTTP response, websocket_handshake_completion_handler()
    /// is called. Messages can only be sent and received after the handshake
    /// has completed.
    void initiate_server_handshake();

    /// initiate_server_websocket_after_handshake() starts the Socket in a state
    /// where it will read and write WebSocket messages but it will expect the
    /// handshake to have been completed by the caller. The use of this
    /// function is to perform HTTP routing externally and then start the
    /// WebSocket in case the HTTP request is an Upgrade to WebSocket.
    /// Typically, the caller will have used make_http_response() to send the
    /// HTTP response itself.
    void initiate_server_websocket_after_handshake();

    /// The async_write_* functions send frames. Only one frame should be sent at a time,
    /// meaning that the user must wait for the handler to be called before sending the next frame.
    /// The handler is type std::function<void()> and is called when the frame has been successfully
    /// sent. In case of errors, the Config::websocket_write_error_handler() is called.

    /// async_write_frame() sends a single frame with this content:
    /// \param fin The fin bit set to 0 or 1
    /// \param opcode Specifies the opcpde.
    /// \param data size The frame payload is taken from this buffer.
    /// \param handler Called when the frame has been successfully sent. Error s are reported through
    /// websocket_write_error_handler() in Config.
    /// This function is rather low level and should only be used with knowledge of the WebSocket protocol.
    /// The five utility functions below are recommended for message sending.
    ///
    /// FIXME: Guarantee no callback reentrance, i.e., that the completion
    /// handler, or the error handler in case an error occurs, is never called
    /// from within the execution of async_write_frame().
    void async_write_frame(bool fin, Opcode opcode, const char* data, size_t size, std::function<void()> handler);

    //@{
    /// Five utility functions used to send whole messages. These five
    /// functions are implemented in terms of async_write_frame(). These
    /// functions send whole unfragmented messages. These functions should be
    /// preferred over async_write_frame() for most use cases.
    ///
    /// FIXME: Guarantee no callback reentrance, i.e., that the completion
    /// handler, or the error handler in case an error occurs, is never called
    /// from within the execution of async_write_text(), and its friends. This
    /// is already assumed by the client and server implementations of the sync
    /// protocol.
    void async_write_text(const char* data, size_t size, std::function<void()> handler);
    void async_write_binary(const char* data, size_t size, std::function<void()> handler);
    void async_write_close(const char* data, size_t size, std::function<void()> handler);
    void async_write_ping(const char* data, size_t size, std::function<void()> handler);
    void async_write_pong(const char* data, size_t size, std::function<void()> handler);
    //@}

    /// stop() stops the socket. The socket will stop processing incoming data,
    /// sending data, and calling callbacks.  It is an error to attempt to send
    /// a message after stop() has been called. stop() will typically be called
    /// before the underlying TCP/TLS connection is closed. The Socket can be
    /// restarted with initiate_client_handshake() and
    /// initiate_server_handshake().
    void stop() noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};


/// read_sec_websocket_protocol() returns the value of the
/// header Sec-WebSocket-Protocol in the http request \a request.
/// None is returned if the header Sec-WebSocket-Protocol is absent
/// in the request.
util::Optional<std::string> read_sec_websocket_protocol(const HTTPRequest& request);

/// make_http_response() takes \a request as a WebSocket handshake request,
/// validates it, and makes a HTTP response. If the request is invalid, the
/// return value is None, and ec is set to Error::bad_request_header_*.
util::Optional<HTTPResponse> make_http_response(const HTTPRequest& request, const std::string& sec_websocket_protocol,
                                                std::error_code& ec);

enum class Error {
    bad_request_malformed_http,
    bad_request_header_upgrade,
    bad_request_header_connection,
    bad_request_header_websocket_version,
    bad_request_header_websocket_key,
    bad_response_invalid_http,
    bad_response_2xx_successful,
    bad_response_200_ok,
    bad_response_3xx_redirection,
    bad_response_301_moved_permanently,
    bad_response_4xx_client_errors,
    bad_response_401_unauthorized,
    bad_response_403_forbidden,
    bad_response_404_not_found,
    bad_response_410_gone,
    bad_response_5xx_server_error,
    bad_response_500_internal_server_error,
    bad_response_502_bad_gateway,
    bad_response_503_service_unavailable,
    bad_response_504_gateway_timeout,
    bad_response_unexpected_status_code,
    bad_response_header_protocol_violation,
    bad_message
};

const std::error_category& websocket_close_status_category() noexcept;

const std::error_category& error_category() noexcept;

std::error_code make_error_code(Error) noexcept;

} // namespace websocket
} // namespace util
} // namespace realm

namespace std {

template <>
struct is_error_code_enum<realm::util::websocket::Error> {
    static const bool value = true;
};

} // namespace std

#endif // REALM_UTIL_WEBSOCKET_HPP
