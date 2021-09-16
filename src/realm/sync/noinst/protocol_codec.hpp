#ifndef REALM_NOINST_PROTOCOL_CODEC_HPP
#define REALM_NOINST_PROTOCOL_CODEC_HPP

#include <cstdint>
#include <algorithm>
#include <memory>
#include <vector>
#include <string>

#include <realm/util/optional.hpp>
#include <realm/util/string_view.hpp>
#include <realm/util/memory_stream.hpp>
#include <realm/util/buffer_stream.hpp>
#include <realm/util/logger.hpp>
#include <realm/binary_data.hpp>
#include <realm/chunked_binary.hpp>
#include <realm/sync/impl/clamped_hex_dump.hpp>
#include <realm/sync/noinst/compression.hpp>
#include <realm/sync/noinst/integer_codec.hpp>
#include <realm/sync/noinst/header_line_parser.hpp>
#include <realm/sync/protocol.hpp>
#include <realm/sync/transform.hpp>
#include <realm/sync/changeset_parser.hpp>
#include <realm/sync/history.hpp>


namespace realm {
namespace _impl {

class ClientProtocol {
public:
    // clang-format off
    using file_ident_type    = sync::file_ident_type;
    using version_type       = sync::version_type;
    using salt_type          = sync::salt_type;
    using timestamp_type     = sync::timestamp_type;
    using session_ident_type = sync::session_ident_type;
    using request_ident_type = sync::request_ident_type;
    using milliseconds_type  = sync::milliseconds_type;
    using SaltedFileIdent    = sync::SaltedFileIdent;
    using SaltedVersion      = sync::SaltedVersion;
    using DownloadCursor     = sync::DownloadCursor;
    using UploadCursor       = sync::UploadCursor;
    using SyncProgress       = sync::SyncProgress;
    // clang-format on

    using OutputBuffer = util::ResettableExpandableBufferOutputStream;
    using RemoteChangeset = sync::Transformer::RemoteChangeset;
    using ReceivedChangesets = std::vector<RemoteChangeset>;

    // FIXME: No need to explicitly assign numbers to these
    enum class Error {
        // clang-format off
        unknown_message             = 101, // Unknown type of input message
        bad_syntax                  = 102, // Bad syntax in input message head
        limits_exceeded             = 103, // Limits exceeded in input message
        bad_changeset_header_syntax = 108, // Bad syntax in changeset header (DOWNLOAD)
        bad_changeset_size          = 109, // Bad changeset size in changeset header (DOWNLOAD)
        bad_server_version          = 111, // Bad server version in changeset header (DOWNLOAD)
        bad_error_code              = 114, ///< Bad error code (ERROR)
        bad_decompression           = 115, // Error in decompression (DOWNLOAD)
        // clang-format on
    };


    /// Messages sent by the client.

    void make_bind_message(int protocol_version, OutputBuffer&, session_ident_type session_ident,
                           const std::string& server_path, const std::string& signed_user_token,
                           bool need_client_file_ident, bool is_subserver);

    void make_refresh_message(OutputBuffer&, session_ident_type session_ident, const std::string& signed_user_token);

    void make_ident_message(OutputBuffer&, session_ident_type session_ident, SaltedFileIdent client_file_ident,
                            const SyncProgress& progress);

    class UploadMessageBuilder {
    public:
        util::Logger& logger;

        UploadMessageBuilder(util::Logger& logger, OutputBuffer& body_buffer, std::vector<char>& compression_buffer,
                             _impl::compression::CompressMemoryArena& compress_memory_arena);

        void add_changeset(version_type client_version, version_type server_version, timestamp_type origin_timestamp,
                           file_ident_type origin_file_ident, ChunkedBinaryData changeset);

        void make_upload_message(int protocol_version, OutputBuffer&, session_ident_type session_ident,
                                 version_type progress_client_version, version_type progress_server_version,
                                 version_type locked_server_version);

    private:
        std::size_t m_num_changesets = 0;
        OutputBuffer& m_body_buffer;
        std::vector<char>& m_compression_buffer;
        _impl::compression::CompressMemoryArena& m_compress_memory_arena;
    };

    UploadMessageBuilder make_upload_message_builder(util::Logger& logger);

    void make_unbind_message(OutputBuffer&, session_ident_type session_ident);

    void make_mark_message(OutputBuffer&, session_ident_type session_ident, request_ident_type request_ident);

    void make_alloc_message(OutputBuffer&, session_ident_type session_ident);

    void make_ping(OutputBuffer&, milliseconds_type timestamp, milliseconds_type rtt);

    std::string compressed_hex_dump(BinaryData blob);

    // Messages received by the client.

    // parse_pong_received takes a (WebSocket) pong and parses it.
    // The result of the parsing is handled by an object of type Connection.
    // Typically, Connection would be the Connection class from client.cpp
    template <typename Connection>
    void parse_pong_received(Connection& connection, util::StringView msg_data)
    {
        util::Logger& logger = connection.logger;

        milliseconds_type timestamp;
        auto sw_msg_data = parse_header_line(msg_data, '\n', timestamp);
        if (!sw_msg_data.is_ok() || !sw_msg_data.get_value().empty()) {
            logger.error("Bad syntax in input message '%1'", msg_data);
            connection.handle_protocol_error(Error::bad_syntax); // Throws
            return;
        }

        connection.receive_pong(timestamp);
    }

    // parse_message_received takes a (WebSocket) message and parses it.
    // The result of the parsing is handled by an object of type Connection.
    // Typically, Connection would be the Connection class from client.cpp
    template <class Connection>
    void parse_message_received(Connection& connection, util::StringView msg_data)
    {
        util::Logger& logger = connection.logger;
        auto report_error = [&](Error err, const auto fmt, auto&&... args) {
            logger.error(fmt, args...);
            connection.handle_protocol_error(err);
        };

        auto parse_and_check_msg_data = [&](const auto what, char end_delim, auto&&... args) {
            auto sw_msg_data = parse_header_line_nothrow(msg_data, end_delim, args...);
            if (!sw_msg_data.is_ok()) {
                report_error(Error::bad_syntax, "Bad syntax in %1: %2", what, sw_msg_data.get_status());
                return false;
            }
            msg_data = sw_msg_data.get_value();
            return true;
        };

        util::StringView message_type;
        if (!parse_and_check_msg_data("wire protocol message type", ' ', message_type)) {
            return;
        }

        if (message_type == "download") {
            SyncProgress progress;
            std::int_fast64_t downloadable_bytes;
            int is_body_compressed;
            std::size_t uncompressed_body_size, compressed_body_size;
            session_ident_type session_ident;

            auto msg_with_header = msg_data;
            if (!parse_and_check_msg_data("DOWNLOAD message", '\n', session_ident, progress.download.server_version,
                                          progress.download.last_integrated_client_version,
                                          progress.latest_server_version.version, progress.latest_server_version.salt,
                                          progress.upload.client_version,
                                          progress.upload.last_integrated_server_version, downloadable_bytes,
                                          is_body_compressed, uncompressed_body_size, compressed_body_size)) {
                return;
            }

            if (uncompressed_body_size > s_max_body_size) {
                auto header = msg_with_header.substr(std::distance(msg_with_header.begin(), msg_data.begin()));
                return report_error(Error::limits_exceeded, "Limits exceeded in input message '%1'", header);
            }

            auto body_data = msg_data;
            std::unique_ptr<char[]> uncompressed_body_buffer;
            // if is_body_compressed == true, we must decompress the received body.
            if (is_body_compressed) {
                uncompressed_body_buffer.reset(new char[uncompressed_body_size]);
                std::error_code ec = _impl::compression::decompress(
                    msg_data.data(), compressed_body_size, uncompressed_body_buffer.get(), uncompressed_body_size);

                if (ec) {
                    return report_error(Error::bad_decompression, "compression::inflate: %1", ec.message());
                }

                body_data = util::StringView(uncompressed_body_buffer.get(), uncompressed_body_size);
                msg_data = msg_data.substr(compressed_body_size);
            }
            else {
                msg_data = msg_data.substr(uncompressed_body_size);
            }

            logger.trace("Download message compression: is_body_compressed = %1, "
                         "compressed_body_size=%2, uncompressed_body_size=%3",
                         is_body_compressed, compressed_body_size, uncompressed_body_size);

            ReceivedChangesets received_changesets;

            // Loop through the body and find the changesets.
            while (!body_data.empty()) {
                realm::sync::Transformer::RemoteChangeset cur_changeset;
                std::size_t changeset_size;
                auto body_data_sw = parse_header_line(body_data, ' ', cur_changeset.remote_version,
                                                      cur_changeset.last_integrated_local_version,
                                                      cur_changeset.origin_timestamp, cur_changeset.origin_file_ident,
                                                      cur_changeset.original_changeset_size, changeset_size);
                if (!body_data_sw.is_ok()) {
                    return report_error(Error::bad_changeset_header_syntax, "Bad changeset header syntax: %1",
                                        body_data_sw.get_status());
                }
                body_data = body_data_sw.get_value();

                if (changeset_size > body_data.size()) {
                    return report_error(Error::bad_changeset_size, "Bad changeset size %1 > %2", changeset_size,
                                        body_data.size());
                }

                BinaryData changeset_data(body_data.data(), changeset_size);
                body_data = body_data.substr(changeset_size);

                if (logger.would_log(util::Logger::Level::trace)) {
                    logger.trace("Received: DOWNLOAD CHANGESET(server_version=%1, "
                                 "client_version=%2, origin_timestamp=%3, origin_file_ident=%4, "
                                 "original_changeset_size=%5, changeset_size=%6)",
                                 cur_changeset.remote_version, cur_changeset.last_integrated_local_version,
                                 cur_changeset.origin_timestamp, cur_changeset.origin_file_ident,
                                 cur_changeset.original_changeset_size, changeset_size); // Throws;
                    if (changeset_data.size() < 1056) {
                        logger.trace("Changeset: %1",
                                     clamped_hex_dump(changeset_data)); // Throws
                    }
                    else {
                        logger.trace("Changeset(comp): %1 %2", changeset_data.size(),
                                     compressed_hex_dump(changeset_data)); // Throws
                    }
#if REALM_DEBUG
                    ChunkedBinaryInputStream in{changeset_data};
                    sync::Changeset log;
                    sync::parse_changeset(in, log);
                    std::stringstream ss;
                    log.print(ss);
                    logger.trace("Changeset (parsed):\n%1", ss.str());
#endif
                }

                cur_changeset.data = changeset_data;
                received_changesets.push_back(cur_changeset); // Throws
            }

            connection.receive_download_message(session_ident, progress, downloadable_bytes,
                                                received_changesets); // Throws
        }
        else if (message_type == "pong") {
            milliseconds_type timestamp;
            if (!parse_and_check_msg_data("PONG message", '\n', timestamp)) {
                return;
            }

            connection.receive_pong(timestamp);
        }
        else if (message_type == "unbound") {
            session_ident_type session_ident;
            if (!parse_and_check_msg_data("UNBOUND message", '\n', session_ident)) {
                return;
            }

            connection.receive_unbound_message(session_ident); // Throws
        }
        else if (message_type == "error") {
            int error_code;
            std::size_t message_size;
            bool try_again;
            session_ident_type session_ident;
            if (!parse_and_check_msg_data("ERROR message", '\n', error_code, message_size, try_again,
                                          session_ident)) {
                return;
            }

            bool unknown_error = !sync::get_protocol_error_message(error_code);
            if (unknown_error) {
                return report_error(Error::bad_error_code, "Bad error code");
            }

            StringData message{msg_data.data(), message_size};
            connection.receive_error_message(error_code, message, try_again, session_ident); // Throws
            msg_data = msg_data.substr(message_size);
        }
        else if (message_type == "mark") {
            session_ident_type session_ident;
            request_ident_type request_ident;
            if (!parse_and_check_msg_data("MARK message", '\n', session_ident, request_ident)) {
                return;
            }

            connection.receive_mark_message(session_ident, request_ident); // Throws
        }
        else if (message_type == "alloc") {
            session_ident_type session_ident;
            file_ident_type file_ident;
            if (!parse_and_check_msg_data("ALLOC message", '\n', session_ident, file_ident)) {
                return;
            }

            connection.receive_alloc_message(session_ident, file_ident); // Throws
            return;
        }
        else if (message_type == "ident") {
            session_ident_type session_ident;
            SaltedFileIdent client_file_ident;
            if (!parse_and_check_msg_data("IDENT message", '\n', session_ident, client_file_ident.ident,
                                          client_file_ident.salt)) {
                return;
            }
            connection.receive_ident_message(session_ident, client_file_ident); // Throws
        }
        else {
            return report_error(Error::unknown_message, "Unknown input message type '%1'", msg_data);
        }
        if (!msg_data.empty()) {
            return report_error(Error::bad_syntax, "wire protocol message had leftover data after being parsed");
        }
    }

private:
    static constexpr std::size_t s_max_body_size = std::numeric_limits<std::size_t>::max();

    // Permanent buffer to use for building messages.
    OutputBuffer m_output_buffer;

    // Permanent buffers to use for internal purposes such as compression.
    std::vector<char> m_buffer;

    _impl::compression::CompressMemoryArena m_compress_memory_arena;
};


class ServerProtocol {
public:
    // clang-format off
    using file_ident_type    = sync::file_ident_type;
    using version_type       = sync::version_type;
    using salt_type          = sync::salt_type;
    using timestamp_type     = sync::timestamp_type;
    using session_ident_type = sync::session_ident_type;
    using request_ident_type = sync::request_ident_type;
    using SaltedFileIdent    = sync::SaltedFileIdent;
    using SaltedVersion      = sync::SaltedVersion;
    using milliseconds_type  = sync::milliseconds_type;
    using UploadCursor       = sync::UploadCursor;
    // clang-format on

    using OutputBuffer = util::ResettableExpandableBufferOutputStream;

    // FIXME: No need to explicitly assign numbers to these
    enum class Error {
        // clang-format off
        unknown_message             = 101, // Unknown type of input message
        bad_syntax                  = 102, // Bad syntax in input message head
        limits_exceeded             = 103, // Limits exceeded in input message
        bad_decompression           = 104, // Error in decompression (UPLOAD)
        bad_changeset_header_syntax = 105, // Bad syntax in changeset header (UPLOAD)
        bad_changeset_size          = 106, // Changeset size doesn't fit in message (UPLOAD)
        // clang-format on
    };

    // Messages sent by the server to the client

    void make_ident_message(int protocol_version, OutputBuffer&, session_ident_type session_ident,
                            file_ident_type client_file_ident, salt_type client_file_ident_salt);

    void make_alloc_message(OutputBuffer&, session_ident_type session_ident, file_ident_type file_ident);

    void make_unbound_message(OutputBuffer&, session_ident_type session_ident);


    struct ChangesetInfo {
        version_type server_version;
        version_type client_version;
        sync::HistoryEntry entry;
        std::size_t original_size;
    };

    void make_download_message(int protocol_version, OutputBuffer&, session_ident_type session_ident,
                               version_type download_server_version, version_type download_client_version,
                               version_type latest_server_version, salt_type latest_server_version_salt,
                               version_type upload_client_version, version_type upload_server_version,
                               std::uint_fast64_t downloadable_bytes, std::size_t num_changesets, const char* body,
                               std::size_t uncompressed_body_size, std::size_t compressed_body_size,
                               bool body_is_compressed, util::Logger&);

    void make_mark_message(OutputBuffer&, session_ident_type session_ident, request_ident_type request_ident);

    void make_error_message(int protocol_version, OutputBuffer&, sync::ProtocolError error_code, const char* message,
                            std::size_t message_size, bool try_again, session_ident_type session_ident);

    void make_pong(OutputBuffer&, milliseconds_type timestamp);

    // Messages received by the server.

    // parse_ping_received takes a (WebSocket) ping and parses it.
    // The result of the parsing is handled by an object of type Connection.
    // Typically, Connection would be the Connection class from server.cpp
    template <typename Connection>
    void parse_ping_received(Connection& connection, util::StringView msg_data)
    {
        util::Logger& logger = connection.logger;

        milliseconds_type timestamp, rtt;
        auto sw_msg_data = parse_header_line(msg_data, '\n', timestamp, rtt);
        if (!sw_msg_data.is_ok()) {
            logger.error("Bad syntax in PING message %1", sw_msg_data.get_status());
            connection.handle_protocol_error(Error::bad_syntax);
            return;
        }

        connection.receive_ping(timestamp, rtt);
    }

    // UploadChangeset is used to store received changesets in
    // the UPLOAD message.
    struct UploadChangeset {
        UploadCursor upload_cursor;
        timestamp_type origin_timestamp;
        file_ident_type origin_file_ident; // Zero when originating from connected client file
        BinaryData changeset;
    };

    // parse_message_received takes a (WebSocket) message and parses it.
    // The result of the parsing is handled by an object of type Connection.
    // Typically, Connection would be the Connection class from server.cpp
    template <class Connection>
    void parse_message_received(Connection& connection, util::StringView msg_data)
    {
        util::Logger& logger = connection.logger;

        auto report_error = [&](Error err, const auto fmt, auto&&... args) {
            logger.error(fmt, args...);
            connection.handle_protocol_error(err);
        };

        auto parse_and_check_msg_data = [&](const auto what, char end_delim, auto&&... args) {
            auto sw_msg_data = parse_header_line_nothrow(msg_data, end_delim, args...);
            if (!sw_msg_data.is_ok()) {
                report_error(Error::bad_syntax, "Bad syntax in %1: %2", what, sw_msg_data.get_status());
                return false;
            }
            msg_data = sw_msg_data.get_value();
            return true;
        };

        util::StringView message_type;
        if (!parse_and_check_msg_data("wire protocol message type", ' ', message_type)) {
            return;
        }

        if (message_type == "upload") {
            session_ident_type session_ident;
            bool is_body_compressed;
            std::size_t uncompressed_body_size, compressed_body_size;
            version_type progress_client_version, progress_server_version;
            version_type locked_server_version;

            auto msg_with_header = msg_data;
            if (!parse_and_check_msg_data("UPLOAD message", '\n', session_ident, is_body_compressed,
                                          uncompressed_body_size, compressed_body_size, progress_client_version,
                                          progress_server_version, locked_server_version)) {
                return;
            }
            std::size_t body_size = (is_body_compressed ? compressed_body_size : uncompressed_body_size);
            if (body_size > s_max_body_size) {
                auto header = msg_with_header.substr(std::distance(msg_with_header.begin(), msg_data.begin()));
                return report_error(Error::limits_exceeded,
                                    "Body size of upload message is too large. Raw header: %1", header);
            }

            util::StringView uncompressed_body = msg_data;
            std::unique_ptr<char[]> uncompressed_body_buffer;
            // if is_body_compressed == true, we must decompress the received body.
            if (is_body_compressed) {
                uncompressed_body_buffer.reset(new char[uncompressed_body_size]);
                std::error_code ec = _impl::compression::decompress(
                    msg_data.data(), compressed_body_size, uncompressed_body_buffer.get(), uncompressed_body_size);

                if (ec) {
                    return report_error(Error::bad_decompression, "compression::inflate: %1", ec.message());
                }

                uncompressed_body = util::StringView(uncompressed_body_buffer.get(), uncompressed_body_size);
            }

            logger.debug("Upload message compression: is_body_compressed = %1, "
                         "compressed_body_size=%2, uncompressed_body_size=%3, "
                         "progress_client_version=%4, progress_server_version=%5, "
                         "locked_server_version=%6",
                         is_body_compressed, compressed_body_size, uncompressed_body_size, progress_client_version,
                         progress_server_version, locked_server_version); // Throws

            util::MemoryInputStream in;
            in.unsetf(std::ios_base::skipws);
            in.set_buffer(uncompressed_body.data(), uncompressed_body.data() + uncompressed_body_size);

            std::vector<UploadChangeset> upload_changesets;

            // Loop through the body and find the changesets.
            while (!uncompressed_body.empty()) {
                version_type client_version;
                version_type server_version;
                timestamp_type origin_timestamp;
                file_ident_type origin_file_ident;
                std::size_t changeset_size;

                auto sw_uncompressed_body = parse_header_line(uncompressed_body, ' ', client_version, server_version,
                                                              origin_timestamp, origin_file_ident, changeset_size);

                if (!sw_uncompressed_body.is_ok()) {
                    return report_error(Error::bad_changeset_header_syntax, "Bad changeset header syntax: %1",
                                        sw_uncompressed_body.get_status());
                }
                uncompressed_body = sw_uncompressed_body.get_value();

                if (changeset_size > uncompressed_body.size()) {
                    return report_error(Error::bad_changeset_size, "Bad changeset size");
                }

                BinaryData changeset_data(uncompressed_body.data(), changeset_size);
                uncompressed_body = uncompressed_body.substr(changeset_size);

                if (logger.would_log(util::Logger::Level::trace)) {
                    logger.trace("Received: UPLOAD CHANGESET(client_version=%1, server_version=%2, "
                                 "origin_timestamp=%3, origin_file_ident=%4, changeset_size=%5)",
                                 client_version, server_version, origin_timestamp, origin_file_ident,
                                 changeset_size); // Throws
                    logger.trace("Changeset: %1",
                                 clamped_hex_dump(changeset_data)); // Throws
                }

                UploadChangeset upload_changeset{UploadCursor{client_version, server_version}, origin_timestamp,
                                                 origin_file_ident, changeset_data};

                upload_changesets.push_back(upload_changeset); // Throws
            }

            connection.receive_upload_message(session_ident, progress_client_version, progress_server_version,
                                              locked_server_version,
                                              upload_changesets); // Throws
        }
        else if (message_type == "mark") {
            session_ident_type session_ident;
            request_ident_type request_ident;
            if (!parse_and_check_msg_data("MARK message", '\n', session_ident, request_ident)) {
                return;
            }

            connection.receive_mark_message(session_ident, request_ident); // Throws
        }
        else if (message_type == "ping") {
            milliseconds_type timestamp, rtt;
            if (!parse_and_check_msg_data("PING message", '\n', timestamp, rtt)) {
                return;
            }

            connection.receive_ping(timestamp, rtt);
        }
        else if (message_type == "bind") {
            session_ident_type session_ident;
            std::size_t path_size;
            std::size_t signed_user_token_size;
            bool need_client_file_ident;
            bool is_subserver;
            if (!parse_and_check_msg_data("BIND message", '\n', session_ident, path_size, signed_user_token_size,
                                          need_client_file_ident, is_subserver)) {
                return;
            }

            if (path_size == 0) {
                return report_error(Error::bad_syntax, "Path size in BIND message is zero");
            }
            if (path_size > s_max_path_size) {
                return report_error(Error::limits_exceeded, "Path size in BIND message is too large");
            }
            if (signed_user_token_size > s_max_signed_user_token_size) {
                return report_error(Error::limits_exceeded, "Signed user token size in BIND message is too large");
            }

            std::string path = static_cast<std::string>(msg_data.substr(0, path_size));
            std::string signed_user_token =
                static_cast<std::string>(msg_data.substr(path_size, signed_user_token_size));
            msg_data = msg_data.substr(path_size + signed_user_token_size);

            connection.receive_bind_message(session_ident, std::move(path), std::move(signed_user_token),
                                            need_client_file_ident, is_subserver); // Throws
        }
        else if (message_type == "refresh") {
            session_ident_type session_ident;
            std::size_t signed_user_token_size;
            if (!parse_and_check_msg_data("REFRESH message", '\n', session_ident, signed_user_token_size)) {
                return;
            }
            if (signed_user_token_size > s_max_signed_user_token_size)
                return report_error(Error::limits_exceeded, "Signed user token in REFRESH message is too large");

            std::string signed_user_token = static_cast<std::string>(msg_data.substr(0, signed_user_token_size));
            msg_data = msg_data.substr(signed_user_token_size);

            connection.receive_refresh_message(session_ident, std::move(signed_user_token)); // Throws
        }
        else if (message_type == "ident") {
            session_ident_type session_ident;
            file_ident_type client_file_ident;
            salt_type client_file_ident_salt;
            version_type scan_server_version, scan_client_version, latest_server_version;
            salt_type latest_server_version_salt;

            if (!parse_and_check_msg_data("IDENT message", '\n', session_ident, client_file_ident,
                                          client_file_ident_salt, scan_server_version, scan_client_version,
                                          latest_server_version, latest_server_version_salt)) {
                return;
            }

            connection.receive_ident_message(session_ident, client_file_ident, client_file_ident_salt,
                                             scan_server_version, scan_client_version, latest_server_version,
                                             latest_server_version_salt); // Throws
        }
        else if (message_type == "alloc") {
            session_ident_type session_ident;
            if (!parse_and_check_msg_data("ALLOC message", '\n', session_ident)) {
                return;
            }

            connection.receive_alloc_message(session_ident); // Throws
        }
        else if (message_type == "unbind") {
            session_ident_type session_ident;
            if (!parse_and_check_msg_data("UNBIND message", '\n', session_ident)) {
                return;
            }

            connection.receive_unbind_message(session_ident); // Throws
        }
        else {
            return report_error(Error::unknown_message, "unknown message type %1", message_type);
        }
    }

    void insert_single_changeset_download_message(OutputBuffer&, const ChangesetInfo&, util::Logger&);

private:
    // clang-format off
    static constexpr std::size_t s_max_head_size              =  256;
    static constexpr std::size_t s_max_signed_user_token_size = 2048;
    static constexpr std::size_t s_max_client_info_size       = 1024;
    static constexpr std::size_t s_max_path_size              = 1024;
    static constexpr std::size_t s_max_changeset_size         = std::numeric_limits<std::size_t>::max(); // FIXME: What is a reasonable value here?
    static constexpr std::size_t s_max_body_size              = std::numeric_limits<std::size_t>::max();
    // clang-format on
};

// make_authorization_header() makes the value of the Authorization header used in the
// sync Websocket handshake.
std::string make_authorization_header(const std::string& signed_user_token);

// parse_authorization_header() parses the value of the Authorization header and returns
// the signed_user_token. None is returned in case of syntax error.
util::Optional<StringData> parse_authorization_header(const std::string& authorization_header);

} // namespace _impl
} // namespace realm

#endif // REALM_NOINST_PROTOCOL_CODEC_HPP
