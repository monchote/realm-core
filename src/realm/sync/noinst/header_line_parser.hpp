#pragma once

#include "realm/util/from_chars.hpp"
#include "realm/util/string_view.hpp"
#include "realm/status_with.hpp"

namespace realm::_impl {

// These functions will parse the space/new-line delimited headers found at the beginning of
// messages and changesets.
inline StatusWith<util::StringView> parse_header_element(util::StringView sv, char) noexcept
{
    return sv;
}

template <typename T, typename... Args>
inline StatusWith<util::StringView> parse_header_element(util::StringView sv, char end_delim, T&& cur_arg,
                                                         Args&&... next_args) noexcept
{
    if (sv.empty()) {
        return {ErrorCodes::RuntimeError, "cannot parse an empty header line"};
    }

    using TBase = std::remove_reference_t<T>;
    if constexpr (std::is_same_v<TBase, util::StringView> || std::is_same_v<TBase, std::string>) {
        // Currently all string fields in wire protocol header lines appear at the beginning of the line and
        // should be delimited by a space.
        auto delim_at = std::find(sv.begin(), sv.end(), ' ');
        if (delim_at == sv.end()) {
            return {ErrorCodes::RuntimeError, "reached end of header line prematurely"};
        }

        auto sub_str_len = std::distance(sv.begin(), delim_at);
        cur_arg = TBase(sv.begin(), sub_str_len);
        sv = sv.substr(sub_str_len);
    }
    else if constexpr (std::is_integral_v<TBase> && !std::is_same_v<TBase, bool>) {
        auto parse_res = realm::util::from_chars(sv.begin(), sv.end(), cur_arg, 10);
        if (parse_res.ec != std::errc{}) {
            return {ErrorCodes::RuntimeError, util::format("error parsing integer in header line: %1",
                                                           std::make_error_code(parse_res.ec).message())};
        }

        sv = sv.substr(parse_res.ptr - sv.begin());
    }
    else if constexpr (std::is_same_v<TBase, bool>) {
        int bool_value = 0;
        auto parse_res = realm::util::from_chars(sv.begin(), sv.end(), bool_value, 10);
        if (parse_res.ec != std::errc{}) {
            return {ErrorCodes::RuntimeError, util::format("error parsing boolean in header line: %1",
                                                           std::make_error_code(parse_res.ec).message())};
        }

        cur_arg = (bool_value != 0);
        sv = sv.substr(parse_res.ptr - sv.begin());
    }
    else {
        // We currently only support numeric, string, and boolean values in header lines.
        REALM_UNREACHABLE();
    }

    if (sv.front() == ' ') {
        return parse_header_element(sv.substr(1), end_delim, next_args...);
    }
    if (sv.front() == end_delim) {
        return sv.substr(1);
    }

    return {ErrorCodes::RuntimeError, "found invalid character in header line"};
}

// parses a header line from a wire protocol message contained in sv. This function will split sv on spaces
// and convert the string values into string, integer, and boolean types as they're split.
//
// This function returns sv after the parsed header prefix has been removed or a Status representing an error.
// It is not effected by locale and does not throw.
template <typename... Args>
inline StatusWith<util::StringView> parse_header_line(util::StringView sv, char end_delim, Args&&... args) noexcept
{
    return parse_header_element(sv, end_delim, args...);
}

} // namespace realm::_impl
