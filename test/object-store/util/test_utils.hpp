////////////////////////////////////////////////////////////////////////////
//
// Copyright 2016 Realm Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////

#ifndef REALM_TEST_UTILS_HPP
#define REALM_TEST_UTILS_HPP

#include <catch2/catch.hpp>
#include <realm/util/file.hpp>
#include <realm/util/optional.hpp>

#include <functional>

namespace realm {

/// Open a Realm at a given path, creating its files.
bool create_dummy_realm(std::string path);
void reset_test_directory(const std::string& base_path);
std::vector<char> make_test_encryption_key(const char start = 0);
void catch2_ensure_section_run_workaround(bool did_run_a_section, std::string section_name,
                                          std::function<void()> func);

std::string encode_fake_jwt(const std::string& in, util::Optional<int64_t> exp = {},
                            util::Optional<int64_t> iat = {});

static inline std::string random_string(std::string::size_type length)
{
    static auto& chrs = "abcdefghijklmnopqrstuvwxyz"
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    thread_local static std::mt19937 rg{std::random_device{}()};
    thread_local static std::uniform_int_distribution<std::string::size_type> pick(0, sizeof(chrs) - 2);
    std::string s;
    s.reserve(length);
    while (length--)
        s += chrs[pick(rg)];
    return s;
}
} // namespace realm

#define REQUIRE_DIR_EXISTS(macro_path)                                                                               \
    do {                                                                                                             \
        CHECK(util::File::is_dir(macro_path) == true);                                                               \
    } while (0)

#define REQUIRE_DIR_DOES_NOT_EXIST(macro_path)                                                                       \
    do {                                                                                                             \
        CHECK(util::File::exists(macro_path) == false);                                                              \
    } while (0)

#define REQUIRE_REALM_EXISTS(macro_path)                                                                             \
    do {                                                                                                             \
        REQUIRE(util::File::exists(macro_path));                                                                     \
        REQUIRE(util::File::exists((macro_path) + ".lock"));                                                         \
        REQUIRE_DIR_EXISTS((macro_path) + ".management");                                                            \
    } while (0)

#define REQUIRE_REALM_DOES_NOT_EXIST(macro_path)                                                                     \
    do {                                                                                                             \
        REQUIRE(!util::File::exists(macro_path));                                                                    \
        REQUIRE(!util::File::exists((macro_path) + ".lock"));                                                        \
        REQUIRE_DIR_DOES_NOT_EXIST((macro_path) + ".management");                                                    \
    } while (0)

#define REQUIRE_THROWS_CONTAINING(expr, msg) REQUIRE_THROWS_WITH(expr, Catch::Matchers::Contains(msg))

#define ENCODE_FAKE_JWT(in) realm::encode_fake_jwt(in)

#endif // REALM_TEST_UTILS_HPP
