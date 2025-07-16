/*
 * Copyright 2025 iLogtail Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <regex>
#include <string>
#include <unordered_map>

namespace logtail {

class Wildcard {
public:
    Wildcard(const std::string &pattern) : mRegex(getRegexPattern(pattern)) {}

    bool IsMatch(const std::string &str) const {
        return std::regex_match(str, mRegex);
    }

private:
    static std::string getRegexPattern(const std::string &pattern) {
        std::string regexPattern = "";
        for (auto &ch : pattern) {
            switch (ch) {
            case '*':
                regexPattern += ".*";
                break;
            case '?':
                regexPattern += ".";
                break;
            case '\\':
                // Escape the next character
                regexPattern += "\\\\";
                break;
            case '.':
            case '+':
            case '(':
            case ')':
            case '[':
            case ']':
            case '{':
            case '}':
            case '^':
            case '$':
            case '|':
                // Escape regex special characters
                regexPattern += '\\';
                regexPattern += ch;
                break;
            default:
                // For any other character, just append it as is
                regexPattern += ch;
                break;
            }
        }
        return regexPattern;
    }

    std::regex mRegex;
};

class WildcardEngine {
public:
    bool IsMatch(const std::string &pattern, const std::string &str,
                 bool cache = true) {
        if (!cache) {
            Wildcard wildcard(pattern);
            return wildcard.IsMatch(str);
        }

        auto it = mWildcards.find(pattern);
        if (it == mWildcards.end()) {
            it = mWildcards.emplace(pattern, Wildcard(pattern));
        }
        return it->second.IsMatch(str);
    }

private:
    std::unordered_multimap<std::string, Wildcard> mWildcards;
};

} // namespace logtail