// Copyright 2025 iLogtail Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <string>
#include <vector>
#include <functional>

#include "json/json.h"

namespace logtail {
namespace ebpf {

class ProcessWatchOptions {
public:
    using Callback = std::function<void(std::vector<uint32_t> pids)>;

    ProcessWatchOptions() = default;

    ProcessWatchOptions(std::vector<std::string> wildcards, Callback callback)
        : mWildcards(std::move(wildcards)), mCallback(std::move(callback)) {}

    std::vector<std::string> mWildcards;
    Callback mCallback;
};

} // namespace ebpf
} // namespace logtail
