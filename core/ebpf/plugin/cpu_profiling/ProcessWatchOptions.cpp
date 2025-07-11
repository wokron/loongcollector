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

#include <vector>

#include "ebpf/plugin/cpu_profiling/ProcessWatchOptions.h"
#include "json/json.h"

namespace logtail {
namespace ebpf {

bool ProcessWatchOptions::IsMatch(const std::string &cmdline) const {
    if (mWildcards.empty()) {
        return true;
    }
    // TODO: support wildcard
    for (const auto &wildcard : mWildcards) {
        if (cmdline.find(wildcard) != std::string::npos) {
            return true;
        }
    }
    return false;
}

} // namespace ebpf
} // namespace logtail
