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

#include "CommonDataEvent.h"

namespace logtail::ebpf {

class ProfilingEvent : public CommonEvent {
public:
    ProfilingEvent(uint32_t pid, KernelEventType type, const std::string &comm,
                   const std::string &symbol, uint32_t cnt)
        : CommonEvent(pid, 0, type, 0), mComm(comm),
          mSymbol(symbol), mCnt(cnt) {}

    [[nodiscard]] PluginType GetPluginType() const override {
        return PluginType::CPU_PROFILING;
    }

    std::string mComm;
    std::string mSymbol;
    uint32_t mCnt;
};

class ProfilingEventGroup {
public:
    ProfilingEventGroup(uint32_t pid, uint64_t ktime)
        : mPid(pid), mKtime(ktime) {}
    uint32_t mPid;
    uint64_t mKtime;
    // attrs
    std::vector<std::shared_ptr<CommonEvent>> mInnerEvents;
};

} // namespace logtail::ebpf
