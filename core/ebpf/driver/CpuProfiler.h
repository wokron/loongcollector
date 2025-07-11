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

#include <cassert>
#include <unordered_set>

#include "Log.h"
#include "ebpf/driver/Livetrace.h"

namespace logtail {
namespace ebpf {

class CpuProfiler {
public:
    CpuProfiler() = default;

    ~CpuProfiler() { Stop(); }

    void Suspend() {
        auto profiler = getProfiler();

        auto &toRemove = mPids;
        if (toRemove.empty()) {
            return;
        }

        std::string pidsToRemove = pidsToString(toRemove);
        auto r =
            livetrace_profiler_ctrl(profiler, kRemove, pidsToRemove.c_str());
        assert(r == 0);

        mPids.clear();
    }

    void Stop() {
        if (mProfiler != nullptr) {
            livetrace_profiler_destroy(mProfiler);
            mProfiler = nullptr;
        }
        mPids.clear();
        mHandler = nullptr;
    }

    void UpdatePids(const std::unordered_set<uint32_t> &newPids) {
        auto profiler = getProfiler();

        auto& toAdd = newPids;
        std::unordered_set<uint32_t> toRemove;
        compareSets(newPids, toRemove);

        if (toAdd.empty() && toRemove.empty()) {
            return; // No changes
        }

        if (!toAdd.empty()) {
            std::string pidsToAdd = pidsToString(toAdd);
            auto r = livetrace_profiler_ctrl(profiler, kAdd, pidsToAdd.c_str());
            assert(r == 0);
        }

        if (!toRemove.empty()) {
            std::string pidsToRemove = pidsToString(toRemove);
            auto r = livetrace_profiler_ctrl(profiler, kRemove,
                                             pidsToRemove.c_str());
            assert(r == 0);
        }

        mPids = newPids;
    }

    void RegisterPollHandler(livetrace_profiler_read_cb_t handler, void *ctx) {
        mHandler = handler;
        mCtx = ctx;
    }

    bool Poll() {
        auto profiler = getProfiler();

        if (mHandler == nullptr) {
            EBPF_LOG(eBPFLogType::NAMI_LOG_TYPE_WARN,
                     "[CpuProfiler] Handler not registered");
            return false;
        }

        livetrace_profiler_read(profiler, mHandler, mCtx);
        return true;
    }

private:
    std::string pidsToString(const std::unordered_set<uint32_t> &pids) {
        std::string result;
        for (const auto &pid : pids) {
            if (!result.empty()) {
                result += ",";
            }
            result += std::to_string(pid);
        }
        return result;
    }

    void compareSets(const std::unordered_set<uint32_t> &newPids,
                     std::unordered_set<uint32_t> &toRemove) {
        for (const auto &pid : mPids) {
            if (newPids.find(pid) == newPids.end()) {
                toRemove.insert(pid);
            }
        }
    }

    Profiler *getProfiler() {
        if (mProfiler == nullptr) {
            mProfiler = livetrace_profiler_create();
        }
        assert(mProfiler != nullptr);
        return mProfiler;
    }

    static constexpr int kAdd = 1, kRemove = 0;

    std::unordered_set<uint32_t> mPids;
    Profiler *mProfiler = nullptr;
    livetrace_profiler_read_cb_t mHandler = nullptr;
    void *mCtx = nullptr;
};

} // namespace ebpf
} // namespace logtail