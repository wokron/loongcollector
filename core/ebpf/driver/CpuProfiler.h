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

#include "ebpf/driver/CpuProfilingAdapter.h"
#include <unordered_set>

namespace logtail {
namespace ebpf {

class CpuProfiler {
public:
    CpuProfiler(std::shared_ptr<CpuProfilingAdapter> profilingAdapter)
        : mProfilingAdapter(std::move(profilingAdapter)) {
        assert(mProfilingAdapter != nullptr);
    }

    ~CpuProfiler() { Stop(); }

    bool Suspend() {
        auto profiler = GetProfiler();
        if (profiler == nullptr) {
            LOG_ERROR(sLogger, ("[CpuProfiler] GetProfiler failed", ""));
            return false;
        }

        auto &toRemove = mPids;
        if (toRemove.empty()) {
            return true;
        }

        std::string pidsToRemove = PidsToString(toRemove);
        auto r = mProfilingAdapter->ProfilerCtrl(profiler, kRemove,
                                                 pidsToRemove.c_str());
        assert(r == 0);

        mPids.clear();

        return true;
    }

    void Stop() {
        if (mProfiler != nullptr) {
            auto ok = mProfilingAdapter->DestroyProfiler(mProfiler);
            assert(ok);
            mProfiler = nullptr;
        }
        mPids.clear();
        mHandler = nullptr;
    }

    bool UpdatePids(const std::unordered_set<uint32_t> &newPids) {
        auto profiler = GetProfiler();
        if (profiler == nullptr) {
            LOG_ERROR(sLogger, ("[CpuProfiler] GetProfiler failed", ""));
            return false;
        }

        std::unordered_set<uint32_t> toAdd, toRemove;
        CompareSets(newPids, toAdd, toRemove);

        if (toAdd.empty() && toRemove.empty()) {
            return true; // No changes
        }

        std::string pidsToAdd = PidsToString(toAdd);
        auto r =
            mProfilingAdapter->ProfilerCtrl(profiler, kAdd, pidsToAdd.c_str());
        assert(r == 0);

        std::string pidsToRemove = PidsToString(toRemove);
        mProfilingAdapter->ProfilerCtrl(profiler, kRemove,
                                        pidsToRemove.c_str());
        assert(r == 0);

        mPids = newPids;

        return true;
    }

    void
    RegisterPollHandler(CpuProfilingAdapter::profiler_read_cb_func handler) {
        mHandler = handler;
    }

    bool Poll() {
        auto profiler = GetProfiler();
        if (profiler == nullptr) {
            LOG_ERROR(sLogger, ("[CpuProfiler] GetProfiler failed", ""));
            return false;
        }

        if (mHandler == nullptr) {
            LOG_ERROR(sLogger, ("[CpuProfiler] Handler not registered", ""));
            return false;
        }

        mProfilingAdapter->ProfilerRead(profiler, mHandler);
        return true;
    }

private:
    std::string PidsToString(const std::unordered_set<uint32_t> &pids) {
        std::string result;
        for (const auto &pid : pids) {
            if (!result.empty()) {
                result += ",";
            }
            result += std::to_string(pid);
        }
        return result;
    }

    void CompareSets(const std::unordered_set<uint32_t> &newPids,
                     std::unordered_set<uint32_t> &toAdd,
                     std::unordered_set<uint32_t> &toRemove) {
        for (const auto &pid : newPids) {
            if (mPids.find(pid) == mPids.end()) {
                toAdd.insert(pid);
            }
        }
        for (const auto &pid : mPids) {
            if (newPids.find(pid) == newPids.end()) {
                toRemove.insert(pid);
            }
        }
    }

    CpuProfilingAdapter::Profiler *GetProfiler() {
        mProfilingAdapter->Init();
        if (mProfiler == nullptr) {
            mProfiler = mProfilingAdapter->CreateProfiler();
            if (mProfiler == nullptr) {
                return nullptr;
            }
        }
        return mProfiler;
    }

    static constexpr int kAdd = 1, kRemove = 0;

    std::unordered_set<uint32_t> mPids;
    std::shared_ptr<CpuProfilingAdapter> mProfilingAdapter;
    CpuProfilingAdapter::Profiler *mProfiler = nullptr;
    CpuProfilingAdapter::profiler_read_cb_func mHandler = nullptr;
};

} // namespace ebpf
} // namespace logtail