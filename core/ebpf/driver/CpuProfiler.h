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
#include <mutex>
#include <unordered_set>
#include <vector>

extern "C" {

void livetrace_enable_system_profiling(void);

void livetrace_disable_symbolizer(void);

struct Profiler;

struct Profiler *livetrace_profiler_create(void);

void livetrace_profiler_destroy(struct Profiler *profiler);

enum LivetraceCtrlOp {
    LIVETRACE_REMOVE = 0,
    LIVETRACE_ADD = 1,
};

int32_t livetrace_profiler_ctrl(struct Profiler *profiler, int op,
                                const char *pids);

using livetrace_profiler_read_cb_t = void (*)(uint32_t pid, const char *comm,
                                              const char *stack, uint32_t cnt);

void livetrace_profiler_read(struct Profiler *profiler,
                             livetrace_profiler_read_cb_t cb);

using livetrace_profiler_read_cb_ctx_t = void (*)(uint32_t pid, const char *comm,
                                              const char *stack, uint32_t cnt, void *ctx);
}

namespace logtail {
namespace ebpf {

class CpuProfiler {
public:
    CpuProfiler() = default;

    ~CpuProfiler() { Stop(); }

    void Start() {
        std::lock_guard<std::mutex> lock(mMutex);
        if (mProfiler == nullptr) {
            ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG,
                "[CPUProfiler][Start] create profiler");
            mProfiler = livetrace_profiler_create();
            assert(mProfiler != nullptr);
        }
    }

    void Stop() {
        std::lock_guard<std::mutex> lock(mMutex);
        if (mProfiler != nullptr) {
            ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG,
                "[CPUProfiler][Stop] destroy profiler");
            livetrace_profiler_destroy(mProfiler);
            mProfiler = nullptr;
        }
        mPids.clear();
        mHandler = nullptr;
        mCtx = nullptr;
    }

    void UpdatePids(std::unordered_set<uint32_t> newPids) {
        assert(mProfiler != nullptr);
        std::lock_guard<std::mutex> lock(mMutex);

        std::unordered_set<uint32_t> toAdd, toRemove;
        compareSets(newPids, toAdd, toRemove);

        if (toAdd.empty() && toRemove.empty()) {
            return; // No changes
        }

        if (!toAdd.empty()) {
            std::string pidsToAdd = pidsToString(toAdd);
            ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG,
                "[CPUProfiler][UpdatePids] add pids: %s", pidsToAdd.c_str());
            livetrace_profiler_ctrl(mProfiler, LivetraceCtrlOp::LIVETRACE_ADD,
                                    pidsToAdd.c_str());
        }

        if (!toRemove.empty()) {
            std::string pidsToRemove = pidsToString(toRemove);
            ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG,
                "[CPUProfiler][UpdatePids] remove pids: %s", pidsToRemove.c_str());
            livetrace_profiler_ctrl(mProfiler,
                                    LivetraceCtrlOp::LIVETRACE_REMOVE,
                                    pidsToRemove.c_str());
        }

        mPids = std::move(newPids);
    }

    void RegisterPollHandler(livetrace_profiler_read_cb_ctx_t handler, void *ctx) {
        std::lock_guard<std::mutex> lock(mMutex);
        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG,
                "[CPUProfiler][RegisterPollHandler] register handler: %p ctx: %p", handler, ctx);
        mHandler = handler;
        mCtx = ctx;
    }

    void Poll() {
        std::lock_guard<std::mutex> lock(mMutex);
        assert(mProfiler != nullptr && mHandler != nullptr);
        if (mPids.empty()) {
            return;
        }

        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG,
                "[CPUProfiler][Poll] poll");
        livetrace_profiler_read(mProfiler, handler_without_ctx);
    }

private:
    static void handler_without_ctx(uint32_t pid, const char *comm, const char *stack, uint32_t cnt) {
        mHandler(pid, comm, stack, cnt, mCtx);
    }

    static std::string pidsToString(const std::unordered_set<uint32_t> &pids) {
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

    std::mutex mMutex;
    std::unordered_set<uint32_t> mPids;
    Profiler *mProfiler = nullptr;
    // TODO: make this non-static
    inline static livetrace_profiler_read_cb_ctx_t mHandler = nullptr;
    inline static void *mCtx = nullptr;
};

} // namespace ebpf
} // namespace logtail