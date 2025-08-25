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

    void Start(livetrace_profiler_read_cb_ctx_t handler, void *ctx) {
        std::lock_guard<std::mutex> lock(mMutex);
        if (mProfiler == nullptr) {
            mProfiler = livetrace_profiler_create();
            assert(mProfiler != nullptr);
            mHandler = handler;
            mCtx = ctx;
            ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG,
                "[CpuProfiler][Start] create profiler, handler: %p ctx: %p", handler, ctx);
        }
    }

    void Stop() {
        std::lock_guard<std::mutex> lock(mMutex);
        if (mProfiler != nullptr) {
            ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG,
                "[CpuProfiler][Stop] destroy profiler");
            livetrace_profiler_destroy(mProfiler);
            mProfiler = nullptr;
        }
        mHandler = nullptr;
        mCtx = nullptr;
    }

    using RootPath = std::string;
    void UpdatePids(std::unordered_map<uint32_t, RootPath> toAddWithRoot, std::unordered_set<uint32_t> toRemove) {
        assert(mProfiler != nullptr);
        std::lock_guard<std::mutex> lock(mMutex);

        auto printToAdd = [&] {
            std::string result;
            for (auto& [pid, rootPath] : toAddWithRoot) {
                result += std::to_string(pid) + ":" + rootPath;
                result += ",";
            }
            return result;
        };
        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG,
                "[CpuProfiler][UpdatePids] toAddWithRoot: %s, toRemove: %s",
                printToAdd().c_str(), pidsToString(toRemove).c_str());

        std::unordered_set<uint32_t> toAdd;
        for (auto& [pids, _] : toAddWithRoot) {
            toAdd.insert(pids);
        }

        if (!toAdd.empty()) {
            std::string toAddStr = pidsToString(toAdd);
            ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG,
                "[CpuProfiler][UpdatePids] add pids: %s", toAddStr.c_str());
            livetrace_profiler_ctrl(mProfiler, LivetraceCtrlOp::LIVETRACE_ADD,
                                    toAddStr.c_str());
        }

        if (!toRemove.empty()) {
            std::string toRemoveStr = pidsToString(toRemove);
            ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG,
                "[CpuProfiler][UpdatePids] remove pids: %s", toRemoveStr.c_str());
            livetrace_profiler_ctrl(mProfiler,
                                    LivetraceCtrlOp::LIVETRACE_REMOVE,
                                    toRemoveStr.c_str());
        }
    }

    void Poll() {
        std::lock_guard<std::mutex> lock(mMutex);
        assert(mProfiler != nullptr && mHandler != nullptr);
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

    std::mutex mMutex;
    Profiler *mProfiler = nullptr;
    // TODO: make this non-static
    inline static livetrace_profiler_read_cb_ctx_t mHandler = nullptr;
    inline static void *mCtx = nullptr;
};

} // namespace ebpf
} // namespace logtail