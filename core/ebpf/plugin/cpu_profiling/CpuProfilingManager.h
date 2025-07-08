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

#include "ebpf/plugin/AbstractManager.h"

namespace logtail::ebpf {

class CpuProfilingManager : public AbstractManager {
public:
    CpuProfilingManager(const std::shared_ptr<ProcessCacheManager>& base,
                           const std::shared_ptr<EBPFAdapter>& eBPFAdapter,
                           moodycamel::BlockingConcurrentQueue<std::shared_ptr<CommonEvent>>& queue,
                           const PluginMetricManagerPtr& metricManager);
    ~CpuProfilingManager() = default;

    static std::shared_ptr<CpuProfilingManager>
    Create(const std::shared_ptr<ProcessCacheManager>& processCacheManager,
           const std::shared_ptr<EBPFAdapter>& eBPFAdapter,
           moodycamel::BlockingConcurrentQueue<std::shared_ptr<CommonEvent>>& queue,
           const PluginMetricManagerPtr& metricMgr) {
        return std::make_shared<CpuProfilingManager>(processCacheManager, eBPFAdapter, queue, metricMgr);
    }

    int Init(const PluginOptions& options) override;
    int Destroy() override;

    int HandleEvent(const std::shared_ptr<CommonEvent>& event) override { return 0; }
    int SendEvents() override { return 0; }

    bool ScheduleNext(const std::chrono::steady_clock::time_point&, const std::shared_ptr<ScheduleConfig>&) override {
        return true;
    }

    PluginType GetPluginType() override { return PluginType::CPU_PROFILING; }

    std::unique_ptr<PluginConfig>
    GeneratePluginConfig([[maybe_unused]] const PluginOptions& options) override {
        auto pc = std::make_unique<PluginConfig>();
        pc->mPluginType = PluginType::CPU_PROFILING;
        CpuProfilingConfig config;
        auto& opts = std::get<CpuProfilingOption*>(options);
        config.mPids = opts->mPids;
        config.mHandler = nullptr; // do not change handler
        pc->mConfig = std::move(config);
        return pc;
    }

    void RecordProfilingEvent(uint pid, const char* comm, const char* symbol, uint cnt);
};

} // namespace logtail::ebpf
