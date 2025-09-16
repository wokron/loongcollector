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
    CpuProfilingManager(
        const std::shared_ptr<ProcessCacheManager> &processCacheManager,
        const std::shared_ptr<EBPFAdapter> &eBPFAdapter,
        moodycamel::BlockingConcurrentQueue<std::shared_ptr<CommonEvent>>
            &queue);
    ~CpuProfilingManager() override = default;

    static std::shared_ptr<CpuProfilingManager>
    Create(const std::shared_ptr<ProcessCacheManager> &processCacheManager,
           const std::shared_ptr<EBPFAdapter> &eBPFAdapter,
           moodycamel::BlockingConcurrentQueue<std::shared_ptr<CommonEvent>>
               &queue) {
        return std::make_shared<CpuProfilingManager>(processCacheManager,
                                                     eBPFAdapter, queue);
    }

    int Init() override;
    int Destroy() override;

    int HandleEvent(const std::shared_ptr<CommonEvent> &event) override {
        return 0;
    }

    int SendEvents() override { return 0; }

    int RegisteredConfigCount() override { return mRegisteredConfigCount; }

    int AddOrUpdateConfig(const CollectionPipelineContext *context,
                          uint32_t configId,
                          const PluginMetricManagerPtr &metricManager,
                          const PluginOptions &options) override;

    int RemoveConfig(const std::string &configName) override;

    PluginType GetPluginType() override { return PluginType::CPU_PROFILING; }

    std::unique_ptr<PluginConfig>
    GeneratePluginConfig(const PluginOptions &options) override {
        assert(false);
        return nullptr;
    }

    int Update([[maybe_unused]] const PluginOptions &options) override {
        assert(false);
        return 0;
    }

    int Suspend() override;

    void HandleCpuProfilingEvent(uint32_t pid, const char *comm,
                                 const char *stack, uint32_t cnt);

private:
    std::atomic<bool> mInited;

    std::string mConfigName;
    const CollectionPipelineContext *mPipelineCtx{nullptr};
    logtail::QueueKey mQueueKey = 0;
    uint32_t mPluginIndex{0};
    int mRegisteredConfigCount = 0;
};

} // namespace logtail::ebpf
