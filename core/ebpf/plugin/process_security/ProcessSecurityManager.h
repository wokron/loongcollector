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

#include <coolbpf/security/type.h>
#include <cstdint>

#include <memory>

#include "common/queue/blockingconcurrentqueue.h"
#include "ebpf/Config.h"
#include "ebpf/plugin/AbstractManager.h"
#include "ebpf/plugin/ProcessCacheManager.h"
#include "ebpf/type/ProcessEvent.h"
#include "ebpf/util/AggregateTree.h"

namespace logtail::ebpf {
class ProcessSecurityManager : public AbstractManager {
public:
    inline static constexpr StringView kExitTidKey = "exit_tid";
    inline static constexpr StringView kExitCodeKey = "exit_code";
    inline static constexpr StringView kExecveValue = "execve";
    inline static constexpr StringView kCloneValue = "clone";
    inline static constexpr StringView kExitValue = "exit";

    ProcessSecurityManager() = delete;
    ProcessSecurityManager(const std::shared_ptr<ProcessCacheManager>& processCacheManager,
                           const std::shared_ptr<EBPFAdapter>& eBPFAdapter,
                           moodycamel::BlockingConcurrentQueue<std::shared_ptr<CommonEvent>>& queue,
                           EventPool* pool);

    static std::shared_ptr<ProcessSecurityManager>
    Create(const std::shared_ptr<ProcessCacheManager>& processCacheManager,
           const std::shared_ptr<EBPFAdapter>& eBPFAdapter,
           moodycamel::BlockingConcurrentQueue<std::shared_ptr<CommonEvent>>& queue,
           EventPool* pool) {
        return std::make_shared<ProcessSecurityManager>(processCacheManager, eBPFAdapter, queue, pool);
    }

    ~ProcessSecurityManager() = default;
    int Init() override;
    int Destroy() override;

    PluginType GetPluginType() override { return PluginType::PROCESS_SECURITY; }

    int HandleEvent(const std::shared_ptr<CommonEvent>& event) override;

    int SendEvents() override;

    // process perfbuffer was polled by processCacheManager ...
    int PollPerfBuffer(int maxWaitTimeMs) override { return 0; }
    int ConsumePerfBufferData() override { return 0; }

    int RegisteredConfigCount() override { return mRegisteredConfigCount; }

    int AddOrUpdateConfig(const CollectionPipelineContext*,
                          uint32_t,
                          const PluginMetricManagerPtr&,
                          const PluginOptions&) override;

    int RemoveConfig(const std::string&) override;

    std::unique_ptr<PluginConfig> GeneratePluginConfig(
        [[maybe_unused]] const PluginOptions& options) override {
        auto ebpfConfig = std::make_unique<PluginConfig>();
        ebpfConfig->mPluginType = PluginType::PROCESS_SECURITY;
        return ebpfConfig;
    }

    int Update([[maybe_unused]] const PluginOptions& options) override {
        // do nothing ...
        return 0;
    }

    void SetMetrics(CounterPtr lossLogsTotal) { mPushLogFailedTotal = std::move(lossLogsTotal); }

private:
    int64_t mSendIntervalMs = 400;
    int64_t mLastSendTimeMs = 0;
    SIZETAggTree<ProcessEventGroup, std::shared_ptr<CommonEvent>> mAggregateTree;

    std::vector<MetricLabels> mRefAndLabels;
    PluginMetricManagerPtr mMetricMgr;
    const CollectionPipelineContext* mPipelineCtx{nullptr};
    logtail::QueueKey mQueueKey = 0;
    int mRegisteredConfigCount = 0;
    uint32_t mPluginIndex{0};
    CounterPtr mPushLogsTotal;
    CounterPtr mPushLogGroupTotal;
    CounterPtr mPushLogFailedTotal;
};

} // namespace logtail::ebpf
