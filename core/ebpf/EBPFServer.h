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

#include <sys/epoll.h>

#include <array>
#include <atomic>
#include <future>
#include <memory>
#include <shared_mutex>
#include <variant>

#include "collection_pipeline/CollectionPipelineContext.h"
#include "common/queue/blockingconcurrentqueue.h"
#include "ebpf/Config.h"
#include "ebpf/EBPFAdapter.h"
#include "ebpf/include/export.h"
#include "ebpf/plugin/AbstractManager.h"
#include "ebpf/plugin/ProcessCacheManager.h"
#include "runner/InputRunner.h"
#include "type/CommonDataEvent.h"
#include "util/FrequencyManager.h"

namespace logtail::ebpf {

class EnvManager {
public:
    void InitEnvInfo();
    bool IsSupportedEnv(PluginType type);
    bool AbleToLoadDyLib();

private:
    volatile bool mInited = false;

    std::atomic_bool mArchSupport = false;
    std::atomic_bool mBTFSupport = false;
    std::atomic_bool m310Support = false;
#ifdef APSARA_UNIT_TEST_MAIN
    friend class eBPFServerUnittest;
#endif
};

enum class PluginStateOperation {
    kAddPipeline,
    kRemovePipeline,
    kRemoveAll,
};

struct PluginState {
    // pipelineName ==> project
    std::map<std::string, std::string> mPipelines;
    std::shared_ptr<AbstractManager> mManager;
    // Shared mutex to coordinate access between plugin management operations
    // (EnablePlugin/DisablePlugin/SuspendPlugin) and event handling operations
    // (PollPerfBuffers/HandlerEvents/GetAllProjects), allowing them to safely interleave.
    mutable std::atomic_bool mValid;
    mutable std::shared_mutex mMtx;
};

class EBPFServer : public InputRunner {
public:
    EBPFServer(const EBPFServer&) = delete;
    EBPFServer& operator=(const EBPFServer&) = delete;

    ~EBPFServer();

    void Init() override;

    static EBPFServer* GetInstance() {
        static EBPFServer sInstance;
        return &sInstance;
    }

    void Stop() override;

    void EventGC() override;

    bool EnablePlugin(const std::string& pipelineName,
                      uint32_t pluginIndex,
                      PluginType type,
                      const logtail::CollectionPipelineContext* ctx,
                      const PluginOptions& options,
                      const PluginMetricManagerPtr& mgr);

    bool DisablePlugin(const std::string& pipelineName, PluginType type);

    bool SuspendPlugin(const std::string& pipelineName, PluginType type);

    bool HasRegisteredPlugins() const override;

    bool IsSupportedEnv(PluginType type);

    std::string GetAllProjects();

    // TODO(qianlu): remove this function when network observer use unified threads
    std::shared_ptr<AbstractManager> GetPluginManager(PluginType type);

    RetryableEventCache& EventCache() { return mRetryableEventCache; }

    void RegisterPluginPerfBuffers(PluginType type);
    void UnregisterPluginPerfBuffers(PluginType type);

private:
    bool startPluginInternal(const std::string& pipelineName,
                             uint32_t pluginIndex,
                             PluginType type,
                             const logtail::CollectionPipelineContext* ctx,
                             const PluginOptions& options,
                             const PluginMetricManagerPtr& metricManager);
    EBPFServer();

    void pollPerfBuffers();
    void handlerEvents();
    // std::string checkLoadedPipelineName(PluginType type);
    void updatePluginState(PluginType type,
                           const std::string& name,
                           const std::string& project,
                           PluginStateOperation op,
                           std::shared_ptr<AbstractManager>);
    PluginState& getPluginState(PluginType type);
    bool checkIfNeedStopProcessCacheManager() const;
    void stopProcessCacheManager();
    void
    updateCbContext(PluginType type, const logtail::CollectionPipelineContext* ctx, logtail::QueueKey key, int idx);
    void handleEvents(std::array<std::shared_ptr<CommonEvent>, 4096>& items, size_t count);
    void sendEvents();
    void handleEventCache();
    void handleEpollEvents();

    // Unified epoll monitoring methods
    bool initUnifiedEpollMonitoring();
    void cleanupUnifiedEpollMonitoring();

    std::shared_ptr<EBPFAdapter> mEBPFAdapter;

    std::array<PluginState, static_cast<size_t>(PluginType::MAX)> mPlugins = {};

    eBPFAdminConfig mAdminConfig;
    std::atomic_bool mInited = false;
    std::atomic_bool mRunning = false;

    std::string mHostIp;
    std::string mHostName;
    std::filesystem::path mHostPathPrefix;

    EnvManager mEnvMgr;
    mutable MetricsRecordRef mMetricsRecordRef;

    // hold some managers ...
    std::shared_ptr<ProcessCacheManager> mProcessCacheManager;

    moodycamel::BlockingConcurrentQueue<std::shared_ptr<CommonEvent>> mCommonEventQueue;

    std::future<void> mPoller; // used to poll perf buffers and handle retry events
    std::future<void> mHandler; // used to handle common events, do aggregate and send events
    std::future<void> mIterator; // used to iterate bpf maps

    FrequencyManager mFrequencyMgr;

    // metrics
    CounterPtr mRecvKernelEventsTotal;
    CounterPtr mLossKernelEventsTotal;
    IntGaugePtr mConnectionCacheSize;
    CounterPtr mPushLogFailedTotal;

    int mUnifiedEpollFd = -1;
    std::vector<struct epoll_event> mEpollEvents;

    RetryableEventCache mRetryableEventCache;
    IntGaugePtr mRetryableEventCacheSize;
    int64_t mLastEventCacheRetryTime = 0;

    EventPool mEventPool;
#ifdef APSARA_UNIT_TEST_MAIN
    friend class eBPFServerUnittest;
#endif
};

} // namespace logtail::ebpf
