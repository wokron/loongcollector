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

#include "CpuProfilingManager.h"
#include "collection_pipeline/queue/ProcessQueueManager.h"
#include "ebpf/plugin/cpu_profiling/ProcessWatcher.h"

namespace logtail::ebpf {

static void handleCpuProfilingEvent(uint32_t pid, char const *comm,
                                    char const *stack, uint32_t cnt,
                                    void *ctx) {
    assert(ctx != nullptr);
    auto& self = reinterpret_cast<CpuProfilingManager&>(ctx);
    self.recordProfilingEvent(pid, comm, stack, cnt);
}

CpuProfilingManager::CpuProfilingManager(
    const std::shared_ptr<ProcessCacheManager> &base,
    const std::shared_ptr<EBPFAdapter> &eBPFAdapter,
    moodycamel::BlockingConcurrentQueue<std::shared_ptr<CommonEvent>> &queue,
    const PluginMetricManagerPtr &metricManager)
    : AbstractManager(base, eBPFAdapter, queue, metricManager) {}

int CpuProfilingManager::Init(const PluginOptions &options) {
    auto *profilingOptsPtr = std::get_if<CpuProfilingOption *>(&options);
    if (!profilingOptsPtr) {
        LOG_ERROR(sLogger, ("Invalid options for CPU Profiling Manager", ""));
        return -1;
    }
    auto &profilingOpts = *profilingOptsPtr;

    mInited = true;

    auto pc = buildPluginConfig({}, handleCpuProfilingEvent, this);

    bool ok =
        mEBPFAdapter->StartPlugin(PluginType::CPU_PROFILING, std::move(pc));
    if (!ok) {
        return -1;
    }

    ProcessWatcher::GetInstance()->Start();
    ProcessWatcher::GetInstance()->Resume();
    ProcessWatcher::GetInstance()->RegisterWatch(
        "cpu_profiling_watch",
        ProcessWatchOptions(
            profilingOpts->mCmdlines,
            std::bind(&CpuProfilingManager::handleProcessWatchEvent, this,
                      std::placeholders::_1)));

    return 0;
}

int CpuProfilingManager::Destroy() {
    mInited = false;
    ProcessWatcher::GetInstance()->RemoveWatch("cpu_profiling_watch");
    ProcessWatcher::GetInstance()->Pause();
    return mEBPFAdapter->StopPlugin(PluginType::CPU_PROFILING) ? 0 : -1;
}

int CpuProfilingManager::Update(const PluginOptions &options) {
    auto &profilingOpts = std::get<CpuProfilingOption *>(options);
    ProcessWatcher::GetInstance()->RegisterWatch(
        "cpu_profiling_watch",
        ProcessWatchOptions(
            profilingOpts->mCmdlines,
            std::bind(&CpuProfilingManager::handleProcessWatchEvent, this,
                      std::placeholders::_1)));
    return 0;
}

std::unique_ptr<PluginConfig>
CpuProfilingManager::buildPluginConfig(std::vector<uint32_t> pids,
                                       CpuProfilingHandler handler, void *ctx) {
    std::unique_ptr<PluginConfig> pc = std::make_unique<PluginConfig>();
    pc->mPluginType = PluginType::CPU_PROFILING;
    CpuProfilingConfig config;
    config.mPids = std::move(pids);
    config.mHandler = handler;
    config.mCtx = ctx;
    pc->mConfig = std::move(config);
    return pc;
}

void CpuProfilingManager::handleProcessWatchEvent(std::vector<uint32_t> pids) {
    auto pc = buildPluginConfig(std::move(pids), nullptr, nullptr);
    mEBPFAdapter->UpdatePlugin(PluginType::CPU_PROFILING, std::move(pc));
}

void CpuProfilingManager::recordProfilingEvent(uint32_t pid, char const *comm,
                                               char const *symbol, uint cnt) {
    // TODO: need aggregate the events
    auto sourceBuffer = std::make_shared<SourceBuffer>();
    PipelineEventGroup eventGroup(sourceBuffer);
    auto *logEvent = eventGroup.AddLogEvent();
    logEvent->SetContentNoCopy("pid", std::to_string(pid));
    logEvent->SetContent("comm", std::string(comm));
    logEvent->SetContent("symbol", std::string(symbol));
    logEvent->SetContentNoCopy("cnt", std::to_string(cnt));

    {
        std::lock_guard lk(mContextMutex);
        if (this->mPipelineCtx == nullptr) {
            return;
        }
        std::unique_ptr<ProcessQueueItem> item =
            std::make_unique<ProcessQueueItem>(std::move(eventGroup),
                                               this->mPluginIndex);
        int maxRetry = 5;
        for (int retry = 0; retry < maxRetry; retry++) {
            auto result = ProcessQueueManager::GetInstance()->PushQueue(
                mQueueKey, std::move(item));
            if (QueueStatus::OK == result) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (retry == maxRetry - 1) {
                LOG_WARNING(sLogger,
                            ("configName", mPipelineCtx->GetConfigName())(
                                "pluginIdx", this->mPluginIndex)(
                                "[CpuProfiling] push log to queue failed!",
                                magic_enum::enum_name(result)));
            }
        }
    }
}

} // namespace logtail::ebpf
