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

#include "ebpf/plugin/cpu_profiling/CpuProfilingManager.h"
#include "collection_pipeline/queue/ProcessQueueManager.h"
#include "common/HashUtil.h"
#include "common/TimeKeeper.h"
#include "common/magic_enum.hpp"
#include "ebpf/plugin/cpu_profiling/ProcessWatcher.h"
#include "ebpf/type/table/ProfileTable.h"

namespace logtail::ebpf {

static void handleCpuProfilingEvent(uint32_t pid, char const *comm,
                                    char const *stack, uint32_t cnt,
                                    void *ctx) {
    assert(ctx != nullptr);
    auto self = static_cast<CpuProfilingManager *>(ctx);
    self->RecordProfilingEvent(pid, comm, stack, cnt);
}

CpuProfilingManager::CpuProfilingManager(
    const std::shared_ptr<ProcessCacheManager> &base,
    const std::shared_ptr<EBPFAdapter> &eBPFAdapter,
    moodycamel::BlockingConcurrentQueue<std::shared_ptr<CommonEvent>> &queue,
    const PluginMetricManagerPtr &metricManager)
    : AbstractManager(base, eBPFAdapter, queue, metricManager),
      mAggregateTree(
          4096,
          [](std::unique_ptr<ProfilingEventGroup> &base,
             const std::shared_ptr<CommonEvent> &other) {
              base->mInnerEvents.emplace_back(other);
          },
          [](const std::shared_ptr<CommonEvent> &in,
             std::shared_ptr<SourceBuffer> &sourceBuffer) {
              return std::make_unique<ProfilingEventGroup>(in->mPid);
          }) {}

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

static std::array<size_t, 1>
generateAggKeyForProfilingEvent(const std::shared_ptr<CommonEvent> &in) {
    auto *event = static_cast<ProfilingEvent *>(in.get());

    std::array<size_t, 1> result{0UL};
    std::hash<uint64_t> hasher;

    AttrHashCombine(result[0], hasher(event->mPid));

    return result;
}

int CpuProfilingManager::HandleEvent(
    const std::shared_ptr<CommonEvent> &event) {
    auto *profilingEvent = static_cast<ProfilingEvent *>(event.get());
    if (profilingEvent == nullptr) {
        LOG_ERROR(sLogger, ("failed to convert CommonEvent to ProfilingEvent, "
                            "kernel event type",
                            magic_enum::enum_name(event->GetKernelEventType()))(
                               "PluginType",
                               magic_enum::enum_name(event->GetPluginType())));
        return 1;
    }

    std::array<size_t, 1> aggKey = generateAggKeyForProfilingEvent(event);

    {
        std::lock_guard<std::mutex> lk(mLock);
        bool ret = mAggregateTree.Aggregate(event, aggKey);
        LOG_DEBUG(sLogger, ("after aggregate", ret));
    }
    return 0;
}

int CpuProfilingManager::SendEvents() {
    if (!IsRunning()) {
        return 0;
    }
    auto nowMs = TimeKeeper::GetInstance()->NowMs();
    if (nowMs - mLastSendTimeMs < mSendIntervalMs) {
        return 0;
    }

    auto aggTree = [this]() {
        std::lock_guard<std::mutex> lk(mLock);
        return mAggregateTree.GetAndReset();
    }();

    auto nodes = aggTree.GetNodesWithAggDepth(1);
    LOG_DEBUG(sLogger, ("enter aggregator ...", nodes.size()));
    if (nodes.empty()) {
        LOG_DEBUG(sLogger, ("empty nodes...", ""));
        return 0;
    }

    auto sourceBuffer = std::make_shared<SourceBuffer>();
    PipelineEventGroup eventGroup(sourceBuffer);
    for (auto &node : nodes) {
        LOG_DEBUG(sLogger, ("child num", node->mChild.size()));
        aggTree.ForEach(node, [&](const ProfilingEventGroup *group) {
            auto pidSb = sourceBuffer->CopyString(std::to_string(group->mPid));

            for (const auto &innerEvent : group->mInnerEvents) {
                CommonEvent *ce = innerEvent.get();
                auto *profilingEvent = static_cast<ProfilingEvent *>(ce);
                auto commSb = sourceBuffer->CopyString(profilingEvent->mComm);

                for (auto &stack : profilingEvent->mStacks) {
                    auto stackSb = sourceBuffer->CopyString(stack.first);
                    auto cntSb =
                        sourceBuffer->CopyString(std::to_string(stack.second));

                    auto *logEvent = eventGroup.AddLogEvent();
                    logEvent->SetContentNoCopy(
                        kPid.LogKey(), StringView(pidSb.data, pidSb.size));
                    logEvent->SetContentNoCopy(
                        kComm.LogKey(), StringView(commSb.data, commSb.size));
                    logEvent->SetContentNoCopy(
                        kStack.LogKey(),
                        StringView(stackSb.data, stackSb.size));
                    logEvent->SetContentNoCopy(
                        kCnt.LogKey(), StringView(cntSb.data, cntSb.size));
                }
            }
        });
    }

    {
        std::lock_guard lk(mContextMutex);
        if (this->mPipelineCtx == nullptr) {
            return 0;
        }
        LOG_DEBUG(sLogger, ("event group size", eventGroup.GetEvents().size()));
        std::unique_ptr<ProcessQueueItem> item =
            std::make_unique<ProcessQueueItem>(std::move(eventGroup),
                                               this->mPluginIndex);
        int maxRetry = 5;
        for (int retry = 0; retry < maxRetry; ++retry) {
            if (QueueStatus::OK ==
                ProcessQueueManager::GetInstance()->PushQueue(
                    mQueueKey, std::move(item))) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (retry == maxRetry - 1) {
                LOG_WARNING(
                    sLogger,
                    ("configName", mPipelineCtx->GetConfigName())(
                        "pluginIdx", this->mPluginIndex)(
                        "[ProcessSecurityEvent] push queue failed!", ""));
                // TODO: Alarm discard data
            }
        }
    }
    return 0;
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

static std::vector<StackCnt> parseStackCnt(char const *symbol) {
    // Format: "<comm>:<pid>;<stacks> <cnt>\n"
    // Example: "bash:1234;func1;func2;func3 10\n"

    std::vector<StackCnt> result;

    std::istringstream ssymbol;
    ssymbol.str(symbol);
    std::string line;
    while (std::getline(ssymbol, line)) {
        auto pos1 = line.find(';');
        if (pos1 == std::string::npos) {
            LOG_ERROR(sLogger, ("Invalid symbol format", line));
            continue;
        }
        auto pos2 = line.find(' ');
        if (pos2 == std::string::npos || pos2 < pos1) {
            LOG_ERROR(sLogger, ("Invalid symbol format", line));
            continue;
        }

        auto stack = line.substr(pos1 + 1, pos2 - pos1 - 1);
        auto cntStr = line.substr(pos2 + 1);
        uint32_t cnt = std::stoul(cntStr);

        result.push_back(std::make_pair(stack, cnt));
    }

    return result;
}

void CpuProfilingManager::RecordProfilingEvent(uint32_t pid, char const *comm,
                                               char const *symbol, uint cnt) {

    auto stackCnt = parseStackCnt(symbol);
    auto ts = std::chrono::system_clock::now().time_since_epoch().count();
    auto event = std::make_shared<ProfilingEvent>(
        pid, KernelEventType::CPU_PROFILING_EVENT, comm, std::move(stackCnt),
        ts);

    if (!mCommonEventQueue.try_enqueue(event)) {
        LOG_WARNING(sLogger,
                    ("[lost_cpu_profiling_event] try_enqueue failed pid",
                     pid)("comm", comm)("symbol", symbol)("cnt", cnt));
    } else {
        LOG_DEBUG(sLogger, ("[record_cpu_profiling_event] pid",
                            pid)("comm", comm)("symbol", symbol)("cnt", cnt));
    }
}

} // namespace logtail::ebpf
