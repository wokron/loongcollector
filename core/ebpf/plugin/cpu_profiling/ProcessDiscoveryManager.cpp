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

#include <cassert>
#include <thread>
#include <thread>
#include <chrono>

#include "ebpf/plugin/cpu_profiling/ProcessDiscoveryManager.h"
#include "ebpf/plugin/cpu_profiling/ProcessEntry.h"
#include "logger/Logger.h"

namespace logtail {
namespace ebpf {

void ProcessDiscoveryManager::Start(NotifyFn fn) {
    if (mRunning) {
        return;
    }
    mRunning = true;
    mCallback = std::move(fn);
    mThreadRes = std::async(std::launch::async,
                            &ProcessDiscoveryManager::run, this);
    LOG_INFO(sLogger, ("ProcessDiscoveryManager", "start"));
}

void ProcessDiscoveryManager::Stop() {
    if (mRunning == false) {
        return;
    }
    if (!mThreadRes.valid()) {
        return;
    }
    mRunning = false;
    mThreadRes.wait();
    mCallback = nullptr;
    LOG_INFO(sLogger, ("ProcessDiscoveryManager", "stop"));
}

void ProcessDiscoveryManager::AddOrUpdateDiscovery(const std::string &configName, UpdateFn updater) {
    std::lock_guard<std::mutex> guard(mLock);
    auto it = mStates.emplace(configName, InnerState{}).first;
    auto &state = it->second;
    auto &config = state.mConfig;
    updater(config);
}

bool ProcessDiscoveryManager::UpdateDiscovery(const std::string &configName, UpdateFn updater) {
    std::lock_guard<std::mutex> guard(mLock);
    auto it = mStates.find(configName);
    if (it == mStates.end()) {
        return false;
    }
    auto &state = it->second;
    auto &config = state.mConfig;
    updater(config);
    return true;
}

void ProcessDiscoveryManager::RemoveDiscovery(const std::string &configName) {
    std::lock_guard<std::mutex> guard(mLock);
    mStates.erase(configName);
}

bool ProcessDiscoveryManager::CheckDiscoveryExist(const std::string &configName) {
    std::lock_guard<std::mutex> guard(mLock);
    return mStates.find(configName) != mStates.end();
}

void ProcessDiscoveryManager::run() {
    while (mRunning) {
        std::vector<ProcessEntry> procs;
        ListAllProcesses(mProcParser, procs);

        DiscoverResult result;

        {
            std::lock_guard<std::mutex> guard(mLock);

            for (auto &[_, state] : mStates) {
                auto& config = state.mConfig;
                std::unordered_set<uint32_t> matchedPids;
                for (const auto& proc : procs) {
                    if (config.IsMatch(proc.mCmdline, proc.mContainerId)) {
                        matchedPids.insert(proc.mPid);
                    }
                }
                Entry entry;
                bool anyUpdate = state.diffAndUpdate(std::move(matchedPids), entry.mPidsToAdd, entry.mPidsToRemove);
                if (!anyUpdate) {
                    continue;
                }
                // TODO: now just mock, need to implement later
                for (auto& pid : entry.mPidsToAdd) {
                    result.mAddPidsToRoot.emplace(pid, "");
                }
                result.mResultsPerConfig.emplace_back(config.mConfigKey, std::move(entry));
            }
        }

        if (!result.mResultsPerConfig.empty()) {
            mCallback(std::move(result));
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

} // namespace ebpf
} // namespace logtail
