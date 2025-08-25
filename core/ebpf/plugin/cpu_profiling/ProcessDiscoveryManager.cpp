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

void ProcessDiscoveryManager::AddOrUpdateDiscovery(const std::string &configName, ProcessDiscoveryConfig config) {
    std::lock_guard<std::mutex> guard(mLock);
    auto it = mStates.emplace(configName, InnerState{}).first;
    auto &state = it->second;
    state.mConfig = std::move(config);
}

void ProcessDiscoveryManager::RemoveDiscovery(const std::string &configName) {
    std::lock_guard<std::mutex> guard(mLock);
    mStates.erase(configName);
}

bool ProcessDiscoveryManager::CheckDiscoveryExist(const std::string &configName) {
    std::lock_guard<std::mutex> guard(mLock);
    return mStates.find(configName) != mStates.end();
}

bool ProcessDiscoveryManager::AddContainerInfo(const std::string &configName,
        std::vector<std::pair<std::string, std::string>> containerToRoot) {
    std::lock_guard<std::mutex> guard(mLock);
    auto it = mStates.find(configName);
    if (it == mStates.end()) {
        return false;
    }
    auto &state = it->second;
    for (auto& [cid, rootPath] : containerToRoot) {
        [[maybe_unused]] auto [it, ok] = state.mContainerIdToRoot.emplace(std::move(cid), std::move(rootPath));
        assert(ok || (!ok && it->second == rootPath)); // rootPath of a container should not change
    }
    return true;
}

bool ProcessDiscoveryManager::RemoveContainerInfo(const std::string &configName, const std::vector<std::string> &containerIds) {
    std::lock_guard<std::mutex> guard(mLock);
    auto it = mStates.find(configName);
    if (it == mStates.end()) {
        return false;
    }
    auto &state = it->second;
    for (auto& cid : containerIds) {
        state.mContainerIdToRoot.erase(cid);
    }
    return true;
}

void ProcessDiscoveryManager::run() {
    while (mRunning) {
        std::vector<ProcessEntry> procs;
        ListAllProcesses(mProcParser, procs);

        DiscoverResult result;

        {
            std::lock_guard<std::mutex> guard(mLock);

            for (auto &[_, state] : mStates) {
                std::unordered_map<uint32_t, ProcessEntry*> matchedPids;
                for (auto& proc : procs) {
                    if (state.isMatch(proc.mCmdline, proc.mContainerId)) {
                        matchedPids.emplace(proc.mPid, &proc);
                    }
                }
                state.diffAndUpdate(matchedPids, result);
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
