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

#include <atomic>
#include <functional>
#include <future>
#include <string>
#include <vector>
#include <unordered_set>
#include <optional>

#include "app_config/AppConfig.h"
#include "common/LogtailCommonFlags.h"
#include "common/ProcParser.h"
#include "boost/regex.hpp"
#include "ebpf/plugin/cpu_profiling/ProcessEntry.h"

namespace logtail {
namespace ebpf {

struct ProcessDiscoveryConfig {
    size_t mConfigKey;
    std::vector<boost::regex> mRegexs;
    bool mFullDiscovery = false;
};

inline std::optional<std::string> GetContainerHostPath() {
    if (AppConfig::GetInstance()->IsPurageContainerMode()) {
        return STRING_FLAG(default_container_host_path);
    }
    return std::nullopt;
}

class ProcessDiscoveryManager {
public:
    struct Entry {
        std::unordered_set<uint32_t> mPidsToAdd;
        std::unordered_set<uint32_t> mPidsToRemove;
    };
    struct DiscoverResult {
        std::vector<std::pair<size_t, Entry>> mResultsPerConfig;
        std::unordered_map<uint32_t, std::string> mAddPidsToRoot;
    };
    using NotifyFn = std::function<void(DiscoverResult)>;

    ProcessDiscoveryManager()
        : mIsContainerMode(AppConfig::GetInstance()->IsPurageContainerMode()),
          mProcParser(GetContainerHostPath().value_or("/")) {}

    ProcessDiscoveryManager(const ProcessDiscoveryManager &) = delete;
    ProcessDiscoveryManager &operator=(const ProcessDiscoveryManager &) = delete;
    ProcessDiscoveryManager(ProcessDiscoveryManager &&) = delete;
    ProcessDiscoveryManager &operator=(ProcessDiscoveryManager &&) = delete;

    ~ProcessDiscoveryManager() { Stop(); }

    static ProcessDiscoveryManager *GetInstance() {
        static ProcessDiscoveryManager instance;
        return &instance;
    }

    void Start(NotifyFn fn);
    void Stop();

    void AddOrUpdateDiscovery(const std::string &configName, ProcessDiscoveryConfig config);

    void RemoveDiscovery(const std::string &configName);

    bool CheckDiscoveryExist(const std::string &configName);

    bool AddContainerInfo(const std::string &configName, std::vector<std::pair<std::string, std::string>> containerToRoot);

    bool RemoveContainerInfo(const std::string &configName, const std::vector<std::string> &containerIds);

private:
    void run();

    struct InnerState {
        ProcessDiscoveryConfig mConfig;
        std::unordered_set<uint32_t> mPrevPids;
        std::unordered_map<std::string, std::string> mContainerIdToRoot;

        void diffAndUpdate(const std::unordered_map<uint32_t, ProcessEntry*> &matchProcs, DiscoverResult &result);

        bool isMatch(const std::string& cmdline, const std::string& containerId, bool isContainerMode);
    };

    std::atomic_bool mRunning = false;
    std::future<void> mThreadRes;
    std::mutex mLock;
    std::unordered_map<std::string, InnerState> mStates;
    NotifyFn mCallback;

    bool mIsContainerMode;
    ProcParser mProcParser;
};

} // namespace ebpf
} // namespace logtail
