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

#include <condition_variable>
#include <future>
#include <mutex>
#include <string>
#include <unordered_map>

#include "ebpf/plugin/cpu_profiling/ProcessWatchOptions.h"

namespace logtail {
namespace ebpf {

class ProcessWatcher {
public:
    ProcessWatcher(const ProcessWatcher &) = delete;
    ProcessWatcher &operator=(const ProcessWatcher &) = delete;

    ProcessWatcher(ProcessWatcher &&) = delete;
    ProcessWatcher &operator=(ProcessWatcher &&) = delete;

    ~ProcessWatcher() { Stop(); }

    static ProcessWatcher *GetInstance() {
        static ProcessWatcher instance;
        return &instance;
    }

    void Start();
    void Stop();

    void Pause();
    void Resume();

    void RegisterWatch(const std::string &name,
                       const ProcessWatchOptions &options);
    void RemoveWatch(const std::string &name);

private:
    ProcessWatcher() = default;

    void watcherThreadFunc();

    void findMatchedProcs();

    std::atomic_bool mRunning = false;
    std::future<void> mWatcher;

    mutable std::mutex mLock;
    mutable std::condition_variable mCond;
    bool mPaused = false;

    struct WatchState {
        ProcessWatchOptions mOptions;
        std::vector<uint32_t> mPrevPids;
    };
    std::unordered_map<std::string, WatchState> mWatchStates;
};

} // namespace ebpf
} // namespace logtail
