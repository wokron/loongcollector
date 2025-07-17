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

#include "boost/filesystem.hpp"

#include "ebpf/plugin/cpu_profiling/ProcessWatcher.h"
#include "logger/Logger.h"

namespace logtail {
namespace ebpf {

struct ProcessEntry {
    std::string cmdline;
    uint32_t pid;

    ProcessEntry(std::string cmdline, uint32_t pid)
        : cmdline(std::move(cmdline)), pid(pid) {}
};

void ListAllProcs(std::vector<ProcessEntry> &proc_out) {
    boost::filesystem::path procPath("/proc");
    for (const auto &entry : boost::filesystem::directory_iterator(procPath)) {
        std::string pidStr = entry.path().filename().string();
        assert(!pidStr.empty());
        if (!std::all_of(pidStr.begin(), pidStr.end(), ::isdigit)) {
            continue;
        }
        uint32_t pid = std::stoi(pidStr);
        boost::filesystem::path cmdlinePath = entry.path() / "cmdline";
        std::ifstream cmdlineFile(cmdlinePath.string());
        if (!cmdlineFile.is_open()) {
            continue;
        }

        std::string cmdline;
        std::getline(cmdlineFile, cmdline);
        if (cmdline.empty()) {
            continue;
        }

        // /proc/<pid>/cmdline use '\0' as separator, replace it with space
        std::replace(cmdline.begin(), cmdline.end(), '\0', ' ');

        proc_out.emplace_back(std::move(cmdline), pid);
    }
}

void ProcessWatcher::Start() {
    if (mRunning) {
        return;
    }
    mRunning = true;
    mWatcher = std::async(std::launch::async,
                          &ProcessWatcher::watcherThreadFunc, this);
}

void ProcessWatcher::Stop() {
    mRunning = false;
    Resume();
    if (mWatcher.valid()) {
        mWatcher.wait();
    }

    {
        std::lock_guard<std::mutex> guard(mLock);
        mWatchStates.clear();
    }

    LOG_INFO(sLogger, ("ProcessWatcher", "stop"));
}

void ProcessWatcher::Pause() {
    std::lock_guard<std::mutex> guard(mLock);
    mPaused = true;
    LOG_INFO(sLogger, ("ProcessWatcher", "pause"));
}

void ProcessWatcher::Resume() {
    std::lock_guard<std::mutex> guard(mLock);
    if (mPaused) {
        mPaused = false;
        mCond.notify_one();
        LOG_INFO(sLogger, ("ProcessWatcher", "resume"));
    }
}

void ProcessWatcher::RegisterWatch(const std::string &name,
                                   const ProcessWatchOptions &options) {
    std::lock_guard<std::mutex> guard(mLock);
    auto it = mWatchStates.emplace(name, WatchState()).first;
    it->second.mOptions = options;
}

void ProcessWatcher::RemoveWatch(const std::string &name) {
    std::lock_guard<std::mutex> guard(mLock);
    mWatchStates.erase(name);
}

void ProcessWatcher::watcherThreadFunc() {
    while (mRunning) {
        {
            std::unique_lock<std::mutex> lock(mLock);
            mCond.wait(lock, [&] { return !mPaused; });
            findMatchedProcs();
        }
        // TODO: make it configurable
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

static bool isOrderedSame(const std::vector<uint32_t> &a,
                          const std::vector<uint32_t> &b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

void ProcessWatcher::findMatchedProcs() {
    std::vector<ProcessEntry> procs;
    ListAllProcs(procs);

    for (auto &[_, state] : mWatchStates) {
        auto &options = state.mOptions;
        std::vector<uint32_t> pids;
        for (auto &process : procs) {
            if (isMatch(options, process.cmdline)) {
                pids.push_back(process.pid);
            }
        }
        std::sort(pids.begin(), pids.end());
        if (!isOrderedSame(pids, state.mPrevPids)) {
            state.mPrevPids = pids;
            options.mCallback(std::move(pids));
        }
    }
}

bool ProcessWatcher::isMatch(const ProcessWatchOptions &options,
                             const std::string &cmdline) {
    if (options.mWildcards.empty()) {
        return true;
    }

    for (const auto &wildcard : options.mWildcards) {
        if (mWildcardEngine.IsMatch(wildcard, cmdline)) {
            return true;
        }
    }
    return false;
}

} // namespace ebpf
} // namespace logtail
