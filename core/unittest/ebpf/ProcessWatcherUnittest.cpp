// Copyright 2025 iLogtail Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstdlib>

#include "ebpf/plugin/cpu_profiling/ProcessWatcher.h"
#include "unittest/Unittest.h"

namespace logtail {
namespace ebpf {

class ProcessWatcherUnittest : public testing::Test {
public:
    void TestStartAndStop();
    void TestWatchProcess();
    void TestSuspendAndResume();
};

void ProcessWatcherUnittest::TestStartAndStop() {
    ProcessWatcher::GetInstance()->Start();
    ProcessWatcher::GetInstance()->Stop();
    ProcessWatcher::GetInstance()->Start();
    ProcessWatcher::GetInstance()->Stop();
}

void ProcessWatcherUnittest::TestWatchProcess() {
    ProcessWatcher::GetInstance()->Start();

    std::vector<uint32_t> pids;
    auto callback = [&](std::vector<uint32_t> pids_inner) {
        pids = std::move(pids_inner);
    };

    // watch processes with "sleep" in cmdline
    ProcessWatchOptions options({"sleep"}, callback);
    ProcessWatcher::GetInstance()->RegisterWatch("test_watch", options);
    std::system("sleep 1");
    APSARA_TEST_FALSE(pids.empty());
    pids.clear();

    // remove the watch
    ProcessWatcher::GetInstance()->RemoveWatch("test_watch");
    std::system("sleep 1");
    APSARA_TEST_TRUE(pids.empty());

    // watch all processes
    ProcessWatchOptions allOptions({}, callback);
    ProcessWatcher::GetInstance()->RegisterWatch("test_watch_all", allOptions);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    APSARA_TEST_FALSE(pids.empty());

    ProcessWatcher::GetInstance()->Stop();
}

void ProcessWatcherUnittest::TestSuspendAndResume() {
    ProcessWatcher::GetInstance()->Start();

    std::vector<uint32_t> pids;
    auto callback = [&](std::vector<uint32_t> pids_inner) {
        pids = std::move(pids_inner);
    };

    // watch processes with "sleep" in cmdline
    ProcessWatchOptions options({"sleep"}, callback);
    ProcessWatcher::GetInstance()->RegisterWatch("test_watch_suspend", options);
    std::system("sleep 1");
    APSARA_TEST_FALSE(pids.empty());
    pids.clear();

    // now suspend the watcher
    ProcessWatcher::GetInstance()->Pause();
    std::system("sleep 1");
    // no new processes should be detected
    APSARA_TEST_TRUE(pids.empty());

    // resume the watcher
    ProcessWatcher::GetInstance()->Resume();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    APSARA_TEST_FALSE(pids.empty());
    pids.clear();

    ProcessWatcher::GetInstance()->Stop();
}

UNIT_TEST_CASE(ProcessWatcherUnittest, TestStartAndStop);
UNIT_TEST_CASE(ProcessWatcherUnittest, TestWatchProcess);
UNIT_TEST_CASE(ProcessWatcherUnittest, TestSuspendAndResume);

} // namespace ebpf
} // namespace logtail

UNIT_TEST_MAIN