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

#include <gtest/gtest.h>

#include "ebpf/driver/CpuProfilingAdapter.h"
#include "unittest/Unittest.h"

namespace logtail {
namespace ebpf {

class CpuProfilingAdapterUnittest : public ::testing::Test {
public:
    void TestLoadDynamicLibrary();
    void TestCreateProfiler();
    void TestDoProfiling();

protected:
    void SetUp() override {}
    void TearDown() override {}

private:
    std::shared_ptr<CpuProfilingAdapter> CreateAdapter() {
        return CpuProfilingAdapter::Create();
    }

    static pid_t CreateTestProcess() {
        pid_t child = fork();
        if (child == 0) { // Child
            while (true) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            assert(false); // Unreachable
        } else {
            return child;
        }
    }

    static void KillTestProcess(pid_t pid) {
        kill(pid, SIGTERM);
        waitpid(pid, nullptr, 0);
    }

    static void ProfileCallback(unsigned int pid, const char *comm,
                                const char *stack, unsigned int cnt) {}
};

void CpuProfilingAdapterUnittest::TestLoadDynamicLibrary() {
    auto adapter = CreateAdapter();
    adapter->Init();
    EXPECT_TRUE(adapter->loadDynamicLib(adapter->mProfilerLibName));
}

void CpuProfilingAdapterUnittest::TestCreateProfiler() {
    auto adapter = CreateAdapter();
    adapter->Init();
    auto profiler = adapter->CreateProfiler();
    EXPECT_NE(profiler, nullptr);

    EXPECT_TRUE(adapter->DestroyProfiler(profiler));
}

void CpuProfilingAdapterUnittest::TestDoProfiling() {
    auto adapter = CreateAdapter();
    adapter->Init();
    auto profiler = adapter->CreateProfiler();

    auto child_pid = CreateTestProcess();
    EXPECT_NE(child_pid, -1);

    auto child_pid_str = std::to_string(child_pid);

    auto r = adapter->ProfilerCtrl(profiler, 1, child_pid_str.c_str());
    EXPECT_EQ(r, 0);

    EXPECT_TRUE(adapter->ProfilerRead(profiler, ProfileCallback));

    KillTestProcess(child_pid);

    adapter->DestroyProfiler(profiler);
}

UNIT_TEST_CASE(CpuProfilingAdapterUnittest, TestLoadDynamicLibrary);
UNIT_TEST_CASE(CpuProfilingAdapterUnittest, TestCreateProfiler);
UNIT_TEST_CASE(CpuProfilingAdapterUnittest, TestDoProfiling);

} // namespace ebpf
} // namespace logtail

UNIT_TEST_MAIN