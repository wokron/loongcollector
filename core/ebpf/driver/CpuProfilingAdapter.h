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

#include <algorithm>
#include <array>
#include <atomic>
#include <memory>

#include "common/DynamicLibHelper.h"
#include "common/RuntimeUtil.h"
#include "logger/Logger.h"

namespace logtail {
namespace ebpf {

#define LOAD_PROFILING_FUNC_ADDR(funcName)                                     \
    ({                                                                         \
        void *funcPtr = tmp_lib->LoadMethod(#funcName, loadErr);               \
        if (funcPtr == NULL) {                                                 \
            LOG_ERROR(sLogger,                                                 \
                      ("[CpuProfilingAdapter] load profiling method",          \
                       "failed")("method", #funcName)("error", loadErr));      \
        }                                                                      \
        funcPtr;                                                               \
    })

#define REGISTER_PROFILING_FUNC(enumName, funcName)                            \
    mFuncs[static_cast<int>(enumName)] = LOAD_PROFILING_FUNC_ADDR(funcName)

class CpuProfilingAdapter {
public:
    const std::string mProfilerLibName = "profiler";

    using profiler_read_cb_func = void (*)(unsigned int, const char *,
                                           const char *, unsigned int);
    using profiler_read_heatmap_cb_func = void (*)(unsigned long long,
                                                   unsigned int, const char *,
                                                   const char *);
    using profiler_read_bytes_cb_func = void (*)(const unsigned char *,
                                                 unsigned int);
    struct Profiler;

    static std::shared_ptr<CpuProfilingAdapter> Create() {
        return std::make_shared<CpuProfilingAdapter>();
    }

    void Init() {
        if (mInited) {
            return;
        }
        mInited = true;
        mBinaryPath = GetProcessExecutionDir();
    }

    bool EnableSystemProfiling() {
        if (!loadDynamicLib(mProfilerLibName)) {
            LOG_ERROR(sLogger,
                      ("[CpuProfilingAdapter] dynamic lib not loaded", ""));
            return false;
        }
        void *f = mFuncs[static_cast<int>(
            livetrace_funcs::LIVETRACE_ENABLE_SYSTEM_PROFILING)];
        assert(f != nullptr);
        auto func = (enable_system_profiling_func)f;
        func();
        return true;
    }

    bool DisableSymbolizer() {
        if (!loadDynamicLib(mProfilerLibName)) {
            LOG_ERROR(sLogger,
                      ("[CpuProfilingAdapter] dynamic lib not loaded", ""));
            return false;
        }
        void *f = mFuncs[static_cast<int>(
            livetrace_funcs::LIVETRACE_DISABLE_SYMBOLIZER)];
        assert(f != nullptr);
        auto func = (disable_symbolizer_func)f;
        func();
        return true;
    }

    Profiler *CreateProfiler() {
        if (!loadDynamicLib(mProfilerLibName)) {
            LOG_ERROR(sLogger,
                      ("[CpuProfilingAdapter] dynamic lib not loaded", ""));
            return nullptr;
        }
        void *f = mFuncs[static_cast<int>(
            livetrace_funcs::LIVETRACE_PROFILER_CREATE)];
        assert(f != nullptr);
        auto func = (profiler_create_func)f;
        return func();
    }

    bool DestroyProfiler(Profiler *profiler) {
        if (!loadDynamicLib(mProfilerLibName)) {
            LOG_ERROR(sLogger,
                      ("[CpuProfilingAdapter] dynamic lib not loaded", ""));
            return false;
        }
        void *f = mFuncs[static_cast<int>(
            livetrace_funcs::LIVETRACE_PROFILER_DESTROY)];
        assert(f != nullptr);
        auto func = (profiler_destroy_func)f;
        func(profiler);
        return true;
    }

    int32_t ProfilerCtrl(Profiler *profiler, int op, const char *pids) {
        if (!loadDynamicLib(mProfilerLibName)) {
            LOG_ERROR(sLogger,
                      ("[CpuProfilingAdapter] dynamic lib not loaded", ""));
            return -1;
        }
        void *f =
            mFuncs[static_cast<int>(livetrace_funcs::LIVETRACE_PROFILER_CTRL)];
        assert(f != nullptr);
        auto func = (profiler_ctrl_func)f;
        return func(profiler, op, pids);
    }

    bool ProfilerRead(Profiler *profiler, profiler_read_cb_func cb) {
        if (!loadDynamicLib(mProfilerLibName)) {
            LOG_ERROR(sLogger,
                      ("[CpuProfilingAdapter] dynamic lib not loaded", ""));
            return false;
        }
        void *f =
            mFuncs[static_cast<int>(livetrace_funcs::LIVETRACE_PROFILER_READ)];
        assert(f != nullptr);
        auto func = (profiler_read_func)f;
        func(profiler, cb);
        return true;
    }

    bool ProfilerReadHeatmap(Profiler *profiler,
                             profiler_read_heatmap_cb_func cb) {
        if (!loadDynamicLib(mProfilerLibName)) {
            LOG_ERROR(sLogger,
                      ("[CpuProfilingAdapter] dynamic lib not loaded", ""));
            return false;
        }
        void *f = mFuncs[static_cast<int>(
            livetrace_funcs::LIVETRACE_PROFILER_READ_HEATMAP)];
        assert(f != nullptr);
        auto func = (profiler_read_heatmap_func)f;
        func(profiler, cb);
        return true;
    }

    bool ProfilerReadBytes(Profiler *profiler, profiler_read_bytes_cb_func cb) {
        if (!loadDynamicLib(mProfilerLibName)) {
            LOG_ERROR(sLogger,
                      ("[CpuProfilingAdapter] dynamic lib not loaded", ""));
            return false;
        }
        void *f = mFuncs[static_cast<int>(
            livetrace_funcs::LIVETRACE_PROFILER_READ_BYTES)];
        assert(f != nullptr);
        auto func = (profiler_read_bytes_func)f;
        func(profiler, cb);
        return true;
    }

private:
    bool loadDynamicLib(const std::string &libName) {
        if (dynamicLibSuccess()) {
            return true;
        }

        std::unique_ptr<DynamicLibLoader> tmp_lib =
            std::make_unique<DynamicLibLoader>();
        LOG_INFO(sLogger, ("[CpuProfilingAdapter] begin load libprofiler, path",
                           mBinaryPath));
        std::string loadErr;
        if (!tmp_lib->LoadDynLib(libName, loadErr, mBinaryPath)) {
            LOG_ERROR(sLogger, ("failed to load libprofiler, path",
                                mBinaryPath)("error", loadErr));
            return false;
        }

        // register methods
        REGISTER_PROFILING_FUNC(
            livetrace_funcs::LIVETRACE_ENABLE_SYSTEM_PROFILING,
            livetrace_enable_system_profiling);
        REGISTER_PROFILING_FUNC(livetrace_funcs::LIVETRACE_DISABLE_SYMBOLIZER,
                                livetrace_disable_symbolizer);
        REGISTER_PROFILING_FUNC(livetrace_funcs::LIVETRACE_PROFILER_CREATE,
                                livetrace_profiler_create);
        REGISTER_PROFILING_FUNC(livetrace_funcs::LIVETRACE_PROFILER_DESTROY,
                                livetrace_profiler_destroy);
        REGISTER_PROFILING_FUNC(livetrace_funcs::LIVETRACE_PROFILER_CTRL,
                                livetrace_profiler_ctrl);
        REGISTER_PROFILING_FUNC(livetrace_funcs::LIVETRACE_PROFILER_READ,
                                livetrace_profiler_read);
        REGISTER_PROFILING_FUNC(
            livetrace_funcs::LIVETRACE_PROFILER_READ_HEATMAP,
            livetrace_profiler_read_heatmap);
        REGISTER_PROFILING_FUNC(livetrace_funcs::LIVETRACE_PROFILER_READ_BYTES,
                                livetrace_profiler_read_bytes);

        if (std::any_of(mFuncs.begin(), mFuncs.end(),
                        [](auto *x) { return x == nullptr; })) {
            return false;
        }

        mLibProfiler = std::move(tmp_lib);
        return true;
    }

    bool dynamicLibSuccess() { return mLibProfiler != nullptr; }

    // clang-format off
    using enable_system_profiling_func = void (*)(void);
    using disable_symbolizer_func = void (*)(void);
    using profiler_create_func = Profiler* (*)(void);
    using profiler_destroy_func = void (*)(Profiler*);
    using profiler_ctrl_func = int32_t (*)(Profiler*, int op, const char* pids);
    using profiler_read_func = void (*)(Profiler*, profiler_read_cb_func cb);
    using profiler_read_heatmap_func = void (*)(Profiler*, profiler_read_heatmap_cb_func cb);
    using profiler_read_bytes_func = void (*)(Profiler*, profiler_read_bytes_cb_func cb);
    // clang-format on

    enum class livetrace_funcs {
        LIVETRACE_ENABLE_SYSTEM_PROFILING,
        LIVETRACE_DISABLE_SYMBOLIZER,
        LIVETRACE_PROFILER_CREATE,
        LIVETRACE_PROFILER_DESTROY,
        LIVETRACE_PROFILER_CTRL,
        LIVETRACE_PROFILER_READ,
        LIVETRACE_PROFILER_READ_HEATMAP,
        LIVETRACE_PROFILER_READ_BYTES,

        LIVETRACE_FUNC_MAX,
    };

    std::atomic_bool mInited = false;
    std::string mBinaryPath;
    std::unique_ptr<DynamicLibLoader> mLibProfiler = nullptr;
    std::array<void *, (int)livetrace_funcs::LIVETRACE_FUNC_MAX> mFuncs = {};

#ifdef APSARA_UNIT_TEST_MAIN
    friend class CpuProfilingAdapterUnittest;
#endif
};

} // namespace ebpf
} // namespace logtail
