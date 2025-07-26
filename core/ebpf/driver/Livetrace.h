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

#include <cstdint>

extern "C" {

void livetrace_enable_system_profiling(void);

void livetrace_disable_symbolizer(void);

struct Profiler;

struct Profiler *livetrace_profiler_create(void);

void livetrace_profiler_destroy(struct Profiler *profiler);

int32_t livetrace_profiler_ctrl(struct Profiler *profiler, int op, const char *pids);

using livetrace_profiler_read_cb_t = void (*)(uint32_t pid, const char *comm,
                                    const char *stack, uint32_t cnt, void *ctx);

void livetrace_profiler_read(struct Profiler *profiler, livetrace_profiler_read_cb_t cb, void *ctx);
}