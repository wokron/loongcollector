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


#include <mutex>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include <coolbpf/security.skel.h>
#pragma GCC diagnostic pop

#include "ebpf/include/export.h"

extern "C" {
#include <coolbpf/net.h>
#include <coolbpf/security/bpf_process_event_type.h>
#include <coolbpf/security/data_msg.h>
#include <coolbpf/security/msg_type.h>
#include <sys/resource.h>

#include "ebpf/driver/eBPFDriver.h"
}

#include "BPFWrapper.h"
#include "FileFilter.h"
#include "ebpf/driver/CpuProfiler.h"
#include "Log.h"
#include "NetworkFilter.h"
#include "common/magic_enum.hpp"

#ifdef ENABLE_COMPATIBLE_MODE
extern "C" {
#include <string.h>
asm(".symver memcpy, memcpy@GLIBC_2.2.5");
void* __wrap_memcpy(void* dest, const void* src, size_t n) {
    return memcpy(dest, src, n);
}
}
#endif

int set_logger(logtail::ebpf::eBPFLogHandler fn) {
    set_log_handler(fn);
    return 0;
}

int bump_memlock_rlimit(void) {
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (0 != setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        return -1;
    }
    return 0;
}

std::array<std::vector<void*>, size_t(logtail::ebpf::PluginType::MAX)> gPluginPbs;

std::array<std::vector<std::string>, size_t(logtail::ebpf::PluginType::MAX)> gPluginCallNames;

void UpdatePluginPerfBuffers(logtail::ebpf::PluginType type, std::vector<void*> pbs) {
    gPluginPbs[int(type)] = pbs;
}

std::shared_ptr<logtail::ebpf::BPFWrapper<security_bpf>> gWrapper = logtail::ebpf::BPFWrapper<security_bpf>::Create();
std::shared_ptr<logtail::ebpf::CpuProfiler> gCpuProfiler = std::make_shared<logtail::ebpf::CpuProfiler>();

void SetCoolBpfConfig(int32_t opt, int32_t value) {
    int32_t* params[] = {&value};
    int32_t paramsLen[] = {4};
    ebpf_config(opt, 0, 1, (void**)params, paramsLen);
}

void set_networkobserver_cid_filter(const char* container_id, size_t length, uint64_t cid_key, bool update) {
    ebpf_set_cid_filter(container_id, length, cid_key, update);
}

void set_networkobserver_config(int32_t opt, int32_t value) {
    SetCoolBpfConfig(opt, value);
}

int SetupPerfBuffers(logtail::ebpf::PluginConfig* arg) {
    std::vector<logtail::ebpf::PerfBufferSpec> specs;
    switch (arg->mPluginType) {
        case logtail::ebpf::PluginType::FILE_SECURITY: {
            auto* cc = std::get_if<logtail::ebpf::FileSecurityConfig>(&arg->mConfig);
            if (cc) {
                specs = cc->mPerfBufferSpec;
            }
            break;
        }
        case logtail::ebpf::PluginType::PROCESS_SECURITY: {
            auto* cc = std::get_if<logtail::ebpf::ProcessConfig>(&arg->mConfig);
            if (cc) {
                specs = cc->mPerfBufferSpec;
            }
            break;
        }
        case logtail::ebpf::PluginType::NETWORK_SECURITY: {
            auto* cc = std::get_if<logtail::ebpf::NetworkSecurityConfig>(&arg->mConfig);
            if (cc) {
                specs = cc->mPerfBufferSpec;
            }
            break;
        }
        case logtail::ebpf::PluginType::NETWORK_OBSERVE:
        default:
            return kErrDriverInternal;
    }
    auto config = arg->mConfig;
    // create pb and set perf buffer meta
    if (specs.size()) {
        std::vector<logtail::ebpf::PerfBufferOps> perfBuffers;
        std::vector<void*> pbs;
        for (auto& spec : specs) {
            void* pb = gWrapper->CreatePerfBuffer(spec.mName,
                                                  spec.mSize,
                                                  spec.mCtx,
                                                  static_cast<perf_buffer_sample_fn>(spec.mSampleHandler),
                                                  static_cast<perf_buffer_lost_fn>(spec.mLostHandler));
            if (!pb) {
                EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                         "plugin type:%s: create perfbuffer fail, name:%s, size:%ld\n",
                         magic_enum::enum_name(arg->mPluginType).data(),
                         spec.mName.c_str(),
                         spec.mSize);
                return kErrDriverInternal;
            }
            pbs.push_back(pb);
        }
        UpdatePluginPerfBuffers(arg->mPluginType, pbs);
    }
    return 0;
}

void DeletePerfBuffers(logtail::ebpf::PluginType pluginType) {
    std::vector<void*> pbs = gPluginPbs[static_cast<int>(pluginType)];
    gPluginPbs[int(pluginType)] = {};
    EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_INFO,
             "[BPFWrapper][stop_plugin] begin clean perfbuffer for pluginType: %d  \n",
             int(pluginType));
    for (auto* pb : pbs) {
        auto* perfbuffer = static_cast<perf_buffer*>(pb);
        if (perfbuffer) {
            gWrapper->DeletePerfBuffer(perfbuffer);
        }
    }
}

int start_plugin(logtail::ebpf::PluginConfig* arg) {
    // 1. load skeleton
    // 2. start consumer
    // 3. attach prog
    EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG, "enter start_plugin, arg is null: %d \n", arg == nullptr);
    if (0 != bump_memlock_rlimit()) {
        return -1;
    }

    // TODO: The coolbpf_set_loglevel API isn't ideal anyway
    libbpf_set_print(libbpf_printf);
    switch (arg->mPluginType) {
        case logtail::ebpf::PluginType::NETWORK_OBSERVE: {
            auto* config = std::get_if<logtail::ebpf::NetworkObserveConfig>(&arg->mConfig);
            // TODO: unnecessary. should be set anyway beyond pluginType (line:158)
            ebpf_setup_print_func(config->mLogHandler);
            ebpf_setup_net_event_process_func(config->mCtrlHandler, config->mCustomCtx);
            ebpf_setup_net_data_process_func(config->mDataHandler, config->mCustomCtx);
            ebpf_setup_net_statistics_process_func(config->mStatsHandler, config->mCustomCtx);
            ebpf_setup_net_lost_func(config->mLostHandler, config->mCustomCtx);

            int err = ebpf_init(nullptr,
                                0,
                                config->mSo.data(),
                                static_cast<int32_t>(config->mSo.length()),
                                config->mUprobeOffset,
                                config->mUpcaOffset,
                                config->mUppsOffset,
                                config->mUpcrOffset);
            if (err) {
                EBPF_LOG(
                    logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, "network observe: ebpf_init fail ret:%d\n", err);
                return err;
            }
            // config
            SetCoolBpfConfig((int32_t)PROTOCOL_FILTER, 1);
            SetCoolBpfConfig((int32_t)TGID_FILTER, -1);
            SetCoolBpfConfig((int32_t)PORT_FILTER, -1);
            SetCoolBpfConfig((int32_t)SELF_FILTER, getpid());
            SetCoolBpfConfig((int32_t)DATA_SAMPLING, 100);

            // TODO
            if (config->mEnableCidFilter) {
                if (config->mCidOffset <= 0) {
                    EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                             "offset invalid!! skip cid filter... offset %d\n",
                             config->mCidOffset);
                }
                SetCoolBpfConfig((int32_t)CONTAINER_ID_FILTER, config->mCidOffset);
            }
            //
            err = ebpf_start();
            if (err) {
                EBPF_LOG(
                    logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, "network observe: ebpf_start fail ret:%d\n", err);
                return err;
            }
            break;
        }
        case logtail::ebpf::PluginType::FILE_SECURITY: {
            auto* config = std::get_if<logtail::ebpf::FileSecurityConfig>(&arg->mConfig);

            int ret = 0;
            ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG, "begin to set tail call\n");
            // setup tail call
            ret = gWrapper->SetTailCall("secure_tailcall_map", {"filter_prog", "secure_data_send"});
            if (ret) {
                ebpf_log(
                    logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, "file security: SetTailCall fail ret:%d\n", ret);
                return ret;
            }

            // setup pb
            ret = SetupPerfBuffers(arg);
            if (ret) {
                ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                         "file security: setup perfbuffer fail ret:%d\n",
                         ret);
                return ret;
            }

            // update filter config
            std::vector<logtail::ebpf::AttachProgOps> attachProgOps;
            for (const auto& opt : config->mOptions) {
                for (const auto& cn : opt.mCallNames) {
                    attachProgOps.emplace_back("kprobe_" + cn, true);
                    gPluginCallNames[int(arg->mPluginType)].push_back(cn);
                    int ret = logtail::ebpf::CreateFileFilterForCallname(gWrapper, cn, opt.mFilter);
                    if (ret) {
                        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                                 "[start_plugin] Failed to create filter for callname %s\n",
                                 cn.c_str());
                        // filter failed, delete perf buffers
                        DeletePerfBuffers(arg->mPluginType);
                        return kErrDriverInternal;
                    }
                }
            }
            // dynamic instrument
            ret = gWrapper->DynamicAttachBPFObject(attachProgOps);
            if (ret) {
                ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                         "file security: DynamicAttachBPFObject fail\n");
                return kErrDriverInternal;
            }
            ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG,
                     "file security: DynamicAttachBPFObject success\n");
            break;
        }
        case logtail::ebpf::PluginType::NETWORK_SECURITY: {
            auto* config = std::get_if<logtail::ebpf::NetworkSecurityConfig>(&arg->mConfig);

            int ret = 0;
            EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG, "begin to set tail call\n");
            // set tail call
            ret = gWrapper->SetTailCall("secure_tailcall_map", {"filter_prog", "secure_data_send"});
            if (ret != 0) {
                EBPF_LOG(
                    logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, "network security: SetTailCall fail ret:%d\n", ret);
                return ret;
            }

            // setup pb
            ret = SetupPerfBuffers(arg);
            if (ret) {
                EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                         "network security: setup perfbuffer fail ret:%d\n",
                         ret);
                return ret;
            }

            // update filter config
            std::vector<logtail::ebpf::AttachProgOps> attachProgOps;
            for (const auto& opt : config->mOptions) {
                for (const auto& cn : opt.mCallNames) {
                    attachProgOps.emplace_back("kprobe_" + cn, true);
                    gPluginCallNames[int(arg->mPluginType)].push_back(cn);
                    int ret = logtail::ebpf::CreateNetworkFilterForCallname(gWrapper, cn, opt.mFilter);
                    if (ret) {
                        EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                                 "[start_plugin] Failed to create filter for callname %s\n",
                                 cn.c_str());
                        // filter failed, delete perf buffers
                        DeletePerfBuffers(arg->mPluginType);
                        return kErrDriverInternal;
                    }
                }
            }
            // dynamic instrument
            ret = gWrapper->DynamicAttachBPFObject(attachProgOps);
            if (ret) {
                EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                         "network security: DynamicAttachBPFObject fail\n");
                return kErrDriverInternal;
            }
            EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG,
                     "network security: DynamicAttachBPFObject success\n");
            break;
        }
        case logtail::ebpf::PluginType::PROCESS_SECURITY: {
            int err = gWrapper->Init();
            if (err) {
                EBPF_LOG(
                    logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, "process security: ebpf_init fail ret:%d\n", err);
                return err;
            }
            // auto* config = std::get_if<logtail::ebpf::ProcessConfig>(&arg->mConfig);
            std::vector<logtail::ebpf::AttachProgOps> attachOps = {
                logtail::ebpf::AttachProgOps("event_exit_acct_process", true),
                logtail::ebpf::AttachProgOps("event_wake_up_new_task", true),
                logtail::ebpf::AttachProgOps("event_exit_disassociate_ctty", true),
                logtail::ebpf::AttachProgOps("event_execve", true),
                logtail::ebpf::AttachProgOps("execve_rate", false),
                logtail::ebpf::AttachProgOps("execve_send", false),
                logtail::ebpf::AttachProgOps("filter_prog", false),
            };

            int ret = 0;
            std::vector<std::pair<const std::string, const std::vector<std::string>>> tailCalls
                = {{"execve_calls", {"execve_rate", "execve_send"}}};

            // set tail call
            for (auto& tailCall : tailCalls) {
                auto ret = gWrapper->SetTailCall(tailCall.first, tailCall.second);
                if (ret != 0) {
                    EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                             "process security: SetTailCall fail ret:%d\n",
                             ret);
                    return ret;
                }
            }

            // setup pb
            ret = SetupPerfBuffers(arg);
            if (ret) {
                EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                         "process security: setup perfbuffer fail ret:%d\n",
                         ret);
                return ret;
            }

            // attach bpf object
            ret = gWrapper->DynamicAttachBPFObject(attachOps);
            if (ret != 0) {
                EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                         "process security: DynamicAttachBPFObject fail ret:%d\n",
                         ret);
                return kErrDriverInternal;
            }
            EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG,
                     "process security: DynamicAttachBPFObject success\n");
            break;
        }
        case logtail::ebpf::PluginType::CPU_PROFILING: {
            auto* config = std::get_if<logtail::ebpf::CpuProfilingConfig>(&arg->mConfig);
            assert(config != nullptr);

            bool ok;
            ok = gCpuProfiler->UpdatePids(std::unordered_set<uint32_t>(config->mPids.begin(), config->mPids.end()));
            if (!ok) {
                EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                         "cpu profiling: UpdatePids failed\n");
                return kErrDriverInternal;
            }

            if (config->mHandler) {
                gCpuProfiler->RegisterPollHandler(config->mHandler, config->mCtx);
            }

            break;
        }
        default: {
            EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                     "[start plugin] unknown plugin type, please check. \n");
        }
    }
    return 0;
}

int poll_plugin_pbs(logtail::ebpf::PluginType type, int32_t max_events, int32_t* stop_flag, int timeout_ms) {
    if (type == logtail::ebpf::PluginType::NETWORK_OBSERVE) {
        return ebpf_poll_events(max_events, stop_flag, timeout_ms);
    } else if (type == logtail::ebpf::PluginType::CPU_PROFILING) {
        auto r = gCpuProfiler->Poll();
        return r ? 1 : 0;
    }
    // find pbs
    std::vector<void*> pbs = gPluginPbs.at(static_cast<size_t>(type));
    if (pbs.empty()) {
        EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, "no pbs registered for type:%d \n", type);
        return -1;
    }
    int cnt = 0;
    for (auto& x : pbs) {
        if (!x) {
            continue;
        }
        int ret = gWrapper->PollPerfBuffer(x, max_events, timeout_ms);
        if (ret < 0 && errno != EINTR) {
            EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, "poll perf buffer failed ...\n");
        } else {
            cnt += ret;
        }
    }
    return cnt;
}

// deprecated
int resume_plugin(logtail::ebpf::PluginConfig* arg) {
    switch (arg->mPluginType) {
        case logtail::ebpf::PluginType::FILE_SECURITY: {
            auto* config = std::get_if<logtail::ebpf::FileSecurityConfig>(&arg->mConfig);
            int ret = 0;
            // update filter config
            std::vector<logtail::ebpf::AttachProgOps> attachOps;
            for (const auto& opt : config->mOptions) {
                for (const auto& cn : opt.mCallNames) {
                    attachOps.emplace_back("kprobe_" + cn, true);
                    gPluginCallNames[int(arg->mPluginType)].push_back(cn);
                }
            }
            // dynamic instrument
            ret = gWrapper->DynamicAttachBPFObject(attachOps);
            if (ret) {
                ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                         "file security: DynamicAttachBPFObject fail\n");
                return kErrDriverInternal;
            }
            ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG,
                     "file security: DynamicAttachBPFObject success\n");
            break;
        }
        case logtail::ebpf::PluginType::NETWORK_SECURITY: {
            auto* config = std::get_if<logtail::ebpf::NetworkSecurityConfig>(&arg->mConfig);
            int ret = 0;
            // update filter config
            std::vector<logtail::ebpf::AttachProgOps> attachOps;
            for (const auto& opt : config->mOptions) {
                for (const auto& cn : opt.mCallNames) {
                    attachOps.emplace_back("kprobe_" + cn, true);
                    gPluginCallNames[int(arg->mPluginType)].push_back(cn);
                }
            }
            // dynamic instrument
            ret = gWrapper->DynamicAttachBPFObject(attachOps);
            if (ret) {
                EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                         "network security: DynamicAttachBPFObject fail\n");
                return kErrDriverInternal;
            }
            EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG,
                     "network security: DynamicAttachBPFObject success\n");
            break;
        }
        case logtail::ebpf::PluginType::PROCESS_SECURITY: {
            break;
        }
        default: {
            EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                     "[resume plugin] unknown plugin type, please check. \n");
        }
    }
    return 0;
}

// just update config ...
int update_plugin(logtail::ebpf::PluginConfig* arg) {
    auto pluginType = arg->mPluginType;
    if (pluginType == logtail::ebpf::PluginType::NETWORK_OBSERVE
        || pluginType == logtail::ebpf::PluginType::PROCESS_SECURITY) {
        return 0;
    }

    switch (pluginType) {
        case logtail::ebpf::PluginType::NETWORK_SECURITY: {
            auto* config = std::get_if<logtail::ebpf::NetworkSecurityConfig>(&arg->mConfig);
            for (const auto& opt : config->mOptions) {
                for (const auto& cn : opt.mCallNames) {
                    gPluginCallNames[int(arg->mPluginType)].push_back(cn);
                    int ret = logtail::ebpf::DeleteNetworkFilterForCallname(gWrapper, cn);
                    if (ret) {
                        EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                                 "[update plugin] network security delete filter for callname %s failed.\n",
                                 cn.c_str());
                        return kErrDriverInternal;
                    }

                    ret = logtail::ebpf::CreateNetworkFilterForCallname(gWrapper, cn, opt.mFilter);
                    if (ret) {
                        EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                                 "[update plugin] network security: create filter for callname %s falied.\n",
                                 cn.c_str());
                    }
                }
            }

            break;
        }
        case logtail::ebpf::PluginType::FILE_SECURITY: {
            auto* config = std::get_if<logtail::ebpf::FileSecurityConfig>(&arg->mConfig);
            // 1. clean-up filter
            for (const auto& opt : config->mOptions) {
                for (const auto& cn : opt.mCallNames) {
                    int ret = logtail::ebpf::DeleteFileFilterForCallname(gWrapper, cn);
                    if (ret) {
                        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                                 "[update plugin] file security: delete filter for callname %s falied.\n",
                                 cn.c_str());
                    }
                    ret = logtail::ebpf::CreateFileFilterForCallname(gWrapper, cn, opt.mFilter);
                    if (ret) {
                        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                                 "[update plugin] file security: create filter for callname %s falied\n",
                                 cn.c_str());
                    }
                }
            }
            break;
        }
        case logtail::ebpf::PluginType::CPU_PROFILING: {
            auto* config = std::get_if<logtail::ebpf::CpuProfilingConfig>(&arg->mConfig);
            assert(config != nullptr);

            bool ok;
            ok = gCpuProfiler->UpdatePids(std::unordered_set<uint32_t>(config->mPids.begin(), config->mPids.end()));
            if (!ok) {
                EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                         "cpu profiling: UpdatePids failed\n");
                return kErrDriverInternal;
            }

            if (config->mHandler) {
                gCpuProfiler->RegisterPollHandler(config->mHandler, config->mCtx);
            }
            
            break;
        }
        default:
            EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                     "[update plugin] %s plugin type not supported.\n",
                     magic_enum::enum_name(arg->mPluginType).data());
            break;
    }

    return 0;
}

int stop_plugin(logtail::ebpf::PluginType pluginType) {
    if (pluginType >= logtail::ebpf::PluginType::MAX) {
        EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                 "[stop_plugin] invalid plugin type: %d\n",
                 static_cast<int>(pluginType));
        return -1;
    }

    switch (pluginType) {
        case logtail::ebpf::PluginType::NETWORK_OBSERVE:
            return ebpf_stop();
        case logtail::ebpf::PluginType::PROCESS_SECURITY: {
            // 1. dynamic detach
            std::vector<logtail::ebpf::AttachProgOps> attachOps = {
                logtail::ebpf::AttachProgOps("event_exit_acct_process", true),
                logtail::ebpf::AttachProgOps("event_wake_up_new_task", true),
                logtail::ebpf::AttachProgOps("event_exit_disassociate_ctty", true),
                logtail::ebpf::AttachProgOps("event_execve", true),
            };
            int ret = gWrapper->DynamicDetachBPFObject(attachOps);
            if (ret) {
                EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                         "[stop plugin] process security: detach progs failed\n");
            }
            // 2. delete perf buffer
            DeletePerfBuffers(pluginType);
            break;
        }
        case logtail::ebpf::PluginType::NETWORK_SECURITY: {
            // 1. dynamic detach
            auto callNames = gPluginCallNames[int(pluginType)];
            gPluginCallNames[int(pluginType)] = {};
            std::vector<logtail::ebpf::AttachProgOps> detachOps;
            for (const auto& cn : callNames) {
                detachOps.emplace_back("kprobe_" + cn, true);
            }
            int ret = 0;
            ret = gWrapper->DynamicDetachBPFObject(detachOps);
            if (ret) {
                EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                         "[stop plugin] network security: detach progs failed\n");
            }
            // 2. clean-up filter
            for (const auto& cn : callNames) {
                ret = logtail::ebpf::DeleteNetworkFilterForCallname(gWrapper, cn);
                if (ret) {
                    EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                             "[stop plugin] network security: delete filter for callname %s falied\n",
                             cn.c_str());
                }
            }
            // 3. delete perf buffer
            DeletePerfBuffers(pluginType);
            break;
        }
        case logtail::ebpf::PluginType::FILE_SECURITY: {
            // 1. dynamic detach
            auto callNames = gPluginCallNames[int(pluginType)];
            gPluginCallNames[int(pluginType)] = {};
            std::vector<logtail::ebpf::AttachProgOps> detachOps;
            for (const auto& cn : callNames) {
                detachOps.emplace_back("kprobe_" + cn, true);
            }
            int ret = gWrapper->DynamicDetachBPFObject(detachOps);
            if (ret) {
                ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                         "[stop plugin] network security: detach progs failed\n");
            }
            // 2. clean-up filter
            for (const auto& cn : callNames) {
                ret = logtail::ebpf::DeleteFileFilterForCallname(gWrapper, cn);
                if (ret) {
                    ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                             "[stop plugin] file security: delete filter for callname %s falied\n",
                             cn.c_str());
                }
            }

            // 3. delete perf buffer
            DeletePerfBuffers(pluginType);
            break;
        }
        case logtail::ebpf::PluginType::CPU_PROFILING: {
            gCpuProfiler->Stop();
            break;
        }
        default: {
            EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                     "[stop plugin] unknown plugin type, please check. \n");
        }
    }
    return 0;
}

// do prog detach
int suspend_plugin(logtail::ebpf::PluginType pluginType) {
    switch (pluginType) {
        case logtail::ebpf::PluginType::NETWORK_SECURITY: {
            auto callNames = gPluginCallNames[int(pluginType)];
            gPluginCallNames[int(pluginType)] = {};
            std::vector<logtail::ebpf::AttachProgOps> detachOps;
            for (const auto& cn : callNames) {
                detachOps.emplace_back("kprobe_" + cn, true);
            }
            int ret = 0;
            ret = gWrapper->DynamicDetachBPFObject(detachOps);
            if (ret) {
                EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                         "[suspend plugin] network security: detach progs failed\n");
            }
            break;
        }
        case logtail::ebpf::PluginType::FILE_SECURITY: {
            auto callNames = gPluginCallNames[int(pluginType)];
            gPluginCallNames[int(pluginType)] = {};
            std::vector<logtail::ebpf::AttachProgOps> detachOps;
            for (const auto& cn : callNames) {
                detachOps.emplace_back("kprobe_" + cn, true);
            }
            int ret = gWrapper->DynamicDetachBPFObject(detachOps);
            if (ret) {
                ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                         "[suspend plugin] file security: detach progs failed\n");
            }
            break;
        }
        case logtail::ebpf::PluginType::PROCESS_SECURITY: {
            break;
        }
        case logtail::ebpf::PluginType::CPU_PROFILING: {
            auto ok = gCpuProfiler->Suspend();
            if (!ok) {
                EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                         "[suspend plugin] cpu profiling: suspend failed\n");
                return kErrDriverInternal;
            }
            break;
        }
        default: {
            EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                     "[suspend plugin] unknown plugin type, please check. \n");
        }
    }
    return 0;
}

int update_bpf_map_elem(logtail::ebpf::PluginType, const char* map_name, void* key, void* value, uint64_t flag) {
    return gWrapper->UpdateBPFHashMap(std::string(map_name), key, value, flag);
}

int get_plugin_pb_epoll_fds(logtail::ebpf::PluginType type, int* fds, int maxCount) {
    if (fds == nullptr || maxCount == 0) {
        return -1;
    }

    if (static_cast<size_t>(type) >= gPluginPbs.size()) {
        EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, "invalid plugin type: %d\n", int(type));
        return -1;
    }

    std::vector<void*>& pbs = gPluginPbs.at(static_cast<size_t>(type));
    if (pbs.empty()) {
        EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG, "no pbs registered for type:%d \n", int(type));
        return 0;
    }

    int count = 0;
    for (auto& pb : pbs) {
        if (!pb) {
            continue;
        }
        if (count >= maxCount) {
            EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, "too many epoll fds, max_count:%d\n", maxCount);
            break;
        }

        int epollFd = gWrapper->GetPerfBufferEpollFd(pb);
        if (epollFd >= 0) {
            fds[count] = epollFd;
            count++;
        } else {
            EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, "failed to get epoll fd for perf buffer\n");
        }
    }

    return count;
}

int consume_plugin_pb_data(logtail::ebpf::PluginType type) {
    if (static_cast<size_t>(type) >= gPluginPbs.size()) {
        EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, "invalid plugin type: %d\n", int(type));
        return -1;
    }
    std::vector<void*>& pbs = gPluginPbs.at(static_cast<size_t>(type));
    if (pbs.empty()) {
        EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG, "no pbs registered for type:%d \n", int(type));
        return 0;
    }

    int cnt = 0;
    for (auto& pb : pbs) {
        if (!pb) {
            continue;
        }
        int ret = gWrapper->ConsumePerfBuffer(pb);
        if (ret < 0) {
            EBPF_LOG(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, "consume perf buffer data failed ...\n");
        } else {
            cnt += ret;
        }
    }
    return cnt;
}
