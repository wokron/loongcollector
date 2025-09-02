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

#include <sys/eventfd.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <shared_mutex>
#include <thread>
#include <vector>

#include "app_config/AppConfig.h"
#include "collection_pipeline/CollectionPipelineContext.h"
#include "common/FileSystemUtil.h"
#include "common/JsonUtil.h"
#include "common/TimeKeeper.h"
#include "common/http/AsynCurlRunner.h"
#include "ebpf/Config.h"
#include "ebpf/EBPFServer.h"
#include "ebpf/include/export.h"
#include "logger/Logger.h"
#include "plugin/input/InputFileSecurity.h"
#include "plugin/input/InputNetworkObserver.h"
#include "plugin/input/InputNetworkSecurity.h"
#include "plugin/input/InputProcessSecurity.h"
#include "plugin/input/InputCpuProfiling.h"
#include "unittest/Unittest.h"

DECLARE_FLAG_BOOL(logtail_mode);

namespace logtail {
namespace ebpf {
class eBPFServerUnittest : public testing::Test {
public:
    eBPFServerUnittest() {}
    ~eBPFServerUnittest() {}

    // for start and stop single
    void TestNetworkObserver();
    void TestProcessSecurity();
    void TestNetworkSecurity();
    void TestFileSecurity();
    void TestCpuProfiling();

    // for start and stop all ...
    void TestAllStartAndStop();

    // for update scenario ...
    void TestUpdateFileSecurity();
    void TestUpdateNetworkSecurity();
    void TestUpdateCpuProfiling();

    void TestLoadEbpfParametersV1();
    void TestLoadEbpfParametersV2();

    void TestDefaultAndLoadEbpfParameters();

    void TestDefaultEbpfParameters();

    void TestEbpfParameters();

    void TestEnvManager();

    void TestUnifiedEpoll();

    void TestRetryCache();

    template <typename T>
    void setJSON(Json::Value& v, const std::string& key, const T& value) {
        v[key] = value;
    }

    void writeLogtailConfigJSON(const Json::Value& v) {
        LOG_INFO(sLogger, ("writeLogtailConfigJSON", v.toStyledString()));
        if (BOOL_FLAG(logtail_mode)) {
            OverwriteFile(STRING_FLAG(ilogtail_config), v.toStyledString());
        } else {
            CreateAgentDir();
            std::string conf = GetAgentConfDir() + "/instance_config/local/loongcollector_config.json";
            AppConfig::GetInstance()->LoadAppConfig(conf);
            OverwriteFile(conf, v.toStyledString());
        }
    }

protected:
    void SetUp() override {
        mConfig = std::make_shared<eBPFAdminConfig>();
        mConfig->mReceiveEventChanCap = 4096;
        mConfig->mAdminConfig.mDebugMode = false;
        mConfig->mAdminConfig.mLogLevel = "warn";
        mConfig->mAdminConfig.mPushAllSpan = false;
        mConfig->mAggregationConfig.mAggWindowSecond = 15;
        mConfig->mConverageConfig.mStrategy = "combine";
        mConfig->mSampleConfig.mStrategy = "fixedRate";
        mConfig->mSampleConfig.mConfig.mRate = 0.01;
        mConfig->mSocketProbeConfig.mSlowRequestThresholdMs = 500;
        mConfig->mSocketProbeConfig.mMaxConnTrackers = 10000;
        mConfig->mSocketProbeConfig.mMaxBandWidthMbPerSec = 30;
        mConfig->mSocketProbeConfig.mMaxRawRecordPerSec = 100000;
        mConfig->mProfileProbeConfig.mProfileSampleRate = 10;
        mConfig->mProfileProbeConfig.mProfileUploadDuration = 10;
        mConfig->mProcessProbeConfig.mEnableOOMDetect = false;
        ebpf::EBPFServer::GetInstance()->Init();
    }

    void TearDown() override {
        mConfig.reset();
        EBPFServer::GetInstance()->Stop();
        AsynCurlRunner::GetInstance()->Stop();
    }

    std::shared_ptr<eBPFAdminConfig> mConfig;
    //     CollectionPipeline p;
    CollectionPipelineContext ctx;
    //     SecurityOptions security_opts;
};

void eBPFServerUnittest::TestNetworkObserver() {
    std::string configStr = R"(
        {
            "Type": "input_network_observer",
            "ProbeConfig": 
            {
                "EnableLog": true,
                "EnableMetric": true,
                "EnableSpan": false,
                "EnableProtocols": [
                    "http"
                ],
                "DisableProtocolParse": false,
                "DisableConnStats": false,
                "EnableConnTrackerDump": false,
                "EnableEvent": true,
            }
        }
    )";
    std::string errorMsg;
    Json::Value configJson, optionalGoPipeline;
    APSARA_TEST_TRUE(ParseJsonTable(configStr, configJson, errorMsg));

    logtail::ebpf::ObserverNetworkOption network_option;
    bool res = ebpf::InitObserverNetworkOption(configJson, network_option, &ctx, "test");
    EXPECT_TRUE(res);
    // observer_options.Init(ObserverType::NETWORK, configJson, &ctx, "test");
    std::shared_ptr<InputNetworkObserver> input(new InputNetworkObserver());
    input->SetContext(ctx);
    input->CreateMetricsRecordRef("test", "1");
    auto initStatus = input->Init(configJson, optionalGoPipeline);
    input->CommitMetricsRecordRef();
    EXPECT_TRUE(initStatus);
    EXPECT_TRUE(ebpf::EBPFServer::GetInstance()->mEnvMgr.AbleToLoadDyLib());
    EXPECT_TRUE(ebpf::EBPFServer::GetInstance()->mEBPFAdapter != nullptr);
    res = ebpf::EBPFServer::GetInstance()->EnablePlugin(
        "test", 1, logtail::ebpf::PluginType::NETWORK_OBSERVE, &ctx, &network_option, input->mPluginMetricPtr);
    EXPECT_TRUE(res);

    std::this_thread::sleep_for(std::chrono::seconds(1));
}

void eBPFServerUnittest::TestNetworkSecurity() {
    std::string configStr = R"(
        {
            "Type": "input_network_security",
            "ProbeConfig":
            {
                "AddrFilter": {
                    "DestAddrList": ["10.0.0.0/8","192.168.0.0/16"],
                    "DestPortList": [80],
                    "SourceAddrBlackList": ["127.0.0.1/8"],
                    "SourcePortBlackList": [9300]
                }
            }
        }
    )";
    std::shared_ptr<InputNetworkSecurity> input(new InputNetworkSecurity());
    input->SetContext(ctx);
    input->CreateMetricsRecordRef("test", "1");
    input->CommitMetricsRecordRef();

    std::string errorMsg;
    Json::Value configJson, optionalGoPipeline;
    ;
    APSARA_TEST_TRUE(ParseJsonTable(configStr, configJson, errorMsg));

    input->SetContext(ctx);
    input->CreateMetricsRecordRef("test", "1");
    auto initStatus = input->Init(configJson, optionalGoPipeline);
    input->CommitMetricsRecordRef();
    APSARA_TEST_TRUE(initStatus);

    ctx.SetConfigName("test-1");
    auto res = input->Start();
    EXPECT_TRUE(res);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    res = input->Stop(true);
    EXPECT_TRUE(res);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    input->Start();
    EXPECT_TRUE(res);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    res = input->Stop(true);
    EXPECT_TRUE(res);
}

void eBPFServerUnittest::TestFileSecurity() {
    std::string configStr = R"(
        {
            "Type": "input_file_security",
            "ProbeConfig":
            {
                "FilePathFilter": [
                    "/etc/passwd",
                    "/etc/shadow",
                    "/bin"
                ]
            }
        }
    )";

    std::shared_ptr<InputFileSecurity> input(new InputFileSecurity());

    std::string errorMsg;
    Json::Value configJson;
    Json::Value optionalGoPipeline;

    APSARA_TEST_TRUE(ParseJsonTable(configStr, configJson, errorMsg));

    input->SetContext(ctx);
    input->CreateMetricsRecordRef("test", "1");
    auto initStatus = input->Init(configJson, optionalGoPipeline);
    input->CommitMetricsRecordRef();
    APSARA_TEST_TRUE(initStatus);

    ctx.SetConfigName("test-1");
    auto res = input->Start();
    EXPECT_TRUE(res);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    // stop
    res = input->Stop(true);
    EXPECT_TRUE(res);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // re-run...
    input->Start();
    EXPECT_TRUE(res);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    res = input->Stop(true);
    EXPECT_TRUE(res);
}

void eBPFServerUnittest::TestProcessSecurity() {
    std::string configStr = R"(
        {
            "Type": "input_process_security"
        }
    )";
    std::string errorMsg;
    Json::Value configJson, optionalGoPipeline;
    APSARA_TEST_TRUE(ParseJsonTable(configStr, configJson, errorMsg));
    SecurityOptions security_options;
    security_options.Init(SecurityProbeType::PROCESS, configJson, &ctx, "test");
    std::shared_ptr<InputProcessSecurity> input(new InputProcessSecurity());
    input->SetContext(ctx);
    input->CreateMetricsRecordRef("test", "1");
    auto initStatus = input->Init(configJson, optionalGoPipeline);
    input->CommitMetricsRecordRef();
    APSARA_TEST_TRUE(initStatus);

    ctx.SetConfigName("test-1");
    auto res = input->Start();
    EXPECT_TRUE(res);

    APSARA_TEST_TRUE(ebpf::EBPFServer::GetInstance()->mEnvMgr.AbleToLoadDyLib());
    APSARA_TEST_TRUE(ebpf::EBPFServer::GetInstance()->mEBPFAdapter != nullptr);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    res = input->Stop(true);
    EXPECT_TRUE(res);

    // std::this_thread::sleep_for(std::chrono::seconds(5));
    // input->Start();
    // EXPECT_TRUE(res);
    // std::this_thread::sleep_for(std::chrono::seconds(10));
    // res = input->Stop(true);
    EXPECT_TRUE(res);
}

void eBPFServerUnittest::TestCpuProfiling() {
    std::string configStr = R"(
        {
            "Type": "input_cpu_profiling"
        }
    )";
    std::string errorMsg;
    Json::Value configJson, optionalGoPipeline;
    APSARA_TEST_TRUE(ParseJsonTable(configStr, configJson, errorMsg));
    CpuProfilingOption profiling_option;
    profiling_option.Init(configJson, &ctx, "test");
    auto input = std::make_shared<InputCpuProfiling>();
    input->SetContext(ctx);
    input->CreateMetricsRecordRef("test", "1");
    auto initStatus = input->Init(configJson, optionalGoPipeline);
    input->CommitMetricsRecordRef();
    APSARA_TEST_TRUE(initStatus);

    ctx.SetConfigName("test-1");
    auto res = input->Start();
    EXPECT_TRUE(res);

    APSARA_TEST_TRUE(ebpf::EBPFServer::GetInstance()->mEnvMgr.AbleToLoadDyLib());
    APSARA_TEST_TRUE(ebpf::EBPFServer::GetInstance()->mEBPFAdapter != nullptr);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    res = input->Stop(true);
    EXPECT_TRUE(res);
}

void eBPFServerUnittest::TestUpdateFileSecurity() {
    std::string configStr = R"(
        {
            "Type": "input_file_security",
            "ProbeConfig":
            {
                "FilePathFilter": [
                    "/etc/passwd",
                    "/etc/shadow",
                    "/bin"
                ]
            }
        }
    )";

    ctx.SetConfigName("test-pipeline-1");
    std::shared_ptr<InputFileSecurity> input(new InputFileSecurity());
    input->SetContext(ctx);
    input->CreateMetricsRecordRef("test", "1");
    input->CommitMetricsRecordRef();

    std::string errorMsg;
    Json::Value configJson;
    Json::Value optionalGoPipeline;

    APSARA_TEST_TRUE(ParseJsonTable(configStr, configJson, errorMsg));
    auto res = input->Init(configJson, optionalGoPipeline);
    LOG_INFO(sLogger, ("test start 1", "FILE_SECURITY"));
    res = input->Start();
    EXPECT_TRUE(res);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    // suspend
    LOG_INFO(sLogger, ("test suspend", "FILE_SECURITY"));
    res = input->Stop(false);
    EXPECT_TRUE(res);

    // resume ...
    input = std::make_shared<InputFileSecurity>();
    configStr = R"(
        {
            "Type": "input_file_security",
            "ProbeConfig":
            {
                "FilePathFilter": [
                    "/lib"
                ]
            }
        }
    )";
    input->SetContext(ctx);
    input->CreateMetricsRecordRef("test", "2");
    APSARA_TEST_TRUE(ParseJsonTable(configStr, configJson, errorMsg));
    res = input->Init(configJson, optionalGoPipeline);
    input->CommitMetricsRecordRef();
    EXPECT_TRUE(res);
    LOG_INFO(sLogger, ("test update", "FILE_SECURITY"));
    res = input->Start();
    EXPECT_TRUE(res);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    LOG_INFO(sLogger, ("test real stop", "FILE_SECURITY"));

    res = input->Stop(true);
    EXPECT_TRUE(res);

    {
        LOG_INFO(sLogger, ("test restart", "FILE_SECURITY"));
        std::string configStr = R"(
            {
                "Type": "input_file_security",
                "ProbeConfig":
                {
                    "FilePathFilter": [
                        "/etc/passwd",
                        "/etc/shadow",
                        "/bin"
                    ]
                }
            }
        )";

        std::shared_ptr<InputFileSecurity> input(new InputFileSecurity());

        std::string errorMsg;
        Json::Value configJson;
        Json::Value optionalGoPipeline;

        APSARA_TEST_TRUE(ParseJsonTable(configStr, configJson, errorMsg));

        input->SetContext(ctx);
        input->CreateMetricsRecordRef("test", "1");
        auto initStatus = input->Init(configJson, optionalGoPipeline);
        input->CommitMetricsRecordRef();
        APSARA_TEST_TRUE(initStatus);

        ctx.SetConfigName("test-1");
        auto res = input->Start();
        EXPECT_TRUE(res);

        std::this_thread::sleep_for(std::chrono::seconds(1));

        // stop
        res = input->Stop(true);
        EXPECT_TRUE(res);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void eBPFServerUnittest::TestUpdateNetworkSecurity() {
    std::string configStr = R"(
        {
            "Type": "input_network_security",
            "ProbeConfig":
            {
                "AddrFilter": {
                    "DestAddrList": ["10.0.0.0/8"],
                    "DestPortList": [80],
                    "SourceAddrBlackList": ["127.0.0.1/8"],
                    "SourcePortBlackList": [9300]
                }
            }
        }
    )";
    std::shared_ptr<InputNetworkSecurity> input(new InputNetworkSecurity());
    ctx.SetConfigName("test-file-pipeline");
    input->SetContext(ctx);
    input->CreateMetricsRecordRef("test", "1");
    input->CommitMetricsRecordRef();

    std::string errorMsg;
    Json::Value configJson, optionalGoPipeline;
    ;
    APSARA_TEST_TRUE(ParseJsonTable(configStr, configJson, errorMsg));

    input->SetContext(ctx);
    input->CreateMetricsRecordRef("test", "1");
    auto initStatus = input->Init(configJson, optionalGoPipeline);
    input->CommitMetricsRecordRef();
    APSARA_TEST_TRUE(initStatus);

    ctx.SetConfigName("test-1");
    auto res = input->Start();
    EXPECT_TRUE(res);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    // suspend
    res = input->Stop(false);
    EXPECT_TRUE(res);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // update & resume
    input = std::make_shared<InputNetworkSecurity>();
    configStr = R"(
        {
            "Type": "input_network_security",
            "ProbeConfig":
            {
                "AddrFilter": {
                    "DestAddrList": ["192.168.0.0/16"],
                    "DestPortList": [80],
                    "SourceAddrBlackList": ["127.0.0.1/8"],
                    "SourcePortBlackList": [9300]
                }
            }
        }
    )";
    input->SetContext(ctx);
    input->CreateMetricsRecordRef("test", "2");
    APSARA_TEST_TRUE(ParseJsonTable(configStr, configJson, errorMsg));
    res = input->Init(configJson, optionalGoPipeline);
    input->CommitMetricsRecordRef();
    EXPECT_TRUE(res);
    res = input->Start();
    EXPECT_TRUE(res);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    res = input->Stop(true);
    EXPECT_TRUE(res);
}


void eBPFServerUnittest::TestUpdateCpuProfiling() {
    std::string configStr = R"(
        {
            "Type": "input_cpu_profiling"
        }
    )";
    auto input = std::make_shared<InputCpuProfiling>();
    ctx.SetConfigName("test-profiling-pipeline");
    input->SetContext(ctx);
    input->CreateMetricsRecordRef("test", "1");
    input->CommitMetricsRecordRef();

    std::string errorMsg;
    Json::Value configJson, optionalGoPipeline;
    APSARA_TEST_TRUE(ParseJsonTable(configStr, configJson, errorMsg));

    input->SetContext(ctx);
    input->CreateMetricsRecordRef("test", "1");
    auto initStatus = input->Init(configJson, optionalGoPipeline);
    input->CommitMetricsRecordRef();
    APSARA_TEST_TRUE(initStatus);

    ctx.SetConfigName("test-1");
    auto res = input->Start();
    EXPECT_TRUE(res);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    // suspend
    res = input->Stop(false);
    EXPECT_TRUE(res);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // update & resume
    input = std::make_shared<InputCpuProfiling>();
    configStr = R"(
        {
            "Type": "input_cpu_profiling",
            "CommandLines": ["java.*"]
        }
    )";
    input->SetContext(ctx);
    input->CreateMetricsRecordRef("test", "2");
    APSARA_TEST_TRUE(ParseJsonTable(configStr, configJson, errorMsg));
    res = input->Init(configJson, optionalGoPipeline);
    input->CommitMetricsRecordRef();
    EXPECT_TRUE(res);
    res = input->Start();
    EXPECT_TRUE(res);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    res = input->Stop(true);
    EXPECT_TRUE(res);
}

void eBPFServerUnittest::TestLoadEbpfParametersV1() {
    Json::Value value;
    std::string configStr, errorMsg;
    // valid optional param, include all appconfig params
    configStr = R"(
        {
            "ebpf": {
                "receive_event_chan_cap": 1024,
                "admin_config": {
                    "debug_mode": true,
                    "log_level": "error",
                    "push_all_span": true
                },
                "aggregation_config": {
                    "agg_window_second": 8
                },
                "converage_config": {
                    "strategy": "combine1"
                },
                "sample_config": {
                    "strategy": "fixedRate1",
                    "config": {
                        "rate": 0.001
                    }
                },
                "socket_probe_config": {
                    "slow_request_threshold_ms": 5000,
                    "max_conn_trackers": 100000,
                    "max_band_width_mb_per_sec": 300,
                    "max_raw_record_per_sec": 1000000
                },
                "profile_probe_config": {
                    "profile_sample_rate": 100,
                    "profile_upload_duration": 100
                },
                "process_probe_config": {
                    "enable_oom_detect": true
                }
            }
        }
    )";
    APSARA_TEST_TRUE(ParseJsonTable(configStr, value, errorMsg));
    value["logtail_sys_conf_dir"] = GetProcessExecutionDir();
    writeLogtailConfigJSON(value);

    AppConfig* app_config = AppConfig::GetInstance();
    app_config->LoadAppConfig(STRING_FLAG(ilogtail_config));
    auto configjson = app_config->GetConfig();
    mConfig->LoadEbpfConfig(configjson);
    APSARA_TEST_EQUAL(mConfig->GetReceiveEventChanCap(), 1024);
    APSARA_TEST_EQUAL(mConfig->GetAdminConfig().mDebugMode, true);
    APSARA_TEST_EQUAL(mConfig->GetAdminConfig().mLogLevel, "error");
    APSARA_TEST_EQUAL(mConfig->GetAdminConfig().mPushAllSpan, true);
    APSARA_TEST_EQUAL(mConfig->GetAggregationConfig().mAggWindowSecond, 8);
    APSARA_TEST_EQUAL(mConfig->GetConverageConfig().mStrategy, "combine1");
    APSARA_TEST_EQUAL(mConfig->GetSampleConfig().mStrategy, "fixedRate1");
    APSARA_TEST_EQUAL(mConfig->GetSampleConfig().mConfig.mRate, 0.001);
    APSARA_TEST_EQUAL(mConfig->GetSocketProbeConfig().mSlowRequestThresholdMs, 5000);
    APSARA_TEST_EQUAL(mConfig->GetSocketProbeConfig().mMaxConnTrackers, 100000);
    APSARA_TEST_EQUAL(mConfig->GetSocketProbeConfig().mMaxBandWidthMbPerSec, 300);
    APSARA_TEST_EQUAL(mConfig->GetSocketProbeConfig().mMaxRawRecordPerSec, 1000000);
    APSARA_TEST_EQUAL(mConfig->GetProfileProbeConfig().mProfileSampleRate, 100);
    APSARA_TEST_EQUAL(mConfig->GetProfileProbeConfig().mProfileUploadDuration, 100);
    APSARA_TEST_EQUAL(mConfig->GetProcessProbeConfig().mEnableOOMDetect, true);
}

void eBPFServerUnittest::TestDefaultAndLoadEbpfParameters() {
    Json::Value value;
    std::string configStr, errorMsg;
    // valid optional param
    configStr = R"(
        {
            "ebpf": {
                "receive_event_chan_cap": 1024,
                "sample_config": {
                    "strategy": "fixedRate1",
                    "config": {
                        "rate": 0.001
                    }
                },
                "socket_probe_config": {
                    "slow_request_threshold_ms": 5000,
                    "max_conn_trackers": 100000,
                    "max_band_width_mb_per_sec": 300,
                    "max_raw_record_per_sec": 1000000
                },
                "profile_probe_config": {
                    "profile_sample_rate": 100,
                    "profile_upload_duration": 100
                },
                "process_probe_config": {
                    "enable_oom_detect": true
                }
            }
        }
    )";
    APSARA_TEST_TRUE(ParseJsonTable(configStr, value, errorMsg));
    value["logtail_sys_conf_dir"] = GetProcessExecutionDir();
    writeLogtailConfigJSON(value);

    AppConfig* app_config = AppConfig::GetInstance();
    app_config->LoadAppConfig(STRING_FLAG(ilogtail_config));
    auto configjson = app_config->GetConfig();
    mConfig->LoadEbpfConfig(configjson);
    APSARA_TEST_EQUAL(mConfig->GetReceiveEventChanCap(), 1024);
    APSARA_TEST_EQUAL(mConfig->GetAdminConfig().mDebugMode, false);
    APSARA_TEST_EQUAL(mConfig->GetAdminConfig().mLogLevel, "warn");
    APSARA_TEST_EQUAL(mConfig->GetAdminConfig().mPushAllSpan, false);
    APSARA_TEST_EQUAL(mConfig->GetAggregationConfig().mAggWindowSecond, 15);
    APSARA_TEST_EQUAL(mConfig->GetConverageConfig().mStrategy, "combine");
    APSARA_TEST_EQUAL(mConfig->GetSampleConfig().mStrategy, "fixedRate1");
    APSARA_TEST_EQUAL(mConfig->GetSampleConfig().mConfig.mRate, 0.001);
    APSARA_TEST_EQUAL(mConfig->GetSocketProbeConfig().mSlowRequestThresholdMs, 5000);
    APSARA_TEST_EQUAL(mConfig->GetSocketProbeConfig().mMaxConnTrackers, 100000);
    APSARA_TEST_EQUAL(mConfig->GetSocketProbeConfig().mMaxBandWidthMbPerSec, 300);
    APSARA_TEST_EQUAL(mConfig->GetSocketProbeConfig().mMaxRawRecordPerSec, 1000000);
    APSARA_TEST_EQUAL(mConfig->GetProfileProbeConfig().mProfileSampleRate, 100);
    APSARA_TEST_EQUAL(mConfig->GetProfileProbeConfig().mProfileUploadDuration, 100);
    APSARA_TEST_EQUAL(mConfig->GetProcessProbeConfig().mEnableOOMDetect, true);
}

void eBPFServerUnittest::TestDefaultEbpfParameters() {
    Json::Value value;
    value["logtail_sys_conf_dir"] = GetProcessExecutionDir();
    writeLogtailConfigJSON(value);
    AppConfig* app_config = AppConfig::GetInstance();
    app_config->LoadAppConfig(STRING_FLAG(ilogtail_config));
    auto configjson = app_config->GetConfig();
    mConfig->LoadEbpfConfig(configjson);

    APSARA_TEST_EQUAL(mConfig->GetReceiveEventChanCap(), 4096);
    APSARA_TEST_EQUAL(mConfig->GetAdminConfig().mDebugMode, false);
    APSARA_TEST_EQUAL(mConfig->GetAdminConfig().mLogLevel, "warn");
    APSARA_TEST_EQUAL(mConfig->GetAdminConfig().mPushAllSpan, false);
    APSARA_TEST_EQUAL(mConfig->GetAggregationConfig().mAggWindowSecond, 15);
    APSARA_TEST_EQUAL(mConfig->GetConverageConfig().mStrategy, "combine");
    APSARA_TEST_EQUAL(mConfig->GetSampleConfig().mStrategy, "fixedRate");
    APSARA_TEST_EQUAL(mConfig->GetSampleConfig().mConfig.mRate, 0.01);
    APSARA_TEST_EQUAL(mConfig->GetSocketProbeConfig().mSlowRequestThresholdMs, 500);
    APSARA_TEST_EQUAL(mConfig->GetSocketProbeConfig().mMaxConnTrackers, 10000);
    APSARA_TEST_EQUAL(mConfig->GetSocketProbeConfig().mMaxBandWidthMbPerSec, 30);
    APSARA_TEST_EQUAL(mConfig->GetSocketProbeConfig().mMaxRawRecordPerSec, 100000);
    APSARA_TEST_EQUAL(mConfig->GetProfileProbeConfig().mProfileSampleRate, 10);
    APSARA_TEST_EQUAL(mConfig->GetProfileProbeConfig().mProfileUploadDuration, 10);
    APSARA_TEST_EQUAL(mConfig->GetProcessProbeConfig().mEnableOOMDetect, false);
}

void eBPFServerUnittest::TestLoadEbpfParametersV2() {
    Json::Value value;
    setJSON(value, "ebpf_receive_event_chan_cap", 4096);
    setJSON(value, "ebpf_admin_config_debug_mode", false);

    writeLogtailConfigJSON(value);
    TestEbpfParameters();
}

void eBPFServerUnittest::TestEbpfParameters() {
    AppConfig* appConfig = AppConfig::GetInstance();
    appConfig->LoadAppConfig(STRING_FLAG(ilogtail_config));

    APSARA_TEST_EQUAL(mConfig->GetReceiveEventChanCap(), 4096);
    APSARA_TEST_EQUAL(mConfig->GetAdminConfig().mDebugMode, false);
}

void eBPFServerUnittest::TestUnifiedEpoll() {
    auto* server = ebpf::EBPFServer::GetInstance();
    server->Init();
    APSARA_TEST_GE(server->mUnifiedEpollFd, 0);

    std::string configStr = R"(
        {
            "Type": "input_file_security",
            "ProbeConfig":
            {
                "FilePathFilter": [
                    "/tmp/test"
                ]
            }
        }
    )";
    ctx.SetConfigName("test-unified-epoll-file");
    std::shared_ptr<InputFileSecurity> inputFile(new InputFileSecurity());
    inputFile->SetContext(ctx);
    inputFile->CreateMetricsRecordRef("test_file", "1");

    std::string errorMsg;
    Json::Value configJson;
    Json::Value optionalGoPipeline;
    APSARA_TEST_TRUE(ParseJsonTable(configStr, configJson, errorMsg));
    auto initStatus = inputFile->Init(configJson, optionalGoPipeline);
    inputFile->CommitMetricsRecordRef();
    APSARA_TEST_TRUE(initStatus);

    // Test plugin init and epoll registration
    auto res = inputFile->Start();
    APSARA_TEST_TRUE(res);

    // Create test eventfds to simulate perf buffer file descriptors
    std::vector<int> testFds;
    for (int i = 0; i < 3; ++i) {
        int efd = eventfd(0, EFD_NONBLOCK);
        APSARA_TEST_GE(efd, 0);
        testFds.push_back(efd);
    }

    // Manually register the test fds to epoll (simulating plugin registration)
    auto pluginType = ebpf::PluginType::FILE_SECURITY;
    for (int testFd : testFds) {
        struct epoll_event event {};
        event.events = EPOLLIN;
        event.data.u32 = static_cast<uint32_t>(pluginType);

        int ret = epoll_ctl(server->mUnifiedEpollFd, EPOLL_CTL_ADD, testFd, &event);
        APSARA_TEST_EQUAL(ret, 0);
    }

    // Test multi-threaded access to epoll structures
    std::vector<std::thread> threads;
    std::atomic<bool> keepRunning{true};

    // Thread 1: Simulate epoll event handling
    threads.emplace_back([&]() {
        while (keepRunning) {
            server->handleEpollEvents();
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    });

    // Thread 2: Write to eventfds to trigger epoll events
    threads.emplace_back([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        for (int i = 0; i < 5 && keepRunning; ++i) {
            for (int testFd : testFds) {
                uint64_t value = 1;
                ssize_t written = write(testFd, &value, sizeof(value));
                (void)written;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    });

    // test epoll registration when epoll handle
    configStr = R"(
        {
            "Type": "input_process_security"
        }
    )";
    ctx.SetConfigName("test-unified-epoll-process");
    std::shared_ptr<InputProcessSecurity> inputProcess(new InputProcessSecurity());
    inputProcess->SetContext(ctx);
    inputProcess->CreateMetricsRecordRef("test_process", "2");

    APSARA_TEST_TRUE(ParseJsonTable(configStr, configJson, errorMsg));
    initStatus = inputProcess->Init(configJson, optionalGoPipeline);
    inputProcess->CommitMetricsRecordRef();
    APSARA_TEST_TRUE(initStatus);

    res = inputProcess->Start();
    APSARA_TEST_TRUE(res);

    // Let threads run for a short time
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Clean up
    keepRunning = false;
    for (auto& t : threads) {
        t.join();
    }

    for (int testFd : testFds) {
        epoll_ctl(server->mUnifiedEpollFd, EPOLL_CTL_DEL, testFd, nullptr);
        close(testFd);
    }

    // Test plugin stop and epoll unregistration
    res = inputFile->Stop(true);
    APSARA_TEST_TRUE(res);
    res = inputProcess->Stop(true);
    APSARA_TEST_TRUE(res);
}

void eBPFServerUnittest::TestRetryCache() {
    auto& server = *ebpf::EBPFServer::GetInstance();
    server.Init();
    auto& eventCache = server.EventCache();
    APSARA_TEST_EQUAL(0UL, eventCache.Size());

    auto initialRetryTime = server.mLastEventCacheRetryTime;
    server.handleEventCache();
    APSARA_TEST_GE(server.mLastEventCacheRetryTime, initialRetryTime);

    // Test multiple rapid calls
    auto retryTimeBefore = server.mLastEventCacheRetryTime;
    server.handleEventCache();
    server.handleEventCache();
    APSARA_TEST_EQUAL(retryTimeBefore, server.mLastEventCacheRetryTime);

    // Test timing stability
    server.mLastEventCacheRetryTime = TimeKeeper::GetInstance()->NowSec() - 10;
    auto oldRetryTime = server.mLastEventCacheRetryTime;
    server.handleEventCache();
    APSARA_TEST_GT(server.mLastEventCacheRetryTime, oldRetryTime);
}

void eBPFServerUnittest::TestEnvManager() {
    EBPFServer::GetInstance()->mEnvMgr.InitEnvInfo();

    EXPECT_TRUE(EBPFServer::GetInstance()->mEnvMgr.mArchSupport);

    EBPFServer::GetInstance()->mEnvMgr.m310Support = false;
    EBPFServer::GetInstance()->mEnvMgr.mArchSupport = false;
    EBPFServer::GetInstance()->mEnvMgr.mBTFSupport = true;
    EXPECT_EQ(EBPFServer::GetInstance()->IsSupportedEnv(logtail::ebpf::PluginType::NETWORK_OBSERVE), false);
    EXPECT_EQ(EBPFServer::GetInstance()->IsSupportedEnv(logtail::ebpf::PluginType::NETWORK_SECURITY), false);
    EXPECT_EQ(EBPFServer::GetInstance()->IsSupportedEnv(logtail::ebpf::PluginType::PROCESS_SECURITY), false);
    EXPECT_EQ(EBPFServer::GetInstance()->IsSupportedEnv(logtail::ebpf::PluginType::FILE_SECURITY), false);

    EBPFServer::GetInstance()->mEnvMgr.m310Support = false;
    EBPFServer::GetInstance()->mEnvMgr.mArchSupport = true;
    EBPFServer::GetInstance()->mEnvMgr.mBTFSupport = true;

    EXPECT_EQ(EBPFServer::GetInstance()->IsSupportedEnv(logtail::ebpf::PluginType::NETWORK_OBSERVE), true);
    EXPECT_EQ(EBPFServer::GetInstance()->IsSupportedEnv(logtail::ebpf::PluginType::NETWORK_SECURITY), true);
    EXPECT_EQ(EBPFServer::GetInstance()->IsSupportedEnv(logtail::ebpf::PluginType::PROCESS_SECURITY), true);
    EXPECT_EQ(EBPFServer::GetInstance()->IsSupportedEnv(logtail::ebpf::PluginType::FILE_SECURITY), true);

    EBPFServer::GetInstance()->mEnvMgr.m310Support = true;
    EBPFServer::GetInstance()->mEnvMgr.mArchSupport = true;
    EBPFServer::GetInstance()->mEnvMgr.mBTFSupport = false;

    EXPECT_EQ(EBPFServer::GetInstance()->IsSupportedEnv(logtail::ebpf::PluginType::NETWORK_OBSERVE), true);
    EXPECT_EQ(EBPFServer::GetInstance()->IsSupportedEnv(logtail::ebpf::PluginType::NETWORK_SECURITY), false);
    EXPECT_EQ(EBPFServer::GetInstance()->IsSupportedEnv(logtail::ebpf::PluginType::PROCESS_SECURITY), false);
    EXPECT_EQ(EBPFServer::GetInstance()->IsSupportedEnv(logtail::ebpf::PluginType::FILE_SECURITY), false);
}

// UNIT_TEST_CASE(eBPFServerUnittest, TestNetworkObserver);

// UNIT_TEST_CASE(eBPFServerUnittest, TestUpdateNetworkSecurity);

// UNIT_TEST_CASE(eBPFServerUnittest, TestNetworkSecurity);

UNIT_TEST_CASE(eBPFServerUnittest, TestUpdateFileSecurity);
UNIT_TEST_CASE(eBPFServerUnittest, TestUpdateCpuProfiling);
UNIT_TEST_CASE(eBPFServerUnittest, TestFileSecurity);
UNIT_TEST_CASE(eBPFServerUnittest, TestProcessSecurity);
UNIT_TEST_CASE(eBPFServerUnittest, TestCpuProfiling);
UNIT_TEST_CASE(eBPFServerUnittest, TestDefaultEbpfParameters);
UNIT_TEST_CASE(eBPFServerUnittest, TestDefaultAndLoadEbpfParameters);
UNIT_TEST_CASE(eBPFServerUnittest, TestLoadEbpfParametersV1);
UNIT_TEST_CASE(eBPFServerUnittest, TestLoadEbpfParametersV2);
UNIT_TEST_CASE(eBPFServerUnittest, TestUnifiedEpoll);
UNIT_TEST_CASE(eBPFServerUnittest, TestRetryCache);
UNIT_TEST_CASE(eBPFServerUnittest, TestEnvManager);

} // namespace ebpf
} // namespace logtail

UNIT_TEST_MAIN
