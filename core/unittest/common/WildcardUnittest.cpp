/*
 * Copyright 2025 iLogtail Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common/Wildcard.h"
#include "unittest/Unittest.h"

namespace logtail {

class WildcardUnittest : public ::testing::Test {
public:
    void TestWildcard();
    void TestWildcardEngine();
};

APSARA_UNIT_TEST_CASE(WildcardUnittest, TestWildcard, 0);
APSARA_UNIT_TEST_CASE(WildcardUnittest, TestWildcardEngine, 0);

void WildcardUnittest::TestWildcard() {
    Wildcard wildcard("*.log");
    EXPECT_TRUE(wildcard.IsMatch("test.log"));
    EXPECT_FALSE(wildcard.IsMatch("test.txt"));
    EXPECT_FALSE(wildcard.IsMatch("test.log.txt"));
    EXPECT_FALSE(wildcard.IsMatch("test.log2"));
}

void WildcardUnittest::TestWildcardEngine() {
    WildcardEngine engine;

    std::string pattern1 = "*.log";
    std::string pattern2 = "test.*";

    EXPECT_TRUE(engine.IsMatch(pattern1, "test.log"));
    EXPECT_TRUE(engine.IsMatch(pattern1, "test.log"));

    EXPECT_TRUE(engine.IsMatch(pattern2, "test.txt", /* cache = */ false));
    EXPECT_TRUE(engine.IsMatch(pattern2, "test.txt", /* cache = */ false));
}

} // namespace logtail

UNIT_TEST_MAIN
