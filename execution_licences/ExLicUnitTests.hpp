#pragma once

#include <cstdint>
#include "exlic_registry.hpp"
#include "exlic_syscall_gate.hpp"
#include "exlic_revocation.hpp"
#include "snt_smm_arena.hpp"
#include "snt_crypto_canary.hpp"
#include "snt_trace_jail.hpp"
#include "snt_test_harness.hpp"

namespace scw::sentinel::execution_lics::tests {

struct ExLicTestFixture {
    smm::SentinelMemoryArena arena;
    crypto::HardwareCanaryEngine canaryEngine;
    policy::TraceJailController jailController;

    ExLicRegistry registry;
    ExLicSyscallGate gate;
    ExLicRevocationEngine revocation;

    ExLicTestFixture();
    ~ExLicTestFixture();
};

class ExLicTestSuite {
public:
    static void RunAll(test::SntTestRunner& runner);

private:
    static void TestIssueAndAlignment(test::TestContext& ctx);
    static void TestLazyRefreshAndTtlExpiration(test::TestContext& ctx);
    static void TestTamperTriggersSntTrace(test::TestContext& ctx);
    static void TestDangerousSyscallWithoutCapsJailsProcess(test::TestContext& ctx);
    static void TestTextSectionHashMismatchRevokes(test::TestContext& ctx);
    static void TestRevocationPurgesAndZeroFillsSlot(test::TestContext& ctx);
};

}