#include "exlic_unit_tests.hpp"
#include "snt_dangerous_apis.hpp"
#include "snt_ram_hasher.hpp"
#include <cstring>

namespace scw::sentinel::execution_lics::tests {

namespace {
constexpr uint64_t kTestPid       = 4096;
constexpr uint64_t kRoguePid      = 9999;
constexpr uint64_t kBaseBootTick  = 100000;
constexpr uintptr_t kFakeTextBase = 0x00007FF600001000ULL;
constexpr size_t    kFakeTextSize = 0x4000;

std::array<uint8_t, kDigestBytes> MakeMockDigest(uint8_t seed) {
    std::array<uint8_t, kDigestBytes> digest{};
    for (size_t i = 0; i < kDigestBytes; ++i) {
        digest[i] = static_cast<uint8_t>(seed ^ (i * 13));
    }
    return digest;
}
} // namespace

ExLicTestFixture::ExLicTestFixture()
    : arena(/*slotCount=*/64, /*slotSize=*/sizeof(ExLicSlot)),
      canaryEngine(/*hardwareSeed=*/0xA55A1999DEADBEEFULL),
      jailController(/*dryRunMode=*/true),
      registry(arena, canaryEngine),
      gate(registry, arena, canaryEngine),
      revocation(arena, jailController) {}

ExLicTestFixture::~ExLicTestFixture() {
    arena.TeardownAndScrubAll();
}

void ExLicTestSuite::RunAll(test::SntTestRunner& runner) {
    runner.Register("ExLic::IssueAndAlignment",        &ExLicTestSuite::TestIssueAndAlignment);
    runner.Register("ExLic::LazyRefreshAndTtl",        &ExLicTestSuite::TestLazyRefreshAndTtlExpiration);
    runner.Register("ExLic::TamperTriggersSntTrace",   &ExLicTestSuite::TestTamperTriggersSntTrace);
    runner.Register("ExLic::DangerousSyscallJail",     &ExLicTestSuite::TestDangerousSyscallWithoutCapsJailsProcess);
    runner.Register("ExLic::TextSectionHashMismatch",  &ExLicTestSuite::TestTextSectionHashMismatchRevokes);
    runner.Register("ExLic::RevocationZeroFillPurge",  &ExLicTestSuite::TestRevocationPurgesAndZeroFillsSlot);
}

void ExLicTestSuite::TestIssueAndAlignment(test::TestContext& ctx) {
    ExLicTestFixture fx;
    const auto hash = MakeMockDigest(0x42);

    ExLicSlot* slot = fx.registry.IssueLicense(
        kTestPid,
        static_cast<uint32_t>(CapabilityMask::ReadOwnMemory),
        hash,
        kBaseBootTick
    );

    SNT_ASSERT_NOT_NULL(ctx, slot);
    SNT_ASSERT_EQ(ctx, slot->magic, kExLicMagic);
    SNT_ASSERT_EQ(ctx, slot->ownerPid, kTestPid);
    SNT_ASSERT_EQ(ctx, slot->state, static_cast<uint32_t>(LicenseState::Active));
    SNT_ASSERT_EQ(ctx, slot->expiresTickMs, kBaseBootTick + kDefaultTtlMs);
    SNT_ASSERT_TRUE(ctx, fx.arena.IsSlotAligned(slot, 128));
}

void ExLicTestSuite::TestLazyRefreshAndTtlExpiration(test::TestContext& ctx) {
    ExLicTestFixture fx;
    ExLicSlot* slot = fx.registry.IssueLicense(
        kTestPid,
        static_cast<uint32_t>(CapabilityMask::FileSystemIo),
        MakeMockDigest(0x10),
        kBaseBootTick
    );

    // 1. A los +50ms (quedan 250ms > 150ms): permite paso pero NO debe renovar el timestamp ni el heartbeat
    SNT_ASSERT_TRUE(ctx, fx.registry.TouchOrRenew(slot, kTestPid, kBaseBootTick + 50));
    SNT_ASSERT_EQ(ctx, slot->expiresTickMs, kBaseBootTick + 300);
    SNT_ASSERT_EQ(ctx, slot->heartbeatCounter, 1ULL);

    // 2. A los +200ms (quedan 100ms < 150ms): dispara Lazy Refresh y extiende otros 300ms
    SNT_ASSERT_TRUE(ctx, fx.registry.TouchOrRenew(slot, kTestPid, kBaseBootTick + 200));
    SNT_ASSERT_EQ(ctx, slot->expiresTickMs, kBaseBootTick + 500);
    SNT_ASSERT_EQ(ctx, slot->heartbeatCounter, 2ULL);

    // 3. Superado el nuevo vencimiento (+501ms): la licencia caduca automaticamente
    SNT_ASSERT_FALSE(ctx, fx.registry.TouchOrRenew(slot, kTestPid, kBaseBootTick + 501));
    SNT_ASSERT_EQ(ctx, slot->state, static_cast<uint32_t>(LicenseState::Expired));
}

void ExLicTestSuite::TestTamperTriggersSntTrace(test::TestContext& ctx) {
    ExLicTestFixture fx;
    ExLicSlot* slot = fx.registry.IssueLicense(
        kTestPid,
        static_cast<uint32_t>(CapabilityMask::ReadOwnMemory),
        MakeMockDigest(0x77),
        kBaseBootTick
    );

    // Simula un ataque en RAM modificando directamente la mascara de capacidades sin recalcular HMAC
    slot->capabilities |= static_cast<uint32_t>(CapabilityMask::ProtectedVault);

    SyscallContext callCtx{};
    callCtx.callingPid  = kTestPid;
    callCtx.timestampMs = kBaseBootTick + 10;
    callCtx.syscallId   = SNT_SYS_NT_READ_FILE;

    const GateVerdict verdict = fx.gate.EvaluateCall(slot, callCtx);
    SNT_ASSERT_EQ(ctx, static_cast<int>(verdict), static_cast<int>(GateVerdict::TriggerSntTrace));
}

void ExLicTestSuite::TestDangerousSyscallWithoutCapsJailsProcess(test::TestContext& ctx) {
    ExLicTestFixture fx;
    ExLicSlot* slot = fx.registry.IssueLicense(
        kTestPid,
        static_cast<uint32_t>(CapabilityMask::ReadOwnMemory),
        MakeMockDigest(0x33),
        kBaseBootTick
    );

    SyscallContext callCtx{};
    callCtx.callingPid   = kTestPid;
    callCtx.targetPid    = kRoguePid;
    callCtx.timestampMs  = kBaseBootTick + 20;
    callCtx.syscallId    = SNT_SYS_NT_WRITE_VIRTUAL_MEMORY;
    callCtx.requiredCaps = static_cast<uint32_t>(CapabilityMask::ProtectedVault);

    const GateVerdict verdict = fx.gate.EvaluateCall(slot, callCtx);
    SNT_ASSERT_EQ(ctx, static_cast<int>(verdict), static_cast<int>(GateVerdict::RevokeAndJail));
}

void ExLicTestSuite::TestTextSectionHashMismatchRevokes(test::TestContext& ctx) {
    ExLicTestFixture fx;
    const auto originalHash = MakeMockDigest(0x99);
    const auto injectedHash = MakeMockDigest(0xEE);

    // Configura el stub del hasher de RAM para devolver un hash alterado (simulando code injection)
    snt_test_mock_ram_sha256(kFakeTextBase, kFakeTextSize, injectedHash);

    ExLicSlot* slot = fx.registry.IssueLicense(
        kTestPid,
        static_cast<uint32_t>(CapabilityMask::NetworkSocket),
        originalHash,
        kBaseBootTick
    );

    SyscallContext callCtx{};
    callCtx.callingPid      = kTestPid;
    callCtx.timestampMs     = kBaseBootTick + 15;
    callCtx.syscallId       = SNT_SYS_NT_DEVICE_IO_CONTROL_FILE;
    callCtx.textSectionBase = kFakeTextBase;
    callCtx.textSectionSize = kFakeTextSize;

    const GateVerdict verdict = fx.gate.EvaluateCall(slot, callCtx);
    SNT_ASSERT_EQ(ctx, static_cast<int>(verdict), static_cast<int>(GateVerdict::RevokeAndJail));
}

void ExLicTestSuite::TestRevocationPurgesAndZeroFillsSlot(test::TestContext& ctx) {
    ExLicTestFixture fx;
    ExLicSlot* slot = fx.registry.IssueLicense(
        kTestPid,
        static_cast<uint32_t>(CapabilityMask::FileSystemIo),
        MakeMockDigest(0x55),
        kBaseBootTick
    );

    fx.revocation.RevokeAndPurge(slot, RevocationReason::UnauthorizedApi, /*terminateOwnerProcess=*/true);

    // Verifica que el slot completo de 128 bytes quedo en ceros absolutos y liberado en el SMM
    const auto* rawBytes = reinterpret_cast<const uint8_t*>(slot);
    bool allZero = true;
    for (size_t i = 0; i < sizeof(ExLicSlot); ++i) {
        if (rawBytes[i] != 0) {
            allZero = false;
            break;
        }
    }

    SNT_ASSERT_TRUE(ctx, allZero);
    SNT_ASSERT_FALSE(ctx, fx.arena.IsSlotInUse(slot));
    SNT_ASSERT_TRUE(ctx, fx.jailController.WasJailEngagedForPid(kTestPid));
}

}