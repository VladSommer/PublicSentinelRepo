#pragma once

#include <cstdint>
#include "exlic_registry.hpp"
#include "snt_syscalls_guard.hpp"
#include "snt_ram_hasher.hpp"

namespace scw::sentinel::execution_lics {

enum class GateVerdict {
    AllowAndRefresh,
    DenyAccess,
    RevokeAndJail,
    TriggerSntTrace
};

struct SyscallContext {
    uint64_t callingPid;
    uint64_t targetPid;
    uint64_t timestampMs;
    uint32_t syscallId;
    uint32_t requiredCaps;
    uintptr_t textSectionBase;
    size_t textSectionSize;
};

class ExLicSyscallGate {
public:
    ExLicSyscallGate(
        ExLicRegistry& registry,
        smm::SentinelMemoryArena& arena,
        crypto::HardwareCanaryEngine& canaryEngine
    );

    GateVerdict EvaluateCall(ExLicSlot* slot, const SyscallContext& ctx);

private:
    bool VerifySlotAuthenticity(const ExLicSlot* slot) const noexcept;
    bool VerifyLiveTextIntegrity(const ExLicSlot* slot, const SyscallContext& ctx) const noexcept;

    ExLicRegistry& m_registry;
    smm::SentinelMemoryArena& m_arena;
    crypto::HardwareCanaryEngine& m_canary;
};

}