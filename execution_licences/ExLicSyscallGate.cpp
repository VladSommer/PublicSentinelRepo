#include "exlic_syscall_gate.hpp"
#include "snt_dangerous_apis.hpp"

namespace scw::sentinel::execution_lics {

ExLicSyscallGate::ExLicSyscallGate(
    ExLicRegistry& registry,
    smm::SentinelMemoryArena& arena,
    crypto::HardwareCanaryEngine& canaryEngine
)
    : m_registry(registry), m_arena(arena), m_canary(canaryEngine) {}

bool ExLicSyscallGate::VerifySlotAuthenticity(const ExLicSlot* slot) const noexcept {
    if (slot == nullptr) {
        return false;
    }
    // Comprueba rango fisico de la Arena y alineacion estricta a 128 bytes
    if (!m_arena.ContainsAddress(slot) || !m_arena.IsSlotAligned(slot, sizeof(ExLicSlot))) {
        return false;
    }
    if (slot->magic != kExLicMagic) {
        return false;
    }

    const uint64_t expectedCanary = m_canary.MaskSlotCanary(reinterpret_cast<uintptr_t>(slot));
    if (slot->sessionCanaryMasked != expectedCanary) {
        return false;
    }

    return m_canary.VerifyLicenseSlotHmac(*slot);
}

bool ExLicSyscallGate::VerifyLiveTextIntegrity(const ExLicSlot* slot, const SyscallContext& ctx) const noexcept {
    if (ctx.textSectionBase == 0 || ctx.textSectionSize == 0) {
        return true;
    }
    const auto liveHash = snt_compute_ram_sha256(ctx.textSectionBase, ctx.textSectionSize);
    return liveHash == slot->textSectionHash;
}

GateVerdict ExLicSyscallGate::EvaluateCall(ExLicSlot* slot, const SyscallContext& ctx) {
    // Si el puntero cae en la Arena pero el canario o el HMAC no cuadran, se sospecha manipulacion de memoria
    if (slot != nullptr && m_arena.ContainsAddress(slot) && !VerifySlotAuthenticity(slot)) {
        return GateVerdict::TriggerSntTrace;
    }

    if (!VerifySlotAuthenticity(slot)) {
        return GateVerdict::RevokeAndJail;
    }

    if (slot->ownerPid != ctx.callingPid) {
        return GateVerdict::RevokeAndJail;
    }

    if (snt_is_dangerous_syscall(ctx.syscallId)) {
        if ((slot->capabilities & ctx.requiredCaps) != ctx.requiredCaps) {
            return GateVerdict::RevokeAndJail;
        }
    }

    if (!VerifyLiveTextIntegrity(slot, ctx)) {
        return GateVerdict::RevokeAndJail;
    }

    if (!m_registry.TouchOrRenew(slot, ctx.callingPid, ctx.timestampMs)) {
        return GateVerdict::DenyAccess;
    }

    return GateVerdict::AllowAndRefresh;
}

}