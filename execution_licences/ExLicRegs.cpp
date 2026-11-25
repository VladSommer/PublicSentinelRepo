#include "exlic_registry.hpp"
#include "snt_atomic_ops.hpp"
#include "snt_zero_purge.hpp"

namespace scw::sentinel::execution_lics {

ExLicRegistry::ExLicRegistry(smm::SentinelMemoryArena& arena, crypto::HardwareCanaryEngine& canaryEngine)
    : m_arena(arena), m_canary(canaryEngine) {}

ExLicSlot* ExLicRegistry::IssueLicense(
    uint64_t pid,
    uint32_t caps,
    const std::array<uint8_t, kDigestBytes>& textHash,
    uint64_t nowMs
) {
    // Solicita un bloque de 128B prealineado dentro de la Non-Paged Pool del SMM
    void* rawSlot = m_arena.AllocateAlignedSlot(sizeof(ExLicSlot));
    if (rawSlot == nullptr) {
        return nullptr;
    }

    auto* slot = static_cast<ExLicSlot*>(rawSlot);
    snt_secure_zero(slot, sizeof(ExLicSlot));

    slot->magic            = kExLicMagic;
    slot->state            = static_cast<uint32_t>(LicenseState::Active);
    slot->ownerPid         = pid;
    slot->createdTickMs    = nowMs;
    slot->expiresTickMs    = nowMs + kDefaultTtlMs;
    slot->heartbeatCounter = 1;
    slot->capabilities     = caps;
    slot->slotIndex        = m_arena.ComputeSlotIndex(slot);

    // Vincula el canario de sesion con la direccion virtual del slot y firma el bloque
    slot->sessionCanaryMasked = m_canary.MaskSlotCanary(reinterpret_cast<uintptr_t>(slot));
    slot->slotHmac            = m_canary.SignLicenseSlot(*slot);
    slot->textSectionHash     = textHash;

    snt_atomic_inc_u64(&m_issuedCount);
    return slot;
}

bool ExLicRegistry::TouchOrRenew(ExLicSlot* slot, uint64_t callingPid, uint64_t nowMs) {
    if (slot == nullptr || slot->magic != kExLicMagic) {
        return false;
    }
    if (slot->ownerPid != callingPid) {
        return false;
    }
    if (slot->state != static_cast<uint32_t>(LicenseState::Active)) {
        return false;
    }
    if (nowMs > slot->expiresTickMs) {
        snt_atomic_store_u32(&slot->state, static_cast<uint32_t>(LicenseState::Expired));
        return false;
    }

    // Lazy Refresh: solo reescribe vencimiento y HMAC si queda menos de la mitad del TTL
    const uint64_t remainingMs = slot->expiresTickMs - nowMs;
    if (remainingMs < kLazyRefreshGateMs) {
        slot->expiresTickMs = nowMs + kDefaultTtlMs;
        snt_atomic_inc_u64(&slot->heartbeatCounter);
        slot->slotHmac = m_canary.SignLicenseSlot(*slot);
    }

    return true;
}

void ExLicRegistry::ExpireStaleLicenses(uint64_t nowMs) {
    m_arena.ForEachAllocatedSlot([nowMs](void* ptr) {
        auto* slot = static_cast<ExLicSlot*>(ptr);
        if (slot->magic == kExLicMagic &&
            slot->state == static_cast<uint32_t>(LicenseState::Active) &&
            nowMs > slot->expiresTickMs) {
            snt_atomic_store_u32(&slot->state, static_cast<uint32_t>(LicenseState::Expired));
        }
    });
}

std::optional<uint32_t> ExLicRegistry::QuerySlotIndex(const ExLicSlot* slot) const noexcept {
    if (slot == nullptr || !m_arena.ContainsAddress(slot)) {
        return std::nullopt;
    }
    return m_arena.ComputeSlotIndex(slot);
}

}