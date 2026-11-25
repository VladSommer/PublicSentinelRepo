#include "exlic_revocation.hpp"
#include "snt_atomic_ops.hpp"
#include "snt_zero_purge.hpp"

namespace scw::sentinel::execution_lics {

ExLicRevocationEngine::ExLicRevocationEngine(
    smm::SentinelMemoryArena& arena,
    policy::TraceJailController& jailController
)
    : m_arena(arena), m_jail(jailController) {}

void ExLicRevocationEngine::RevokeAndPurge(
    ExLicSlot* slot,
    RevocationReason reason,
    bool terminateOwnerProcess
) {
    if (slot == nullptr || !m_arena.ContainsAddress(slot)) {
        return;
    }

    const uint64_t targetPid = slot->ownerPid;
    const LicenseState nextState =
        (reason == RevocationReason::TtlExpired) ? LicenseState::Expired : LicenseState::Revoked;

    // Transicion atomica de estado y anulado de capacidades antes de limpiar el resto del bloque
    snt_atomic_store_u32(&slot->state, static_cast<uint32_t>(nextState));
    snt_atomic_store_u32(&slot->capabilities, static_cast<uint32_t>(CapabilityMask::None));

    if (reason == RevocationReason::UnauthorizedApi ||
        reason == RevocationReason::TextHashMismatch ||
        reason == RevocationReason::TamperDetected) {
        m_jail.EngageJailAndTrace(targetPid, static_cast<uint32_t>(reason));
    }

    if (terminateOwnerProcess && targetPid != 0) {
        snt_zw_terminate_process_by_pid(targetPid);
    }

    PurgeAndReleaseSlot(slot);
}

void ExLicRevocationEngine::PurgeAndReleaseSlot(ExLicSlot* slot) {
    if (slot == nullptr || !m_arena.ContainsAddress(slot)) {
        return;
    }

    // Borra hashes, canarios y HMAC en RAM, invalida linea de cache y devuelve el slot al SMM
    snt_secure_zero(slot, sizeof(ExLicSlot));
    snt_flush_cache_line(slot);
    m_arena.ReleaseSlot(slot);
}

}