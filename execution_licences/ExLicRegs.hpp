#pragma once


#include <cstdint>
#include <array>
#include <optional>
#include "snt_smm_arena.hpp"
#include "snt_crypto_canary.hpp"
#include "snt_kernel_types.hpp"

namespace scw::sentinel::execution_lics {

inline constexpr uint32_t kExLicMagic        = 0x534E5458; // "SNTX"
inline constexpr uint64_t kDefaultTtlMs      = 300;
inline constexpr uint64_t kLazyRefreshGateMs = 150;
inline constexpr size_t   kDigestBytes       = 32;

enum class LicenseState : uint32_t {
    Free      = 0,
    Active    = 1,
    Expired   = 2,
    Revoked   = 3,
    Jailed    = 4
};

enum class CapabilityMask : uint32_t {
    None            = 0x00000000u,
    ReadOwnMemory   = 0x00000001u,
    WriteOwnHeap    = 0x00000002u,
    NetworkSocket   = 0x00000004u,
    FileSystemIo    = 0x00000008u,
    ProtectedVault  = 0x80000000u
};

struct alignas(128) ExLicSlot {
    uint32_t magic;
    uint32_t state;
    uint64_t ownerPid;
    uint64_t createdTickMs;
    uint64_t expiresTickMs;
    uint64_t heartbeatCounter;
    uint32_t capabilities;
    uint32_t slotIndex;
    uint64_t sessionCanaryMasked;
    std::array<uint8_t, kDigestBytes> textSectionHash;
    std::array<uint8_t, kDigestBytes> slotHmac;
    std::array<uint8_t, 20> reservedPadding;
};

static_assert(sizeof(ExLicSlot) == 128, "ExLicSlot debe ocupar exactamente una linea de cache de 128B");

class ExLicRegistry {
public:
    explicit ExLicRegistry(smm::SentinelMemoryArena& arena, crypto::HardwareCanaryEngine& canaryEngine);

    ExLicSlot* IssueLicense(uint64_t pid, uint32_t caps, const std::array<uint8_t, kDigestBytes>& textHash, uint64_t nowMs);
    bool TouchOrRenew(ExLicSlot* slot, uint64_t callingPid, uint64_t nowMs);
    void ExpireStaleLicenses(uint64_t nowMs);
    std::optional<uint32_t> QuerySlotIndex(const ExLicSlot* slot) const noexcept;

private:
    smm::SentinelMemoryArena& m_arena;
    crypto::HardwareCanaryEngine& m_canary;
    uint64_t m_issuedCount{0};
};

}