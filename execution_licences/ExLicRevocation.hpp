#pragma once

#include <cstdint>
#include "exlic_registry.hpp"
#include "snt_trace_jail.hpp"
#include "snt_process_killer.hpp"

namespace scw::sentinel::execution_lics {

enum class RevocationReason : uint8_t {
    CleanProcessExit = 0,
    TtlExpired       = 1,
    UnauthorizedApi  = 2,
    TextHashMismatch = 3,
    TamperDetected   = 4
};

class ExLicRevocationEngine {
public:
    ExLicRevocationEngine(
        smm::SentinelMemoryArena& arena,
        policy::TraceJailController& jailController
    );

    void RevokeAndPurge(ExLicSlot* slot, RevocationReason reason, bool terminateOwnerProcess);
    void PurgeAndReleaseSlot(ExLicSlot* slot);

private:
    smm::SentinelMemoryArena& m_arena;
    policy::TraceJailController& m_jail;
};

}