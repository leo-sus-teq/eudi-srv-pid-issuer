/*
 * Copyright (c) 2023-2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.pidissuer.adapter.out.persistence

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.time.Instant

/**
 * Tracks which pre-authorized codes (by their `jti`) have already been redeemed, so a stateless, self-encrypted
 * pre-authorized code can still be enforced as single-use. Mirrors [InMemoryDeferredCredentialRepository]'s
 * in-memory, non-persistent style - entries are pruned once their bound expiry has passed.
 */
class InMemoryUsedPreAuthorizedCodeChecker(
    private val used: MutableMap<String, Instant> = mutableMapOf(),
) {
    private val mutex = Mutex()

    /**
     * Atomically marks [jti] as used, unless it was already used before. Returns `true` if this call is the one
     * that marked it (i.e. the code is being redeemed for the first time), `false` if it had already been used.
     */
    suspend fun markUsedIfNotAlready(
        jti: String,
        expiresAt: Instant,
        now: Instant,
    ): Boolean =
        mutex.withLock(this) {
            used.entries.removeIf { it.value <= now }
            if (used.containsKey(jti)) {
                false
            } else {
                used[jti] = expiresAt
                true
            }
        }
}
