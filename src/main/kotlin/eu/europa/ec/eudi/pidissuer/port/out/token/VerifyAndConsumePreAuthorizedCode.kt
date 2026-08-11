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
package eu.europa.ec.eudi.pidissuer.port.out.token

import arrow.core.NonEmptySet
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.PreAuthorizedCode
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.port.input.Username
import kotlinx.serialization.json.JsonObject
import kotlin.time.Instant

/**
 * The outcome of redeeming a [PreAuthorizedCode].
 */
sealed interface PreAuthorizedCodeRedemption {
    data class Valid(
        val username: Username,
        val scopes: NonEmptySet<Scope>,
        val customData: Map<CredentialConfigurationId, JsonObject> = emptyMap(),
    ) : PreAuthorizedCodeRedemption

    /**
     * The code is malformed, expired, or has already been redeemed once before.
     */
    data object Invalid : PreAuthorizedCodeRedemption
}

/**
 * Verifies a [PreAuthorizedCode] is well-formed, not expired, and has not been redeemed before, and atomically
 * marks it as redeemed so it cannot be used again.
 */
fun interface VerifyAndConsumePreAuthorizedCode {
    suspend operator fun invoke(
        code: PreAuthorizedCode,
        at: Instant,
    ): PreAuthorizedCodeRedemption
}
