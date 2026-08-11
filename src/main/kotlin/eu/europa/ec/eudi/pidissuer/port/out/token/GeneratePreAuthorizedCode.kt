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
import kotlin.time.Duration
import kotlin.time.Instant

/**
 * Generates a new [PreAuthorizedCode], bound to the provided [Username] and [Scope]s, that expires after a specific
 * [Duration]. [customData] carries operator-entered claim values per Credential Configuration (see
 * [eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOffer.Request.customData]), embedded directly in the
 * encrypted code so it survives to issuance time without any server-side session state.
 */
interface GeneratePreAuthorizedCode {
    suspend operator fun invoke(
        generatedAt: Instant,
        expiresIn: Duration,
        username: Username,
        scopes: NonEmptySet<Scope>,
        customData: Map<CredentialConfigurationId, JsonObject> = emptyMap(),
    ): PreAuthorizedCode
}
