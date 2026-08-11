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
package eu.europa.ec.eudi.pidissuer.port.input

import arrow.core.NonEmptySet
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken
import eu.europa.ec.eudi.pidissuer.domain.ClientStatus
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.Scope
import kotlinx.serialization.json.JsonObject

typealias Username = String
typealias ClientId = String

data class AuthorizationContext(
    val username: Username,
    val accessToken: DPoPAccessToken,
    val scopes: NonEmptySet<Scope>,
    val clientId: ClientId? = null,
    val clientStatus: ClientStatus,
    /**
     * Operator-entered claim values, per Credential Configuration, carried over from the pre-authorized_code
     * offer that was used to obtain the current access token. Empty for tokens obtained via the
     * authorization_code flow (there is no such data for those).
     */
    val customData: Map<CredentialConfigurationId, JsonObject> = emptyMap(),
)
