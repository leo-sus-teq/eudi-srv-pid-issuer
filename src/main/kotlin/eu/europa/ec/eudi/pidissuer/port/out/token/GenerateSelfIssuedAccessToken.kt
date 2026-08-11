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
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation
import eu.europa.ec.eudi.pidissuer.domain.ClientStatus
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.port.input.ClientId
import eu.europa.ec.eudi.pidissuer.port.input.Username
import kotlinx.serialization.json.JsonObject
import kotlin.time.Duration
import kotlin.time.Instant

/**
 * Mints a self-issued, DPoP-bound access token for the [urn:ietf:params:oauth:grant-type:pre-authorized_code]
 * grant. The issuer never delegates issuance of these tokens to Keycloak; they are validated locally by a
 * matching [IntrospectSelfIssuedAccessToken] implementation. [customData] (carried over from the redeemed
 * pre-authorized code) is embedded too, so it's available at credential-issuance time via
 * [eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext.customData].
 */
interface GenerateSelfIssuedAccessToken {
    suspend operator fun invoke(
        generatedAt: Instant,
        expiresIn: Duration,
        username: Username,
        clientId: ClientId,
        scopes: NonEmptySet<Scope>,
        dpopJwkThumbprint: JWKThumbprintConfirmation,
        clientStatus: ClientStatus,
        customData: Map<CredentialConfigurationId, JsonObject> = emptyMap(),
    ): String
}
