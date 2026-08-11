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
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.port.input.ClientId
import eu.europa.ec.eudi.pidissuer.port.input.Username
import kotlin.time.Instant

/**
 * The claims embedded in a self-issued access token, shaped so they can be dropped directly into an
 * `OAuth2AuthenticatedPrincipal`'s attributes map exactly as a real Keycloak introspection response would be.
 */
data class SelfIssuedAccessTokenClaims(
    val username: Username,
    val clientId: ClientId,
    val scopes: NonEmptySet<Scope>,
    val cnf: Map<String, Any?>,
    val clientStatus: Map<String, Any?>,
    val customData: Map<String, Any?>,
)

sealed interface SelfIssuedAccessTokenIntrospectionResult {
    data class Valid(
        val claims: SelfIssuedAccessTokenClaims,
    ) : SelfIssuedAccessTokenIntrospectionResult

    /**
     * The token is not shaped like one of our self-issued access tokens at all (e.g. a real Keycloak-issued
     * token) - callers should fall back to introspecting it some other way.
     */
    data object NotOurs : SelfIssuedAccessTokenIntrospectionResult

    /**
     * The token is shaped like one of our self-issued access tokens, but is expired, tampered with, or otherwise
     * invalid - callers should reject it outright rather than falling back to another introspection mechanism.
     */
    data object InvalidOrExpired : SelfIssuedAccessTokenIntrospectionResult
}

fun interface IntrospectSelfIssuedAccessToken {
    suspend operator fun invoke(
        token: String,
        at: Instant,
    ): SelfIssuedAccessTokenIntrospectionResult
}
