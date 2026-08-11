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
package eu.europa.ec.eudi.pidissuer.adapter.input.web.security

import eu.europa.ec.eudi.pidissuer.domain.TS3
import eu.europa.ec.eudi.pidissuer.port.out.token.IntrospectSelfIssuedAccessToken
import eu.europa.ec.eudi.pidissuer.port.out.token.SelfIssuedAccessTokenIntrospectionResult
import kotlinx.coroutines.reactor.awaitSingle
import kotlinx.coroutines.reactor.mono
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector
import reactor.core.publisher.Mono
import kotlin.time.Clock

/**
 * A [ReactiveOpaqueTokenIntrospector] that first tries to validate a token as one of the issuer's own self-issued
 * access tokens (see [IntrospectSelfIssuedAccessToken]); only when the token isn't shaped like one of those at
 * all does it fall back to [delegate] (the real Keycloak-backed introspector). A token that *is* shaped like a
 * self-issued access token but fails validation is rejected outright rather than forwarded to Keycloak.
 */
class CompositeReactiveOpaqueTokenIntrospector(
    private val introspectSelfIssuedAccessToken: IntrospectSelfIssuedAccessToken,
    private val delegate: ReactiveOpaqueTokenIntrospector,
    private val clock: Clock,
) : ReactiveOpaqueTokenIntrospector {
    override fun introspect(token: String): Mono<OAuth2AuthenticatedPrincipal> =
        mono {
            when (val result = introspectSelfIssuedAccessToken(token, clock.now())) {
                is SelfIssuedAccessTokenIntrospectionResult.Valid -> {
                    val claims = result.claims
                    val authorities: List<GrantedAuthority> =
                        claims.scopes.map { SimpleGrantedAuthority("SCOPE_${it.value}") }
                    val attributes =
                        buildMap<String, Any> {
                            put(OAuth2TokenIntrospectionClaimNames.ACTIVE, true)
                            put("username", claims.username)
                            put(OAuth2TokenIntrospectionClaimNames.CLIENT_ID, claims.clientId)
                            put(OAuth2TokenIntrospectionClaimNames.SCOPE, claims.scopes.map { it.value })
                            put("cnf", claims.cnf)
                            put(TS3.CLIENT_STATUS, claims.clientStatus)
                            put("custom_data", claims.customData)
                        }
                    DefaultOAuth2AuthenticatedPrincipal(claims.username, attributes, authorities)
                }

                SelfIssuedAccessTokenIntrospectionResult.InvalidOrExpired -> {
                    throw BadOpaqueTokenException("Self-issued access token is not valid")
                }

                SelfIssuedAccessTokenIntrospectionResult.NotOurs -> {
                    delegate.introspect(token).awaitSingle()
                }
            }
        }
}
