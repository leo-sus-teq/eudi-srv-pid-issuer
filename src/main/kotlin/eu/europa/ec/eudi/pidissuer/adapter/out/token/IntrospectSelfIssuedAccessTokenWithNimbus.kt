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
package eu.europa.ec.eudi.pidissuer.adapter.out.token

import arrow.core.raise.result
import arrow.core.toNonEmptySetOrNull
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWEDecryptionKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.pidissuer.adapter.out.nonce.NonceEncryptionKey
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.domain.toKotlinInstant
import eu.europa.ec.eudi.pidissuer.port.out.token.IntrospectSelfIssuedAccessToken
import eu.europa.ec.eudi.pidissuer.port.out.token.SelfIssuedAccessTokenClaims
import eu.europa.ec.eudi.pidissuer.port.out.token.SelfIssuedAccessTokenIntrospectionResult
import org.bouncycastle.jce.provider.BouncyCastleProvider
import kotlin.time.Instant

/**
 * Decrypts and verifies a self-issued access token minted by [GenerateSelfIssuedAccessTokenWithNimbus]. Tokens
 * that aren't even shaped like one of ours (e.g. a real Keycloak-issued opaque token) are reported as
 * [SelfIssuedAccessTokenIntrospectionResult.NotOurs] so the caller can fall back to introspecting them elsewhere;
 * tokens that are shaped like ours but fail decryption/verification are reported as
 * [SelfIssuedAccessTokenIntrospectionResult.InvalidOrExpired] instead, so a tampered token is never forwarded on.
 */
internal class IntrospectSelfIssuedAccessTokenWithNimbus(
    private val issuer: CredentialIssuerId,
    private val decryptionKey: NonceEncryptionKey,
) : IntrospectSelfIssuedAccessToken {
    private val expectedType = JOSEObjectType(SELF_ISSUED_ACCESS_TOKEN_JWT_TYPE)

    private val processor =
        DefaultJWTProcessor<SecurityContext>()
            .apply {
                jweTypeVerifier = DefaultJOSEObjectTypeVerifier(expectedType)
                jweKeySelector =
                    JWEDecryptionKeySelector(
                        decryptionKey.algorithm,
                        decryptionKey.method,
                        ImmutableJWKSet(JWKSet(decryptionKey.encryptionKey)),
                    )
                jweDecrypterFactory =
                    DefaultJWEDecrypterFactory()
                        .apply {
                            jcaContext.provider = BouncyCastleProvider()
                        }
                jwtClaimsSetVerifier =
                    DefaultJWTClaimsVerifier(
                        issuer.externalForm,
                        JWTClaimsSet
                            .Builder()
                            .issuer(issuer.externalForm)
                            .audience(issuer.externalForm)
                            .build(),
                        setOf("iss", "aud", "username", "client_id", "scope", "cnf", "client_status", "iat", "exp"),
                    )
            }

    override suspend fun invoke(
        token: String,
        at: Instant,
    ): SelfIssuedAccessTokenIntrospectionResult {
        val jwt =
            try {
                EncryptedJWT.parse(token)
            } catch (_: Exception) {
                return SelfIssuedAccessTokenIntrospectionResult.NotOurs
            }
        if (jwt.header.type != expectedType) {
            return SelfIssuedAccessTokenIntrospectionResult.NotOurs
        }

        return result {
            val claimSet = processor.process(jwt, null)
            val expiresAt = requireNotNull(claimSet.expirationTime) { "expirationTime is required" }.toKotlinInstant()
            require(at < expiresAt) { "token has expired" }

            val username = requireNotNull(claimSet.getStringClaim("username")) { "username is required" }
            val clientId = requireNotNull(claimSet.getStringClaim("client_id")) { "client_id is required" }
            val scopes =
                requireNotNull(claimSet.getStringClaim("scope")) { "scope is required" }
                    .split(" ")
                    .filter { it.isNotBlank() }
                    .map { Scope(it) }
                    .toNonEmptySetOrNull()
            requireNotNull(scopes) { "scope must not be empty" }
            val cnf = requireNotNull(claimSet.getJSONObjectClaim("cnf")) { "cnf is required" }
            val clientStatus = requireNotNull(claimSet.getJSONObjectClaim("client_status")) { "client_status is required" }
            val customData = claimSet.getJSONObjectClaim("custom_data").orEmpty()

            SelfIssuedAccessTokenIntrospectionResult.Valid(
                SelfIssuedAccessTokenClaims(
                    username = username,
                    clientId = clientId,
                    scopes = scopes,
                    cnf = cnf,
                    clientStatus = clientStatus,
                    customData = customData,
                ),
            )
        }.getOrElse { SelfIssuedAccessTokenIntrospectionResult.InvalidOrExpired }
    }
}
