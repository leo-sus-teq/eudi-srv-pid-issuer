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

import arrow.core.nonEmptySetOf
import com.eygraber.uri.Uri
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation
import eu.europa.ec.eudi.pidissuer.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.pidissuer.adapter.out.nonce.NonceEncryptionKey
import eu.europa.ec.eudi.pidissuer.domain.ClientStatus
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.domain.StatusClaim
import eu.europa.ec.eudi.pidissuer.domain.StatusListToken
import eu.europa.ec.eudi.pidissuer.port.out.token.SelfIssuedAccessTokenIntrospectionResult
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

internal class SelfIssuedAccessTokenRoundTripTest {
    private val issuer = CredentialIssuerId.unsafe("https://eudi.ec.europa.eu/issuer")
    private val clock = Clock.System
    private val encryptionKey =
        NonceEncryptionKey(
            ECKeyGenerator(Curve.P_256).keyUse(KeyUse.ENCRYPTION).generate(),
        )
    private val generate = GenerateSelfIssuedAccessTokenWithNimbus(issuer, encryptionKey)
    private val introspect = IntrospectSelfIssuedAccessTokenWithNimbus(issuer, encryptionKey)

    private fun clientStatus(now: kotlin.time.Instant) =
        ClientStatus(
            status = StatusClaim(StatusListToken(Uri.parse("urn:test:no-status"), 0u)),
            expiresAt = now + 365.minutes,
        )

    @Test
    fun `a freshly minted access token introspects with every claim WalletApi needs`() =
        runTest {
            val now = clock.now()
            val thumbprint = JWKThumbprintConfirmation(Base64URL.encode("thumbprint-value"))
            val scopes = nonEmptySetOf(Scope("eu.europa.ec.eudi.pid_mso_mdoc"), Scope("eu.europa.ec.eudi.pid_vc_sd_jwt"))
            val token =
                generate(
                    generatedAt = now,
                    expiresIn = 10.minutes,
                    username = "tneal",
                    clientId = "wallet-abc",
                    scopes = scopes,
                    dpopJwkThumbprint = thumbprint,
                    clientStatus = clientStatus(now),
                )

            val result = introspect(token, now)
            val valid = assertIs<SelfIssuedAccessTokenIntrospectionResult.Valid>(result)
            assertEquals("tneal", valid.claims.username)
            assertEquals("wallet-abc", valid.claims.clientId)
            assertEquals(scopes, valid.claims.scopes)

            // exactly the same decode WalletApi.authorizationContext() performs for the 'cnf' claim
            val parsedThumbprint = JWKThumbprintConfirmation.parse(net.minidev.json.JSONObject(mapOf("cnf" to valid.claims.cnf)))
            assertEquals(thumbprint, parsedThumbprint)

            // exactly the same decode WalletApi.authorizationContext() performs for the 'client_status' claim
            val decodedClientStatus =
                jsonSupport.decodeFromString<ClientStatus>(
                    JSONObjectUtils.toJSONString(valid.claims.clientStatus),
                )
            assertEquals(clientStatus(now).status, decodedClientStatus.status)
        }

    @Test
    fun `operator-entered custom data survives the generate-introspect round trip`() =
        runTest {
            val now = clock.now()
            val configId = CredentialConfigurationId("urn:eudi:ehic:1:dc+sd-jwt-compact")
            val customData = mapOf(configId to buildJsonObject { put("family_name", "Doe") })
            val token =
                generate(
                    generatedAt = now,
                    expiresIn = 10.minutes,
                    username = "tneal",
                    clientId = "wallet-abc",
                    scopes = nonEmptySetOf(Scope("urn:eudi:ehic:1:dc+sd-jwt")),
                    dpopJwkThumbprint = JWKThumbprintConfirmation(Base64URL.encode("thumbprint-value")),
                    clientStatus = clientStatus(now),
                    customData = customData,
                )

            val result = introspect(token, now)
            val valid = assertIs<SelfIssuedAccessTokenIntrospectionResult.Valid>(result)

            // exactly the same decode WalletApi.authorizationContext() performs for the 'custom_data' claim
            val decodedCustomData =
                jsonSupport
                    .decodeFromString<Map<String, JsonObject>>(
                        JSONObjectUtils.toJSONString(valid.claims.customData),
                    ).mapKeys { (id, _) -> CredentialConfigurationId(id) }
            assertEquals(customData, decodedCustomData)
        }

    @Test
    fun `an expired access token is rejected as invalid, not treated as not-ours`() =
        runTest {
            val now = clock.now()
            val token =
                generate(
                    generatedAt = now,
                    expiresIn = 1.seconds,
                    username = "tneal",
                    clientId = "wallet-abc",
                    scopes = nonEmptySetOf(Scope("eu.europa.ec.eudi.pid_mso_mdoc")),
                    dpopJwkThumbprint = JWKThumbprintConfirmation(Base64URL.encode("thumbprint-value")),
                    clientStatus = clientStatus(now),
                )

            val result = introspect(token, now + 1.minutes)
            assertIs<SelfIssuedAccessTokenIntrospectionResult.InvalidOrExpired>(result)
        }

    @Test
    fun `a token that isn't shaped like one of ours is reported as not-ours`() =
        runTest {
            val result = introspect("not-a-real-token", clock.now())
            assertIs<SelfIssuedAccessTokenIntrospectionResult.NotOurs>(result)
        }

    @Test
    fun `a pre-authorized code cannot be introspected as an access token`() =
        runTest {
            val now = clock.now()
            val generateCode = GeneratePreAuthorizedCodeWithNimbus(issuer, encryptionKey)
            val code = generateCode(now, 10.minutes, "tneal", nonEmptySetOf(Scope("eu.europa.ec.eudi.pid_mso_mdoc")))

            val result = introspect(code.value, now)
            assertIs<SelfIssuedAccessTokenIntrospectionResult.NotOurs>(result)
        }
}
