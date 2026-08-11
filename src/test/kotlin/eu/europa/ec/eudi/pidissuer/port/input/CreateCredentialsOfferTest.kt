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

import arrow.core.nonEmptySetOf
import arrow.core.raise.effect
import arrow.core.raise.fold
import arrow.core.raise.getOrElse
import eu.europa.ec.eudi.pidissuer.PidIssuerApplicationTest
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.context.TestPropertySource
import kotlin.test.*

@PidIssuerApplicationTest
@TestPropertySource(
    properties = [
        "issuer.credentialOffer.allowedSchemes=https,openid-credential-offer,haip-vci,eu-eaa-offer",
    ],
)
class CreateCredentialsOfferTest {
    @Autowired
    private lateinit var credentialIssuerMetadata: CredentialIssuerMetaData

    @Autowired
    private lateinit var createCredentialsOffer: CreateCredentialsOffer

    @Test
    fun `credential offer must be created when using an allowed credential offer uri scheme`() =
        runTest {
            val schemes =
                nonEmptySetOf(
                    "https",
                    "openid-credential-offer",
                    "haip-vci",
                    "eu-eaa-offer",
                ).flatMap { nonEmptySetOf(it, it.uppercase()) }

            schemes.forEach { scheme ->
                effect {
                    val credentialConfigurationIds = nonEmptySetOf(credentialIssuerMetadata.credentialConfigurationsSupported.first().id)
                    val uri =
                        createCredentialsOffer(
                            CreateCredentialsOffer.Request(
                                credentialConfigurationIds,
                                "$scheme://",
                            ),
                        )
                    assertTrue { scheme.equals(uri.scheme, ignoreCase = true) }
                }.getOrElse {
                    fail("Failed to create credential offer with scheme $scheme, error: $it")
                }
            }
        }

    @Test
    fun `credential offer must not be created when not using an allowed credential offer uri scheme`() =
        runTest {
            val customCredentialsOfferUris =
                nonEmptySetOf(
                    "javascript://%0aalert('Hacked');//",
                    "data:text/html,<script>alert(1)</script>",
                    "vbscript:msgbox(1)",
                    "file:///etc/passwd",
                    "http://attacker.example/",
                    "//example.com",
                )

            customCredentialsOfferUris.forEach { customCredentialsOfferUri ->
                effect {
                    val credentialConfigurationIds = nonEmptySetOf(credentialIssuerMetadata.credentialConfigurationsSupported.first().id)
                    createCredentialsOffer(
                        CreateCredentialsOffer.Request(
                            credentialConfigurationIds,
                            customCredentialsOfferUri,
                        ),
                    )
                }.fold(
                    transform = { fail("Credential Offer must not be created with uri $it") },
                    recover = {
                        val error = assertIs<CreateCredentialsOffer.Error.InvalidCredentialsOfferUri>(it)
                        val cause = assertIs<IllegalArgumentException>(error.cause)
                        val message = assertNotNull(cause.message)
                        assertTrue { "credentialsOfferUri must use one of the following schemes" in message }
                    },
                )
            }
        }

    @Test
    fun `pre-authorized_code offer is bound to the issuer's own token endpoint, carries only that grant`() =
        runTest {
            effect {
                val credentialConfigurationIds = nonEmptySetOf(credentialIssuerMetadata.credentialConfigurationsSupported.first().id)
                val uri =
                    createCredentialsOffer(
                        CreateCredentialsOffer.Request(credentialConfigurationIds, preAuthorizedCode = true),
                    )
                val offerJson = assertNotNull(uri.getQueryParameter("credential_offer"))
                val offer = Json.decodeFromString<CredentialsOfferTO>(offerJson)

                assertNull(offer.grants?.authorizationCode)
                val grant = assertNotNull(offer.grants?.preAuthorizedCode)
                assertTrue(grant.preAuthorizedCode.isNotBlank())
                // index 0 stays Keycloak (used by the authorization_code grant); the issuer's own url is index 1
                assertEquals(credentialIssuerMetadata.authorizationServers[1].externalForm, grant.authorizationServer)
                assertNotEquals(credentialIssuerMetadata.authorizationServers[0].externalForm, grant.authorizationServer)
            }.getOrElse { fail("Failed to create pre-authorized_code offer, error: $it") }
        }

    @Test
    fun `pre-authorized_code offer generation succeeds when carrying operator-entered custom data`() =
        runTest {
            effect {
                val configId = credentialIssuerMetadata.credentialConfigurationsSupported.first().id
                val credentialConfigurationIds = nonEmptySetOf(configId)
                val customData = mapOf(configId to buildJsonObject { put("family_name", "Doe") })
                val uri =
                    createCredentialsOffer(
                        CreateCredentialsOffer.Request(
                            credentialConfigurationIds,
                            preAuthorizedCode = true,
                            customData = customData,
                        ),
                    )
                val offerJson = assertNotNull(uri.getQueryParameter("credential_offer"))
                val offer = Json.decodeFromString<CredentialsOfferTO>(offerJson)
                val grant = assertNotNull(offer.grants?.preAuthorizedCode)
                assertTrue(grant.preAuthorizedCode.isNotBlank())
            }.getOrElse { fail("Failed to create pre-authorized_code offer with custom data, error: $it") }
        }

    @Test
    fun `authorization_code offer is unaffected by the pre-authorized_code addition`() =
        runTest {
            effect {
                val credentialConfigurationIds = nonEmptySetOf(credentialIssuerMetadata.credentialConfigurationsSupported.first().id)
                val uri =
                    createCredentialsOffer(
                        CreateCredentialsOffer.Request(credentialConfigurationIds, preAuthorizedCode = false),
                    )
                val offerJson = assertNotNull(uri.getQueryParameter("credential_offer"))
                val offer = Json.decodeFromString<CredentialsOfferTO>(offerJson)

                assertNull(offer.grants?.preAuthorizedCode)
                val grant = assertNotNull(offer.grants?.authorizationCode)
                assertEquals(credentialIssuerMetadata.authorizationServers[0].externalForm, grant.authorizationServer)
            }.getOrElse { fail("Failed to create authorization_code offer, error: $it") }
        }
}
