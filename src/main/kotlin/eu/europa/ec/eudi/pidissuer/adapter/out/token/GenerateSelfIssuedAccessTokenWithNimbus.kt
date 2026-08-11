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

import arrow.core.NonEmptySet
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation
import eu.europa.ec.eudi.pidissuer.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.pidissuer.adapter.out.nonce.NonceEncryptionKey
import eu.europa.ec.eudi.pidissuer.domain.ClientStatus
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.domain.toJavaDate
import eu.europa.ec.eudi.pidissuer.port.input.ClientId
import eu.europa.ec.eudi.pidissuer.port.input.Username
import eu.europa.ec.eudi.pidissuer.port.out.token.GenerateSelfIssuedAccessToken
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import org.bouncycastle.jce.provider.BouncyCastleProvider
import kotlin.time.Duration
import kotlin.time.Instant

internal const val SELF_ISSUED_ACCESS_TOKEN_JWT_TYPE = "self-issued-access-token+jwt"

/**
 * Mints a self-issued, DPoP-bound access token as an encrypted [EncryptedJWT] with Nimbus, mirroring
 * [eu.europa.ec.eudi.pidissuer.adapter.out.nonce.GenerateNonceAndEncryptWithNimbus]. Every claim the existing
 * DPoP/resource-server pipeline requires (`cnf`, `username`, `client_id`, `scope`, `client_status`) is embedded
 * directly, since this token is never sent to Keycloak for introspection.
 */
internal class GenerateSelfIssuedAccessTokenWithNimbus(
    private val issuer: CredentialIssuerId,
    private val encryptionKey: NonceEncryptionKey,
) : GenerateSelfIssuedAccessToken {
    private val encrypter =
        ECDHEncrypter(encryptionKey.encryptionKey)
            .apply {
                jcaContext.provider = BouncyCastleProvider()
            }

    override suspend fun invoke(
        generatedAt: Instant,
        expiresIn: Duration,
        username: Username,
        clientId: ClientId,
        scopes: NonEmptySet<Scope>,
        dpopJwkThumbprint: JWKThumbprintConfirmation,
        clientStatus: ClientStatus,
        customData: Map<CredentialConfigurationId, JsonObject>,
    ): String =
        withContext(Dispatchers.Default) {
            val expiresAt = generatedAt + expiresIn
            val cnfClaim = dpopJwkThumbprint.toJWTClaim()
            val clientStatusClaim = JSONObjectUtils.parse(jsonSupport.encodeToString(ClientStatus.serializer(), clientStatus))

            val header =
                JWEHeader
                    .Builder(encryptionKey.algorithm, encryptionKey.method)
                    .type(JOSEObjectType(SELF_ISSUED_ACCESS_TOKEN_JWT_TYPE))
                    .build()
            val claimSet =
                JWTClaimsSet
                    .Builder()
                    .apply {
                        issuer(issuer.externalForm)
                        audience(issuer.externalForm)
                        claim("username", username)
                        claim("client_id", clientId)
                        claim("scope", scopes.joinToString(" ") { it.value })
                        claim(cnfClaim.key, cnfClaim.value)
                        claim("client_status", clientStatusClaim)
                        if (customData.isNotEmpty()) {
                            val wrapped = buildJsonObject { customData.forEach { (id, data) -> put(id.value, data) } }
                            val customDataClaim = JSONObjectUtils.parse(jsonSupport.encodeToString(JsonObject.serializer(), wrapped))
                            claim("custom_data", customDataClaim)
                        }
                        issueTime(generatedAt.toJavaDate())
                        expirationTime(expiresAt.toJavaDate())
                    }.build()

            EncryptedJWT(header, claimSet)
                .apply { encrypt(encrypter) }
                .serialize()
        }
}
