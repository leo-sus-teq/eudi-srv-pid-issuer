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
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import eu.europa.ec.eudi.pidissuer.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.pidissuer.adapter.out.nonce.NonceEncryptionKey
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerId
import eu.europa.ec.eudi.pidissuer.domain.PreAuthorizedCode
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.domain.toJavaDate
import eu.europa.ec.eudi.pidissuer.port.input.Username
import eu.europa.ec.eudi.pidissuer.port.out.token.GeneratePreAuthorizedCode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.util.UUID
import kotlin.time.Duration
import kotlin.time.Instant

internal const val PRE_AUTHORIZED_CODE_JWT_TYPE = "pre-authorized-code+jwt"

/**
 * Generates a [PreAuthorizedCode] and encrypts it as a self-contained [EncryptedJWT] with Nimbus, mirroring
 * [eu.europa.ec.eudi.pidissuer.adapter.out.nonce.GenerateNonceAndEncryptWithNimbus]. The username and scopes it
 * was generated for are embedded in the encrypted payload rather than tracked server-side.
 */
internal class GeneratePreAuthorizedCodeWithNimbus(
    private val issuer: CredentialIssuerId,
    private val encryptionKey: NonceEncryptionKey,
) : GeneratePreAuthorizedCode {
    private val encrypter =
        ECDHEncrypter(encryptionKey.encryptionKey)
            .apply {
                jcaContext.provider = BouncyCastleProvider()
            }

    override suspend fun invoke(
        generatedAt: Instant,
        expiresIn: Duration,
        username: Username,
        scopes: NonEmptySet<Scope>,
        customData: Map<CredentialConfigurationId, JsonObject>,
    ): PreAuthorizedCode =
        withContext(Dispatchers.Default) {
            val expiresAt = generatedAt + expiresIn

            val header =
                JWEHeader
                    .Builder(encryptionKey.algorithm, encryptionKey.method)
                    .type(JOSEObjectType(PRE_AUTHORIZED_CODE_JWT_TYPE))
                    .build()
            val claimSet =
                JWTClaimsSet
                    .Builder()
                    .apply {
                        issuer(issuer.externalForm)
                        audience(issuer.externalForm)
                        jwtID(UUID.randomUUID().toString())
                        claim("username", username)
                        claim("scope", scopes.joinToString(" ") { it.value })
                        if (customData.isNotEmpty()) {
                            val wrapped = buildJsonObject { customData.forEach { (id, data) -> put(id.value, data) } }
                            claim("custom_data", jsonSupport.encodeToString(JsonObject.serializer(), wrapped))
                        }
                        issueTime(generatedAt.toJavaDate())
                        expirationTime(expiresAt.toJavaDate())
                    }.build()

            val value =
                EncryptedJWT(header, claimSet)
                    .apply { encrypt(encrypter) }
                    .serialize()
            PreAuthorizedCode(value)
        }
}
