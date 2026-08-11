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
@file:UseSerializers(NonEmptyListSerializer::class)

package eu.europa.ec.eudi.pidissuer.port.input

import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import arrow.core.serialization.NonEmptyListSerializer
import eu.europa.ec.eudi.pidissuer.adapter.input.web.security.DPoPConfigurationProperties
import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers

/**
 * A minimal [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html) Authorization Server Metadata document,
 * describing pid-issuer's own limited role as authorization server for the
 * `urn:ietf:params:oauth:grant-type:pre-authorized_code` grant only.
 */
@Serializable
data class AuthorizationServerMetadataTO(
    @Required @SerialName("issuer") val issuer: String,
    @Required @SerialName("token_endpoint") val tokenEndpoint: String,
    @Required @SerialName("grant_types_supported") val grantTypesSupported: NonEmptyList<String>,
    @SerialName("dpop_signing_alg_values_supported") val dpopSigningAlgValuesSupported: NonEmptyList<String>? = null,
)

class GetAuthorizationServerMetadata(
    private val issuerPublicUrl: HttpsUrl,
    private val tokenEndpoint: HttpsUrl,
    private val dPoPConfigurationProperties: DPoPConfigurationProperties,
) {
    fun unsigned(): AuthorizationServerMetadataTO =
        AuthorizationServerMetadataTO(
            issuer = issuerPublicUrl.externalForm,
            tokenEndpoint = tokenEndpoint.externalForm,
            grantTypesSupported = nonEmptyListOf(IssuePreAuthorizedCodeAccessToken.GRANT_TYPE),
            dpopSigningAlgValuesSupported =
                dPoPConfigurationProperties.algorithms
                    .map { it.name }
                    .let { nonEmptyListOf(it.first(), *it.drop(1).toTypedArray()) },
        )
}
