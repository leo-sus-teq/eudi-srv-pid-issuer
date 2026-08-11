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

import arrow.core.raise.Raise
import arrow.core.raise.context.ensure
import arrow.core.raise.context.raise
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation
import eu.europa.ec.eudi.pidissuer.domain.ClientStatus
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.NoClientStatus
import eu.europa.ec.eudi.pidissuer.domain.PreAuthorizedCode
import eu.europa.ec.eudi.pidissuer.domain.StatusClaim
import eu.europa.ec.eudi.pidissuer.domain.StatusListToken
import eu.europa.ec.eudi.pidissuer.port.out.token.GenerateSelfIssuedAccessToken
import eu.europa.ec.eudi.pidissuer.port.out.token.PreAuthorizedCodeRedemption
import eu.europa.ec.eudi.pidissuer.port.out.token.VerifyAndConsumePreAuthorizedCode
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

/**
 * Exchanges a [PreAuthorizedCode] for a self-issued, DPoP-bound access token, implementing the
 * `urn:ietf:params:oauth:grant-type:pre-authorized_code` grant at the issuer's own `/token` endpoint.
 */
class IssuePreAuthorizedCodeAccessToken(
    private val credentialIssuerMetadata: CredentialIssuerMetaData,
    private val verifyAndConsumePreAuthorizedCode: VerifyAndConsumePreAuthorizedCode,
    private val generateSelfIssuedAccessToken: GenerateSelfIssuedAccessToken,
    private val accessTokenExpiresIn: Duration,
    private val clock: Clock,
) {
    sealed interface Error {
        data object UnsupportedGrantType : Error

        data object InvalidGrant : Error
    }

    data class Request(
        val grantType: String,
        val preAuthorizedCode: String,
        val dpopJwkThumbprint: JWKThumbprintConfirmation,
        val clientId: ClientId,
    )

    data class Response(
        val accessToken: String,
        val expiresIn: Duration,
    )

    context(_: Raise<Error>)
    suspend operator fun invoke(request: Request): Response {
        ensure(request.grantType == GRANT_TYPE) { Error.UnsupportedGrantType }

        val now = clock.now()
        val redemption = verifyAndConsumePreAuthorizedCode(PreAuthorizedCode(request.preAuthorizedCode), now)
        val valid =
            when (redemption) {
                is PreAuthorizedCodeRedemption.Valid -> redemption
                PreAuthorizedCodeRedemption.Invalid -> raise(Error.InvalidGrant)
            }

        val clientStatus =
            ClientStatus(
                status = StatusClaim(StatusListToken(NoClientStatus, index = 0u)),
                expiresAt = now + credentialIssuerMetadata.preferredClientStatusPeriod.value + 1.days,
            )
        val accessToken =
            generateSelfIssuedAccessToken(
                generatedAt = now,
                expiresIn = accessTokenExpiresIn,
                username = valid.username,
                clientId = request.clientId,
                scopes = valid.scopes,
                dpopJwkThumbprint = request.dpopJwkThumbprint,
                clientStatus = clientStatus,
                customData = valid.customData,
            )
        return Response(accessToken, accessTokenExpiresIn)
    }

    companion object {
        const val GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    }
}
