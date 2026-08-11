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

import arrow.core.NonEmptySet
import arrow.core.raise.Raise
import arrow.core.raise.catch
import arrow.core.raise.context.ensure
import arrow.core.raise.context.ensureNotNull
import arrow.core.raise.context.raise
import arrow.core.toNonEmptySetOrNull
import com.eygraber.uri.Uri
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfiguration
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.CredentialIssuerMetaData
import eu.europa.ec.eudi.pidissuer.domain.HttpsUrl
import eu.europa.ec.eudi.pidissuer.port.out.token.GeneratePreAuthorizedCode
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlin.time.Clock
import kotlin.time.Duration

/**
 * Generates a Credential Offer and a QR Code in PNG format.
 */
class CreateCredentialsOffer(
    private val metadata: CredentialIssuerMetaData,
    val defaultCredentialOfferUri: Uri,
    private val allowedSchemes: NonEmptySet<SupportedCredentialOfferUriScheme>,
    private val generatePreAuthorizedCode: GeneratePreAuthorizedCode,
    private val preAuthorizedCodeDemoUsername: Username,
    private val preAuthorizedCodeExpiresIn: Duration,
    private val selfIssuedAuthorizationServer: HttpsUrl,
    private val clock: Clock,
) {
    init {
        val scheme = defaultCredentialOfferUri.scheme?.let { SupportedCredentialOfferUriScheme.ofOrNull(it) }
        require(null != scheme && scheme in allowedSchemes) {
            "defaultCredentialOfferUri must use one of the following schemes: ${allowedSchemes.joinToString { it.scheme }}, got: $scheme"
        }
    }

    context(_: Raise<Error>)
    suspend operator fun invoke(request: Request): Uri =
        context(metadata, defaultCredentialOfferUri, allowedSchemes) {
            val validatedIds = validate(request.credentialConfigurationIds)
            val credentialOffer =
                if (request.preAuthorizedCode) {
                    validatedIds.preAuthorizedCodeGrantOffer(
                        generatePreAuthorizedCode,
                        preAuthorizedCodeDemoUsername,
                        preAuthorizedCodeExpiresIn,
                        selfIssuedAuthorizationServer,
                        clock,
                        request.customData,
                    )
                } else {
                    validatedIds.authorizationCodeGrantOffer()
                }
            val credentialOfferUri = request.customCredentialsOfferUri?.toUri() ?: defaultCredentialOfferUri
            credentialOfferUri.append(credentialOffer)
        }

    data class Request(
        val credentialConfigurationIds: Set<CredentialConfigurationId>,
        val customCredentialsOfferUri: String? = null,
        val preAuthorizedCode: Boolean = false,
        /**
         * Operator-entered claim values, per Credential Configuration, only meaningful when [preAuthorizedCode]
         * is used - there is no interactive login step in that flow, so this is the only way to customize what
         * gets issued. Ignored for the authorization_code flow.
         */
        val customData: Map<CredentialConfigurationId, JsonObject> = emptyMap(),
    )

    /**
     * Errors that might be returned by [CreateCredentialsOffer].
     */
    sealed interface Error {
        /**
         * No Credentials Unique Ids have been provided.
         */
        data object MissingCredentialConfigurationIds : Error

        /**
         * The provided Credential Unique Ids are not valid.
         */
        data class InvalidCredentialConfigurationIds(
            val ids: NonEmptySet<CredentialConfigurationId>,
        ) : Error

        /**
         * Selected credential configuration ids contain mixing attestation categories.
         */
        data object MultipleAttestationCategories : Error

        /**
         * Indicates the Credentials Offer URI cannot be generated.
         */
        data class InvalidCredentialsOfferUri(
            val cause: Throwable,
        ) : Error
    }
}

context(_: Raise<CreateCredentialsOffer.Error>, metadata: CredentialIssuerMetaData)
private fun validate(unvalidatedIds: Set<CredentialConfigurationId>): NonEmptySet<CredentialConfigurationId> {
    val nonEmptyIds = unvalidatedIds.toNonEmptySetOrNull()
    ensureNotNull(nonEmptyIds) { CreateCredentialsOffer.Error.MissingCredentialConfigurationIds }
    val supportedIds = metadata.credentialConfigurationsSupported.map(CredentialConfiguration::id)
    val unknownIds = nonEmptyIds.filter { it !in supportedIds }.toNonEmptySetOrNull()
    if (unknownIds != null) raise(CreateCredentialsOffer.Error.InvalidCredentialConfigurationIds(unknownIds))
    val supported = metadata.credentialConfigurationsSupported
    val selectedCategories = nonEmptyIds.map { id -> supported.first { it.id == id }.category }.toSet()
    ensure(selectedCategories.size == 1) { CreateCredentialsOffer.Error.MultipleAttestationCategories }
    return nonEmptyIds
}

/**
 * Creates a new [CredentialsOfferTO] for an [Authorization Code Grant][AuthorizationCodeTO] flow.
 * When more than one Authorization Servers are provided, only the first one is included in the resulting
 * [CredentialsOfferTO] as per
 * [OpenId4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1-4.1.2.2).
 *
 * @param this@authorizationCodeGrantOffer the Ids of the Credentials to include in the generated request
 * @return the resulting TO
 */
context(metadata: CredentialIssuerMetaData)
private fun NonEmptySet<CredentialConfigurationId>.authorizationCodeGrantOffer(): CredentialsOfferTO {
    val authorizationCode =
        AuthorizationCodeTO(
            authorizationServer = metadata.authorizationServers.firstOrNull()?.externalForm,
        )
    return CredentialsOfferTO(
        metadata.id.externalForm,
        map(CredentialConfigurationId::value).toSet(),
        GrantsTO(authorizationCode),
    )
}

/**
 * Creates a new [CredentialsOfferTO] for a [Pre-Authorized Code Grant][PreAuthorizedCodeTO] flow. The generated
 * offer is bound to [username], since there is no interactive login step in this flow to establish who the
 * Credentials should be issued for.
 */
context(metadata: CredentialIssuerMetaData)
private suspend fun NonEmptySet<CredentialConfigurationId>.preAuthorizedCodeGrantOffer(
    generatePreAuthorizedCode: GeneratePreAuthorizedCode,
    username: Username,
    expiresIn: Duration,
    selfIssuedAuthorizationServer: HttpsUrl,
    clock: Clock,
    customData: Map<CredentialConfigurationId, JsonObject>,
): CredentialsOfferTO {
    val supported = metadata.credentialConfigurationsSupported
    val scopes = checkNotNull(map { id -> supported.first { it.id == id }.scope }.toNonEmptySetOrNull())
    val now = clock.now()
    val relevantCustomData = customData.filterKeys { it in this }
    val code = generatePreAuthorizedCode(now, expiresIn, username, scopes, relevantCustomData)
    val preAuthorizedCode =
        PreAuthorizedCodeTO(
            preAuthorizedCode = code.value,
            authorizationServer = selfIssuedAuthorizationServer.externalForm,
        )
    return CredentialsOfferTO(
        metadata.id.externalForm,
        map(CredentialConfigurationId::value).toSet(),
        GrantsTO(preAuthorizedCode = preAuthorizedCode),
    )
}

context(_: Raise<CreateCredentialsOffer.Error.InvalidCredentialsOfferUri>, allowedSchemes: NonEmptySet<SupportedCredentialOfferUriScheme>)
private fun String.toUri(): Uri =
    catch({
        val uri = Uri.parse(this)
        val scheme = uri.scheme?.let { SupportedCredentialOfferUriScheme.ofOrNull(it) }
        require(null != scheme && scheme in allowedSchemes) {
            "credentialsOfferUri must use one of the following schemes: ${allowedSchemes.joinToString()}, got: ${uri.scheme}"
        }
        uri
    }) { raise(CreateCredentialsOffer.Error.InvalidCredentialsOfferUri(it)) }

private fun Uri.append(credentialOffer: CredentialsOfferTO): Uri =
    buildUpon()
        .appendQueryParameter("credential_offer", Json.encodeToString(credentialOffer))
        .build()

enum class SupportedCredentialOfferUriScheme(
    val scheme: String,
) {
    OPENID_CREDENTIAL_OFFER("openid-credential-offer"),
    HAIP_VCI("haip-vci"),
    EU_EAA_OFFER("eu-eaa-offer"),
    HTTPS("https"),
    ;

    companion object {
        fun of(value: String): SupportedCredentialOfferUriScheme =
            ofOrNull(value) ?: throw IllegalArgumentException("Unsupported Credential Offer URI scheme: $value")

        fun ofOrNull(value: String): SupportedCredentialOfferUriScheme? = entries.firstOrNull { it.scheme.equals(value, ignoreCase = true) }
    }
}
