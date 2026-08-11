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
package eu.europa.ec.eudi.pidissuer.adapter.out.attestation.ehic

import arrow.core.nonEmptyListOf
import arrow.core.nonEmptySetOf
import arrow.core.raise.Raise
import arrow.core.toNonEmptyListOrNull
import arrow.fx.coroutines.parMap
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.format.AttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.EncodeAttestationAttributes
import eu.europa.ec.eudi.pidissuer.adapter.out.format.sdjwtvc.SdJwtVcSerialization
import eu.europa.ec.eudi.pidissuer.adapter.out.format.sdjwtvc.encodeAttestationAttributesInSdJwtVc
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.attestation.AttestationIssuer
import eu.europa.ec.eudi.pidissuer.port.out.attestation.GetAttestationAttributes
import eu.europa.ec.eudi.pidissuer.port.out.attestation.keyAttestation
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.proof.ValidateProof
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import eu.europa.ec.eudi.sdjwt.dsl.values.SdJwtObjectBuilder
import kotlinx.coroutines.Dispatchers
import org.slf4j.LoggerFactory
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.uuid.Uuid

private val log = LoggerFactory.getLogger(IssueEhic::class.java)

class IssueEhic(
    override val configuration: SdJwtVcCredentialConfiguration,
    private val clock: Clock,
    private val getAttestationAttributes: GetAttestationAttributes<Ehic>,
    private val validateProof: ValidateProof,
    private val generateNotificationId: GenerateNotificationId?,
    private val storeIssuedCredential: StoreIssuedCredential,
    private val encodeAttestationAttributes: EncodeAttestationAttributes<Ehic>,
) : AttestationIssuer {
    context(_: Raise<IssueCredentialError>, authorizationContext: AuthorizationContext)
    override suspend fun invoke(request: AuthorizedCredentialRequest): CredentialResponse {
        log.info("Issuing EHIC")
        val issuedAt = clock.now()
        val keyAttestation = context(validateProof) { keyAttestation(request, issuedAt) }
        val attributes = getAttestationAttributes()
        val expiresAt = issuedAt + configuration.validity
        val notificationId = generateNotificationId?.invoke()
        val clientStatus = authorizationContext.clientStatus.status.statusList
        val keyStorageStatus = keyAttestation.keyStorageStatus?.status?.statusList
        val issuedCredentials =
            keyAttestation.keys.value
                .parMap(Dispatchers.Default, 4) { deviceKey ->
                    val attestedAttributes =
                        AttestationAttributes(attributes, issuedAt, expiresAt, notBefore = issuedAt, deviceKey, status = null)
                    val attestationInstance = encodeAttestationAttributes(attestedAttributes)

                    storeIssuedCredential(
                        IssuedCredential(
                            format = SD_JWT_VC_FORMAT,
                            type = configuration.type.value,
                            attestedAttributes.issuedAt,
                            attestedAttributes.expiresAt,
                            notificationId,
                            attestedAttributes.status,
                            clientStatus,
                            keyStorageStatus,
                        ),
                    )

                    attestationInstance
                }.toNonEmptyListOrNull()

        checkNotNull(issuedCredentials) { "Cannot happen" }

        return CredentialResponse
            .Issued(issuedCredentials, notificationId)
            .also { log.info("Successfully issued EHIC") }
    }

    companion object {
        val CONFIGURATION_ID = CredentialConfigurationId("urn:eudi:ehic:1:dc+sd-jwt-compact")
        val SCOPE = Scope("urn:eudi:ehic:1:dc+sd-jwt")
        val TYPE = SdJwtVcType("urn:eudi:ehic:1")

        operator fun invoke(
            sdJwtVcSerialization: SdJwtVcSerialization = SdJwtVcSerialization.Compact,
            clock: Clock,
            getAttestationAttributes: GetAttestationAttributes<Ehic>,
            issuerSigningKey: IssuerSigningKey,
            digestsHashAlgorithm: HashAlgorithm,
            deviceBinding: DeviceBinding.Required,
            credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
            validity: Duration,
            validateProof: ValidateProof,
            generateNotificationId: GenerateNotificationId?,
            storeIssuedCredential: StoreIssuedCredential,
        ): IssueEhic {
            val credentialConfiguration = cfg(deviceBinding, credentialReusePolicy, validity, issuerSigningKey)
            return IssueEhic(
                credentialConfiguration,
                clock,
                getAttestationAttributes,
                validateProof,
                generateNotificationId,
                storeIssuedCredential,
                encodeAttestationAttributesInSdJwtVc(
                    sdJwtVcSerialization,
                    digestsHashAlgorithm,
                    issuerSigningKey,
                    vct = credentialConfiguration.type,
                    generateJwtId = { Uuid.random().toHexDashString() },
                    build = { ehic(it) },
                ),
            )
        }

        /**
         * Builds a fixed demo dataset, overridden field-by-field by whatever the operator typed into the
         * offer-generation form (see [Ehic.overriddenBy]).
         */
        fun demoAttestationAttributes(clock: Clock): GetAttestationAttributes<Ehic> =
            object : GetAttestationAttributes<Ehic> {
                context(_: Raise<IssueCredentialError.AttestationDatasetNotFound>, authorizationContext: AuthorizationContext)
                override suspend fun invoke(): Ehic {
                    val default = Ehic.default(clock.now())
                    val customData = authorizationContext.customData[CONFIGURATION_ID]
                    return if (customData != null) default.overriddenBy(customData) else default
                }
            }
    }
}

private fun cfg(
    deviceBinding: DeviceBinding.Required,
    credentialReusePolicy: CredentialReusePolicy,
    validity: Duration,
    issuerSigningKey: IssuerSigningKey,
): SdJwtVcCredentialConfiguration =
    SdJwtVcCredentialConfiguration(
        IssueEhic.CONFIGURATION_ID,
        IssueEhic.SCOPE,
        display = nonEmptyListOf(CredentialDisplay(DisplayName.en("Health Insurance Card"))),
        claims = EhicClaims.all(),
        deviceBinding = deviceBinding,
        category = AttestationCategory.EuPubEaa,
        reusePolicy = credentialReusePolicy,
        validity = validity,
        type = IssueEhic.TYPE,
        credentialSigningAlgorithmsSupported = nonEmptySetOf(issuerSigningKey.signingAlgorithm),
        publicKey = issuerSigningKey.key.toPublicJWK(),
    )

fun SdJwtObjectBuilder.ehic(ehic: Ehic) {
    with(ehic) {
        sdClaim(EhicClaims.FamilyName.name, familyName.value)
        sdClaim(EhicClaims.GivenName.name, givenName.value)
        sdClaim(EhicClaims.BirthDate.name, birthDate.toString())
        sdClaim(EhicClaims.PersonalAdministrativeNumber.name, personalAdministrativeNumber.value)
        claim(EhicClaims.IssuingAuthorityId.name, issuingAuthority.id.value)
        claim(EhicClaims.IssuingAuthorityName.name, issuingAuthority.name.value)
        claim(EhicClaims.IssuingCountry.name, issuingCountry.code)
        claim(EhicClaims.DateOfExpiry.name, dateOfExpiry.toString())
    }
}
