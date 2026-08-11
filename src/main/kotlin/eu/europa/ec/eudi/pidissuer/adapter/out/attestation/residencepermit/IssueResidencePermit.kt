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
package eu.europa.ec.eudi.pidissuer.adapter.out.attestation.residencepermit

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

private val log = LoggerFactory.getLogger(IssueResidencePermit::class.java)

class IssueResidencePermit(
    override val configuration: SdJwtVcCredentialConfiguration,
    private val clock: Clock,
    private val getAttestationAttributes: GetAttestationAttributes<ResidencePermit>,
    private val validateProof: ValidateProof,
    private val generateNotificationId: GenerateNotificationId?,
    private val storeIssuedCredential: StoreIssuedCredential,
    private val encodeAttestationAttributes: EncodeAttestationAttributes<ResidencePermit>,
) : AttestationIssuer {
    context(_: Raise<IssueCredentialError>, authorizationContext: AuthorizationContext)
    override suspend fun invoke(request: AuthorizedCredentialRequest): CredentialResponse {
        log.info("Issuing Residence Permit")
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
            .also { log.info("Successfully issued Residence Permit") }
    }

    companion object {
        val CONFIGURATION_ID = CredentialConfigurationId("urn:eudi:residence.permit:1:dc+sd-jwt-compact")
        val SCOPE = Scope("urn:eudi:residence.permit:1:dc+sd-jwt")
        val TYPE = SdJwtVcType("urn:eudi:residence.permit:1")

        operator fun invoke(
            sdJwtVcSerialization: SdJwtVcSerialization = SdJwtVcSerialization.Compact,
            clock: Clock,
            getAttestationAttributes: GetAttestationAttributes<ResidencePermit>,
            issuerSigningKey: IssuerSigningKey,
            digestsHashAlgorithm: HashAlgorithm,
            deviceBinding: DeviceBinding.Required,
            credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
            validity: Duration,
            validateProof: ValidateProof,
            generateNotificationId: GenerateNotificationId?,
            storeIssuedCredential: StoreIssuedCredential,
        ): IssueResidencePermit {
            val credentialConfiguration = cfg(deviceBinding, credentialReusePolicy, validity, issuerSigningKey)
            return IssueResidencePermit(
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
                    build = { residencePermit(it) },
                ),
            )
        }

        /**
         * Builds a fixed demo dataset, overridden field-by-field by whatever the operator typed into the
         * offer-generation form (see [ResidencePermit.overriddenBy]).
         */
        fun demoAttestationAttributes(clock: Clock): GetAttestationAttributes<ResidencePermit> =
            object : GetAttestationAttributes<ResidencePermit> {
                context(_: Raise<IssueCredentialError.AttestationDatasetNotFound>, authorizationContext: AuthorizationContext)
                override suspend fun invoke(): ResidencePermit {
                    val default = ResidencePermit.default(clock.now())
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
        IssueResidencePermit.CONFIGURATION_ID,
        IssueResidencePermit.SCOPE,
        display = nonEmptyListOf(CredentialDisplay(DisplayName.en("Residence Permit"))),
        claims = ResidencePermitClaims.all(),
        deviceBinding = deviceBinding,
        category = AttestationCategory.EuPubEaa,
        reusePolicy = credentialReusePolicy,
        validity = validity,
        type = IssueResidencePermit.TYPE,
        credentialSigningAlgorithmsSupported = nonEmptySetOf(issuerSigningKey.signingAlgorithm),
        publicKey = issuerSigningKey.key.toPublicJWK(),
    )

fun SdJwtObjectBuilder.residencePermit(residencePermit: ResidencePermit) {
    with(residencePermit) {
        sdClaim(ResidencePermitClaims.FamilyName.name, familyName.value)
        sdClaim(ResidencePermitClaims.GivenName.name, givenName.value)
        sdClaim(ResidencePermitClaims.BirthDate.name, birthDate.toString())
        sdClaim(ResidencePermitClaims.Nationality.name, nationality.code)
        sdClaim(ResidencePermitClaims.DocumentNumber.name, documentNumber.value)
        sdClaim(ResidencePermitClaims.AdministrativeNumber.name, administrativeNumber.value)
        claim(ResidencePermitClaims.IssuingAuthority.name, issuingAuthority.value)
        claim(ResidencePermitClaims.IssuingCountry.name, issuingCountry.code)
        claim(ResidencePermitClaims.DateOfIssuance.name, dateOfIssuance.toString())
        claim(ResidencePermitClaims.DateOfExpiry.name, dateOfExpiry.toString())
        sdClaim(ResidencePermitClaims.ResidentAddress.name, residentAddress.value)
    }
}
