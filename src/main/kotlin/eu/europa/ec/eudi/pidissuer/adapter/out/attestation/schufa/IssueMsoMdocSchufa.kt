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
package eu.europa.ec.eudi.pidissuer.adapter.out.attestation.schufa

import arrow.core.nonEmptyListOf
import arrow.core.nonEmptySetOf
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.IssueMdoc
import eu.europa.ec.eudi.pidissuer.adapter.out.coseAlgorithm
import eu.europa.ec.eudi.pidissuer.adapter.out.format.mdoc.encodeAttestationAttributesInMdoc
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.out.attestation.GetAttestationAttributes
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredential
import eu.europa.ec.eudi.pidissuer.port.out.proof.ValidateProof
import eu.europa.ec.eudi.pidissuer.port.out.status.AllocateStatus
import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.toDataElement
import id.walt.mdoc.doc.MDocBuilder
import kotlin.time.Clock
import kotlin.time.Duration

val SchufaMsoMdocScope: Scope = Scope("eudi.schufa.1")
val SchufaMsoMdocConfigurationId: CredentialConfigurationId = CredentialConfigurationId(SchufaMsoMdocScope.value)

private fun schufaMsoMdocCfg(
    credentialSigningAlgorithm: CoseAlgorithm,
    deviceBinding: DeviceBinding.Required,
    credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    validity: Duration,
): MsoMdocCredentialConfiguration =
    MsoMdocCredentialConfiguration(
        id = SchufaMsoMdocConfigurationId,
        docType = SchufaMsoMdocScope.value,
        display = nonEmptyListOf(CredentialDisplay(DisplayName.en("Schufa Credit Report"))),
        claims = MsoMdocSchufaClaims.all(),
        credentialSigningAlgorithmsSupported = nonEmptySetOf(credentialSigningAlgorithm),
        scope = SchufaMsoMdocScope,
        deviceBinding = deviceBinding,
        category = AttestationCategory.Eaa,
        reusePolicy = credentialReusePolicy,
        validity = validity,
    )

@Suppress("FunctionName")
fun IssueMsoMdocSchufa(
    credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    deviceBinding: DeviceBinding.Required,
    validity: Duration,
    clock: Clock,
    validateProof: ValidateProof,
    generateNotificationId: GenerateNotificationId?,
    storeIssuedCredential: StoreIssuedCredential,
    getAttestationAttributes: GetAttestationAttributes<Schufa>,
    allocateStatus: AllocateStatus,
    issuerSigningKey: IssuerSigningKey,
): IssueMdoc<Schufa> {
    val configuration = schufaMsoMdocCfg(issuerSigningKey.coseAlgorithm, deviceBinding, credentialReusePolicy, validity)
    return IssueMdoc(
        configuration,
        clock,
        validateProof,
        generateNotificationId,
        storeIssuedCredential,
        getAttestationAttributes,
        allocateStatus,
        encodeAttestationAttributesInMdoc(configuration.docType, issuerSigningKey) { schufa -> addItemsToSign(schufa) },
    )
}

private fun MDocBuilder.addItemsToSign(schufa: Schufa) {
    addItemToSign(MsoMdocSchufaClaims.FamilyName, schufa.familyName.value.toDataElement())
    addItemToSign(MsoMdocSchufaClaims.GivenName, schufa.givenName.value.toDataElement())
    addItemToSign(MsoMdocSchufaClaims.BirthDate, schufa.birthDate.toDataElement())
    addItemToSign(MsoMdocSchufaClaims.CreditScore, schufa.creditScore.value.toDataElement())
    addItemToSign(MsoMdocSchufaClaims.ReportDate, schufa.reportDate.toDataElement())
    addItemToSign(MsoMdocSchufaClaims.ValidUntil, schufa.validUntil.toDataElement())
    addItemToSign(MsoMdocSchufaClaims.IssuingEntity, schufa.issuingEntity.value.toDataElement())
}

private fun MDocBuilder.addItemToSign(
    claim: ClaimDefinition,
    value: DataElement,
) {
    addItemToSign(MsoMdocSchufaClaims.nameSpace, claim.name, value)
}
