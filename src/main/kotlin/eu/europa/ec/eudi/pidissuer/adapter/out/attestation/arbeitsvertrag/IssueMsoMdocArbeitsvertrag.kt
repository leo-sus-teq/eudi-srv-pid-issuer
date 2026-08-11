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
package eu.europa.ec.eudi.pidissuer.adapter.out.attestation.arbeitsvertrag

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

val ArbeitsvertragMsoMdocScope: Scope = Scope("eudi.trusteq.arbeitsvertrag.1")
val ArbeitsvertragMsoMdocConfigurationId: CredentialConfigurationId = CredentialConfigurationId(ArbeitsvertragMsoMdocScope.value)

private fun arbeitsvertragMsoMdocCfg(
    credentialSigningAlgorithm: CoseAlgorithm,
    deviceBinding: DeviceBinding.Required,
    credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    validity: Duration,
): MsoMdocCredentialConfiguration =
    MsoMdocCredentialConfiguration(
        id = ArbeitsvertragMsoMdocConfigurationId,
        docType = ArbeitsvertragMsoMdocScope.value,
        display = nonEmptyListOf(CredentialDisplay(DisplayName.en("Employment Certificate (TRUSTEQ)"))),
        claims = MsoMdocArbeitsvertragClaims.all(),
        credentialSigningAlgorithmsSupported = nonEmptySetOf(credentialSigningAlgorithm),
        scope = ArbeitsvertragMsoMdocScope,
        deviceBinding = deviceBinding,
        category = AttestationCategory.Eaa,
        reusePolicy = credentialReusePolicy,
        validity = validity,
    )

@Suppress("FunctionName")
fun IssueMsoMdocArbeitsvertrag(
    credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
    deviceBinding: DeviceBinding.Required,
    validity: Duration,
    clock: Clock,
    validateProof: ValidateProof,
    generateNotificationId: GenerateNotificationId?,
    storeIssuedCredential: StoreIssuedCredential,
    getAttestationAttributes: GetAttestationAttributes<Arbeitsvertrag>,
    allocateStatus: AllocateStatus,
    issuerSigningKey: IssuerSigningKey,
): IssueMdoc<Arbeitsvertrag> {
    val configuration = arbeitsvertragMsoMdocCfg(issuerSigningKey.coseAlgorithm, deviceBinding, credentialReusePolicy, validity)
    return IssueMdoc(
        configuration,
        clock,
        validateProof,
        generateNotificationId,
        storeIssuedCredential,
        getAttestationAttributes,
        allocateStatus,
        encodeAttestationAttributesInMdoc(configuration.docType, issuerSigningKey) { arbeitsvertrag -> addItemsToSign(arbeitsvertrag) },
    )
}

private fun MDocBuilder.addItemsToSign(arbeitsvertrag: Arbeitsvertrag) {
    addItemToSign(MsoMdocArbeitsvertragClaims.EmployeeFamilyName, arbeitsvertrag.employeeFamilyName.value.toDataElement())
    addItemToSign(MsoMdocArbeitsvertragClaims.EmployeeGivenName, arbeitsvertrag.employeeGivenName.value.toDataElement())
    addItemToSign(MsoMdocArbeitsvertragClaims.JobTitle, arbeitsvertrag.jobTitle.value.toDataElement())
    addItemToSign(MsoMdocArbeitsvertragClaims.EmploymentStartDate, arbeitsvertrag.employmentStartDate.toDataElement())
    addItemToSign(MsoMdocArbeitsvertragClaims.Employer, arbeitsvertrag.employer.value.toDataElement())
    addItemToSign(MsoMdocArbeitsvertragClaims.ContractType, arbeitsvertrag.contractType.value.toDataElement())
    addItemToSign(MsoMdocArbeitsvertragClaims.Department, arbeitsvertrag.department.value.toDataElement())
}

private fun MDocBuilder.addItemToSign(
    claim: ClaimDefinition,
    value: DataElement,
) {
    addItemToSign(MsoMdocArbeitsvertragClaims.nameSpace, claim.name, value)
}
