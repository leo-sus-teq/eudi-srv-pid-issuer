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

import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.mdl.IsoAlpha2CountryCode
import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.stringFieldOrNull
import eu.europa.ec.eudi.pidissuer.domain.NonBlankString
import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlinx.serialization.json.JsonObject
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

typealias FamilyName = NonBlankString
typealias GivenName = NonBlankString
typealias DocumentNumber = NonBlankString
typealias AdministrativeNumber = NonBlankString
typealias IssuingAuthority = NonBlankString
typealias ResidentAddress = NonBlankString

/**
 * A (heavily simplified, demo-only) Residence Permit.
 */
data class ResidencePermit(
    val familyName: FamilyName,
    val givenName: GivenName,
    val birthDate: LocalDate,
    val nationality: IsoAlpha2CountryCode,
    val documentNumber: DocumentNumber,
    val administrativeNumber: AdministrativeNumber,
    val issuingAuthority: IssuingAuthority,
    val issuingCountry: IsoAlpha2CountryCode,
    val dateOfIssuance: LocalDate,
    val dateOfExpiry: LocalDate,
    val residentAddress: ResidentAddress,
) {
    companion object {
        /**
         * A plausible, fixed demo dataset - used whenever the operator didn't type in custom values (e.g. the
         * authorization_code flow, or a pre-authorized offer generated without filling in the form).
         */
        fun default(generatedAt: Instant): ResidencePermit =
            ResidencePermit(
                familyName = FamilyName("Neal"),
                givenName = GivenName("Tyler"),
                birthDate = LocalDate(1955, 4, 12),
                nationality = IsoAlpha2CountryCode("US"),
                documentNumber = DocumentNumber("RP1234567"),
                administrativeNumber = AdministrativeNumber("ADM9876543"),
                issuingAuthority = IssuingAuthority("Austrian Federal Office for Immigration and Asylum"),
                issuingCountry = IsoAlpha2CountryCode("AT"),
                dateOfIssuance = generatedAt.toLocalDate(),
                dateOfExpiry = (generatedAt + (5 * 365).days).toLocalDate(),
                residentAddress = ResidentAddress("Traunerstrasse 1, 4021 Linz, Austria"),
            )

        private fun Instant.toLocalDate(): LocalDate = toLocalDateTime(TimeZone.currentSystemDefault()).date
    }
}

/**
 * Overrides only the fields present in operator-entered [customData], keeping this [ResidencePermit]'s values for
 * the rest.
 */
fun ResidencePermit.overriddenBy(customData: JsonObject): ResidencePermit =
    copy(
        familyName = customData.stringFieldOrNull("family_name")?.let(::FamilyName) ?: familyName,
        givenName = customData.stringFieldOrNull("given_name")?.let(::GivenName) ?: givenName,
        birthDate = customData.stringFieldOrNull("birth_date")?.let(LocalDate::parse) ?: birthDate,
        nationality = customData.stringFieldOrNull("nationality")?.let(::IsoAlpha2CountryCode) ?: nationality,
        documentNumber = customData.stringFieldOrNull("document_number")?.let(::DocumentNumber) ?: documentNumber,
        administrativeNumber =
            customData.stringFieldOrNull("administrative_number")?.let(::AdministrativeNumber) ?: administrativeNumber,
        issuingAuthority = customData.stringFieldOrNull("issuing_authority")?.let(::IssuingAuthority) ?: issuingAuthority,
        issuingCountry = customData.stringFieldOrNull("issuing_country")?.let(::IsoAlpha2CountryCode) ?: issuingCountry,
        dateOfIssuance = customData.stringFieldOrNull("date_of_issuance")?.let(LocalDate::parse) ?: dateOfIssuance,
        dateOfExpiry = customData.stringFieldOrNull("date_of_expiry")?.let(LocalDate::parse) ?: dateOfExpiry,
        residentAddress = customData.stringFieldOrNull("resident_address")?.let(::ResidentAddress) ?: residentAddress,
    )
