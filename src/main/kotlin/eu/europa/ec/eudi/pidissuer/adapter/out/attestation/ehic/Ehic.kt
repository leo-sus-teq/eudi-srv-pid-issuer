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
typealias PersonalAdministrativeNumber = NonBlankString

data class IssuingAuthority(
    val id: NonBlankString,
    val name: NonBlankString,
)

/**
 * A (heavily simplified, demo-only) European Health Insurance Card.
 */
data class Ehic(
    val familyName: FamilyName,
    val givenName: GivenName,
    val birthDate: LocalDate,
    val personalAdministrativeNumber: PersonalAdministrativeNumber,
    val issuingAuthority: IssuingAuthority,
    val issuingCountry: IsoAlpha2CountryCode,
    val dateOfExpiry: LocalDate,
) {
    companion object {
        /**
         * A plausible, fixed demo dataset - used whenever the operator didn't type in custom values (e.g. the
         * authorization_code flow, or a pre-authorized offer generated without filling in the form).
         */
        fun default(generatedAt: Instant): Ehic =
            Ehic(
                familyName = FamilyName("Neal"),
                givenName = GivenName("Tyler"),
                birthDate = LocalDate(1955, 4, 12),
                personalAdministrativeNumber = PersonalAdministrativeNumber("80750401734"),
                issuingAuthority = IssuingAuthority(NonBlankString("AT-SVN"), NonBlankString("Austrian Social Insurance")),
                issuingCountry = IsoAlpha2CountryCode("AT"),
                dateOfExpiry = (generatedAt + (3 * 365).days).toLocalDate(),
            )

        private fun Instant.toLocalDate(): LocalDate = toLocalDateTime(TimeZone.currentSystemDefault()).date
    }
}

/**
 * Overrides only the fields present in operator-entered [customData], keeping this [Ehic]'s values for the rest.
 */
fun Ehic.overriddenBy(customData: JsonObject): Ehic =
    copy(
        familyName = customData.stringFieldOrNull("family_name")?.let(::FamilyName) ?: familyName,
        givenName = customData.stringFieldOrNull("given_name")?.let(::GivenName) ?: givenName,
        birthDate = customData.stringFieldOrNull("birth_date")?.let(LocalDate::parse) ?: birthDate,
        personalAdministrativeNumber =
            customData.stringFieldOrNull("personal_administrative_number")?.let(::PersonalAdministrativeNumber)
                ?: personalAdministrativeNumber,
        issuingAuthority =
            IssuingAuthority(
                id = customData.stringFieldOrNull("issuing_authority_id")?.let(::NonBlankString) ?: issuingAuthority.id,
                name = customData.stringFieldOrNull("issuing_authority_name")?.let(::NonBlankString) ?: issuingAuthority.name,
            ),
        issuingCountry = customData.stringFieldOrNull("issuing_country")?.let(::IsoAlpha2CountryCode) ?: issuingCountry,
        dateOfExpiry = customData.stringFieldOrNull("date_of_expiry")?.let(LocalDate::parse) ?: dateOfExpiry,
    )
