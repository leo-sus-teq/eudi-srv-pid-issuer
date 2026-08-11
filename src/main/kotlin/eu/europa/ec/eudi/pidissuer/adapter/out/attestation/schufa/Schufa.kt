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
typealias CreditScore = NonBlankString
typealias IssuingEntity = NonBlankString

/**
 * A (heavily simplified, demo-only) SCHUFA credit report (Bonitätsauskunft). Issued in both mdoc and SD-JWT VC
 * format from the same dataset - see [IssueMsoMdocSchufa] / [IssueSdJwtVcSchufa].
 */
data class Schufa(
    val familyName: FamilyName,
    val givenName: GivenName,
    val birthDate: LocalDate,
    val creditScore: CreditScore,
    val reportDate: LocalDate,
    val validUntil: LocalDate,
    val issuingEntity: IssuingEntity,
) {
    companion object {
        /**
         * A plausible, fixed demo dataset - used whenever the operator didn't type in custom values (e.g. the
         * authorization_code flow, or a pre-authorized offer generated without filling in the form).
         */
        fun default(generatedAt: Instant): Schufa =
            Schufa(
                familyName = FamilyName("Neal"),
                givenName = GivenName("Tyler"),
                birthDate = LocalDate(1955, 4, 12),
                creditScore = CreditScore("97.5"),
                reportDate = generatedAt.toLocalDate(),
                validUntil = (generatedAt + (180).days).toLocalDate(),
                issuingEntity = IssuingEntity("SCHUFA Holding AG"),
            )

        private fun Instant.toLocalDate(): LocalDate = toLocalDateTime(TimeZone.currentSystemDefault()).date
    }
}

/**
 * Overrides only the fields present in operator-entered [customData], keeping this [Schufa]'s values for the rest.
 */
fun Schufa.overriddenBy(customData: JsonObject): Schufa =
    copy(
        familyName = customData.stringFieldOrNull("family_name")?.let(::FamilyName) ?: familyName,
        givenName = customData.stringFieldOrNull("given_name")?.let(::GivenName) ?: givenName,
        birthDate = customData.stringFieldOrNull("birth_date")?.let(LocalDate::parse) ?: birthDate,
        creditScore = customData.stringFieldOrNull("credit_score")?.let(::CreditScore) ?: creditScore,
    )
