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

import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import eu.europa.ec.eudi.pidissuer.domain.ClaimDefinition
import eu.europa.ec.eudi.pidissuer.domain.MsoNameSpace
import eu.europa.ec.eudi.pidissuer.domain.invoke
import java.util.*

object MsoMdocSchufaClaims {
    val nameSpace: MsoNameSpace = "eudi.schufa.1"

    val FamilyName = ClaimDefinition(nameSpace, "family_name", mandatory = true, display = mapOf(Locale.ENGLISH to "Family Name(s)"))
    val GivenName = ClaimDefinition(nameSpace, "given_name", mandatory = true, display = mapOf(Locale.ENGLISH to "Given Name(s)"))
    val BirthDate = ClaimDefinition(nameSpace, "birth_date", mandatory = true, display = mapOf(Locale.ENGLISH to "Date of Birth"))
    val CreditScore = ClaimDefinition(nameSpace, "credit_score", mandatory = true, display = mapOf(Locale.ENGLISH to "Credit Score"))
    val ReportDate = ClaimDefinition(nameSpace, "report_date", mandatory = true, display = mapOf(Locale.ENGLISH to "Report Date"))
    val ValidUntil = ClaimDefinition(nameSpace, "valid_until", mandatory = true, display = mapOf(Locale.ENGLISH to "Valid Until"))
    val IssuingEntity =
        ClaimDefinition(nameSpace, "issuing_entity", mandatory = true, display = mapOf(Locale.ENGLISH to "Issuing Entity"))

    fun all(): NonEmptyList<ClaimDefinition> =
        nonEmptyListOf(
            FamilyName,
            GivenName,
            BirthDate,
            CreditScore,
            ReportDate,
            ValidUntil,
            IssuingEntity,
        )
}
