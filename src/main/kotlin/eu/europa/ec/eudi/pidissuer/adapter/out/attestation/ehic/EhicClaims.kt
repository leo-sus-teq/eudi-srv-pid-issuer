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

import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import eu.europa.ec.eudi.pidissuer.domain.ClaimDefinition
import eu.europa.ec.eudi.pidissuer.domain.ClaimPath
import java.util.*

object EhicClaims {
    val FamilyName: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("family_name"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Family Name(s)"),
        )
    val GivenName: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("given_name"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Given Name(s)"),
        )
    val BirthDate: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("birth_date"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Date of Birth"),
        )
    val PersonalAdministrativeNumber: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("personal_administrative_number"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Health Insurance Number"),
        )
    val IssuingAuthorityId: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("issuing_authority_id"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Issuing Authority Identifier"),
        )
    val IssuingAuthorityName: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("issuing_authority_name"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Issuing Authority Name"),
        )
    val IssuingCountry: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("issuing_country"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Issuing Country"),
        )
    val DateOfExpiry: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("date_of_expiry"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Date of Expiry"),
        )

    fun all(): NonEmptyList<ClaimDefinition> =
        nonEmptyListOf(
            FamilyName,
            GivenName,
            BirthDate,
            PersonalAdministrativeNumber,
            IssuingAuthorityId,
            IssuingAuthorityName,
            IssuingCountry,
            DateOfExpiry,
        )
}
