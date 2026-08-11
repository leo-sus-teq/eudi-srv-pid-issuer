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

import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import eu.europa.ec.eudi.pidissuer.domain.ClaimDefinition
import eu.europa.ec.eudi.pidissuer.domain.ClaimPath
import java.util.*

object ResidencePermitClaims {
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
    val Nationality: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("nationality"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Nationality"),
        )
    val DocumentNumber: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("document_number"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Document Number"),
        )
    val AdministrativeNumber: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("administrative_number"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Administrative Number"),
        )
    val IssuingAuthority: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("issuing_authority"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Issuing Authority"),
        )
    val IssuingCountry: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("issuing_country"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Issuing Country"),
        )
    val DateOfIssuance: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("date_of_issuance"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Date of Issuance"),
        )
    val DateOfExpiry: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("date_of_expiry"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Date of Expiry"),
        )
    val ResidentAddress: ClaimDefinition =
        ClaimDefinition(
            path = ClaimPath.claim("resident_address"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Resident Address"),
        )

    fun all(): NonEmptyList<ClaimDefinition> =
        nonEmptyListOf(
            FamilyName,
            GivenName,
            BirthDate,
            Nationality,
            DocumentNumber,
            AdministrativeNumber,
            IssuingAuthority,
            IssuingCountry,
            DateOfIssuance,
            DateOfExpiry,
            ResidentAddress,
        )
}
