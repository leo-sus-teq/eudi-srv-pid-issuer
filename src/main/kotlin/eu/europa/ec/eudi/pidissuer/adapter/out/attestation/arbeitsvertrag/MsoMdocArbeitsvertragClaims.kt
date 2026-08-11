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

import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import eu.europa.ec.eudi.pidissuer.domain.ClaimDefinition
import eu.europa.ec.eudi.pidissuer.domain.MsoNameSpace
import eu.europa.ec.eudi.pidissuer.domain.invoke
import java.util.*

object MsoMdocArbeitsvertragClaims {
    val nameSpace: MsoNameSpace = "eudi.trusteq.arbeitsvertrag.1"

    val EmployeeFamilyName =
        ClaimDefinition(nameSpace, "employee_family_name", mandatory = true, display = mapOf(Locale.ENGLISH to "Employee Family Name(s)"))
    val EmployeeGivenName =
        ClaimDefinition(nameSpace, "employee_given_name", mandatory = true, display = mapOf(Locale.ENGLISH to "Employee Given Name(s)"))
    val JobTitle = ClaimDefinition(nameSpace, "job_title", mandatory = true, display = mapOf(Locale.ENGLISH to "Job Title"))
    val EmploymentStartDate =
        ClaimDefinition(nameSpace, "employment_start_date", mandatory = true, display = mapOf(Locale.ENGLISH to "Employment Start Date"))
    val Employer = ClaimDefinition(nameSpace, "employer", mandatory = true, display = mapOf(Locale.ENGLISH to "Employer"))
    val ContractType = ClaimDefinition(nameSpace, "contract_type", mandatory = true, display = mapOf(Locale.ENGLISH to "Contract Type"))
    val Department = ClaimDefinition(nameSpace, "department", mandatory = true, display = mapOf(Locale.ENGLISH to "Department"))

    fun all(): NonEmptyList<ClaimDefinition> =
        nonEmptyListOf(
            EmployeeFamilyName,
            EmployeeGivenName,
            JobTitle,
            EmploymentStartDate,
            Employer,
            ContractType,
            Department,
        )
}
