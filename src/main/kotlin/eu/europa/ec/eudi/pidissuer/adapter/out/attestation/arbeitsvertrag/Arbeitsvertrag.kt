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

import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.stringFieldOrNull
import eu.europa.ec.eudi.pidissuer.domain.NonBlankString
import kotlinx.datetime.LocalDate
import kotlinx.serialization.json.JsonObject

typealias EmployeeFamilyName = NonBlankString
typealias EmployeeGivenName = NonBlankString
typealias JobTitle = NonBlankString
typealias Employer = NonBlankString
typealias ContractType = NonBlankString
typealias Department = NonBlankString

/**
 * A (heavily simplified, demo-only) TRUSTEQ employment certificate (Arbeitsvertrag). Issued in both mdoc and
 * SD-JWT VC format from the same dataset - see [IssueMsoMdocArbeitsvertrag] / [IssueSdJwtVcArbeitsvertrag].
 */
data class Arbeitsvertrag(
    val employeeFamilyName: EmployeeFamilyName,
    val employeeGivenName: EmployeeGivenName,
    val jobTitle: JobTitle,
    val employmentStartDate: LocalDate,
    val employer: Employer,
    val contractType: ContractType,
    val department: Department,
) {
    companion object {
        /**
         * A plausible, fixed demo dataset - used whenever the operator didn't type in custom values (e.g. the
         * authorization_code flow, or a pre-authorized offer generated without filling in the form). [employer]
         * is always "TRUSTEQ" - this credential exists specifically to demo a TRUSTEQ-issued attestation and is
         * not operator-overridable.
         */
        fun default(): Arbeitsvertrag =
            Arbeitsvertrag(
                employeeFamilyName = EmployeeFamilyName("Neal"),
                employeeGivenName = EmployeeGivenName("Tyler"),
                jobTitle = JobTitle("Software Engineer"),
                employmentStartDate = LocalDate(2024, 1, 15),
                employer = Employer("TRUSTEQ"),
                contractType = ContractType("Permanent"),
                department = Department("Software Engineering"),
            )
    }
}

/**
 * Overrides only the fields present in operator-entered [customData], keeping this [Arbeitsvertrag]'s values for
 * the rest. [Arbeitsvertrag.employer] is intentionally not overridable.
 */
fun Arbeitsvertrag.overriddenBy(customData: JsonObject): Arbeitsvertrag =
    copy(
        employeeFamilyName =
            customData.stringFieldOrNull("employee_family_name")?.let(::EmployeeFamilyName) ?: employeeFamilyName,
        employeeGivenName =
            customData.stringFieldOrNull("employee_given_name")?.let(::EmployeeGivenName) ?: employeeGivenName,
        jobTitle = customData.stringFieldOrNull("job_title")?.let(::JobTitle) ?: jobTitle,
        employmentStartDate =
            customData.stringFieldOrNull("employment_start_date")?.let(LocalDate::parse) ?: employmentStartDate,
    )
