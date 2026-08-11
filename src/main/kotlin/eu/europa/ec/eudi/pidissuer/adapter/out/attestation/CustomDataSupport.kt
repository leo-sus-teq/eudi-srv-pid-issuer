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
package eu.europa.ec.eudi.pidissuer.adapter.out.attestation

import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive

/**
 * Reads a non-blank string field out of operator-entered custom data
 * ([eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext.customData]), or `null` if absent/blank -
 * used by demo credential types to let a fixed default be overridden field-by-field.
 */
fun JsonObject.stringFieldOrNull(key: String): String? = this[key]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() }

/**
 * Looks up operator-entered custom data under any of [ids], returning the first match. Needed because
 * [eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOffer] only keeps a custom-data entry whose key is
 * among the *actually-selected* credential configuration ids for the offer - so a credential type offered in
 * multiple forms (e.g. mdoc and SD-JWT VC, or a "_deferred" variant) must be looked up under every id its
 * issuance could resolve to, not just one "canonical" id (see [[customdata-filter-scope]]).
 */
fun Map<CredentialConfigurationId, JsonObject>.firstCustomData(ids: List<CredentialConfigurationId>): JsonObject? =
    ids.firstNotNullOfOrNull { this[it] }

/**
 * The "_deferred" variant of [this] configuration id, matching the suffix
 * [eu.europa.ec.eudi.pidissuer.port.out.attestation.DeferredIssuer] appends.
 */
fun CredentialConfigurationId.deferred(): CredentialConfigurationId = CredentialConfigurationId(value + "_deferred")
