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
package eu.europa.ec.eudi.pidissuer.domain

import com.eygraber.uri.Uri
import eu.europa.ec.eudi.pidissuer.adapter.out.json.InstantEpochSecondsSerializer
import eu.europa.ec.eudi.sdjwt.RFC7519
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

/**
 * Sentinel status-list URI used when there is no real Wallet Unit Attestation to check a
 * status for - currently only the pre-authorized_code (demo/auto-approve) grant, see
 * IssuePreAuthorizedCodeAccessToken. Never meant to be dereferenced over the network; callers
 * that verify a [StatusListToken] (e.g. IssueCredential.checkClientStatusIsValid) must recognize
 * this value and treat it as trivially valid instead of attempting the check.
 */
val NoClientStatus: Uri = Uri.parse("urn:eudi:pid-issuer:pre-authorized-code:no-status")

@Serializable
data class ClientStatus(
    @Required @SerialName(TokenStatusListSpec.STATUS) val status: StatusClaim,
    @Required @SerialName(RFC7519.EXPIRATION_TIME) @Serializable(with = InstantEpochSecondsSerializer::class) val expiresAt: Instant,
)

@Serializable
data class StatusClaim(
    @Required @SerialName(TokenStatusListSpec.STATUS_LIST) val statusList: StatusListToken,
)
