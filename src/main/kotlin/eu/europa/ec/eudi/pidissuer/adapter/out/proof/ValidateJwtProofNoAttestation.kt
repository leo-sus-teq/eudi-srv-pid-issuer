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
package eu.europa.ec.eudi.pidissuer.adapter.out.proof

import arrow.core.nonEmptyListOf
import arrow.core.raise.Raise
import arrow.core.raise.context.ensure
import arrow.core.raise.context.ensureNotNull
import arrow.core.raise.context.raise
import arrow.core.raise.effect
import arrow.core.raise.fold
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.proof.ValidateProof
import kotlin.time.Duration.Companion.seconds
import kotlin.time.DurationUnit
import kotlin.time.Instant

/**
 * Validator for plain JWT Proofs that carry no key attestation - selected only for credential configurations
 * whose [DeviceBinding.Required.ProofOption] is [DeviceBinding.Required.ProofOption.ProofJwtNoAttestation]. The
 * credential is bound to whatever public key the proof JWT itself embeds in its `jwk` header (standard OpenID4VCI
 * JWT proof-of-possession), with no assurance about where that key is stored - unlike
 * [ValidateJwtProofWithKeyAttestation], which mandates a hardware key attestation.
 */
class ValidateJwtProofNoAttestation(
    private val credentialIssuerId: CredentialIssuerId,
) : ValidateProof.Validator<UnvalidatedProof.Jwt, ProofType.Jwt> {
    context(_: Raise<IssueCredentialError.InvalidProof>, proofType: ProofType.Jwt)
    override suspend operator fun invoke(
        unvalidatedProof: UnvalidatedProof.Jwt,
        at: Instant,
    ): KeyAttestation =
        effect { doValidate(unvalidatedProof) }
            .fold(
                transform = { it },
                recover = { raise(IssueCredentialError.InvalidProof(it)) },
                catch = { raise(IssueCredentialError.InvalidProof("Invalid proof JWT", it)) },
            )

    context(_: Raise<String>, proofType: ProofType.Jwt)
    private fun doValidate(unvalidatedProof: UnvalidatedProof.Jwt): KeyAttestation {
        val jwtProof = SignedJWT.parse(unvalidatedProof.jwt)
        ensure(jwtProof.header.algorithm in proofType.signingAlgorithmsSupported) {
            "JWT proof signing algorithm '${jwtProof.header.algorithm}' is not supported, " +
                "must be one of: ${proofType.signingAlgorithmsSupported.joinToString(", ") { it.name }}"
        }
        val nonce = ensureNotNull(jwtProof.jwtClaimsSet.getStringClaim("nonce")) { "Missing 'nonce'" }

        val jwk = ensureNotNull(jwtProof.header.jwk) { "JWT Proof must contain a 'jwk' header" }
        val asymmetricJwk = jwk as? AsymmetricJWK
        ensureNotNull(asymmetricJwk) { "'jwk' header must be an asymmetric key" }
        ensure(!jwk.isPrivate) { "'jwk' header must be a public key" }

        val keySelector = SingleKeyJWSKeySelector<SecurityContext>(jwtProof.header.algorithm, asymmetricJwk.toPublicKey())
        val processor =
            DefaultJWTProcessor<SecurityContext>().apply {
                jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(expectedType)
                jwsKeySelector = keySelector
                jwtClaimsSetVerifier =
                    DefaultJWTClaimsVerifier<SecurityContext?>(
                        credentialIssuerId.externalForm,
                        JWTClaimsSet.Builder().build(),
                        setOf("iat"),
                    ).apply { maxClockSkew = maxSkew.toInt(DurationUnit.SECONDS) }
            }
        processor.process(jwtProof, null)

        return KeyAttestation(
            keys = CredentialKeys(nonEmptyListOf(jwk)),
            cNonce = nonce,
            keyStorageStatus = null,
        )
    }

    companion object {
        private val expectedType = JOSEObjectType("openid4vci-proof+jwt")
        private val maxSkew = 30.seconds
    }
}
