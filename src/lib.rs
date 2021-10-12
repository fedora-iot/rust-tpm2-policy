// Copyright 2020 Patrick Uiterwijk
//
// Licensed under the EUPL-1.2-or-later
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::convert::{TryFrom, TryInto};
use std::io::Write;

use tss_esapi::{
    attributes::SessionAttributesBuilder,
    constants::SessionType,
    handles::KeyHandle,
    interface_types::algorithm::HashingAlgorithm,
    interface_types::{resource_handles::Hierarchy, session_handles::AuthSession},
    structures::SymmetricDefinition,
    structures::{Digest, MaxBuffer, Nonce, PcrSelectionListBuilder, PcrSlot, VerifiedTicket},
    utils::AsymSchemeUnion,
};

mod error;
mod structures;
pub use error::{Error, Result};
pub use structures::{PublicKey, SignedPolicy, SignedPolicyList, SignedPolicyStep, TPMPolicyStep};

fn create_tpm2_session(
    ctx: &mut tss_esapi::Context,
    session_type: SessionType,
) -> Result<AuthSession> {
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            session_type,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .unwrap();
    let (session_attrs, session_attr_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();

    ctx.tr_sess_set_attributes(session, session_attrs, session_attr_mask)?;

    Ok(session)
}

fn pcr_id_to_slot(pcr: &u64) -> Result<PcrSlot> {
    match pcr {
        0 => Ok(PcrSlot::Slot0),
        1 => Ok(PcrSlot::Slot1),
        2 => Ok(PcrSlot::Slot2),
        3 => Ok(PcrSlot::Slot3),
        4 => Ok(PcrSlot::Slot4),
        5 => Ok(PcrSlot::Slot5),
        6 => Ok(PcrSlot::Slot6),
        7 => Ok(PcrSlot::Slot7),
        8 => Ok(PcrSlot::Slot8),
        9 => Ok(PcrSlot::Slot9),
        10 => Ok(PcrSlot::Slot10),
        11 => Ok(PcrSlot::Slot11),
        12 => Ok(PcrSlot::Slot12),
        13 => Ok(PcrSlot::Slot13),
        14 => Ok(PcrSlot::Slot14),
        15 => Ok(PcrSlot::Slot15),
        16 => Ok(PcrSlot::Slot16),
        17 => Ok(PcrSlot::Slot17),
        18 => Ok(PcrSlot::Slot18),
        19 => Ok(PcrSlot::Slot19),
        20 => Ok(PcrSlot::Slot20),
        21 => Ok(PcrSlot::Slot21),
        22 => Ok(PcrSlot::Slot22),
        23 => Ok(PcrSlot::Slot23),
        _ => Err(Error::InvalidValue),
    }
}

impl TPMPolicyStep {
    /// Sends the policy to the TPM2
    /// Returns the session, and policy_digest for authInfo
    pub fn send_policy(
        self,
        ctx: &mut tss_esapi::Context,
        trial_policy: bool,
    ) -> Result<(Option<AuthSession>, Option<Digest>)> {
        match self {
            TPMPolicyStep::NoStep => {
                let session = create_tpm2_session(ctx, SessionType::Hmac)?;
                Ok((Some(session), None))
            }
            _ => {
                let session = create_tpm2_session(
                    ctx,
                    if trial_policy {
                        SessionType::Trial
                    } else {
                        SessionType::Policy
                    },
                )
                .unwrap();

                self._send_policy(ctx, session)?;

                let pol_digest = ctx.policy_get_digest(session.try_into()?)?;

                Ok((Some(session), Some(pol_digest)))
            }
        }
    }

    fn _send_policy(self, ctx: &mut tss_esapi::Context, policy_session: AuthSession) -> Result<()> {
        match self {
            TPMPolicyStep::NoStep => Ok(()),

            TPMPolicyStep::PCRs(pcr_hash_alg, pcr_ids, next) => {
                let pcr_ids: Result<Vec<PcrSlot>> =
                    pcr_ids.iter().map(|x| pcr_id_to_slot(x)).collect();
                let pcr_ids: Vec<PcrSlot> = pcr_ids?;

                let pcr_sel = PcrSelectionListBuilder::new()
                    .with_selection(pcr_hash_alg, &pcr_ids)
                    .build();

                let (_update_counter, pcr_sel, pcr_data) =
                    ctx.execute_without_session(|context| context.pcr_read(&pcr_sel))?;

                let concatenated_pcr_values: Result<Vec<&[u8]>> = pcr_ids
                    .iter()
                    .map(|x| {
                        Ok(pcr_data
                            .pcr_bank(pcr_hash_alg)
                            .ok_or_else(|| Error::PcrValueNotReturned(pcr_hash_alg, None))?
                            .pcr_value(*x)
                            .ok_or_else(|| Error::PcrValueNotReturned(pcr_hash_alg, Some(*x)))?
                            .value())
                    })
                    .collect();
                let concatenated_pcr_values = concatenated_pcr_values?.as_slice().concat();
                let concatenated_pcr_values = MaxBuffer::try_from(concatenated_pcr_values)?;

                let (hashed_data, _ticket) = ctx.execute_without_session(|context| {
                    context.hash(
                        &concatenated_pcr_values,
                        HashingAlgorithm::Sha256,
                        Hierarchy::Owner,
                    )
                })?;

                ctx.policy_pcr(policy_session.try_into()?, &hashed_data, pcr_sel)?;
                next._send_policy(ctx, policy_session)
            }

            TPMPolicyStep::Authorized {
                signkey,
                policy_ref,
                policies,
                next,
            } => {
                let policy_ref = Nonce::try_from(policy_ref)?;

                let tpm_signkey = tss_esapi::tss2_esys::TPM2B_PUBLIC::try_from(&signkey)?;
                let loaded_key = ctx.load_external_public(&tpm_signkey, Hierarchy::Owner)?;
                let loaded_key_name = ctx.tr_get_name(loaded_key.into())?;

                let (approved_policy, check_ticket) = match policies {
                    None => {
                        let null_ticket = tss_esapi::tss2_esys::TPMT_TK_VERIFIED {
                            tag: tss_esapi::constants::tss::TPM2_ST_VERIFIED,
                            hierarchy: tss_esapi::constants::tss::TPM2_RH_NULL,
                            digest: tss_esapi::tss2_esys::TPM2B_DIGEST {
                                size: 32,
                                buffer: [0; 64],
                            },
                        };
                        (Digest::try_from(vec![])?, null_ticket.try_into()?)
                    }
                    Some(policies) => find_and_play_applicable_policy(
                        ctx,
                        &policies,
                        policy_session,
                        policy_ref.value(),
                        signkey.get_signing_scheme(),
                        loaded_key,
                    )?,
                };

                ctx.policy_authorize(
                    policy_session.try_into()?,
                    &approved_policy,
                    &policy_ref,
                    &loaded_key_name,
                    check_ticket,
                )?;

                next._send_policy(ctx, policy_session)
            }

            _ => Err(Error::NotImplemented("Policy type".to_string())),
        }
    }
}

fn find_and_play_applicable_policy(
    ctx: &mut tss_esapi::Context,
    policies: &[SignedPolicy],
    policy_session: AuthSession,
    policy_ref: &[u8],
    scheme: AsymSchemeUnion,
    loaded_key: KeyHandle,
) -> Result<(Digest, VerifiedTicket)> {
    for policy in policies {
        if policy.policy_ref != policy_ref {
            continue;
        }

        if let Some(policy_digest) = play_policy(ctx, &policy, policy_session)? {
            // aHash ≔ H_{aHashAlg}(approvedPolicy || policyRef)
            let mut ahash = Vec::new();
            ahash.write_all(&policy_digest)?;
            ahash.write_all(&policy_ref)?;

            let ahash = MaxBuffer::try_from(ahash)?;

            let ahash = ctx
                .hash(&ahash, HashingAlgorithm::Sha256, Hierarchy::Null)?
                .0;
            let signature = tss_esapi::utils::Signature {
                scheme,
                signature: tss_esapi::utils::SignatureData::RsaSignature(policy.signature.clone()),
            };
            let tkt = ctx.verify_signature(loaded_key, &ahash, signature)?;

            return Ok((policy_digest, tkt));
        }
    }

    Err(Error::NoMatchingPolicy)
}

// This function would do a simple check whether the policy has a chance for success.
// It does explicitly not change policy_session
fn check_policy_feasibility(_ctx: &mut tss_esapi::Context, _policy: &SignedPolicy) -> Result<bool> {
    Ok(true)
    // TODO: Implement this, to check whether the PCRs in this branch would match
}

fn play_policy(
    ctx: &mut tss_esapi::Context,
    policy: &SignedPolicy,
    policy_session: AuthSession,
) -> Result<Option<Digest>> {
    if !check_policy_feasibility(ctx, policy)? {
        return Ok(None);
    }

    for step in &policy.steps {
        let tpmstep = TPMPolicyStep::try_from(step)?;
        tpmstep._send_policy(ctx, policy_session)?;
    }

    Ok(Some(ctx.policy_get_digest(policy_session.try_into()?)?))
}
