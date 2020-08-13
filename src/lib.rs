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

use tss_esapi::constants::algorithm::HashingAlgorithm;
use tss_esapi::constants::tss as tss_constants;
use tss_esapi::structures::{Digest, MaxBuffer, Nonce, PcrSelectionListBuilder, PcrSlot};
use tss_esapi::tss2_esys::{ESYS_TR, ESYS_TR_NONE, ESYS_TR_RH_OWNER};
use tss_esapi::utils::AsymSchemeUnion;
use tss_esapi::utils::TpmaSessionBuilder;

use serde::{Deserialize, Serialize};

fn serialize_as_base64<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&base64::encode(bytes))
}

fn deserialize_as_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer)
        .and_then(|string| base64::decode(&string).map_err(serde::de::Error::custom))
}

mod error;
pub use error::Error;

#[derive(Debug, Serialize, Deserialize)]
pub enum SignedPolicyStep {
    PCRs {
        pcr_ids: Vec<u16>,
        hash_algorithm: String,
        #[serde(
            deserialize_with = "deserialize_as_base64",
            serialize_with = "serialize_as_base64"
        )]
        value: Vec<u8>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedPolicy {
    // policy_ref contains the policy_ref used in the aHash, used to determine the policy to use from a list
    #[serde(
        deserialize_with = "deserialize_as_base64",
        serialize_with = "serialize_as_base64"
    )]
    policy_ref: Vec<u8>,
    // steps contains the policy steps that are signed
    steps: Vec<SignedPolicyStep>,
    // signature contains the signature over aHash
    #[serde(
        deserialize_with = "deserialize_as_base64",
        serialize_with = "serialize_as_base64"
    )]
    signature: Vec<u8>,
}

pub type SignedPolicyList = Vec<SignedPolicy>;

#[derive(Debug)]
pub enum TPMPolicyStep {
    NoStep,
    PCRs(HashingAlgorithm, Vec<u64>, Box<TPMPolicyStep>),
    Authorized {
        signkey: PublicKey,
        policy_ref: Vec<u8>,
        policies: Option<SignedPolicyList>,
        next: Box<TPMPolicyStep>,
    },
    Or([Box<TPMPolicyStep>; 8]),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RSAPublicKeyScheme {
    RSAPSS,
    RSASSA,
}

impl RSAPublicKeyScheme {
    fn to_scheme(&self, hash_algo: &HashAlgo) -> AsymSchemeUnion {
        match self {
            RSAPublicKeyScheme::RSAPSS => AsymSchemeUnion::RSAPSS(hash_algo.into()),
            RSAPublicKeyScheme::RSASSA => AsymSchemeUnion::RSASSA(hash_algo.into()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum HashAlgo {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
    SM3_256,
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

impl HashAlgo {
    fn to_tpmi_alg_hash(&self) -> tss_esapi::tss2_esys::TPMI_ALG_HASH {
        let alg: HashingAlgorithm = self.into();
        alg.into()
    }
}

impl From<&HashAlgo> for HashingAlgorithm {
    fn from(halg: &HashAlgo) -> Self {
        match halg {
            HashAlgo::SHA1 => HashingAlgorithm::Sha1,
            HashAlgo::SHA256 => HashingAlgorithm::Sha256,
            HashAlgo::SHA384 => HashingAlgorithm::Sha384,
            HashAlgo::SHA512 => HashingAlgorithm::Sha512,
            HashAlgo::SM3_256 => HashingAlgorithm::Sm3_256,
            HashAlgo::SHA3_256 => HashingAlgorithm::Sha3_256,
            HashAlgo::SHA3_384 => HashingAlgorithm::Sha3_384,
            HashAlgo::SHA3_512 => HashingAlgorithm::Sha3_512,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum PublicKey {
    RSA {
        scheme: RSAPublicKeyScheme,
        hashing_algo: HashAlgo,
        exponent: u32,
        #[serde(
            deserialize_with = "deserialize_as_base64",
            serialize_with = "serialize_as_base64"
        )]
        modulus: Vec<u8>,
    },
}

impl PublicKey {
    fn get_signing_scheme(&self) -> tss_esapi::utils::AsymSchemeUnion {
        match self {
            PublicKey::RSA {
                scheme,
                hashing_algo,
                exponent: _,
                modulus: _,
            } => scheme.to_scheme(hashing_algo),
        }
    }
}

impl TryFrom<&PublicKey> for tss_esapi::tss2_esys::TPM2B_PUBLIC {
    type Error = Error;

    fn try_from(publickey: &PublicKey) -> Result<Self, Self::Error> {
        match publickey {
            PublicKey::RSA {
                scheme,
                hashing_algo,
                modulus,
                exponent,
            } => {
                let mut object_attributes = tss_esapi::utils::ObjectAttributes(0);
                object_attributes.set_fixed_tpm(false);
                object_attributes.set_fixed_parent(false);
                object_attributes.set_sensitive_data_origin(false);
                object_attributes.set_user_with_auth(true);
                object_attributes.set_decrypt(false);
                object_attributes.set_sign_encrypt(true);
                object_attributes.set_restricted(false);

                let len = modulus.len();
                let mut buffer = [0_u8; 512];
                buffer[..len].clone_from_slice(&modulus[..len]);
                let rsa_uniq = Box::new(tss_esapi::tss2_esys::TPM2B_PUBLIC_KEY_RSA {
                    size: len as u16,
                    buffer,
                });

                Ok(tss_esapi::utils::Tpm2BPublicBuilder::new()
                    .with_type(tss_constants::TPM2_ALG_RSA)
                    .with_name_alg(hashing_algo.to_tpmi_alg_hash())
                    .with_parms(tss_esapi::utils::PublicParmsUnion::RsaDetail(
                        tss_esapi::utils::TpmsRsaParmsBuilder::new_unrestricted_signing_key(
                            scheme.to_scheme(&hashing_algo),
                            (modulus.len() * 8) as u16,
                            *exponent,
                        )
                        .build()?,
                    ))
                    .with_object_attributes(object_attributes)
                    .with_unique(tss_esapi::utils::PublicIdUnion::Rsa(rsa_uniq))
                    .build()?)
            }
        }
    }
}

fn tpm_sym_def(_ctx: &mut tss_esapi::Context) -> tss_esapi::tss2_esys::TPMT_SYM_DEF {
    tss_esapi::tss2_esys::TPMT_SYM_DEF {
        algorithm: tss_constants::TPM2_ALG_AES,
        keyBits: tss_esapi::tss2_esys::TPMU_SYM_KEY_BITS { aes: 128 },
        mode: tss_esapi::tss2_esys::TPMU_SYM_MODE {
            aes: tss_constants::TPM2_ALG_CFB,
        },
    }
}

fn create_and_set_tpm2_session(
    ctx: &mut tss_esapi::Context,
    session_type: tss_esapi::tss2_esys::TPM2_SE,
) -> Result<ESYS_TR, Error> {
    let symdef = tpm_sym_def(ctx);

    let session = ctx.start_auth_session(
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        None,
        session_type,
        symdef,
        tss_constants::TPM2_ALG_SHA256,
    )?;
    let session_attr = TpmaSessionBuilder::new()
        .with_flag(tss_constants::TPMA_SESSION_DECRYPT)
        .with_flag(tss_constants::TPMA_SESSION_ENCRYPT)
        .build();

    ctx.tr_sess_set_attributes(session, session_attr)?;

    ctx.set_sessions((session, ESYS_TR_NONE, ESYS_TR_NONE));

    Ok(session)
}

fn pcr_id_to_slot(pcr: &u64) -> Result<PcrSlot, Error> {
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
    /// Sends the generate policy to the TPM2, and sets the authorized policy as active
    /// Returns the policy_digest for authInfo
    pub fn send_policy(
        self,
        ctx: &mut tss_esapi::Context,
        trial_policy: bool,
    ) -> Result<Option<Digest>, Error> {
        let pol_type = if trial_policy {
            tss_constants::TPM2_SE_TRIAL
        } else {
            tss_constants::TPM2_SE_POLICY
        };

        let symdef = tpm_sym_def(ctx);

        let session = ctx.start_auth_session(
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            None,
            pol_type,
            symdef,
            tss_constants::TPM2_ALG_SHA256,
        )?;
        let session_attr = TpmaSessionBuilder::new()
            .with_flag(tss_constants::TPMA_SESSION_DECRYPT)
            .with_flag(tss_constants::TPMA_SESSION_ENCRYPT)
            .build();
        ctx.tr_sess_set_attributes(session, session_attr)?;

        match self {
            TPMPolicyStep::NoStep => {
                create_and_set_tpm2_session(ctx, tss_constants::TPM2_SE_HMAC)?;
                Ok(None)
            }
            _ => {
                self._send_policy(ctx, session)?;

                let pol_digest = ctx.policy_get_digest(session)?;

                if trial_policy {
                    create_and_set_tpm2_session(ctx, tss_constants::TPM2_SE_HMAC)?;
                } else {
                    ctx.set_sessions((session, ESYS_TR_NONE, ESYS_TR_NONE));
                }
                Ok(Some(pol_digest))
            }
        }
    }

    fn _send_policy(
        self,
        ctx: &mut tss_esapi::Context,
        policy_session: tss_esapi::tss2_esys::ESYS_TR,
    ) -> Result<(), Error> {
        match self {
            TPMPolicyStep::NoStep => Ok(()),

            TPMPolicyStep::PCRs(pcr_hash_alg, pcr_ids, next) => {
                let pcr_ids: Result<Vec<PcrSlot>, Error> =
                    pcr_ids.iter().map(|x| pcr_id_to_slot(x)).collect();
                let pcr_ids: Vec<PcrSlot> = pcr_ids?;

                let pcr_sel = PcrSelectionListBuilder::new()
                    .with_selection(pcr_hash_alg, &pcr_ids)
                    .build();

                // Ensure PCR reading occurs with no sessions (we don't use audit sessions)
                let old_ses = ctx.sessions();
                ctx.set_sessions((ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE));
                let (_update_counter, pcr_sel, pcr_data) = ctx.pcr_read(&pcr_sel)?;
                ctx.set_sessions(old_ses);

                let concatenated_pcr_values: Vec<&[u8]> = pcr_ids
                    .iter()
                    .map(|x| {
                        pcr_data
                            .pcr_bank(pcr_hash_alg)
                            .unwrap()
                            .pcr_value(*x)
                            .unwrap()
                            .value()
                    })
                    .collect();
                let concatenated_pcr_values = concatenated_pcr_values.as_slice().concat();
                let concatenated_pcr_values = MaxBuffer::try_from(concatenated_pcr_values)?;

                let (hashed_data, _ticket) = ctx.hash(
                    &concatenated_pcr_values,
                    HashingAlgorithm::Sha256,
                    tss_esapi::utils::Hierarchy::Owner,
                )?;

                ctx.policy_pcr(policy_session, &hashed_data, pcr_sel)?;
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
                let loaded_key =
                    ctx.load_external_public(&tpm_signkey, tss_esapi::utils::Hierarchy::Owner)?;
                let loaded_key_name = ctx.tr_get_name(loaded_key)?;

                let (approved_policy, check_ticket) = match policies {
                    None => {
                        /* Some TPMs don't seem to like the Null ticket.. Let's just use a dummy
                        let null_ticket = tss_esapi::tss2_esys::TPMT_TK_VERIFIED {
                            tag: tss_esapi::constants::TPM2_ST_VERIFIED,
                            hierarchy: tss_esapi::tss2_esys::ESYS_TR_RH_NULL,
                            digest: tss_esapi::tss2_esys::TPM2B_DIGEST {
                                size: 32,
                                buffer: [0; 64],
                            },
                        };
                        */
                        let dummy_ticket = get_dummy_ticket(ctx);
                        (Digest::try_from(vec![])?, dummy_ticket)
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
                    policy_session,
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
    policy_session: ESYS_TR,
    policy_ref: &[u8],
    scheme: AsymSchemeUnion,
    loaded_key: ESYS_TR,
) -> Result<(Digest, tss_esapi::tss2_esys::TPMT_TK_VERIFIED), Error> {
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
                .hash(
                    &ahash,
                    HashingAlgorithm::Sha256,
                    tss_esapi::utils::Hierarchy::Null,
                )?
                .0;
            let signature = tss_esapi::utils::Signature {
                scheme,
                signature: tss_esapi::utils::SignatureData::RsaSignature(policy.signature.clone()),
            };
            let tkt = ctx.verify_signature(loaded_key, &ahash, &signature.try_into()?)?;

            return Ok((policy_digest, tkt));
        }
    }

    Err(Error::NoMatchingPolicy)
}

// This function would do a simple check whether the policy has a chance for success.
// It does explicitly not change policy_session
fn check_policy_feasibility(
    _ctx: &mut tss_esapi::Context,
    _policy: &SignedPolicy,
) -> Result<bool, Error> {
    Ok(true)
    // TODO: Implement this, to check whether the PCRs in this branch would match
}

fn play_policy(
    ctx: &mut tss_esapi::Context,
    policy: &SignedPolicy,
    policy_session: ESYS_TR,
) -> Result<Option<Digest>, Error> {
    if !check_policy_feasibility(ctx, policy)? {
        return Ok(None);
    }

    for step in &policy.steps {
        let tpmstep = TPMPolicyStep::try_from(step)?;
        tpmstep._send_policy(ctx, policy_session)?;
    }

    Ok(Some(ctx.policy_get_digest(policy_session)?))
}

// It turns out that a Null ticket does not work for some TPMs, so let's just generate
// a dummy ticket. This is a valid ticket, but over a totally useless piece of data.
fn get_dummy_ticket(context: &mut tss_esapi::Context) -> tss_esapi::tss2_esys::TPMT_TK_VERIFIED {
    let old_ses = context.sessions();
    context.set_sessions((ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE));
    create_and_set_tpm2_session(context, tss_constants::TPM2_SE_HMAC).unwrap();

    let signing_key_pub = tss_esapi::utils::create_unrestricted_signing_rsa_public(
        tss_esapi::utils::AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
        2048,
        0,
    )
    .unwrap();

    let key_handle = context
        .create_primary_key(ESYS_TR_RH_OWNER, &signing_key_pub, None, None, None, &[])
        .unwrap();
    let ahash = context
        .hash(
            &MaxBuffer::try_from(vec![0x1, 0x2]).unwrap(),
            HashingAlgorithm::Sha256,
            tss_esapi::utils::Hierarchy::Null,
        )
        .unwrap()
        .0;

    let scheme = tss_esapi::tss2_esys::TPMT_SIG_SCHEME {
        scheme: tss_constants::TPM2_ALG_NULL,
        details: Default::default(),
    };
    let validation = tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
        tag: tss_constants::TPM2_ST_HASHCHECK,
        hierarchy: tss_constants::TPM2_RH_NULL,
        digest: Default::default(),
    };
    // A signature over just the policy_digest, since the policy_ref is empty
    let signature = context
        .sign(key_handle, &ahash, scheme, &validation)
        .unwrap();
    let tkt = context
        .verify_signature(key_handle, &ahash, &signature.try_into().unwrap())
        .unwrap();

    context.set_sessions(old_ses);

    tkt
}

fn get_pcr_hash_alg_from_name(name: Option<&String>) -> HashingAlgorithm {
    match name {
        None => HashingAlgorithm::Sha256,
        Some(val) => match val.to_lowercase().as_str() {
            "sha1" => HashingAlgorithm::Sha1,
            "sha256" => HashingAlgorithm::Sha256,
            "sha384" => HashingAlgorithm::Sha384,
            "sha512" => HashingAlgorithm::Sha512,
            _ => panic!(format!("Unsupported hash algo: {:?}", name)),
        },
    }
}

impl TryFrom<&SignedPolicyStep> for TPMPolicyStep {
    type Error = Error;

    fn try_from(spolicy: &SignedPolicyStep) -> Result<Self, Error> {
        match spolicy {
            SignedPolicyStep::PCRs {
                pcr_ids,
                hash_algorithm,
                value: _,
            } => Ok(TPMPolicyStep::PCRs(
                get_pcr_hash_alg_from_name(Some(&hash_algorithm)),
                pcr_ids.iter().map(|x| *x as u64).collect(),
                Box::new(TPMPolicyStep::NoStep),
            )),
        }
    }
}
