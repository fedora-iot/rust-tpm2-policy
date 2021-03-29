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

use crate::error::{Error, Result};

use std::convert::TryFrom;

use serde::{Deserialize, Serialize};
use tss_esapi::{
    constants::tss as tss_constants, interface_types::algorithm::HashingAlgorithm,
    utils::AsymSchemeUnion,
};

fn serialize_as_base64<S>(bytes: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&base64::encode(bytes))
}

fn deserialize_as_base64<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer)
        .and_then(|string| base64::decode(&string).map_err(serde::de::Error::custom))
}

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
    pub policy_ref: Vec<u8>,
    // steps contains the policy steps that are signed
    pub steps: Vec<SignedPolicyStep>,
    // signature contains the signature over aHash
    #[serde(
        deserialize_with = "deserialize_as_base64",
        serialize_with = "serialize_as_base64"
    )]
    pub signature: Vec<u8>,
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
    pub(crate) fn get_signing_scheme(&self) -> tss_esapi::utils::AsymSchemeUnion {
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

    fn try_from(publickey: &PublicKey) -> Result<Self> {
        match publickey {
            PublicKey::RSA {
                scheme,
                hashing_algo,
                modulus,
                exponent,
            } => {
                let object_attributes =
                    tss_esapi::attributes::object::ObjectAttributesBuilder::new()
                        .with_fixed_tpm(false)
                        .with_fixed_parent(false)
                        .with_sensitive_data_origin(false)
                        .with_user_with_auth(true)
                        .with_decrypt(false)
                        .with_sign_encrypt(true)
                        .with_restricted(false);

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
                    .with_object_attributes(object_attributes.build()?)
                    .with_unique(tss_esapi::utils::PublicIdUnion::Rsa(rsa_uniq))
                    .build()?)
            }
        }
    }
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

    fn try_from(spolicy: &SignedPolicyStep) -> Result<Self> {
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
