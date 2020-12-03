mod utils;

use std::convert::TryFrom;
use std::fs;

use tss_esapi::constants::algorithm::HashingAlgorithm;

use tpm2_policy::{PublicKey, SignedPolicyList, TPMPolicyStep};

const TEST_POLICY: &str = "---
- policy_ref:
  steps:
    - PCRs:
        hash_algorithm: sha256
        selection:
          - pcr_id: 21
            value: \"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\"
          - pcr_id: 22
            value: \"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\"";

fn get_signed_policy() -> (String, String) {
    utils::run_with_tempdir(|tmpdir| {
        let signed_policy = utils::run_signtool(tmpdir, TEST_POLICY);
        let pubkey =
            fs::read_to_string(tmpdir.join("publickey.json")).expect("Error reading pubkey");

        (pubkey, signed_policy)
    })
}

#[test]
fn test_deserialize() {
    let (pubkey, signed_policy) = get_signed_policy();

    let _ = serde_json::from_str::<PublicKey>(&pubkey).unwrap();
    let _ = serde_json::from_str::<SignedPolicyList>(&signed_policy).unwrap();
}

#[test]
fn test_send_policy_authorized() {
    let (pubkey, signed_policy) = get_signed_policy();

    let pubkey = serde_json::from_str::<PublicKey>(&pubkey).unwrap();
    let signed_policy = serde_json::from_str::<SignedPolicyList>(&signed_policy).unwrap();

    let policy = TPMPolicyStep::Authorized {
        signkey: pubkey,
        policy_ref: vec![],
        policies: Some(signed_policy),
        next: Box::new(TPMPolicyStep::NoStep),
    };

    let mut ctx = utils::get_tpm2_ctx();

    let _ = policy.send_policy(&mut ctx, false).unwrap();
}

#[test]
fn test_send_trial_policy_authorized() {
    let (pubkey, signed_policy) = get_signed_policy();

    let pubkey = serde_json::from_str::<PublicKey>(&pubkey).unwrap();
    let signed_policy = serde_json::from_str::<SignedPolicyList>(&signed_policy).unwrap();

    let policy = TPMPolicyStep::Authorized {
        signkey: pubkey,
        policy_ref: vec![],
        policies: Some(signed_policy),
        next: Box::new(TPMPolicyStep::NoStep),
    };

    let mut ctx = utils::get_tpm2_ctx();

    let _ = policy.send_policy(&mut ctx, true).unwrap();
}

#[test]
fn test_send_wellknown_policy_authorized() {
    let signkey = {
        let contents = fs::read_to_string("tests/fixtures/pubkey.json").unwrap();
        serde_json::from_str::<PublicKey>(&contents).unwrap()
    };

    let policies = {
        let contents = fs::read_to_string("tests/fixtures/signedpolicy.json").unwrap();
        serde_json::from_str::<SignedPolicyList>(&contents).unwrap()
    };

    let policy = TPMPolicyStep::Authorized {
        signkey,
        policy_ref: vec![],
        policies: Some(policies),
        next: Box::new(TPMPolicyStep::NoStep),
    };

    let mut ctx = utils::get_tpm2_ctx();

    const EXPECTED: [u8; 32] = [
        202, 175, 146, 109, 169, 68, 83, 0, 134, 132, 136, 40, 231, 191, 42, 234, 60, 132, 235,
        159, 123, 206, 17, 35, 42, 137, 69, 18, 46, 56, 152, 99,
    ];

    let (_, digest) = policy.send_policy(&mut ctx, true).unwrap();
    let digest = digest.unwrap();
    let digest = <[u8; 32]>::try_from(digest).unwrap();
    assert_eq!(digest, EXPECTED);
}

#[test]
fn test_send_wellknown_policy_pcr() {
    let policy = TPMPolicyStep::PCRs(
        HashingAlgorithm::Sha256,
        vec![0b_0000_0000, 0b_0000_0000, 0b_0000_0000_0001],
        Box::new(TPMPolicyStep::NoStep),
    );

    let mut ctx = utils::get_tpm2_ctx();

    /*const EXPECTED: [u8; 32] = [
        56, 149, 100, 61, 120, 47, 146, 3, 123, 196, 97, 70, 119, 224, 46, 52, 178, 151, 8, 242,
        90, 118, 183, 117, 234, 249, 33, 160, 238, 74, 127, 205,
    ];*/

    let (_, _digest) = policy.send_policy(&mut ctx, true).unwrap();
    //let digest = digest.unwrap();
    //let digest = <[u8; 32]>::try_from(digest).unwrap();
    //assert_eq!(digest, EXPECTED);
}

#[test]
fn test_send_wellknown_policy_nostep() {
    let policy = TPMPolicyStep::NoStep;

    let mut ctx = utils::get_tpm2_ctx();

    let (_, digest) = policy.send_policy(&mut ctx, true).unwrap();
    assert_eq!(digest, None);
}
