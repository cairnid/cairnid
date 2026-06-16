use super::super::super::ReleaseEvidenceEnvironmentRequirement;
use super::helpers::environment_requirement_satisfied;

#[test]
fn environment_requirement_accepts_any_complete_alternative() {
    let requirement = ReleaseEvidenceEnvironmentRequirement {
        alternatives: vec![
            vec!["CAIRN_KEY_ENCRYPTION_KEY"],
            vec![
                "CAIRN_SIGNING_KEY_ID",
                "CAIRN_SIGNING_PRIVATE_KEY_PEM",
                "CAIRN_SIGNING_PUBLIC_JWK",
            ],
        ],
        purpose: "OIDC signing source",
        contains_secret: true,
    };

    assert!(environment_requirement_satisfied(&requirement, &|name| {
        name == "CAIRN_KEY_ENCRYPTION_KEY"
    }));
    assert!(environment_requirement_satisfied(&requirement, &|name| {
        matches!(
            name,
            "CAIRN_SIGNING_KEY_ID" | "CAIRN_SIGNING_PRIVATE_KEY_PEM" | "CAIRN_SIGNING_PUBLIC_JWK"
        )
    }));
    assert!(!environment_requirement_satisfied(&requirement, &|name| {
        matches!(
            name,
            "CAIRN_SIGNING_KEY_ID" | "CAIRN_SIGNING_PRIVATE_KEY_PEM"
        )
    }));
}
