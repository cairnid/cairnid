use super::super::scim_protocol::SCIM_PATCH_OP_SCHEMA;
use super::super::scim_protocol::{SCIM_GROUP_SCHEMA, SCIM_USER_SCHEMA};
use super::scim_patch_request::ScimPatchOperation;
use super::*;
use cairn_database::ScimGroupMember;
use cairn_domain::{Group, MembershipRole, User};
use serde_json::json;
use time::OffsetDateTime;

#[test]
fn scim_user_input_validates_schema_email_and_display_name() {
    let input = scim_user_input(ScimUserRequest {
        schemas: vec![SCIM_USER_SCHEMA.to_owned()],
        user_name: "USER@example.COM".to_owned(),
        external_id: Some(" hr-123 ".to_owned()),
        name: Some(ScimNameRequest {
            formatted: None,
            given_name: Some("Ada".to_owned()),
            family_name: Some("Lovelace".to_owned()),
        }),
        display_name: None,
        active: Some(false),
        emails: vec![ScimEmailRequest {
            value: "user@example.com".to_owned(),
            email_type: Some("work".to_owned()),
            primary: Some(true),
        }],
    })
    .expect("valid SCIM user");

    assert_eq!(input.email, "user@example.com");
    assert_eq!(input.external_id.as_deref(), Some("hr-123"));
    assert_eq!(input.display_name, "Ada Lovelace");
    assert_eq!(input.status, UserStatus::Suspended);
    assert!(!input.email_verified);

    let mismatch = scim_user_input(ScimUserRequest {
        schemas: vec![SCIM_USER_SCHEMA.to_owned()],
        user_name: "user@example.com".to_owned(),
        external_id: None,
        name: None,
        display_name: Some("User".to_owned()),
        active: Some(true),
        emails: vec![ScimEmailRequest {
            value: "other@example.com".to_owned(),
            email_type: Some("work".to_owned()),
            primary: Some(true),
        }],
    })
    .expect_err("mismatched email should fail");
    assert_eq!(mismatch.scim_type, Some("invalidValue"));

    let unsupported_email_type = scim_user_input(ScimUserRequest {
        schemas: vec![SCIM_USER_SCHEMA.to_owned()],
        user_name: "user@example.com".to_owned(),
        external_id: None,
        name: None,
        display_name: Some("User".to_owned()),
        active: Some(true),
        emails: vec![ScimEmailRequest {
            value: "user@example.com".to_owned(),
            email_type: Some("home".to_owned()),
            primary: Some(true),
        }],
    })
    .expect_err("unsupported email type should fail");
    assert_eq!(unsupported_email_type.scim_type, Some("invalidValue"));
}

#[test]
fn scim_group_input_validates_schema_display_name_and_members() {
    let user_id = Uuid::new_v4();
    let input = scim_group_input(ScimGroupRequest {
        schemas: vec![SCIM_GROUP_SCHEMA.to_owned()],
        external_id: Some(" group-123 ".to_owned()),
        display_name: Some(" Engineering ".to_owned()),
        members: vec![ScimGroupMemberRequest {
            value: user_id,
            reference: Some(format!("/scim/v2/Users/{user_id}")),
            member_type: Some("User".to_owned()),
            display: Some("User Example".to_owned()),
        }],
    })
    .expect("valid SCIM group");

    assert_eq!(input.display_name, "Engineering");
    assert_eq!(input.external_id.as_deref(), Some("group-123"));
    assert_eq!(input.member_user_ids, vec![user_id]);

    let nested = scim_group_input(ScimGroupRequest {
        schemas: vec![SCIM_GROUP_SCHEMA.to_owned()],
        external_id: None,
        display_name: Some("Engineering".to_owned()),
        members: vec![ScimGroupMemberRequest {
            value: Uuid::new_v4(),
            reference: None,
            member_type: Some("Group".to_owned()),
            display: None,
        }],
    })
    .expect_err("nested groups are not supported");
    assert_eq!(nested.scim_type, Some("invalidValue"));

    let duplicate = scim_group_input(ScimGroupRequest {
        schemas: vec![SCIM_GROUP_SCHEMA.to_owned()],
        external_id: None,
        display_name: Some("Engineering".to_owned()),
        members: vec![
            ScimGroupMemberRequest {
                value: user_id,
                reference: None,
                member_type: None,
                display: None,
            },
            ScimGroupMemberRequest {
                value: user_id,
                reference: None,
                member_type: None,
                display: None,
            },
        ],
    })
    .expect_err("duplicate members should fail");
    assert_eq!(duplicate.scim_type, Some("invalidValue"));
}

#[test]
fn scim_patch_user_input_applies_resource_and_path_operations() {
    let current_user =
        User::new(Uuid::new_v4(), "user@example.com", "Original User").expect("valid user");

    let input = scim_patch_user_input(
        &current_user,
        ScimPatchRequest {
            schemas: vec![SCIM_PATCH_OP_SCHEMA.to_owned()],
            operations: vec![
                ScimPatchOperation {
                    op: "replace".to_owned(),
                    path: None,
                    value: Some(json!({
                        "userName": "ADA@Example.COM",
                        "externalId": "hr-123",
                        "active": "false",
                        "name": {
                            "givenName": "Ada",
                            "familyName": "Lovelace"
                        },
                        "emails": [{
                            "value": "ada@example.com",
                            "type": "work",
                            "primary": true
                        }]
                    })),
                },
                ScimPatchOperation {
                    op: "Replace".to_owned(),
                    path: Some(format!(
                        "{SCIM_USER_SCHEMA}:emails[value eq \"ada@example.com\"].value"
                    )),
                    value: Some(json!("ada.lovelace@example.com")),
                },
                ScimPatchOperation {
                    op: "replace".to_owned(),
                    path: Some("emails[type eq \"work\"].type".to_owned()),
                    value: Some(json!("work")),
                },
                ScimPatchOperation {
                    op: "replace".to_owned(),
                    path: Some("emails[primary eq true].primary".to_owned()),
                    value: Some(json!(true)),
                },
            ],
        },
    )
    .expect("valid SCIM PATCH");

    assert_eq!(input.email, "ada.lovelace@example.com");
    assert_eq!(input.external_id.as_deref(), Some("hr-123"));
    assert_eq!(input.display_name, "Ada Lovelace");
    assert_eq!(input.status, UserStatus::Suspended);
    assert!(!input.email_verified);
}

#[test]
fn scim_patch_user_input_rejects_unsupported_or_unsafe_operations() {
    let current_user =
        User::new(Uuid::new_v4(), "user@example.com", "Original User").expect("valid user");

    let missing_schema = scim_patch_user_input(
        &current_user,
        ScimPatchRequest {
            schemas: vec![SCIM_USER_SCHEMA.to_owned()],
            operations: vec![ScimPatchOperation {
                op: "replace".to_owned(),
                path: Some("active".to_owned()),
                value: Some(json!(false)),
            }],
        },
    )
    .expect_err("missing PatchOp schema should fail");
    assert_eq!(missing_schema.scim_type, Some("invalidValue"));

    let read_only = scim_patch_user_input(
        &current_user,
        ScimPatchRequest {
            schemas: vec![SCIM_PATCH_OP_SCHEMA.to_owned()],
            operations: vec![ScimPatchOperation {
                op: "replace".to_owned(),
                path: Some("id".to_owned()),
                value: Some(json!("not-allowed")),
            }],
        },
    )
    .expect_err("read-only id should fail");
    assert_eq!(read_only.scim_type, Some("mutability"));

    let remove_required = scim_patch_user_input(
        &current_user,
        ScimPatchRequest {
            schemas: vec![SCIM_PATCH_OP_SCHEMA.to_owned()],
            operations: vec![ScimPatchOperation {
                op: "remove".to_owned(),
                path: Some("userName".to_owned()),
                value: None,
            }],
        },
    )
    .expect_err("required username should not be removable");
    assert_eq!(remove_required.scim_type, Some("mutability"));

    let no_target = scim_patch_user_input(
        &current_user,
        ScimPatchRequest {
            schemas: vec![SCIM_PATCH_OP_SCHEMA.to_owned()],
            operations: vec![ScimPatchOperation {
                op: "replace".to_owned(),
                path: Some("emails[value eq \"other@example.com\"].value".to_owned()),
                value: Some(json!("new@example.com")),
            }],
        },
    )
    .expect_err("unmatched email filter should fail");
    assert_eq!(no_target.scim_type, Some("noTarget"));

    let unsupported_email_type = scim_patch_user_input(
        &current_user,
        ScimPatchRequest {
            schemas: vec![SCIM_PATCH_OP_SCHEMA.to_owned()],
            operations: vec![ScimPatchOperation {
                op: "replace".to_owned(),
                path: Some("emails[type eq \"work\"].type".to_owned()),
                value: Some(json!("home")),
            }],
        },
    )
    .expect_err("unsupported email type should fail");
    assert_eq!(unsupported_email_type.scim_type, Some("invalidValue"));

    let demote_primary = scim_patch_user_input(
        &current_user,
        ScimPatchRequest {
            schemas: vec![SCIM_PATCH_OP_SCHEMA.to_owned()],
            operations: vec![ScimPatchOperation {
                op: "replace".to_owned(),
                path: Some("emails[primary eq true].primary".to_owned()),
                value: Some(json!(false)),
            }],
        },
    )
    .expect_err("primary work email demotion should fail");
    assert_eq!(demote_primary.scim_type, Some("invalidValue"));

    let unsupported_path = scim_patch_user_input(
        &current_user,
        ScimPatchRequest {
            schemas: vec![SCIM_PATCH_OP_SCHEMA.to_owned()],
            operations: vec![ScimPatchOperation {
                op: "replace".to_owned(),
                path: Some("title".to_owned()),
                value: Some(json!("Engineer")),
            }],
        },
    )
    .expect_err("unsupported path should fail");
    assert_eq!(unsupported_path.scim_type, Some("invalidPath"));
}

fn test_group_with_members(user_ids: &[UserId]) -> (Group, Vec<ScimGroupMember>, OffsetDateTime) {
    let organization_id = Uuid::new_v4();
    let group_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let group = Group {
        id: group_id,
        organization_id,
        slug: "engineering".to_owned(),
        scim_external_id: Some("old-group".to_owned()),
        display_name: "Engineering".to_owned(),
        created_at: now,
    };
    let members = user_ids
        .iter()
        .enumerate()
        .map(|(index, user_id)| ScimGroupMember {
            group_id,
            user_id: *user_id,
            email: format!("user-{index}@example.com"),
            display_name: format!("User {index}"),
            role: MembershipRole::Member,
            created_at: now,
        })
        .collect();
    (group, members, now)
}

#[test]
fn scim_patch_group_input_applies_resource_and_member_operations() {
    let first_user_id = Uuid::new_v4();
    let second_user_id = Uuid::new_v4();
    let third_user_id = Uuid::new_v4();
    let (current_group, current_members, _) =
        test_group_with_members(&[first_user_id, second_user_id]);

    let input = scim_patch_group_input(
        &current_group,
        &current_members,
        ScimPatchRequest {
            schemas: vec![SCIM_PATCH_OP_SCHEMA.to_owned()],
            operations: vec![
                ScimPatchOperation {
                    op: "replace".to_owned(),
                    path: None,
                    value: Some(json!({
                        "displayName": "Product Engineering",
                        "externalId": "new-group"
                    })),
                },
                ScimPatchOperation {
                    op: "add".to_owned(),
                    path: Some("members".to_owned()),
                    value: Some(json!([{ "value": third_user_id, "type": "User" }])),
                },
                ScimPatchOperation {
                    op: "remove".to_owned(),
                    path: Some(format!("members[value eq \"{first_user_id}\"]")),
                    value: None,
                },
            ],
        },
    )
    .expect("valid SCIM group patch");

    assert_eq!(input.display_name, "Product Engineering");
    assert_eq!(input.external_id.as_deref(), Some("new-group"));
    assert_eq!(input.member_user_ids, vec![second_user_id, third_user_id]);
}

#[test]
fn scim_patch_group_input_supports_filtered_member_add_replace_and_remove() {
    let first_user_id = Uuid::new_v4();
    let second_user_id = Uuid::new_v4();
    let third_user_id = Uuid::new_v4();
    let fourth_user_id = Uuid::new_v4();
    let non_member_user_id = Uuid::new_v4();
    let (mut current_group, current_members, _) =
        test_group_with_members(&[first_user_id, second_user_id]);
    current_group.scim_external_id = None;

    let input = scim_patch_group_input(
        &current_group,
        &current_members,
        ScimPatchRequest {
            schemas: vec![SCIM_PATCH_OP_SCHEMA.to_owned()],
            operations: vec![
                ScimPatchOperation {
                    op: "add".to_owned(),
                    path: Some(format!("members[value eq \"{third_user_id}\"]")),
                    value: Some(json!({ "value": third_user_id, "type": "User" })),
                },
                ScimPatchOperation {
                    op: "add".to_owned(),
                    path: Some(format!("members[value eq \"{third_user_id}\"]")),
                    value: Some(json!({ "value": third_user_id, "type": "User" })),
                },
                ScimPatchOperation {
                    op: "replace".to_owned(),
                    path: Some(format!("members[value eq \"{first_user_id}\"]")),
                    value: Some(json!({ "value": fourth_user_id, "type": "User" })),
                },
                ScimPatchOperation {
                    op: "remove".to_owned(),
                    path: Some(format!("members[value eq \"{non_member_user_id}\"]")),
                    value: None,
                },
            ],
        },
    )
    .expect("valid filtered SCIM group patch");

    assert_eq!(
        input.member_user_ids,
        vec![fourth_user_id, second_user_id, third_user_id]
    );
}

#[test]
fn scim_patch_group_input_supports_members_value_paths() {
    let first_user_id = Uuid::new_v4();
    let second_user_id = Uuid::new_v4();
    let third_user_id = Uuid::new_v4();
    let fourth_user_id = Uuid::new_v4();
    let (mut current_group, current_members, _) =
        test_group_with_members(&[first_user_id, second_user_id]);
    current_group.scim_external_id = None;

    let input = scim_patch_group_input(
        &current_group,
        &current_members,
        ScimPatchRequest {
            schemas: vec![SCIM_PATCH_OP_SCHEMA.to_owned()],
            operations: vec![
                ScimPatchOperation {
                    op: "add".to_owned(),
                    path: Some("members.value".to_owned()),
                    value: Some(json!([
                        second_user_id.to_string(),
                        third_user_id.to_string()
                    ])),
                },
                ScimPatchOperation {
                    op: "replace".to_owned(),
                    path: Some(format!(
                        "{SCIM_GROUP_SCHEMA}:members[value eq \"{first_user_id}\"].value"
                    )),
                    value: Some(json!(fourth_user_id.to_string())),
                },
                ScimPatchOperation {
                    op: "remove".to_owned(),
                    path: Some(format!("members[value eq \"{second_user_id}\"].value")),
                    value: None,
                },
            ],
        },
    )
    .expect("valid members.value SCIM group patch");

    assert_eq!(input.member_user_ids, vec![fourth_user_id, third_user_id]);
}

#[test]
fn scim_patch_group_input_rejects_unsafe_or_unsupported_operations() {
    let existing_user_id = Uuid::new_v4();
    let (group, current_members, _) = test_group_with_members(&[existing_user_id]);
    let missing_schema = scim_patch_group_input(
        &group,
        &[],
        ScimPatchRequest {
            schemas: vec![SCIM_GROUP_SCHEMA.to_owned()],
            operations: vec![ScimPatchOperation {
                op: "replace".to_owned(),
                path: Some("displayName".to_owned()),
                value: Some(json!("Product Engineering")),
            }],
        },
    )
    .expect_err("missing PatchOp schema should fail");
    assert_eq!(missing_schema.scim_type, Some("invalidValue"));

    let remove_display_name = scim_patch_group_input(
        &group,
        &[],
        ScimPatchRequest {
            schemas: vec![SCIM_PATCH_OP_SCHEMA.to_owned()],
            operations: vec![ScimPatchOperation {
                op: "remove".to_owned(),
                path: Some("displayName".to_owned()),
                value: None,
            }],
        },
    )
    .expect_err("required displayName should not be removable");
    assert_eq!(remove_display_name.scim_type, Some("mutability"));

    let no_target = scim_patch_group_input(
        &group,
        &current_members,
        ScimPatchRequest {
            schemas: vec![SCIM_PATCH_OP_SCHEMA.to_owned()],
            operations: vec![ScimPatchOperation {
                op: "replace".to_owned(),
                path: Some(format!("members[value eq \"{}\"]", Uuid::new_v4())),
                value: Some(json!({ "value": existing_user_id, "type": "User" })),
            }],
        },
    )
    .expect_err("unmatched member replace filter should fail");
    assert_eq!(no_target.scim_type, Some("noTarget"));

    let mismatched_filtered_add = scim_patch_group_input(
        &group,
        &current_members,
        ScimPatchRequest {
            schemas: vec![SCIM_PATCH_OP_SCHEMA.to_owned()],
            operations: vec![ScimPatchOperation {
                op: "add".to_owned(),
                path: Some(format!("members[value eq \"{}\"]", Uuid::new_v4())),
                value: Some(json!({ "value": existing_user_id, "type": "User" })),
            }],
        },
    )
    .expect_err("filtered add value must match the filter");
    assert_eq!(mismatched_filtered_add.scim_type, Some("invalidValue"));

    let generated_member_attribute = scim_patch_group_input(
        &group,
        &current_members,
        ScimPatchRequest {
            schemas: vec![SCIM_PATCH_OP_SCHEMA.to_owned()],
            operations: vec![ScimPatchOperation {
                op: "replace".to_owned(),
                path: Some(format!("members[value eq \"{existing_user_id}\"].display")),
                value: Some(json!("Updated Display")),
            }],
        },
    )
    .expect_err("generated member attributes are not mutable");
    assert_eq!(generated_member_attribute.scim_type, Some("mutability"));
}
