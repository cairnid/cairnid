#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LifecycleEmailTemplateContract {
    kind: &'static str,
    allowed_templates: &'static [&'static str],
}

pub const REQUIRED_LIFECYCLE_EMAIL_KINDS: &[&str] = &[
    "invitation",
    "email_verification",
    "password_recovery",
    "password_recovered_notification",
    "password_changed_notification",
    "new_login_notification",
];

const LIFECYCLE_EMAIL_TEMPLATE_CONTRACTS: &[LifecycleEmailTemplateContract] = &[
    LifecycleEmailTemplateContract {
        kind: "invitation",
        allowed_templates: &["account_invitation"],
    },
    LifecycleEmailTemplateContract {
        kind: "email_verification",
        allowed_templates: &["email_verification"],
    },
    LifecycleEmailTemplateContract {
        kind: "password_recovery",
        allowed_templates: &["password_recovery"],
    },
    LifecycleEmailTemplateContract {
        kind: "password_recovered_notification",
        allowed_templates: &["password_recovered_notification"],
    },
    LifecycleEmailTemplateContract {
        kind: "password_changed_notification",
        allowed_templates: &["password_changed_notification"],
    },
    LifecycleEmailTemplateContract {
        kind: "new_login_notification",
        allowed_templates: &["new_login_notification"],
    },
];

fn allowed_lifecycle_email_templates(kind: &str) -> Option<&'static [&'static str]> {
    LIFECYCLE_EMAIL_TEMPLATE_CONTRACTS
        .iter()
        .find(|contract| contract.kind == kind)
        .map(|contract| contract.allowed_templates)
}

pub fn lifecycle_email_template_is_allowed(kind: &str, template: &str) -> bool {
    allowed_lifecycle_email_templates(kind)
        .is_some_and(|allowed_templates| allowed_templates.contains(&template))
}

pub fn lifecycle_email_template_requirement(kind: &str) -> Option<String> {
    allowed_lifecycle_email_templates(kind).map(|allowed_templates| {
        format!(
            "template must be one of {} for lifecycle kind {kind}",
            allowed_templates.join(", ")
        )
    })
}
