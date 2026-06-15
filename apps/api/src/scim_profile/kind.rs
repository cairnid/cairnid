use super::types::ScimConnectorProfileError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScimConnectorProfileKind {
    Generic,
    Okta,
    Entra,
}

impl ScimConnectorProfileKind {
    pub(super) fn parse(value: &str) -> Result<Self, ScimConnectorProfileError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "generic" => Ok(Self::Generic),
            "okta" => Ok(Self::Okta),
            "entra" | "azure-ad" | "azuread" => Ok(Self::Entra),
            other => Err(ScimConnectorProfileError::UnknownProfile(other.to_owned())),
        }
    }

    pub(super) const fn key(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Okta => "okta",
            Self::Entra => "entra",
        }
    }

    pub(super) const fn display_name(self) -> &'static str {
        match self {
            Self::Generic => "Generic SCIM 2.0",
            Self::Okta => "Okta SCIM 2.0",
            Self::Entra => "Microsoft Entra SCIM 2.0",
        }
    }
}
