use super::paths::ScimProjectionPath;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(in crate::http) enum ScimProjection {
    #[default]
    Default,
    Include(Vec<ScimProjectionPath>),
    Exclude(Vec<ScimProjectionPath>),
}
