CREATE INDEX IF NOT EXISTS audit_events_org_actor_kind_created_id_idx
    ON audit_events(organization_id, actor_kind, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS audit_events_org_actor_id_created_id_idx
    ON audit_events(organization_id, actor_id, created_at DESC, id DESC)
    WHERE actor_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS audit_events_org_lower_action_prefix_idx
    ON audit_events(organization_id, (lower(action)) text_pattern_ops, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS audit_events_org_lower_target_prefix_idx
    ON audit_events(organization_id, (lower(target)) text_pattern_ops, created_at DESC, id DESC);
