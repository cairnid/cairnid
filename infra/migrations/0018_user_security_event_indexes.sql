CREATE INDEX IF NOT EXISTS audit_events_org_metadata_subject_user_created_id_idx
    ON audit_events(organization_id, (metadata->>'subject_user_id'), created_at DESC, id DESC)
    WHERE metadata ? 'subject_user_id';

CREATE INDEX IF NOT EXISTS audit_events_org_metadata_user_created_id_idx
    ON audit_events(organization_id, (metadata->>'user_id'), created_at DESC, id DESC)
    WHERE metadata ? 'user_id';
