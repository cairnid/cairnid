import type { AuditEvent } from '$lib/api';

export function auditActorLabel(event: AuditEvent) {
  return event.actor_id ? `${event.actor_kind}:${event.actor_id}` : event.actor_kind;
}

export function metadataLabel(metadata: unknown) {
  if (metadata === null || metadata === undefined) {
    return '{}';
  }
  try {
    return JSON.stringify(metadata) ?? String(metadata);
  } catch {
    return String(metadata);
  }
}
