CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'USER'
        CHECK (role IN ('USER', 'ADMIN', 'FOUNDER')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS wallets (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    currency CHAR(3) NOT NULL DEFAULT 'NGN',
    available_kobo BIGINT NOT NULL DEFAULT 0
        CHECK (available_kobo >= 0),
    reserved_kobo BIGINT NOT NULL DEFAULT 0
        CHECK (reserved_kobo >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (user_id, currency)
);

CREATE TABLE IF NOT EXISTS payouts (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,

    reference TEXT NOT NULL UNIQUE,

    account_number TEXT NOT NULL,
    bank_code TEXT NOT NULL,
    account_name TEXT NOT NULL DEFAULT '',

    amount_kobo BIGINT NOT NULL
        CHECK (amount_kobo > 0),

    status TEXT NOT NULL DEFAULT 'PENDING_APPROVAL'
        CHECK (
            status IN (
                'PENDING_APPROVAL',
                'PROCESSING',
                'SUCCESS',
                'FAILED',
                'REJECTED',
                'REVERSED',
                'UNKNOWN'
            )
        ),

    approval_status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (
            approval_status IN (
                'PENDING',
                'APPROVED',
                'REJECTED'
            )
        ),

    recipient_code TEXT,
    provider_status TEXT,
    provider_response JSONB,
    failure_reason TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_payouts_user_created
ON payouts(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_payouts_reference
ON payouts(reference);

CREATE INDEX IF NOT EXISTS idx_payouts_status
ON payouts(status);

CREATE TABLE IF NOT EXISTS ledger_entries (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,

    kind TEXT NOT NULL,

    amount_kobo BIGINT NOT NULL,
    reference TEXT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ledger_user_created
ON ledger_entries(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ledger_reference
ON ledger_entries(reference);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    id BIGSERIAL PRIMARY KEY,

    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    key TEXT NOT NULL,

    response_code INTEGER NOT NULL,
    response_body JSONB NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(user_id, key)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY,

    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,

    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,

    details JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_created
ON audit_logs(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_entity
ON audit_logs(entity_type, entity_id);

CREATE TABLE IF NOT EXISTS webhook_events (
    event_id TEXT PRIMARY KEY,

    event_type TEXT NOT NULL,

    payload JSONB NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_event_type
ON webhook_events(event_type);

CREATE INDEX IF NOT EXISTS idx_webhook_created
ON webhook_events(created_at DESC);
