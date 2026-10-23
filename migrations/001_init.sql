CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text UNIQUE NOT NULL,
    password_hash text NOT NULL,
    role text NOT NULL DEFAULT 'customer'
        CHECK (role IN ('customer','founder','admin')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS wallets (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    currency text NOT NULL DEFAULT 'NGN',
    available_kobo bigint NOT NULL DEFAULT 0
        CHECK (available_kobo >= 0),
    reserved_kobo bigint NOT NULL DEFAULT 0
        CHECK (reserved_kobo >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ledger_entries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id),
    kind text NOT NULL,
    amount_kobo bigint NOT NULL,
    reference text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS payouts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id uuid NOT NULL REFERENCES users(id),

    reference text UNIQUE NOT NULL,

    account_number text NOT NULL,
    bank_code text NOT NULL,
    account_name text NOT NULL,

    recipient_code text,

    amount_kobo bigint NOT NULL
        CHECK (amount_kobo > 0),

    status text NOT NULL
        CHECK (
            status IN (
                'PENDING_APPROVAL',
                'PROCESSING',
                'SUCCESS',
                'FAILED',
                'REVERSED',
                'UNKNOWN'
            )
        ),

    approval_status text NOT NULL DEFAULT 'NOT_REQUIRED'
        CHECK (
            approval_status IN (
                'NOT_REQUIRED',
                'PENDING',
                'APPROVED',
                'REJECTED'
            )
        ),

    provider_status text,

    provider_response jsonb,

    failure_reason text,

    created_at timestamptz NOT NULL DEFAULT now(),

    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_payouts_user_created
ON payouts(user_id, created_at);

CREATE INDEX IF NOT EXISTS idx_payouts_reference
ON payouts(reference);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    user_id uuid NOT NULL REFERENCES users(id),

    key text NOT NULL,

    request_hash text NOT NULL,

    response_code int NOT NULL,

    response_body jsonb NOT NULL,

    created_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (user_id, key)
);

CREATE TABLE IF NOT EXISTS webhook_events (
    event_id text PRIMARY KEY,

    event_type text NOT NULL,

    payload jsonb NOT NULL,

    received_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    actor_user_id uuid REFERENCES users(id),

    action text NOT NULL,

    entity_type text NOT NULL,

    entity_id text,

    details jsonb,

    created_at timestamptz NOT NULL DEFAULT now()
);
