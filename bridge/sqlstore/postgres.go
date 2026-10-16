// Package sqlstore provides a PostgreSQL execution journal for a bridge runtime.
// The application supplies its database/sql driver and custody-local database.
// It has no dependency on Lotor Control or a third-party runtime package.
package sqlstore

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/2kims/lotor-go/bridge"
)

type Store struct {
	database  *sql.DB
	namespace string
}

var _ bridge.ExecutionStore = (*Store)(nil)

func New(database *sql.DB, namespace string) (*Store, error) {
	if database == nil || !identifier(namespace, 256) {
		return nil, bridge.ErrInvalid
	}
	return &Store{database: database, namespace: namespace}, nil
}

// Initialize explicitly installs the journal in the configured runtime database.
// Run once as a deployment migration, not on every Lambda invocation. Results
// may contain protected customer data: keep this DB inside the runtime's custody
// boundary. Never point it at Lotor Control as a convenience fallback.
func (store *Store) Initialize(ctx context.Context) error {
	for _, statement := range []string{
		`create schema if not exists lotor_function_runtime`,
		`create table if not exists lotor_function_runtime.executions (
            namespace text not null check (length(namespace) between 1 and 256),
            operation_id text not null check (length(operation_id) between 1 and 513),
            request_digest text not null check (request_digest ~ '^[a-f0-9]{64}$'),
            result jsonb check (result is null or jsonb_typeof(result) = 'object'),
            created_at timestamptz not null default clock_timestamp(),
            primary key (namespace, operation_id)
        )`,
	} {
		if _, err := store.database.ExecContext(ctx, statement); err != nil {
			return bridge.ErrUnavailable
		}
	}
	return nil
}

// Reserve never steals or expires an incomplete reservation. An ambiguous
// provider effect remains non-reexecutable across restarts and reconnects.
func (store *Store) Reserve(ctx context.Context, operationID, digest string) (*bridge.Result, error) {
	if !validIdentity(operationID, digest) {
		return nil, bridge.ErrInvalid
	}
	inserted, err := store.database.ExecContext(ctx, `insert into lotor_function_runtime.executions(namespace, operation_id, request_digest)
        values ($1,$2,$3) on conflict (namespace, operation_id) do nothing`, store.namespace, operationID, digest)
	if err != nil {
		return nil, bridge.ErrUnavailable
	}
	count, err := inserted.RowsAffected()
	if err != nil {
		return nil, bridge.ErrUnavailable
	}
	if count == 1 {
		return nil, nil
	}
	var existing string
	var raw []byte
	err = store.database.QueryRowContext(ctx, `select request_digest, result from lotor_function_runtime.executions where namespace=$1 and operation_id=$2`, store.namespace, operationID).Scan(&existing, &raw)
	if err != nil {
		return nil, bridge.ErrUnavailable
	}
	if existing != digest {
		return nil, bridge.ErrConflict
	}
	if len(raw) == 0 {
		return nil, bridge.ErrInProgress
	}
	var result bridge.Result
	if len(raw) > bridge.MaximumBodyBytes || json.Unmarshal(raw, &result) != nil {
		return nil, bridge.ErrUnavailable
	}
	return &result, nil
}

func (store *Store) Complete(ctx context.Context, operationID, digest string, result bridge.Result) error {
	if !validIdentity(operationID, digest) {
		return bridge.ErrInvalid
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > bridge.MaximumBodyBytes/2 {
		return bridge.ErrInvalid
	}
	updated, err := store.database.ExecContext(ctx, `update lotor_function_runtime.executions set result=$4::jsonb
        where namespace=$1 and operation_id=$2 and request_digest=$3
            and (result is null or result=$4::jsonb)`, store.namespace, operationID, digest, string(raw))
	if err != nil {
		return bridge.ErrUnavailable
	}
	count, err := updated.RowsAffected()
	if err != nil {
		return bridge.ErrUnavailable
	}
	if count != 1 {
		return bridge.ErrConflict
	}
	return nil
}

func validIdentity(operationID, digest string) bool {
	decoded, err := hex.DecodeString(digest)
	return identifier(operationID, 513) && err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == digest
}

func identifier(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.IndexFunc(value, func(character rune) bool { return character <= 32 || character >= 127 }) == -1
}
