package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/authflow"
	"github.com/oneissuer/oneissuer/internal/storage/postgres/sqlcgen"
)

// CreateAuthTransaction atomically inserts a transaction and audit event.
func (s *Store) CreateAuthTransaction(ctx context.Context, transaction authflow.Transaction, event audit.Event) error {
	return s.inTxWithAudit(ctx, pgx.TxOptions{}, []audit.Event{event}, func(queries *sqlcgen.Queries) error {
		if err := queries.CreateAuthTransaction(ctx, authTransactionParams(transaction)); err != nil {
			return wrapError("create authorization transaction", ErrorKindQuery, err)
		}
		return insertAudit(ctx, queries, event)
	})
}

// FindAuthTransaction resolves a transaction by opaque-token digest.
func (s *Store) FindAuthTransaction(ctx context.Context, tokenHash []byte) (authflow.Transaction, error) {
	row, err := s.queries.GetAuthTransactionByTokenHash(ctx, tokenHash)
	if isNoRows(err) {
		return authflow.Transaction{}, authflow.ErrNotFound
	}
	if err != nil {
		return authflow.Transaction{}, wrapError("find authorization transaction", ErrorKindQuery, err)
	}
	return mapAuthTransaction(row), nil
}

// ConsumeAuthTransaction marks a transaction used once and appends audit atomically.
func (s *Store) ConsumeAuthTransaction(ctx context.Context, id uuid.UUID, now time.Time, event audit.Event) (authflow.Transaction, error) {
	var result authflow.Transaction
	err := s.inTxWithAudit(ctx, pgx.TxOptions{}, []audit.Event{event}, func(queries *sqlcgen.Queries) error {
		row, err := queries.ConsumeAuthTransaction(ctx, sqlcgen.ConsumeAuthTransactionParams{ConsumedAt: timestamp(now), ID: id})
		if isNoRows(err) {
			return authflow.ErrConsumed
		}
		if err != nil {
			return wrapError("consume authorization transaction", ErrorKindQuery, err)
		}
		if err := insertAudit(ctx, queries, event); err != nil {
			return err
		}
		result = mapAuthTransaction(row)
		return nil
	}, func() { result = authflow.Transaction{} })
	return result, err
}

// RejectAuthTransaction terminally consumes one live transaction with a fixed
// protocol reason and appends the supplied value-free audit event atomically.
func (s *Store) RejectAuthTransaction(ctx context.Context, id uuid.UUID, reason string, now time.Time, event audit.Event) (authflow.Transaction, error) {
	var result authflow.Transaction
	err := s.inTxWithAudit(ctx, pgx.TxOptions{}, []audit.Event{event}, func(queries *sqlcgen.Queries) error {
		row, err := queries.RejectAuthTransaction(ctx, sqlcgen.RejectAuthTransactionParams{
			ConsumedAt: timestamp(now), FailureReason: pointerString(reason), ID: id,
		})
		if isNoRows(err) {
			return authflow.ErrConsumed
		}
		if err != nil {
			return wrapError("reject authorization transaction", ErrorKindQuery, err)
		}
		if err := insertAudit(ctx, queries, event); err != nil {
			return err
		}
		result = mapAuthTransaction(row)
		return nil
	}, func() { result = authflow.Transaction{} })
	return result, err
}

// ExpireAuthTransactions marks elapsed live transactions expired.
func (s *Store) ExpireAuthTransactions(ctx context.Context, now time.Time) (int64, error) {
	var total int64
	for {
		var count int64
		var events []audit.Event
		err := s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
			ids, err := queries.ExpireAuthTransactions(ctx, sqlcgen.ExpireAuthTransactionsParams{
				Now: timestamp(now), BatchLimit: cleanupBatchSize,
			})
			if err != nil {
				return wrapError("expire authorization transactions", ErrorKindQuery, err)
			}
			for _, id := range ids {
				event, eventErr := audit.New(audit.AuthorizationTransactionExpired, audit.ResultSuccess, nil, audit.TargetAuthTransaction, &id, "", nil, now)
				if eventErr != nil {
					return eventErr
				}
				if err := insertAudit(ctx, queries, event); err != nil {
					return err
				}
				events = append(events, event)
			}
			count = int64(len(ids))
			return nil
		}, func() {
			count = 0
			events = nil
		})
		if err != nil {
			return total, err
		}
		s.observeAuditEvents(events)
		total += count
		if count < int64(cleanupBatchSize) {
			return total, nil
		}
	}
}

// CleanupAuthTransactions deletes terminal transactions older than the cutoff.
func (s *Store) CleanupAuthTransactions(ctx context.Context, cutoff time.Time) (int64, error) {
	var total int64
	for {
		count, err := s.queries.DeleteRetiredAuthTransactions(ctx, sqlcgen.DeleteRetiredAuthTransactionsParams{
			Cutoff: timestamp(cutoff), BatchLimit: cleanupBatchSize,
		})
		if err != nil {
			return total, wrapError("clean authorization transactions", ErrorKindQuery, err)
		}
		total += count
		if count < int64(cleanupBatchSize) {
			return total, nil
		}
	}
}

func authTransactionParams(value authflow.Transaction) sqlcgen.CreateAuthTransactionParams {
	return sqlcgen.CreateAuthTransactionParams{
		ID: value.ID, TokenHash: value.TokenHash, TransactionKind: string(value.Kind), ClientID: value.ClientID,
		RedirectUri: pointerString(value.RedirectURI), Scopes: value.Scopes,
		PkceChallenge: pointerString(value.PKCEChallenge), PkceMethod: pointerString(value.PKCEMethod),
		StateValue: pointerString(value.State), NonceValue: pointerString(value.Nonce), PromptCreate: value.PromptCreate,
		ResponseType: pointerString(value.ResponseType), ResponseMode: pointerString(value.ResponseMode),
		PromptValues: append([]string{}, value.Prompts...), MaxAgeSeconds: uint32ToInt64(value.MaxAgeSeconds),
		CreatedAt: timestamp(value.CreatedAt), ExpiresAt: timestamp(value.ExpiresAt),
	}
}

func mapAuthTransaction(row sqlcgen.AuthTransaction) authflow.Transaction {
	return authflow.Transaction{
		ID: row.ID, TokenHash: row.TokenHash, Kind: authflow.Kind(row.TransactionKind), ClientID: row.ClientID,
		RedirectURI: valueString(row.RedirectUri), Scopes: row.Scopes, PKCEChallenge: valueString(row.PkceChallenge),
		PKCEMethod: valueString(row.PkceMethod), State: valueString(row.StateValue), Nonce: valueString(row.NonceValue),
		PromptCreate: row.PromptCreate, ResponseType: valueString(row.ResponseType), ResponseMode: valueString(row.ResponseMode),
		Prompts: append([]string(nil), row.PromptValues...), MaxAgeSeconds: int64ToUint32(row.MaxAgeSeconds),
		CreatedAt: requiredTime(row.CreatedAt), ExpiresAt: requiredTime(row.ExpiresAt),
		ConsumedAt: optionalTime(row.ConsumedAt), FailureReason: valueString(row.FailureReason),
	}
}

func uint32ToInt64(value *uint32) *int64 {
	if value == nil {
		return nil
	}
	converted := int64(*value)
	return &converted
}

func int64ToUint32(value *int64) *uint32 {
	if value == nil || *value < 0 || *value > int64(^uint32(0)) {
		return nil
	}
	converted := uint32(*value)
	return &converted
}

func valueString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
