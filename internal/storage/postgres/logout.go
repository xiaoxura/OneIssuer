package postgres

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/logout"
	"github.com/oneissuer/oneissuer/internal/storage/postgres/sqlcgen"
)

// CreateLogoutTransaction persists only the zero-authority, digest-backed
// transaction produced by the logout Service.
func (s *Store) CreateLogoutTransaction(ctx context.Context, value logout.Transaction) error {
	if value.ID == uuid.Nil || len(value.LookupHash) != 32 || value.Stage != logout.StagePreConfirm ||
		value.CreatedAt.IsZero() || !value.ExpiresAt.After(value.CreatedAt) {
		return logout.ErrInvalid
	}
	if err := s.queries.CreateLogoutTransaction(ctx, sqlcgen.CreateLogoutTransactionParams{
		ID: value.ID, LookupHash: value.LookupHash, VerifiedClientID: value.VerifiedClientID,
		PostLogoutRedirectUri: pointerString(value.PostLogoutRedirectURI), StateValue: pointerString(value.State),
		HintSubject: pointerString(value.HintSubject), CreatedAt: timestamp(value.CreatedAt), ExpiresAt: timestamp(value.ExpiresAt),
	}); err != nil {
		return wrapError("create logout transaction", ErrorKindQuery, err)
	}
	return nil
}

// BindLogoutTransaction performs the clean-GET transition under the frozen
// Logout transaction -> Session -> per-Session-cap lock order.
func (s *Store) BindLogoutTransaction(ctx context.Context, input logout.BindInput) (logout.Transaction, error) {
	if len(input.LookupHash) != 32 || len(input.CSRFHash) != 32 || input.UserID == uuid.Nil ||
		input.SessionID == uuid.Nil || input.SessionBindingID == uuid.Nil || input.Now.IsZero() ||
		input.MaxActive < 1 || input.MaxActive > 5 || input.MaxAttempts < 1 || input.MaxAttempts > 10 {
		return logout.Transaction{}, logout.ErrNotFound
	}
	var result logout.Transaction
	err := s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		row, err := queries.LockLogoutTransactionByLookupHash(ctx, input.LookupHash)
		if isNoRows(err) {
			return logout.ErrNotFound
		}
		if err != nil {
			return wrapError("lock logout transaction for bind", ErrorKindQuery, err)
		}
		transaction := mapLogoutTransaction(row)
		if !sameDigest(transaction.LookupHash, input.LookupHash) || transaction.ConsumedAt != nil ||
			!input.Now.UTC().Before(transaction.ExpiresAt) || transaction.AttemptCount >= input.MaxAttempts {
			return logout.ErrNotFound
		}

		sessionRow, err := queries.LockLoginSessionByID(ctx, input.SessionID)
		if isNoRows(err) {
			return logout.ErrNotFound
		}
		if err != nil {
			return wrapError("lock browser session for logout bind", ErrorKindQuery, err)
		}
		if sessionRow.UserID != input.UserID || sessionRow.SessionBindingID != input.SessionBindingID ||
			sessionRow.RevokedAt.Valid || !input.Now.UTC().Before(requiredTime(sessionRow.ExpiresAt)) ||
			!input.Now.UTC().Before(requiredTime(sessionRow.IdleExpiresAt)) {
			return logout.ErrNotFound
		}

		sessionID, userID, bindingID := input.SessionID, input.UserID, input.SessionBindingID
		switch transaction.Stage {
		case logout.StagePreConfirm:
			count, err := queries.CountLiveBoundLogoutTransactionsBySession(ctx, sqlcgen.CountLiveBoundLogoutTransactionsBySessionParams{
				SessionID: &sessionID, Now: timestamp(input.Now),
			})
			if err != nil {
				return wrapError("count live logout transactions", ErrorKindQuery, err)
			}
			if count >= int64(input.MaxActive) {
				return logout.ErrCapacity
			}
			row, err = queries.BindPreConfirmLogoutTransaction(ctx, sqlcgen.BindPreConfirmLogoutTransactionParams{
				CsrfHash: input.CSRFHash, UserID: &userID, SessionID: &sessionID, SessionBindingID: &bindingID,
				BoundAt: timestamp(input.Now), Subject: pointerString(input.Subject), ID: transaction.ID,
			})
			if isNoRows(err) {
				return logout.ErrNotFound
			}
			if err != nil {
				return wrapError("bind logout transaction", ErrorKindQuery, err)
			}
		case logout.StageBoundConfirm:
			if transaction.UserID == nil || transaction.SessionID == nil || transaction.SessionBindingID == nil ||
				*transaction.UserID != input.UserID || *transaction.SessionID != input.SessionID || *transaction.SessionBindingID != input.SessionBindingID {
				return logout.ErrNotFound
			}
			row, err = queries.RotateBoundLogoutTransactionCSRF(ctx, sqlcgen.RotateBoundLogoutTransactionCSRFParams{
				CsrfHash: input.CSRFHash, ID: transaction.ID, Now: timestamp(input.Now),
				UserID: &userID, SessionID: &sessionID, SessionBindingID: &bindingID,
			})
			if isNoRows(err) {
				return logout.ErrNotFound
			}
			if err != nil {
				return wrapError("rotate logout confirmation proof", ErrorKindQuery, err)
			}
		default:
			return logout.ErrNotFound
		}
		result = mapLogoutTransaction(row)
		return nil
	}, func() { result = logout.Transaction{} })
	return result, err
}

// CompleteLogoutTransaction consumes a bound transaction and, for confirmation,
// revokes the exact Session binding, families, live Access metadata, and Audit
// rows atomically. Unknown/stale authority never mutates a Session.
func (s *Store) CompleteLogoutTransaction(ctx context.Context, input logout.CompleteInput) (logout.CompletionCandidate, error) {
	if len(input.LookupHash) != 32 || len(input.CSRFHash) != 32 || input.UserID == uuid.Nil ||
		input.SessionID == uuid.Nil || input.SessionBindingID == uuid.Nil || input.Now.IsZero() ||
		(input.Decision != logout.DecisionConfirm && input.Decision != logout.DecisionCancel) ||
		input.MaxAttempts < 1 || input.MaxAttempts > 10 {
		return logout.CompletionCandidate{}, logout.ErrNotFound
	}
	var candidate logout.CompletionCandidate
	var events []audit.Event
	var committedOutcome error
	err := s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		row, err := queries.LockLogoutTransactionByLookupHash(ctx, input.LookupHash)
		if isNoRows(err) {
			return logout.ErrNotFound
		}
		if err != nil {
			return wrapError("lock logout transaction for completion", ErrorKindQuery, err)
		}
		transaction := mapLogoutTransaction(row)
		if !sameDigest(transaction.LookupHash, input.LookupHash) || transaction.Stage != logout.StageBoundConfirm ||
			transaction.ConsumedAt != nil || !input.Now.UTC().Before(transaction.ExpiresAt) ||
			transaction.AttemptCount >= input.MaxAttempts ||
			transaction.UserID == nil || transaction.SessionID == nil || transaction.SessionBindingID == nil ||
			*transaction.UserID != input.UserID || *transaction.SessionID != input.SessionID || *transaction.SessionBindingID != input.SessionBindingID {
			return logout.ErrNotFound
		}

		sessionRow, err := queries.LockLoginSessionByID(ctx, input.SessionID)
		if isNoRows(err) {
			return logout.ErrNotFound
		}
		if err != nil {
			return wrapError("lock browser session for logout completion", ErrorKindQuery, err)
		}
		if sessionRow.UserID != input.UserID || sessionRow.SessionBindingID != input.SessionBindingID || sessionRow.RevokedAt.Valid ||
			!input.Now.UTC().Before(requiredTime(sessionRow.ExpiresAt)) || !input.Now.UTC().Before(requiredTime(sessionRow.IdleExpiresAt)) {
			return logout.ErrNotFound
		}
		if !sameDigest(transaction.CSRFHash, input.CSRFHash) {
			if transaction.AttemptCount < input.MaxAttempts {
				if _, attemptErr := queries.IncrementLogoutTransactionAttempt(ctx, sqlcgen.IncrementLogoutTransactionAttemptParams{ID: transaction.ID, MaxAttempts: input.MaxAttempts}); attemptErr != nil && !isNoRows(attemptErr) {
					return wrapError("record logout proof failure", ErrorKindQuery, attemptErr)
				}
			}
			committedOutcome = logout.ErrCSRF
			return nil
		}

		clientID := transaction.VerifiedClientID
		candidate = logout.CompletionCandidate{
			Confirmed:             input.Decision == logout.DecisionConfirm,
			VerifiedClientID:      clientID,
			PostLogoutRedirectURI: transaction.PostLogoutRedirectURI,
			State:                 transaction.State,
		}
		if input.Decision == logout.DecisionCancel {
			if _, err := queries.CancelLogoutTransaction(ctx, sqlcgen.CancelLogoutTransactionParams{ConsumedAt: timestamp(input.Now), ID: transaction.ID}); isNoRows(err) {
				return logout.ErrNotFound
			} else if err != nil {
				return wrapError("cancel logout transaction", ErrorKindQuery, err)
			}
			return nil
		}

		bindingID := input.SessionBindingID
		if _, err := queries.LockUnrevokedRefreshTokenFamiliesByBinding(ctx, bindingID); err != nil {
			return wrapError("lock logout refresh families", ErrorKindQuery, err)
		}
		if _, err := queries.LockLiveAccessTokensByBinding(ctx, sqlcgen.LockLiveAccessTokensByBindingParams{SessionBindingID: &bindingID, Now: timestamp(input.Now)}); err != nil {
			return wrapError("lock logout access metadata", ErrorKindQuery, err)
		}
		if _, err := queries.RevokeRefreshTokenFamiliesByBinding(ctx, sqlcgen.RevokeRefreshTokenFamiliesByBindingParams{
			RevokedAt: timestamp(input.Now), RevokeReason: pointerString("session_revoked"), SessionBindingID: bindingID,
		}); err != nil {
			return wrapError("revoke logout refresh families", ErrorKindQuery, err)
		}
		if _, err := queries.RevokeLiveAccessTokensByBinding(ctx, sqlcgen.RevokeLiveAccessTokensByBindingParams{
			RevokedAt: timestamp(input.Now), RevokeReason: pointerString("session_revoked"), SessionBindingID: &bindingID,
		}); err != nil {
			return wrapError("revoke logout access metadata", ErrorKindQuery, err)
		}
		if _, err := queries.RevokeLoginSessionBindingByID(ctx, sqlcgen.RevokeLoginSessionBindingByIDParams{
			RevokedAt: timestamp(input.Now), RevokeReason: pointerString("logout"), ID: input.SessionID,
		}); isNoRows(err) {
			return logout.ErrNotFound
		} else if err != nil {
			return wrapError("revoke logout browser session", ErrorKindQuery, err)
		}
		if _, err := queries.ConfirmLogoutTransaction(ctx, sqlcgen.ConfirmLogoutTransactionParams{ConsumedAt: timestamp(input.Now), ID: transaction.ID}); isNoRows(err) {
			return logout.ErrNotFound
		} else if err != nil {
			return wrapError("confirm logout transaction", ErrorKindQuery, err)
		}

		actor := input.UserID
		sessionTarget := input.SessionID
		txTarget := transaction.ID
		sessionEvent, err := audit.New(audit.SessionRevoked, audit.ResultSuccess, &actor, audit.TargetSession, &sessionTarget, input.RequestID, []string{"revoked"}, input.Now)
		if err != nil {
			return err
		}
		logoutEvent, err := audit.New(audit.RPLogoutCompleted, audit.ResultSuccess, &actor, audit.TargetLogoutTransaction, &txTarget, input.RequestID, []string{"revoked"}, input.Now)
		if err != nil {
			return err
		}
		if err := insertAudit(ctx, queries, sessionEvent); err != nil {
			return err
		}
		if err := insertAudit(ctx, queries, logoutEvent); err != nil {
			return err
		}
		events = append(events, sessionEvent, logoutEvent)
		return nil
	}, func() {
		candidate = logout.CompletionCandidate{}
		events = nil
		committedOutcome = nil
	})
	if err == nil {
		s.observeAuditEvents(events)
		if committedOutcome != nil {
			return logout.CompletionCandidate{}, committedOutcome
		}
	}
	return candidate, err
}

// CleanupLogoutTransactions removes expired zero-authority and retired terminal
// rows in bounded committed batches.
func (s *Store) CleanupLogoutTransactions(ctx context.Context, now, terminalCutoff time.Time) (int64, error) {
	var total int64
	for {
		var count int64
		err := s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
			var err error
			count, err = queries.DeleteRetiredLogoutTransactions(ctx, sqlcgen.DeleteRetiredLogoutTransactionsParams{
				Now: timestamp(now), Cutoff: timestamp(terminalCutoff), BatchLimit: cleanupBatchSize,
			})
			if err != nil {
				return wrapError("clean logout transactions", ErrorKindQuery, err)
			}
			return nil
		}, func() { count = 0 })
		if err != nil {
			return total, err
		}
		total += count
		if count < int64(cleanupBatchSize) {
			return total, nil
		}
	}
}

func mapLogoutTransaction(row sqlcgen.LogoutTransaction) logout.Transaction {
	return logout.Transaction{
		ID: row.ID, LookupHash: append([]byte(nil), row.LookupHash...), Stage: logout.Stage(row.Stage),
		CSRFHash: append([]byte(nil), row.CsrfHash...), VerifiedClientID: row.VerifiedClientID,
		PostLogoutRedirectURI: valueString(row.PostLogoutRedirectUri), State: valueString(row.StateValue), HintSubject: valueString(row.HintSubject),
		UserID: row.UserID, SessionID: row.SessionID, SessionBindingID: row.SessionBindingID,
		CreatedAt: requiredTime(row.CreatedAt), ExpiresAt: requiredTime(row.ExpiresAt), BoundAt: optionalTime(row.BoundAt),
		ConsumedAt: optionalTime(row.ConsumedAt), AttemptCount: row.AttemptCount,
	}
}

func sameDigest(left, right []byte) bool {
	return len(left) == len(right) && len(left) == 32 && subtle.ConstantTimeCompare(left, right) == 1
}
