package token

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestProjectReviewUserInfoRepositoryErrorsKeepBearerClassification(t *testing.T) {
	t.Parallel()

	infrastructureCause := errors.New("userinfo metadata storage unavailable")
	tests := []struct {
		name             string
		repositoryErr    error
		wantErr          error
		wantResult       string
		wantCanonicalErr bool
	}{
		{
			name:             "invalid token",
			repositoryErr:    ErrInvalidToken,
			wantErr:          ErrInvalidToken,
			wantResult:       "rejected",
			wantCanonicalErr: true,
		},
		{
			name:             "wrapped invalid token",
			repositoryErr:    fmt.Errorf("metadata lookup rejected: %w", ErrInvalidToken),
			wantErr:          ErrInvalidToken,
			wantResult:       "rejected",
			wantCanonicalErr: true,
		},
		{
			name:          "wrapped deadline exceeded",
			repositoryErr: fmt.Errorf("metadata lookup deadline: %w", context.DeadlineExceeded),
			wantErr:       context.DeadlineExceeded,
			wantResult:    "failure",
		},
		{
			name:          "wrapped canceled",
			repositoryErr: fmt.Errorf("metadata lookup canceled: %w", context.Canceled),
			wantErr:       context.Canceled,
			wantResult:    "failure",
		},
		{
			name:          "wrapped infrastructure",
			repositoryErr: fmt.Errorf("metadata storage: %w", infrastructureCause),
			wantErr:       infrastructureCause,
			wantResult:    "failure",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTokenFixture(t, []string{"openid"})
			issued, err := fixture.service.Exchange(context.Background(), fixture.exchangeInput())
			if err != nil {
				t.Fatal(err)
			}
			fixture.repository.accessAuthority = fixture.accessAuthority()
			fixture.repository.accessErr = test.repositoryErr
			metrics := &projectReviewUserInfoMetrics{}
			fixture.service.metrics = metrics

			userinfo, gotErr := fixture.service.UserInfoForAccessToken(context.Background(), issued.AccessToken, fixture.now)
			if userinfo != (UserInfo{}) {
				t.Fatalf("userinfo=%+v, want empty projection", userinfo)
			}
			if !errors.Is(gotErr, test.wantErr) {
				t.Fatalf("error=%v, want errors.Is(..., %v)", gotErr, test.wantErr)
			}
			if test.wantCanonicalErr {
				if !errors.Is(gotErr, ErrInvalidToken) {
					t.Fatalf("error=%v, want canonical ErrInvalidToken", gotErr)
				}
			} else if !errors.Is(gotErr, test.repositoryErr) {
				t.Fatalf("error=%v, want original repository error %v", gotErr, test.repositoryErr)
			}
			if len(metrics.calls) != 1 || metrics.calls[0] != "userinfo:"+test.wantResult {
				t.Fatalf("metric calls=%v, want [userinfo:%s]", metrics.calls, test.wantResult)
			}
		})
	}
}

type projectReviewUserInfoMetrics struct {
	calls []string
}

func (m *projectReviewUserInfoMetrics) Token(operation, result string) {
	m.calls = append(m.calls, operation+":"+result)
}
