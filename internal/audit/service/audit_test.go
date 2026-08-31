// What the service refuses before storage ever sees it.

package service

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kotsmile/keyway/internal/audit/entity"
	secrets "github.com/kotsmile/keyway/internal/secrets/entity"
)

// recordingRepo keeps what it was asked to append. No database: the rule
// under test is that some entries never reach one.
type recordingRepo struct {
	appended []entity.Record
}

func (r *recordingRepo) Append(_ context.Context, _, _ string, record entity.Record) error {
	r.appended = append(r.appended, record)
	return nil
}

func (r *recordingRepo) ForSecret(
	context.Context, secrets.StoreID, secrets.SecretName, int64,
) ([]entity.Entry, error) {
	return nil, nil
}

func (r *recordingRepo) Feed(context.Context, int64, *int64) ([]entity.Entry, error) {
	return nil, nil
}

type sessionActor struct{}

func (sessionActor) Handle() string          { return "alice" }
func (sessionActor) TokenID() (string, bool) { return "", false }

func TestAnActionNothingCouldHaveMeantIsRefusedBeforeTheColumnRefusesIt(t *testing.T) {
	t.Parallel()
	// The `action` column's CHECK constraint would refuse this too — with a
	// message naming a constraint, and after the thing being recorded has
	// already happened. Here the caller learns which word was wrong.
	repo := &recordingRepo{}
	service := NewService(repo)

	err := service.Record(context.Background(), sessionActor{}, entity.Record{
		Action: "rotate",
		Store:  "local",
		Secret: "db-creds",
	})
	var unknown *entity.UnknownActionError
	require.ErrorAs(t, err, &unknown)
	assert.Equal(t, entity.Action("rotate"), unknown.Action)
	assert.Empty(t, repo.appended, "nothing reached storage")
}

func TestEveryActionThisBuildHasIsAppended(t *testing.T) {
	t.Parallel()
	repo := &recordingRepo{}
	service := NewService(repo)
	ctx := context.Background()

	for _, action := range []entity.Action{
		entity.Create, entity.Update, entity.Reveal, entity.Delete,
		entity.Delegate, entity.Revoke, entity.Transfer,
	} {
		require.NoError(t, service.Record(ctx, sessionActor{},
			entity.NewRecord(action, uuid.New(), "local", "db-creds")), "%q", action)
	}
	assert.Len(t, repo.appended, 7)
}
