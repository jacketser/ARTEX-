package db

import (
	"context"
	"database/sql"
	"errors"
)

// FindingAutoReviewContext reads one consistent snapshot without target access.
// Retest snapshots are reduced to finding evidence, never asset secrets.
func (d *DB) FindingAutoReviewContext(ctx context.Context, id int64) (*DBFinding, []*FindingRetest, error) {
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	f := &DBFinding{ID: id}
	err = tx.QueryRowContext(ctx, `SELECT evidence_version,vulnclass,severity,summary,evidence FROM findings WHERE id=$1`, id).Scan(&f.EvidenceVersion, &f.VulnClass, &f.Severity, &f.Summary, &f.Evidence)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrFindingNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	review := &FindingReview{}
	err = tx.QueryRowContext(ctx, `SELECT fingerprint,verdict,sources,reproduction,counter_evidence,limitations,updated_at FROM finding_reviews WHERE finding_id=$1`, id).Scan(&review.Fingerprint, &review.Verdict, &review.Sources, &review.Reproduction, &review.CounterEvidence, &review.Limitations, &review.UpdatedAt)
	if err == nil {
		f.Review = review
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, err
	}
	traffic, err := FindingTrafficTx(tx, id)
	if err != nil {
		return nil, nil, err
	}
	f.TrafficBindings = traffic.Bindings
	f.TrafficCount = len(traffic.Bindings)
	r, err := scanRetest(tx.QueryRowContext(ctx, `SELECT `+retestCols+` FROM finding_retests WHERE finding_id=$1 ORDER BY id DESC LIMIT 1`, id))
	if err != nil {
		return nil, nil, err
	}
	retests := []*FindingRetest{}
	if r != nil {
		err = tx.QueryRowContext(ctx, `SELECT jsonb_build_object('finding',jsonb_build_object('evidence_version',snapshot->'finding'->'evidence_version','vulnclass',snapshot->'finding'->'vulnclass','severity',snapshot->'finding'->'severity','summary',snapshot->'finding'->'summary','evidence',snapshot->'finding'->'evidence')) FROM finding_retests WHERE id=$1`, r.ID).Scan(&r.Snapshot)
		if err != nil {
			return nil, nil, err
		}
		retests = append(retests, r)
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return f, retests, nil
}
