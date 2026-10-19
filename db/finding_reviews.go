package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var ErrReviewStale = errors.New("证据已变化，请重新加载并复核")

type FindingReview struct {
	Fingerprint     string    `json:"fingerprint"`
	Verdict         string    `json:"verdict"`
	Sources         string    `json:"sources"`
	Reproduction    string    `json:"reproduction"`
	CounterEvidence string    `json:"counter_evidence"`
	Limitations     string    `json:"limitations"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func (r FindingReview) Validate() error {
	if r.Verdict != "supported" && r.Verdict != "refuted" && r.Verdict != "inconclusive" {
		return errors.New("请选择有效的复核结论")
	}
	for _, s := range []string{r.Sources, r.Reproduction, r.CounterEvidence, r.Limitations} {
		if len(s) > 16000 {
			return errors.New("单项复核内容不能超过 16000 字节")
		}
	}
	if r.Verdict != "inconclusive" && (strings.TrimSpace(r.Sources) == "" || strings.TrimSpace(r.Reproduction) == "" || strings.TrimSpace(r.CounterEvidence) == "") {
		return errors.New("支持或反驳结论必须填写证据来源、复现条件及反证检查")
	}
	if r.Verdict == "inconclusive" && strings.TrimSpace(r.Limitations) == "" {
		return errors.New("无法确认时请填写缺少的证据或验证限制")
	}
	return nil
}
func FindingFingerprint(f *DBFinding) string {
	raw, _ := json.Marshal([]any{f.EvidenceVersion, f.VulnClass, f.Severity, f.Summary, f.Evidence})
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}
func (d *DB) GetFindingReview(id int64) (*FindingReview, error) {
	r := &FindingReview{}
	err := d.QueryRow(`SELECT fingerprint,verdict,sources,reproduction,counter_evidence,limitations,updated_at FROM finding_reviews WHERE finding_id=$1`, id).Scan(&r.Fingerprint, &r.Verdict, &r.Sources, &r.Reproduction, &r.CounterEvidence, &r.Limitations, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

// The review never changes triage status. Lock the source while checking its
// fingerprint so concurrently arriving evidence cannot be labelled reviewed.
func (d *DB) SaveFindingReview(ctx context.Context, id int64, r FindingReview) error {
	if err := r.Validate(); err != nil {
		return err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	f := &DBFinding{}
	err = tx.QueryRowContext(ctx, `SELECT evidence_version,vulnclass,severity,summary,evidence FROM findings WHERE id=$1 FOR UPDATE`, id).Scan(&f.EvidenceVersion, &f.VulnClass, &f.Severity, &f.Summary, &f.Evidence)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrFindingNotFound
	}
	if err != nil {
		return err
	}
	if r.Fingerprint != FindingFingerprint(f) {
		return ErrReviewStale
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO finding_reviews(finding_id,fingerprint,verdict,sources,reproduction,counter_evidence,limitations)
 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(finding_id) DO UPDATE SET fingerprint=$2,verdict=$3,sources=$4,reproduction=$5,counter_evidence=$6,limitations=$7,updated_at=now()`, id, r.Fingerprint, r.Verdict, r.Sources, r.Reproduction, r.CounterEvidence, r.Limitations)
	if err != nil {
		return err
	}
	return tx.Commit()
}
