package notify

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRecoveryOptInAndRendering(t *testing.T) {
	s := Snapshot{Kind: EventRecoveryExhausted, TaskID: 42, Severity: "notice"}
	if Match(Filter{}, s) {
		t.Fatal("must opt in")
	}
	if Match(ParseFilter([]byte(`{"on_recovery_failure":true,"task_ids":"bad"}`)), s) {
		t.Fatal("malformed opt in")
	}
	if !Match(Filter{OnRecoveryFailure: true, TaskIDs: []int64{42}, MinSeverity: "critical", AssetIDs: []int64{99}}, s) {
		t.Fatal("task event incorrectly uses finding filters")
	}
	if Match(Filter{OnRecoveryFailure: true, TaskIDs: []int64{43}}, s) {
		t.Fatal("task filter ignored")
	}
	body, err := renderWebhookBody("", Message{Items: []Item{{TaskID: 42, Kind: EventRecoveryExhausted, Severity: "notice", Name: "恢复失败"}}})
	if err != nil || !json.Valid([]byte(body)) || !strings.Contains(body, `"task_id": 42`) || !strings.Contains(body, EventRecoveryExhausted) {
		t.Fatal(body, err)
	}
}
