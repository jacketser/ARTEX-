package agent

import (
	"encoding/json"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/scenarioprompt"
	"strings"
	"testing"
)

func TestScenarioIntentPersistenceAndWorkerGuidance(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	cfg := scenarioprompt.Default()
	cfg.Profiles[1].Prompt = "custom API fixture guidance"
	old, present, err := d.GetSetting(db.ScenarioKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if present {
			d.SetSetting(db.ScenarioKey, old)
		} else {
			d.Exec(`DELETE FROM settings WHERE key=$1`, db.ScenarioKey)
		}
	})
	if err := d.SaveScenarioConfig(cfg); err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTaskWithOptions("scene fixture", "local evidence only", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(task.ID) })
	ts := d.Exploration(task.ExplorationID)
	tools := NewToolSet(ts, "planner")
	tools.SetTaskID(task.ID)
	id, err := tools.addOneIntent(intentItem{Summary: "Web review", ChainTags: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	node, err := ts.GetNodeWithSources(id)
	if err != nil {
		t.Fatal(err)
	}
	var events []db.Activity
	prompt := workerScenario(d.Assets(), node, func(a db.Activity) { events = append(events, a) })
	if !strings.Contains(prompt, "custom API fixture guidance") || !strings.Contains(prompt, "固定边界") || len(events) != 1 {
		t.Fatal(prompt, events)
	}
	var metadata map[string]any
	if json.Unmarshal(events[0].Metadata, &metadata) != nil || metadata["selection"] != "explicit" {
		t.Fatal(events)
	}
	if _, err := tools.addOneIntent(intentItem{Summary: "bad tags", ChainTags: []string{"unknown"}}); err == nil {
		t.Fatal("invalid tag persisted")
	}
	cfg.Enabled = false
	d.SaveScenarioConfig(cfg)
	if got := workerScenario(d.Assets(), node, nil); got != "" {
		t.Fatal("disabled configuration injected", got)
	}
	d.SetSetting(db.ScenarioKey, "invalid")
	events = nil
	if got := workerScenario(d.Assets(), node, func(a db.Activity) { events = append(events, a) }); got != "" || len(events) != 1 || !events[0].IsError {
		t.Fatal(got, events)
	}
}
