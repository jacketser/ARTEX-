package agent

import (
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/scenarioprompt"
)

func workerScenario(as *db.AssetStore, intent *db.Node, emit func(db.Activity)) string {
	if as == nil || intent == nil {
		return ""
	}
	cfg, err := as.ScenarioConfig()
	if err != nil {
		if emit != nil {
			emit(db.Activity{Worker: "system", Kind: "text", IsError: true, Summary: "场景配置不可用，本轮未注入场景指导"})
		}
		return ""
	}
	selected := scenarioprompt.Select(intent.Payload, cfg)
	if selected.Text != "" && emit != nil {
		b, _ := json.Marshal(map[string]any{"scenario_tags": selected.Tags, "selection": selected.Source, "truncated": selected.Truncated})
		emit(db.Activity{Worker: "system", Kind: "text", Summary: fmt.Sprintf("本轮场景指导：%v（%s）", selected.Tags, selected.Source), Metadata: b})
	}
	return selected.Text
}
