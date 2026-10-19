package server

import (
	"fmt"
	"github.com/Autumn-27/artex/db"
	"sync"
	"time"
)

type runningTool struct {
	worker string
	since  time.Time
}
type taskProgress struct {
	mu    sync.Mutex
	tools map[string]runningTool
}

// Observe lifecycle events instead of interpreting a whole agent run as an LLM call.
func (e *Engine) observeProgress(task string, a db.Activity) {
	value, _ := e.progress.LoadOrStore(task, &taskProgress{tools: map[string]runningTool{}})
	p := value.(*taskProgress)
	p.mu.Lock()
	defer p.mu.Unlock()
	key := fmt.Sprintf("%s/%v/%s", a.Worker, nodeID(a.NodeID), a.ToolUseID)
	switch a.Kind {
	case "tool_use":
		p.tools[key] = runningTool{worker: fmt.Sprintf("%s/%v", a.Worker, nodeID(a.NodeID)), since: time.Now()}
	case "tool_result":
		delete(p.tools, key)
	case "result":
		worker := fmt.Sprintf("%s/%v", a.Worker, nodeID(a.NodeID))
		for k, v := range p.tools {
			if v.worker == worker {
				delete(p.tools, k)
			}
		}
	}
}
func nodeID(id *int64) int64 {
	if id == nil {
		return 0
	}
	return *id
}
func (e *Engine) toolProgress(task string) (int, int64) {
	value, ok := e.progress.Load(task)
	if !ok {
		return 0, 0
	}
	p := value.(*taskProgress)
	p.mu.Lock()
	defer p.mu.Unlock()
	var oldest time.Time
	for _, v := range p.tools {
		if oldest.IsZero() || v.since.Before(oldest) {
			oldest = v.since
		}
	}
	if oldest.IsZero() {
		return 0, 0
	}
	return len(p.tools), int64(time.Since(oldest).Seconds())
}

type taskDiagnostic struct {
	Code               string `json:"code"`
	Message            string `json:"message"`
	Advice             string `json:"advice"`
	PendingApprovals   int    `json:"pending_approvals"`
	ActiveTools        int    `json:"active_tools"`
	ToolElapsedSeconds int64  `json:"tool_elapsed_seconds"`
}

func diagnoseTask(running, paused bool, calls int64, intents int, last, now int64, approvals, tools int, toolAge int64, available bool) taskDiagnostic {
	d := taskDiagnostic{PendingApprovals: approvals, ActiveTools: tools, ToolElapsedSeconds: toolAge}
	switch {
	case paused:
		d.Code = "paused"
		d.Message = "任务已暂停"
		d.Advice = "确认执行记录后，可使用页面的恢复按钮继续。"
	case !available:
		d.Code = "unknown"
		d.Message = "暂时无法读取完整诊断状态"
		d.Advice = "检查数据库连接及系统日志。"
	case approvals > 0:
		d.Code = "approval"
		d.Message = "正在等待人工审批"
		d.Advice = "在拦截审批页面核对待审批请求。"
	case !running:
		d.Code = "idle"
		d.Message = "任务引擎未运行"
	case tools > 0:
		d.Code = "tool"
		d.Message = "工具执行中"
		if toolAge > 120 {
			d.Message = "工具已执行较长时间（尚未收到结束事件）"
		}
		d.Advice = "查看会话中的工具输入、输出及超时设置；需要中止时使用暂停或停止操作。"
	case calls > 0:
		d.Code = "model_or_agent"
		d.Message = "模型推理或代理调度中"
		d.Advice = "查看模型调用记录；单次模型调用受整体超时约束。"
	case intents > 0 && last > 0 && now-last > 120:
		d.Code = "stalled"
		d.Message = "运行中意图超过 120 秒无活动，且未观察到执行中的代理或工具"
		d.Advice = "先查看会话和系统日志；确认无外部操作在执行后，再人工暂停、恢复或终止。"
	case intents > 0:
		d.Code = "scheduling"
		d.Message = "等待调度或下一条执行事件"
	default:
		d.Code = "idle"
		d.Message = "暂无待执行工作"
	}
	return d
}
