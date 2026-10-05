package scenario

import (
	"strings"
	"testing"
)

// 脚本化场景应覆盖全部关键行为，并以 v3 结算收尾。
func TestScenarioFlow(t *testing.T) {
	events := Run()
	if len(events) == 0 {
		t.Fatal("场景不应为空")
	}

	kinds := map[string]int{}
	for _, ev := range events {
		kinds[ev.Kind]++
		if ev.Seq == 0 {
			t.Error("事件序号应从 1 开始")
		}
	}
	for _, want := range []string{
		"open", "update", "replay-rejected", "forgery-rejected",
		"dispute", "challenge", "challenge-rejected", "settle",
	} {
		if kinds[want] == 0 {
			t.Errorf("场景缺少事件类型 %q", want)
		}
	}

	last := events[len(events)-1]
	if last.Kind != "settle" {
		t.Fatalf("最后一个事件应为结算，实际 %q", last.Kind)
	}
	if last.Chain.Status != "已结算" || last.Chain.FinalVersion != 3 {
		t.Fatalf("应按 v3 结算，实际状态 %q final=%d", last.Chain.Status, last.Chain.FinalVersion)
	}

	// 伪造事件中的签名校验必须体现"一方签名无效"。
	for _, ev := range events {
		if ev.Kind == "forgery-rejected" && ev.SigAOK {
			t.Error("伪造状态中 Alice 的签名应校验失败")
		}
	}
}

// 生成的 HTML 必须是自包含的单文件：数据内嵌、无外部资源引用。
func TestRenderHTMLSelfContained(t *testing.T) {
	html, err := RenderHTML(Run())
	if err != nil {
		t.Fatal(err)
	}
	s := string(html)
	if !strings.Contains(s, "const EVENTS = [{") {
		t.Error("HTML 中未找到内嵌的事件数据")
	}
	for _, external := range []string{"http://", "https://", "<link", "src=\"", "@import"} {
		if strings.Contains(s, external) {
			t.Errorf("HTML 不应引用外部资源，发现 %q", external)
		}
	}
	if !strings.Contains(s, "争议期") {
		t.Error("HTML 应包含争议期相关说明")
	}
}
