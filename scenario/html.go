package scenario

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// RenderHTML 把事件序列渲染成一个完全自包含的静态 HTML 文件：
// 数据与逻辑全部内嵌，不加载任何外部脚本、样式或字体。
func RenderHTML(events []Event) ([]byte, error) {
	data, err := json.Marshal(events)
	if err != nil {
		return nil, fmt.Errorf("序列化事件: %w", err)
	}
	// 防止 JSON 中的 "</script>" 提前闭合脚本标签。
	safe := strings.ReplaceAll(string(data), "</", `<\/`)
	html := strings.Replace(pageTemplate, "/*__DATA__*/", safe, 1)
	if !strings.Contains(html, "const EVENTS = [") {
		return nil, fmt.Errorf("数据注入失败：模板占位符未被替换")
	}
	return []byte(html), nil
}

// WriteHTML 生成 HTML 并写入文件。
func WriteHTML(events []Event, path string) error {
	html, err := RenderHTML(events)
	if err != nil {
		return err
	}
	return os.WriteFile(path, html, 0o644)
}
