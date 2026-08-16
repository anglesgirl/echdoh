// 管理后台（2026-08-16）：https://doh.anglesgirl.eu.org:8443/admin
// 域名解析 127.0.0.1 → 手机本机的 echdoh → 本机浏览器直接打开即后台。
// 功能：工作日志（DNS/探测/错误）、状态（上游/云配置/缓存）、刷新云配置。
package echdoh

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const adminHTML = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>echdoh Admin</title>
<style>
body{font-family:ui-monospace,Menlo,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:16px}
h1{font-size:18px;color:#58a6ff}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;margin-bottom:12px}
.card h2{font-size:14px;color:#79c0ff;margin:0 0 8px}
table{width:100%;border-collapse:collapse;font-size:12px}
td,th{text-align:left;padding:4px 8px;border-bottom:1px solid #21262d}
th{color:#8b949e}
.ok{color:#3fb950}.warn{color:#d29922}.err{color:#f85149}
#logs{font-size:11px;max-height:420px;overflow-y:auto;white-space:pre-wrap}
button{background:#238636;color:#fff;border:none;border-radius:6px;padding:8px 16px;font-size:13px;cursor:pointer;margin-right:8px}
button:hover{background:#2ea043}
button:disabled{opacity:.5}
</style>
</head>
<body>
<h1>echdoh 管理后台</h1>
<div class="card"><h2>状态</h2><table id="status"><tbody></tbody></table></div>
<div class="card"><h2>云配置</h2><table id="cfg"><tbody></tbody></table></div>
<div class="card"><h2>工作日志 <button onclick="refreshCfg()">刷新云配置</button> <button onclick="load()">刷新日志</button></h2>
<pre id="logs">加载中...</pre></div>
<script>
async function j(u){const r=await fetch(u);return r.json()}
async function load(){
  try{
    const s=await j('/admin/api/status');
    let html='';
    const rows=[['运行','ok'===s.running?'<span class=ok>运行中</span>':'<span class=err>停止</span>'],
      ['上游',(s.upstreams||[]).length+' 个<br>'+(s.upstreams||[]).join('<br>')],
      ['监听',s.listen],['启动',s.startedAt],['DNS 查询',s.queries],['ECH 探测缓存',s.probeCache+' 条'],
      ['上游错误',s.upstreamErrors]];
    for(const[k,v]of rows)html+='<tr><th>'+k+'</th><td>'+v+'</td></tr>';
    document.getElementById('status').innerHTML=html;
    let c='';const cf=s.cloud||{};
    for(const k of Object.keys(cf)){c+='<tr><th>'+k+'</th><td>'+(cf[k]||'(空)')+'</td></tr>'}
    document.getElementById('cfg').innerHTML=c;
  }catch(e){document.getElementById('status').innerHTML='<tr><td class=err>状态加载失败: '+e+'</td></tr>'}
  try{
    const l=await j('/admin/api/logs');
    document.getElementById('logs').textContent=l.logs||'(无日志)';
  }catch(e){document.getElementById('logs').textContent='日志加载失败: '+e}
}
async function refreshCfg(){
  const b=event.target;b.disabled=true;b.textContent='刷新中...';
  try{const r=await j('/admin/api/refresh');alert(r.msg||'完成')}catch(e){alert('失败: '+e)}
  b.disabled=false;b.textContent='刷新云配置';
}
load();setInterval(load,5000);
</script>
</body>
</html>`

// AdminStatus 状态快照（JSON 序列化用）。
type AdminStatus struct {
	Running        string            `json:"running"`
	Listen         string            `json:"listen"`
	StartedAt      string            `json:"startedAt"`
	Upstreams      []string          `json:"upstreams"`
	Queries        int64             `json:"queries"`
	ProbeCache     int               `json:"probeCache"`
	UpstreamErrors string            `json:"upstreamErrors"`
	Cloud          map[string]string `json:"cloud"`
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, adminHTML)
}

func handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	st := AdminStatus{
		Running:   "ok",
		Listen:    listenAddr,
		StartedAt: startedAt.Format(time.RFC3339),
		Upstreams: append([]string{}, upstream...),
		Queries:   queryCount,
		ProbeCache: func() int {
			probeMu.Lock()
			defer probeMu.Unlock()
			return len(probeCache)
		}(),
	}
	mu.Unlock()

	// 云配置快照
	cloudMu.Lock()
	force := "从 shouldForceCF 内置名单判断"
	if len(cloudCfg.ForceCF) > 0 {
		force = strings.Join(cloudCfg.ForceCF, ", ")
	}
	st.Cloud = map[string]string{
		"pool":      strings.Join(cloudPoolIPs(), ", "),
		"force":     force,
		"overrides": cloudOverridesStr(),
	}
	cloudMu.Unlock()

	// 上游错误统计（最近一条）
	st.UpstreamErrors = lastUpstreamErr
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(st)
}

func handleAdminLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"logs": PollLogs()})
}

func handleAdminRefresh(w http.ResponseWriter, r *http.Request) {
	msg := "云配置已刷新"
	fetchCloudConfigTXT()
	if seed := fetchSeedTXT(); seed != nil {
		msg += "，种子配置已刷新"
	} else {
		msg += "，种子刷新失败（保留原配置）"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"msg": msg})
}

// cloudOverridesStr 云 override 规则摘要。
func cloudOverridesStr() string {
	cloudMu.Lock()
	defer cloudMu.Unlock()
	if len(overrideMap) == 0 {
		return "(空)"
	}
	var keys []string
	for k := range overrideMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+overrideMap[k])
	}
	return strings.Join(parts, "; ")
}

var lastUpstreamErr = "(无)"

var queryCount int64

var listenAddr = "127.0.0.1:8443"

var startedAt = time.Now()
