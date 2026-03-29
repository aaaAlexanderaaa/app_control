# Claw系列与高风险APP深度安全分析报告

**日期**: 2026-03-29  
**分析范围**: Claw系列APP (46个) + 高风险APP

---

## 执行摘要

本次深度分析对46个Claw系列APP和多个高风险APP进行了系统性安全review，通过源码分析、网络侦察、威胁情报整合，发现了以下关键IOC和检测方法。

### 关键发现

| 发现类别 | 数量 | 说明 |
|---------|------|------|
| 新增网络IOC | 15+ | 钓鱼域名、C2服务器、API端点 |
| 新增主机IOC | 50+ | 存储路径、进程名、bundle ID |
| 能力指标(Capabilities) | 30+ | 权限请求、安全风险因素 |
| 威胁情报IOC | 10+ | 已知恶意软件C2、钓鱼域名 |
| CVE关联 | 5+ | OpenClaw系RCE漏洞 |

---

## 一、OpenClaw 核心漏洞分析

### 1.1 CVE-2026-25253 (CVSS 9.8)
**影响**: OpenClaw v2026.1.24及之前版本

**攻击链**:
```
恶意网站 → WebSocket连接 localhost:18789 → 窃取认证token → RCE
```

### 1.2 ClawHavoc 供应链攻击
| 统计 | 数据 |
|------|------|
| 恶意Skills | 341+ |
| 恶意率 | ~12% |
| 攻击者账户 | hightower6eu (314个恶意技能) |

### 1.3 网络暴露统计
| 指标 | 数值 |
|------|------|
| 互联网暴露实例 | 135,000+ |
| 直接可利用 | 15,000+ |
| 暴露端口 | TCP 18789 |

---

## 二、新增IOC清单

### 2.1 钓鱼域名 (阻断/告警)
```
app-clawbot.org
ai-clawbot.org
ai-openclaw.org
clearl.co
```

### 2.2 恶意C2服务器
| IP | 恶意软件 |
|----|---------|
| 146.103.127.46 | StealC |
| 172.94.9.250 | AMOS (macOS窃密) |
| 188.137.246.189 | Windows Stealer |

### 2.3 文件哈希 (阻断)
```
StealC_v2:  d9f0dd48745d5be7ef74ee9f2cb4640ab310a5a7d2f2f01654e15370ac5853eb
AMOS DMG:    5efe3d6ff69002f2cf82683f2d866264d0836b9f02e8b52719ecbd6fecf72a62
```

---

## 三、各APP深度分析结果

### 3.1 ClawApp (Critical)
**风险评级**: 极高  
**主要风险**:
- 继承OpenClaw所有漏洞
- DMG安装无代码签名
- Moltbook数据泄露历史

**新增IOC**:
```yaml
bundle_ids:
  - com.sorin.clawdbot
ports:
  - 18789
```

### 3.2 ClawX (Critical)
**风险评级**: 高  
**主要风险**:
- Electron entitlements危险配置(allow-unsigned-executable-memory)
- 阿里云OSS自动更新无签名验证
- macOS沙箱权限过度

**新增IOC**:
```yaml
capabilities:
  - electron_framework
  - preinstalled_skills
```

### 3.3 AutoClaw (Critical)
**风险评级**: 极高  
**主要风险**:
- Zhipu AI官方发行版
- 继承OpenClaw完整漏洞集
- 一体化安装器定位

### 3.4 ZeptoClaw (Critical)
**风险评级**: 高  
**能力范围**:
- 32个工具(shell, filesystem, network等)
- 9个channels(Telegram, Discord, Slack等)
- 6个sandbox运行时
- Agent swarms协调

**新增IOC**:
```yaml
ports:
  - 9876  # Telegram webhook
  - 8765  # ACP HTTP
  - 9090  # Health check
capabilities:
  - shell_command_execution
  - delegate_spawn_subagents
  - agent_swarms
```

### 3.5 AgenticSeek (Critical)
**风险评级**: 极高  
**关键漏洞**:
```python
# 无沙箱的Python exec()
exec(code, {"__builtins__": __builtins__, "os": os})

# shell=True危险
subprocess.Popen(cmd, shell=True)
```

### 3.6 UI-TARS Desktop (Critical)
**风险评级**: 高  
**已知漏洞**(未修复):
- Tool Description Injection
- Missing Output Sanitization

**新增IOC**:
```yaml
capabilities:
  - full_mouse_keyboard_control
  - macos_accessibility_permission
risk_factors:
  - api_key_plaintext_storage
```

### 3.7 AionUI (Critical)
**风险评级**: 高  
**新增IOC**:
```yaml
ports:
  - 18792
capabilities:
  - sentry_telemetry_enabled_by_default
risk_factors:
  - xml_injection_in_skills
```

### 3.8 Rewind (High Risk)
**风险评级**: 高  
**数据收集范围**:
- 屏幕截图 (0.5 FPS)
- OCR文本
- 浏览器URL
- 会议音频转录
- 击键/麦克风

**新增IOC**:
```yaml
bundle_ids:
  - com.memoryvault.MemoryVault
process_names:
  - Rewind Helper
capabilities:
  - screen_recording
  - whisper_transcription
telemetry:
  - clientstream.launchdarkly.com
risk_factors:
  - launchdarkly_remote_kill_switch
```

---

## 四、检测方法论

### 4.1 网络层检测 (NDR)

```bash
# 1. 监控暴露的Gateway
alert tcp $HOME_NET any -> $EXTERNAL_NET 18789

# 2. 检测已知C2
alert http $HOME_NET any -> $EXTERNAL_NET any 
  (content:"146.103.127.46")

# 3. 检测钓鱼域名
alert dns query any -> any (
  name: "app-clawbot.org" OR 
  name: "ai-clawbot.org")

# 4. 检测文件外泄服务
alert tls $HOME_NET any -> $EXTERNAL_NET any (
  tls.sni; pcre:"/(file\.io|gofile\.io)/"
)
```

### 4.2 主机层检测 (EDR)

```bash
# 1. 检测OpenClaw进程
ps aux | grep -E 'openclaw|clawdbot|moltbot'

# 2. 检测暴露的Gateway
lsof -i :18789
netstat -tlnp | grep 18789

# 3. 检测恶意目录
find ~ -name ".clawdbot" -o -name ".openclaw" -o -name ".zeptoclaw"

# 4. 检测恶意Skills
find ~/.openclaw/skills -name "SKILL.md" -exec grep -l "curl.*bash\|base64" {} \;

# 5. 检测屏幕录制应用
mdfind "kMDItemDisplayName == 'Rewind'"
```

### 4.3 YARA 规则

```yara
rule Claw_Family_Detection {
    strings:
        $openclaw_path = "~/.openclaw" ascii
        $gateway_port = "18789"
        $clawdbot_bundle = "com.sorin.clawdbot"
        $skill_marker = "SKILL.md"
    condition:
        2 of them
}

rule Malicious_C2_Indicators {
    strings:
        $stealc_c2 = "146.103.127.46"
        $amos_c2 = "172.94.9.250"
        $phishing_claw = "app-clawbot.org"
    condition:
        any of them
}

rule FileExfil_Service {
    strings:
        $gofile_api = "api.gofile.io/getServer"
        $file_io = "file.io"
    condition:
        any of them
}
```

---

## 五、Gofile 动态服务器IP段

| IP段 | 区域 | 运营商 |
|------|------|--------|
| 45.112.123.0/24 | EU Paris | - |
| 195.154.100.0/24 | EU Paris | Scaleway |
| 62.210.172.0/24 | EU Paris | Scaleway |
| 51.77.165.0/24 | EU Calais | OVH |
| 195.201.161.0/24 | EU Germany | Hetzner |
| 94.139.32.0/24 | NA Phoenix | 1GSERVERS |

**来源**: Gist社区追踪 + Cisco Talos LOLEXFIL

---

## 六、MITRE ATT&CK 映射

| 战术 | 技术 | Claw应用场景 |
|------|------|-------------|
| Initial Access | Exposed Web Service | Gateway暴露18789 |
| Execution | Command/Script Interpreter | exec/bash tool |
| Persistence | Systemd/LaunchAgent | daemon autostart |
| Defense Evasion | Hidden Directories | ~/.openclaw/ |
| Credential Access | Credentials from APIs | env var访问 |
| Exfiltration | Cloud Storage | webhook外泄 |
| Impact | Data Manipulation | workspace篡改 |

---

## 七、更新catalog的APP列表

| APP | 更新内容 |
|-----|---------|
| openclaw.yaml | 添加端口18789、钓鱼域名、恶意C2、文件哈希 |
| clawapp.yaml | 已有完整IOC |
| clawx.yaml | 已有完整IOC |
| zeptoclaw.yaml | 添加端口、capabilities |
| aionui.yaml | 添加路径、端口、capabilities |
| ui_tars_desktop.yaml | 添加路径、capabilities、risk_factors |
| agenticseek.yaml | 添加路径、capabilities、risk_factors |
| lobsterai.yaml | 添加Electron特征、存储路径 |
| workbuddy.yaml | 添加Electron特征、Tencent相关 |
| troublemaker.yaml | 添加capabilities |
| rewind.yaml | 添加capabilities、telemetry、risk_factors |
| gofile.yaml | 添加API端点、IP段、detection_signatures |

---

## 八、后续建议

### 8.1 紧急行动
1. **阻断**: 防火墙规则阻断已知C2和钓鱼域名
2. **扫描**: EDR扫描 18789 端口暴露
3. **审计**: 检查 `~/.openclaw/` 权限
4. **升级**: 强制OpenClaw用户升级到最新版本

### 8.2 持续监控
1. **订阅威胁情报**: LOLEXFIL, ClawHavoc更新
2. **DNS监控**: gofile动态服务器发现
3. **文件完整性**: SKILL.md变更监控

### 8.3 企业策略
1. **黑名单**: 将所有Claw应用纳入AUP禁止列表
2. **网络隔离**: 禁止18789端口出站
3. **DLP增强**: 监控向file.io/gofile.io的文件上传

---

## 九、参考链接

- [OpenClaw CVE-2026-25253](待补充)
- [ClawHavoc Campaign Analysis](待补充)
- [SANS ISC - K1w1 Infostealer](https://isc.sans.edu/diary/30972)
- [LOLEXFIL - LOL Exfiltration](https://lolexfil.github.io/)
- [Gofile Server IP List](https://gist.github.com/nillpoe/18f11f94ebc3115d5234d07cac030cdb)

---

**报告生成时间**: 2026-03-29  
**分析工具**: Web搜索、源码分析、威胁情报整合  
**验证状态**: `make validate` 通过
