# macOS Host Scan 脚本评估报告

## 一、优先级评估 (P1-P6)

### 当前优先级

| 优先级 | 方法 | 评估 |
|--------|------|------|
| **P1** `check_app_paths` | 固定路径存在性检查 | ✅ 合理 |
| **P2** `check_bundle_id` | Bundle ID 精确匹配 | ⚠️ 应提升为 P1 并列 |
| **P3** `check_process_name` | 进程名精确匹配 | ✅ 合理 |
| **P4** `check_chrome_extension` | Chrome 扩展 ID 匹配 | ✅ 合理 |
| **P5** `search_dirs` | 开发目录拼接检查 | ⚠️ 低置信度，需审慎 |
| **P6** `search_name` | 文件系统索引名称匹配 | ⚠️ 低置信度，需审慎 |

### 详细评估

**P1 (路径检查) — 合理但有细微问题**

路径直接 `[ -e "$path" ]` 是最快最确定的方法。但需要区分：
- **`.app` + `Contents/` 存在** → 确定性极高，这是真实安装的应用
- **`~/.openclaw` 之类的配置目录** → 确定性低，可能是残留
- **`/opt/homebrew/bin/xxx` 可执行文件** → 确定性较高，但可能是同名工具

当前逻辑在 `path_match_is_strong_signal()` 中已做了这个区分，**但 P1 阶段只用于跳过 stale 检查，没有用于调整报告的置信度标签**。建议：路径匹配结果应附带 `CONFIDENCE=high|medium|low` 字段。

**P2 (Bundle ID) — 应与 P1 并列**

Bundle ID 是 macOS 应用最权威的标识符（类似 Android 的 package name），确定性 > 路径。当前排在 P1 之后意味着如果路径先命中了就跳过 Bundle ID 检查，这对于 `first_hit` 模式是有问题的——路径可能命中一个低置信的目录 IOC，而 Bundle ID 能确认更高质量的 `.app` 存在。

**建议**：P1 和 P2 合并为同一优先级层，或者 **P2 提升到 P1 之前**。理由是 Bundle ID 匹配的 false positive rate 几乎为零（精确匹配 `CFBundleIdentifier`），而路径匹配可能命中配置目录残留。

**P3 (进程名) — 合理**

运行中的进程是最强的"正在使用"信号。当前排在 P3 没问题，因为：
1. 不是所有应用都有持久进程（GUI 应用关闭后就消失）
2. `ps -axco comm=` 只返回进程基本名（15 字符截断），可能误匹配
3. 但作为补充信号很有价值

**P5/P6 (目录搜索 / 名称搜索) — 最大风险来源**

这是误报的主要来源。`find -maxdepth 3` + 名称匹配可以命中：
- 用户 clone 的 GitHub 仓库（有开源代码但从未运行）
- 配置残留目录
- 同名但无关的目录

**建议**：P5/P6 的结果应标记 `CONFIDENCE=low`，并在企业管理中不直接生成 alert，仅用于 inventory 参考。

---

## 二、置信度 / Stale 过滤评估

### 当前逻辑

```
强信号 (不过滤):
  - .app + Contents/ 存在
  - 可执行文件 (-f && -x)

弱信号 (stale 过滤):
  - INSTALL_APPROX 和 LAST_ACCESS 都超过 STALE_DAYS → 跳过
  - 任一在阈值内 → 报告
```

### 问题

**核心问题：`stat -f "%Sa"` (atime) 在 macOS APFS 上不可靠**

这不是一个"不太准"的问题，而是一个**根本性的语义错误**：

1. **APFS 默认行为 (relatime 语义)**：只有当 atime < mtime 时，读操作才会更新 atime。这意味着 atime 可能停留在一个很旧的值上，也可能被某次系统操作意外刷新。
2. **目录的 atime 更不可靠**：任何 `readdir` 操作（`ls`, `find`, tab completion, Spotlight indexing, 甚至你的扫描脚本本身）都可能更新目录的 atime。
3. **自我污染**：脚本中 `find "$_fs_d" -maxdepth 3 -print` 会遍历目录，可能更新被检查目录的 atime，导致下次运行时将其视为"活跃"。

**结论**：当前的 stale 过滤逻辑对于弱信号（目录 IOC）**几乎无效**。任何被 Spotlight / Time Machine / 扫描脚本自身扫过的目录都会显示"最近访问"。

### 置信度矩阵（建议）

| 信号类型 | 置信度 | 误报风险 | 建议处理 |
|----------|--------|----------|----------|
| `.app` + `Contents/` 存在 | **HIGH** | 极低 | 直接报告 |
| Bundle ID 匹配 | **HIGH** | 极低 | 直接报告 |
| 运行中进程 | **HIGH** | 低 | 直接报告 |
| Chrome 扩展 ID | **HIGH** | 极低 | 直接报告 |
| 可执行文件 (-f && -x) 在 bin 目录 | **MEDIUM** | 低 | 报告但标注 |
| LaunchAgent plist 存在 | **MEDIUM** | 低 | 报告但标注 |
| 配置目录存在 (`~/.xxx`) | **LOW** | 高 | 仅在内容有 mtime 近期时报告 |
| search_name 匹配 | **LOW** | 很高 | 仅 inventory 参考 |

---

## 三、更好的时间获取方式

### 方案对比

| 方案 | 命令 | 含义 | 可靠性 | 适用场景 |
|------|------|------|--------|----------|
| ❌ `stat "%Sa"` (atime) | `stat -f "%Sa"` | 最后访问时间 | **不可靠** — APFS 不保证更新 | 不推荐 |
| ✅ `stat "%Sm"` (mtime) | `stat -f "%Sm"` | 最后修改时间 | **可靠** — 文件内容变更时更新 | 判断文件/目录是否有内容变更 |
| ✅ **递归 mtime** | `find dir -type f -exec stat -f "%m" {} + \| sort -rn \| head -1` | 目录内最新文件的 mtime | **可靠** — 真实反映最后写入活动 | **最适合目录型 IOC** |
| ⭐ `mdls kMDItemLastUsedDate` | `mdls -name kMDItemLastUsedDate -raw` | LaunchServices 记录的最后使用时间 | **对 .app 可靠**，对普通目录通常为空 | **最适合 .app 判断** |
| ⭐ `mdls kMDItemContentModificationDate` | `mdls -name kMDItemContentModificationDate -raw` | Spotlight 索引的内容修改时间 | **可靠** | 补充参考 |
| ✅ `stat "%SB"` (birthtime) | `stat -f "%SB"` | 创建时间 | **可靠** — APFS 保留 | 判断安装时间 |

### 推荐方案：分层时间策略

```bash
get_activity_time() {
    local path="$1"
    
    # 1. 对 .app 包：用 kMDItemLastUsedDate（LaunchServices 维护，双击/open 时更新）
    case "$path" in
        *.app)
            local last_used
            last_used=$(mdls -name kMDItemLastUsedDate -raw "$path" 2>/dev/null || true)
            if [ -n "$last_used" ] && [ "$last_used" != "(null)" ]; then
                echo "$last_used"
                return 0
            fi
            ;;
    esac
    
    # 2. 对目录：递归找最新 mtime 的文件（限深度 2，限时间，避免性能问题）
    if [ -d "$path" ]; then
        local newest
        newest=$(find "$path" -maxdepth 2 -type f -print0 2>/dev/null \
            | xargs -0 stat -f "%m" 2>/dev/null \
            | sort -rn | head -1)
        if [ -n "$newest" ]; then
            /bin/date -r "$newest" "+%Y-%m-%d %H:%M:%S" 2>/dev/null && return 0
        fi
    fi
    
    # 3. 回退：用路径本身的 mtime（而非 atime）
    stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$path" 2>/dev/null || echo "UNKNOWN"
}
```

**关键改进**：
- **不再依赖 atime** — 从信号源上消除误报
- **对 `.app` 使用 `kMDItemLastUsedDate`** — 这是 macOS 原生的"最后使用"概念，只在用户通过 LaunchServices 打开应用时更新（双击、`open` 命令、Dock 启动等），不受 Spotlight 索引或文件系统扫描影响
- **对目录使用递归 mtime** — 如果 `~/.openclaw/` 下没有任何文件在近期被修改过，说明确实是残留
- **性能保护**：`-maxdepth 2` + `head -1` 限制开销

### 实际影响

以 `~/.openclaw` 为例：
- **旧方案 (atime)**：Spotlight 扫过 → atime 更新 → 误报为"活跃" → ❌
- **新方案 (递归 mtime)**：即使被 Spotlight 扫过，里面的文件 mtime 不变 → 正确识别为"残留" → ✅

---

## 四、企业管理视角：0.2 人力/天下的关注策略

### 约束条件
- 每天 0.2 人 ≈ 1.6 小时 ≈ **每周 8 小时**
- 不可能逐条处理所有 alert
- 误报直接浪费最稀缺的人力资源

### 建议策略：三层分级

#### 第一层：自动阻断 (Zero Touch)

**不需要人力，MDM 直接执行**：
- 通过 MDM 策略阻断已知高风险应用的安装（如果 MDM 支持）
- 通过网络层（DNS/防火墙）阻断已知 C2 域名

#### 第二层：高置信 Alert → 自动工单 (≤ 0.5h/周)

**只处理高置信度信号，每条 alert 直接可操作**：

| 信号 | 为什么值得关注 | 处理方式 |
|------|---------------|----------|
| `.app` + `Contents/` 存在 | 确定安装了应用 | 联系用户确认 → 卸载或加白 |
| Bundle ID 匹配 | 确定安装了应用 | 同上 |
| 运行中进程 | 确定正在使用 | 同上（优先级最高） |
| Chrome 扩展 ID | 确定安装了扩展 | 同上 |
| LaunchAgent plist | 有持久化机制 | 检查是否恶意 |

#### 第三层：低置信 Inventory → 周报审查 (≤ 1h/周)

**P5/P6 目录匹配、配置目录残留，汇总后人工判读**：
- 每周生成一次汇总报告
- 新增项标注 `NEW`（与上周对比）
- **只关注新增**，忽略持续存在的残留
- 使用递归 mtime 辅助判断是否活跃

#### 你当前最应该做的改动

1. **立即修改**：`get_times()` 中将 `%Sa` (atime) 替换为递归 mtime 或 `%Sm` (mtime)
2. **立即修改**：`path_match_is_stale()` 中增加 `kMDItemLastUsedDate` 作为 `.app` 的时间源
3. **在报告输出中增加 `CONFIDENCE` 字段**：方便下游系统过滤
4. **P5/P6 结果与 P1-P4 分开报告**：不要混在同一个 RESULTS 数组里

### 什么值得关注、什么不值得

| 场景 | 值得关注？ | 理由 |
|------|-----------|------|
| `/Applications/Tailscale.app` 存在 | ✅ 是 | 确定安装了未授权 VPN |
| `tailscaled` 二进制存在 | ⚠️ 取决于来源 | 如果在 homebrew bin 中，可能是用户装的 |
| `~/.openclaw/` 存在但 mtime 2年前 | ❌ 否 | 残留配置，不值得花人力 |
| `~/.openclaw/` 存在且内部文件 mtime 3天前 | ✅ 是 | 近期活跃使用 |
| 项目目录中有 `openclaw/` 子目录 | ❌ 否 | 大概率是 git clone 的源码 |
| 进程列表中有 `openclaw` | ✅ 是 | 正在运行，最高优先级 |

---

## 五、应用清点脚本

### 设计原则

- Tailscale.app → ✅ 报告 / tailscaled 二进制 → ❌ 不报告
- 只报告**经过验证的 `.app` bundle**（Info.plist + CFBundleExecutable + 可执行文件存在）
- 不做全盘扫描（高 I/O 会产生客诉），只用 Spotlight + 已知目录有限深度扫描
- **READ-ONLY**：零文件写入、零临时文件、零 cleanup trap — 全部输出到 stdout
- CSV 输出，带 proper escaping，由 MDM 框架捕获

### 维护方式

`inventory.sh` 直接维护，不再通过代码生成器产出。运行时行为通过环境变量控制。

### 数据采集策略（按优先级）

| 来源 | 方式 | I/O 开销 |
|------|------|----------|
| Spotlight | `mdfind kMDItemContentTypeTree == com.apple.application-bundle` | 极低（查索引） |
| 标准目录 | `/Applications`, `~/Applications`, `/Users/*/Applications` — `find -name *.app -prune` | 低（-prune 不进入 .app 内部） |
| 用户可能下载 | `~/Desktop`, `~/Downloads`, `~/Documents` — `find -maxdepth 4 -name *.app -prune` | 低（限深度） |
| 外部卷 | `/Volumes/*` — 仅在 `INCLUDE_EXTERNAL_VOLUMES=1` 时 | 可选 |

**不做的事**：不递归用户整个 home 目录、不扫描 `node_modules`、不扫描 `/System/Volumes`。

### 过滤层

1. **噪声路径过滤** (`is_noisy_path`)：排除 Trash、Caches、DerivedData、CoreSimulator、node_modules、.git
2. **嵌套 bundle 过滤** (`is_nested_app`)：排除 `*.app/Contents/*.app` 和 `*.app/Versions/*.app`
3. **系统应用过滤** (`should_emit_app`)：排除 `/System/*` 路径和 `com.apple.*` bundle ID
4. **Bundle 验证** (`is_valid_app_bundle`)：Info.plist + CFBundleExecutable + 可执行文件三重验证

### 去重

- 候选路径通过 `canonical_dir()`（`cd + pwd -P`）解析符号链接
- `sort -u` 去除重复路径

### 时间字段

| 字段 | 来源 | 含义 |
|------|------|------|
| `last_used_date` | `mdls kMDItemLastUsedDate` | LaunchServices 维护，仅用户主动启动时更新 |
| `bundle_birth_time` | `stat -f '%SB'` | APFS 创建时间，反映安装时间 |

**不使用 atime**，避免 Spotlight/扫描脚本自身导致的误报。

### 可选增强

| 开关 | 作用 | 性能影响 |
|------|------|----------|
| `WITH_SIGNATURE=1` | codesign 验证 + Gatekeeper 评估 + Team ID | 每 app ~1s |
| `WITH_PKG_RECEIPT=1` | 查询 macOS installer pkg receipt (pkgutil) | 低 |

### 输出格式

CSV 直接输出到 stdout（由 MDM 框架捕获），字段：

```
path, display_name, bundle_id, version, build,
team_id, signed, gatekeeper,
last_used_date, bundle_birth_time,
receipt_pkgid, receipt_install_time, source_hint
```
