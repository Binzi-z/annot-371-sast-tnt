# 设计说明：tree-sitter 静态污点分析器

只使用语法解析库（`tree-sitter` / `tree-sitter-language-pack`），**不调用任何
Semgrep / CodeQL 的现成规则**。所有 source / sink / sanitizer 规则与数据流引擎
均为本项目自研，代码在 `taint/` 包内。

## 1. 总体架构

```
源码
 │  tree-sitter 解析（parser_util.py，仅语法，无规则）
 ▼
ParsedFile（AST + 函数表 + import 表）
 │  RepoIndex：跨文件符号解析、调用边（model.py）
 ▼
Engine：过程内流敏感求值 + 跨过程摘要不动点（engine.py）
   ├─ Evaluator：表达式污点（字段/下标/集合/返回值/f-string/内置建模）
   ├─ 守卫：if 白名单校验在作用域内精确清除污点（rules.py）
   └─ 摘要：returns_taint / 条件性 sink，带形参依赖
 ▼
instantiate_findings：按入口可达性把条件性 sink 实例化（每 sink 只报一次）
 ▼
JSON + SARIF 2.1.0 + CI 基线（scanner.py）
```

分层让"语法事实"（解析层）与"安全判断"（规则/引擎层）解耦：换语言只需换 parser
与节点导航，规则与不动点框架不变。

## 2. 四类 sink 与识别方式

| 类型 | 危险 API（AST 结构匹配，非正则） | 安全形态（抑制条件） |
|---|---|---|
| SQL 注入 | `cursor.execute/executemany` 的动态 SQL（`%` 拼接、f-string、`.format`、标识符） | 参数化 `execute(sql, params)` 且 SQL 文本不脏；静态字符串 |
| 命令注入 | `subprocess.run/Popen/call/...` 且 `shell=True` 或字符串命令；`os.system/popen`、`getoutput` | `shell=False` + list/tuple 形式；`shlex.quote`；`isalnum` 等白名单守卫 |
| SSRF | `requests.*` / `httpx.*` / `urllib.request.urlopen` 的 URL 实参 | `url.startswith(白名单前缀)`、`host in ALLOWED` 等主机白名单守卫 |
| 路径穿越 | `open` / `os.remove` / `shutil.*` / `Path.open` 等的路径实参 | `realpath/abspath` + `startswith(realpath(base)+sep)` 前缀守卫；`secure_filename` |

关键点：**sink 规则只判断"危险 API 形态"，是否成洞由数据流 + sanitizer 共同决定**。
这正是基线正则扫描误报率 47% 的根因——它看到 `open(` 就报，完全不看数据来源。

## 3. 污点源

- **显式源**（`rules.explicit_source`）：`request.args/form/json/values/cookies/
  headers/data/files/GET/POST` 及其 `.get(...)`、下标访问；`sys.argv`、`os.environ`、
  `os.getenv`。
- **隐式源（入口边界策略）**：服务层仓库里函数形参即外部输入边界，分析时假设所有
  形参带污点。这是一个显式策略，对应"服务函数最终被 handler 用用户输入调用"的现实。
  最终实例化阶段再用跨函数可达性确认污点能否真正到达 sink，避免无脑全报。

## 4. 过程内传播（流敏感）

`Evaluator` 对表达式做污点求值，环境是 `变量名 -> Taint(tainted, roots)`：

- **赋值/增强赋值**：右值污点绑到左值根变量；
- **字段 `x.a` / 下标 `x[k]`**：统一折叠到根 `x`，但保留 `roots` 集合使守卫能精确
  清除（见下"折叠"的取舍）；
- **集合**：list/tuple/set/dict/推导式，任一元素脏则容器脏；`append/extend/add/
  update` 把元素污点并回容器根；
- **运算**：二元/布尔/三元/比较合并两侧；`"x"*n` 数字乘数不传播；
- **f-string**：按 tree-sitter 的 `interpolation` 子节点求插值表达式污点；
- **内置/库建模**：`str/strip/format/join` 等字符串变形**不净化**（保留接收者污点），
  `int/len/bool` 等数值化不保留污点；未知函数保守按实参合并。

### 守卫（sanitizer 白名单）的生命周期

识别 `if not <校验>: raise/return/...` 这类**终止型拒绝分支**：

- `x.isalnum/isalpha/isdigit`、正则 fullmatch、`x in ALLOWED` → `allowlist`；
- `url.startswith("https://允许域/")` → `host-prefix`（只防护 ssrf）；
- `path.startswith(realpath(base)+sep)` → `path-prefix`（只防护 path）；
- 命名净化函数 `shlex.quote / secure_filename / html.escape / quote_plus /
  safe_join ...` → 返回值直接干净。

因为拒绝分支会终止执行，守卫在 **if 之后继续生效**（这是白名单校验的核心语义，
容易写错成"出块即撤销"）。sink 检查时按 sink 类型匹配守卫：路径前缀守卫不能用来
豁免 SSRF，反之亦然，避免一种校验被错误地当作万能净化。

## 5. 跨过程、跨文件传播

### 5.1 符号解析（RepoIndex）

- 解析 `import x` / `from a.b import c [as alias]`，建立文件内本地名绑定；
- 调用点名字点链（如 `db.run_query`）按「import 绑定 → 同文件函数 → 仓库唯一同名
  回退」解析到 `NodeId`。**全局同名回退只在候选唯一时采用**，避免重名函数乱连边。

### 5.2 摘要不动点（上下文不敏感）

每个函数产出一个摘要：

```
FuncSummary {
  returns_taint: bool          # 返回值是否可能带污点
  return_deps: tuple[int]      # 依赖哪些形参下标
  cond_findings: [sink + deps] # 函数体内 sink，及其依赖的形参下标
  invocations: [callee + 实参污点位置]
}
```

- 首轮分析全部函数；之后只有摘要发生变化的函数，沿**反向调用边**把它的 callers
  重新加入工作队列；
- 调用点只记录"哪些实参位置带污点"，callee 内部 sink 不在调用点实例化——否则同一
  sink 会在每个 caller 重复报告；
- 收敛后 `instantiate_findings` 从每个入口（形参全脏）出发，沿"实参确实带污点"的
  调用边做一次有界可达，触发 callee 内部条件性 sink，**每个 (文件,行,kind) 只报
  一次**，并保留最长传播链写进 SARIF message。

这套设计让跨文件传播（如 `handler → pkg/db.run_query → cursor.execute`）和返回值
传播（`build_url(user) → requests.get(...)`）都能命中，见
`tests/test_propagation.py`。

## 6. 如何控制跨过程传播的爆炸半径

这是本设计最关键的工程约束，共六道闸：

1. **上下文不敏感 + 单一摘要**。不克隆调用上下文、不展开调用栈，每个函数只维护一个
   摘要。复杂度从上下文敏感的指数级降到 `O(函数数 × 不动点轮数)`，与调用深度无关。
2. **字段/下标折叠，不无限展开堆结构**。`x.a.b[i]` 统一映射到根 `x` 的污点，只保留
   根变量名集合用于守卫清除。不对对象做字段级点-流图，杜绝 `a.b.c.d...` 的状态爆炸。
3. **不动点轮数硬上限 `MAX_FIXPOINT_ROUNDS=6`**，且**每函数重分析上限
   `MAX_REANALYZES_PER_FUNC=4`**。SCC 递归环上版本号不再变化即停；环再大也有界。
4. **实例化阶段深度上限 `MAX_INSTANTIATE_DEPTH=8` + 路径环截断**
   （`callee in path` 即停）。深于 8 跳的传播链截断，递归互调不会沿环无限走。
5. **调用边只在仓库内、且符号可解析时建立**；未知函数（库调用、动态 `getattr` 调用）
   不建跨过程边，只在过程内保守合并实参污点，不向外扩散。全局同名回退要求候选唯一。
6. **单函数语句预算 `STMT_BUDGET=20000` + 循环体只分析一遍**。循环导致的局部放大被
   掐断，循环携带的数据流靠轮间不动点收敛，而不是把循环展开 N 次。

实测（`tests/test_explosion_radius.py`）：自递归、互递归、20 跳深链、1 入口扇出 50
叶子，均在 5 秒内收敛；50 个叶子 sink 全部可达且无重复。

代价（已知近似，换取可扩展性）：上下文不敏感会合并不同调用点的状态，理论上可能
产生少量"路径不可行"的报告；字段折叠牺牲强字段敏感性。当前语料与 50 条标注下
实测误报率 0%，未来若出现此类误报，可在摘要里增加有限的调用点特化而不破坏上述
预算。

## 7. 增量扫描

- 缓存文件 `out/.taint-cache.json`：按 `sha256(文件内容)` 存每个文件的函数形参与
  摘要；`CACHE_VERSION` 变更即整体失效。
- 缓存命中的文件走 `quick_structure` 轻量恢复函数表、**直接装载旧摘要，不重新解析
  AST、不参与本轮 fixpoint**（但保留调用边，保证变更函数的跨文件传播不中断）。
- 只有哈希变化的文件重新解析并进入工作队列；删除的文件在缓存回写时自然丢弃。
- 因此增量成本 ≈ 变更文件解析 + 其反向可达小集合的重算，与仓库总规模解耦。

## 8. SARIF 与 CI 阻断

- 手写 SARIF 2.1.0（`$schema` 指向官方 schema），四类 sink 各一条 rule、`level=
  error`，带 `partialFingerprints`（传播链哈希），可直接被 GitHub code scanning 等
  消费；见 `.github/workflows/taint-analysis.yml`。
- 阻断策略用**基线文件** `security/taint-baseline.json`：`--update-baseline` 记录
  存量违规，之后 CI 只对基线外的**新增** `(file,line,kind)` 返回退出码 2 失败，
  避免历史债务一次性卡死流水线。SARIF 上传与门禁解耦——即使不接 code scanning，
  退出码也能在任意 CI 里阻断合并。

## 9. 评测与性能（本机实测）

| 指标 | 要求 | 实测 |
|---|---|---|
| 召回（50 标注） | ≥ 85% | **100%**（tp=33, fn=0） |
| 误报率 | ≤ 15% | **0%**（fp=0, tn=17） |
| 全量 800 文件 / 20.6 万行 | < 180 s | **~35 s** |
| 增量（改 3 文件） | < 15 s | **~7 s**；零变更 ~2 s |
| 测试 | — | 25 项 pytest 全过 |

复现：

```bash
python tools/gen_corpus.py --files 800 --out target --labels samples/labels.json
python scan.py --repo target --sarif out/report.sarif --cache out/.cache.json
python tools/evaluate.py --report out/report.json --labels samples/labels.json
python -m pytest tests/ -q
```
