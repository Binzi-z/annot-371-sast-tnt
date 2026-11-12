# sast-taint

基于 **tree-sitter** 的可增量静态污点分析器（Python）。不套用 Semgrep / CodeQL 的
现成规则，source / sink / sanitizer 规则与数据流引擎全部自研，见 [`DESIGN.md`](DESIGN.md)。

## 能力

- **四类 sink**：SQL 注入、命令注入、SSRF、路径穿越（AST 结构匹配，非正则）；
- **污点源**：`request.args/form/json/...`、`sys.argv`、`os.environ` 等显式源 +
  服务层函数形参隐式入口源；
- **跨函数 / 跨文件传播**：流敏感过程内 + 上下文不敏感摘要不动点，覆盖字段、下标、
  集合、f-string、返回值；
- **sanitizer 白名单**：参数化查询、`realpath` 前缀校验、`isalnum`/正则/成员白名单、
  域名前缀、`shlex.quote`、`secure_filename` 等，且守卫按 sink 类型精确生效；
- **输出 SARIF 2.1.0**，可被 CI 消费；基线模式只对**新增违规**阻断（退出码 2）；
- **增量扫描**：文件哈希 + 摘要缓存，未变更文件不重新解析、不参与不动点。

## 结构

```
scan.py                     CLI 入口（替代旧正则基线）
taint/
  parser_util.py            tree-sitter 封装、AST 节点工具、轻量缓存恢复
  rules.py                  source / sink / sanitizer / 验证守卫规则
  model.py                  函数摘要、RepoIndex、import 与调用边解析
  engine.py                 流敏感求值 + 跨过程摘要不动点 + 实例化
  scanner.py                扫描编排、增量缓存、JSON/SARIF、CI 基线
tools/
  gen_corpus.py             生成 20 万行目标仓库 + 50 条标注样本
  evaluate.py               按标注算 recall / 误报率（不达标返回非零）
  ast_dump.py               调试用：打印 tree-sitter AST
tests/                      25 项 pytest（sink/传播/增量/SARIF/爆炸半径）
.github/workflows/          CI：SARIF 上传 + 新增违规阻断 + 增量耗时门禁
DESIGN.md                   架构与「跨过程爆炸半径」控制的完整说明
```

## 快速开始

```bash
# 0) 环境（本机已预装，见 requirements.txt，仅 tree-sitter 系解析库）
python -m pip install -r requirements.txt

# 1) 生成语料与标注
python tools/gen_corpus.py --files 800 --out target --labels samples/labels.json

# 2) 全量扫描（JSON + SARIF + 增量缓存）
python scan.py --repo target --out out/report.json \
               --sarif out/report.sarif --cache out/.taint-cache.json

# 3) 评测
python tools/evaluate.py --report out/report.json --labels samples/labels.json

# 4) 测试
python -m pytest tests/ -q
```

## CI 用法

```bash
# 首次：登记存量违规为基线（之后不再被阻断）
python scan.py --repo . --baseline security/taint-baseline.json --update-baseline

# 日常：只阻断基线外的新增违规（有新增时退出码 2）
python scan.py --repo . --sarif out/report.sarif \
               --cache out/.taint-cache.json \
               --baseline security/taint-baseline.json
```

## 实测指标（800 文件 / 206,001 行，Python 3.12 / Windows 11）

| 指标 | 要求 | 实测 |
|---|---|---|
| 召回（50 标注） | ≥ 85% | **100%**（tp=33 / fn=0） |
| 误报率 | ≤ 15% | **0%**（fp=0 / tn=17） |
| 全量扫描 | < 3 min | **~35 s** |
| 增量扫描（改 3 文件） | < 15 s | **~7 s**（零变更 ~2 s） |
| 测试 | — | 25 passed |

> 对比旧正则基线：recall 75.8% / 误报率 47.1%、无增量、非 SARIF。

## 跨过程爆炸半径（摘要，详见 DESIGN.md §6）

上下文不敏感单一摘要（不克隆调用栈）＋字段/下标折叠到根变量＋不动点 6 轮/每函数
重分析 4 次硬上限＋实例化深度 8 跳与环截断＋仅对可解析的仓库内调用建边＋单函数语句
预算与循环单次分析。复杂度 `O(函数数 × 轮数)`，递归/互调/深链/大扇出均有界收敛。

## 约定

- 只用语法解析库（tree-sitter 等），不直接调用 Semgrep / CodeQL 规则；
- `target/`、`out/`、缓存与临时仓库均已 gitignore。
