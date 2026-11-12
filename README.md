# sast-taint

静态污点分析器（Python）。**当前只有正则匹配**，没有任何数据流能力。

## 结构

```
scan.py               扫描器（正则，逐文件，输出 out/report.json）
tools/gen_corpus.py   生成 20 万行目标仓库 + 50 条标注样本
tools/evaluate.py     按标注算 recall / 误报率（不达标返回非零退出码）
target/               生成的目标仓库（gitignore）
samples/labels.json   标注样本（生成）
out/                  扫描结果（gitignore）
```

## 快速开始

```bash
# 0) 环境：本机已预装（见 requirements.txt），不需要联网装包
python -m pip install -r requirements.txt     # 已装齐，重装也很快

# 1) 生成语料与标注
python tools/gen_corpus.py --files 800 --out target --labels samples/labels.json

# 2) 跑基线扫描
python scan.py --repo target --out out/report.json

# 3) 评测
python tools/evaluate.py --report out/report.json --labels samples/labels.json
```

## 本机环境（已实测）

| 项 | 值 |
|---|---|
| Python | 3.12.1 |
| 允许的解析库 | `tree-sitter 0.26.1` + `tree-sitter-language-pack 1.25.0`（**已装**，`get_parser("python")` 可直接用） |
| SARIF | `sarif-om 1.0.4`（已装），也可以手写 JSON |
| 语料规模 | 800 文件 / 206,001 行，生成 0.5 秒 |
| 基线指标 | recall 75.8% / 误报率 47.1%，`evaluate.py` 返回退出码 1（**故意不达标**） |
| 基线耗时 | 正则全量扫描 12.7 秒；没有增量能力 |

## 现状与差距（要补的）

| 能力 | 现在 | 要求 |
|---|---|---|
| 污点源 | 无 | 识别 request.args / form / json / path 参数 |
| 传播 | 无 | 跨函数、跨文件（含返回值、字段、集合） |
| sanitizer | 无 | 白名单（参数化查询、realpath 校验、isalnum、域名白名单） |
| 输出 | 自定义 JSON | **SARIF**，可被 CI 消费并在新增违规时阻断 |
| 指标 | 无 | recall ≥ 85%、误报率 ≤ 15%（用 evaluate.py 验证） |
| 性能 | 未测 | 全量 < 3 分钟、增量 < 15 秒 |

> 基线在 `target/` 上会把大量"安全实现"也报出来——因为 `open(` / `requests.get(` 只要出现就命中了，这正是误报的来源。

## 约定

- 不提交 `target/`、`out/`、`samples/labels.json` 生成物以外的大文件；
- 只允许用语法解析库（tree-sitter 等），不得直接调用 Semgrep / CodeQL 的现成规则。
