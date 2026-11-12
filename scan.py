"""静态污点分析器入口（tree-sitter；替代旧的正则基线）。

能力：
  - 污点源：request.args/form/json/path 参数等显式源 + 服务层函数形参隐式源；
  - 传播：流敏感过程内 + 上下文不敏感跨函数/跨文件摘要不动点
    （字段、下标、集合、返回值均建模，见 taint/engine.py）；
  - sanitizer 白名单：参数化查询、realpath 前缀校验、isalnum/正则白名单、
    主机白名单、shlex.quote/secure_filename 等（见 taint/rules.py）；
  - 输出 JSON + SARIF 2.1.0，支持 CI 基线，仅对新增违规阻断；
  - 增量：基于文件哈希的解析/摘要缓存，只重算变更文件。

    python scan.py --repo target --out out/report.json --sarif out/report.sarif
    python scan.py --repo target --baseline out/baseline.json      # CI 模式
    python scan.py --repo target --update-baseline --baseline out/baseline.json
"""

from taint.scanner import main

if __name__ == "__main__":
    raise SystemExit(main())
