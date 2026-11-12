"""taint —— 基于 tree-sitter 的增量静态污点分析器（不依赖 Semgrep/CodeQL 规则）。

模块划分：
  parser_util  tree-sitter 封装、源文本读取、节点工具
  rules        source / sink / sanitizer / 守卫识别
  model        函数摘要与全局索引
  engine       流敏感过程内分析 + 有界跨过程不动点
  scanner      仓库扫描、增量缓存、报告/SARIF 输出、CI 基线
"""

__version__ = "1.0.0"
