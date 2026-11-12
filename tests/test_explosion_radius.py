"""跨过程爆炸半径控制：递归环、深链、扇出场景必须收敛且有界。"""
import time

from conftest import analyze_sources


def test_direct_recursion_terminates():
    # 自递归：环截断，不能无限展开
    files = {"a.py": '''
import subprocess


def rec(n, cmd):
    if n <= 0:
        subprocess.run(cmd, shell=True)
        return
    rec(n - 1, cmd)
'''}
    t0 = time.perf_counter()
    findings, _ = analyze_sources(files)
    assert time.perf_counter() - t0 < 5
    assert len(findings) == 1 and findings[0].kind == "cmdi"


def test_mutual_recursion_terminates():
    files = {"a.py": '''
import subprocess


def a(x, cmd):
    if x:
        b(x, cmd)


def b(x, cmd):
    a(x, cmd)
    subprocess.run(cmd, shell=True)
'''}
    t0 = time.perf_counter()
    findings, _ = analyze_sources(files)
    assert time.perf_counter() - t0 < 5
    assert any(f.kind == "cmdi" for f in findings)


def test_long_chain_is_depth_bounded():
    # 20 跳调用链：超过实例化深度上限(8)的部分被截断，但分析必须快速完成
    funcs = ["import subprocess\n"]
    funcs.append("""
def f0(cmd):
    subprocess.run(cmd, shell=True)
""")
    for i in range(1, 20):
        funcs.append(f"""
def f{i}(x):
    return f{i-1}(x)
""")
    t0 = time.perf_counter()
    findings, _ = analyze_sources({"chain.py": "\n".join(funcs)})
    assert time.perf_counter() - t0 < 5
    # sink 仍可从近邻入口到达
    assert any(f.kind == "cmdi" for f in findings)


def test_wide_fanout_linear_cost():
    # 一个入口扇出调用 50 个叶子函数：分析次数应与函数数同阶，不指数膨胀
    leaves = []
    calls = []
    for i in range(50):
        leaves.append(f"""
def leaf{i}(v):
    import subprocess
    subprocess.run(v + str({i}), shell=True)
""")
        calls.append(f"    leaf{i}(x)")
    entry = "def entry(x):\n" + "\n".join(calls) + "\n"
    t0 = time.perf_counter()
    findings, index = analyze_sources({"wide.py": "\n".join(leaves + [entry])})
    elapsed = time.perf_counter() - t0
    assert elapsed < 5
    # 50 个叶子 sink 都应被入口的污点到达
    assert len([f for f in findings if f.kind == "cmdi"]) == 50
    assert len(index.funcs) == 51
