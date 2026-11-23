发布包的校验清单在传输时被替换，安装程序照样装完：清单把相对路径直接拼到根目录却不做规范化，点点路径可以逃出根目录；路径校验只判断开头是否为斜杠，Windows 盘符路径被放过；差异比对只检查缺失和被改，多出来的文件被忽略；签名校验排在文件比对之后，被篡改的内容已经先被读取；签名比较使用普通等号，不是恒定时间比较；清单哈希使用弱算法，碰撞可以被构造；空清单被当成通过，等于关掉校验；策略校验不检查是否忽略多出文件；批量校验复用上一包的实际文件集合，后一个包命中前一个包；目录被软链接指向根外时不检查真实路径。manifest/verify.py 是核心，tests/test_verify.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

运行方式
在仓库根目录执行 pytest tests -q。
初始状态下 src/manifest/verify.py 的 8 个函数全部只抛出 NotImplementedError，因此输出末尾必须恰好是 15 failed，并且没有 error。出现 collection error、import error 或 skip 都视为不合格。

字段表
所属领域　　安全
子方向　　　漏洞检测与攻防
任务类型　　Bugfix
语言框架　　Python 3, pytest
环境等级　　无外部依赖

目录结构
sec-integrity-manifest
  README.md
  pyproject.toml
  src/manifest/__init__.py
  src/manifest/verify.py
  tests/conftest.py
  tests/test_verify.py

布局说明
仓库采用 src 布局，源码包放在 src/manifest，tests/conftest.py 与 pyproject.toml 已把 src 加入导入路径，不需要安装包即可运行测试。

约束
只使用标准库 hashlib、hmac、json、os 与 pytest，离线运行，不使用随机数，不联网，不引入第三方依赖。
tests 不可修改。解题只实现 src/manifest/verify.py 的 8 个桩，不改测试，不跳过测试，不放宽断言。清单签名、文件集合和文件哈希的容差都是 0。
## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

