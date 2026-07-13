# qqnt-db-export 🚀

> 🌐 Prefer English? See the short [English section](#english).

这是一个面向 **QQ NT** 的个人数据导出工具仓库，当前覆盖：

- 🪟 Windows QQ NT：抓取数据库 key，复制并自动解密 `nt_msg.db`，再提取本人消息。
- 🤖 Android QQ NT：通过 Frida 调用 QQ 自己的 SQLCipher 句柄导出明文库。
- 🧠 语料提取：从明文 `nt_msg.db` 中提取“本人发送”的文本消息，生成 JSONL 和纯文本语料。

> ⚠️ 只用于你自己的账号、设备和已获授权的数据。不要用于未授权访问，也不要公开上传数据库、key、JSONL、聊天语料或日志。

## 📦 脚本命名

| 脚本 | 平台 | 作用 |
| --- | --- | --- |
| `scripts/qqnt_windows_export.py` | Windows | 自动定位 `wrapper.node` key 函数，抓 key、复制库、解密明文库、提取本人消息 |
| `scripts/qqnt_android_export.js` | Android | Frida 注入 QQ，调用 `sqlcipher_export` 导出明文数据库 |
| `scripts/qqnt_extract_self_messages.py` | 通用 | 从明文 `nt_msg.db` 提取本人消息和语料 |

## 🪟 Windows QQ NT 导出

Windows 脚本默认使用 **debugger 后端**，不依赖旧版本偏移表。它会：

1. 自动检测 QQ 安装目录和 `wrapper.node`。
2. 在 `wrapper.node` 中定位字符串 `nt_sqlite3_key_v2: db=%p zDb=%s`。
3. 找到引用该字符串的函数入口。
4. 调试启动 QQ，在 `wrapper.node` 加载后立即下断点。
5. 从 x64 第三个参数 `R8` 读取数据库 key。
6. 复制 `nt_msg.db`、`-wal`、`-shm`、`*.material` 到输出目录。
7. 去掉 QQ NT 数据库前 1024 字节 header。
8. 优先用 `rotki-pysqlcipher3` 导出明文 SQLite 数据库；不可用时回退 SQLCipher CLI。
9. 如果提供了 `--account`，自动提取本人消息。

推荐使用 Python 后端：

```powershell
python -m pip install rotki-pysqlcipher3
python scripts\qqnt_windows_export.py --kill-qq-first --account YOUR_QQ_NUMBER --outdir RE\windows_qq_export
```

注意：截至当前测试，`rotki-pysqlcipher3` 在 PyPI 上提供 Windows `cp311/cp312` wheel；如果你使用 Python 3.14，pip 可能会退回源码构建并失败。这种情况下请使用 Python 3.11/3.12 虚拟环境，或使用 SQLCipher CLI 后端。

SQLCipher CLI 备用方案：可以把 `sqlcipher.exe` 放进 `PATH`，也可以用 `--sqlcipher` 指定真实路径。Windows 可用版本可从 QQBackup 的 SQLCipher 构建下载：

```text
https://github.com/QQBackup/sqlcipher-github-actions/releases/latest
```

用 GitHub CLI 下载到本仓库的 `tools\sqlcipher` 示例：

```powershell
mkdir tools\sqlcipher
gh release download latest --repo QQBackup/sqlcipher-github-actions --pattern sqlcipher-x64.exe --dir tools\sqlcipher
```

推荐命令：

```powershell
python scripts\qqnt_windows_export.py --kill-qq-first --account YOUR_QQ_NUMBER --outdir RE\windows_qq_export --decrypt-backend cli --sqlcipher tools\sqlcipher\sqlcipher-x64.exe
```

只做静态定位，不启动 QQ：

```powershell
python scripts\qqnt_windows_export.py --static-only
```

只抓 key 和复制加密库，不解密：

```powershell
python scripts\qqnt_windows_export.py --kill-qq-first --account YOUR_QQ_NUMBER --outdir RE\windows_qq_export --no-decrypt
```

跳过本人消息提取：

```powershell
python scripts\qqnt_windows_export.py --kill-qq-first --account YOUR_QQ_NUMBER --outdir RE\windows_qq_export --no-extract
```

已在本机 `QQ 9.9.32-50828` 验证：脚本可抓到 16 位 key，复制 5 个数据库相关文件，导出明文 `nt_msg_plaintext.db`，并提取本人消息 JSONL/语料。

## 🤖 Android QQ NT 导出

Android 脚本会等待 `libkernel.so`，解析 QQ NT 导入的 `nt_sqlite3_exec` / `nt_sqlite3_prepare_v2` / `nt_sqlite3_open_v2`，识别活跃的 `nt_msg.db` 句柄，然后执行 `sqlcipher_export`。

启动 QQ 并注入：

```powershell
frida -U -f com.tencent.mobileqq -l scripts\qqnt_android_export.js
```

附加已运行 QQ：

```powershell
frida -U -n QQ -l scripts\qqnt_android_export.js
```

默认导出到手机：

```text
/storage/emulated/0/Download/qq_nt_msg_plaintext.db
```

拉回本机：

```powershell
adb pull /storage/emulated/0/Download/qq_nt_msg_plaintext.db RE\qq_nt_msg_plaintext.db
```

## 🧠 提取本人消息

拿到明文 `nt_msg.db` 后，按 QQ 号提取本人发送的文本：

```powershell
python scripts\qqnt_extract_self_messages.py --db RE\qq_nt_msg_plaintext.db --account YOUR_QQ_NUMBER --outdir RE\qq_export
```

输出：

| 文件 | 说明 |
| --- | --- |
| `qq_own_messages.jsonl` | 本人发送的全部消息行 |
| `qq_own_text_messages.jsonl` | 成功提取出文本内容的消息 |
| `qq_own_corpus.txt` | 一行一条纯文本语料 |
| `summary.json` | 统计摘要 |

## 🔐 隐私提醒

- 不要提交 `.db`、`.db-wal`、`.db-shm`、`.jsonl`、语料 `.txt`、key 摘要或日志。
- Windows 默认会输出 `windows_qq_key_summary.json`，里面包含 key，只能保存在本机私密目录。
- 如果要发布研究结论，请先脱敏，不要泄漏聊天对象、群号、链接、文件名或原文。

## 🧯 常见问题

- **Windows 抓不到 key**：使用 `--kill-qq-first`，确保 QQ 从脚本启动；不要先手动打开 QQ。
- **安装 `rotki-pysqlcipher3` 失败**：确认 Python 版本。当前 PyPI wheel 覆盖 Windows Python 3.11/3.12；Python 3.14 可改用 SQLCipher CLI。
- **Windows 提示找不到 SQLCipher**：下载 SQLCipher CLI，或用 `--sqlcipher` 指向真实存在的 `sqlcipher-x64.exe`。
- **Windows 只想保留加密库**：加上 `--no-decrypt`。
- **Android 没开始导出**：打开任意聊天或切换页面，让 QQ 触发数据库访问。
- **Android 导出 ret 非 0**：删除手机旧的 `qq_nt_msg_plaintext.db` 后重试。
- **提取文本有乱码**：QQ NT 历史消息结构可能变化，建议抽样检查后再用于分析。

## 📄 License

MIT License

## 🙏 鸣谢

- [QQBackup/QQDecrypt](https://github.com/QQBackup/QQDecrypt)：QQ NT 数据库解密资料与 SQLCipher 参数参考。

---

## English

QQ NT database export helpers for personal backup and self-distillation workflows.

- `scripts/qqnt_windows_export.py`: Windows QQ NT key capture, database copy, `rotki-pysqlcipher3`/SQLCipher decrypt, and self-message extraction helper.
- `scripts/qqnt_android_export.js`: Android Frida SQLCipher export script.
- `scripts/qqnt_extract_self_messages.py`: Extract self-authored messages from a plaintext `nt_msg.db`.

Use only on accounts, devices, and data you are authorized to access. Do not publish exported databases, keys, JSONL files, logs, or chat corpora.
