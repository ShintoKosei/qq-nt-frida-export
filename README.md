# qqnt-db-export 🚀

> 🌐 Prefer English? See [README_en.md](README_en.md).

这是一个面向 **QQ NT** 的个人数据导出工具仓库，当前覆盖：

- 🪟 Windows QQ NT：抓取数据库 key，复制并自动解密 `nt_msg.db`，再提取本人消息。
- 🤖 Android QQ NT：通过 Frida 调用 QQ 自己的 SQLCipher 句柄导出明文库。
- 🧠 语料提取：从明文 `nt_msg.db` 中提取“本人发送”的文本消息，生成 JSONL 和纯文本语料。

> [!WARNING]
> ⚠️ 只用于你自己的账号、设备和已获授权的数据。不要用于未授权访问，也不要公开上传数据库、key、JSONL、聊天语料或日志。

## ✅ 已测试版本

| 平台 | 已测试 QQ NT 版本 | 测试环境 | 验证内容 |
| --- | --- | --- | --- |
| Windows | `9.9.32-50828` | Windows QQ NT | 抓取 16 位 key、复制数据库、SQLCipher CLI 解密、提取本人消息 |
| Android | `9.3.1` (`versionCode=14378`) | `com.tencent.mobileqq` / PLK110 / arm64 | Frida hook `libkernel.so`，导出明文 `qq_nt_msg_plaintext.db` |

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
8. 使用 SQLCipher CLI 导出明文 SQLite 数据库。
9. 如果提供了 `--account`，自动提取本人消息。

仓库已内置配套构建的 SQLCipher CLI，路径为 `tools\sqlcipher\sqlcipher.exe`。如果需要更新 SQLCipher，可从 [sqlcipher-windows-builds releases](https://github.com/ShintoKosei/sqlcipher-windows-builds/releases/latest) 下载新版 zip 并覆盖 `tools\sqlcipher` 目录。

### 示例命令

```powershell
python scripts\qqnt_windows_export.py --kill-qq-first --account YOUR_QQ_NUMBER --outdir RE\windows_qq_export --sqlcipher tools\sqlcipher\sqlcipher.exe
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

## 🤖 Android QQ NT 导出

Android 脚本会等待 `libkernel.so`，解析 QQ NT 导入的 `nt_sqlite3_exec` / `nt_sqlite3_prepare_v2` / `nt_sqlite3_open_v2`，识别活跃的 `nt_msg.db` 句柄，然后执行 `sqlcipher_export`。

请先在 PC 端和 Android 设备上配置好 Frida 环境，设备需要 root 权限。

启动 QQ 并注入：

```powershell
frida -U -f com.tencent.mobileqq -l scripts\qqnt_android_export.js
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

## 🧩 依赖说明

- 默认 Windows 导出和语料提取脚本只使用 Python 标准库，不需要 `requirements.txt`。
- SQLCipher CLI 已内置在 `tools\sqlcipher`。
- Android 导出依赖 Frida CLI / frida-server 和 root 环境。
- Windows 的可选 `--backend frida` 需要额外安装 Python 包：`python -m pip install frida`。

## 🧯 常见问题

- **Windows 抓不到 key**：使用 `--kill-qq-first`，确保 QQ 从脚本启动；不要先手动打开 QQ。
- **提示 QQ 号不正确**：把命令里的 `YOUR_QQ_NUMBER` 替换成真实纯数字 QQ 号，例如 `--account 12345678`。
- **Windows 提示找不到 SQLCipher**：下载 SQLCipher CLI，或用 `--sqlcipher` 指向真实存在的 `sqlcipher.exe`。
- **Windows 只想保留加密库**：加上 `--no-decrypt`。
- **Android 没开始导出**：打开任意聊天或切换页面，让 QQ 触发数据库访问。
- **Android 导出 ret 非 0**：删除手机旧的 `qq_nt_msg_plaintext.db` 后重试。
- **提取文本有乱码**：QQ NT 历史消息结构可能变化，建议抽样检查后再用于分析。

## 🔎 相似项目

- [artiga033/ntdb_unwrap](https://github.com/artiga033/ntdb_unwrap)：面向 NTQQ 数据库的一键解密/解析工具，提供 Rust 实现，可作为不同实现路线的参考。
- [miniyu157/qq-dump](https://github.com/miniyu157/qq-dump)：Android 端 NTQQ 数据库密钥提取、解密与聊天记录导出工具，强调速度和移动端 I/O 友好。

## 📄 License

MIT License

## 🙏 鸣谢

- [QQBackup/QQDecrypt](https://github.com/QQBackup/QQDecrypt)：QQ NT 数据库解密资料与 SQLCipher 参数参考。
- [sqlcipher/sqlcipher](https://github.com/sqlcipher/sqlcipher)：SQLCipher 上游项目。
