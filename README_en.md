# qqnt-db-export 🚀

> 🌐 中文说明见 [README.md](README.md)。

QQ NT database export helpers for personal backup and self-distillation workflows.

- 🪟 Windows QQ NT: capture the database key, copy and decrypt `nt_msg.db`, then extract self-authored messages.
- 🤖 Android QQ NT: use Frida to call QQ's own SQLCipher handle and export a plaintext database.
- 🧠 Corpus extraction: extract messages sent by your own QQ account into JSONL and plain-text corpus files.

> [!WARNING]
> Use this only on accounts, devices, and data you own or are authorized to access. Do not publish exported databases, keys, JSONL files, corpora, or logs.

## ✅ Tested Versions

| Platform | Tested QQ NT version | Environment | Verified behavior |
| --- | --- | --- | --- |
| Windows | `9.9.32-50828` | Windows QQ NT | Captured 16-byte key, copied database files, decrypted with SQLCipher CLI, extracted self-authored messages |
| Android | `9.3.1` (`versionCode=14378`) | `com.tencent.mobileqq` / PLK110 / arm64 | Hooked `libkernel.so` with Frida and exported `qq_nt_msg_plaintext.db` |

## 📦 Scripts

| Script | Platform | Purpose |
| --- | --- | --- |
| `scripts/qqnt_windows_export.py` | Windows | Locate the `wrapper.node` key function, capture the key, copy and decrypt the database, extract self-authored messages |
| `scripts/qqnt_android_export.js` | Android | Inject into QQ with Frida and run `sqlcipher_export` |
| `scripts/qqnt_extract_self_messages.py` | Shared | Extract self-authored messages and corpus files from plaintext `nt_msg.db` |

## 🪟 Windows Export

The Windows script uses the **debugger backend** by default and does not depend on fixed version offsets. It:

1. Detects the QQ install directory and `wrapper.node`.
2. Locates the string `nt_sqlite3_key_v2: db=%p zDb=%s`.
3. Finds the function entry referencing that string.
4. Starts QQ under the Windows Debug API and sets an early breakpoint after `wrapper.node` is loaded.
5. Reads the database key from the x64 third argument, `R8`.
6. Copies `nt_msg.db`, `-wal`, `-shm`, and `*.material` files to the output directory.
7. Removes the first 1024-byte QQ NT database header.
8. Uses SQLCipher CLI to export a plaintext SQLite database.
9. Extracts self-authored messages when `--account` is provided.

The repository includes a companion SQLCipher CLI at `tools\sqlcipher\sqlcipher.exe`. To update SQLCipher, download a newer zip from [sqlcipher-windows-builds releases](https://github.com/ShintoKosei/sqlcipher-windows-builds/releases/latest) and replace the `tools\sqlcipher` directory.

### Example

```powershell
python scripts\qqnt_windows_export.py --kill-qq-first --account YOUR_QQ_NUMBER --outdir RE\windows_qq_export --sqlcipher tools\sqlcipher\sqlcipher.exe
```

Static analysis only:

```powershell
python scripts\qqnt_windows_export.py --static-only
```

Capture the key and copy encrypted database files without decrypting:

```powershell
python scripts\qqnt_windows_export.py --kill-qq-first --account YOUR_QQ_NUMBER --outdir RE\windows_qq_export --no-decrypt
```

Skip self-message extraction:

```powershell
python scripts\qqnt_windows_export.py --kill-qq-first --account YOUR_QQ_NUMBER --outdir RE\windows_qq_export --no-extract
```

## 🤖 Android Export

The Android script waits for `libkernel.so`, resolves QQ NT's imported `nt_sqlite3_exec`, `nt_sqlite3_prepare_v2`, and `nt_sqlite3_open_v2`, identifies an active `nt_msg.db` handle, then runs `sqlcipher_export`.

Set up Frida on both the PC and the Android device first. The Android device must be rooted.

Spawn QQ and inject:

```powershell
frida -U -f com.tencent.mobileqq -l scripts\qqnt_android_export.js
```

Default output path on the phone:

```text
/storage/emulated/0/Download/qq_nt_msg_plaintext.db
```

Pull the database back to the PC:

```powershell
adb pull /storage/emulated/0/Download/qq_nt_msg_plaintext.db RE\qq_nt_msg_plaintext.db
```

## 🧠 Extract Self-Authored Messages

After obtaining a plaintext `nt_msg.db`, extract messages sent by your own QQ account:

```powershell
python scripts\qqnt_extract_self_messages.py --db RE\qq_nt_msg_plaintext.db --account YOUR_QQ_NUMBER --outdir RE\qq_export
```

Output files:

| File | Description |
| --- | --- |
| `qq_own_messages.jsonl` | All message rows sent by your own account |
| `qq_own_text_messages.jsonl` | Rows whose text content was successfully extracted |
| `qq_own_corpus.txt` | One plain-text message per line |
| `summary.json` | Summary statistics |

## 🔐 Privacy

- Do not commit `.db`, `.db-wal`, `.db-shm`, `.jsonl`, corpus `.txt`, key summaries, or logs.
- Windows export writes `windows_qq_key_summary.json` by default; it contains the database key and must stay private.
- If you publish research notes, redact chat peers, group IDs, links, filenames, and message content first.

## 🧩 Dependencies

- The default Windows export and corpus extraction scripts use only the Python standard library, so this repository does not need a `requirements.txt`.
- SQLCipher CLI is bundled in `tools\sqlcipher`.
- Android export requires Frida CLI / frida-server and a rooted device.
- The optional Windows `--backend frida` mode needs the Python package: `python -m pip install frida`.

## 🧯 FAQ

- **Windows cannot capture the key**: use `--kill-qq-first` and let the script start QQ. Do not open QQ manually first.
- **The QQ number is invalid**: replace `YOUR_QQ_NUMBER` with your real numeric QQ number, for example `--account 12345678`.
- **Windows cannot find SQLCipher**: download SQLCipher CLI and pass the real `sqlcipher.exe` path with `--sqlcipher`.
- **Keep only encrypted Windows database files**: add `--no-decrypt`.
- **Android export does not start**: open any chat or switch pages in QQ to trigger database access.
- **Android export returns non-zero**: delete the old `qq_nt_msg_plaintext.db` on the phone and try again.
- **Extracted text looks garbled**: QQ NT message structures may change; sample-check the output before using it.

## 🔎 Similar Projects

- [artiga033/ntdb_unwrap](https://github.com/artiga033/ntdb_unwrap): a Rust-based one-click decrypt/parse tool for NTQQ databases, useful as a reference for a different implementation approach.
- [miniyu157/qq-dump](https://github.com/miniyu157/qq-dump): an Android-side NTQQ database key extraction, decryption, and chat history export tool focused on speed and mobile-friendly I/O.

## 📄 License

MIT License

## 🙏 Acknowledgements

- [QQBackup/QQDecrypt](https://github.com/QQBackup/QQDecrypt): QQ NT database decrypt notes and SQLCipher parameter references.
- [sqlcipher/sqlcipher](https://github.com/sqlcipher/sqlcipher): upstream SQLCipher project.
