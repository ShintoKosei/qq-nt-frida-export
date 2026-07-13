// 通过 QQ 自己已打开的 SQLite/SQLCipher 句柄导出 Android QQ NT 数据库。
//
// 用法：
//   frida -U -f com.tencent.mobileqq -l scripts/qqnt_android_export.js
//   frida -U -n QQ -l scripts/qqnt_android_export.js
//
// 如果附加到已经运行的 QQ，请打开最近聊天或切换一次页面，
// 让 QQ 触发 SQLite 调用，脚本才能观察到 nt_msg.db 的活跃句柄。

'use strict';

const TARGET_DB_BASENAME = 'nt_msg.db';
const MODULE_NAME = 'libkernel.so';
const EXPORT_FILE_PATH = '/storage/emulated/0/Download/qq_nt_msg_plaintext.db';
const EXPORT_DELAY_MS = 1500;

let kernelModule = null;
let sqlite3Exec = null;
let sqlite3ExecAddr = null;
let sqlite3PrepareV2Addr = null;
let sqlite3OpenV2Addr = null;
let targetDbHandle = null;
let hasHooked = false;
let hasExported = false;
let inInternalExec = false;
const seenHandles = {};

function log(message) {
  console.log('[qq-export] ' + message);
}

function findKernelModule() {
  const modules = Process.enumerateModules();
  for (let i = 0; i < modules.length; i++) {
    if (modules[i].path.indexOf(MODULE_NAME) !== -1) {
      return modules[i];
    }
  }
  return null;
}

function findGlobalExport(name) {
  if (typeof Module.findGlobalExportByName === 'function') {
    return Module.findGlobalExportByName(name);
  }
  if (typeof Module.getGlobalExportByName === 'function') {
    try {
      return Module.getGlobalExportByName(name);
    } catch (_) {
      return null;
    }
  }
  if (typeof Module.findExportByName === 'function') {
    return Module.findExportByName(null, name);
  }

  const modules = Process.enumerateModules();
  for (let i = 0; i < modules.length; i++) {
    try {
      const exports = modules[i].enumerateExports();
      for (let j = 0; j < exports.length; j++) {
        if (exports[j].name === name) {
          return exports[j].address;
        }
      }
    } catch (_) {}
  }
  return null;
}

function getImportAddress(name) {
  const imports = kernelModule.enumerateImports();
  for (let i = 0; i < imports.length; i++) {
    if (imports[i].name === name) {
      log('已解析导入 ' + name + '，来源模块 ' + imports[i].module + ' @ ' + imports[i].address);
      return imports[i].address;
    }
  }
  throw new Error('缺少导入符号 ' + name);
}

function makeSqlite3Api() {
  // 当前 QQ NT 从 libbasic_share.so 导入私有 SQLCipher API。
  // 这里直接 hook 已解析的导入目标，避免依赖特定版本字节特征。
  sqlite3ExecAddr = getImportAddress('nt_sqlite3_exec');
  sqlite3PrepareV2Addr = getImportAddress('nt_sqlite3_prepare_v2');
  sqlite3OpenV2Addr = getImportAddress('nt_sqlite3_open_v2');
  sqlite3Exec = new NativeFunction(sqlite3ExecAddr, 'int', [
    'pointer',
    'pointer',
    'pointer',
    'pointer',
    'pointer',
  ]);
}

const printRowsCallback = new NativeCallback(
  function (_ctx, nColumn, colValue, colName) {
    const cols = [];
    for (let i = 0; i < nColumn; i++) {
      let name = '';
      let value = '';
      try {
        name = colName.add(i * Process.pointerSize).readPointer().readUtf8String() || '';
      } catch (_) {}
      try {
        const valuePtr = colValue.add(i * Process.pointerSize).readPointer();
        value = valuePtr.isNull() ? '' : valuePtr.readUtf8String() || '';
      } catch (_) {}
      cols.push(name + '=' + value);
    }
    log('SQL 行: ' + cols.join(' | '));
    return 0;
  },
  'int',
  ['pointer', 'int', 'pointer', 'pointer']
);

function execSql(dbHandle, sql, callback) {
  if (sqlite3Exec === null || dbHandle === null || dbHandle.isNull()) {
    return -1;
  }
  const sqlPtr = Memory.allocUtf8String(sql);
  inInternalExec = true;
  let ret = -1;
  try {
    ret = sqlite3Exec(dbHandle, sqlPtr, callback || ptr(0), ptr(0), ptr(0));
  } finally {
    inInternalExec = false;
  }
  return ret;
}

function identifyHandleWithPragma(dbHandle) {
  const key = dbHandle.toString();
  if (seenHandles[key]) {
    return;
  }
  seenHandles[key] = true;

  let matchedPath = '';
  const dbListCallback = new NativeCallback(
    function (_ctx, nColumn, colValue, colName) {
      let fileValue = '';
      let nameValue = '';
      for (let i = 0; i < nColumn; i++) {
        let col = '';
        let value = '';
        try {
          col = colName.add(i * Process.pointerSize).readPointer().readUtf8String() || '';
          const valuePtr = colValue.add(i * Process.pointerSize).readPointer();
          value = valuePtr.isNull() ? '' : valuePtr.readUtf8String() || '';
        } catch (_) {}
        if (col === 'file') fileValue = value;
        if (col === 'name') nameValue = value;
      }
      if (fileValue.indexOf('/' + TARGET_DB_BASENAME) !== -1) {
        matchedPath = fileValue;
        log('命中目标数据库 name=' + nameValue + ' file=' + fileValue);
      }
      return 0;
    },
    'int',
    ['pointer', 'int', 'pointer', 'pointer']
  );

  const ret = execSql(dbHandle, 'PRAGMA database_list;', dbListCallback);
  if (matchedPath !== '') {
    targetDbHandle = dbHandle;
    log('已捕获目标句柄 ' + dbHandle + ' ret=' + ret);
    scheduleExport();
  }
}

function scheduleExport() {
  if (hasExported || targetDbHandle === null) {
    return;
  }
  hasExported = true;
  setTimeout(exportDatabase, EXPORT_DELAY_MS);
}

function exportDatabase() {
  if (targetDbHandle === null) {
    log('还没有目标句柄；请打开一个 QQ 聊天，等待下一次 SQLite 调用');
    hasExported = false;
    return;
  }

  log('正在导出到 ' + EXPORT_FILE_PATH);
  execSql(targetDbHandle, "DETACH DATABASE plaintext;", ptr(0));
  const exportSql =
    "ATTACH DATABASE '" +
    EXPORT_FILE_PATH +
    "' AS plaintext KEY '';" +
    "SELECT sqlcipher_export('plaintext');" +
    'DETACH DATABASE plaintext;';
  const ret = execSql(targetDbHandle, exportSql, printRowsCallback);
  log('导出返回值 ret=' + ret);
  if (ret !== 0) {
    hasExported = false;
    log('导出失败；请删除旧明文文件，或重新打开 QQ 聊天后再试');
  }
}

function hookSqlite3Exec() {
  if (hasHooked) return;
  hasHooked = true;
  makeSqlite3Api();

  Interceptor.attach(sqlite3ExecAddr, {
    onEnter(args) {
      if (inInternalExec) return;
      const dbHandle = ptr(args[0]);
      let sql = '';
      try {
        sql = ptr(args[1]).readCString();
      } catch (_) {}
      if (sql !== '') {
        log('sqlite3_exec db=' + dbHandle + ' sql=' + sql.substring(0, 160));
      }
      identifyHandleWithPragma(dbHandle);
    },
  });

  Interceptor.attach(sqlite3PrepareV2Addr, {
    onEnter(args) {
      if (inInternalExec) return;
      const dbHandle = ptr(args[0]);
      let sql = '';
      try {
        sql = ptr(args[1]).readCString();
      } catch (_) {}
      if (sql !== '') {
        log('sqlite3_prepare_v2 db=' + dbHandle + ' sql=' + sql.substring(0, 160));
      }
      identifyHandleWithPragma(dbHandle);
    },
  });

  Interceptor.attach(sqlite3OpenV2Addr, {
    onEnter(args) {
      if (inInternalExec) return;
      this.outDb = ptr(args[1]);
      this.filename = '';
      try {
        this.filename = ptr(args[0]).readCString() || '';
      } catch (_) {}
    },
    onLeave(retval) {
      if (inInternalExec) return;
      const rc = retval.toInt32();
      if (this.filename !== '') {
        log('sqlite3_open_v2 rc=' + rc + ' file=' + this.filename);
      }
      if (rc === 0 && this.filename.indexOf('/' + TARGET_DB_BASENAME) !== -1) {
        try {
          targetDbHandle = this.outDb.readPointer();
          log('已从 open_v2 捕获目标句柄 ' + targetDbHandle);
          scheduleExport();
        } catch (_) {}
      }
    },
  });

  log('hook 已安装。如果没有开始导出，请打开任意 QQ 聊天触发 SQLite。');
}

function tryHookNowOrWait() {
  kernelModule = findKernelModule();
  if (kernelModule !== null) {
    log(MODULE_NAME + ' 已加载，base=' + kernelModule.base + ' size=' + kernelModule.size);
    hookSqlite3Exec();
    return;
  }

  log('等待 ' + MODULE_NAME + ' 加载...');
  const dlopenHandler = {
    onEnter(args) {
      this.path = '';
      try {
        this.path = ptr(args[0]).readUtf8String() || '';
      } catch (_) {}
    },
    onLeave(_retval) {
      if (!hasHooked && this.path.indexOf(MODULE_NAME) !== -1) {
        log('观察到模块加载: ' + this.path);
        kernelModule = findKernelModule();
        hookSqlite3Exec();
      }
    },
  };

  const dlopen = findGlobalExport('dlopen');
  const androidDlopenExt = findGlobalExport('android_dlopen_ext');
  if (dlopen !== null) Interceptor.attach(dlopen, dlopenHandler);
  if (androidDlopenExt !== null) Interceptor.attach(androidDlopenExt, dlopenHandler);
}

tryHookNowOrWait();
