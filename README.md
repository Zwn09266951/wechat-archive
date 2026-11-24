# 微信个人聊天记录自动归档工具 (`wechat-archive`)

支持 **Windows + macOS 双端** 的微信 4.x 本地 `db_storage` 只读解密（SQLCipher 4 + WAL 增量帧合并）与按会话增量 Markdown 归档工具。

- **零第三方 Python 依赖**：Windows 使用原生 CNG (`bcrypt.dll`)，macOS 使用系统原生 `CommonCrypto` (`CCCrypt`)。
- **隐私安全**：`.gitignore` 默认忽略 `secrets/`、`notes/`、`state/`、`logs/` 与本机 `config.json`，Git 仓库仅同步工具源码。

## 目录结构

- `config.example.json`：配置模板（首次使用时复制为 `config.json` 并按需修改）
- `config.json`：本机配置（微信 `db_storage` 路径、账号 ID 等，已加入 `.gitignore`）
- `secrets/all_keys.json`：**仅存本机**的数据库与图片密钥文件（切勿上传或分享）
- `state/archive_state.json`：增量归档游标与会话统计缓存
- `notes/`：归档产物（按会话单文件，超大群自动分卷，仅存本机）
  - `index.md`：全部会话总览索引（按最近活跃时间倒序）
  - `好友_<名称>.md` / `群聊_<名称>.md`：单会话单文件，内部按 `## YYYY-MM-DD` 日期分节
  - `assets/<会话名>/<YYYY-MM>/`：解密后的聊天图片资源目录
- `src/`：核心源码（`decryptor.py`、`image_decryptor.py`、`parser.py`、`exporter.py`、`run_archive.py`）
- `scripts/`：
  - Windows：`run_archive.bat`、`register_task.ps1`
  - macOS：`extract_keys_macos.sh`、`install_macos_launchd.sh`
- `logs/archive.log`：运行日志

---

## Windows 使用说明

```powershell
# 0. 首次使用：复制模板并填写本机 db_storage_dir 与 self_wxid
Copy-Item config.example.json config.json

# 1. 增量归档（日常/定时任务默认使用）
py src\run_archive.py

# 2. 全量重建全部会话归档
py src\run_archive.py --full

# 3. 仅导出最近 7 天消息
py src\run_archive.py --days 7

# 4. 首次解锁图片或微信更换密钥后，提取图片 V2 AES 密钥并全量重导（需先打开登录微信并点开任意一张大图）
py src\run_archive.py --refresh-image-key --full

# 5. 微信新增分库或更换数据库密钥后，重新扫描提取密钥（需保持微信登录运行）
py src\run_archive.py --refresh-keys

# 6. 注册/调整 Windows 定时任务间隔（默认每 30 分钟一次）
powershell -ExecutionPolicy Bypass -File scripts\register_task.ps1 -IntervalMinutes 30
```

---

## macOS 使用说明

> **前置要求**：Python 3.10+，并已安装 Xcode Command Line Tools（`xcode-select --install`，提供 `lldb`）。

```bash
# 0. 拉取仓库并创建本机配置（macOS 支持 db_storage_dir 保持 "auto" 自动检测，只需填 self_wxid）
cp config.example.json config.json

# 1. 首次提取数据库密钥（微信 4.1+ 需先重签名移除 Hardened Runtime，并按提示重新登录一次微信）
bash scripts/extract_keys_macos.sh --resign

# 2. 首次执行归档（验证文字归档；如暂不解密图片可先加 --no-images）
python3 src/run_archive.py

# 3. （可选）首次提取图片 V2 AES 密钥：在微信中点开任意一张大图后执行一次
sudo python3 src/run_archive.py --refresh-image-key --full
# 提取完成后把密钥文件归还给当前用户，方便后续非 root 定时任务运行
sudo chown "$(id -un):$(id -gn)" secrets/all_keys.json

# 4. 注册 macOS launchd 后台定时任务（默认每 30 分钟增量运行一次）
bash scripts/install_macos_launchd.sh --interval 30

# 如需卸载定时任务
bash scripts/install_macos_launchd.sh --uninstall
```
