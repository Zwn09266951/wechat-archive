# 微信个人聊天记录自动归档工具 (`D:\wechat-archive`)

基于 Windows 微信 4.2.x 本地 `db_storage` 只读解密（SQLCipher 4 + WAL 增量帧合并）与按会话增量 Markdown 归档。

## 目录结构

- `config.json`：本地配置（微信 `db_storage` 路径、账号 ID、输出目录等）
- `secrets/all_keys.json`：**仅存本机**的数据库密钥文件（切勿上传或分享）
- `state/archive_state.json`：增量归档游标与会话统计缓存
- `notes/`：归档产物（按会话单文件，超大群自动分卷）
  - `index.md`：全部会话总览索引（按最近活跃时间倒序）
  - `好友_<名称>.md` / `群聊_<名称>.md`：单会话单文件，内部按 `## YYYY-MM-DD` 日期分节
  - `assets/<会话名>/<YYYY-MM>/`：解密后的聊天图片资源目录（Markdown 中自动以相对路径内嵌显示）
- `src/`：核心源码（`decryptor.py`、`image_decryptor.py`、`parser.py`、`exporter.py`、`run_archive.py`）
- `scripts/`：快捷启动脚本（`run_archive.bat`）与 Windows 定时任务注册脚本（`register_task.ps1`）
- `logs/archive.log`：运行日志

## 常用命令

```powershell
# 1. 增量归档（日常/定时任务默认使用）
py D:\wechat-archive\src\run_archive.py

# 2. 全量重建全部会话归档
py D:\wechat-archive\src\run_archive.py --full

# 3. 仅导出最近 7 天消息
py D:\wechat-archive\src\run_archive.py --days 7

# 4. 首次解锁图片或微信更换密钥后，提取图片 V2 AES 密钥并全量重导（需先打开登录微信并点开任意一张大图）
py D:\wechat-archive\src\run_archive.py --refresh-image-key --full

# 5. 微信新增分库或更换数据库密钥后，重新扫描提取密钥（需保持微信登录运行）
py D:\wechat-archive\src\run_archive.py --refresh-keys

# 6. 注册/调整定时任务间隔（默认每 30 分钟一次）
powershell -ExecutionPolicy Bypass -File D:\wechat-archive\scripts\register_task.ps1 -IntervalMinutes 30
```
