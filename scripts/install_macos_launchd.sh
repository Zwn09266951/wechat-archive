#!/usr/bin/env bash
set -euo pipefail

# 注册或卸载 macOS launchd 定时任务（默认每 30 分钟增量归档一次微信聊天记录）
# 用法：
#   bash scripts/install_macos_launchd.sh                 # 默认每 30 分钟
#   bash scripts/install_macos_launchd.sh --interval 15   # 每 15 分钟
#   bash scripts/install_macos_launchd.sh --uninstall     # 卸载定时任务

INTERVAL_MINUTES=30
UNINSTALL=0
LABEL="com.wechat.archive"
PLIST_PATH="${HOME}/Library/LaunchAgents/${LABEL}.plist"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --interval)
      INTERVAL_MINUTES="${2:?请指定分钟数}"
      shift 2
      ;;
    --uninstall)
      UNINSTALL=1
      shift
      ;;
    *)
      echo "未知参数: $1" >&2
      exit 1
      ;;
  esac
done

if [[ "${UNINSTALL}" -eq 1 ]]; then
  launchctl bootout "gui/$(id -u)" "${PLIST_PATH}" 2>/dev/null || launchctl unload "${PLIST_PATH}" 2>/dev/null || true
  rm -f "${PLIST_PATH}"
  echo "[OK] 已卸载 macOS 定时任务: ${LABEL}"
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PYTHON_BIN="$(command -v python3)"
INTERVAL_SECONDS=$((INTERVAL_MINUTES * 60))

mkdir -p "${HOME}/Library/LaunchAgents" "${PROJECT_ROOT}/logs"

cat > "${PLIST_PATH}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${PYTHON_BIN}</string>
    <string>${PROJECT_ROOT}/src/run_archive.py</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${PROJECT_ROOT}</string>
  <key>StartInterval</key>
  <integer>${INTERVAL_SECONDS}</integer>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${PROJECT_ROOT}/logs/launchd_stdout.log</string>
  <key>StandardErrorPath</key>
  <string>${PROJECT_ROOT}/logs/launchd_stderr.log</string>
</dict>
</plist>
EOF

launchctl bootout "gui/$(id -u)" "${PLIST_PATH}" 2>/dev/null || launchctl unload "${PLIST_PATH}" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "${PLIST_PATH}" 2>/dev/null || launchctl load "${PLIST_PATH}"

echo "[OK] 已注册 macOS 定时任务: ${LABEL} (每 ${INTERVAL_MINUTES} 分钟增量运行一次)"
echo "     配置文件: ${PLIST_PATH}"
echo "     日志目录: ${PROJECT_ROOT}/logs/"
