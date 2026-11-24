#!/usr/bin/env bash
set -euo pipefail

# macOS 微信 4.x 数据库密钥首次提取引导脚本
# 用法：
#   bash scripts/extract_keys_macos.sh
#   bash scripts/extract_keys_macos.sh --resign   # 先重签名 WeChat.app 再提取

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
KEYS_OUT="${PROJECT_ROOT}/secrets/all_keys.json"
TOOL="${PROJECT_ROOT}/vendor/wcdb-key-tool/wcdb_key_tool_macos.py"

mkdir -p "${PROJECT_ROOT}/secrets"

if [[ "${1:-}" == "--resign" ]]; then
  echo "[*] 正在对 /Applications/WeChat.app 执行本地 ad-hoc 重签名以移除 Hardened Runtime..."
  sudo codesign --force --deep --sign - /Applications/WeChat.app
  echo "[!] 重签名完成，请先完全退出并重新打开微信，然后按回车继续提取密钥..."
  read -r
fi

echo "[*] 开始提取 macOS 微信数据库密钥 -> ${KEYS_OUT}"
echo "    (如首次使用微信 4.1+，工具会提示在微信设置中退出登录再重新登录一次)"
sudo python3 "${TOOL}" extract --output "${KEYS_OUT}"

# 将 sudo 生成的密钥文件权限归还给当前登录用户，避免后续非 root 定时任务无法读写
if [[ -f "${KEYS_OUT}" ]]; then
  sudo chown "$(id -un):$(id -gn)" "${KEYS_OUT}"
  chmod 600 "${KEYS_OUT}"
  echo "[OK] 数据库密钥已保存并调整权限: ${KEYS_OUT}"
fi
