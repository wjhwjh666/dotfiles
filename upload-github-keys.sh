#!/bin/bash
# === GitHub Keys 一键上传脚本 ===
# 用法: bash upload-github-keys.sh
# 会在浏览器弹出 device activation，按提示操作即可

set -e

echo "=== 1/3 刷新 Token 权限 ==="
echo "👉 如果浏览器没有自动打开，手动访问显示的网址，输入验证码"
gh auth refresh -h github.com -s admin:public_key,admin:gpg_key

echo ""
echo "=== 2/3 上传 SSH Key ==="
gh ssh-key add ~/.ssh/github_wjhwjh666.pub --title "Win11-ClaudeCastle"

echo ""
echo "=== 3/3 上传 GPG Key ==="
cat ~/gpg_key_block.txt | gh gpg-key add -

echo ""
echo "✅ 全部完成！"
echo "验证 SSH: ssh -T git@ssh.github.com -p 443"
echo "验证 GPG: gh api user/gpg_keys --jq '.[].key_id'"
