#!/usr/bin/env bash
# Bootstrap Hermes skills corpus onto a NEW machine from Cstrien/Skills_Dior.
# Usage:
#   bash bootstrap_skills.sh                    # clone vào ~/.hermes/skills (repo public, không cần auth)
#   BOOTSTRAP_FORCE=1 bash bootstrap_skills.sh  # ghi đè nếu ~/.hermes/skills đã có nội dung
set -e
REPO="https://github.com/Cstrien/Skills_Dior.git"
DEST="${HOME}/.hermes/skills"

if [ -d "$DEST/.git" ]; then
  echo "[*] $DEST đã là git repo — pull mới nhất..."
  git -C "$DEST" pull --rebase origin master
elif [ -d "$DEST" ] && [ -n "$(ls -A "$DEST" 2>/dev/null)" ]; then
  if [ "${BOOTSTRAP_FORCE:-0}" = "1" ]; then
    echo "[!] $DEST không rỗng — BOOTSTRAP_FORCE=1 nên XÓA và clone lại."
    rm -rf "$DEST"
  else
    echo "[!] $DEST đã tồn tại và không rỗng."
    echo "    Muốn ghi đè:  BOOTSTRAP_FORCE=1 bash $0"
    exit 1
  fi
fi

if [ ! -d "$DEST/.git" ]; then
  echo "[*] Clone $REPO -> $DEST"
  git clone --depth 1 "$REPO" "$DEST"
fi

echo "[✓] Skills: $(find "$DEST" -name SKILL.md | wc -l) SKILL.md trong $(du -sh "$DEST" | cut -f1)"
echo "[i] Muốn PUSH từ máy này sau này: tạo SSH key (ssh-keygen -t ed25519), thêm tại"
echo "    https://github.com/settings/ssh/new rồi:  git -C $DEST remote set-url origin git@github.com:Cstrien/Skills_Dior.git"
echo "[i] Khởi động lại Hermes (hoặc 'hermes skills list') để load skills."
