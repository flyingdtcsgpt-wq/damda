#!/bin/sh
# 담다 실행 (Mac · Linux). Node.js가 없으면 이 폴더 안에 자동으로 내려받습니다.
cd "$(dirname "$0")" || exit 1
NODE_VER=v22.12.0
if command -v node >/dev/null 2>&1; then NODE=node
else
  NODE="./runtime/bin/node"
  if [ ! -x "$NODE" ]; then
    case "$(uname -s)" in Darwin) OS=darwin ;; *) OS=linux ;; esac
    case "$(uname -m)" in arm64|aarch64) ARCH=arm64 ;; *) ARCH=x64 ;; esac
    echo "Node.js 를 내려받는 중… (처음 한 번만)"
    mkdir -p runtime
    curl -fsSL "https://nodejs.org/dist/$NODE_VER/node-$NODE_VER-$OS-$ARCH.tar.gz" | tar -xz -C runtime --strip-components=1 || { echo "내려받기 실패. 인터넷 연결을 확인하세요."; exit 1; }
  fi
fi
export DATA_DIR="${DATA_DIR:-$PWD/data}"
( sleep 1; (command -v open >/dev/null && open "http://localhost:${PORT:-8787}") || (command -v xdg-open >/dev/null && xdg-open "http://localhost:${PORT:-8787}") ) >/dev/null 2>&1 &
exec "$NODE" server/server.js
