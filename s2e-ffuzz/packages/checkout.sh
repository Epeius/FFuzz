#!/bin/sh

. ./config.sh

clone_or_pull() {
  #$1 git url
  #$2 dir
  #$3 branch
  if [ -d "$2" ]; then
    cd "$2"
    git fetch --all
  else
    git clone "$1" "$2"
    cd "$2"
  fi
  git checkout "$3"

  date -d @`git log --format="%ct" -1` "+%Y%m%d%H%M%S" > "$2.version"
}

mkdir -p "$S2E_ROOT"

cd "$S2E_ROOT"
clone_or_pull "$GIT_S2E" "$DIR_S2E_SRC" "$GIT_S2E_BRANCH"

