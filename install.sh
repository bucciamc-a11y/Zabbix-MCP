#!/usr/bin/env bash
# Zabbix MCP Server installer for Debian 12 / 13.
#
#   sudo ./install.sh                 interactive install (asks every question it needs)
#   sudo ./install.sh --reconfigure   change answers of an existing install
#   sudo ./install.sh --upgrade       rebuild from this checkout, keep configuration
#   sudo ./install.sh --uninstall     remove the container (asks about data)
#   sudo ZMCP_ZABBIX_URL=... ZMCP_ZABBIX_TOKEN=... ./install.sh --non-interactive
#
# Non-interactive answers come from ZMCP_* environment variables (see docs/INSTALL.md).
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$SCRIPT_DIR/pyproject.toml" 2>/dev/null | head -1)"
readonly SCRIPT_DIR APP_VERSION
INSTALL_DIR="${ZMCP_INSTALL_DIR:-/opt/zabbix-mcp}"
NON_INTERACTIVE=0
MODE=install
TMP_FILES=()
DETECT_NAME=""; DETECT_NETWORKS=""; DETECT_ENTRYPOINTS=""; DETECT_RESOLVERS=""
GENERATED_PASSWORD=0; NEW_TOKEN=0; MCP_TOKEN=""

# ----------------------------------------------------------------------------- output
if [[ -t 1 ]]; then C_B=$'\033[1m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_R=$'\033[31m'; C_0=$'\033[0m'; else C_B=; C_G=; C_Y=; C_R=; C_0=; fi
info() { printf '%s==>%s %s\n' "$C_B" "$C_0" "$*" >&2; }
ok()   { printf '%s ok%s  %s\n' "$C_G" "$C_0" "$*" >&2; }
warn() { printf '%swarn%s %s\n' "$C_Y" "$C_0" "$*" >&2; }
die()  { printf '%serror%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }
cleanup() { local f; for f in "${TMP_FILES[@]:-}"; do [[ -n $f ]] && rm -f "$f"; done; return 0; }
trap cleanup EXIT
trap 'die "failed at line $LINENO (exit $?). Nothing is half-configured that re-running will not fix."' ERR

# ----------------------------------------------------------------------------- prompts
# ask VAR "Prompt" [default]   - uses a preset value of VAR, else asks (or takes default when non-interactive)
ask() {
  local name=$1 prompt=$2 def=${3:-} ans prev="ZMCP_PREV_${1#ZMCP_}"
  [[ -n ${!name:-} ]] && return 0
  def=${!prev:-$def}
  if ((NON_INTERACTIVE)); then
    if [[ -z $def && ${4:-} != optional ]]; then die "missing required setting $name (non-interactive mode)"; fi
    printf -v "$name" '%s' "$def"; return 0
  fi
  read -r -p "$prompt${def:+ [$def]}: " ans || true
  printf -v "$name" '%s' "${ans:-$def}"
}

ask_secret() {
  local name=$1 prompt=$2 ans
  [[ -n ${!name:-} ]] && return 0
  if ((NON_INTERACTIVE)); then return 0; fi
  read -r -s -p "$prompt: " ans || true
  echo >&2
  printf -v "$name" '%s' "$ans"
}

# ask_yn VAR "Question" default(y|n)  - stores yes/no
ask_yn() {
  local name=$1 prompt=$2 def=$3 ans prev="ZMCP_PREV_${1#ZMCP_}"
  if [[ -z ${!name:-} && -n ${!prev:-} ]]; then
    case "${!prev,,}" in y|yes|true|1) def=y ;; *) def=n ;; esac
  fi
  if [[ -n ${!name:-} ]]; then
    case "${!name,,}" in y|yes|true|1) printf -v "$name" yes ;; *) printf -v "$name" no ;; esac
    return 0
  fi
  if ((NON_INTERACTIVE)); then
    [[ $def == y ]] && printf -v "$name" yes || printf -v "$name" no
    return 0
  fi
  read -r -p "$prompt [$([[ $def == y ]] && echo Y/n || echo y/N)]: " ans || true
  ans=${ans:-$def}
  case "${ans,,}" in y|yes) printf -v "$name" yes ;; *) printf -v "$name" no ;; esac
}

# choose VAR "Prompt" default opt1 opt2 ...
choose() {
  local name=$1 prompt=$2 def=$3 prev="ZMCP_PREV_${1#ZMCP_}"; shift 3
  local opts=("$@") ans o
  def=${!prev:-$def}
  if [[ -n ${!name:-} ]]; then
    for o in "${opts[@]}"; do [[ ${!name} == "$o" ]] && return 0; done
    die "$name must be one of: ${opts[*]}"
  fi
  if ((NON_INTERACTIVE)); then printf -v "$name" '%s' "$def"; return 0; fi
  while :; do
    read -r -p "$prompt (${opts[*]}) [$def]: " ans || true
    ans=${ans:-$def}
    for o in "${opts[@]}"; do [[ $ans == "$o" ]] && { printf -v "$name" '%s' "$ans"; return 0; }; done
    warn "please enter one of: ${opts[*]}"
  done
}

# ----------------------------------------------------------------------------- pure helpers (unit-tested)
normalize_zabbix_url() {  # https://host[/path] without trailing slash or api_jsonrpc.php
  local u=$1
  [[ $u =~ ^https?:// ]] || u="https://$u"
  u=${u%/}; u=${u%/api_jsonrpc.php}; u=${u%/}
  printf '%s' "$u"
}

url_host() { local u=${1#*://}; u=${u%%/*}; printf '%s' "${u%%:*}"; }

normalize_prefix() {  # /zabbix-mcp   (never empty, never trailing slash)
  local p=$1
  [[ $p == /* ]] || p="/$p"
  p=${p%/}
  [[ -n $p ]] || p=/zabbix-mcp
  printf '%s' "$p"
}

valid_prefix() { [[ $1 =~ ^(/[A-Za-z0-9._~-]+)+$ ]]; }
valid_port() { [[ $1 =~ ^[0-9]+$ ]] && (($1 >= 1 && $1 <= 65535)); }
valid_name() { [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]*$ ]]; }

random_password() { od -An -N16 -tx1 /dev/urandom | tr -d ' \n'; }  # 128 bits, hex

# ----------------------------------------------------------------------------- environment checks
need_root() {
  [[ ${ZMCP_SKIP_ROOT_CHECK:-} == 1 || $EUID -eq 0 ]] || die "run as root (sudo ./install.sh)"
}

check_os() {
  local osr=${ZMCP_OS_RELEASE:-/etc/os-release}
  [[ -r $osr ]] || die "cannot read $osr"
  # shellcheck disable=SC1090
  . "$osr"
  if [[ ${ID:-} != debian ]] || [[ ${VERSION_ID:-} != 12 && ${VERSION_ID:-} != 13 ]]; then
    if [[ ${ZMCP_FORCE:-} == 1 ]]; then warn "unsupported OS (${PRETTY_NAME:-unknown}); continuing because ZMCP_FORCE=1"
    else die "this installer supports Debian 12 and 13 (found: ${PRETTY_NAME:-unknown}). Set ZMCP_FORCE=1 to try anyway."; fi
  else
    ok "Debian $VERSION_ID"
  fi
}

# apt_update - refresh package indexes; a wrong system clock makes every signature "not live yet"
apt_update() {
  local out rc=0
  out=$(apt-get update 2>&1) || rc=$?
  if grep -qiE "not live until|not yet valid|not valid yet" <<<"$out"; then
    die "the system clock ($(date -u +%Y-%m-%dT%H:%M:%SZ)) is behind: apt rejects repository signatures that are not valid yet.
       Sync the clock, then re-run:  sudo timedatectl set-ntp true   (or: sudo apt-get install -y systemd-timesyncd)
       Check it with 'timedatectl' (System clock synchronized: yes)."
  fi
  if ((rc)); then printf '%s\n' "$out" >&2; die "apt-get update failed (exit $rc)"; fi
}

install_prereqs() {
  local missing=() c
  for c in curl jq tar; do command -v "$c" >/dev/null || missing+=("$c"); done
  if ((${#missing[@]})); then
    info "installing prerequisites: ${missing[*]}"
    apt_update
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates "${missing[@]}" >/dev/null
  fi
}

install_docker() {
  if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
    ok "Docker $(docker --version | sed 's/Docker version \([^,]*\).*/\1/') with compose plugin"
    return 0
  fi
  info "installing Docker Engine from Docker's official apt repository"
  # shellcheck disable=SC1091
  . /etc/os-release  # Docker repository setup only runs on a real Debian host
  apt_update
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl gnupg >/dev/null
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian %s stable\n' \
    "$(dpkg --print-architecture)" "$VERSION_CODENAME" >/etc/apt/sources.list.d/docker.list
  apt_update
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin >/dev/null
  systemctl enable --now docker >/dev/null 2>&1 || true
  docker compose version >/dev/null || die "Docker installed but 'docker compose' is unavailable"
  ok "Docker installed"
}

# ----------------------------------------------------------------------------- Zabbix validation
CURL_TLS=()

# zbx_rpc URL METHOD PARAMS [TOKEN] -> JSON on stdout (token never appears in the process list)
zbx_rpc() {
  local url=$1 method=$2 params=$3 token=${4:-}
  local body; body=$(jq -cn --arg m "$method" --argjson p "$params" '{jsonrpc:"2.0",method:$m,params:$p,id:1}')
  {
    printf 'header = "Content-Type: application/json-rpc"\n'
    [[ -n $token ]] && printf 'header = "Authorization: Bearer %s"\n' "$token"
    printf 'url = "%s/api_jsonrpc.php"\n' "$url"
  } | curl -sS --max-time 20 "${CURL_TLS[@]}" -K - -d "$body"
}

validate_zabbix() {
  local out rc
  [[ ${ZMCP_SKIP_VALIDATION:-} == 1 ]] && { warn "skipping Zabbix validation (ZMCP_SKIP_VALIDATION=1)"; return 0; }
  CURL_TLS=()
  [[ ${ZMCP_VERIFY_TLS:-yes} == no ]] && CURL_TLS=(-k)
  [[ -n ${ZMCP_CA_FILE:-} ]] && CURL_TLS=(--cacert "$ZMCP_CA_FILE")
  while :; do
    if out=$(zbx_rpc "$ZMCP_ZABBIX_URL" apiinfo.version '{}' 2>&1); then rc=0; else rc=$?; fi
    if ((rc == 0)) && jq -e '.result' >/dev/null 2>&1 <<<"$out"; then break; fi
    if ((rc == 60 || rc == 35 || rc == 77)); then
      warn "TLS certificate problem talking to $ZMCP_ZABBIX_URL"
      if ((NON_INTERACTIVE)); then die "TLS verification failed; set ZMCP_VERIFY_TLS=no or ZMCP_CA_FILE=/path/ca.pem"; fi
      local choice=""
      choose choice "Skip verification, or supply a CA certificate file?" ca skip ca
      if [[ $choice == skip ]]; then ZMCP_VERIFY_TLS=no; CURL_TLS=(-k)
      else
        ZMCP_CA_FILE=""; ask ZMCP_CA_FILE "Path to CA certificate (PEM)"
        [[ -r $ZMCP_CA_FILE ]] || { warn "cannot read $ZMCP_CA_FILE"; continue; }
        CURL_TLS=(--cacert "$ZMCP_CA_FILE")
      fi
      continue
    fi
    warn "could not reach the Zabbix API at $ZMCP_ZABBIX_URL/api_jsonrpc.php (curl exit $rc)"
    ((NON_INTERACTIVE)) && die "Zabbix API unreachable"
    local again=""; ask_yn again "Enter the URL again?" y
    [[ $again == yes ]] || die "aborted"
    ZMCP_ZABBIX_URL=""; ask ZMCP_ZABBIX_URL "Zabbix URL"; ZMCP_ZABBIX_URL=$(normalize_zabbix_url "$ZMCP_ZABBIX_URL")
  done
  local ver; ver=$(jq -r '.result' <<<"$out")
  if [[ $ver == 7.4* ]]; then ok "Zabbix $ver"
  else
    warn "Zabbix reports version $ver; this server is built for 7.4 and some tools may not work"
    local go=""; ask_yn go "Continue anyway?" n; [[ $go == yes ]] || die "aborted"
  fi
  [[ -n ${ZMCP_ZABBIX_TOKEN:-} ]] || return 0
  out=$(zbx_rpc "$ZMCP_ZABBIX_URL" host.get '{"limit":1,"output":["hostid"]}' "$ZMCP_ZABBIX_TOKEN" || true)
  if jq -e '.result|type=="array"' >/dev/null 2>&1 <<<"$out"; then ok "API token works (can read hosts)"
  else
    warn "the API token was rejected: $(jq -r '.error.data // .error.message // "no answer"' <<<"$out" 2>/dev/null)"
    ((NON_INTERACTIVE)) && die "invalid Zabbix API token"
    local go=""; ask_yn go "Continue with this token anyway?" n; [[ $go == yes ]] || die "aborted"
  fi
}

# ----------------------------------------------------------------------------- Traefik discovery
traefik_container() {
  docker ps --format '{{.Names}}	{{.Image}}' 2>/dev/null | awk -F'\t' 'tolower($2) ~ /traefik/ {print $1; exit}'
}

detect_traefik() {
  local c; c=$(traefik_container || true)
  if [[ -z $c ]]; then return 0; fi
  DETECT_NAME=$c
  DETECT_NETWORKS=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$c" 2>/dev/null || true)
  local args; args=$(docker inspect -f '{{join .Args " "}} {{join .Config.Cmd " "}}' "$c" 2>/dev/null || true)
  # entrypoints, HTTPS-looking ones first (address :443, or a name containing secure/https/tls)
  local eps ep addr secure="" other=""
  eps=$(grep -oE -- '--entrypoints\.[^.= ]+\.address=[^ ]+' <<<"$args" || true)
  while IFS= read -r ep; do
    [[ -n $ep ]] || continue
    addr=${ep#*=}; ep=${ep#--entrypoints.}; ep=${ep%%.*}
    if [[ $addr == *:443 || ${ep,,} == *secure* || ${ep,,} == *https* || ${ep,,} == *tls* ]]; then secure+="$ep "; else other+="$ep "; fi
  done <<<"$eps"
  DETECT_ENTRYPOINTS="$secure$other"
  DETECT_RESOLVERS=$(grep -oE -- '--certificatesresolvers\.[^.= ]+' <<<"$args" | sed -E 's/--certificatesresolvers\.//' | sort -u | tr '\n' ' ' || true)
}

# ----------------------------------------------------------------------------- questions
install_conf() { printf '%s/install.conf' "$INSTALL_DIR"; }

load_previous_answers() {
  local f; f=$(install_conf)
  [[ -r $f ]] || return 0
  local line k
  while IFS= read -r line; do
    k=${line%%=*}
    [[ $k == ZMCP_* && $line == *=* ]] || continue
    printf -v "ZMCP_PREV_${k#ZMCP_}" '%s' "${line#*=}"
  done <"$f"
  return 0
}

save_install_conf() {
  local f; f=$(install_conf)
  {
    echo "# written by install.sh $APP_VERSION - non-secret answers, used by reconfigure/upgrade"
    local v
    for v in ZMCP_ZABBIX_URL ZMCP_VERIFY_TLS ZMCP_CA_FILE ZMCP_ALLOW_WRITES ZMCP_CONFIRM ZMCP_EXPOSE \
             ZMCP_PUBLIC_URL ZMCP_PATH_PREFIX ZMCP_TRAEFIK_NETWORK ZMCP_TRAEFIK_ENTRYPOINT \
             ZMCP_TRAEFIK_RESOLVER ZMCP_BIND ZMCP_PORT ZMCP_ADMIN_UI ZMCP_ADMIN_TOOLSET; do
      printf '%s=%s\n' "$v" "${!v:-}"
    done
  } >"$f"
  chmod 600 "$f"
}

ask_questions() {
  echo >&2
  info "Zabbix connection"
  ask ZMCP_ZABBIX_URL "Zabbix web URL (e.g. https://zabbix.example.com)"
  ZMCP_ZABBIX_URL=$(normalize_zabbix_url "$ZMCP_ZABBIX_URL")
  ask_secret ZMCP_ZABBIX_TOKEN "Zabbix API token of the dedicated API user$([[ $MODE == reconfigure ]] && echo ' (blank = keep current)')"
  if [[ -z ${ZMCP_ZABBIX_TOKEN:-} && $MODE != reconfigure ]]; then die "an API token is required (Zabbix: Users > API tokens)"; fi
  validate_zabbix

  echo >&2
  info "What may agents do?"
  ask_yn ZMCP_ALLOW_WRITES "Allow changes in Zabbix (create/update/delete hosts, dashboards, maintenance...)? 'no' = read-only" n
  choose ZMCP_CONFIRM "Write confirmation level" all all destructive none
  ask_yn ZMCP_ADMIN_TOOLSET "Also expose user/token/role/settings management tools (high risk)?" n

  echo >&2
  info "How will agents reach this server?"
  detect_traefik
  local default_expose=direct
  if [[ -n ${DETECT_NAME:-} ]]; then ok "found Traefik container '$DETECT_NAME' (networks: ${DETECT_NETWORKS:-?})"; default_expose=traefik; fi
  choose ZMCP_EXPOSE "Expose via Traefik reverse proxy, or publish a port directly?" "$default_expose" traefik direct
  if [[ $ZMCP_EXPOSE == traefik ]]; then
    ask ZMCP_PUBLIC_URL "Base URL of your server as agents reach it (e.g. https://example.com)"
    ZMCP_PUBLIC_URL=$(normalize_zabbix_url "$ZMCP_PUBLIC_URL")
    ask ZMCP_PATH_PREFIX "URL path for this service" "/zabbix-mcp"
    ZMCP_PATH_PREFIX=$(normalize_prefix "$ZMCP_PATH_PREFIX")
    valid_prefix "$ZMCP_PATH_PREFIX" || die "invalid path '$ZMCP_PATH_PREFIX' (letters, digits, . _ ~ - and / only)"
    local first_net=${DETECT_NETWORKS%% *}
    ask ZMCP_TRAEFIK_NETWORK "Docker network Traefik uses${DETECT_NETWORKS:+ (found: $DETECT_NETWORKS)}" "${first_net:-traefik}"
    local first_ep=${DETECT_ENTRYPOINTS%% *}
    ask ZMCP_TRAEFIK_ENTRYPOINT "Traefik HTTPS entrypoint name${DETECT_ENTRYPOINTS:+ (found: $DETECT_ENTRYPOINTS)}" "${first_ep:-websecure}"
    local first_res=${DETECT_RESOLVERS%% *}
    ask ZMCP_TRAEFIK_RESOLVER "Traefik certificate resolver name (blank = use Traefik's default certificate)${DETECT_RESOLVERS:+ (found: $DETECT_RESOLVERS)}" "${first_res:-}" optional
    if ! valid_name "$ZMCP_TRAEFIK_NETWORK" || ! valid_name "$ZMCP_TRAEFIK_ENTRYPOINT"; then die "invalid Traefik network or entrypoint name"; fi
    [[ -z $ZMCP_TRAEFIK_RESOLVER ]] || valid_name "$ZMCP_TRAEFIK_RESOLVER" || die "invalid resolver name"
    ZMCP_PUBLIC_URL="${ZMCP_PUBLIC_URL}${ZMCP_PATH_PREFIX}"
    ZMCP_BIND=""; ZMCP_PORT=""
  else
    ask ZMCP_BIND "Address to publish on (127.0.0.1 = this host only, 0.0.0.0 = all interfaces)" "127.0.0.1"
    ask ZMCP_PORT "Port" "8000"
    valid_port "$ZMCP_PORT" || die "invalid port"
    ask ZMCP_PUBLIC_URL "Public URL agents will use (blank = http://$ZMCP_BIND:$ZMCP_PORT)" "" optional
    [[ -n $ZMCP_PUBLIC_URL ]] || ZMCP_PUBLIC_URL="http://$ZMCP_BIND:$ZMCP_PORT"
    ZMCP_PUBLIC_URL=${ZMCP_PUBLIC_URL%/}
    [[ $ZMCP_BIND == 127.0.0.1 ]] || warn "plain HTTP on $ZMCP_BIND: put TLS in front of it before exposing it to a network"
    ZMCP_PATH_PREFIX=""; ZMCP_TRAEFIK_NETWORK=""; ZMCP_TRAEFIK_ENTRYPOINT=""; ZMCP_TRAEFIK_RESOLVER=""
  fi

  echo >&2
  info "Web admin UI"
  ask_yn ZMCP_ADMIN_UI "Enable the web admin UI (${ZMCP_PUBLIC_URL}/admin)?" y
  if [[ $ZMCP_ADMIN_UI == yes && -z ${ZMCP_ADMIN_PASSWORD:-} ]]; then
    if [[ $MODE == reconfigure ]]; then
      if ((! NON_INTERACTIVE)); then
        local np=""
        ask_secret np "New admin password (blank = keep current)"
        if [[ -n $np ]]; then
          if ((${#np} < 12)); then die "admin password must be at least 12 characters"; fi
          ZMCP_ADMIN_PASSWORD=$np
        fi
      fi
    elif ((NON_INTERACTIVE)); then
      ZMCP_ADMIN_PASSWORD=$(random_password); GENERATED_PASSWORD=1
    else
      local p1="" p2=""
      while :; do
        ask_secret p1 "Admin password (min 12 chars, blank = generate one)"
        if [[ -z $p1 ]]; then ZMCP_ADMIN_PASSWORD=$(random_password); GENERATED_PASSWORD=1; break; fi
        if ((${#p1} < 12)); then warn "too short"; p1=""; continue; fi
        ask_secret p2 "Repeat password"
        if [[ $p1 == "$p2" ]]; then ZMCP_ADMIN_PASSWORD=$p1; break; fi
        warn "passwords differ"; p1=""; p2=""
      done
    fi
  fi
}

summary() {
  echo >&2
  info "Summary"
  {
    printf '  %-26s %s\n' "Install directory" "$INSTALL_DIR"
    printf '  %-26s %s\n' "Zabbix" "$ZMCP_ZABBIX_URL"
    printf '  %-26s %s\n' "Changes allowed" "$ZMCP_ALLOW_WRITES (confirmation: $ZMCP_CONFIRM)"
    printf '  %-26s %s\n' "User/token tools" "$ZMCP_ADMIN_TOOLSET"
    printf '  %-26s %s\n' "Agents connect to" "$ZMCP_PUBLIC_URL/mcp"
    printf '  %-26s %s\n' "Exposure" "$ZMCP_EXPOSE${ZMCP_TRAEFIK_NETWORK:+ (network $ZMCP_TRAEFIK_NETWORK, entrypoint $ZMCP_TRAEFIK_ENTRYPOINT)}"
    printf '  %-26s %s\n' "Admin UI" "$ZMCP_ADMIN_UI"
  } >&2
  local go=""; ask_yn go "Proceed with installation?" y
  [[ $go == yes ]] || die "aborted"
}

# ----------------------------------------------------------------------------- file generation
render_compose() {
  local bt='`' f="$INSTALL_DIR/docker-compose.yml" host
  {
    echo "# Generated by install.sh - edit via 'zabbix-mcp-ctl reconfigure' (manual edits are overwritten)."
    echo "name: zabbix-mcp"
    echo "services:"
    echo "  zabbix-mcp:"
    echo "    build:"
    echo "      context: ./src"
    echo "    image: zabbix-mcp:local"
    echo "    container_name: zabbix-mcp"
    echo "    restart: unless-stopped"
    echo "    user: \"10001:10001\""
    echo "    read_only: true"
    echo "    cap_drop: [ALL]"
    echo "    security_opt: [\"no-new-privileges:true\"]"
    echo "    tmpfs: [\"/tmp:size=16m,mode=1777\"]"
    echo "    mem_limit: 256m"
    echo "    pids_limit: 128"
    echo "    cpus: 1.0"
    echo "    volumes:"
    echo "      - ./data:/data"
    echo "    logging:"
    echo "      driver: json-file"
    echo "      options: {max-size: \"10m\", max-file: \"3\"}"
    if [[ $ZMCP_EXPOSE == traefik ]]; then
      host=$(url_host "$ZMCP_PUBLIC_URL")
      echo "    networks: [proxy]"
      echo "    labels:"
      echo "      - \"traefik.enable=true\""
      echo "      - \"traefik.docker.network=$ZMCP_TRAEFIK_NETWORK\""
      echo "      - \"traefik.http.routers.zabbix-mcp.rule=Host(${bt}${host}${bt}) && PathPrefix(${bt}${ZMCP_PATH_PREFIX}${bt})\""
      echo "      - \"traefik.http.routers.zabbix-mcp.entrypoints=$ZMCP_TRAEFIK_ENTRYPOINT\""
      echo "      - \"traefik.http.routers.zabbix-mcp.tls=true\""
      [[ -z $ZMCP_TRAEFIK_RESOLVER ]] || echo "      - \"traefik.http.routers.zabbix-mcp.tls.certresolver=$ZMCP_TRAEFIK_RESOLVER\""
      echo "      - \"traefik.http.routers.zabbix-mcp.priority=1000\""
      echo "      - \"traefik.http.routers.zabbix-mcp.middlewares=zabbix-mcp-strip\""
      echo "      - \"traefik.http.middlewares.zabbix-mcp-strip.stripprefix.prefixes=$ZMCP_PATH_PREFIX\""
      echo "      - \"traefik.http.services.zabbix-mcp.loadbalancer.server.port=8000\""
      echo "networks:"
      echo "  proxy:"
      echo "    external: true"
      echo "    name: $ZMCP_TRAEFIK_NETWORK"
    else
      echo "    ports:"
      echo "      - \"$ZMCP_BIND:$ZMCP_PORT:8000\""
    fi
  } >"$f"
  chmod 600 "$f"
}

# init_config  - writes /data/config.json from answers using the freshly built image
run_init() {
  local envf; envf=$(mktemp "$INSTALL_DIR/.init-env.XXXXXX"); TMP_FILES+=("$envf")
  {
    echo "ZABBIX_URL=$ZMCP_ZABBIX_URL"
    [[ -z ${ZMCP_ZABBIX_TOKEN:-} ]] || echo "ZABBIX_API_TOKEN=$ZMCP_ZABBIX_TOKEN"
    echo "ZABBIX_VERIFY_TLS=$([[ ${ZMCP_VERIFY_TLS:-yes} == no ]] && echo false || echo true)"
    [[ -z ${ZMCP_CA_FILE:-} ]] || echo "ZABBIX_CA_BUNDLE=/data/ca.pem"
    echo "READ_ONLY=$([[ $ZMCP_ALLOW_WRITES == yes ]] && echo false || echo true)"
    echo "CONFIRM_WRITES=$ZMCP_CONFIRM"
    local ts="monitoring,hosts,config,visualization,services,alerting"
    [[ $ZMCP_ADMIN_TOOLSET == yes ]] && ts="$ts,admin"
    echo "ZABBIX_TOOLSETS=$ts"
    echo "ADMIN_ENABLED=$([[ $ZMCP_ADMIN_UI == yes ]] && echo true || echo false)"
    echo "MCP_PUBLIC_URL=$ZMCP_PUBLIC_URL"
    echo "AUDIT_LOG=/data/audit.log"
    echo "LOG_LEVEL=INFO"
  } >"$envf"
  local args=(init)
  [[ -z ${ZMCP_ADMIN_PASSWORD:-} ]] || args+=(--admin-password-stdin)
  [[ ${NEW_TOKEN:-0} == 1 ]] && args+=(--new-token)
  local out
  out=$(printf '%s\n' "${ZMCP_ADMIN_PASSWORD:-}" | docker run --rm -i --user 10001:10001 --read-only \
        -v "$INSTALL_DIR/data:/data" --env-file "$envf" zabbix-mcp:local "${args[@]}")
  MCP_TOKEN=$(tail -n1 <<<"$out")
  [[ $MCP_TOKEN == zmcp_* ]] || MCP_TOKEN=""
}

# The container runs as uid/gid 10001 and must own the data directory.
own_args() {
  if [[ $EUID -eq 0 ]]; then OWN=(-o 10001 -g 10001); else OWN=(); fi
}

install_ca() {
  own_args
  install -d "${OWN[@]}" -m 700 "$INSTALL_DIR/data"
  if [[ -n ${ZMCP_CA_FILE:-} && -r $ZMCP_CA_FILE ]]; then
    install "${OWN[@]}" -m 600 "$ZMCP_CA_FILE" "$INSTALL_DIR/data/ca.pem"
  fi
}

install_files() {
  info "installing files to $INSTALL_DIR"
  install -d -m 700 "$INSTALL_DIR"
  own_args
  install -d "${OWN[@]}" -m 700 "$INSTALL_DIR/data"
  rm -rf "$INSTALL_DIR/src.new"; install -d -m 700 "$INSTALL_DIR/src.new"
  tar -C "$SCRIPT_DIR" --exclude=.git --exclude=.venv --exclude=__pycache__ --exclude=.pytest_cache \
      --exclude=.ruff_cache --exclude=./data -cf - . | tar -C "$INSTALL_DIR/src.new" -xf -
  rm -rf "$INSTALL_DIR/src"; mv "$INSTALL_DIR/src.new" "$INSTALL_DIR/src"
  printf '%s\n' "$SCRIPT_DIR" >"$INSTALL_DIR/.source"
  local bindir=${ZMCP_BIN_DIR:-/usr/local/bin}
  install -d "$bindir"
  install -m 755 "$SCRIPT_DIR/deploy/zabbix-mcp-ctl" "$bindir/zabbix-mcp-ctl"
  sed -i "s|^INSTALL_DIR=.*|INSTALL_DIR=\"$INSTALL_DIR\"|" "$bindir/zabbix-mcp-ctl"
}

compose() { docker compose --project-directory "$INSTALL_DIR" -f "$INSTALL_DIR/docker-compose.yml" "$@"; }

build_image() {
  info "building the container image (first build takes a few minutes)"
  local log; log=$(mktemp)
  if ! compose build >"$log" 2>&1; then
    tail -n 25 "$log" >&2; rm -f "$log"
    die "image build failed (last lines above); retry with: docker compose -f $INSTALL_DIR/docker-compose.yml build"
  fi
  rm -f "$log"
  ok "image built"
}

wait_healthy() {
  local i st
  for ((i = 0; i < 60; i++)); do
    st=$(docker inspect -f '{{.State.Health.Status}}' zabbix-mcp 2>/dev/null || echo none)
    [[ $st == healthy ]] && { ok "container healthy"; return 0; }
    sleep 1
  done
  warn "container not healthy after 60s (status: $st). Recent logs:"
  docker logs --tail 30 zabbix-mcp >&2 || true
  die "service did not become healthy"
}

smoke_test() {
  info "smoke tests"
  if docker exec zabbix-mcp zabbix-mcp check >/dev/null 2>&1; then ok "container can reach Zabbix with the stored token"
  else warn "container could not verify the Zabbix connection: docker exec zabbix-mcp zabbix-mcp check"; fi
  [[ -n ${MCP_TOKEN:-} ]] || return 0
  local code
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "${CURL_PUBLIC[@]}" -X POST "$ZMCP_PUBLIC_URL/mcp" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H "Authorization: Bearer $MCP_TOKEN" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"installer","version":"1"}}}' 2>/dev/null || echo 000)
  if [[ $code == 200 ]]; then ok "MCP endpoint answers at $ZMCP_PUBLIC_URL/mcp"
  else
    warn "MCP endpoint at $ZMCP_PUBLIC_URL/mcp returned HTTP $code from this host."
    warn "  (Traefik routing, DNS or firewall may need attention. Local check: docker exec zabbix-mcp zabbix-mcp check)"
  fi
}
CURL_PUBLIC=()

print_client_info() {
  local f="$INSTALL_DIR/client-config.txt" tok=${MCP_TOKEN:-<your MCP token>} url=$ZMCP_PUBLIC_URL/mcp
  {
    echo "Zabbix MCP server - connection details"
    echo "======================================"
    echo "MCP endpoint : $url"
    echo "Auth header  : Authorization: Bearer $tok"
    [[ $ZMCP_ADMIN_UI == yes ]] && echo "Admin UI     : $ZMCP_PUBLIC_URL/admin"
    echo
    echo "Claude Code:"
    echo "  claude mcp add --transport http zabbix $url --header \"Authorization: Bearer $tok\""
    echo
    echo "Cursor / generic JSON clients (mcp.json):"
    echo "  {\"mcpServers\":{\"zabbix\":{\"url\":\"$url\",\"headers\":{\"Authorization\":\"Bearer $tok\"}}}}"
    echo
    echo "Claude Desktop (claude_desktop_config.json, via mcp-remote):"
    echo "  {\"mcpServers\":{\"zabbix\":{\"command\":\"npx\",\"args\":[\"-y\",\"mcp-remote\",\"$url\",\"--header\",\"Authorization:\${ZABBIX_MCP_AUTH}\"],\"env\":{\"ZABBIX_MCP_AUTH\":\"Bearer $tok\"}}}}"
    echo
    echo "Hermes, OpenClaw, ChatGPT desktop: see docs/CLIENTS.md in the repository."
    echo
    echo "Delete this file after copying the token - it is not stored anywhere else in plain text."
  } >"$f"
  chmod 600 "$f"
  echo >&2
  info "Done. Connection details (also saved to $f):"
  sed 's/^/    /' "$f" >&2
  if [[ ${GENERATED_PASSWORD:-0} == 1 ]]; then
    echo >&2
    warn "Generated admin password (shown once): $ZMCP_ADMIN_PASSWORD"
  fi
  echo >&2
  echo "Manage with: zabbix-mcp-ctl status | logs | reconfigure | upgrade | token | uninstall" >&2
}

# ----------------------------------------------------------------------------- flows
do_install() {
  need_root; check_os; install_prereqs; install_docker
  if [[ -f $(install_conf) ]]; then
    warn "an installation already exists in $INSTALL_DIR; its answers are offered as defaults"
    load_previous_answers
  fi
  ask_questions
  if ((! NON_INTERACTIVE)); then summary; fi
  install_files
  install_ca
  save_install_conf
  render_compose
  build_image
  NEW_TOKEN=1
  run_init
  info "starting the service"
  compose up -d --remove-orphans >/dev/null
  wait_healthy
  smoke_test
  print_client_info
}

do_reconfigure() {
  need_root
  [[ -f $(install_conf) ]] || die "no installation found in $INSTALL_DIR"
  load_previous_answers
  ask_questions
  if [[ $SCRIPT_DIR != "$INSTALL_DIR/src" ]]; then install_files; fi
  install_ca
  save_install_conf
  render_compose
  if [[ $SCRIPT_DIR != "$INSTALL_DIR/src" ]]; then build_image; fi
  NEW_TOKEN=0
  run_init
  compose up -d --remove-orphans >/dev/null
  wait_healthy
  ok "reconfigured"
}

do_upgrade() {
  need_root; [[ -f $(install_conf) ]] || die "no installation found in $INSTALL_DIR"
  load_previous_answers
  local v pv
  for v in ZMCP_EXPOSE ZMCP_PUBLIC_URL ZMCP_PATH_PREFIX ZMCP_TRAEFIK_NETWORK ZMCP_TRAEFIK_ENTRYPOINT \
           ZMCP_TRAEFIK_RESOLVER ZMCP_BIND ZMCP_PORT ZMCP_CA_FILE; do
    pv="ZMCP_PREV_${v#ZMCP_}"; printf -v "$v" '%s' "${!pv:-}"
  done
  install_files
  install_ca
  render_compose
  build_image
  compose up -d --remove-orphans >/dev/null
  wait_healthy
  ok "upgraded to $APP_VERSION (configuration kept)"
}

do_uninstall() {
  need_root
  [[ -f $INSTALL_DIR/docker-compose.yml ]] || die "no installation found in $INSTALL_DIR"
  local go=""; ask_yn go "Stop and remove the Zabbix MCP container?" n
  [[ $go == yes ]] || die "aborted"
  compose down --remove-orphans >/dev/null 2>&1 || true
  docker rmi zabbix-mcp:local >/dev/null 2>&1 || true
  local purge=""; ask_yn purge "Also delete $INSTALL_DIR (configuration, tokens, audit log)?" n
  if [[ $purge == yes ]]; then rm -rf "$INSTALL_DIR"; rm -f "${ZMCP_BIN_DIR:-/usr/local/bin}/zabbix-mcp-ctl"; ok "removed everything"
  else ok "container removed; data kept in $INSTALL_DIR"; fi
}

usage() { sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

main() {
  local a
  for a in "$@"; do
    case $a in
      --non-interactive|-y) NON_INTERACTIVE=1 ;;
      --reconfigure) MODE=reconfigure ;;
      --upgrade) MODE=upgrade ;;
      --uninstall) MODE=uninstall ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $a (try --help)" ;;
    esac
  done
  [[ -t 0 ]] || NON_INTERACTIVE=1
  [[ ${ZMCP_ASSUME_YES:-} == 1 ]] && NON_INTERACTIVE=1
  case $MODE in
    install) do_install ;;
    reconfigure) do_reconfigure ;;
    upgrade) do_upgrade ;;
    uninstall) do_uninstall ;;
  esac
}

if [[ ${ZMCP_SOURCE_ONLY:-} != 1 ]]; then main "$@"; fi
