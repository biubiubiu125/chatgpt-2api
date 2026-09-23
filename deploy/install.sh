#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="${REPO_OWNER:-biubiubiu125}"
REPO_NAME="${REPO_NAME:-chatgpt-2api}"
BRANCH="main"
INSTALL_DIR="${INSTALL_DIR:-/opt/chatgpt-2api}"
PORT="${CHATGPT2API_PORT:-${PORT:-2080}}"
THREAD_TOKENS="${CHATGPT2API_THREAD_TOKENS:-${THREAD_TOKENS:-120}}"
BASE_URL_EXPLICIT=0
if [[ -n "${CHATGPT2API_BASE_URL+x}" || -n "${BASE_URL+x}" ]]; then
  BASE_URL_EXPLICIT=1
fi
BASE_URL="${CHATGPT2API_BASE_URL:-${BASE_URL:-}}"
MODE="${MODE:-docker}"
AUTH_KEY="${CHATGPT2API_AUTH_KEY:-${AUTH_KEY:-}}"
DATABASE_MODE="postgres-local"
DATABASE_URL=""
POSTGRES_DB_INPUT="${POSTGRES_DB:-}"
POSTGRES_DB="chatgpt_2api_app"
POSTGRES_USER_EXPLICIT=0
if [[ -n "${POSTGRES_USER+x}" ]]; then
  POSTGRES_USER_EXPLICIT=1
fi
POSTGRES_USER="${POSTGRES_USER:-chatgpt_2api}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"
INSTALL_LANG="${INSTALL_LANG:-}"
CHATGPT2API_IMAGE="${CHATGPT2API_IMAGE:-}"

if [[ -z "${UI_DEV:-}" ]]; then
  UI_DEV="/dev/tty"
  if [[ ! -r "${UI_DEV}" ]]; then
    UI_DEV="/dev/stdin"
  fi
fi

usage() {
  printf '%s\n\n' "$(text usage_title)"
  printf '%s\n' "$(text usage_usage)"
  cat <<'EOF'
  bash deploy/install.sh
  curl -fsSL https://raw.githubusercontent.com/biubiubiu125/chatgpt-2api/main/deploy/install.sh | sudo bash
EOF

  printf '\n%s\n' "$(text usage_env)"
  cat <<'EOF'
  INSTALL_DIR=/opt/chatgpt-2api
  PORT=2080
  CHATGPT2API_BASE_URL=https://your-domain.com
  CHATGPT2API_THREAD_TOKENS=120
  MODE=docker
  AUTH_KEY=your-auth-key
  POSTGRES_PASSWORD=generated-automatically
  INSTALL_LANG=zh|en
  CHATGPT2API_IMAGE=ghcr.io/biubiubiu125/chatgpt-2api:latest
EOF

  printf '\n%s\n' "$(text usage_flags)"
  cat <<'EOF'
  --mode docker
  --port 2080
  --base-url https://your-domain.com
  --thread-tokens 120
  --install-dir /opt/chatgpt-2api
  --auth-key your-auth-key
  --postgres-password your-postgres-password
  --repo-owner biubiubiu125
  --repo-name chatgpt-2api
  -h, --help
EOF
}

ui_print() {
  printf '%s' "$*" >"${UI_DEV}"
}

ui_println() {
  printf '%s\n' "$*" >"${UI_DEV}"
}

is_en() {
  [[ "${INSTALL_LANG}" =~ ^([Ee][Nn]|[Ee]nglish)$ ]]
}

normalize_language() {
  case "${INSTALL_LANG}" in
    en|EN|english|English|英文) INSTALL_LANG="en" ;;
    *) INSTALL_LANG="zh" ;;
  esac
}

echo_selected() {
  ui_println "$(text chosen_prefix)$*"
}

print_banner() {
  ui_println ""
  ui_println "========================================"
  ui_println "  ChatGPT2API 安装向导 / Setup wizard"
  ui_println "========================================"
  ui_println "直接回车使用 [方括号] 默认值，并立刻显示已选择的结果。"
  ui_println "Press Enter to keep the default in [brackets]; the chosen value is printed immediately."
  ui_println ""
}

print_step() {
  local index="$1"
  local title="$2"
  local hint="$3"
  ui_println ""
  ui_println "----- $(text step_prefix) ${index}/5：${title} -----"
  ui_println "${hint}"
}

text() {
  local key="$1"
  if is_en; then
    case "${key}" in
      usage_title) printf 'ChatGPT2API installer' ;;
      usage_usage) printf 'Usage:' ;;
      usage_env) printf 'Environment overrides:' ;;
      usage_flags) printf 'Flags:' ;;
      prefix_error) printf 'ERROR' ;;
      prefix_info) printf 'INFO' ;;
      prefix_warn) printf 'WARN' ;;
      prefix_done) printf 'OK' ;;
      step_prefix) printf 'Step' ;;
      chosen_prefix) printf 'Selected: ' ;;
      step_language) printf 'Interface language' ;;
      hint_language) printf 'This language is used for the remaining installer prompts.' ;;
      step_port) printf 'Web/API port' ;;
      hint_port) printf 'Browser and API clients will use this host port. The container still listens on port 80.' ;;
      step_base_url) printf 'Image access URL' ;;
      hint_base_url) printf 'Prefix used in returned image URLs. Press Enter to leave it empty and follow the current request. A bare domain or IP is saved as https, for example example.com becomes https://example.com.' ;;
      step_dir) printf 'Install directory' ;;
      hint_dir) printf 'Compose files, .env, and config.json are written here. The default is /opt/chatgpt-2api.' ;;
      step_auth) printf 'Admin login key' ;;
      hint_auth) printf 'Used to sign in to the console. Input is hidden. It cannot be empty, and you must type it twice.' ;;
      prompt_select) printf 'Select' ;;
      prompt_port) printf 'Web/API port' ;;
      prompt_base_url) printf 'Image access URL' ;;
      prompt_dir) printf 'Install directory' ;;
      prompt_auth) printf 'Admin login key' ;;
      prompt_auth_again) printf 'Type the admin login key again' ;;
      secret_saved) printf 'Saved. The key was not displayed.' ;;
      err_auth_empty) printf 'The admin login key cannot be empty. Type it, do not press Enter to skip.' ;;
      err_auth_mismatch) printf 'The two keys do not match. Try again.' ;;
      info_mode) printf 'Run mode is fixed to Docker with a local PostgreSQL 18 container.' ;;
      label_mode_docker) printf 'Docker container (recommended)' ;;
      info_database) printf 'Database is fixed to a local PostgreSQL 18 container. SQLite and external URLs are not offered.' ;;
      label_database) printf 'PostgreSQL 18 local container' ;;
      label_branch) printf 'repository main (fixed)' ;;
      summary_title) printf 'Ready to install' ;;
      summary_language) printf 'Language' ;;
      summary_mode) printf 'Run mode' ;;
      summary_port) printf 'Port' ;;
      summary_base_url) printf 'Image URL' ;;
      summary_base_url_empty) printf 'not set; image links follow the current request address' ;;
      summary_dir) printf 'Directory' ;;
      summary_database) printf 'Database' ;;
      summary_git) printf 'Source' ;;
      summary_auth) printf 'Admin key' ;;
      summary_auth_set) printf 'set (hidden)' ;;
      confirm_install) printf 'Start installation now?' ;;
      confirm_yes) printf 'Yes, start installation' ;;
      confirm_no) printf 'Installation cancelled.' ;;
      label_lang_zh) printf 'Chinese' ;;
      label_lang_en) printf 'English' ;;
      err_missing_cmd) printf 'Missing command' ;;
      err_unknown_arg) printf 'Unknown argument' ;;
      err_mode) printf 'Only Docker with local PostgreSQL 18 is supported.' ;;
      err_port) printf 'PORT must be a number from 1 to 65535.' ;;
      err_base_url) printf 'Image access URL must be empty, an http(s) URL, or a domain/IP. A domain or IP is saved as https. Query strings and fragments are not allowed.' ;;
      err_thread_tokens) printf 'CHATGPT2API_THREAD_TOKENS must be a positive integer.' ;;
      err_install_dir) printf 'Install directory must be an absolute path, for example /opt/chatgpt-2api.' ;;
      err_branch) printf 'The install branch is fixed to main.' ;;
      err_database_url) printf 'The installer creates local PostgreSQL 18 and does not accept a database URL.' ;;
      err_database_name) printf 'The database name must be chatgpt_2api_app.' ;;
      err_postgres_password) printf 'POSTGRES_PASSWORD may only contain letters, numbers, underscores, and hyphens.' ;;
      err_dotenv) printf 'A value written to .env must not contain newlines.' ;;
      err_not_git) printf 'exists but is not a git repository.' ;;
      err_compose) printf 'docker compose plugin not found. Please install Docker Compose v2 first.' ;;
      info_update) printf 'Updating' ;;
      info_clone) printf 'Cloning' ;;
      info_start_docker) printf 'Starting Docker service...' ;;
      done_ready) printf 'ChatGPT2API is ready' ;;
      done_base_url) printf 'Image access URL' ;;
      done_auth) printf 'Admin auth key' ;;
      done_auth_saved) printf 'saved in .env and config.json' ;;
      *) printf '%s' "${key}" ;;
    esac
    return
  fi

  case "${key}" in
    usage_title) printf 'ChatGPT2API 安装脚本' ;;
    usage_usage) printf '用法：' ;;
    usage_env) printf '可用环境变量：' ;;
    usage_flags) printf '可用参数：' ;;
    prefix_error) printf '错误' ;;
    prefix_info) printf '信息' ;;
    prefix_warn) printf '警告' ;;
    prefix_done) printf '完成' ;;
    step_prefix) printf '步骤' ;;
    chosen_prefix) printf '已选择：' ;;
    step_language) printf '界面语言' ;;
    hint_language) printf '后续安装提示会使用这个语言。直接回车即中文。' ;;
    step_port) printf 'Web/API 端口' ;;
    hint_port) printf '浏览器打开控制台、调用 API 都走这个宿主机端口。容器内部仍监听 80。' ;;
    step_base_url) printf '图片访问地址' ;;
    hint_base_url) printf '用来生成图片结果的访问前缀。直接回车留空，按当前请求地址生成链接。只填域名或 IP 会自动补成 https，例如 example.com 会变成 https://example.com。' ;;
    step_dir) printf '安装目录' ;;
    hint_dir) printf 'Compose、.env 和 config.json 会写到这里。默认目录是 /opt/chatgpt-2api。' ;;
    step_auth) printf '管理员登录密钥' ;;
    hint_auth) printf '用来登录管理控制台。输入时不显示。不能空回车，必须输入两次且一致。' ;;
    prompt_select) printf '请选择' ;;
    prompt_port) printf 'Web/API 端口' ;;
    prompt_base_url) printf '图片访问地址' ;;
    prompt_dir) printf '安装目录' ;;
    prompt_auth) printf '管理员登录密钥' ;;
    prompt_auth_again) printf '请再输入一次管理员登录密钥' ;;
    secret_saved) printf '已保存，输入内容未显示。' ;;
    err_auth_empty) printf '管理员登录密钥不能为空，不能直接回车跳过。' ;;
    err_auth_mismatch) printf '两次输入不一致，请重新输入。' ;;
    info_mode) printf '运行方式固定为 Docker，并使用本机 PostgreSQL 18 容器。' ;;
    label_mode_docker) printf 'Docker 容器（推荐）' ;;
    info_database) printf '数据库固定为 PostgreSQL 18 本地容器，不再提供 SQLite 或外部数据库地址。' ;;
    label_database) printf 'PostgreSQL 18 本地容器' ;;
    label_branch) printf '仓库 main（固定）' ;;
    summary_title) printf '即将安装' ;;
    summary_language) printf '界面语言' ;;
    summary_mode) printf '运行方式' ;;
    summary_port) printf '端口' ;;
    summary_base_url) printf '图片访问地址' ;;
    summary_base_url_empty) printf '未设置，按当前请求地址生成图片链接' ;;
    summary_dir) printf '安装目录' ;;
    summary_database) printf '数据库' ;;
    summary_git) printf '代码来源' ;;
    summary_auth) printf '管理员密钥' ;;
    summary_auth_set) printf '已设置（输入已隐藏）' ;;
    confirm_install) printf '确认开始安装？' ;;
    confirm_yes) printf '是，开始安装' ;;
    confirm_no) printf '已取消安装。' ;;
    label_lang_zh) printf '中文' ;;
    label_lang_en) printf 'English' ;;
    err_missing_cmd) printf '缺少命令' ;;
    err_unknown_arg) printf '未知参数' ;;
    err_mode) printf '只支持 Docker 与本地 PostgreSQL 18。' ;;
    err_port) printf '端口必须是 1 到 65535 的数字。' ;;
    err_base_url) printf '图片访问地址可以留空，也可以填写 http/https 地址、域名或 IP。只填域名或 IP 会保存为 https。不能带查询参数或片段。' ;;
    err_thread_tokens) printf 'CHATGPT2API_THREAD_TOKENS 必须是正整数。' ;;
    err_install_dir) printf '安装目录必须是绝对路径，例如 /opt/chatgpt-2api。' ;;
    err_branch) printf '安装分支固定为 main。' ;;
    err_database_url) printf '安装不需要填写 PostgreSQL 地址，会在本机创建数据库。' ;;
    err_database_name) printf '数据库名必须是 chatgpt_2api_app。' ;;
    err_postgres_password) printf 'POSTGRES_PASSWORD 只能包含字母、数字、下划线和连字符。' ;;
    err_dotenv) printf '写入 .env 的值不能包含换行。' ;;
    err_not_git) printf '已存在，但不是 Git 仓库。' ;;
    err_compose) printf '未找到 docker compose 插件，请先安装 Docker Compose v2。' ;;
    info_update) printf '正在更新' ;;
    info_clone) printf '正在克隆' ;;
    info_start_docker) printf '正在启动 Docker 服务...' ;;
    done_ready) printf 'ChatGPT2API 已就绪' ;;
    done_base_url) printf '图片访问地址' ;;
    done_auth) printf '管理员登录密钥' ;;
    done_auth_saved) printf '已写入 .env 和 config.json' ;;
    *) printf '%s' "${key}" ;;
  esac
}

prompt_input() {
  local label="$1"
  local default="${2-}"
  local echo_choice="${3:-1}"
  local answer=""

  if [[ -n "${default}" ]]; then
    ui_print "${label} [${default}]: "
  else
    ui_print "${label}: "
  fi

  IFS= read -r answer <"${UI_DEV}" || true
  if [[ -z "${answer}" ]]; then
    answer="${default}"
  fi
  if [[ "${echo_choice}" == "1" ]]; then
    echo_selected "${answer}"
  fi
  printf '%s' "${answer}"
}

prompt_secret_confirmed() {
  local first=""
  local second=""

  while true; do
    ui_print "$(text prompt_auth): "
    IFS= read -r -s first <"${UI_DEV}" || true
    ui_println ""
    if [[ -z "${first//[[:space:]]/}" ]]; then
      ui_println "[$(text prefix_error)] $(text err_auth_empty)"
      continue
    fi
    ui_print "$(text prompt_auth_again): "
    IFS= read -r -s second <"${UI_DEV}" || true
    ui_println ""
    if [[ "${first}" != "${second}" ]]; then
      ui_println "[$(text prefix_error)] $(text err_auth_mismatch)"
      continue
    fi
    ui_println "$(text secret_saved)"
    printf '%s' "${first}"
    return
  done
}

confirm_start() {
  local answer=""
  ui_print "$(text confirm_install) [Y]: "
  IFS= read -r answer <"${UI_DEV}" || true
  if [[ -z "${answer}" || "${answer}" =~ ^([Yy]|yes|YES)$ ]]; then
    echo_selected "$(text confirm_yes)"
    return 0
  fi
  ui_println "$(text confirm_no)"
  return 1
}

language_label() {
  if is_en; then
    text label_lang_en
  else
    text label_lang_zh
  fi
}

choose_language() {
  if [[ -n "${INSTALL_LANG}" ]]; then
    normalize_language
    echo_selected "$(language_label)"
    return
  fi

  local answer=""
  print_step "1" "$(text step_language)" "$(text hint_language)"
  ui_println "  1) 中文（默认）"
  ui_println "  2) English"
  answer="$(prompt_input "请选择 / Select" "1" "0")"
  case "${answer}" in
    2|en|EN|english|English) INSTALL_LANG="en" ;;
    *) INSTALL_LANG="zh" ;;
  esac
  normalize_language
  echo_selected "$(language_label)"
}

base_url_label() {
  if [[ -n "${BASE_URL}" ]]; then
    printf '%s' "${BASE_URL}"
  else
    text summary_base_url_empty
  fi
}

read_existing_env_value() {
  local key="$1"
  local env_file="${INSTALL_DIR}/.env"
  local value=""
  [[ -f "${env_file}" ]] || return 0
  value="$(sed -n "s/^${key}=//p" "${env_file}" | tail -n 1)"
  if [[ "${value}" == \"*\" && "${value}" == *\" ]]; then
    value="${value:1:${#value}-2}"
    value="${value//\\\"/\"}"
    value="${value//\\\\/\\}"
    value="${value//\$\$/\$}"
  fi
  printf '%s' "${value}"
}

configure_database() {
  local existing_user=""
  local requested_db="${POSTGRES_DB_INPUT:-}"
  DATABASE_MODE="postgres-local"
  DATABASE_URL=""
  ui_println ""
  ui_println "$(text info_mode)"
  echo_selected "$(text label_mode_docker)"
  ui_println "$(text info_database)"
  echo_selected "$(text label_database)"

  if [[ -n "${requested_db}" && "${requested_db}" != "chatgpt_2api_app" ]]; then
    echo "[$(text prefix_error)] $(text err_database_name)" >&2
    exit 1
  fi
  POSTGRES_DB="chatgpt_2api_app"
  existing_user="$(read_existing_env_value POSTGRES_USER)"
  if [[ -z "${POSTGRES_USER_EXPLICIT:-}" && -n "${existing_user}" ]]; then
    POSTGRES_USER="${existing_user}"
  fi
  if [[ -z "${POSTGRES_PASSWORD}" ]]; then
    POSTGRES_PASSWORD="$(read_existing_env_value POSTGRES_PASSWORD)"
  fi
  if [[ -z "${POSTGRES_PASSWORD}" ]]; then
    POSTGRES_PASSWORD="$(generate_secret)"
  fi
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[$(text prefix_error)] $(text err_missing_cmd): $1" >&2
    exit 1
  fi
}

generate_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
    return
  fi
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    tr -d '-' </proc/sys/kernel/random/uuid
    return
  fi
  date +%s%N
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        usage
        exit 0
        ;;
      --mode)
        MODE="${2:-}"
        shift 2
        ;;
      --port)
        PORT="${2:-}"
        shift 2
        ;;
      --base-url)
        BASE_URL="${2:-}"
        BASE_URL_EXPLICIT=1
        shift 2
        ;;
      --thread-tokens)
        THREAD_TOKENS="${2:-}"
        shift 2
        ;;
      --install-dir)
        INSTALL_DIR="${2:-}"
        shift 2
        ;;
      --branch)
        BRANCH="${2:-}"
        shift 2
        ;;
      --auth-key)
        AUTH_KEY="${2:-}"
        shift 2
        ;;
      --database-url)
        echo "[$(text prefix_error)] $(text err_database_url)" >&2
        exit 1
        ;;
      --database)
        DATABASE_MODE="${2:-}"
        shift 2
        ;;
      --postgres-password)
        POSTGRES_PASSWORD="${2:-}"
        shift 2
        ;;
      --repo-owner)
        REPO_OWNER="${2:-}"
        shift 2
        ;;
      --repo-name)
        REPO_NAME="${2:-}"
        shift 2
        ;;
      *)
        echo "[$(text prefix_error)] $(text err_unknown_arg): $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done
}

normalize_base_url() {
  local value="${1-}"
  local rest=""
  local hostpart=""
  local portpart=""

  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  while [[ "${value}" == */ ]]; do
    value="${value%/}"
  done
  if [[ -z "${value}" ]]; then
    printf ''
    return 0
  fi
  if [[ "${value}" == *[[:space:]]* || "${value}" == *\?* || "${value}" == *\#* || "${value}" == *\\* ]]; then
    return 1
  fi
  if [[ "${value}" =~ ^[Hh][Tt][Tt][Pp][Ss]:// ]]; then
    rest="${value#*://}"
    value="https://${rest}"
  elif [[ "${value}" =~ ^[Hh][Tt][Tt][Pp]:// ]]; then
    rest="${value#*://}"
    value="http://${rest}"
  elif [[ "${value}" == *://* ]]; then
    return 1
  else
    value="https://${value}"
  fi
  if [[ ! "${value}" =~ ^https?://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?(/[A-Za-z0-9._~%/+:@-]+)?$ ]]; then
    return 1
  fi
  hostpart="${value#*://}"
  hostpart="${hostpart%%/*}"
  if [[ "${hostpart}" == *@* || "${hostpart}" == .* || "${hostpart}" == *..* || "${hostpart}" == *.-* || "${hostpart}" == -* ]]; then
    return 1
  fi
  if [[ "${hostpart}" == *:* ]]; then
    portpart="${hostpart##*:}"
    if [[ "${portpart}" -lt 1 || "${portpart}" -gt 65535 ]]; then
      return 1
    fi
  fi
  printf '%s' "${value}"
}

is_valid_port() {
  local value="${1-}"
  [[ "${value}" =~ ^[0-9]+$ ]] || return 1
  [[ "${value}" -ge 1 && "${value}" -le 65535 ]]
}

is_valid_install_dir() {
  local value="${1-}"
  [[ -n "${value}" && "${value}" == /* && "${value}" != *"//"* && "${value}" != *[[:space:]]* ]]
}

validate_inputs() {
  local normalized=""

  if [[ "${MODE}" != "docker" || "${DATABASE_MODE}" != "postgres-local" ]]; then
    echo "[$(text prefix_error)] $(text err_mode)" >&2
    exit 1
  fi
  if [[ "${BRANCH}" != "main" ]]; then
    echo "[$(text prefix_error)] $(text err_branch)" >&2
    exit 1
  fi
  if ! is_valid_port "${PORT}"; then
    echo "[$(text prefix_error)] $(text err_port)" >&2
    exit 1
  fi
  if ! is_valid_install_dir "${INSTALL_DIR}"; then
    echo "[$(text prefix_error)] $(text err_install_dir)" >&2
    exit 1
  fi
  if ! normalized="$(normalize_base_url "${BASE_URL}")"; then
    echo "[$(text prefix_error)] $(text err_base_url)" >&2
    exit 1
  fi
  BASE_URL="${normalized}"
  if [[ -z "${THREAD_TOKENS}" || ! "${THREAD_TOKENS}" =~ ^[0-9]+$ || "${THREAD_TOKENS}" -lt 1 ]]; then
    echo "[$(text prefix_error)] $(text err_thread_tokens)" >&2
    exit 1
  fi
  if [[ -z "${AUTH_KEY//[[:space:]]/}" ]]; then
    echo "[$(text prefix_error)] $(text err_auth_empty)" >&2
    exit 1
  fi
  if [[ ! "${POSTGRES_PASSWORD}" =~ ^[A-Za-z0-9_-]+$ ]]; then
    echo "[$(text prefix_error)] $(text err_postgres_password)" >&2
    exit 1
  fi
}

print_summary() {
  ui_println ""
  ui_println "$(text summary_title)"
  ui_println "  $(text summary_language): $(language_label)"
  ui_println "  $(text summary_mode): $(text label_mode_docker)"
  ui_println "  $(text summary_port): ${PORT}"
  ui_println "  $(text summary_base_url): $(base_url_label)"
  ui_println "  $(text summary_dir): ${INSTALL_DIR}"
  ui_println "  $(text summary_database): $(text label_database)"
  ui_println "  $(text summary_git): $(text label_branch)"
  ui_println "  $(text summary_auth): $(text summary_auth_set)"
  ui_println ""
}

repo_url() {
  printf 'https://github.com/%s/%s.git' "${REPO_OWNER}" "${REPO_NAME}"
}

default_image() {
  if [[ -n "${CHATGPT2API_IMAGE}" ]]; then
    printf '%s' "${CHATGPT2API_IMAGE}"
    return
  fi
  printf 'ghcr.io/%s/%s:latest' "${REPO_OWNER}" "${REPO_NAME}"
}

raw_url() {
  printf 'https://raw.githubusercontent.com/%s/%s/%s/%s' "${REPO_OWNER}" "${REPO_NAME}" "${BRANCH}" "$1"
}

download_file() {
  local source_path="$1"
  local target_path="${INSTALL_DIR}/${source_path}"

  mkdir -p "$(dirname "${target_path}")"
  curl -fsSL "$(raw_url "${source_path}")" -o "${target_path}"
}

json_escape() {
  local value="${1-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "${value}"
}

dotenv_quote() {
  local value="${1-}"
  if [[ "${value}" == *$'\n'* || "${value}" == *$'\r'* ]]; then
    echo "[$(text prefix_error)] $(text err_dotenv)" >&2
    return 1
  fi
  value="${value//\\/\\\\}"
  value="${value//\$/\$\$}"
  value="${value//\"/\\\"}"
  printf '"%s"' "${value}"
}

write_default_config_json() {
  local config_file="${INSTALL_DIR}/config.json"
  local tmp_file="${config_file}.tmp"

  if [[ -f "${config_file}" ]]; then
    return
  fi
  if [[ -e "${config_file}" ]]; then
    echo "[$(text prefix_error)] ${config_file} exists but is not a regular file." >&2
    exit 1
  fi

  cat >"${tmp_file}" <<EOF
{
  "auth-key": "$(json_escape "${AUTH_KEY}")"
}
EOF

  mv "${tmp_file}" "${config_file}"
  chmod 600 "${config_file}" || true
}

prepare_docker_bundle() {
  need_cmd curl

  mkdir -p "${INSTALL_DIR}"
  download_file "docker-compose.yml"
  download_file "docker-compose.postgres.yml"
}

write_env_file() {
  local env_file="${INSTALL_DIR}/.env"
  local tmp_file="${env_file}.tmp"

  cat >"${tmp_file}" <<EOF
CHATGPT2API_AUTH_KEY=$(dotenv_quote "${AUTH_KEY}")
CHATGPT2API_PORT=$(dotenv_quote "${PORT}")
CHATGPT2API_THREAD_TOKENS=$(dotenv_quote "${THREAD_TOKENS}")
CHATGPT2API_IMAGE=$(dotenv_quote "$(default_image)")
CHATGPT2API_BASE_URL=$(dotenv_quote "${BASE_URL}")

DATABASE_MODE=$(dotenv_quote "${DATABASE_MODE}")
# 本地 PostgreSQL 由安装脚本创建，不要填写数据库地址。
DATABASE_URL=
POSTGRES_DB=$(dotenv_quote "${POSTGRES_DB}")
POSTGRES_USER=$(dotenv_quote "${POSTGRES_USER}")
POSTGRES_PASSWORD=$(dotenv_quote "${POSTGRES_PASSWORD}")
TZ=$(dotenv_quote "Asia/Shanghai")
COMPOSE_PROJECT_NAME=$(dotenv_quote "chatgpt-2api")
EOF

  mv "${tmp_file}" "${env_file}"
  chmod 600 "${env_file}" || true
}

export_compose_env() {
  # Compose 优先使用当前 shell 环境变量，不会用刚写入 .env 的新值覆盖旧值。
  export CHATGPT2API_AUTH_KEY="${AUTH_KEY}"
  export CHATGPT2API_PORT="${PORT}"
  export CHATGPT2API_THREAD_TOKENS="${THREAD_TOKENS}"
  export CHATGPT2API_IMAGE="$(default_image)"
  export CHATGPT2API_BASE_URL="${BASE_URL}"
  export POSTGRES_DB="${POSTGRES_DB}"
  export POSTGRES_USER="${POSTGRES_USER}"
  export POSTGRES_PASSWORD="${POSTGRES_PASSWORD}"
}

run_docker() {
  need_cmd docker
  if ! docker compose version >/dev/null 2>&1; then
    echo "[$(text prefix_error)] $(text err_compose)" >&2
    exit 1
  fi

  local compose_args=(-p chatgpt-2api -f docker-compose.yml -f docker-compose.postgres.yml)

  export_compose_env
  ui_println "[$(text prefix_info)] $(text info_start_docker)"
  (
    cd "${INSTALL_DIR}"
    docker compose "${compose_args[@]}" pull
    docker compose "${compose_args[@]}" up -d
  )
}

mask_secret() {
  local value="${1-}"
  if [[ ${#value} -le 8 ]]; then
    printf '****'
  else
    printf '%s****%s' "${value:0:4}" "${value: -4}"
  fi
}

print_ready() {
  ui_println ""
  ui_println "[$(text prefix_done)] $(text done_ready): http://localhost:${PORT}"
  ui_println "[$(text prefix_done)] $(text done_base_url): $(base_url_label)"
  ui_println "[$(text prefix_done)] $(text done_auth): $(mask_secret "${AUTH_KEY}") ($(text done_auth_saved))"
  ui_println "[$(text prefix_done)] $(text summary_dir): ${INSTALL_DIR}"
  ui_println "[$(text prefix_done)] 应用容器: chatgpt-2api-app"
  ui_println "[$(text prefix_done)] 数据库容器: chatgpt-2api-postgres"
  ui_println "[$(text prefix_done)] 隔离网络: chatgpt-2api-net"
  ui_println "[$(text prefix_done)] 时区: Asia/Shanghai"
}

main() {
  parse_args "$@"
  if [[ "${MODE}" != "docker" || "${DATABASE_MODE}" != "postgres-local" ]]; then
    echo "[$(text prefix_error)] $(text err_mode)" >&2
    exit 1
  fi
  if [[ "${BRANCH}" != "main" ]]; then
    echo "[$(text prefix_error)] $(text err_branch)" >&2
    exit 1
  fi
  MODE="docker"
  DATABASE_MODE="postgres-local"
  print_banner
  choose_language

  print_step "2" "$(text step_port)" "$(text hint_port)"
  while true; do
    PORT="$(prompt_input "$(text prompt_port)" "${PORT}" "0")"
    if is_valid_port "${PORT}"; then
      echo_selected "${PORT}"
      break
    fi
    ui_println "[$(text prefix_error)] $(text err_port)"
  done

  print_step "3" "$(text step_dir)" "$(text hint_dir)"
  while true; do
    INSTALL_DIR="$(prompt_input "$(text prompt_dir)" "${INSTALL_DIR}" "0")"
    while [[ "${INSTALL_DIR}" == */ ]]; do
      INSTALL_DIR="${INSTALL_DIR%/}"
    done
    if is_valid_install_dir "${INSTALL_DIR}"; then
      echo_selected "${INSTALL_DIR}"
      break
    fi
    ui_println "[$(text prefix_error)] $(text err_install_dir)"
  done
  configure_database
  if [[ "${BASE_URL_EXPLICIT}" != "1" ]]; then
    local existing_base=""
    existing_base="$(read_existing_env_value CHATGPT2API_BASE_URL)"
    if [[ -n "${existing_base}" ]]; then
      BASE_URL="${existing_base}"
    fi
  fi

  print_step "4" "$(text step_base_url)" "$(text hint_base_url)"
  while true; do
    local entered_base=""
    entered_base="$(prompt_input "$(text prompt_base_url)" "${BASE_URL}" "0")"
    if BASE_URL="$(normalize_base_url "${entered_base}")"; then
      echo_selected "$(base_url_label)"
      break
    fi
    ui_println "[$(text prefix_error)] $(text err_base_url)"
  done

  print_step "5" "$(text step_auth)" "$(text hint_auth)"
  if [[ -z "${AUTH_KEY}" || "${AUTH_KEY}" == "your_secret_key_here" ]]; then
    AUTH_KEY="$(prompt_secret_confirmed)"
  else
    echo_selected "$(text summary_auth_set)"
  fi

  validate_inputs
  print_summary
  if ! confirm_start; then
    exit 0
  fi
  prepare_docker_bundle
  write_default_config_json
  write_env_file
  run_docker
  print_ready
}

if [[ -z "${BASH_SOURCE[0]:-}" || "${BASH_SOURCE[0]:-}" == "$0" ]]; then
  main "$@"
fi
