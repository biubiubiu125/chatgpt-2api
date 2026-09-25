#!/bin/sh
set -eu

db_url="${DATABASE_URL:-}"
case "${db_url}" in
  postgresql://*|postgres://*)
    ;;
  *)
    echo "chatgpt-2api requires a PostgreSQL DATABASE_URL. An empty value must not fall back to SQLite." >&2
    exit 1
    ;;
esac

seed_root=/opt/chatgpt-2api
runtime_root=/app
marker_name=.chatgpt-2api-image-version
seed_version="$(tr -d '\r\n' < "${seed_root}/VERSION")"
installed_image_version=""

if [ -f "${runtime_root}/${marker_name}" ]; then
  installed_image_version="$(tr -d '\r\n' < "${runtime_root}/${marker_name}")"
fi

if [ ! -f "${runtime_root}/VERSION" ] || [ "${installed_image_version}" != "${seed_version}" ]; then
  mkdir -p "${runtime_root}"
  find "${runtime_root}" -mindepth 1 -maxdepth 1 \
    ! -name data \
    ! -name config.json \
    ! -name .venv \
    ! -name "${marker_name}" \
    -exec rm -rf -- {} +

  for source in "${seed_root}"/* "${seed_root}"/.[!.]* "${seed_root}"/..?*; do
    [ -e "${source}" ] || continue
    [ "$(basename "${source}")" = ".venv" ] && continue
    cp -a "${source}" "${runtime_root}/"
  done

  marker_tmp="${runtime_root}/${marker_name}.tmp"
  printf '%s\n' "${seed_version}" > "${marker_tmp}"
  mv "${marker_tmp}" "${runtime_root}/${marker_name}"
fi

cd "${runtime_root}"
uv sync --frozen --no-dev --no-install-project
exec "$@"
