#!/usr/bin/env bash
set -euo pipefail

extract_one() {
  local label="$1"
  local file="$2"
  local expression="$3"
  local matches=()
  mapfile -t matches < <(sed -nE "$expression" "$file")
  if [[ "${#matches[@]}" -ne 1 || -z "${matches[0]}" ]]; then
    printf 'expected one %s in %s, found %d\n' "$label" "$file" "${#matches[@]}" >&2
    return 1
  fi
  printf '%s\n' "${matches[0]}"
}

assert_same() {
  local label="$1"
  shift
  local expected="$1"
  shift
  local value
  for value in "$@"; do
    if [[ "$value" != "$expected" ]]; then
      printf '%s versions are out of sync: %s != %s\n' "$label" "$expected" "$value" >&2
      return 1
    fi
  done
}

go_workspace="$(extract_one 'Go version' go.work 's/^go ([0-9.]+)$/\1/p')"
go_agent_module="$(extract_one 'Go version' agent/go.mod 's/^go ([0-9.]+)$/\1/p')"
go_hub_module="$(extract_one 'Go version' hub/go.mod 's/^go ([0-9.]+)$/\1/p')"
go_agent_image="$(extract_one 'Go image version' docker/examples/agent.Dockerfile 's/^FROM .*golang:([0-9.]+)-.*$/\1/p')"
go_hub_image="$(extract_one 'Go image version' docker/examples/hub.Dockerfile 's/^FROM .*golang:([0-9.]+)-.*$/\1/p')"
assert_same Go "$go_workspace" "$go_agent_module" "$go_hub_module" "$go_agent_image" "$go_hub_image"

node_engine="$(extract_one 'Node engine version' dashboard/package.json 's/^[[:space:]]*"node": ">=([0-9.]+) <.*$/\1/p')"
node_ci="$(extract_one 'Node CI version' .github/workflows/ci.yml 's/^[[:space:]]*node-version: ([0-9.]+)$/\1/p')"
node_image="$(extract_one 'Node image version' docker/examples/hub.Dockerfile 's/^FROM .*node:([0-9.]+)-.*$/\1/p')"
assert_same Node "$node_engine" "$node_ci" "$node_image"

npm_package_manager="$(extract_one 'npm package manager version' dashboard/package.json 's/^[[:space:]]*"packageManager": "npm@([0-9.]+)",$/\1/p')"
npm_engine="$(extract_one 'npm engine version' dashboard/package.json 's/^[[:space:]]*"npm": ">=([0-9.]+) <.*$/\1/p')"
npm_ci="$(extract_one 'npm CI version' .github/workflows/ci.yml 's/^[[:space:]]*NPM_VERSION: ([0-9.]+)$/\1/p')"
npm_image="$(extract_one 'npm image version' docker/examples/hub.Dockerfile 's/^ARG NPM_VERSION=([0-9.]+)$/\1/p')"
assert_same npm "$npm_package_manager" "$npm_engine" "$npm_ci" "$npm_image"

dockerfile_frontend_agent="$(extract_one 'Dockerfile frontend' docker/examples/agent.Dockerfile 's/^# syntax=(.*)$/\1/p')"
dockerfile_frontend_hub="$(extract_one 'Dockerfile frontend' docker/examples/hub.Dockerfile 's/^# syntax=(.*)$/\1/p')"
assert_same 'Dockerfile frontend' "$dockerfile_frontend_agent" "$dockerfile_frontend_hub"

extract_service_images() {
  sed -nE 's/^[[:space:]]*image:[[:space:]]*((pgvector\/pgvector|redis):[^[:space:]]+)$/\1/p' "$1" | sort
}

ci_images="$(extract_service_images .github/workflows/ci.yml)"
service_images="$(extract_service_images docker/services/compose.yaml)"
example_images="$(extract_service_images docker/examples/hub.compose.yaml)"
assert_same 'service image' "$ci_images" "$service_images" "$example_images"
