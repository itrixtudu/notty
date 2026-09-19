#!/usr/bin/env bash
set -euo pipefail
REPO=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
case "${1:---help}" in
  --deterministic)
    if [[ -f /.dockerenv ]]; then
      exec node --test "$REPO/tests/nosh-policy-capacity.test.cjs"
    fi
    image=${NOSH_POLICY_TOOLING_IMAGE:-}
    [[ "$image" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo 'Set NOSH_POLICY_TOOLING_IMAGE to the exact local tooling image ID.' >&2; exit 1; }
    exec docker run --rm --pull never --network none --read-only --cap-drop ALL \
      --security-opt no-new-privileges:true --user "$(id -u):$(id -g)" \
      --mount "type=bind,src=$REPO,dst=/app,readonly" --entrypoint node "$image" \
      --test /app/tests/nosh-policy-capacity.test.cjs ;;
  --live)
    shift
    exec env NOSH_EGRESS_POC_RULE_COUNT=16384 bash "$REPO/scripts/nosh-egress-poc.sh" --run "$@" ;;
  *)
    cat <<'HELP'
Usage: scripts/nosh-egress-capacity.sh --deterministic | --live [POC options]

--deterministic checks compiler and renderer at N-1, N, and N+1, port
expansion, and the shared exact/wildcard DNS slot limit. Runs in a container.
--live runs the isolated real-socket proof with 16,384 IPv4 rules per policy.
Use the same root/Docker/image setup as scripts/nosh-egress-poc.sh --run.
Evidence records capacityRuleCount. Existing POC defaults stay at one rule.
This is an IPv4 kernel/socket capacity check; it does not measure IPv6 or
DNS map capacity on the kernel, browser responsiveness, or throughput.
HELP
    ;;
esac
