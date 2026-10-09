const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const componentDir = path.resolve(__dirname, '..');
const appRoot = path.resolve(componentDir, '..', '..');
const source = fs.readFileSync(
  path.join(componentDir, 'nosh_build.bpf.c'),
  'utf8',
);
const header = fs.readFileSync(
  path.join(componentDir, 'include', 'nosh_build.h'),
  'utf8',
);
const loader = fs.readFileSync(
  path.join(componentDir, 'loader', 'nosh_build_loader.c'),
  'utf8',
);

function readJson(relative) {
  return JSON.parse(fs.readFileSync(path.join(componentDir, relative), 'utf8'));
}

function collectPropertyNames(value, names = []) {
  if (Array.isArray(value)) {
    for (const item of value)
      collectPropertyNames(item, names);
    return names;
  }
  if (!value || typeof value !== 'object')
    return names;
  if (value.properties)
    names.push(...Object.keys(value.properties));
  for (const child of Object.values(value))
    collectPropertyNames(child, names);
  return names;
}

test('balanced BPF ABI is versioned and uses bounded maps', () => {
  assert.match(header, /#define NOSH_BUILD_SCHEMA_VERSION 2\b/);
  assert.match(header, /NOSH_BUILD_EVENT_PROCESS_EXEC = 1/);
  assert.match(header, /NOSH_BUILD_EVENT_PROCESS_EXIT = 2/);
  assert.match(header, /NOSH_BUILD_EVENT_DNS_QUERY = 3/);
  assert.match(header, /NOSH_BUILD_EVENT_DNS_RESPONSE = 4/);
  assert.match(header, /#define NOSH_BUILD_DNS_MAX_ANSWERS 16\b/);
  assert.match(header, /#define NOSH_BUILD_DNS_MAX_VISITED_ANSWERS 16\b/);
  assert.match(loader, /#define NOSH_BUILD_LOADER_VERSION "5"/);
  assert.match(loader, /sizeof\(struct nosh_build_dns_wire_event\) <= UINT16_MAX/);
  assert.match(source, /__uint\(type, BPF_MAP_TYPE_RINGBUF\)/);
  assert.match(source, /} events SEC\("\.maps"\);/);
  assert.match(source, /__uint\(type, BPF_MAP_TYPE_PERCPU_HASH\)/);
  assert.match(source, /} syscall_totals SEC\("\.maps"\);/);
  assert.equal(
    [...source.matchAll(/__uint\(type, BPF_MAP_TYPE_HASH\)/g)].length,
    2,
  );
  assert.match(source, /} inflight_syscalls SEC\("\.maps"\);/);
  assert.match(source, /} file_totals SEC\("\.maps"\);/);
  assert.match(header, /#define NOSH_BUILD_FILE_MAX_ENTRIES 32768\b/);
  assert.match(source, /__uint\(type, BPF_MAP_TYPE_PERCPU_ARRAY\)/);
  assert.match(source, /} stats SEC\("\.maps"\);/);
  assert.match(source, /} session_config SEC\("\.maps"\);/);
});

test('process depth loads only successful exec observation and records no argv', () => {
  assert.match(loader, /bool process_depth;/);
  assert.match(loader, /!strcmp\(options->depth, "process"\)/);
  assert.ok(loader.includes('\\"availableSources\\":[\\"process-exec\\"]'));
  for (const program of [
    'nosh_build_process_exit',
    'nosh_build_sys_enter',
    'nosh_build_sys_exit',
    'nosh_build_dns_egress',
    'nosh_build_dns_ingress',
  ]) {
    assert.match(
      loader,
      new RegExp(`skeleton->progs\\.${program}, false`),
    );
  }
  assert.ok(!loader.includes('\\"argv\\"'));
  assert.ok(!loader.includes('\\"arguments\\"'));
  assert.match(loader, /if \(!context\.process_depth\) \{/);
  assert.match(loader, /final process-observer stats emitted/);
});

test('global tracepoints fail closed through the kernel cgroup descendant filter', () => {
  for (const section of [
    'tracepoint/sched/sched_process_exec',
    'tracepoint/sched/sched_process_exit',
    'tracepoint/raw_syscalls/sys_enter',
    'tracepoint/raw_syscalls/sys_exit',
  ]) {
    assert.ok(source.includes(`SEC("${section}")`), `missing ${section}`);
  }
  assert.match(source, /__uint\(type, BPF_MAP_TYPE_CGROUP_ARRAY\)/);
  assert.match(source, /} target_cgroup SEC\("\.maps"\);/);
  assert.match(source, /bpf_current_task_under_cgroup\(&target_cgroup, 0\)/);
  assert.match(source, /NOSH_BUILD_STAT_CGROUP_FILTER_ERRORS/);

  const matcher = source.match(
    /static __always_inline bool current_is_target_descendant[\s\S]*?\n\}/,
  );
  assert.ok(matcher);
  assert.match(matcher[0], /return result == 1;/);
  assert.match(matcher[0], /return false;/);
});

test('syscalls retain counts, completion errors, and durations', () => {
  assert.match(header, /struct nosh_build_syscall_key \{\s*__s64 syscall_number;/);
  assert.match(header, /struct nosh_build_inflight_syscall \{[\s\S]*__s64 syscall_number;/);
  assert.match(header, /__u64 calls;/);
  assert.match(header, /__u64 completions;/);
  assert.match(header, /__u64 errors;/);
  assert.match(header, /__u64 total_duration_ns;/);
  assert.match(header, /__u64 max_duration_ns;/);
  assert.match(source, /totals->calls \+= 1/);
  assert.match(source, /totals->completions \+= 1/);
  assert.match(source, /ctx->ret < 0 && ctx->ret >= -4095/);
  assert.match(source, /totals->errors \+= 1/);
  assert.match(source, /bpf_ktime_get_ns\(\) - inflight->started_ns/);
  assert.match(source, /if \(duration > totals->max_duration_ns\)/);
  assert.match(loader, /read_syscall_totals\(/);
  assert.match(
    loader,
    /if \(slot->max_duration_ns > totals->max_duration_ns\)/,
  );
  assert.match(loader, /saturating_add_u64\(/);
  assert.match(source, /bpf_map_delete_elem\(&inflight_syscalls/);
  assert.ok(loader.includes('\"syscallNumber\\\":%\" PRId64'));
});

test('UDP DNS query and response collection is correlated, bounded, and allow-only', () => {
  assert.match(header, /#define NOSH_BUILD_ALLOW 1\b/);
  assert.match(source, /SEC\("cgroup_skb\/egress"\)/);
  assert.match(source, /SEC\("cgroup_skb\/ingress"\)/);
  const egressStart = source.indexOf('int nosh_build_dns_egress');
  const ingressStart = source.indexOf('int nosh_build_dns_ingress');
  const licenseStart = source.indexOf('char LICENSE[]');
  const egressHook = source.slice(egressStart, ingressStart);
  const ingressHook = source.slice(ingressStart, licenseStart);
  assert.ok(egressStart >= 0 && ingressStart > egressStart);
  for (const hook of [egressHook, ingressHook]) {
    assert.match(hook, /return NOSH_BUILD_ALLOW;/);
    assert.doesNotMatch(hook, /return\s+0\s*;/);
    assert.doesNotMatch(hook, /read_process_identity/);
    assert.doesNotMatch(hook, /bpf_get_current_pid_tgid/);
  }
  assert.match(egressHook, /capture_dns_wire\(skb, &packet, false, target_id\)/);
  assert.match(ingressHook, /capture_dns_wire\(skb, &packet, true, target_id\)/);
  const clearMatcher = source.match(
    /static __always_inline void clear_dns_wire_event[\s\S]*?\n\}/,
  );
  assert.ok(clearMatcher);
  assert.match(
    clearMatcher[0],
    /volatile __u64 \*words = \(volatile __u64 \*\)event;/,
  );
  assert.match(clearMatcher[0], /DNS wire event must be word aligned/);
  assert.match(
    clearMatcher[0],
    /#pragma clang loop unroll\(disable\)[\s\S]*?words\[index\] = 0;/,
  );
  assert.match(source, /#define NOSH_BUILD_DNS_PORT 53\b/);
  assert.match(header, /#define NOSH_BUILD_DNS_WIRE_LEN 1232\b/);
  assert.match(header, /struct nosh_build_dns_wire_event/);
  const capture = source.slice(
    source.indexOf('static __always_inline int capture_dns_wire'),
    source.indexOf('SEC("cgroup_skb/egress")'),
  );
  assert.ok(capture.length > 0);
  assert.match(capture, /copy_dns_wire\(skb, packet, event, wire_length\)/);
  const copy = source.slice(
    source.indexOf('static __always_inline int copy_dns_wire'),
    source.indexOf('static __always_inline int capture_dns_wire'),
  );
  assert.equal([...copy.matchAll(/load_dns_bytes\(/g)].length, 2);
  assert.match(source, /#define NOSH_BUILD_DNS_COPY_CHUNK_LEN 32\b/);
  assert.match(copy, /NOSH_BUILD_DNS_COPY_CHUNK_LEN/);
  assert.match(copy, /event->wire \+ offset \+ tail, 1/);
  assert.match(capture, /bpf_get_socket_cookie\(skb\)/);
  const kernelDns = source.slice(
    source.indexOf('static __always_inline int load_network_bytes'),
    source.indexOf('SEC("cgroup_skb/egress")'),
  );
  const kernelDnsCode = kernelDns.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, '');
  assert.doesNotMatch(kernelDnsCode, /parse_dns_(?:question|response|name)/);
  assert.doesNotMatch(
    kernelDnsCode,
    /qname|cname|owner_name|answers?_visited|compression|pointer|ttl/i,
  );
  assert.doesNotMatch(
    source,
    /NOSH_BUILD_DNS_(?:MAX_LABELS|MAX_ANSWERS|MAX_VISITED_ANSWERS)/,
  );
  assert.equal([...kernelDnsCode.matchAll(/\bfor\s*\(/g)].length, 3);
  assert.equal([...kernelDnsCode.matchAll(/\bwhile\s*\(/g)].length, 0);
  assert.match(loader, /static int decode_dns_name/);
  assert.match(loader, /static int decode_dns_common/);
  assert.match(loader, /static int decode_and_emit_dns_response/);
  assert.match(loader, /NOSH_BUILD_DNS_MAX_POINTERS/);
  assert.match(loader, /NOSH_BUILD_DNS_MAX_VISITED_ANSWERS/);
  assert.match(source, /NOSH_BUILD_STAT_DNS_TRUNCATED_NAMES/);
  assert.match(source, /NOSH_BUILD_STAT_DNS_TRUNCATED_RESPONSES/);
  assert.match(source, /NOSH_BUILD_STAT_DNS_CORRELATION_MISSING/);
  assert.match(source, /udp_dns_candidate\(skb, false/);
  assert.match(source, /udp_dns_candidate\(skb, true/);
  assert.match(source, /bpf_skb_load_bytes_relative\(/);
  assert.doesNotMatch(source, /bpf_skb_store_bytes|bpf_clone_redirect/);
  assert.doesNotMatch(header, /\bpayload\b/i);
  assert.doesNotMatch(loader, /write_json_string\([^\n]*wire/);
  assert.match(loader, /\\"keyVersion\\":1/);
  assert.match(loader, /\\"id\\":\\"udp53:/);
  assert.match(loader, /\\"kind\\":\\"cname\\"/);
  assert.match(loader, /\\"kind\\":\\"ipv4\\"/);
  assert.match(loader, /\\"kind\\":\\"ipv6\\"/);
});

test('normalized schemas expose loss and contain no packet or command payload', () => {
  const eventSchema = readJson('schema/nosh-build-event.schema.json');
  const statsSchema = readJson('schema/nosh-build-stats.schema.json');
  const syscallSchema = readJson(
    'schema/nosh-build-syscall-summary.schema.json',
  );
  const capabilitiesSchema = readJson(
    'schema/nosh-build-capabilities.schema.json',
  );
  const controlSchema = readJson('schema/nosh-build-control.schema.json');
  const fileSchema = readJson('schema/nosh-build-file-summary.schema.json');

  assert.equal(eventSchema.properties.schemaVersion.const, 2);
  assert.equal(eventSchema.properties.metadataOnly.const, true);
  assert.deepEqual(
    new Set(eventSchema.properties.eventKind.enum),
    new Set(['process-exec', 'process-exit', 'dns-query', 'dns-response']),
  );
  assert.equal(statsSchema.properties.final.type, 'boolean');
  assert.deepEqual(
    new Set(statsSchema.properties.counters.required),
    new Set([
      'ringbufDrops',
      'syscallMapFull',
      'inflightMapFull',
      'configMissing',
      'cgroupFilterErrors',
      'dnsParseErrors',
      'dnsCompressedNames',
      'dnsTruncatedNames',
      'dnsTruncatedResponses',
      'dnsAnswerLimitReached',
      'dnsUnsupportedAnswers',
      'dnsCorrelationMissing',
      'dnsQueryObservations',
      'dnsResponseObservations',
      'dnsNamePointers',
      'fileMapFull',
      'filePathErrors',
      'fileOpenObservations',
    ]),
  );
  assert.equal(syscallSchema.properties.recordKind.const, 'syscall-summary');
  assert.ok(syscallSchema.properties.syscallNumber.minimum < 0);
  assert.ok(syscallSchema.properties.syscallNumber.maximum > 0);
  assert.deepEqual(
    capabilitiesSchema.properties.collectionDepth.enum,
    ['process', 'balanced', 'policy'],
  );
  assert.ok(
    capabilitiesSchema.properties.unavailableSources.items
      .properties.name.enum.includes('process-exit'),
  );
  assert.equal(fileSchema.properties.recordKind.const, 'file-summary');
  assert.equal(fileSchema.properties.metadataOnly.const, true);
  assert.equal(fileSchema.properties.aggregationKey.const, 'resolved-path');
  assert.ok(
    capabilitiesSchema.properties.unavailableSources.items
      .properties.name.enum.includes('encrypted-dns'),
  );
  assert.ok(
    capabilitiesSchema.properties.unavailableSources.items
      .properties.name.enum.includes('off-cpu'),
  );
  assert.ok(
    capabilitiesSchema.properties.availableSources.items.enum
      .includes('udp-dns-response'),
  );
  assert.equal(controlSchema.$defs.status.properties.deepCollectionSupported.const, false);
  assert.equal(controlSchema.$defs.status.properties.attachedPrograms.maximum, 7);

  const [execVariant, exitVariant, queryVariant, responseVariant] = eventSchema.oneOf;
  for (const variant of [execVariant, exitVariant]) {
    assert.equal(variant.properties.network, false);
    assert.equal(variant.properties.dns, false);
  }
  for (const dnsVariant of [queryVariant, responseVariant]) {
    assert.equal(dnsVariant.properties.executable, false);
    assert.equal(dnsVariant.properties.rawExitCode, false);
  }
  assert.equal(queryVariant.properties.eventKind.const, 'dns-query');
  assert.equal(responseVariant.properties.eventKind.const, 'dns-response');
  assert.equal(eventSchema.$defs.response.properties.answers.maxItems, 16);
  assert.equal(eventSchema.$defs.response.properties.answersVisited.maximum, 16);
  assert.equal(eventSchema.$defs.correlation.properties.keyVersion.const, 1);
  assert.equal(eventSchema.$defs.answer.properties.class.const, 1);
  const [ipv4Variant, ipv6Variant] = eventSchema.$defs.network.oneOf;
  assert.equal(ipv4Variant.properties.family.const, 'ipv4');
  assert.equal(
    ipv4Variant.properties.serverAddress.format,
    'ipv4',
  );
  assert.equal(ipv6Variant.properties.family.const, 'ipv6');
  assert.equal(
    ipv6Variant.properties.serverAddress.format,
    'ipv6',
  );

  const forbidden = new Set([
    'payload',
    'packetPayload',
    'body',
    'content',
    'arguments',
    'environment',
  ]);
  for (const schema of [
    eventSchema,
    statsSchema,
    syscallSchema,
    capabilitiesSchema,
    controlSchema,
    fileSchema,
  ]) {
    for (const name of collectPropertyNames(schema))
      assert.equal(forbidden.has(name), false, `forbidden schema field: ${name}`);
  }
});

test('loader validates exact cgroup identity and clean finalization', () => {
  assert.match(loader, /name_to_handle_at\(cgroup_fd, "\."/);
  assert.match(loader, /O_NOFOLLOW/);
  assert.match(loader, /CGROUP2_SUPER_MAGIC/);
  assert.match(loader, /refusing to attach to the cgroup v2 mount root/);
  assert.match(loader, /cgroup id mismatch/);
  assert.match(loader, /#define NOSH_BUILD_PROGRAM_COUNT 7\b/);
  assert.match(loader, /bpf_program__attach_cgroup\(/);
  assert.match(loader, /skeleton->progs\.nosh_build_process_exec/);
  assert.match(loader, /skeleton->progs\.nosh_build_sys_exit/);
  assert.match(loader, /skeleton->progs\.nosh_build_dns_egress/);
  assert.match(loader, /skeleton->progs\.nosh_build_dns_ingress/);
  assert.match(loader, /skeleton->progs\.nosh_build_file_open/);
  assert.match(loader, /ring_buffer__consume\(/);
  assert.match(loader, /emit_syscall_summaries\(&context\)/);
  assert.match(loader, /emit_file_summaries\(&context\)/);
  assert.match(loader, /emit_stats_json\(&context, true\)/);
  assert.match(loader, /"stopped"/);
  assert.match(loader, /SIGTERM/);
  assert.match(loader, /SIGPIPE/);
  assert.match(loader, /prctl\(PR_SET_PDEATHSIG, SIGTERM\)/);
  assert.match(loader, /getppid\(\) != expected_parent_pid/);
  assert.match(loader, /RLIMIT_FSIZE/);
  assert.match(loader, /128ULL \* 1024ULL \* 1024ULL/);
  assert.match(loader, /sigaction\(SIGXFSZ/);
  assert.match(loader, /runtime_error = EFBIG/);
  assert.match(loader, /evidence file-size limit reached; detaching/);
  assert.match(loader, /NOSH_BUILD_LIBBPF_LOG_HEAD_BYTES 512\b/);
  assert.match(loader, /NOSH_BUILD_LIBBPF_LOG_TAIL_BYTES 1408\b/);
  assert.match(loader, /fopencookie\(/);
  assert.match(loader, /libbpf diagnostic bytes omitted/);
  assert.doesNotMatch(loader, /char message\[2048\]/);

  const runLoaderIndex = loader.indexOf('static int run_loader(');
  assert.ok(runLoaderIndex >= 0);
  const fileLimitIndex = loader.indexOf(
    'if (install_evidence_file_size_limit() != 0)',
    runLoaderIndex,
  );
  const bpfOpenIndex = loader.indexOf(
    'skeleton = nosh_build_bpf__open()',
    runLoaderIndex,
  );
  assert.ok(fileLimitIndex >= 0 && fileLimitIndex < bpfOpenIndex);

  const configIndex = loader.indexOf(
    'bpf_map_update_elem(bpf_map__fd(skeleton->maps.session_config)',
  );
  const filterIndex = loader.indexOf(
    'bpf_map_update_elem(bpf_map__fd(skeleton->maps.target_cgroup)',
  );
  const attachIndex = loader.indexOf('bpf_program__attach_cgroup(');
  assert.ok(configIndex >= 0 && configIndex < filterIndex);
  assert.ok(filterIndex < attachIndex);
});

test('verifier probe loads without attaching and keeps health read-only', () => {
  assert.match(loader, /strcmp\(argv\[1\], "verify"\)/);
  assert.match(loader, /static int run_verifier_probe/);
  assert.match(loader, /nosh_build_bpf__load\(skeleton\)/);
  assert.match(
    loader,
    /kernel verifier accepted BPF object; no programs attached/,
  );
  const probe = loader.slice(
    loader.indexOf('static int run_verifier_probe'),
    loader.indexOf('static int attach_program'),
  );
  assert.ok(probe.length > 0);
  assert.doesNotMatch(probe, /bpf_program__attach|attach_cgroup/);
  assert.match(probe, /nosh_build_bpf__destroy\(skeleton\)/);

  const health = loader.slice(
    loader.indexOf('static int run_health'),
    loader.indexOf('static int emit_capabilities'),
  );
  assert.doesNotMatch(health, /nosh_build_bpf__open|nosh_build_bpf__load/);
});

test('deep mode is rejected instead of silently degrading', () => {
  assert.match(loader, /strcmp\(options->depth, "deep"\)/);
  assert.match(loader, /deep collection is unavailable/);
  assert.match(loader, /requestedDepthSupported/);
  assert.match(loader, /deepCollectionSupported/);
  assert.match(loader, /off-cpu/);
  assert.match(loader, /file-operations/);
  assert.match(loader, /block-latency/);
});

test('policy mode is capability-gated and file loss fails completion', () => {
  assert.match(source, /SEC\("lsm\.s\/file_open"\)/);
  assert.match(source, /bpf_d_path\(&file->f_path/);
  assert.match(source, /bpf_current_task_under_cgroup\(&target_cgroup, 0\)/);
  assert.match(source, /bpf_map_update_elem\(&file_totals[\s\S]*BPF_NOEXIST/);
  assert.doesNotMatch(source, /BPF_MAP_TYPE_LRU_HASH/);
  assert.match(source, /NOSH_BUILD_STAT_FILE_MAP_FULL/);
  assert.match(source, /NOSH_BUILD_STAT_FILE_PATH_ERRORS/);
  assert.match(loader, /bpf_lsm_enabled\(\)/);
  assert.match(loader, /kernel_at_least_5_10\(\)/);
  assert.match(loader, /bpf_program__set_autoload\(/);
  assert.match(loader, /fileMapFull/);
  assert.match(loader, /filePathErrors/);
  assert.match(loader, /fileSummaryRecords/);
});

test('build adapters compose required kernel evidence with legacy URL collection disabled', () => {
  const config = JSON.parse(fs.readFileSync(
    path.join(appRoot, 'config', 'nosh-build', 'adapters.json'),
    'utf8',
  ));
  const names = config.adapters.map((adapter) => adapter.name);
  assert.deepEqual(names, ['nosh-build', 'nosh-l4', 'nosh-url']);
  for (const adapter of config.adapters.slice(0, 2)) {
    assert.deepEqual(
      adapter.requiredModes,
      ['build-profile', 'build-net-learn'],
    );
    assert.equal(adapter.readiness.match.recordKind, 'status');
    assert.equal(adapter.readiness.match.status, 'ready');
    assert.equal(adapter.completion.match.recordKind, 'stats');
    assert.equal(adapter.completion.match.final, true);
    assert.equal(adapter.longRunning, true);
    assert.equal(adapter.cleanupCritical, true);
  }
  assert.equal(config.adapters[0].outputFile, 'nosh-build.jsonl');
  assert.equal(config.adapters[1].outputFile, 'nosh-l4.jsonl');
  assert.deepEqual(config.adapters[0].supportedDepths, ['balanced', 'policy']);
  assert.ok(config.adapters[0].completion.requireZero.includes('counters.fileMapFull'));
  assert.ok(config.adapters[0].completion.requireZero.includes('counters.filePathErrors'));
  assert.deepEqual(config.adapters[1].attach.args.slice(-2), [
    '--output-mode',
    'flow-summary',
  ]);
  assert.equal(config.adapters[1].readiness.match.outputMode, 'flow-summary');
  assert.equal(config.adapters[1].completion.match.outputMode, 'flow-summary');
  assert.deepEqual(config.adapters[2].requiredModes, []);
  assert.deepEqual(config.adapters[2].modes, []);
  assert.equal(config.adapters[2].evidenceRequired, false);
  assert.equal(config.adapters[2].cleanupCritical, true);
  assert.equal(config.adapters[2].readiness.match.coverageComplete, false);
  assert.equal(config.adapters[2].completion.match.coverageComplete, false);
  assert.equal(config.adapters[2].outputFile, 'nosh-url.jsonl');
});

test('live BuildKit runs require an immutable deployment digest', () => {
  const versions = JSON.parse(fs.readFileSync(
    path.join(appRoot, 'config', 'nosh-build', 'versions.json'),
    'utf8',
  ));
  assert.equal(versions.buildkit.version, 'v0.30.0');
  assert.equal(
    versions.buildkit.image,
    'moby/buildkit:v0.30.0@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f',
  );
  assert.equal(
    versions.buildkit.digest,
    'sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f',
  );
  assert.equal(versions.buildkit.requireDeploymentDigest, true);
  assert.equal(versions.noshBuild.loaderVersion, '5');
  assert.equal(versions.noshBuild.evidenceSchemaVersion, 2);
  assert.equal(
    versions.supplyChain.requireImmutableBuildkitDigestForLiveRuns,
    true,
  );
  assert.equal(versions.supplyChain.allowLatestTags, false);
});

test('Makefile builds one CO-RE object and installs the expected loader', () => {
  const makefile = fs.readFileSync(path.join(componentDir, 'Makefile'), 'utf8');
  assert.match(makefile, /-target bpf/);
  assert.match(makefile, /btf dump file \/sys\/kernel\/btf\/vmlinux format c/);
  assert.match(makefile, /gen skeleton/);
  assert.match(makefile, /LOADER_BINARY := \$\(BUILD_DIR\)\/nosh-build-loader/);
  assert.match(makefile, /LOADER_INSTALL_DIR \?= \$\(PREFIX\)\/libexec\/nosh-build/);
  assert.match(makefile, /^install: install-loader install-config$/m);
  assert.match(makefile, /^install-loader:/m);
  assert.match(makefile, /^install-config:/m);
  assert.match(makefile, /-o root -g root -m 0640/);
  assert.match(makefile, /build-adapters\.json/);
  assert.match(makefile, /build-versions\.json/);
});

test('container release audit compiles all four BPF components without loading BPF', () => {
  const dockerfile = fs.readFileSync(
    path.join(appRoot, 'Dockerfile.release-audit'),
    'utf8',
  );
  const audit = fs.readFileSync(
    path.join(appRoot, 'scripts', 'release-audit-container.sh'),
    'utf8',
  );

  for (const packageName of [
    'bpftool',
    'clang-14',
    'gcc',
    'libbpf-dev',
    'libelf-dev',
    'pkg-config',
    'zlib1g-dev',
  ]) {
    assert.match(dockerfile, new RegExp(`\\s${packageName.replaceAll('+', '\\+')} \\\\`));
  }
  assert.match(audit, /make -C "\$component" CLANG=clang-14 loader/);
  assert.match(audit, /make -C "\$component" clean/);
  assert.match(audit, /compile_collector_loader bpf\/nosh_build/);
  assert.match(audit, /compile_collector_loader bpf\/nosh_url/);
  assert.match(audit, /compile_collector_loader bpf\/nosh_l4/);
  assert.match(audit, /compile_collector_loader bpf\/nosh_egress/);
  assert.doesNotMatch(audit, /bpftool\s+prog\s+load/);
});
