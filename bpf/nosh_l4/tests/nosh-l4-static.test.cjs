const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const componentDir = path.resolve(__dirname, '..');
const source = fs.readFileSync(
  path.join(componentDir, 'nosh_l4.bpf.c'),
  'utf8',
);
const header = fs.readFileSync(
  path.join(componentDir, 'include', 'nosh_l4.h'),
  'utf8',
);
const schema = JSON.parse(fs.readFileSync(
  path.join(componentDir, 'schema', 'nosh-l4-event.schema.json'),
  'utf8',
));
const statsSchema = JSON.parse(fs.readFileSync(
  path.join(componentDir, 'schema', 'nosh-l4-stats.schema.json'),
  'utf8',
));
const controlSchema = JSON.parse(fs.readFileSync(
  path.join(componentDir, 'schema', 'nosh-l4-control.schema.json'),
  'utf8',
));
const flowSchema = JSON.parse(fs.readFileSync(
  path.join(componentDir, 'schema', 'nosh-l4-flow-summary.schema.json'),
  'utf8',
));
const loaderSource = fs.readFileSync(
  path.join(componentDir, 'loader', 'nosh_l4_loader.c'),
  'utf8',
);

function collectPropertyNames(value, names = []) {
  if (Array.isArray(value)) {
    for (const item of value)
      collectPropertyNames(item, names);
    return names;
  }

  if (!value || typeof value !== 'object')
    return names;

  if (value.properties) {
    for (const name of Object.keys(value.properties))
      names.push(name);
  }

  for (const child of Object.values(value))
    collectPropertyNames(child, names);
  return names;
}

test('the normalized event schema is versioned and metadata-only', () => {
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
  assert.equal(schema.properties.schemaVersion.const, 1);
  assert.equal(schema.properties.metadataOnly.const, true);
  assert.equal(schema.additionalProperties, false);
  assert.ok(schema.required.includes('sensorDecision'));
  assert.deepEqual(
    new Set(schema.properties.eventKind.enum),
    new Set(['attempt', 'packet']),
  );

  const propertyNames = collectPropertyNames(schema);
  const forbidden = new Set([
    'payload',
    'packetPayload',
    'body',
    'content',
    'sample',
    'rawPacket',
  ]);
  for (const name of propertyNames)
    assert.equal(forbidden.has(name), false, `forbidden schema field: ${name}`);

  assert.equal(schema.$defs.attempt.properties.completionKnown.const, false);
  assert.equal(schema.$defs.sensorDecision.properties.verdict.const, 'allow');
  assert.equal(
    schema.$defs.sensorDecision.properties.observedOnly.const,
    true,
  );
  assert.equal(schema.$defs.sensorDecision.properties.hookReturn.const, 1);
  assert.equal(
    schema.$defs.accounting.properties.scope.const,
    'running-flow-total',
  );
  assert.equal(schema.$defs.uint64.type, 'string');
});

test('all six cgroup observation hooks are present and allow-only', () => {
  const programs = [
    ['cgroup/connect4', 'nosh_l4_connect4'],
    ['cgroup/connect6', 'nosh_l4_connect6'],
    ['cgroup/sendmsg4', 'nosh_l4_sendmsg4'],
    ['cgroup/sendmsg6', 'nosh_l4_sendmsg6'],
    ['cgroup_skb/ingress', 'nosh_l4_ingress'],
    ['cgroup_skb/egress', 'nosh_l4_egress'],
  ];

  assert.match(header, /#define NOSH_L4_ALLOW 1\b/);
  for (const [section, functionName] of programs) {
    assert.ok(source.includes(`SEC("${section}")`), `missing ${section}`);
    const body = source.match(new RegExp(
      `int ${functionName}\\([^)]*\\)\\n\\{([\\s\\S]*?)\\n\\}`,
    ));
    assert.ok(body, `missing body for ${functionName}`);
    assert.match(body[1], /return NOSH_L4_ALLOW;/);
    assert.doesNotMatch(body[1], /return\s+0\s*;/);
    assert.doesNotMatch(body[1], /return\s+-/);
  }
});

test('TCP, UDP, ICMPv4, and ICMPv6 are represented in ABI and parser', () => {
  const protocols = [
    ['ICMP', 1],
    ['TCP', 6],
    ['UDP', 17],
    ['ICMPV6', 58],
  ];

  for (const [name, number] of protocols) {
    assert.match(
      header,
      new RegExp(`NOSH_L4_PROTOCOL_${name} = ${number},`),
    );
    assert.ok(
      source.includes(`NOSH_L4_PROTOCOL_${name}`),
      `parser does not reference ${name}`,
    );
  }

  assert.match(source, /#pragma unroll\s+for \(iteration = 0; iteration < 6;/);
  assert.match(source, /NOSH_L4_IPV6_FRAGMENT_OFFSET_MASK/);
  assert.match(source, /NOSH_L4_IPV4_FRAGMENT_OFFSET_MASK/);
  assert.match(source, /NOSH_L4_F_L4_UNAVAILABLE/);
});

test('flow accounting and loss visibility use bounded maps', () => {
  assert.match(source, /__uint\(type, BPF_MAP_TYPE_RINGBUF\)/);
  assert.match(source, /} events SEC\("\.maps"\);/);
  assert.match(source, /__uint\(type, BPF_MAP_TYPE_HASH\)/);
  assert.match(source, /} flow_totals SEC\("\.maps"\);/);
  assert.match(source, /__uint\(type, BPF_MAP_TYPE_PERCPU_ARRAY\)/);
  assert.match(source, /} stats SEC\("\.maps"\);/);
  assert.match(source, /} session_config SEC\("\.maps"\);/);
  assert.match(source, /configured_cgroup_id\(\)/);
  assert.match(source, /NOSH_L4_STAT_CONFIG_MISSING/);
  assert.match(source, /__sync_fetch_and_add\(&totals->packets, 1\);/);
  assert.match(source, /__sync_fetch_and_add\(&totals->bytes, packet_bytes\);/);
  assert.match(source, /NOSH_L4_STAT_RINGBUF_DROPS/);
  assert.match(source, /NOSH_L4_STAT_FLOW_MAP_FULL/);
  assert.match(header, /#define NOSH_L4_FLOW_MAX_ENTRIES 65536\b/);
  assert.match(source, /GADGET_MAPITER\(nosh_l4_totals, flow_totals\)/);
});

test('process attribution is keyed by socket cookie without guessing packet task', () => {
  assert.match(source, /bpf_get_socket_cookie\(ctx\)/);
  assert.match(source, /bpf_get_socket_cookie\(skb\)/);
  assert.match(source, /} socket_owners SEC\("\.maps"\);/);
  assert.match(
    source,
    /bpf_map_update_elem\(&socket_owners, &socket_cookie, &owner, BPF_ANY\)/,
  );
  assert.match(
    source,
    /bpf_map_lookup_elem\(&socket_owners, &socket_cookie\)/,
  );
  assert.match(header, /NOSH_L4_OWNER_CURRENT_TASK = 1/);
  assert.match(header, /NOSH_L4_OWNER_SOCKET_COOKIE_CACHE = 2/);

  const packetObserver = source.match(
    /static __always_inline void observe_packet[\s\S]*?\n\}/,
  );
  assert.ok(packetObserver);
  assert.doesNotMatch(packetObserver[0], /read_current_process/);
  assert.doesNotMatch(packetObserver[0], /bpf_get_current_pid_tgid/);
});

test('packet access is read-only and limited to protocol headers', () => {
  const forbiddenHelpers = [
    'bpf_probe_read_user',
    'bpf_copy_from_user',
    'bpf_skb_store_bytes',
    'bpf_skb_change_tail',
    'bpf_skb_adjust_room',
    'bpf_clone_redirect',
  ];

  for (const helper of forbiddenHelpers)
    assert.equal(source.includes(helper), false, `forbidden helper: ${helper}`);

  assert.match(source, /bpf_skb_load_bytes_relative\(/);
  assert.match(source, /#define NOSH_L4_HDR_START_NET 1\b/);
  assert.doesNotMatch(source, /\bskb->data\b/);
  assert.doesNotMatch(
    source,
    /load_network_bytes\([^;]*\bskb->len\b/s,
  );
  assert.match(
    source,
    /load_network_bytes\(skb, packet->l4_offset, &ports, sizeof\(ports\)\)/,
  );
  assert.match(
    source,
    /load_network_bytes\(skb, packet->l4_offset, &icmp, sizeof\(icmp\)\)/,
  );
  assert.doesNotMatch(header, /\bpayload\b/i);
});

test('IPv6 socket-address reads retain verifier-safe fixed context offsets', () => {
  assert.match(
    source,
    /volatile struct bpf_sock_addr \*ctx/,
  );
  for (const field of ['user_ip6', 'msg_src_ip6']) {
    for (let index = 0; index < 4; index++) {
      assert.match(
        source,
        new RegExp(`word = ctx->${field}\\[${index}\\];`),
      );
    }
  }
  assert.doesNotMatch(
    source,
    /__builtin_memcpy\([^;]*ctx->(?:user_ip6|msg_src_ip6)/s,
  );
});

test('libbpf and Inspektor Gadget build metadata stay wired to one source', () => {
  const makefile = fs.readFileSync(path.join(componentDir, 'Makefile'), 'utf8');
  const buildYaml = fs.readFileSync(
    path.join(componentDir, 'build.yaml'),
    'utf8',
  );
  const gadgetYaml = fs.readFileSync(
    path.join(componentDir, 'gadget.yaml'),
    'utf8',
  );

  assert.match(makefile, /-target bpf/);
  assert.match(makefile, /btf dump file \/sys\/kernel\/btf\/vmlinux format c/);
  assert.match(makefile, /gen skeleton/);
  assert.match(makefile, /\$\(IG\) image build \. -f build\.yaml/);
  assert.match(buildYaml, /^ebpfsource: nosh_l4\.bpf\.c$/m);
  assert.match(buildYaml, /-DNOSH_L4_INSPEKTOR_GADGET=1/);
  assert.match(gadgetYaml, /^  nosh_l4_events:$/m);
  assert.match(gadgetYaml, /^  nosh_l4_totals:$/m);
  assert.match(source, /GADGET_TRACER\(nosh_l4_events, events, nosh_l4_event\)/);
});

test('loader schemas separate evidence, cumulative loss, and control output', () => {
  assert.equal(statsSchema.properties.schemaVersion.const, 1);
  assert.equal(statsSchema.properties.recordKind.const, 'stats');
  assert.equal(statsSchema.properties.final.type, 'boolean');
  assert.deepEqual(
    new Set(statsSchema.properties.counters.required),
    new Set([
      'ringbufDrops',
      'parseErrors',
      'unsupportedProtocol',
      'flowMapFull',
      'configMissing',
    ]),
  );
  assert.equal(controlSchema.oneOf.length, 2);
  assert.deepEqual(statsSchema.properties.outputMode.enum, [
    'events',
    'flow-summary',
  ]);
  assert.equal(flowSchema.properties.recordKind.const, 'flow-summary');
  assert.equal(flowSchema.properties.metadataOnly.const, true);
  assert.equal(
    flowSchema.properties.accounting.properties.scope.const,
    'capture-flow-total',
  );
  assert.ok(
    controlSchema.$defs.status.properties.status.enum.includes('ready'),
  );
  assert.ok(
    controlSchema.$defs.status.properties.status.enum.includes('healthy'),
  );

  for (const propertyName of [
    ...collectPropertyNames(statsSchema),
    ...collectPropertyNames(controlSchema),
    ...collectPropertyNames(flowSchema),
  ]) {
    assert.notEqual(propertyName.toLowerCase(), 'payload');
    assert.notEqual(propertyName.toLowerCase(), 'rawpacket');
  }
});

test('host loader resolves one exact cgroup and attaches all six programs', () => {
  assert.match(loaderSource, /name_to_handle_at\(cgroup_fd, "\."/);
  assert.match(loaderSource, /O_NOFOLLOW/);
  assert.match(loaderSource, /CGROUP2_SUPER_MAGIC/);
  assert.match(
    loaderSource,
    /refusing to attach to the cgroup v2 mount root/,
  );
  assert.match(loaderSource, /cgroup id mismatch/);
  assert.match(loaderSource, /#define NOSH_L4_PROGRAM_COUNT 6\b/);

  const programNames = [
    'nosh_l4_connect4',
    'nosh_l4_connect6',
    'nosh_l4_sendmsg4',
    'nosh_l4_sendmsg6',
    'nosh_l4_ingress',
    'nosh_l4_egress',
  ];
  for (const programName of programNames)
    assert.ok(loaderSource.includes(`progs.${programName}`));
  assert.match(loaderSource, /bpf_program__attach_cgroup\(/);
  assert.match(
    source,
    /event->direction = NOSH_L4_DIRECTION_EGRESS;/,
  );

  const configIndex = loaderSource.indexOf(
    'bpf_map_update_elem(bpf_map__fd(skeleton->maps.session_config)',
  );
  const attachIndex = loaderSource.indexOf('bpf_program__attach_cgroup(');
  assert.ok(configIndex >= 0 && configIndex < attachIndex);
});

test('host loader has a clean supervised JSONL lifecycle', () => {
  assert.match(loaderSource, /"run"/);
  assert.match(loaderSource, /"health"/);
  assert.match(loaderSource, /--status-fd/);
  assert.match(loaderSource, /SIGTERM/);
  assert.match(loaderSource, /SIGPIPE/);
  assert.match(loaderSource, /prctl\(PR_SET_PDEATHSIG, SIGTERM\)/);
  assert.match(loaderSource, /getppid\(\) != expected_parent_pid/);
  assert.match(loaderSource, /RLIMIT_FSIZE/);
  assert.match(loaderSource, /128ULL \* 1024ULL \* 1024ULL/);
  assert.match(loaderSource, /sigaction\(SIGXFSZ/);
  assert.match(loaderSource, /runtime_error = EFBIG/);
  assert.match(loaderSource, /evidence file-size limit reached; detaching/);
  assert.match(loaderSource, /ring_buffer__poll\(/);
  assert.match(loaderSource, /ring_buffer__consume\(/);
  assert.match(loaderSource, /sample_clock_offset\(/);
  assert.match(loaderSource, /realtime_minus_monotonic_ns/);
  assert.match(loaderSource, /emit_stats_json\(&context, true\)/);
  assert.match(loaderSource, /emit_flow_summaries\(&context\)/);
  assert.match(loaderSource, /"ready"/);
  assert.match(loaderSource, /"stopped"/);
  assert.match(loaderSource, /libbpf_num_possible_cpus\(/);
  assert.match(loaderSource, /NOSH_L4_LIBBPF_LOG_HEAD_BYTES 512\b/);
  assert.match(loaderSource, /NOSH_L4_LIBBPF_LOG_TAIL_BYTES 1408\b/);
  assert.match(loaderSource, /fopencookie\(/);
  assert.match(loaderSource, /libbpf diagnostic bytes omitted/);
  assert.doesNotMatch(loaderSource, /char message\[2048\]/);
  assert.doesNotMatch(loaderSource, /payload/i);
  assert.doesNotMatch(loaderSource, /bpf_probe_read|skb_load_bytes/);

  const fileLimitIndex = loaderSource.indexOf(
    'if (install_evidence_file_size_limit() != 0)',
  );
  const bpfOpenIndex = loaderSource.indexOf('skeleton = nosh_l4_bpf__open()');
  assert.ok(fileLimitIndex >= 0 && fileLimitIndex < bpfOpenIndex);

  const makefile = fs.readFileSync(path.join(componentDir, 'Makefile'), 'utf8');
  assert.match(makefile, /^loader: \$\(LOADER_BINARY\)$/m);
  assert.match(makefile, /LOADER_BINARY := \$\(BUILD_DIR\)\/nosh-l4-loader/);
  assert.match(makefile, /^install-loader:/m);
  assert.match(makefile, /-Iinclude -I\$\(BUILD_DIR\)/);

  const adapter = JSON.parse(fs.readFileSync(
    path.join(componentDir, 'adapter.example.json'),
    'utf8',
  ));
  assert.equal(adapter.name, 'nosh-l4');
  assert.deepEqual(adapter.health.args, ['health']);
  assert.deepEqual(
    adapter.attach.args,
    [
      'run',
      '--cgroup',
      '{cgroupPath}',
      '--cgroup-id',
      '{cgroupId}',
    ],
  );
  assert.deepEqual(
    adapter.readiness.match,
    { recordKind: 'status', status: 'ready' },
  );
  assert.equal(adapter.outputFile, 'nosh-l4.jsonl');
  assert.equal(adapter.stderrFile, 'nosh-l4.status.jsonl');
  assert.equal(adapter.longRunning, true);
});

test('flow-summary mode suppresses packet JSON in BPF and keeps attempts', () => {
  assert.match(header, /NOSH_L4_OUTPUT_EVENTS = 0/);
  assert.match(header, /NOSH_L4_OUTPUT_FLOW_SUMMARY = 1/);
  const packetObserver = source.match(
    /static __always_inline void observe_packet[\s\S]*?\n\}/,
  );
  assert.ok(packetObserver);
  const aggregateIndex = packetObserver[0].indexOf('update_flow_totals(');
  const modeIndex = packetObserver[0].indexOf('configured_output_mode()');
  const reserveIndex = packetObserver[0].indexOf('bpf_ringbuf_reserve(');
  assert.ok(aggregateIndex >= 0 && aggregateIndex < modeIndex);
  assert.ok(modeIndex < reserveIndex);
  assert.match(loaderSource, /--output-mode/);
  assert.match(loaderSource, /options->output_mode = "events"/);
  assert.match(loaderSource, /"flow-summary"/);
  assert.match(loaderSource, /NOSH_L4_FLOW_MAX_ENTRIES/);
  assert.match(
    loaderSource,
    /static int destroy_links\(struct bpf_link \*links\[NOSH_L4_PROGRAM_COUNT\]\)/,
  );
  assert.match(
    loaderSource,
    /if \(destroy_links\(links\) != 0 && !runtime_error\)\s+runtime_error = EIO;/,
  );
});
