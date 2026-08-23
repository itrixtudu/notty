# Security Policy

## Project Status and Supported Versions

Notty is currently pre-release software. No released version has a guaranteed
support period, maintenance window, or response time. Do not expose a
pre-release checkout to untrusted users or the public Internet.

After stable releases are available, use the latest stable version. Security
reports and fixes are handled on a best-effort basis; this policy does not
promise that any particular version will receive a fix.

Forks and downstream distributions are responsible for their own releases,
updates, deployment guidance, and security response. A fix in this repository
does not automatically protect a fork or deployed copy.

## Reporting a Vulnerability

Use **GitHub Private Vulnerability Reporting** for this repository: open the
repository's **Security** tab, select **Advisories**, and choose **Report a
vulnerability**. This is the project's only private vulnerability-reporting
channel.

Do not disclose a suspected vulnerability in a public issue, pull request,
discussion, chat, or terminal transcript. If GitHub does not offer the private
reporting control, do not publish the details; Private Vulnerability Reporting
must be enabled before this repository is publicly launched.

Include enough information to reproduce and assess the issue:

- the affected commit or version and deployment mode;
- the reachable interface and required privileges;
- minimal reproduction steps or a proof of concept;
- the observed and expected behavior;
- the likely impact and any known mitigations; and
- whether anyone else has received the report.

Remove OAuth credentials, provider tokens, spawn OTPs, terminal contents,
personal data, and unrelated secrets from reports and attachments.

## Scope

Reports are welcome for reachable first-party Notty code and its integration
boundaries, including the browser UI, HTTP and MCP services, authentication and
authorization, terminal lifecycle, agent and Collab features, Nosh containers,
launchers, and guard tooling. Supported, Preview, and Labs features are all in
scope when they are reachable; a feature label does not waive its security
boundaries.

A defect that exists solely in an upstream package, model provider, operating
system, container runtime, or other third-party service should normally be
reported to that project. Report it to Notty as well when Notty's configuration
or integration creates or materially increases the vulnerability.

`vlock` is a convenience for pausing an individual interactive terminal. When
used inside Nosh, it locks only the current PTY. It does **not** lock other tmux
sessions, the Notty UI or APIs, containers, agents, or the host, and it is not
an agent-isolation or application-security boundary. Notty's current lockdown
view and selected HTTP-route guards are separate controls, but they do not
disable MCP or terminal WebSocket input and are not a complete application
security boundary.

## Research Guidelines and Safe Harbor

To qualify as good-faith research:

- test only systems and accounts you own or are explicitly authorized to use;
- avoid privacy violations, service disruption, persistence, and destructive
  actions;
- access only the minimum data needed to demonstrate the issue, do not retain
  or share it, and stop immediately if you encounter sensitive data;
- do not use a vulnerability to pivot into third-party systems or provider
  accounts; and
- allow a reasonable opportunity for private coordination before disclosure.

When research follows these rules, the maintainers intend not to initiate legal
action over that research and will work to clarify or resolve accidental policy
violations. This statement is limited to the maintainers' own actions: it does
not authorize access, bind third parties, waive applicable law, or grant rights
over systems or data belonging to others.

## Response and Disclosure

Reports are evaluated best-effort. Acknowledgment, investigation, remediation,
release, and disclosure timing are decided case by case based on severity,
reproducibility, affected users, upstream coordination, and release readiness.
There is no guaranteed response or remediation SLA and no fixed embargo period.
Do not publish report details until disclosure has been coordinated or the
maintainers have explicitly agreed that publication is appropriate.

The project does not currently offer a bug bounty and does not promise payment,
rewards, public credit, or inclusion in release notes. Any acknowledgment is
case by case and requires the reporter's consent.
