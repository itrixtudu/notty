# Repository Guidelines

## Project Structure & Module Organization

This repository is a Node.js/Next.js MCP terminal service. Server entrypoints live at the root (`server.js`, `main.js`, `proxy.js`) and reusable server logic is in `lib/`. Next.js routes are in `pages/`, with API routes under `pages/api/`. React UI components are in `components/`, shared hooks in `hooks/`, global CSS in `styles/`, runtime config in `config/`, and operational scripts in `scripts/`. Root `Dockerfile*` files and launchers under `scripts/` support containerized workflows. ANSI art, durdraw material, and other assets are under `ansi/`, `art/`, and `dist/`. Documentation lives in `README.md`, `docs/`, and `collab/`.

## Build, Test, and Development Commands

Never run `npm`, `npx`, or `npm exec` on the host. Package installation,
tests, builds, audits, and packaging must run inside a container.

- `./scripts/release-audit.sh`: host entrypoint for the clean install, deterministic
  tests, production build, advisory check, and package inspection. Docker is
  mandatory and the script has no host-package-manager fallback.
- `./scripts/build-nosh.sh`: build the local Nosh image; package-manager commands run
  in the Docker build.
- `./scripts/nosh.sh`: launch or attach to the project container.
- Inside a Nosh container only, `npm run dev:ui`, `npm run start`,
  `npm run start:sse`, `npm run start:stdio`, and targeted package scripts are
  available for interactive development.
- `bash scripts/test.sh`: run the Docker-backed MCP terminal flow; requires
  Docker and usually `jq`.

## Coding Style & Naming Conventions

Use modern ES modules (`"type": "module"`) and keep JavaScript indentation at two spaces, matching the existing files. Prefer descriptive camelCase for variables/functions, PascalCase for React components, and kebab-case for shell scripts and launcher names. Keep API route filenames aligned with their URL paths, for example `pages/api/terminals/[id]/read.js`. No project-wide formatter is configured, so preserve local style and avoid unrelated reformatting.

NOSH Design Principle #42: Do not make the boundary more interesting than the task.

## Testing Guidelines

Treat `./scripts/release-audit.sh` as the host-side baseline. When already inside a
container, the underlying deterministic test and build package scripts plus
targeted MCP smoke scripts in `scripts/` are the baseline checks. For
terminal/MCP behavior, include both HTTP and SSE flows when practical. Name
new test or smoke scripts by behavior, such as `scripts/sse-roundtrip.mjs`.

## Commit & Pull Request Guidelines

Recent commits use short, lowercase, imperative or note-style subjects (`scripts`, `updates`, `nosh`). Keep commits focused and avoid bundling unrelated formatting. Pull requests should describe the behavior changed, list commands run, note any Docker or environment assumptions, and include screenshots for visible UI changes.

## Security & Configuration Tips

Do not commit OAuth tokens, spawn OTPs, or local host overrides. Document required environment variables such as `NOTTY_OAUTH_*`, `NOTTY_MCP_SPAWN_OTP`, `PORT`, and `NOTTY_PUBLIC_HOST` in PR notes when they affect testing.




