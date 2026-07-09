#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '..');
const adminUiDir = path.join(repoRoot, 'admin-ui');
const outputGif = path.join(repoRoot, 'docs', 'images', 'demo-mcp-rbac.gif');
const port = process.env.GG_MCP_RBAC_DEMO_PORT ?? '43184';
const baseUrl = `http://127.0.0.1:${port}`;
const adminUrl = `${baseUrl}/admin`;
const adminRequire = createRequire(path.join(adminUiDir, 'package.json'));
const { chromium } = adminRequire('playwright');

const viewport = { width: 1440, height: 900 };
const targetSize = { width: 960, height: 600 };
const frameDurationsMs = [3500, 3500, 3500, 4000, 4500, 4500, 3500, 3000];
const adminTokenStorageKey = 'greengateway_admin_token';

async function main() {
  await mkdir(path.dirname(outputGif), { recursive: true });
  const framesDir = await mkdtemp(path.join(os.tmpdir(), 'gg-mcp-rbac-demo-'));
  const server = startViteServer();
  let browser;

  try {
    await waitForServer(`${adminUrl}/`, 120_000);
    browser = await chromium.launch();
    const page = await browser.newPage({ viewport, deviceScaleFactor: 1 });

    await page.addInitScript(
      ({ key, token }) => {
        window.sessionStorage.setItem(key, token);
        window.localStorage.setItem('greengateway_admin_theme', 'light');
      },
      { key: adminTokenStorageKey, token: jwtWithRoles(['admin']) },
    );

    await installMockRoutes(page);

    const frames = [];
    const capture = async ({ name, caption, locator, cursorAt = 'center' }) => {
      await page.addStyleTag({
        content:
          '*, *::before, *::after { transition-duration: 0ms !important; animation-duration: 0ms !important; scroll-behavior: auto !important; }',
      });
      const imagePath = path.join(
        framesDir,
        `${String(frames.length + 1).padStart(2, '0')}-${name}.png`,
      );
      const box = locator ? await locator.boundingBox() : null;
      await page.screenshot({ path: imagePath, fullPage: false });
      frames.push({
        imagePath,
        caption,
        durationMs: frameDurationsMs[frames.length],
        highlight: box ? boxToRect(box) : null,
        cursor: box ? cursorPoint(box, cursorAt) : null,
      });
    };

    await page.goto(`${adminUrl}/traffic`);
    await page.waitForSelector('text=Traffic inventory');
    const trafficTable = page.locator('.traffic-table');
    await capture({
      name: 'mcp-traffic-learning',
      caption:
        'Claude, Cursor, and GitHub MCP clients call tools through GreenGateway instead of hitting the server directly.',
      locator: trafficTable,
      cursorAt: 'none',
    });

    await page.getByRole('link', { name: 'View detail for tool repo.delete_file' }).click();
    await page.waitForURL(/\/admin\/traffic\/detail/);
    await page.waitForSelector('text=Principal breakdown');
    await page.evaluate(() => {
      document
        .querySelector('[aria-labelledby="principal-breakdown-heading"]')
        ?.scrollIntoView({ block: 'center' });
    });
    await capture({
      name: 'mcp-principals',
      caption:
        'The detail view shows the identities behind the tool traffic: Claude Desktop, Cursor, and GitHub Actions.',
      locator: page.locator('[aria-labelledby="principal-breakdown-heading"]'),
      cursorAt: 'none',
    });

    await page.goto(`${adminUrl}/traffic`);
    await page.waitForSelector('text=Traffic inventory');
    const createRuleButton = page.getByRole('button', {
      name: 'Create rule for tool repo.delete_file',
    });
    await capture({
      name: 'mcp-create-rule',
      caption:
        'A risky MCP tool can become a rule candidate directly from observed traffic.',
      locator: createRuleButton,
    });

    await createRuleButton.click();
    await page.waitForURL(/\/admin\/policy\/rules\/editor/);
    await page.waitForSelector('text=Create policy rule');
    await capture({
      name: 'editor-prefilled-tool',
      caption:
        'The visual editor is prefilled for the exact MCP tool, so the rule does not overreach into other tools.',
      locator: page.locator('.rule-form').first(),
      cursorAt: 'none',
    });

    await page.getByRole('combobox', { name: 'Role constraints' }).fill('ci-bot');
    await page.getByRole('button', { name: 'Add role' }).click();
    await page.getByLabel('Bearer token').check();
    await page.getByRole('textbox', { name: 'Principal IDs' }).fill('github-actions[bot]');
    await page.getByRole('button', { name: 'Add principal ID' }).click();
    await page.getByRole('radio', { name: /Deny/ }).check();
    await page.waitForSelector('text=Deny MCP tool calls to repo.delete_file');
    await page.evaluate(() => {
      document
        .querySelector('[aria-labelledby="rule-principal-heading"]')
        ?.scrollIntoView({ block: 'center' });
    });

    await capture({
      name: 'editor-identity-scope',
      caption:
        'Scope the deny to the GitHub Actions identity while leaving Claude and Cursor traffic outside the block.',
      locator: page.locator('[aria-labelledby="rule-principal-heading"]'),
      cursorAt: 'none',
    });

    await page.waitForSelector('.rule-preview-stat .stat-value');
    await page.evaluate(() => {
      window.scrollTo(0, 0);
    });
    await capture({
      name: 'preview-impact',
      caption:
        'Live preview shows the exact MCP calls that would match before the deny rule is saved.',
      locator: page.locator('.rule-preview-panel'),
      cursorAt: 'none',
    });

    await page.getByRole('button', { name: 'Save rule' }).click();
    await page.waitForSelector('text=Rule saved.');
    const logicSummary = page.locator('.rule-logic-summary');
    await logicSummary.scrollIntoViewIfNeeded();
    await capture({
      name: 'policy-expression',
      caption:
        'The generated policy expression is narrow: one MCP tool, role ci-bot, and principal github-actions[bot].',
      locator: logicSummary,
      cursorAt: 'none',
    });

    await page.goto(`${adminUrl}/rules`);
    await page.waitForSelector('text=block-github-repo-delete');
    await capture({
      name: 'rulebase-enforcing',
      caption:
        'The Rulebase now allows normal MCP usage but blocks github-actions[bot] from repo.delete_file.',
      locator: page.locator('[data-testid="rule-row-block-github-repo-delete"]'),
      cursorAt: 'none',
    });

    const manifestPath = path.join(framesDir, 'manifest.json');
    await writeFile(
      manifestPath,
      JSON.stringify(
        {
          outputGif,
          targetSize,
          frames,
        },
        null,
        2,
      ),
      'utf8',
    );

    await assembleGif(manifestPath);
    console.log(`Wrote ${path.relative(repoRoot, outputGif)}`);
  } finally {
    if (browser) {
      await browser.close();
    }
    await stopServer(server);
    if (process.env.GG_KEEP_DEMO_FRAMES !== '1') {
      await rm(framesDir, { recursive: true, force: true });
    } else {
      console.log(`Kept frames in ${framesDir}`);
    }
  }
}

function startViteServer() {
  const command = process.platform === 'win32' ? 'cmd.exe' : 'npm';
  const args =
    process.platform === 'win32'
      ? [
          '/d',
          '/s',
          '/c',
          'npm.cmd',
          'run',
          'dev',
          '--',
          '--host',
          '127.0.0.1',
          '--port',
          port,
          '--strictPort',
        ]
      : ['run', 'dev', '--', '--host', '127.0.0.1', '--port', port, '--strictPort'];
  const child = spawn(command, args, {
    cwd: adminUiDir,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });

  child.stdout.on('data', (chunk) => {
    if (process.env.GG_MCP_RBAC_DEMO_VERBOSE === '1') {
      process.stdout.write(chunk);
    }
  });
  child.stderr.on('data', (chunk) => {
    if (process.env.GG_MCP_RBAC_DEMO_VERBOSE === '1') {
      process.stderr.write(chunk);
    }
  });

  return child;
}

async function waitForServer(url, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;

  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  throw new Error(
    `Timed out waiting for ${url}${lastError ? `: ${lastError.message}` : ''}`,
  );
}

async function stopServer(server) {
  if (server.exitCode !== null || server.killed) {
    return;
  }

  if (process.platform === 'win32' && server.pid) {
    await new Promise((resolve) => {
      const killer = spawn(
        'taskkill.exe',
        ['/PID', String(server.pid), '/T', '/F'],
        {
          stdio: 'ignore',
          windowsHide: true,
        },
      );
      killer.on('error', () => {
        server.kill();
        resolve();
      });
      killer.on('exit', resolve);
    });
    return;
  }

  server.kill();
}

async function installMockRoutes(page) {
  let savedBlockRule = null;

  await page.route('**/version', async (route) => {
    await json(route, { admin_login_configured: false });
  });

  await page.route('**/v1/admin/policy/rules/preview', async (route) => {
    await json(route, {
      match_count: 6,
      scanned_event_count: 321,
      sample_strategy: 'newest_matches',
      samples: [
        previewSample({
          event_id: 'evt-mcp-delete-6',
          request_id: 'req-mcp-delete-6',
          minutesAgo: 2,
          method: 'MCP',
          path: '/mcp/tools/repo.delete_file',
          actor: {
            user_id: 'github-actions[bot]',
            auth_mode: 'bearer_token',
            roles: ['ci-bot'],
          },
          status: 200,
          policy_decision: 'allow',
          matched_rule_id: 'mcp-tools-default',
        }),
        previewSample({
          event_id: 'evt-mcp-delete-5',
          request_id: 'req-mcp-delete-5',
          minutesAgo: 14,
          method: 'MCP',
          path: '/mcp/tools/repo.delete_file',
          actor: {
            user_id: 'github-actions[bot]',
            auth_mode: 'bearer_token',
            roles: ['ci-bot'],
          },
          status: 200,
          policy_decision: 'allow',
          matched_rule_id: 'mcp-tools-default',
        }),
      ],
    });
  });

  await page.route('**/v1/admin/policy/rules/hits', async (route) => {
    await json(route, {
      rules: [
        { rule_id: 'block-github-repo-delete', hits: savedBlockRule ? 6 : 0 },
        { rule_id: 'allow-claude-cursor-repo-read', hits: 1442 },
        { rule_id: 'allow-developer-ticket-tools', hits: 218 },
      ],
    });
  });

  await page.route('**/v1/admin/traffic/endpoints?**', async (route) => {
    await json(route, {
      endpoints: [
        trafficEndpoint({
          method: 'MCP',
          endpoint_template: '/mcp/tools/repo.delete_file',
          call_count: 37,
          distinct_principal_count: 3,
          minutesAgo: 2,
          is_new: true,
          reviewed: false,
          covered_by_rule: Boolean(savedBlockRule),
          open_signals: {
            count: 1,
            signal_types: ['principal_new_to_endpoint'],
          },
          latency: { count: 37, p50_ms: 29, p95_ms: 82, p99_ms: 119 },
          status_counts: [
            { status: 200, count: savedBlockRule ? 31 : 37 },
            ...(savedBlockRule ? [{ status: 403, count: 6 }] : []),
          ],
        }),
        trafficEndpoint({
          method: 'MCP',
          endpoint_template: '/mcp/tools/repo.read_file',
          call_count: 1442,
          distinct_principal_count: 2,
          minutesAgo: 1,
          is_new: false,
          reviewed: true,
          reviewed_at: isoMinutesAgo(6),
          reviewed_by: 'platform-admin',
          covered_by_rule: true,
          latency: { count: 1442, p50_ms: 18, p95_ms: 41, p99_ms: 66 },
          status_counts: [{ status: 200, count: 1442 }],
        }),
        trafficEndpoint({
          method: 'MCP',
          endpoint_template: '/mcp/tools/issues.create',
          call_count: 218,
          distinct_principal_count: 3,
          minutesAgo: 4,
          is_new: false,
          reviewed: true,
          reviewed_at: isoMinutesAgo(12),
          reviewed_by: 'platform-admin',
          covered_by_rule: true,
          latency: { count: 218, p50_ms: 24, p95_ms: 58, p99_ms: 91 },
          status_counts: [{ status: 200, count: 218 }],
        }),
      ],
      next_cursor: null,
    });
  });

  await page.route('**/v1/admin/traffic/endpoint?**', async (route) => {
    await json(route, {
      endpoint: {
        ...trafficEndpoint({
          method: 'MCP',
          endpoint_template: '/mcp/tools/repo.delete_file',
          call_count: 37,
          distinct_principal_count: 3,
          minutesAgo: 2,
          is_new: true,
          reviewed: false,
          covered_by_rule: Boolean(savedBlockRule),
          latency: { count: 37, p50_ms: 29, p95_ms: 82, p99_ms: 119 },
          status_counts: [
            { status: 200, count: savedBlockRule ? 31 : 37 },
            ...(savedBlockRule ? [{ status: 403, count: 6 }] : []),
          ],
        }),
        updated_at: isoMinutesAgo(1),
        latency: {
          count: 37,
          sample_count: 37,
          p50_ms: 29,
          p95_ms: 82,
          p99_ms: 119,
        },
      },
      principals: {
        principals: [
          {
            user_id: 'claude-desktop/alex',
            first_seen: isoMinutesAgo(90),
            last_seen: isoMinutesAgo(3),
          },
          {
            user_id: 'cursor/jordan',
            first_seen: isoMinutesAgo(84),
            last_seen: isoMinutesAgo(4),
          },
          {
            user_id: 'github-actions[bot]',
            first_seen: isoMinutesAgo(42),
            last_seen: isoMinutesAgo(2),
          },
        ],
        next_cursor: null,
      },
      audit: {
        available: true,
        match_strategy: 'mcp_tool_name',
        match_limitations: '',
        time_series_truncated: false,
        time_series: [
          { bucket_start: isoMinutesAgo(180), count: 8 },
          { bucket_start: isoMinutesAgo(120), count: 11 },
          { bucket_start: isoMinutesAgo(60), count: 18 },
        ],
        recent_events: [
          recentEvent({
            id: 3,
            event_id: 'evt-mcp-delete-github',
            request_id: 'req-mcp-delete-github',
            minutesAgo: 2,
            actor: 'github-actions[bot]',
          }),
          recentEvent({
            id: 2,
            event_id: 'evt-mcp-delete-cursor',
            request_id: 'req-mcp-delete-cursor',
            minutesAgo: 4,
            actor: 'cursor/jordan',
          }),
          recentEvent({
            id: 1,
            event_id: 'evt-mcp-delete-claude',
            request_id: 'req-mcp-delete-claude',
            minutesAgo: 9,
            actor: 'claude-desktop/alex',
          }),
        ],
        recent_events_next_cursor: null,
        recent_events_scan_truncated: false,
      },
    });
  });

  await page.route('**/v1/admin/policy/rules', async (route) => {
    if (route.request().method() !== 'POST') {
      await route.fallback();
      return;
    }

    const body = JSON.parse(route.request().postData() ?? '{}');
    savedBlockRule = {
      ...body,
      id: 'block-github-repo-delete',
      enabled: true,
    };

    await route.fulfill({
      status: 201,
      contentType: 'application/json',
      headers: { ETag: '"demo-mcp-rbac-policy-etag-2"' },
      body: JSON.stringify(savedBlockRule),
    });
  });

  await page.route('**/v1/admin/policy', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: { ETag: savedBlockRule ? '"demo-mcp-rbac-policy-etag-2"' : '"demo-mcp-rbac-policy-etag"' },
      body: JSON.stringify(policyDocument(savedBlockRule)),
    });
  });

  await page.route('**/v1/admin/policy/rules/*', async (route) => {
    await route.fallback();
  });
}

function policyDocument(savedBlockRule = null) {
  const rules = [
    {
      id: 'allow-claude-cursor-repo-read',
      enabled: true,
      methods: [],
      tool_name: 'repo.read_file',
      principal: {
        roles: ['developer'],
        principal_ids: ['claude-desktop/alex', 'cursor/jordan'],
      },
      action: 'allow',
    },
    {
      id: 'allow-developer-ticket-tools',
      enabled: true,
      methods: [],
      tool_name: 'issues.create',
      principal: { roles: ['developer', 'ci-bot'] },
      action: 'allow',
    },
  ];

  if (savedBlockRule) {
    rules.unshift(savedBlockRule);
  }

  return {
    schema_version: '0.1.0',
    id: 'demo-mcp-rbac-policy',
    default_action: 'deny',
    enforcement_mode: 'enforce',
    roles: {
      admin: {
        permissions: [
          'admin:policy:read',
          'admin:policy:write',
          'admin:traffic:read',
          'admin:traffic:write',
        ],
      },
      developer: { permissions: ['mcp:tools:read'] },
      'ci-bot': { permissions: ['mcp:tools:automation'] },
    },
    routes: [],
    rules,
  };
}

function trafficEndpoint(overrides) {
  return {
    method: 'GET',
    endpoint_template: '/api/example',
    first_seen: isoMinutesAgo(24 * 60),
    last_seen: isoMinutesAgo(overrides.minutesAgo ?? 1),
    call_count: 1,
    distinct_principal_count: 1,
    is_new: false,
    reviewed: false,
    reviewed_at: null,
    reviewed_by: null,
    covered_by_rule: false,
    latency: { count: 1, p50_ms: 10, p95_ms: 15, p99_ms: 20 },
    status_counts: [{ status: 200, count: 1 }],
    ...overrides,
  };
}

function previewSample(overrides) {
  return {
    event_id: 'evt-demo',
    timestamp: isoMinutesAgo(overrides.minutesAgo ?? 1),
    request_id: 'req-demo',
    source_ip: '203.0.113.24',
    user_agent: 'GreenGateway README demo',
    method: 'MCP',
    path: '/mcp/tools/repo.delete_file',
    actor: {
      user_id: 'github-actions[bot]',
      auth_mode: 'bearer_token',
      roles: ['ci-bot'],
    },
    status: 200,
    policy_decision: 'allow',
    matched_rule_id: null,
    ...overrides,
  };
}

function recentEvent(overrides) {
  return {
    id: 1,
    event_id: 'evt-demo',
    request_id: 'req-demo',
    timestamp: isoMinutesAgo(overrides.minutesAgo ?? 1),
    method: 'MCP',
    path: '/mcp/tools/repo.delete_file',
    status: 200,
    actor: null,
    ...overrides,
  };
}

async function json(route, value) {
  await route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(value),
  });
}

function isoMinutesAgo(minutes) {
  return new Date(Date.now() - minutes * 60_000).toISOString();
}

function jwtWithRoles(roles) {
  return [
    base64UrlJson({ alg: 'none', typ: 'JWT' }),
    base64UrlJson({ sub: 'readme-demo-operator', roles }),
    'signature',
  ].join('.');
}

function base64UrlJson(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function boxToRect(box) {
  return {
    x: box.x,
    y: box.y,
    width: box.width,
    height: box.height,
  };
}

function cursorPoint(box, placement) {
  if (placement === 'none') {
    return null;
  }
  if (placement === 'right') {
    return { x: box.x + box.width - 16, y: box.y + box.height / 2 };
  }
  return { x: box.x + box.width / 2, y: box.y + box.height / 2 };
}

async function assembleGif(manifestPath) {
  const python = process.env.PYTHON ?? 'python';
  await new Promise((resolve, reject) => {
    const child = spawn(python, ['-', manifestPath], {
      cwd: repoRoot,
      stdio: ['pipe', 'inherit', 'inherit'],
      windowsHide: true,
    });
    child.stdin.end(gifAssemblerPython);
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`GIF assembler exited with code ${code}`));
      }
    });
  });
}

const gifAssemblerPython = String.raw`
import json
import sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

manifest_path = Path(sys.argv[1])
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
target = (manifest["targetSize"]["width"], manifest["targetSize"]["height"])
output_path = Path(manifest["outputGif"])

def font(size, bold=False):
    candidates = [
        "C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf",
        "C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size)
        except Exception:
            pass
    return ImageFont.load_default()

title_font = font(22, bold=True)
caption_font = font(24, bold=True)
meta_font = font(16)

def wrap_text(draw, text, max_width, font_obj):
    words = text.split()
    lines = []
    current = ""
    for word in words:
        trial = word if current == "" else current + " " + word
        if draw.textbbox((0, 0), trial, font=font_obj)[2] <= max_width:
            current = trial
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines

def scale_box(box, source_size):
    sx = target[0] / source_size[0]
    sy = target[1] / source_size[1]
    return (
        int(box["x"] * sx),
        int(box["y"] * sy),
        int((box["x"] + box["width"]) * sx),
        int((box["y"] + box["height"]) * sy),
    )

def scale_point(point, source_size):
    sx = target[0] / source_size[0]
    sy = target[1] / source_size[1]
    return int(point["x"] * sx), int(point["y"] * sy)

def clamp(value, lower, upper):
    return max(lower, min(upper, value))

def ease_in_out(value):
    value = clamp(value, 0.0, 1.0)
    if value < 0.5:
        return 4 * value * value * value
    return 1 - pow(-2 * value + 2, 3) / 2

def ease_out(value):
    value = clamp(value, 0.0, 1.0)
    return 1 - pow(1 - value, 3)

def lerp(left, right, progress):
    return left + (right - left) * progress

def point_lerp(left, right, progress):
    return (
        int(lerp(left[0], right[0], progress)),
        int(lerp(left[1], right[1], progress)),
    )

def draw_cursor(draw, point):
    x, y = point
    shape = [
        (x, y),
        (x, y + 36),
        (x + 10, y + 27),
        (x + 18, y + 43),
        (x + 26, y + 39),
        (x + 18, y + 24),
        (x + 33, y + 23),
    ]
    draw.polygon(shape, fill=(255, 255, 255), outline=(20, 31, 23))

def draw_click_pulse(draw, point, progress):
    if progress < 0 or progress > 1:
        return
    alpha = int(210 * (1 - progress))
    radius = int(11 + 22 * progress)
    x, y = point
    draw.ellipse(
        (x - radius, y - radius, x + radius, y + radius),
        outline=(30, 145, 82, alpha),
        width=4,
    )

def draw_highlight(draw, entry, source_size, alpha_scale=1.0, pulse_progress=None):
    if not entry.get("highlight"):
        return
    rect = scale_box(entry["highlight"], source_size)
    pad = 8
    rect = (
        max(0, rect[0] - pad),
        max(0, rect[1] - pad),
        min(target[0] - 1, rect[2] + pad),
        min(target[1] - 1, rect[3] + pad),
    )
    fill_alpha = int(32 * alpha_scale)
    outline_alpha = int(255 * alpha_scale)
    width = 5
    if pulse_progress is not None:
        pulse = 1 - abs((pulse_progress % 1.0) * 2 - 1)
        fill_alpha = int((30 + 24 * pulse) * alpha_scale)
        outline_alpha = int((190 + 65 * pulse) * alpha_scale)
        width = int(4 + 2 * pulse)
    draw.rounded_rectangle(
        rect,
        radius=14,
        fill=(25, 117, 67, fill_alpha),
        outline=(30, 145, 82, outline_alpha),
        width=width,
    )

def draw_frame_chrome(draw, entry, index, total):
    header = "Demo 1: MCP RBAC in 5 minutes"
    draw.rounded_rectangle((18, 16, 518, 58), radius=11, fill=(7, 22, 13, 224))
    draw.text((34, 25), header, font=title_font, fill=(235, 250, 240, 255))
    draw.rounded_rectangle((target[0] - 96, 16, target[0] - 18, 58), radius=11, fill=(235, 250, 240, 230))
    draw.text((target[0] - 76, 27), f"{index}/{total}", font=meta_font, fill=(7, 22, 13, 255))

    bar_top = target[1] - 112
    draw.rectangle((0, bar_top, target[0], target[1]), fill=(4, 15, 9, 226))
    draw.rectangle((0, bar_top, target[0], bar_top + 4), fill=(45, 181, 99, 255))
    lines = wrap_text(draw, entry["caption"], target[0] - 64, caption_font)
    y = bar_top + 24
    for line in lines[:2]:
        draw.text((32, y), line, font=caption_font, fill=(244, 255, 248, 255))
        y += 31

def render_still(entry):
    source = Image.open(entry["imagePath"]).convert("RGB")
    source_size = source.size
    return source.resize(target, Image.Resampling.LANCZOS).convert("RGBA"), source_size

def cursor_target(entry, source_size):
    if not entry.get("cursor"):
        return None
    return scale_point(entry["cursor"], source_size)

def cursor_start(previous_entry, previous_source_size, target_point):
    previous_target = (
        cursor_target(previous_entry, previous_source_size)
        if previous_entry is not None
        else None
    )
    if previous_target is not None:
        return previous_target
    return (
        clamp(target_point[0] - 120, 22, target[0] - 60),
        clamp(target_point[1] - 90, 22, target[1] - 70),
    )

def render_animation_frame(
    entry,
    previous_entry,
    base_image,
    previous_base_image,
    source_size,
    previous_source_size,
    step_index,
    total_steps,
    elapsed_ms,
    segment_duration_ms,
    scene_number,
    scene_count,
):
    transition_ms = 500
    if previous_base_image is not None and elapsed_ms < transition_ms:
        alpha = ease_in_out(elapsed_ms / transition_ms)
        image = Image.blend(previous_base_image, base_image, alpha)
    else:
        image = base_image.copy()

    overlay = Image.new("RGBA", target, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    highlight_alpha = ease_out(min(elapsed_ms, 650) / 650)
    draw_highlight(
        draw,
        entry,
        source_size,
        alpha_scale=highlight_alpha,
        pulse_progress=elapsed_ms / 1200,
    )

    target_point = cursor_target(entry, source_size)
    if target_point is not None:
        travel_ms = min(900, max(500, int(segment_duration_ms * 0.28)))
        start_point = cursor_start(previous_entry, previous_source_size, target_point)
        progress = ease_out(elapsed_ms / travel_ms)
        current_point = point_lerp(start_point, target_point, progress)
        pulse_start = travel_ms + 100
        pulse_progress = (elapsed_ms - pulse_start) / 650
        draw_click_pulse(draw, target_point, pulse_progress)
        draw_cursor(draw, current_point)

    draw_frame_chrome(draw, entry, scene_number, scene_count)

    combined = Image.alpha_composite(image, overlay).convert("RGB")
    return combined.convert("P", palette=Image.Palette.ADAPTIVE, colors=96)

fps = 8
frame_ms = 1000 / fps
scene_count = len(manifest["frames"])
rendered = []
durations = []
previous_entry = None
previous_base_image = None
previous_source_size = None

for scene_index, entry in enumerate(manifest["frames"]):
    base_image, source_size = render_still(entry)
    duration = entry["durationMs"]
    steps = max(1, round(duration / frame_ms))
    duration_cs = duration // 10
    base_duration_cs = duration_cs // steps
    remainder_cs = duration_cs - base_duration_cs * steps
    for step_index in range(steps):
        elapsed_ms = int(duration * step_index / steps)
        rendered.append(
            render_animation_frame(
                entry=entry,
                previous_entry=previous_entry,
                base_image=base_image,
                previous_base_image=previous_base_image,
                source_size=source_size,
                previous_source_size=previous_source_size,
                step_index=step_index,
                total_steps=steps,
                elapsed_ms=elapsed_ms,
                segment_duration_ms=duration,
                scene_number=scene_index + 1,
                scene_count=scene_count,
            )
        )
        frame_duration_cs = base_duration_cs + (1 if step_index < remainder_cs else 0)
        durations.append(frame_duration_cs * 10)
    previous_entry = entry
    previous_base_image = base_image
    previous_source_size = source_size

frames = rendered
frames[0].save(
    output_path,
    save_all=True,
    append_images=frames[1:],
    duration=durations,
    loop=0,
    optimize=True,
    disposal=2,
)
`;

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
