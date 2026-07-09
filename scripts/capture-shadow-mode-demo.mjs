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
const outputGif = path.join(repoRoot, 'docs', 'images', 'demo-shadow-mode.gif');
const port = process.env.GG_SHADOW_DEMO_PORT ?? '43183';
const baseUrl = `http://127.0.0.1:${port}`;
const adminUrl = `${baseUrl}/admin`;
const adminRequire = createRequire(path.join(adminUiDir, 'package.json'));
const { chromium } = adminRequire('playwright');

const viewport = { width: 1440, height: 900 };
const targetSize = { width: 960, height: 600 };
const frameDurationsMs = [4000, 3500, 4000, 4500, 5000, 4500, 4500];
const adminTokenStorageKey = 'greengateway_admin_token';

async function main() {
  await mkdir(path.dirname(outputGif), { recursive: true });
  const framesDir = await mkdtemp(path.join(os.tmpdir(), 'gg-shadow-demo-'));
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
      name: 'traffic-learning',
      caption:
        'GreenGateway learns API traffic: methods, endpoint shapes, volume, principals, coverage, and open signals.',
      locator: trafficTable,
      cursorAt: 'none',
    });

    const createRuleButton = page.getByRole('button', {
      name: 'Create rule for GET /api/orders/{order_id}',
    });
    await capture({
      name: 'traffic-create-rule',
      caption:
        'Uncovered traffic becomes a rule candidate. Operators can draft policy from the observed endpoint.',
      locator: createRuleButton,
    });

    await createRuleButton.click();
    await page.waitForURL(/\/admin\/policy\/rules\/editor/);
    await page.waitForSelector('text=Create policy rule');
    await capture({
      name: 'editor-prefilled',
      caption:
        'The visual editor is prefilled from real traffic, including the HTTP method and path pattern.',
      locator: page.locator('.rule-form').first(),
      cursorAt: 'none',
    });

    await page.getByRole('combobox', { name: 'Role constraints' }).fill('support');
    await page.getByRole('button', { name: 'Add role' }).click();
    await page.getByLabel('Bearer token').check();
    await page.getByRole('textbox', { name: 'Principal IDs' }).fill('support-lee');
    await page.getByRole('button', { name: 'Add principal ID' }).click();
    await page.getByRole('radio', { name: /Shadow/ }).check();
    await page.waitForSelector('text=Log-only GET requests to /api/orders/{order_id}');
    await page.evaluate(() => {
      window.scrollBy(0, 180);
    });

    await capture({
      name: 'editor-shadow',
      caption:
        'Shadow mode forwards matching requests but records a would-deny decision for review.',
      locator: page.getByRole('radio', { name: /Shadow/ }),
    });

    await page.waitForSelector('.rule-preview-stat .stat-value');
    await page.evaluate(() => {
      window.scrollTo(0, 0);
    });
    await capture({
      name: 'preview-impact',
      caption:
        'Before enforcement, the live preview scans historical traffic and shows the exact requests that would match.',
      locator: page.locator('.rule-preview-panel'),
      cursorAt: 'none',
    });

    await page.goto(`${adminUrl}/policy/shadow-review`);
    await page.waitForSelector('text=Shadow review queue');
    await capture({
      name: 'shadow-review',
      caption:
        'The shadow review queue shows would-deny counts, affected principals, and sample requests.',
      locator: page.locator('.shadow-review-list'),
      cursorAt: 'none',
    });

    const promoteButton = page.getByRole('button', {
      name: 'Promote shadow-report-deletes to deny',
    });
    await promoteButton.click();
    await page.waitForSelector('text=Confirm');
    await capture({
      name: 'promote-when-ready',
      caption:
        'When the preview is acceptable, promote the shadow rule to deny or disable it without editing JSON.',
      locator: page.getByRole('button', {
        name: 'Confirm promote shadow-report-deletes to deny',
      }),
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
    if (process.env.GG_SHADOW_DEMO_VERBOSE === '1') {
      process.stdout.write(chunk);
    }
  });
  child.stderr.on('data', (chunk) => {
    if (process.env.GG_SHADOW_DEMO_VERBOSE === '1') {
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
  await page.route('**/version', async (route) => {
    await json(route, { admin_login_configured: false });
  });

  await page.route('**/v1/admin/policy/rules/preview', async (route) => {
    await json(route, {
      match_count: 31,
      scanned_event_count: 416,
      sample_strategy: 'newest_matches',
      samples: [
        previewSample({
          event_id: 'evt-orders-shadow-31',
          request_id: 'req-orders-31',
          minutesAgo: 3,
          path: '/api/orders/ord_9842',
          actor: { user_id: 'support-lee', auth_mode: 'bearer_token', roles: ['support'] },
          status: 200,
          policy_decision: 'allow',
          matched_rule_id: 'support-orders-read',
        }),
        previewSample({
          event_id: 'evt-orders-shadow-30',
          request_id: 'req-orders-30',
          minutesAgo: 8,
          path: '/api/orders/ord_9801',
          actor: { user_id: 'support-jules', auth_mode: 'bearer_token', roles: ['support'] },
          status: 200,
          policy_decision: 'allow',
          matched_rule_id: 'support-orders-read',
        }),
      ],
    });
  });

  await page.route('**/v1/admin/policy/rules/shadow-review', async (route) => {
    await json(route, {
      scanned_event_count: 416,
      scan_truncated: false,
      rules: [
        {
          rule_id: 'shadow-report-deletes',
          rule: {
            id: 'shadow-report-deletes',
            enabled: true,
            methods: ['DELETE'],
            path: '/reports/**',
            principal: { roles: ['analyst'] },
            action: 'shadow',
          },
          would_deny_count: 28,
          affected_principals: [
            { user_id: 'analyst-ada', roles: ['analyst'] },
            { user_id: 'ops-mira', roles: ['ops', 'analyst'] },
          ],
          samples: [
            shadowSample({
              event_id: 'sample-report-delete',
              minutesAgo: 7,
              method: 'DELETE',
              path: '/reports/quarterly/42',
              actor: {
                user_id: 'analyst-ada',
                roles: ['analyst'],
                auth_mode: 'bearer_token',
              },
            }),
          ],
        },
        {
          rule_id: 'shadow-admin-posts',
          rule: {
            id: 'shadow-admin-posts',
            enabled: true,
            methods: ['POST', 'PATCH'],
            path: '/admin/**',
            principal: { roles: ['support'] },
            action: 'shadow',
          },
          would_deny_count: 7,
          affected_principals: [
            { user_id: 'support-jules', roles: ['support'] },
            { user_id: 'support-lee', roles: ['support', 'tier2'] },
          ],
          samples: [
            shadowSample({
              event_id: 'sample-admin-patch',
              minutesAgo: 17,
              method: 'PATCH',
              path: '/admin/users/117',
              actor: {
                user_id: 'support-lee',
                roles: ['support', 'tier2'],
                auth_mode: 'bearer_token',
              },
            }),
          ],
        },
      ],
    });
  });

  await page.route('**/v1/admin/policy/rules/hits', async (route) => {
    await json(route, {
      rules: [
        { rule_id: 'support-orders-read', hits: 1258 },
        { rule_id: 'shadow-report-deletes', hits: 28 },
        { rule_id: 'shadow-admin-posts', hits: 7 },
      ],
    });
  });

  await page.route('**/v1/admin/traffic/endpoints?**', async (route) => {
    await json(route, {
      endpoints: [
        trafficEndpoint({
          method: 'GET',
          endpoint_template: '/api/orders/{order_id}',
          call_count: 1284,
          distinct_principal_count: 31,
          minutesAgo: 3,
          is_new: true,
          reviewed: false,
          covered_by_rule: false,
          open_signals: {
            count: 2,
            signal_types: ['schema_mismatch', 'principal_new_to_endpoint'],
          },
          latency: { count: 1284, p50_ms: 18, p95_ms: 46, p99_ms: 88 },
          status_counts: [
            { status: 200, count: 1221 },
            { status: 404, count: 44 },
            { status: 500, count: 19 },
          ],
        }),
        trafficEndpoint({
          method: 'POST',
          endpoint_template: '/api/payments/authorize',
          call_count: 412,
          distinct_principal_count: 8,
          minutesAgo: 6,
          is_new: false,
          reviewed: true,
          reviewed_at: isoMinutesAgo(5),
          reviewed_by: 'ops-admin',
          covered_by_rule: true,
          latency: { count: 412, p50_ms: 36, p95_ms: 92, p99_ms: 131 },
          status_counts: [
            { status: 201, count: 399 },
            { status: 409, count: 13 },
          ],
        }),
        trafficEndpoint({
          method: 'DELETE',
          endpoint_template: '/reports/**',
          call_count: 61,
          distinct_principal_count: 5,
          minutesAgo: 9,
          is_new: true,
          reviewed: false,
          covered_by_rule: false,
          open_signals: { count: 1, signal_types: ['volume_outlier'] },
          latency: { count: 61, p50_ms: 24, p95_ms: 71, p99_ms: 110 },
          status_counts: [
            { status: 200, count: 55 },
            { status: 403, count: 6 },
          ],
        }),
      ],
      next_cursor: null,
    });
  });

  await page.route('**/v1/admin/policy', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: { ETag: '"demo-shadow-policy-etag"' },
      body: JSON.stringify(policyDocument()),
    });
  });

  await page.route('**/v1/admin/policy/rules/*', async (route) => {
    if (route.request().method() !== 'PATCH') {
      await route.fallback();
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: { ETag: '"demo-shadow-policy-etag-2"' },
      body: JSON.stringify({
        id: 'shadow-report-deletes',
        enabled: true,
        methods: ['DELETE'],
        path: '/reports/**',
        principal: { roles: ['analyst'] },
        action: 'deny',
      }),
    });
  });
}

function policyDocument() {
  return {
    schema_version: '0.1.0',
    id: 'demo-shadow-policy',
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
      support: { permissions: ['orders:read'] },
      analyst: { permissions: ['reports:read'] },
    },
    routes: [],
    rules: [
      {
        id: 'support-orders-read',
        enabled: true,
        methods: ['GET'],
        path: '/api/orders/{order_id}',
        principal: { roles: ['support'], auth_methods: ['bearer_token'] },
        action: 'allow',
      },
      {
        id: 'shadow-report-deletes',
        enabled: true,
        methods: ['DELETE'],
        path: '/reports/**',
        principal: { roles: ['analyst'] },
        action: 'shadow',
      },
      {
        id: 'shadow-admin-posts',
        enabled: true,
        methods: ['POST', 'PATCH'],
        path: '/admin/**',
        principal: { roles: ['support'] },
        action: 'shadow',
      },
    ],
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
    method: 'GET',
    path: '/api/orders/ord_demo',
    actor: { user_id: 'support-lee', auth_mode: 'bearer_token', roles: ['support'] },
    status: 200,
    policy_decision: 'allow',
    matched_rule_id: null,
    ...overrides,
  };
}

function shadowSample(overrides) {
  return {
    event_id: 'sample-demo',
    timestamp: isoMinutesAgo(overrides.minutesAgo ?? 1),
    method: 'DELETE',
    path: '/reports/demo',
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
    header = "Demo 2: Shadow mode for API firewall rules"
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
