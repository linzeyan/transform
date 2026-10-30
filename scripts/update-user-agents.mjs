#!/usr/bin/env node
// Refreshes the browser versions in wasm_core/data/user_agents.json from the
// vendors' own release feeds, so the User-Agent tool does not silently age.
//
// Usage: node scripts/update-user-agents.mjs   (or `make update-user-agents`)
// Needs: Node 18+ (global fetch) and network access. No npm dependencies, so
// CI can run it on the runner's preinstalled Node without an install step.
//
// The data file has two arrays:
// - "automated": rebuilt from scratch on every run from the templates below.
//   Hand edits there are overwritten; change the template instead.
// - "manual": copied through untouched. Safari, Vivaldi and Yandex live here
//   because none of them publishes a stable-version API: Safari ships with the
//   OS (release notes only), Vivaldi has a per-OS Sparkle appcast, Yandex a
//   Linux apt repo. Update them by hand when a major lands.
//
// Strings follow what the browsers really send, not what they could send:
// - Chrome/Edge apply UA reduction: minor version frozen to 0.0.0, platform
//   frozen per OS, Android always "Android 10; K".
//   https://www.chromium.org/updates/ua-reduction/
//   https://learn.microsoft.com/en-us/microsoft-edge/web-platform/user-agent-guidance
// - Firefox reports "<major>.0" and caps macOS at 10.15.
//   https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/User-Agent/Firefox
// Because only the major is visible, the stored version is the one in the
// string ("156.0.0.0", "159.0"). Storing the full build would turn every
// weekly patch release into a PR whose user-agent strings did not change.
//
// Idempotent: the file is rewritten only when its serialized content changes.

import { readFile, writeFile } from 'node:fs/promises';

const DATA = new URL('../wasm_core/data/user_agents.json', import.meta.url);
const TIMEOUT_MS = 30_000;

// Frozen platform tokens per the UA-reduction spec; Chrome and Edge share them.
const CHROMIUM_PLATFORMS = {
    windows: { token: 'Windows NT 10.0; Win64; x64', osVersion: '10' },
    macos: { token: 'Macintosh; Intel Mac OS X 10_15_7', osVersion: '10.15.7' },
    linux: { token: 'X11; Linux x86_64', osVersion: 'x86_64' },
    android: { token: 'Linux; Android 10; K', osVersion: '10' },
};

const FIREFOX_PLATFORMS = {
    windows: { token: 'Windows NT 10.0; Win64; x64', osVersion: '10' },
    macos: { token: 'Macintosh; Intel Mac OS X 10.15', osVersion: '10.15' },
};

async function getJson(url) {
    const res = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
    return res.json();
}

function major(version, source) {
    const m = /^(\d+)\./.exec(String(version ?? ''));
    if (!m) throw new Error(`${source}: unexpected version ${JSON.stringify(version)}`);
    return Number(m[1]);
}

// A staged rollout serves several builds at once; the highest one is the
// version a freshly updated browser reports.
function highestMajor(versions, source) {
    if (!versions.length) throw new Error(`${source}: no stable version listed`);
    return Math.max(...versions.map((v) => major(v, source)));
}

// Stable also serves the next major to ~0.5% of users a week early ("early
// stable"), so the highest version is not what users send. Weight each major by
// the share of users it is served to and take the dominant one.
async function chromeMajor(platform) {
    const source = `chrome ${platform}`;
    const url = `https://versionhistory.googleapis.com/v1/chrome/platforms/${platform}/channels/stable/versions/all/releases?filter=endtime=none`;
    const body = await getJson(url);
    const share = new Map();
    for (const r of body.releases ?? []) {
        const m = major(r.version, source);
        share.set(m, (share.get(m) ?? 0) + Number(r.fraction ?? 0));
    }
    if (!share.size) throw new Error(`${source}: no stable version listed`);
    return [...share].reduce((best, cur) => (cur[1] > best[1] ? cur : best))[0];
}

async function firefoxMajor() {
    const body = await getJson('https://product-details.mozilla.org/1.0/firefox_versions.json');
    return major(body.LATEST_FIREFOX_VERSION, 'firefox');
}

async function edgeMajors() {
    const products = await getJson('https://edgeupdates.microsoft.com/api/products');
    const stable = products.find((p) => p.Product === 'Stable');
    if (!stable) throw new Error('edge: no Stable product');
    // macOS lists the previous build next to the current one, so take the max.
    const pick = (platform, arch) =>
        highestMajor(
            stable.Releases.filter((r) => r.Platform === platform && r.Architecture === arch).map(
                (r) => r.ProductVersion
            ),
            `edge ${platform}`
        );
    return { windows: pick('Windows', 'x64'), macos: pick('MacOS', 'universal') };
}

function chromiumUA(platform, chromeMajor, suffix) {
    const mobile = platform === CHROMIUM_PLATFORMS.android ? 'Mobile ' : '';
    return `Mozilla/5.0 (${platform.token}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeMajor}.0.0.0 ${mobile}Safari/537.36${suffix}`;
}

function automatedEntries({ chrome, firefox, edge }) {
    const entries = [];
    for (const [os, platform] of Object.entries(CHROMIUM_PLATFORMS)) {
        const version = `${chrome[os]}.0.0.0`;
        entries.push({
            userAgent: chromiumUA(platform, chrome[os], ''),
            browserName: 'chrome',
            browserVersion: version,
            osName: os,
            osVersion: platform.osVersion,
            engineName: 'Blink',
            engineVersion: version,
        });
    }
    for (const [os, platform] of Object.entries(FIREFOX_PLATFORMS)) {
        const version = `${firefox}.0`;
        entries.push({
            userAgent: `Mozilla/5.0 (${platform.token}; rv:${version}) Gecko/20100101 Firefox/${version}`,
            browserName: 'firefox',
            browserVersion: version,
            osName: os,
            osVersion: platform.osVersion,
            engineName: 'Gecko',
            engineVersion: version,
        });
    }
    for (const os of ['windows', 'macos']) {
        const platform = CHROMIUM_PLATFORMS[os];
        const version = `${edge[os]}.0.0.0`;
        // Edge's Chromium major always equals its own major.
        entries.push({
            userAgent: chromiumUA(platform, edge[os], ` Edg/${version}`),
            browserName: 'edge',
            browserVersion: version,
            osName: os,
            osVersion: platform.osVersion,
            engineName: 'Blink',
            engineVersion: version,
        });
    }
    return entries;
}

async function main() {
    const before = await readFile(DATA, 'utf8');
    const data = JSON.parse(before);
    if (!Array.isArray(data.manual)) throw new Error('user_agents.json: missing "manual" array');

    const [win, mac, linux, android, firefox, edge] = await Promise.all([
        chromeMajor('win'),
        chromeMajor('mac'),
        chromeMajor('linux'),
        chromeMajor('android'),
        firefoxMajor(),
        edgeMajors(),
    ]);
    const chrome = { windows: win, macos: mac, linux, android };
    console.log(`chrome ${JSON.stringify(chrome)} firefox ${firefox} edge ${JSON.stringify(edge)}`);

    const after =
        JSON.stringify(
            { automated: automatedEntries({ chrome, firefox, edge }), manual: data.manual },
            null,
            2
        ) + '\n';
    if (after === before) {
        console.log('user_agents.json unchanged');
        return;
    }
    await writeFile(DATA, after);
    const old = new Set((data.automated ?? []).map((e) => e.userAgent));
    for (const e of JSON.parse(after).automated) {
        if (!old.has(e.userAgent)) console.log(`updated: ${e.userAgent}`);
    }
}

main().catch((err) => {
    console.error(err.message ?? err);
    process.exit(1);
});
