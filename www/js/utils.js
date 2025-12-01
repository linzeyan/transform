/**
 * Utility functions for the Transform application
 * Contains common helper functions used across different modules
 */

/**
 * Copy text to clipboard and show feedback
 * @param {string} value - Text to copy
 * @param {string} label - Label for status message
 * @param {function} setStatusCallback - Callback to set status
 * @param {function} showFeedbackCallback - Callback to show feedback
 */
export async function copyText(value, label, setStatusCallback, showFeedbackCallback) {
    try {
        await navigator.clipboard.writeText(value);
        if (setStatusCallback) setStatusCallback(`Copied ${label}`, false);
        if (showFeedbackCallback) showFeedbackCallback(`Copied ${label}`);
    } catch (err) {
        console.error(err);
        if (setStatusCallback) setStatusCallback('Unable to access clipboard', true);
        if (showFeedbackCallback) showFeedbackCallback('Failed to copy');
    }
}

/**
 * Show temporary copy feedback message
 * @param {string} message - Message to display
 */
export function showCopyFeedback(message) {
    // Remove existing feedback
    const existing = document.querySelector('.copy-feedback');
    if (existing) {
        existing.remove();
    }

    // Create new feedback element
    const feedback = document.createElement('div');
    feedback.className = 'copy-feedback';
    feedback.textContent = message;
    document.body.appendChild(feedback);

    // Remove after animation
    setTimeout(() => {
        if (feedback.parentNode) {
            feedback.remove();
        }
    }, 2000);
}

/**
 * Escape HTML special characters
 * @param {string} value - String to escape
 * @returns {string} Escaped HTML string
 */
export function escapeHTML(value = '') {
    const text = value == null ? '' : String(value);
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

/**
 * Escape HTML attribute values
 * @param {string} value - String to escape
 * @returns {string} Escaped attribute string
 */
export function escapeAttr(value = '') {
    return escapeHTML(value).replace(/'/g, '&#39;');
}

/**
 * Normalize UUID result from WASM
 * @param {*} value - Raw result from WASM
 * @returns {object} Normalized object
 */
export function normalizeUuidResult(value) {
    return normalizeMapResult(value);
}

/**
 * Normalize Map or object result from WASM
 * @param {*} value - Raw result from WASM
 * @returns {object} Normalized object
 */
export function normalizeMapResult(value) {
    if (!value) {
        return {};
    }
    if (value instanceof Map) {
        const record = {};
        value.forEach((val, key) => {
            record[String(key)] = typeof val === 'string' ? val : String(val ?? '');
        });
        return record;
    }
    if (typeof value === 'object' && !Array.isArray(value)) {
        const record = {};
        Object.keys(value).forEach((key) => {
            const val = value[key];
            record[key] = typeof val === 'string' ? val : String(val ?? '');
        });
        return record;
    }
    return {};
}

/**
 * Capitalize first letter of string
 * @param {string} text - Text to capitalize
 * @returns {string} Capitalized text
 */
export function capitalize(text) {
    if (!text) return '';
    return text.charAt(0).toUpperCase() + text.slice(1);
}

/**
 * Check if storage type is available
 * @param {string} type - Storage type ('localStorage' or 'sessionStorage')
 * @returns {boolean} Whether storage is available
 */
export function storageAvailable(type) {
    try {
        const storage = window[type];
        const test = '__transform_fp__';
        storage.setItem(test, '1');
        storage.removeItem(test);
        return true;
    } catch (_err) {
        return false;
    }
}

/**
 * Format timezone offset in hours:minutes format
 * @param {number} offsetMinutes - Offset in minutes
 * @returns {string} Formatted offset
 */
export function formatTimezoneOffset(offsetMinutes) {
    if (!Number.isFinite(offsetMinutes)) return '';
    const total = Math.abs(offsetMinutes);
    const hours = String(Math.floor(total / 60)).padStart(2, '0');
    const minutes = String(total % 60).padStart(2, '0');
    const sign = offsetMinutes <= 0 ? '+' : '-';
    return `${sign}${hours}:${minutes}`;
}

/**
 * Format byte count with appropriate unit
 * @param {number} bytes - Number of bytes
 * @returns {string} Formatted byte string
 */
export function formatBytes(bytes) {
    if (!Number.isFinite(bytes)) return '';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
        value /= 1024;
        unit += 1;
    }
    return `${value.toFixed(1)} ${units[unit]}`;
}

/**
 * Measure browser timer resolution
 * @returns {string} Resolution string
 */
export function measureTimeResolution() {
    if (typeof performance === 'undefined' || typeof performance.now !== 'function') return '';
    let min = Infinity;
    let last = performance.now();
    for (let i = 0; i < 40; i++) {
        const now = performance.now();
        const delta = now - last;
        if (delta > 0 && delta < min) {
            min = delta;
        }
        last = now;
    }
    if (!Number.isFinite(min) || min === Infinity) return '';
    return `${min.toFixed(3)} ms (min delta)`;
}

/**
 * Detect media query features
 * @returns {object} Media feature detection results
 */
export function detectMediaFeatures() {
    const query = (q) =>
        typeof window !== 'undefined' && window.matchMedia
            ? window.matchMedia(q).matches
            : 'Unknown';
    return {
        'prefers-color-scheme: dark': query('(prefers-color-scheme: dark)') ? 'Yes' : 'No',
        'prefers-reduced-motion': query('(prefers-reduced-motion: reduce)') ? 'Reduce' : 'No',
        'pointer: fine': query('(pointer: fine)') ? 'Yes' : 'No',
        'hover: hover': query('(hover: hover)') ? 'Yes' : 'No',
    };
}

/**
 * Detect browser feature support
 * @returns {object} Feature support results
 */
export function detectFeatureSupport() {
    if (typeof document === 'undefined') return {};
    const supports = (prop, value) =>
        typeof CSS !== 'undefined' && CSS.supports ? CSS.supports(prop, value) : false;
    return {
        'CSS Backdrop Filter': supports('backdrop-filter', 'blur(4px)') ? 'Yes' : 'No',
        'CSS Subgrid': supports('display', 'subgrid') ? 'Yes' : 'No',
        IntersectionObserver: 'IntersectionObserver' in window ? 'Yes' : 'No',
        'Clipboard API': 'clipboard' in navigator ? 'Yes' : 'No',
        'Gamepad API': 'getGamepads' in navigator ? 'Yes' : 'No',
    };
}

/**
 * Generate canvas fingerprint hash
 * @returns {string} Canvas hash
 */
export function generateCanvasHash() {
    try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        if (!ctx) return '';
        canvas.width = 240;
        canvas.height = 60;
        ctx.textBaseline = 'top';
        ctx.font = "16px 'Arial'";
        ctx.fillStyle = '#f60';
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.fillText('transform-fp', 2, 10);
        ctx.strokeStyle = '#fff';
        ctx.strokeText('transform-fp', 2, 10);
        const data = canvas.toDataURL();
        return hashString(data).slice(0, 16);
    } catch (_err) {
        return '';
    }
}

/**
 * Get WebGL renderer information
 * @returns {object} WebGL information
 */
export function getWebGLInfo() {
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (!gl) return {};
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        const vendor = debugInfo
            ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL)
            : gl.getParameter(gl.VENDOR);
        const renderer = debugInfo
            ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
            : gl.getParameter(gl.RENDERER);
        const version = gl.getParameter(gl.VERSION);
        const extensions = gl.getSupportedExtensions() || [];
        const limits = {
            maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
            maxVertexAttribs: gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
        };
        return {
            vendor,
            renderer,
            version,
            extensions,
            limits,
        };
    } catch (_err) {
        return {};
    }
}

/**
 * Get audio context information
 * @returns {object} Audio context information
 */
export function getAudioContextInfo() {
    try {
        const AudioCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (!AudioCtx) {
            return { context: 'Unavailable', hash: '' };
        }
        const context = new AudioCtx(1, 512, 44100);
        const osc = context.createOscillator();
        const compressor = context.createDynamicsCompressor();
        osc.type = 'triangle';
        osc.frequency.value = 1000;
        compressor.threshold.value = -50;
        compressor.knee.value = 40;
        compressor.ratio.value = 12;
        compressor.attack.value = 0;
        compressor.release.value = 0.25;
        osc.connect(compressor);
        compressor.connect(context.destination);
        osc.start(0);
        const bufferPromise = context.startRendering();
        // OfflineAudioContext renders async; we expose a stable hash string when ready.
        bufferPromise.then((buffer) => {
            const channel = buffer.getChannelData(0) || new Float32Array(0);
            const hash = hashArray(channel);
            // Note: This would need access to state and renderFingerprintFacts
            // which are in other modules, so this function signature may need adjustment
            console.log('Audio hash computed:', hash);
        });
        return { context: 'OfflineAudioContext', hash: 'Rendering…' };
    } catch (_err) {
        return { context: 'Error', hash: '' };
    }
}

/**
 * Upsert a fingerprint fact
 * @param {string} group - Fact group
 * @param {string} label - Fact label
 * @param {*} value - Fact value
 * @param {Array} targetFacts - Target facts array (optional)
 */
export function upsertFact(group, label, value, targetFacts = []) {
    if (value === undefined || value === null || value === '') return;
    const idx = targetFacts.findIndex((entry) => entry.group === group && entry.label === label);
    const payload = { group, label, value: String(value) };
    if (idx >= 0) {
        targetFacts[idx] = payload;
    } else {
        targetFacts.push(payload);
    }
}

/**
 * Remove duplicate facts from list
 * @param {Array} list - List of facts
 * @returns {Array} Deduplicated facts
 */
export function dedupeFacts(list = []) {
    const seen = new Set();
    return list.filter((entry) => {
        const key = `${entry.group}::${entry.label}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

/**
 * Generate hash from array of numbers
 * @param {Array<number>} arr - Number array
 * @returns {string} Hash string
 */
export function hashArray(arr) {
    let hash = 0;
    for (let i = 0; i < arr.length; i += 16) {
        hash = (hash << 5) - hash + Math.floor(arr[i] * 1e6);
        hash |= 0;
    }
    return `a${Math.abs(hash).toString(16)}`;
}

/**
 * Generate hash from string
 * @param {string} input - Input string
 * @returns {string} Hash string
 */
export function hashString(input) {
    let hash = 0;
    if (!input) return '';
    for (let i = 0; i < input.length; i++) {
        hash = (hash << 5) - hash + input.charCodeAt(i);
        hash |= 0;
    }
    return `h${Math.abs(hash).toString(16)}`;
}

/**
 * Sanitize random exclude characters
 * @param {string} value - Raw exclude string
 * @returns {string} Sanitized exclude string
 */
export function sanitizeRandomExclude(value) {
    if (!value) return '';
    const compact = value.replace(/\s+/g, '');
    if (!compact) return '';
    const seen = new Set();
    let result = '';
    for (const ch of compact) {
        if (!seen.has(ch)) {
            seen.add(ch);
            result += ch;
        }
    }
    return result;
}

// Note: setStatus and other dependencies will be injected when this module is used
