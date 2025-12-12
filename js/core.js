/**
 * Core application functionality
 * Handles initialization, UI setup, and basic state management
 */

// WASM imports will be handled by main.js

import { workspaceByTool, implementedTools, toolGroups, workspaceIds } from './constants.js';

import { state, elements } from './state.js';

// Global error handler to suppress Cursor IDE extension errors
window.addEventListener('error', (event) => {
    // Suppress specific Cursor IDE extension errors related to form control detection
    if (
        event.error &&
        event.error.message &&
        event.error.message.includes("Cannot read properties of undefined (reading 'control')") &&
        event.filename &&
        event.filename.includes('content_script.js')
    ) {
        event.preventDefault();
        console.warn('Suppressed Cursor IDE extension error:', event.error.message);
        return false;
    }
});

// Suppress unhandled promise rejections from Cursor IDE extension
window.addEventListener('unhandledrejection', (event) => {
    if (
        event.reason &&
        event.reason.message &&
        event.reason.message.includes("Cannot read properties of undefined (reading 'control')")
    ) {
        event.preventDefault();
        console.warn('Suppressed Cursor IDE extension promise rejection:', event.reason.message);
    }
});

/**
 * Set application status message
 * @param {string} message - Status message
 * @param {boolean} isError - Whether this is an error message
 */
export function setStatus(message, isError) {
    if (!elements.status) return;
    elements.status.textContent = message;
    elements.status.className = isError ? 'status-error' : 'status-ok';
}

/**
 * Toggle sidebar visibility
 */
export function toggleSidebar() {
    if (!elements.sidebar) return;
    const isOpen = elements.sidebar.classList.contains('open');
    if (isOpen) {
        closeSidebar();
    } else {
        openSidebar();
    }
}

/**
 * Open sidebar
 */
function openSidebar() {
    if (!elements.sidebar) return;
    elements.sidebar.classList.add('open');
    elements.sidebarBackdrop?.classList.add('visible');
    document.body.style.overflow = 'hidden';
}

/**
 * Close sidebar
 */
export function closeSidebar() {
    if (!elements.sidebar) return;
    elements.sidebar.classList.remove('open');
    elements.sidebarBackdrop?.classList.remove('visible');
    document.body.style.overflow = '';
}

/**
 * Toggle sidebar collapse state
 */
export function toggleSidebarCollapse() {
    if (!elements.sidebar) return;
    elements.sidebar.classList.toggle('collapsed');
}

/**
 * Close sidebar on mobile
 */
export function closeSidebarOnMobile() {
    if (window.innerWidth <= 768) {
        closeSidebar();
    }
}

/**
 * Cache DOM elements for performance
 */
export function cacheElements() {
    elements.sidebar = document.getElementById('sidebar');
    elements.sidebarToggle = document.getElementById('sidebarToggle');
    elements.sidebarCollapseBtn = document.getElementById('sidebarCollapseBtn');
    elements.sidebarBackdrop = document.getElementById('sidebarBackdrop');
    elements.toolGroups = document.getElementById('toolGroups');
    elements.toolName = document.getElementById('toolName');
    elements.toolDesc = document.getElementById('toolDesc');
    elements.converterControls = document.getElementById('converterControls');
    elements.from = document.getElementById('fromSelect');
    elements.to = document.getElementById('toSelect');
    elements.swap = document.getElementById('swap');
    elements.input = document.getElementById('input');
    elements.output = document.getElementById('output');
    elements.copy = document.getElementById('copy');
    elements.clear = document.getElementById('clear');
    elements.formatInput = document.getElementById('formatInput');
    elements.minifyInput = document.getElementById('minifyInput');
    elements.formatOutput = document.getElementById('formatOutput');
    elements.minifyOutput = document.getElementById('minifyOutput');
    elements.status = document.getElementById('status');

    // Defensive fix for Cursor IDE extension compatibility
    setTimeout(() => {
        const formElements = document.querySelectorAll('input, select, textarea');
        formElements.forEach((element) => {
            if (!element.control) {
                element.control = element; // Self-reference for compatibility
            }
            // Ensure proper form association
            if (!element.form && element.closest('form')) {
                element.form = element.closest('form');
            }
        });
    }, 100);

    // Core workspace elements
    elements.imageWorkspace = document.getElementById('imageWorkspace');
    elements.coderWorkspace = document.getElementById('coderWorkspace');
    elements.pairWorkspace = document.getElementById('pairWorkspace');
    elements.numberWorkspace = document.getElementById('numberWorkspace');
    elements.unitWorkspace = document.getElementById('unitWorkspace');
    elements.ipv4Workspace = document.getElementById('ipv4Workspace');
    elements.uuidList = document.getElementById('uuidList');
    elements.uaResults = document.getElementById('uaResults');
    elements.randomWorkspace = document.getElementById('randomWorkspace');
    elements.qrWorkspace = document.getElementById('qrWorkspace');
    elements.totpWorkspace = document.getElementById('totpWorkspace');
    elements.dataWorkspace = document.getElementById('dataWorkspace');
    elements.sshWorkspace = document.getElementById('sshWorkspace');
    elements.fingerprintWorkspace = document.getElementById('fingerprintWorkspace');
    elements.certWorkspace = document.getElementById('certWorkspace');
    elements.cryptoWorkspace = document.getElementById('cryptoWorkspace');
    elements.kdfWorkspace = document.getElementById('kdfWorkspace');
    elements.diffWorkspace = document.getElementById('diffWorkspace');
    elements.timestampWorkspace = document.getElementById('timestampWorkspace');
}

/**
 * Render the sidebar with tool groups and buttons
 */
export function renderSidebar() {
    if (!elements.toolGroups) return;
    elements.toolGroups.innerHTML = '';

    toolGroups.forEach((group) => {
        const details = document.createElement('details');
        details.open = true;
        const summary = document.createElement('summary');
        const iconSpan = document.createElement('span');
        iconSpan.className = 'group-icon';
        iconSpan.textContent = group.icon;
        const textSpan = document.createElement('span');
        textSpan.className = 'group-text';
        textSpan.textContent = group.name;
        summary.appendChild(iconSpan);
        summary.appendChild(textSpan);
        details.appendChild(summary);
        const wrapper = document.createElement('div');
        wrapper.className = 'tool-buttons';
        group.tools.forEach((tool) => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.dataset.toolId = tool.id;
            btn.textContent = tool.label;
            btn.addEventListener('click', () => {
                selectTool(tool.id);
                closeSidebar();
            });
            wrapper.appendChild(btn);
        });
        details.appendChild(wrapper);
        elements.toolGroups.appendChild(details);
    });
    updateToolButtons();
}

/**
 * Initialize coder controls with encoding variants
 */
export function initCoderControls() {
    // This will be implemented when we extract coder functions
    console.log('Coder controls initialization placeholder');
}

/**
 * Update tool button states based on current tool
 */
export function updateToolButtons() {
    const buttons = elements.toolGroups?.querySelectorAll('button[data-tool-id]');
    if (!buttons) return;

    buttons.forEach((btn) => {
        const toolId = btn.dataset.toolId;
        if (toolId === state.currentTool) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });
}

/**
 * Select and activate a tool
 * @param {string} toolId - Tool ID to select
 */
export function selectTool(toolId) {
    if (!implementedTools.has(toolId)) return;

    state.currentTool = toolId;
    updateBodyClasses(toolId);
    showWorkspace(workspaceByTool[toolId]);

    // Update tool info display
    const toolInfo = getToolInfo(toolId);
    if (elements.toolName) elements.toolName.textContent = toolInfo.label;
    if (elements.toolDesc) elements.toolDesc.textContent = toolInfo.description;

    updateToolButtons();

    // Tool-specific initialization will be handled by respective modules
    console.log('Selected tool:', toolId);
}

/**
 * Update body classes based on current tool
 * @param {string} toolId - Current tool ID
 */
export function updateBodyClasses(toolId) {
    document.body.className = `tool-${toolId}`;
}

/**
 * Show a specific workspace
 * @param {string} workspaceId - Workspace ID to show
 */
export function showWorkspace(workspaceId) {
    // Hide all workspaces
    workspaceIds.forEach((id) => {
        const workspace = document.getElementById(id);
        if (workspace) {
            workspace.style.display = 'none';
        }
    });

    // Show target workspace
    const targetWorkspace = document.getElementById(workspaceId);
    if (targetWorkspace) {
        targetWorkspace.style.display = 'block';
    }
}

/**
 * Get tool information by ID
 * @param {string} toolId - Tool ID
 * @returns {object} Tool information
 */
function getToolInfo(toolId) {
    // Search through tool groups
    for (const group of toolGroups) {
        const tool = group.tools.find((t) => t.id === toolId);
        if (tool) {
            return tool;
        }
    }

    // Fallback
    return { label: toolId, description: '' };
}

/**
 * Initialize UI event bindings
 */
export function bindUI() {
    elements.sidebarToggle?.addEventListener('click', toggleSidebar);
    elements.sidebarCollapseBtn?.addEventListener('click', toggleSidebarCollapse);
    elements.sidebarBackdrop?.addEventListener('click', closeSidebar);

    // Basic converter controls
    elements.swap?.addEventListener('click', () => {
        if (state.currentTool !== 'format') return;
        const from = elements.from?.value || '';
        const to = elements.to?.value || '';
        if (elements.from) elements.from.value = to;
        if (elements.to) elements.to.value = from;
        if (elements.input && elements.output) {
            const previous = elements.input.value;
            elements.input.value = elements.output.value;
            elements.output.value = previous;
        }
        // Additional converter logic will be handled by converter module
    });

    elements.copy?.addEventListener('click', async () => {
        const value = elements.output?.value?.trim();
        if (!value) {
            setStatus('No output to copy', true);
            return;
        }
        const { copyText, showCopyFeedback } = await import('./utils.js');
        copyText(value, 'output', setStatus, showCopyFeedback);
    });

    elements.clear?.addEventListener('click', () => {
        if (elements.input) elements.input.value = '';
        if (elements.output) elements.output.value = '';
        setStatus('Cleared input/output', false);
    });

    // More bindings will be added by specific modules
}

/**
 * Boot the application
 */
export async function boot() {
    cacheElements();
    // renderSymbolButtons(); // Will be implemented in generators
    initCoderControls();
    renderSidebar();
    bindUI();
    // renderCoderEmpty(); // Will be implemented in coders
    // updateCoderTexts(); // Will be implemented in coders
    selectTool(state.currentTool);
    setStatus('Ready', false);

    // WASM initialization and tool-specific setup will be handled by main.js
}
