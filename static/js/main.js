/**
 * Apple-Core Mach-O Analyzer
 * Main JavaScript functionality
 */

document.addEventListener('DOMContentLoaded', function() {
    // Toggle sidebar on mobile
    const sidebarToggles = document.querySelectorAll('[data-toggle="sidebar"]');
    sidebarToggles.forEach(toggle => {
        toggle.addEventListener('click', function() {
            const target = document.querySelector(this.dataset.target);
            if (target) {
                target.classList.toggle('collapse');
            }
        });
    });
    
    // Initialize hex viewer if present
    initHexViewer();
    
    // Initialize navigation tree if present
    initNavTree();
});

/**
 * Initialize hex viewer functionality
 */
function initHexViewer() {
    const hexContainer = document.getElementById('hex-viewer');
    if (!hexContainer) return;
    
    const fileId = hexContainer.dataset.fileId;
    if (!fileId) return;
    
    let offset = 0;
    const length = 256;
    
    // Initial load
    loadHexData(fileId, offset, length);
    
    // Navigation buttons
    const prevBtn = document.getElementById('prev-page');
    const nextBtn = document.getElementById('next-page');
    
    if (prevBtn) {
        prevBtn.addEventListener('click', function() {
            if (offset >= length) {
                offset -= length;
                loadHexData(fileId, offset, length);
            }
        });
    }
    
    if (nextBtn) {
        nextBtn.addEventListener('click', function() {
            offset += length;
            loadHexData(fileId, offset, length);
        });
    }
    
    // Jump to offset
    const offsetForm = document.getElementById('jump-to-offset');
    if (offsetForm) {
        offsetForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const jumpOffset = parseInt(document.getElementById('offset-input').value, 16);
            if (!isNaN(jumpOffset)) {
                offset = jumpOffset;
                loadHexData(fileId, offset, length);
            }
        });
    }
}

/**
 * Load hex data from the server
 */
function loadHexData(fileId, offset, length) {
    fetch(`/api/files/${fileId}/hex?offset=${offset}&length=${length}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error(data.error);
                return;
            }
            
            updateHexView(data.hex);
            updateInterpretationPanel(data.interpretation);
            updateOffsetDisplay(offset);
        })
        .catch(error => {
            console.error('Error fetching hex data:', error);
        });
}

/**
 * Update the hex viewer display
 */
function updateHexView(hexData) {
    const hexViewer = document.getElementById('hex-content');
    if (!hexViewer) return;
    
    // Split hex data into 16-byte lines
    const hexBytes = hexData.split(' ');
    let html = '';
    
    for (let i = 0; i < hexBytes.length; i += 16) {
        const lineBytes = hexBytes.slice(i, i + 16);
        const offset = i.toString(16).padStart(8, '0');
        const hexLine = lineBytes.join(' ').padEnd(47, ' ');
        
        // Create ASCII representation
        let asciiLine = '';
        for (let j = 0; j < lineBytes.length; j++) {
            if (lineBytes[j]) {
                const byte = parseInt(lineBytes[j], 16);
                asciiLine += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
            }
        }
        
        html += `<div class="hex-line">
            <span class="offset-col">${offset}</span>
            <span class="hex-col">${hexLine}</span>
            <span class="ascii-col">${asciiLine}</span>
        </div>`;
    }
    
    hexViewer.innerHTML = html;
}

/**
 * Update the interpretation panel
 */
function updateInterpretationPanel(interpretation) {
    const panel = document.getElementById('interpretation-panel');
    if (!panel) return;
    
    let html = '';
    
    if (interpretation && interpretation.length > 0) {
        for (const item of interpretation) {
            html += `<div class="interpretation-item" data-offset="${item.offset}" data-length="${item.length}">
                <div class="item-name">${item.name}</div>
                <div class="item-value">${item.value}</div>
                <div class="item-description">${item.description}</div>
            </div>`;
        }
    } else {
        html = '<p class="text-muted">No interpretations available for this section.</p>';
    }
    
    panel.innerHTML = html;
    
    // Add click handlers to highlight corresponding bytes
    const items = panel.querySelectorAll('.interpretation-item');
    items.forEach(item => {
        item.addEventListener('click', function() {
            const offset = parseInt(this.dataset.offset);
            const length = parseInt(this.dataset.length);
            highlightBytes(offset, length);
        });
    });
}

/**
 * Update the current offset display
 */
function updateOffsetDisplay(offset) {
    const display = document.getElementById('current-offset');
    if (display) {
        display.textContent = '0x' + offset.toString(16).padStart(8, '0');
    }
}

/**
 * Highlight bytes in the hex viewer
 */
function highlightBytes(offset, length) {
    // Clear any existing highlights
    const highlighted = document.querySelectorAll('.highlighted');
    highlighted.forEach(el => el.classList.remove('highlighted'));
    
    // Calculate which line and which bytes to highlight
    const startLine = Math.floor(offset / 16);
    const startByte = offset % 16;
    const endLine = Math.floor((offset + length - 1) / 16);
    const endByte = (offset + length - 1) % 16;
    
    const hexLines = document.querySelectorAll('.hex-line');
    
    // Loop through lines that need highlighting
    for (let i = startLine; i <= endLine && i < hexLines.length; i++) {
        const line = hexLines[i];
        const hexBytes = line.querySelector('.hex-col').childNodes;
        const asciiChars = line.querySelector('.ascii-col').textContent;
        
        // Determine the range of bytes to highlight in this line
        const lineStartByte = (i === startLine) ? startByte : 0;
        const lineEndByte = (i === endLine) ? endByte : 15;
        
        // Highlight the hex and ASCII representations
        for (let j = lineStartByte; j <= lineEndByte; j++) {
            // Highlight hex bytes
            const byteIndex = j * 3; // Each byte takes 3 characters (XX )
            if (hexBytes[byteIndex]) {
                const span = document.createElement('span');
                span.className = 'highlighted';
                span.textContent = hexBytes[byteIndex].textContent;
                hexBytes[byteIndex].replaceWith(span);
            }
            
            // Highlight ASCII
            if (j < asciiChars.length) {
                // This would need a more complex implementation to highlight
                // individual characters in the ASCII representation
            }
        }
    }
}

/**
 * Initialize navigation tree functionality
 */
function initNavTree() {
    const navTree = document.querySelector('.nav-tree');
    if (!navTree) return;
    
    // Find all toggles
    const toggles = navTree.querySelectorAll('.nav-tree-toggle');
    toggles.forEach(toggle => {
        const target = document.getElementById(toggle.dataset.target);
        
        // Set initial state (hidden)
        if (target) {
            target.style.display = 'none';
        }
        
        // Add click handler
        toggle.addEventListener('click', function() {
            if (target) {
                // Toggle visibility
                const isVisible = target.style.display !== 'none';
                target.style.display = isVisible ? 'none' : 'block';
                
                // Toggle indicator
                this.classList.toggle('expanded', !isVisible);
            }
        });
    });
} 