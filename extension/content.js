// extension/content.js

// 1. Inbox Filtering (Visual Grouping)
function filterInbox() {
  const rows = document.querySelectorAll('tr.zA'); // Gmail inbox rows
  if (rows.length === 0) return;

  const promoKeywords = ['unsubscribe', 'special offer', 'discount', 'sale', 'newsletter', 'opt out', 'promotional'];
  const spamKeywords = ['viagra', 'lottery', 'winner', 'casino'];

  rows.forEach(row => {
    // Avoid double processing
    if (row.hasAttribute('data-phishshield-scanned')) return;
    row.setAttribute('data-phishshield-scanned', 'true');

    const snippetEl = row.querySelector('.y2');
    if (!snippetEl) return;
    
    const text = snippetEl.innerText.toLowerCase();
    
    let isPromo = promoKeywords.some(kw => text.includes(kw));
    let isSpam = spamKeywords.some(kw => text.includes(kw));

    if (isSpam || isPromo) {
      // Visually dim the row and add a badge
      row.style.opacity = '0.4';
      row.style.borderLeft = isSpam ? '4px solid #ef4444' : '4px solid #8b5cf6';
      
      const badge = document.createElement('span');
      badge.innerText = isSpam ? ' SPAM ' : ' PROMO ';
      badge.style.backgroundColor = isSpam ? '#ef4444' : '#8b5cf6';
      badge.style.color = 'white';
      badge.style.padding = '2px 6px';
      badge.style.borderRadius = '4px';
      badge.style.fontSize = '10px';
      badge.style.marginLeft = '8px';
      badge.style.fontWeight = 'bold';
      
      const subjectContainer = row.querySelector('.bog'); // Gmail subject container
      if (subjectContainer) {
        subjectContainer.appendChild(badge);
      }
    }
  });
}

// 2. Auto-Scan Opened Emails
let currentEmailScanContent = null;

function checkForOpenedEmail() {
  // Gmail email body container class
  const emailBodies = document.querySelectorAll('.a3s.aiL, .ii.gt');
  
  if (emailBodies.length > 0) {
    const latestBody = emailBodies[0];
    
    if (latestBody.hasAttribute('data-phishshield-analyzed')) return;
    latestBody.setAttribute('data-phishshield-analyzed', 'true');
    
    const textToScan = latestBody.innerText;
    if (textToScan.trim().length < 20) return;
    
    currentEmailScanContent = latestBody;
    
    // Inject "Scanning" banner
    injectInlineBanner(latestBody, 'processing', null);

    // Trigger backend scan via background.js
    chrome.runtime.sendMessage({ action: "scanText", text: textToScan });
  }
}

function injectInlineBanner(container, status, result) {
  // Remove existing banner if any
  const existing = container.querySelector('.phishshield-inline-banner');
  if (existing) existing.remove();

  const banner = document.createElement('div');
  banner.className = 'phishshield-inline-banner';
  
  if (status === 'processing') {
    banner.style.backgroundColor = '#3b82f6';
    banner.innerHTML = `<strong>PhishShield AI:</strong> Automatically scanning this email...`;
  } else if (status === 'completed' && result) {
    let color = '#10b981'; // Safe
    let verdict = result.verdict || 'SAFE';
    
    if (verdict === 'PHISHING') color = '#ef4444';
    else if (verdict === 'SUSPICIOUS') color = '#f59e0b';
    else if (verdict === 'SPAM') color = '#ef4444';
    else if (verdict === 'PROMO') color = '#8b5cf6';
    
    banner.style.backgroundColor = color;
    
    let html = `<strong>Verdict: ${verdict}</strong> (Risk Score: ${result.risk_score || 0}/100)`;
    
    if (verdict !== 'SAFE') {
      const topReason = result.explanation_tree && result.explanation_tree.length > 0 
        ? result.explanation_tree[0].reason 
        : 'Flags detected';
      html += `<span style="margin-left: 12px; font-size: 12px;">Primary Reason: ${topReason}</span>`;
    }
    
    banner.innerHTML = html;
  } else if (status === 'error') {
    banner.style.backgroundColor = '#6b7280';
    banner.innerHTML = `<strong>PhishShield AI:</strong> Auto-scan failed.`;
  }

  // Prepend to email body
  container.insertBefore(banner, container.firstChild);
}

// 3. Listen for Storage Changes to update inline banner
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'local' && changes.latestScan) {
    const scan = changes.latestScan.newValue;
    if (!scan || !currentEmailScanContent) return;
    
    if (scan.status === 'completed' || scan.status === 'error') {
      injectInlineBanner(currentEmailScanContent, scan.status, scan.result);
    }
  }
});

// Setup MutationObserver to watch DOM for changes
const observer = new MutationObserver((mutations) => {
  if (window.phishshieldTimeout) clearTimeout(window.phishshieldTimeout);
  window.phishshieldTimeout = setTimeout(() => {
    filterInbox();
    checkForOpenedEmail();
  }, 500);
});

observer.observe(document.body, { childList: true, subtree: true });

// Run once on load
setTimeout(() => {
  filterInbox();
  checkForOpenedEmail();
}, 1000);
