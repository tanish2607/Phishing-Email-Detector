document.addEventListener('DOMContentLoaded', () => {
  const inputSection = document.getElementById('input-section');
  const loadingSection = document.getElementById('loading-section');
  const resultsSection = document.getElementById('results-section');
  
  const emailInput = document.getElementById('email-input');
  const scanBtn = document.getElementById('scan-btn');
  const resetBtn = document.getElementById('reset-btn');
  
  const progressBar = document.getElementById('progress-bar');
  const progressText = document.getElementById('progress-text');
  
  const riskScoreEl = document.getElementById('risk-score');
  const verdictTextEl = document.getElementById('verdict-text');
  const llmExplanationEl = document.getElementById('llm-explanation');
  const detailsListEl = document.getElementById('details-list');

  let pollInterval;

  // Initialize UI state
  checkStorageForActiveScan();

  // Scan Button Click
  scanBtn.addEventListener('click', () => {
    const text = emailInput.value.trim();
    if (!text) return;

    // Send message to background to start scan
    chrome.runtime.sendMessage({ action: "scanText", text: text }, (response) => {
      showLoading();
      startPollingStorage();
    });
  });

  // Reset Button Click
  resetBtn.addEventListener('click', async () => {
    await chrome.storage.local.remove('latestScan');
    emailInput.value = '';
    showInput();
  });

  function checkStorageForActiveScan() {
    chrome.storage.local.get(['latestScan'], (result) => {
      if (result.latestScan) {
        handleScanState(result.latestScan);
        if (result.latestScan.status === 'processing') {
          startPollingStorage();
        }
      } else {
        showInput();
      }
    });
  }

  function startPollingStorage() {
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(() => {
      chrome.storage.local.get(['latestScan'], (result) => {
        if (result.latestScan) {
          handleScanState(result.latestScan);
          if (result.latestScan.status !== 'processing') {
            clearInterval(pollInterval);
          }
        }
      });
    }, 500);
  }

  function handleScanState(scan) {
    if (scan.status === 'processing') {
      showLoading();
      const pct = scan.progress || 0;
      progressBar.style.width = `${pct}%`;
      progressText.innerText = `${pct}% Complete`;
    } else if (scan.status === 'completed') {
      showResults(scan.result);
    } else if (scan.status === 'error') {
      alert("Error: " + scan.error);
      chrome.storage.local.remove('latestScan');
      showInput();
    }
  }

  function showInput() {
    inputSection.classList.remove('hidden');
    loadingSection.classList.add('hidden');
    resultsSection.classList.add('hidden');
  }

  function showLoading() {
    inputSection.classList.add('hidden');
    loadingSection.classList.remove('hidden');
    resultsSection.classList.add('hidden');
  }

  function showResults(result) {
    inputSection.classList.add('hidden');
    loadingSection.classList.add('hidden');
    resultsSection.classList.remove('hidden');

    const score = result.risk_score || 0;
    riskScoreEl.querySelector('span').innerText = score;
    
    riskScoreEl.className = 'score-circle'; // reset classes
    verdictTextEl.className = '';
    
    if (score > 70) {
      riskScoreEl.classList.add('phishing');
      verdictTextEl.innerText = 'PHISHING';
      verdictTextEl.classList.add('verdict-text-phishing');
    } else if (score > 40) {
      riskScoreEl.classList.add('suspicious');
      verdictTextEl.innerText = 'SUSPICIOUS';
      verdictTextEl.classList.add('verdict-text-suspicious');
    } else {
      verdictTextEl.innerText = 'SAFE';
      verdictTextEl.classList.add('verdict-text-safe');
    }

    // Replace markdown bold with HTML bold
    let formattedHtml = (result.llm_explanation || '').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    // Replace newlines with <br>
    formattedHtml = formattedHtml.replace(/\n/g, '<br/>');
    llmExplanationEl.innerHTML = formattedHtml;

    detailsListEl.innerHTML = '';
    if (result.explanation_tree && result.explanation_tree.length > 0) {
      result.explanation_tree.forEach(item => {
        const div = document.createElement('div');
        div.className = 'detail-item';
        div.innerHTML = `<strong>${item.reason}</strong><p>${item.detail}</p>`;
        detailsListEl.appendChild(div);
      });
    }
  }
});
