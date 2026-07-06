chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scanWithPhishShield",
    title: "Scan with PhishShield AI",
    contexts: ["selection"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "scanWithPhishShield" && info.selectionText) {
    analyzeText(info.selectionText);
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "scanText" && request.text) {
    analyzeText(request.text);
    sendResponse({ status: "started" });
  }
});

async function analyzeText(text) {
  await chrome.storage.local.set({ 
    latestScan: { status: 'processing', text: text.substring(0, 100) + '...', progress: 0 } 
  });
  
  try {
    const response = await fetch('http://127.0.0.1:5000/api/v1/scan/paste', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ raw_email: text })
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    const jobId = data.job_id;
    
    pollJobStatus(jobId);
    
  } catch (error) {
    console.error('Error analyzing text:', error);
    await chrome.storage.local.set({ 
      latestScan: { status: 'error', error: error.message } 
    });
  }
}

async function pollJobStatus(jobId) {
  const maxRetries = 60; // 60 seconds max poll
  let retries = 0;
  
  const interval = setInterval(async () => {
    try {
      const response = await fetch(`http://127.0.0.1:5000/api/v1/scan/status/${jobId}`);
      const data = await response.json();
      
      if (data.status === 'completed') {
        clearInterval(interval);
        await chrome.storage.local.set({ 
          latestScan: { status: 'completed', result: data.result } 
        });
      } else if (data.status === 'error') {
        clearInterval(interval);
        await chrome.storage.local.set({ 
          latestScan: { status: 'error', error: data.error } 
        });
      } else {
        // Still processing (status is 'waiting' or 'processing')
        await chrome.storage.local.set({ 
          latestScan: { status: 'processing', progress: data.progress || 0 } 
        });
      }
    } catch (err) {
      console.error('Polling error', err);
      // Wait for next tick, might be transient
    }
    
    retries++;
    if (retries >= maxRetries) {
      clearInterval(interval);
      await chrome.storage.local.set({ 
        latestScan: { status: 'error', error: 'Timeout waiting for scan results.' } 
      });
    }
  }, 1000);
}
