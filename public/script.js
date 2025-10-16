// public/script.js

const vulnForm = document.getElementById('vulnForm');
const secureForm = document.getElementById('secureForm');
const vulnResult = document.getElementById('vulnResult');
const secureResult = document.getElementById('secureResult');

const API_BASE = 'http://localhost:1234';

vulnForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('vuln-username').value;
  const password = document.getElementById('vuln-password').value;
  vulnResult.textContent = '...waiting';
  try {
    const res = await fetch(`${API_BASE}/vuln-login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    vulnResult.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    vulnResult.textContent = 'Error: ' + err;
  }
});

secureForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('sec-username').value;
  const password = document.getElementById('sec-password').value;
  secureResult.textContent = '...waiting';
  try {
    const res = await fetch(`${API_BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    secureResult.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    secureResult.textContent = 'Error: ' + err;
  }
});
