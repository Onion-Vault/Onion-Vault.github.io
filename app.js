let vault = [];
let vaultKey = null;

function showStatus(msg, isError = false) {
  const status = document.getElementById("status");
  status.textContent = msg;
  status.style.color = isError ? "tomato" : "lightgreen";
}

async function deriveKey(password) {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode("onionvault-salt"),
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptVault() {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(vault));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    vaultKey,
    encoded
  );
  return { ciphertext: new Uint8Array(ciphertext), iv };
}

async function decryptVault(encrypted, iv) {
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    vaultKey,
    encrypted
  );
  return JSON.parse(new TextDecoder().decode(decrypted));
}

async function loadVault() {
  const password = document.getElementById("masterPassword").value;
  if (!password) return showStatus("Enter a password", true);
  vaultKey = await deriveKey(password);

  const stored = localStorage.getItem("vaultBlob");
  if (!stored) {
    vault = [];
    showStatus("No vault found. New vault created.");
    renderVault();
    document.getElementById("vault").style.display = "block";
    document.getElementById("login").style.display = "none";
    return;
  }

  try {
    const blob = JSON.parse(stored);
    const encrypted = Uint8Array.from(blob.ciphertext);
    const iv = Uint8Array.from(blob.iv);
    vault = await decryptVault(encrypted, iv);
    showStatus("Vault unlocked.");
    renderVault();
    document.getElementById("vault").style.display = "block";
    document.getElementById("login").style.display = "none";
  } catch (e) {
    showStatus("Incorrect password or corrupted vault.", true);
  }
}

function renderVault() {
  const list = document.getElementById("entries");
  list.innerHTML = "";
  vault.forEach((entry, i) => {
    const li = document.createElement("li");
    li.textContent = `${entry.site} | ${entry.username} | ${entry.password}`;
    list.appendChild(li);
  });
}

function addEntry() {
  const site = document.getElementById("site").value;
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  vault.push({ site, username, password });
  renderVault();
  saveToLocalStorage();
}

async function saveToLocalStorage() {
  const { ciphertext, iv } = await encryptVault();
  const blob = JSON.stringify({
    ciphertext: Array.from(ciphertext),
    iv: Array.from(iv)
  });
  localStorage.setItem("vaultBlob", blob);
}

function logout() {
  vault = [];
  vaultKey = null;
  document.getElementById("vault").style.display = "none";
  document.getElementById("login").style.display = "block";
  showStatus("Logged out.");
}
