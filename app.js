let vault = [];
let vaultKey = null;

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
  if (!password) return alert("Enter password");
  vaultKey = await deriveKey(password);
  try {
    // placeholder: load local or fake encrypted vault
    const stored = localStorage.getItem("vaultBlob");
    if (stored) {
      const blob = JSON.parse(stored);
      const encrypted = Uint8Array.from(blob.ciphertext);
      const iv = Uint8Array.from(blob.iv);
      vault = await decryptVault(encrypted, iv);
    } else {
      vault = [];
    }
    renderVault();
    document.getElementById("vault").style.display = "block";
  } catch (e) {
    alert("Decryption failed");
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
}

async function downloadVault() {
  const { ciphertext, iv } = await encryptVault();
  const blob = new Blob(
    [JSON.stringify({ ciphertext: Array.from(ciphertext), iv: Array.from(iv) })],
    { type: "application/json" }
  );
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "onionvault.enc.json";
  a.click();
}
