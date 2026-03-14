const enableBtn = document.getElementById("enableGmail");
const skipLink = document.getElementById("skipSetup");
const statusPill = document.getElementById("status");
const permissionBox = document.getElementById("permissionBox");

function setStatus({ text, ok = true }) {
  if (!statusPill) return;

  statusPill.textContent = "";
  const dot = document.createElement("span");
  dot.className = "status-dot";

  if (!ok) {
    statusPill.classList.add("status-pill--error");
  } else {
    statusPill.classList.remove("status-pill--error");
  }

  statusPill.appendChild(dot);
  statusPill.appendChild(document.createTextNode(" " + text));
}

function pulsePermissionBox(error = false) {
  if (!permissionBox) return;
  permissionBox.style.transition = "box-shadow 0.25s ease, border-color 0.25s ease";
  if (error) {
    permissionBox.style.boxShadow = "0 0 0 1px rgba(248,113,113,0.6)";
    permissionBox.style.borderColor = "rgba(248,113,113,0.7)";
  } else {
    permissionBox.style.boxShadow = "0 0 0 1px rgba(59,130,246,0.7)";
    permissionBox.style.borderColor = "rgba(59,130,246,0.9)";
  }
  setTimeout(() => {
    permissionBox.style.boxShadow = "";
    permissionBox.style.borderColor = "";
  }, 600);
}

async function requestPermissions() {
  setStatus({ text: "Requesting Gmail access…", ok: true });
  pulsePermissionBox(false);

  try {
    const granted = await chrome.permissions.request({
      origins: ["https://mail.google.com/"]
    });

    if (granted) {
      setStatus({ text: "Gmail access enabled", ok: true });
      pulsePermissionBox(false);

      chrome.tabs.create({ url: "https://mail.google.com/" });
    } else {
      setStatus({ text: "Permission denied · try again", ok: false });
      pulsePermissionBox(true);
    }
  } catch (e) {
    console.error("Permission request failed", e);
    setStatus({ text: "Something went wrong · check console", ok: false });
    pulsePermissionBox(true);
  }
}

function skipSetup() {
  setStatus({ text: "Setup skipped · you can enable later", ok: true });
  window.close?.();
}

if (enableBtn) {
  enableBtn.addEventListener("click", (event) => {
    event.preventDefault();
    requestPermissions();
  });
}

if (skipLink) {
  skipLink.addEventListener("click", (event) => {
    event.preventDefault();
    skipSetup();
  });
}
