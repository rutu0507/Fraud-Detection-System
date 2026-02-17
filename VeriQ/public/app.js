// ---------------- VERIFY ----------------
function verifyContent() {
  if (!consent.checked) {
    alert("Consent required");
    return;
  }

  fetch("/api/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: urlInput.value || null,
      text: textInput.value || null,
      filename: fileInput.files[0]?.name || null,
      consent: true,
      user_id: 1
    })
  })
  .then(r => r.json())
  .then(d => {
    resultBox.classList.remove("d-none");
    status.innerText = d.status;

    meterBar.style.width = d.confidence + "%";
    meterBar.innerText = d.confidence + "%";

    reasons.innerHTML = "";
    d.reasons.forEach(x => {
      const li = document.createElement("li");
      li.innerText = x;
      reasons.appendChild(li);
    });

    if (d.status === "FRAUDULENT") {
      reportBtn.classList.remove("d-none");
    }
  });
}

// ---------------- AUTH ----------------
function login() {
  fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: email.value,
      password: password.value
    })
  })
  .then(r => r.json())
  .then(() => location.href = "dashboard.html");
}

function register() {
  fetch("/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: regEmail.value,
      password: regPassword.value
    })
  })
  .then(() => location.href = "login.html");
}
