const form = document.getElementById("setup"),
  button = document.getElementById("connect"),
  status = document.getElementById("status"),
  code = document.getElementById("code");
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  button.disabled = true;
  status.className = "";
  status.textContent =
    "Waiting for administrator approval, then verifying the connection…";
  const request = {
    url: document.getElementById("url").value,
    code: code.value,
  };
  try {
    const result = await window.keenSetup.connect(request);
    if (result.ok) {
      code.value = "";
      form.hidden = true;
      status.className = "success";
      status.textContent =
        result.warning ||
        "Connected. Hourly posture checks and automatic startup are enabled.";
      document.getElementById("complete").hidden = false;
    } else {
      status.className = "error";
      status.textContent = result.error;
    }
  } catch {
    status.className = "error";
    status.textContent = "Setup could not finish. Please try again.";
  } finally {
    request.code = "";
    button.disabled = false;
  }
});
