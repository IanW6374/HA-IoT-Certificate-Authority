(() => {
  "use strict";

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (form.matches("form[data-confirm]") && !window.confirm(form.dataset.confirm)) {
      event.preventDefault();
    }
  });

  function statusElement(form) {
    let status = form.querySelector(".portal-status");
    if (status) return status;
    status = document.createElement("span");
    status.className = "portal-status";
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    const actions = form.querySelector(".actions");
    if (actions) actions.prepend(status);
    else form.append(status);
    return status;
  }

  function setStatus(status, state, message) {
    status.className = `portal-status${state ? ` ${state}` : ""}`;
    status.textContent = message || "";
  }

  function initializeCountdowns(root = document) {
    root.querySelectorAll("[data-enrollment-countdown]").forEach((counter) => {
      if (counter.dataset.countdownReady) return;
      counter.dataset.countdownReady = "true";
      const deadline = Date.parse(counter.dataset.until || "");
      let expired = false;
      function updateCountdown() {
        const remaining = Number.isFinite(deadline)
          ? Math.max(0, Math.ceil((deadline - Date.now()) / 1000)) : 0;
        const minutes = Math.floor(remaining / 60);
        const seconds = remaining % 60;
        counter.textContent = `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
        if (!remaining && !expired) {
          expired = true;
          window.setTimeout(() => window.location.reload(), 500);
        }
      }
      updateCountdown();
      window.setInterval(updateCountdown, 1000);
    });
  }

  document.addEventListener("submit", async (event) => {
    const form = event.target;
    if (!form.matches("form[data-portal-async]") || event.defaultPrevented) return;
    event.preventDefault();
    const button = event.submitter || form.querySelector("button[type=submit]");
    const original = button ? button.textContent : "";
    const status = statusElement(form);
    if (button) {
      button.disabled = true;
      button.textContent = form.dataset.busyLabel || "Saving…";
    }
    setStatus(status, "", form.dataset.status || "Saving changes…");
    try {
      const response = await fetch(form.action, {
        method: "POST",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
        body: new FormData(form),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "The change could not be saved");
      const selector = payload.refresh_target || form.dataset.refreshTarget;
      if (selector) {
        const refreshed = await fetch(payload.refresh_url || window.location.href, {
          cache: "no-store", credentials: "same-origin",
        });
        if (!refreshed.ok) throw new Error("The updated section could not be loaded");
        const parsed = new DOMParser().parseFromString(await refreshed.text(), "text/html");
        const fresh = parsed.querySelector(selector);
        const current = document.querySelector(selector);
        if (!fresh || !current) throw new Error("The updated section is unavailable");
        const openDetails = [...current.querySelectorAll("details")]
          .map((item, index) => item.open ? index : -1)
          .filter((index) => index >= 0);
        current.replaceWith(fresh);
        [...fresh.querySelectorAll("details")].forEach((item, index) => {
          if (openDetails.includes(index)) item.open = true;
        });
        let nextStatus = fresh.querySelector(".portal-status");
        if (!nextStatus) {
          nextStatus = document.createElement("div");
          nextStatus.setAttribute("role", "status");
          nextStatus.setAttribute("aria-live", "polite");
          fresh.prepend(nextStatus);
        }
        setStatus(nextStatus, "success", payload.message || "Changes saved");
        initializeCountdowns(fresh);
      } else {
        setStatus(status, "success", payload.message || "Changes saved");
      }
      form.dataset.portalDirty = "0";
    } catch (error) {
      setStatus(status, "error", error.message);
    } finally {
      if (button && document.contains(button)) {
        button.disabled = false;
        button.textContent = original;
      }
    }
  });

  function markDirty(event) {
    const form = event.target.form;
    if (form && form.hasAttribute("data-portal-dirty")) form.dataset.portalDirty = "1";
  }
  document.addEventListener("input", markDirty, true);
  document.addEventListener("change", markDirty, true);
  document.addEventListener("reset", (event) => {
    if (event.target.matches("form[data-portal-dirty]")) event.target.dataset.portalDirty = "0";
  }, true);
  window.addEventListener("beforeunload", (event) => {
    if (!document.querySelector('form[data-portal-dirty][data-portal-dirty="1"]')) return;
    event.preventDefault();
    event.returnValue = "";
  });

  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    const originalLabel = button.getAttribute("aria-label") || "Copy";
    button.addEventListener("click", async () => {
      const source = document.querySelector(button.dataset.copyTarget);
      const status = button.parentElement.querySelector(".copy-status");
      if (!source) return;
      try {
        const value = source.textContent.trim();
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(value);
        } else {
          const temporary = document.createElement("textarea");
          temporary.value = value;
          temporary.setAttribute("readonly", "");
          temporary.style.position = "fixed";
          temporary.style.opacity = "0";
          document.body.append(temporary);
          temporary.select();
          const copied = document.execCommand("copy");
          temporary.remove();
          if (!copied) throw new Error("Clipboard copy failed");
        }
        button.classList.add("copied");
        button.setAttribute("aria-label", "Copied");
        if (status) status.textContent = "URL copied to clipboard";
      } catch (_error) {
        if (status) status.textContent = "Could not copy automatically; select and copy the URL";
      }
      window.setTimeout(() => {
        button.classList.remove("copied");
        button.setAttribute("aria-label", originalLabel);
      }, 2000);
    });
  });

  document.querySelectorAll("[data-auto-submit]").forEach((control) => {
    control.addEventListener("change", () => control.form.requestSubmit());
  });

  initializeCountdowns();

  const publicCertificateForm = document.getElementById("public-certificate-form");
  if (publicCertificateForm) {
    const portalHost = document.getElementById("public-portal-host");
    const apiHostname = document.getElementById("public-api-hostname");
    const validation = document.getElementById("public-certificate-validation");
    const submitButton = document.getElementById("prepare-public-certificate");
    let apiHostnameEdited = Boolean(apiHostname.value.trim());

    function clearValidation() {
      validation.hidden = true;
      validation.textContent = "";
      portalHost.removeAttribute("aria-invalid");
      apiHostname.removeAttribute("aria-invalid");
    }

    function reject(field, message) {
      validation.textContent = message;
      validation.hidden = false;
      field.setAttribute("aria-invalid", "true");
      field.focus();
    }

    apiHostname.addEventListener("input", () => {
      apiHostnameEdited = true;
      clearValidation();
    });

    portalHost.addEventListener("input", () => {
      clearValidation();
      if (apiHostnameEdited) return;
      const host = portalHost.value.trim();
      if (/^[A-Za-z0-9-]+$/.test(host)) {
        apiHostname.value = `${host}.local`;
      } else {
        apiHostname.value = "";
      }
    });

    publicCertificateForm.addEventListener("submit", (event) => {
      clearValidation();
      const host = portalHost.value.trim().toLowerCase();
      const privateName = apiHostname.value.trim().toLowerCase().replace(/[.]$/, "");
      portalHost.value = host;
      apiHostname.value = privateName;

      if (!host) {
        event.preventDefault();
        reject(portalHost, "Enter the public portal host. The example text is not submitted as a value.");
        return;
      }
      if (!/^(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9])$/.test(host)) {
        event.preventDefault();
        reject(portalHost, "Use a single DNS host label containing only letters, numbers, or internal hyphens.");
        return;
      }
      if (!/^[A-Za-z0-9-]+[.]local$/.test(privateName)) {
        event.preventDefault();
        reject(apiHostname, "Enter a single-label private hostname ending in .local, for example device.local.");
        return;
      }

      validation.classList.remove("error");
      validation.classList.add("info");
      validation.textContent = "Validating authoritative DNS and requesting the certificate. This can take several minutes.";
      validation.hidden = false;
      submitButton.disabled = true;
      submitButton.textContent = "Preparing certificate…";
    });
  }

  const form = document.getElementById("certificate-form");
  if (!form) return;
  const profile = document.getElementById("profile");
  const keyType = document.getElementById("key-type");
  const validity = document.getElementById("validity-days");
  const exportFormat = document.getElementById("export-format");
  const passwordField = document.getElementById("export-password-field");
  const initialKeyType = form.dataset.initialKey || "";
  const initialExportFormat = form.dataset.initialExport || "";

  function fill(select, values, selected) {
    const current = select.value;
    select.replaceChildren();
    values.forEach((value) => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value === "iot_md" ? "IoT MD" : value.toUpperCase();
      option.selected = value === (current || selected);
      select.append(option);
    });
  }

  function updateProfile(useInitialValues = false) {
    const selected = profile.selectedOptions[0];
    fill(
      keyType,
      selected.dataset.keyTypes.split(","),
      useInitialValues && initialKeyType ? initialKeyType : selected.dataset.defaultKey,
    );
    fill(
      exportFormat,
      selected.dataset.exports.split(","),
      useInitialValues && initialExportFormat
        ? initialExportFormat : selected.dataset.exports.split(",")[0],
    );
    if (!validity.value) validity.value = selected.dataset.defaultDays;
    document.getElementById("profile-description").textContent = selected.dataset.description;
    updateExport();
  }

  function updateExport() {
    passwordField.hidden = exportFormat.value !== "pkcs12";
    passwordField.querySelector("input").required = exportFormat.value === "pkcs12";
  }

  profile.addEventListener("change", () => {
    validity.value = "";
    updateProfile(false);
  });
  exportFormat.addEventListener("change", updateExport);
  updateProfile(true);
})();
