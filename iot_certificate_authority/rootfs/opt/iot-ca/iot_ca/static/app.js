(() => {
  "use strict";

  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  document.querySelectorAll("[data-copy-target]").forEach((button) => {
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
        button.textContent = "Copied";
        if (status) status.textContent = "ACME URL copied to clipboard";
      } catch (_error) {
        if (status) status.textContent = "Could not copy automatically; select and copy the URL";
      }
      window.setTimeout(() => {
        button.textContent = "Copy URL";
      }, 2000);
    });
  });

  const form = document.getElementById("certificate-form");
  if (!form) return;
  const profile = document.getElementById("profile");
  const keyType = document.getElementById("key-type");
  const validity = document.getElementById("validity-days");
  const exportFormat = document.getElementById("export-format");
  const passwordField = document.getElementById("export-password-field");

  function fill(select, values, selected) {
    const current = select.value;
    select.replaceChildren();
    values.forEach((value) => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value.toUpperCase();
      option.selected = value === (current || selected);
      select.append(option);
    });
  }

  function updateProfile() {
    const selected = profile.selectedOptions[0];
    fill(keyType, selected.dataset.keyTypes.split(","), selected.dataset.defaultKey);
    fill(exportFormat, selected.dataset.exports.split(","), selected.dataset.exports.split(",")[0]);
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
    updateProfile();
  });
  exportFormat.addEventListener("change", updateExport);
  updateProfile();
})();
