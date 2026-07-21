(() => {
  "use strict";

  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
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
