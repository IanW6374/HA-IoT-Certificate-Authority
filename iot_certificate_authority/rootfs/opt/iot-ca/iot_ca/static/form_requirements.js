/* Required/optional labels shared by the IoT portfolio portals. */
(() => {
  "use strict";
  function annotate() {
    for (const notice of document.querySelectorAll('.portal-status,.notice,.status:not(.badge)')) {
      const role = notice.classList.contains('error') ? 'alert' : 'status';
      if (notice.getAttribute('role') !== role) notice.setAttribute('role', role);
    }
    for (const label of document.querySelectorAll("label")) {
      const control = label.control || label.querySelector("input:not([type=hidden]),select,textarea");
      if (!control || control.type === "hidden" || control.type === "radio") continue;
      if (control.type === "checkbox" && control.parentElement === label && label.firstChild !== control) label.prepend(control);
      const entry = label.closest(".profile-entry");
      let heading = entry?.querySelector(".profile-entry-heading strong") || label.querySelector(".field-title");
      if (!heading) {
        const first = control.type === "checkbox" ? [...label.children].find(child => child.tagName === "SPAN" && !child.querySelector("input,select,textarea")) : label.firstElementChild;
        if (first?.tagName === "SPAN" && !first.querySelector("input,select,textarea")) heading = first;
        else {
          const texts = [...label.childNodes].filter(node => node.nodeType === 3 && node.textContent.trim());
          if (!texts.length) continue;
          heading = document.createElement("span");
          heading.className = "field-title";
          label.insertBefore(heading, control.type === "checkbox" ? control.nextSibling : label.firstChild);
          for (const text of texts) heading.append(text);
        }
      }
      for (const node of heading.childNodes) if (node.nodeType === 3 && /\((optional|required)\)/i.test(node.textContent)) node.textContent = node.textContent.replace(/\s*\((optional|required)\)/ig, "");
      const text = control.dataset.requirement || (control.required ? "required" : "optional");
      if (text === "required when enabled") {
        const enabled = Boolean(control.form?.elements.namedItem("enabled")?.checked);
        if (control.required !== enabled) control.required = enabled;
      }
      const required = !control.disabled && !control.readOnly && control.required;
      let marker = heading.querySelector(".field-requirement");
      if (!required) { if (marker) marker.remove(); continue; }
      if (!marker) {
        marker = document.createElement("small"); marker.className = "field-requirement";
        marker.textContent = "✱"; marker.setAttribute("role", "img");
        heading.insertBefore(marker, heading.querySelector("small"));
      }
      const hint = text.startsWith("required") ? text[0].toUpperCase() + text.slice(1) : "Required";
      if (marker.title !== hint) { marker.title = hint; marker.setAttribute("aria-label", hint); }
    }
  }
  let pending = false;
  const observer = new MutationObserver(() => {
    if (pending) return;
    pending = true;
    requestAnimationFrame(() => { pending = false; annotate(); });
  });
  annotate();
  document.addEventListener("change", annotate);
  document.addEventListener("reset", () => requestAnimationFrame(annotate));
  observer.observe(document.body, {subtree:true, childList:true, attributes:true, attributeFilter:["required","disabled","readonly","data-requirement","class"]});
})();
