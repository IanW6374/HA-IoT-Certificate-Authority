/* Required/optional labels shared by the IoT portfolio portals. */
(() => {
  "use strict";
  function annotate() {
    for (const label of document.querySelectorAll("form label")) {
      const control = label.querySelector("input:not([type=hidden]):not([type=checkbox]):not([type=radio]),select,textarea");
      if (!control || label.classList.contains("check")) continue;
      const entry = label.closest(".profile-entry");
      let heading = entry?.querySelector(".profile-entry-heading strong") || label.querySelector(".field-title");
      if (!heading) {
        const first = label.firstElementChild;
        if (first?.tagName === "SPAN" && !first.querySelector("input,select,textarea")) heading = first;
        else {
          const texts = [...label.childNodes].filter(node => node.nodeType === 3 && node.textContent.trim());
          if (!texts.length) continue;
          heading = document.createElement("span");
          heading.className = "field-title";
          label.insertBefore(heading, label.firstChild);
          for (const text of texts) heading.append(text);
        }
      }
      for (const node of heading.childNodes) if (node.nodeType === 3 && /\((optional|required)\)/i.test(node.textContent)) node.textContent = node.textContent.replace(/\s*\((optional|required)\)/ig, "");
      let marker = heading.querySelector(".field-requirement");
      if (!marker) { marker = document.createElement("small"); marker.className = "field-requirement"; heading.append(marker); }
      const text = control.dataset.requirement || (control.required ? "required" : "optional");
      if (marker.textContent !== " (" + text + ")") marker.textContent = " (" + text + ")";
    }
  }
  let pending = false;
  const observer = new MutationObserver(() => {
    if (pending) return;
    pending = true;
    requestAnimationFrame(() => { pending = false; annotate(); });
  });
  annotate();
  observer.observe(document.body, {subtree:true, childList:true, attributes:true, attributeFilter:["required","data-requirement"]});
})();
