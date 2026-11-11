// Small UI-only helpers: panel clock and a collapse toggle for the file inspector. No app logic lives here.
(function () {
  const clock = document.getElementById('sb-clock');
  const pad = (n) => String(n).padStart(2, '0');
  const tick = () => {
    if (!clock) return;
    const d = new Date();
    clock.textContent = `${d.toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short' })}  ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  };
  tick();
  setInterval(tick, 10000);

  // Inspector collapse: the terminal gets the whole window until you want to look at a file.
  const viewer = document.querySelector('.chmain > .viewer');
  const tabs = viewer?.querySelector('.vtabs');
  if (viewer && tabs) {
    const btn = document.createElement('button');
    btn.className = 'icon-btn insp-toggle';
    btn.title = 'Show / hide the file inspector';
    const set = (collapsed) => {
      viewer.classList.toggle('collapsed', collapsed);
      btn.textContent = collapsed ? '▴ show' : '▾ hide';
      try { localStorage.setItem('cho.inspCollapsed', collapsed ? '1' : '0'); } catch { /* ignore */ }
    };
    btn.addEventListener('click', (e) => { e.stopPropagation(); set(!viewer.classList.contains('collapsed')); });
    tabs.append(btn);
    // Clicking a tab (Preview / Hex / Metadata / Strings) opens the inspector again.
    tabs.querySelectorAll('button[data-vtab]').forEach((b) => b.addEventListener('click', () => set(false)));
    let saved = '';
    try { saved = localStorage.getItem('cho.inspCollapsed') || ''; } catch { /* ignore */ }
    set(saved !== '0');
  }

  // Click anywhere in the terminal output to focus the prompt, like a real terminal.
  document.getElementById('term-log')?.addEventListener('click', () => {
    if (!String(window.getSelection())) document.getElementById('term-input')?.focus();
  });
})();
