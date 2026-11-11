// Tiny, safe markdown renderer for Cho's replies. Everything is escaped before formatting.
// Code blocks become DOM nodes so we can attach Run / Copy buttons.
(function () {
  const esc = (s) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  function inline(text) {
    let h = esc(text);
    h = h.replace(/`([^`\n]+)`/g, '<code class="inline">$1</code>');
    h = h.replace(/\*\*([^*\n]+)\*\*/g, '<b>$1</b>');
    h = h.replace(/(^|\s)\*([^*\n]+)\*(?=\s|$)/g, '$1<i>$2</i>');
    h = h.replace(/^#{1,4}\s+(.+)$/gm, '<b>$1</b>');
    h = h.replace(/^FLAG:\s*(.+)$/gm, '<div class="flagline">[FLAG] $1</div>');
    h = h.replace(/^FINDING:\s*(.+)$/gm, '<div class="findline">[*] $1</div>');
    h = h.replace(/^VERIFIED:\s*(.+)$/gm, '<div class="verline">✔ Verified: $1</div>');
    h = h.replace(/^ASSUMPTION:\s*(.+)$/gm, '<div class="asmline">? Assumption: $1</div>');
    return h.split(/\n{2,}/).map((p) => `<p>${p.replace(/\n/g, '<br>')}</p>`).join('');
  }

  // opts.onRun(cmd) is called when the user clicks Run on a shell block.
  function render(text, opts = {}) {
    const frag = document.createDocumentFragment();
    const re = /```([\w+-]*)[^\n]*\n([\s\S]*?)```/g;
    let last = 0;
    let m;
    const addText = (t) => {
      if (!t.trim()) return;
      const div = document.createElement('div');
      div.innerHTML = inline(t.trim());
      frag.append(div);
    };
    while ((m = re.exec(text))) {
      addText(text.slice(last, m.index));
      frag.append(codeBlock(m[1].toLowerCase(), m[2].replace(/\n$/, ''), opts));
      last = re.lastIndex;
    }
    // Unclosed block while streaming / truncated replies.
    const rest = text.slice(last);
    const open = rest.indexOf('```');
    if (open >= 0) {
      addText(rest.slice(0, open));
      const body = rest.slice(open + 3).replace(/^[\w+-]*\n?/, '');
      frag.append(codeBlock('', body, {}));
    } else {
      addText(rest);
    }
    return frag;
  }

  function codeBlock(lang, code, opts) {
    const wrap = document.createElement('div');
    wrap.className = 'code';
    const bar = document.createElement('div');
    bar.className = 'bar';
    const label = document.createElement('span');
    label.textContent = lang || 'code';
    const btns = document.createElement('span');
    const copy = document.createElement('button');
    copy.textContent = 'Copy';
    copy.onclick = () => { navigator.clipboard.writeText(code); copy.textContent = 'Copied'; setTimeout(() => { copy.textContent = 'Copy'; }, 1200); };
    btns.append(copy);
    if (opts.onRun && ['bash', 'sh', 'shell', 'zsh', 'console', 'powershell', 'ps1', 'pwsh', ''].includes(lang)) {
      const run = document.createElement('button');
      run.className = 'run';
      run.textContent = '▶ Run';
      run.title = 'Approve and run this command inside the challenge folder';
      run.onclick = () => { run.disabled = true; run.textContent = '✓ Ran'; opts.onRun(code.replace(/^\$\s+/gm, '')); };
      btns.append(run);
      wrap.runButton = run;
    }
    if (opts.onEditor && ['python', 'py', 'python3'].includes(lang)) {
      const ed = document.createElement('button');
      ed.className = 'run';
      ed.textContent = '→ Python tab';
      ed.title = 'Load this script into the Python tab (solve.py)';
      ed.onclick = () => opts.onEditor(code);
      btns.append(ed);
    }
    bar.append(label, btns);
    const pre = document.createElement('pre');
    pre.textContent = code;
    wrap.append(bar, pre);
    return wrap;
  }

  window.md = { render, esc };
})();
