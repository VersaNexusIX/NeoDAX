// ── NEODAX SHARED JS ──

// Mobile sidebar
function toggleSidebar() {
  const s = document.getElementById('sidebar');
  const o = document.getElementById('sidebarOverlay');
  const h = document.getElementById('hamburger');
  if (s.classList.contains('mobile-open')) { closeSidebar(); return; }
  s.classList.add('mobile-open'); o.classList.add('open'); h.classList.add('open');
}
function closeSidebar() {
  const s = document.getElementById('sidebar');
  const o = document.getElementById('sidebarOverlay');
  const h = document.getElementById('hamburger');
  s.classList.remove('mobile-open'); o.classList.remove('open');
  if (h) h.classList.remove('open');
}
function onNavClick() { if (window.innerWidth <= 768) closeSidebar(); }

// Sidebar search filter
function filterNav(q) {
  q = q.toLowerCase().trim();
  document.querySelectorAll('.nav-item').forEach(el => {
    el.style.display = (!q || el.textContent.toLowerCase().includes(q)) ? '' : 'none';
  });
  document.querySelectorAll('.sidebar-section-header').forEach(h => {
    if (!q) { h.style.display = ''; return; }
    let sib = h.nextElementSibling, any = false;
    while (sib && !sib.classList.contains('sidebar-section-header')) {
      if (sib.style.display !== 'none') any = true;
      sib = sib.nextElementSibling;
    }
    h.style.display = any ? '' : 'none';
  });
}

// Keyboard shortcuts
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    const si = document.getElementById('searchInput');
    if (si) si.focus();
  }
  if (e.key === 'Escape') {
    const si = document.getElementById('searchInput');
    if (si) { si.value = ''; filterNav(''); si.blur(); }
    closeSidebar();
  }
});

// ── FOOTER HTML ──
function renderFooter() {
  return `
  <footer class="site-footer">
    <div class="footer-inner">
      <div class="footer-grid">
        <div>
          <div class="footer-col-title">▸ Project</div>
          <a class="footer-link" href="https://github.com/VersaNexusIX/NeoDAX" target="_blank" rel="noopener">
            <span class="footer-link-icon">⌥</span> NeoDAX Repository
          </a>
          <a class="footer-link" href="docs.html">
            <span class="footer-link-icon">⌥</span> Documentation
          </a>
          <a class="footer-link" href="learn.html">
            <span class="footer-link-icon">⌥</span> Learning Path
          </a>
        </div>
        <div>
          <div class="footer-col-title">▸ Connect</div>
          <a class="footer-link" href="https://github.com/VersaNexusIX" target="_blank" rel="noopener">
            <span class="footer-link-icon">⌥</span> GitHub
          </a>
          <a class="footer-link" href="https://instagram.com/versa_nexusix" target="_blank" rel="noopener">
            <span class="footer-link-icon">⌥</span> Instagram
          </a>
          <a class="footer-link" href="https://wa.me/6285166984285" target="_blank" rel="noopener">
            <span class="footer-link-icon">⌥</span> WhatsApp
          </a>
          <a class="footer-link" href="mailto:vera@versas.my.id">
            <span class="footer-link-icon">⌥</span> vera@versas.my.id
          </a>
        </div>
        <div>
          <div class="footer-col-title">▸ Portfolio</div>
          <a class="footer-link" href="https://portfolio.versas.my.id" target="_blank" rel="noopener">
            <span class="footer-link-icon">⌥</span> portfolio.versas.my.id
          </a>
          <a class="footer-link" href="https://versa-xivs.vercel.app" target="_blank" rel="noopener">
            <span class="footer-link-icon">⌥</span> versa-xivs.vercel.app
          </a>
        </div>
      </div>
      <div class="footer-bottom">
        <span class="footer-copy">© VersaNexusIX — All rights reserved.</span>
        <span>NeoDAX v1.0.0 · MIT License · C99 · Zero Dependencies</span>
      </div>
    </div>
  </footer>`;
}

// ── SHARED SIDEBAR HTML ──
function renderSidebar(activePage) {
  const docActive   = activePage === 'docs'   ? 'active' : '';
  const learnActive = activePage === 'learn'  ? 'active' : '';
  const homeActive  = activePage === 'home'   ? 'active' : '';
  return `
  <div class="sidebar-overlay" id="sidebarOverlay" onclick="closeSidebar()"></div>
  <nav class="sidebar" id="sidebar">
    <div class="search-box">
      <input class="search-input" type="text" placeholder="// search..." id="searchInput" oninput="filterNav(this.value)">
    </div>
    <div class="sidebar-section-header">▸ Navigation</div>
    <a class="nav-item ${homeActive}"  href="index.html"  onclick="onNavClick()"><span class="nav-icon">◈</span> Home</a>
    <a class="nav-item ${docActive}"   href="docs.html"   onclick="onNavClick()"><span class="nav-icon">◧</span> Documentation</a>
    <a class="nav-item ${learnActive}" href="learn.html"  onclick="onNavClick()"><span class="nav-icon">⬡</span> Learning Path</a>
  </nav>`;
}
