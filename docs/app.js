/* =========================================================================
   polinrider-hunter — site behaviour

   No framework, no build step. Everything here degrades to a perfectly usable
   page if it fails to run: the tabs are real buttons, the commands are already
   in the markup, and the theme defaults to dark in CSS.
   ========================================================================= */
(function () {
  'use strict';

  /* ---------------------------------------------------------------------
     The install URL points at wherever this page is actually served from.
     Hardcoding it is how install instructions go stale; computing it means a
     fork, a preview deploy or a move between hosts all stay correct.

     `location.origin` alone is wrong on a GitHub Pages project site: the page
     lives at https://user.github.io/repo/, so the origin omits the /repo
     segment and the copied command would 404. What is needed is the directory
     the page sits in.
     --------------------------------------------------------------------- */
  function baseUrl() {
    var path = location.pathname;
    // Drop a trailing filename ("/repo/index.html" -> "/repo/").
    path = path.replace(/\/[^\/]*\.[^\/]*$/, '/');
    // Then drop trailing slashes so callers can append "/install.ps1".
    return (location.origin + path).replace(/\/+$/, '');
  }

  function applyOrigin() {
    var host = location.hostname;
    // Keep the illustrative URL when previewing from disk or localhost —
    // "http://localhost:8080/install.ps1" would be useless to copy.
    if (!host || host === 'localhost' || host === '127.0.0.1' || location.protocol === 'file:') {
      return;
    }
    var base = baseUrl();
    var nodes = document.querySelectorAll('[data-origin]');
    for (var i = 0; i < nodes.length; i++) {
      nodes[i].textContent = base;
    }
  }

  /* ---------------------------------------------------------------------
     Theme
     --------------------------------------------------------------------- */
  var MOON = 'M21 12.8A8.5 8.5 0 1 1 11.2 3a6.6 6.6 0 0 0 9.8 9.8Z';
  var SUN = 'M12 4V2m0 20v-2m8-8h2M2 12h2m13.7-5.7 1.4-1.4M4.9 19.1l1.4-1.4m0-11.4L4.9 4.9m14.2 14.2-1.4-1.4M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z';

  function setTheme(mode) {
    var light = mode === 'light';
    document.documentElement.classList.toggle('light', light);
    var icon = document.getElementById('theme-icon');
    if (icon) {
      icon.innerHTML = '<path d="' + (light ? SUN : MOON) + '"/>';
    }
    var btn = document.getElementById('theme');
    if (btn) {
      btn.setAttribute('aria-label', light ? 'Switch to dark' : 'Switch to light');
    }
    try { localStorage.setItem('prh-theme', mode); } catch (e) { /* private mode */ }
  }

  function initTheme() {
    var saved = null;
    try { saved = localStorage.getItem('prh-theme'); } catch (e) { /* ignore */ }
    if (!saved) {
      // The design is dark-first; only follow the OS when it explicitly asks.
      saved = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches
        ? 'light' : 'dark';
    }
    setTheme(saved);
    var btn = document.getElementById('theme');
    if (btn) {
      btn.addEventListener('click', function () {
        setTheme(document.documentElement.classList.contains('light') ? 'dark' : 'light');
      });
    }
  }

  /* ---------------------------------------------------------------------
     Install tabs, pre-selected from the visitor's platform
     --------------------------------------------------------------------- */
  function detectOs() {
    var ua = (navigator.userAgent || '') + ' ' + (navigator.platform || '');
    // Order matters: iOS reports "Mac" in some UA strings, and Android
    // contains "Linux" — neither is a target here, but Linux is the safer
    // fallback for anything unix-shaped.
    if (/Win/i.test(ua)) return 'win';
    if (/Mac|iPhone|iPad|iPod/i.test(ua)) return 'mac';
    if (/Linux|X11|CrOS|Android/i.test(ua)) return 'linux';
    return 'win';
  }

  function initTabs() {
    var tabs = Array.prototype.slice.call(document.querySelectorAll('.tab[data-os]'));
    if (!tabs.length) return;

    function select(os) {
      tabs.forEach(function (tab) {
        var on = tab.getAttribute('data-os') === os;
        tab.setAttribute('aria-selected', on ? 'true' : 'false');
        var pane = document.getElementById(tab.getAttribute('aria-controls'));
        if (pane) pane.hidden = !on;
      });
    }

    tabs.forEach(function (tab) {
      tab.addEventListener('click', function () { select(tab.getAttribute('data-os')); });
      // Arrow-key navigation, which a tablist is expected to support.
      tab.addEventListener('keydown', function (ev) {
        var i = tabs.indexOf(tab);
        var next = ev.key === 'ArrowRight' ? i + 1 : ev.key === 'ArrowLeft' ? i - 1 : -1;
        if (next < 0 || next >= tabs.length) return;
        ev.preventDefault();
        tabs[next].focus();
        select(tabs[next].getAttribute('data-os'));
      });
    });

    select(detectOs());
  }

  /* ---------------------------------------------------------------------
     Copy buttons
     --------------------------------------------------------------------- */
  var ICON_COPY = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>';
  var ICON_DONE = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="m5 13 4 4L19 7"/></svg>';

  /** The runnable lines only: drop shell comments and blank lines. */
  function commandText(block) {
    var code = block.querySelector('code');
    if (!code) return '';
    return code.textContent
      .split('\n')
      .filter(function (line) {
        var t = line.trim();
        return t && t.charAt(0) !== '#';
      })
      .join('\n')
      .trim();
  }

  function copy(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    // Fallback for non-secure contexts, where the async API is unavailable.
    return new Promise(function (resolve, reject) {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(ta);
      ok ? resolve() : reject(new Error('copy unavailable'));
    });
  }

  function initCopy() {
    var buttons = document.querySelectorAll('.copy');
    Array.prototype.forEach.call(buttons, function (btn) {
      btn.innerHTML = ICON_COPY;
      btn.addEventListener('click', function () {
        var block = btn.closest('.code');
        if (!block) return;
        copy(commandText(block)).then(function () {
          btn.innerHTML = ICON_DONE;
          btn.classList.add('is-done');
          btn.setAttribute('aria-label', 'Copied');
          setTimeout(function () {
            btn.innerHTML = ICON_COPY;
            btn.classList.remove('is-done');
            btn.setAttribute('aria-label', 'Copy command');
          }, 1600);
        }).catch(function () {
          btn.setAttribute('aria-label', 'Copy failed — select the text instead');
        });
      });
    });
  }

  /* ---------------------------------------------------------------------
     Reveal on scroll, and the active nav link
     --------------------------------------------------------------------- */
  function initObservers() {
    var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if ('IntersectionObserver' in window && !reduced) {
      var reveal = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) {
          if (e.isIntersecting) {
            e.target.classList.add('is-in');
            reveal.unobserve(e.target);
          }
        });
      }, { rootMargin: '0px 0px -8% 0px', threshold: 0.04 });
      document.querySelectorAll('.reveal').forEach(function (el) { reveal.observe(el); });
    } else {
      // Without the observer the content must simply be visible.
      document.querySelectorAll('.reveal').forEach(function (el) { el.classList.add('is-in'); });
    }

    if (!('IntersectionObserver' in window)) return;
    var links = Array.prototype.slice.call(document.querySelectorAll('.nav__links a'));
    var byId = {};
    links.forEach(function (a) {
      var id = a.getAttribute('href').replace('#', '');
      if (id) byId[id] = a;
    });
    var spy = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        var link = byId[e.target.id];
        if (!link) return;
        if (e.isIntersecting) {
          links.forEach(function (l) { l.classList.remove('is-active'); });
          link.classList.add('is-active');
        }
      });
    }, { rootMargin: '-45% 0px -50% 0px' });
    Object.keys(byId).forEach(function (id) {
      var el = document.getElementById(id);
      if (el) spy.observe(el);
    });
  }

  /* ------------------------------------------------------------------- */
  function start() {
    applyOrigin();
    initTheme();
    initTabs();
    initCopy();
    initObservers();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
