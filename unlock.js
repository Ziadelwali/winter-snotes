/* Opens the private page. The passphrase is never stored: the first time it derives keys that
   cannot be read back out (IndexedDB 'pp'), and later opens use those keys directly.
   Needs sync.js (SYNC2) first. Nothing decrypted is written to storage by this file; the page's own
   local copy is kept sealed with the data key. */
(function () {
  'use strict';
  var f = document.getElementById('f'), p = document.getElementById('p'),
      b = document.getElementById('b'), m = document.getElementById('m');
  var BOX = null; try { BOX = JSON.parse(document.getElementById('ct').textContent); } catch (e) {}

  /* IndexedDB 'pp'/'kv'. Without IndexedDB the keys live in memory only, so the passphrase is asked on every open. */
  var kv = (function () {
    var dbp = null, mem = {};
    function db() {
      if (!dbp) dbp = new Promise(function (res, rej) {
        if (!window.indexedDB) return rej(new Error('no IndexedDB'));
        var r = indexedDB.open('pp', 1);
        r.onupgradeneeded = function () { r.result.createObjectStore('kv'); };
        r.onsuccess = function () { res(r.result); }; r.onerror = function () { rej(r.error); };
      });
      return dbp;
    }
    function tx(mode, fn) {
      return db().then(function (d) {
        return new Promise(function (res, rej) {
          var t = d.transaction('kv', mode), q = fn(t.objectStore('kv'));
          t.oncomplete = function () { res(q && q.result); }; t.onerror = t.onabort = function () { rej(t.error); };
        });
      });
    }
    return {
      get: function (k) { return tx('readonly', function (s) { return s.get(k); }).then(function (v) { return v == null ? (mem[k] || null) : v; }, function () { return mem[k] || null; }); },
      set: function (k, v) { mem[k] = v; return tx('readwrite', function (s) { s.put(v, k); }).catch(function () {}); },
      del: function (k) { delete mem[k]; return tx('readwrite', function (s) { s.delete(k); }).catch(function () {}); },
      clear: function () { mem = {}; return tx('readwrite', function (s) { s.clear(); }).catch(function () {}); }
    };
  })();

  function say(t) { m.textContent = t; }
  function busy(on) { b.disabled = on; b.textContent = on ? 'Unlocking…' : 'Unlock'; }
  /* this page's localStorage keys all start with "pp." (the page moves older ones there on its first start) */
  function forget() {
    try { Object.keys(localStorage).forEach(function (k) { if (k.indexOf('pp.') === 0) localStorage.removeItem(k); }); } catch (e) {}
    return kv.clear();
  }

  /* keep a copy of this page on the device so it opens with no signal. A new version is never
     forced on an open page: PP_UPDATE is set, and the page offers the reload (PP_onUpdate). */
  if ('serviceWorker' in navigator && location.hostname !== 'localhost') {
    var had = !!navigator.serviceWorker.controller;
    navigator.serviceWorker.addEventListener('controllerchange', function () {
      if (had) { window.PP_UPDATE = true; if (typeof window.PP_onUpdate === 'function') window.PP_onUpdate(); }
      had = true;
    });
    navigator.serviceWorker.register('sw.js').then(function (r) { try { r.update(); } catch (e) {} }).catch(function () {});
  }

  function show(html, keys, pass) {
    /* the page's sealed local copy, opened here so the page can draw at once */
    return kv.get('local').then(function (rec) {
      return SYNC2.openLocal(keys.dataKey, rec).catch(function () { return null; });
    }).then(function (local) {
      window.PP_UNLOCK = { keys: keys, pass: pass || null, local: local, kv: kv };
      document.open(); document.write(html); document.close();
    });
  }

  /* from stored keys: no typing */
  function fromKeys(rec) {
    return SYNC2.openPage(rec.pageKey, BOX).then(function (html) { return show(html, rec, null); });
  }
  /* from a typed passphrase (or one an older version left in localStorage) */
  function fromPass(pass, quiet) {
    return SYNC2.deriveKeys(pass).then(function (k) {
      return SYNC2.openPage(k.pageKey, BOX).then(function (html) {
        return kv.get('keys').then(function (old) {
          var rec = { pageKey: k.pageKey, docId: k.docId, dataKey: k.dataKey, cfgKey: k.cfgKey };
          if (old && old.v1Id) rec.v1Id = old.v1Id;
          // a different passphrase than before: the page takes the old copy along once
          if (old && old.docId && old.docId !== k.docId) rec.prev = { docId: old.docId, dataKey: old.dataKey };
          return kv.set('keys', rec).then(function () { return kv.get('keys'); }).then(function (back) {
            if (back && back.docId === rec.docId) { try { localStorage.removeItem('pp.k'); } catch (e) {} }
            return show(html, rec, SYNC2.norm(pass));
          });
        });
      });
    }).catch(function (e) {
      // a wrong passphrase fails the AES-GCM check (OperationError); anything else is the browser
      var why = (e && e.name || 'Error') + ': ' + (e && e.message || e);
      if (!quiet) say(/DecompressionStream|format/.test(why) ? 'This browser is too old to open the page. Update it and try again.'
        : (e && e.name === 'OperationError') ? 'That passphrase is not right.'
        : 'This browser could not open the page (' + why + ').');
      busy(false);
      throw e;
    });
  }

  if (location.hash === '#forget') { forget(); say('Forgotten on this device.'); }
  try { addEventListener('hashchange', function () { if (location.hash === '#forget') forget().then(function () { location.reload(); }); }); } catch (e) {}
  if (!(window.crypto && crypto.subtle && window.SYNC2 && BOX)) {
    say('This page must be opened over https to decrypt.'); b.disabled = true; return;
  }

  f.addEventListener('submit', function (e) {
    e.preventDefault(); var v = SYNC2.norm(p.value);
    if (!v) { say('Type the passphrase.'); return; }
    say(''); busy(true);
    setTimeout(function () { fromPass(v, false).catch(function () {}); }, 20);
  });

  if (location.hash === '#forget') { try { p.focus(); } catch (e) {} return; }
  busy(true);
  kv.get('keys').then(function (rec) {
    if (rec && rec.pageKey) {
      return fromKeys(rec).catch(function () {
        // the passphrase changed since these keys were made: keep them as the old copy, ask for the new one
        busy(false); say('The passphrase has changed. Type the new one.'); try { p.focus(); } catch (e) {}
      });
    }
    var legacy = null; try { legacy = localStorage.getItem('pp.k'); } catch (e) {}
    if (legacy) return fromPass(legacy, true).catch(function () { try { localStorage.removeItem('pp.k'); } catch (e) {} busy(false); try { p.focus(); } catch (e) {} });
    busy(false); try { p.focus(); } catch (e) {}
  });
})();
