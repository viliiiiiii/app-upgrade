document.addEventListener('DOMContentLoaded', () => {
  /* =========================
     ROOMS (manual only + datalist)
     - No dropdown for room; user types a number
     - We still fetch rooms for the selected building to:
       a) populate datalist suggestions, and
       b) validate on submit (alert if not found)
     ========================= */
  const roomsCache = new Map(); // buildingId -> [{id,label}] where label starts with room_number
  const buildingSelect = document.querySelector('[data-room-source]');
  const roomInput      = buildingSelect ? document.getElementById(buildingSelect.dataset.roomInput) : null;
  const datalistEl     = buildingSelect ? document.getElementById(buildingSelect.dataset.roomDatalist) : null;

  async function fetchRooms(buildingId){
    if(!buildingId) return [];
    if(roomsCache.has(buildingId)) return roomsCache.get(buildingId);
    const res = await fetch(`rooms.php?action=by_building&id=${encodeURIComponent(buildingId)}`, { credentials:'same-origin' });
    if(!res.ok) throw new Error('Failed to load rooms');
    const data = await res.json(); // [{id,label: "006 - Kitchen"}]
    roomsCache.set(buildingId, data || []);
    return data || [];
  }

  function extractRoomNumber(label){
    // Your PHP returns: "room_number" or "room_number - Label"
    if (typeof label !== 'string') return '';
    const idx = label.indexOf(' - ');
    return (idx === -1 ? label : label.slice(0, idx)).trim();
  }

  function fillDatalist(rooms){
    if(!datalistEl) return;
    datalistEl.innerHTML = '';
    rooms.forEach(r => {
      const num = extractRoomNumber(r.label);
      if(!num) return;
      const o = document.createElement('option');
      o.value = num;
      datalistEl.appendChild(o);
    });
  }

  function validateManual(rooms){
    if(!roomInput) return true;
    const val = roomInput.value.trim();
    if(!val){ roomInput.setCustomValidity(''); return true; }
    const exists = rooms.some(r => extractRoomNumber(r.label).toLowerCase() === val.toLowerCase());
    if(!exists){
      roomInput.setCustomValidity('This room does not exist for the selected building.');
      return false;
    }
    roomInput.setCustomValidity('');
    return true;
  }

  if(buildingSelect){
    buildingSelect.addEventListener('change', async (event) => {
      const buildingId = event.target.value;
      if (!buildingId) {
        if (datalistEl) datalistEl.innerHTML = '';
        return;
      }
      try{
        const rooms = await fetchRooms(buildingId);
        fillDatalist(rooms);
      }catch(_){ /* ignore */ }
    });
  }

  // Validate on blur for quick feedback
  if(roomInput && buildingSelect){
    roomInput.addEventListener('blur', async () => {
      const id = buildingSelect.value;
      if(!id) return;
      try{
        const rooms = await fetchRooms(id);
        validateManual(rooms);
      }catch(_){}
    });
  }

  /* ======================================
     TASK CREATE FORM — client-side checks
     ====================================== */
  const createForm = document.querySelector('[data-create-task]');
  if(createForm && roomInput && buildingSelect){
    createForm.addEventListener('submit', async (e) => {
      const buildingId = buildingSelect.value;
      if(!buildingId){ return; } // native "required" will handle
      try{
        const rooms = await fetchRooms(buildingId);
        const ok = validateManual(rooms);
        if(!ok){
          e.preventDefault();
          alert('Room does not exist in the selected building.');
          roomInput.reportValidity();
          return false;
        }
      }catch(_){ /* if fetch fails, let server validate */ }
      return true;
    });
  }

  /* ===========================================================
     ORBITAL LIGHT ADDITIONS — mobile header + image modal
     - Non-destructive: no overrides to your existing functions
     =========================================================== */

  // 1) Collapsible mobile header (hamburger toggles nav)
  (function initMobileHeader(){
    const toggle = document.querySelector('.nav-toggle');
    const wrap   = document.querySelector('.nav-wrap');
    if (!toggle || !wrap) return;

    const setExpanded = (open) => toggle.setAttribute('aria-expanded', open ? 'true' : 'false');

    toggle.addEventListener('click', () => {
      wrap.classList.toggle('open');
      setExpanded(wrap.classList.contains('open'));
    });

    // Close on ESC or when clicking outside the open area (mobile)
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && wrap.classList.contains('open')) {
        wrap.classList.remove('open');
        setExpanded(false);
      }
    });
    document.addEventListener('click', (e) => {
      if (!wrap.classList.contains('open')) return;
      const withinNav = e.target.closest('.nav-wrap') || e.target.closest('.nav-toggle');
      if (!withinNav) {
        wrap.classList.remove('open');
        setExpanded(false);
      }
    });
  })();

  // 2) Bulletproof Image Modal
  (function initImageModal(){
    const CLICK_SEL = '.thumbs img, img[data-modal], a[data-modal], a[data-full]';
    let modal;

    function ensureModal() {
      if (modal) return modal;
      modal = document.createElement('div');
      modal.className = 'media-modal';
      modal.innerHTML = `
        <div class="media-modal__inner" role="dialog" aria-modal="true" aria-label="Image viewer">
          <button class="media-modal__close" aria-label="Close">&times;</button>
          <img class="media-modal__img" alt="">
          <div class="media-modal__bar">
            <span class="media-modal__caption"></span>
            <a class="btn small secondary" target="_blank" rel="noopener" data-full>Open original</a>
          </div>
        </div>`;
      document.body.appendChild(modal);

      const close = () => modal.classList.remove('open');

      // Close on backdrop click, close button, or ESC
      modal.addEventListener('click', (e) => { if (e.target === modal) close(); });
      modal.querySelector('.media-modal__close').addEventListener('click', close);
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && modal.classList.contains('open')) close();
      });

      return modal;
    }

    function openModal(src, alt, href) {
      const m = ensureModal();
      const img = m.querySelector('.media-modal__img');
      const cap = m.querySelector('.media-modal__caption');
      const link = m.querySelector('[data-full]');

      // Preload before showing for smoother UX
      const pre = new Image();
      pre.onload = () => {
        img.src = src;
        img.alt = alt || '';
        cap.textContent = alt || '';
        link.href = href || src;
        m.classList.add('open');
      };
      pre.onerror = () => {
        img.src = '';
        cap.textContent = 'Unable to load image.';
        link.removeAttribute('href');
        m.classList.add('open');
      };
      pre.src = src;
    }

    document.addEventListener('click', function (e) {
      const node = e.target.closest(CLICK_SEL);
      if (!node) return;

      // IMG: use data-full/src + alt
      if (node.tagName === 'IMG') {
        const src  = node.dataset.full || node.currentSrc || node.src;
        const alt  = node.alt || '';
        const href = node.closest('a')?.href || node.dataset.href || src;
        e.preventDefault();
        openModal(src, alt, href);
        return;
      }

      // A: prefer data-full or href if it's an image link or explicitly data-modal
      if (node.tagName === 'A') {
        const href = node.getAttribute('href') || '';
        const full = node.dataset.full || href;
        const img  = node.querySelector('img');
        const alt  = (img && img.alt) || node.getAttribute('title') || '';
        const isImgLike = /\.(png|jpe?g|webp|gif|heic|heif)$/i.test(full) || node.hasAttribute('data-modal');
        if (!isImgLike) return;
        e.preventDefault();
        openModal(full, alt, full);
        return;
      }
    }, false);
  })();

});
