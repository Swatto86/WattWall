// Line icons for buttons and banners, drawn in the text colour.

const svg = (body: string): string =>
  `<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;

export const icon = {
  search: svg('<circle cx="11" cy="11" r="6.5"/><path d="M16 16l4.5 4.5"/>'),
  plus: svg('<path d="M12 5v14M5 12h14"/>'),
  settings: svg('<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>'),
  pause: svg('<rect x="6.5" y="5" width="3.5" height="14" rx="1"/><rect x="14" y="5" width="3.5" height="14" rx="1"/>'),
  play: svg('<path d="M8 5.5v13l10-6.5z"/>'),
  close: svg('<path d="M6 6l12 12M18 6L6 18"/>'),
  warning: svg('<path d="M12 3.5L21.5 20h-19z"/><path d="M12 10v4.5M12 17.5v.01"/>'),
  info: svg('<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.5v.01"/>'),
  download: svg('<path d="M12 4v11M7 10.5l5 5 5-5M5 20h14"/>'),
  up: svg('<path d="M12 19V6M6.5 11.5L12 6l5.5 5.5"/>'),
  down: svg('<path d="M12 5v13M6.5 12.5L12 18l5.5-5.5"/>'),
  ban: svg('<circle cx="12" cy="12" r="8.5"/><path d="M6 6l12 12"/>'),
  shield: svg('<path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6z"/><path d="M8.8 12.2l2.2 2.2 4.3-4.6"/>'),
  wall: svg('<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 9.7h18M3 14.3h18M12 5v4.7M7.5 9.7v4.6M16.5 9.7v4.6M12 14.3V19"/>'),
};
