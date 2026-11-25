# DESIGN.md — VersaNexusIX Design System

Canonical design specification for **David Daryanto (`VersaNexusIX`)** — [`daviddaryanto.my.id`](https://daviddaryanto.my.id). Use this file as the single source of truth for every portfolio page, subdomain microsite, custom endpoint, admin tool, and future web project so the entire ecosystem shares one unmistakable visual language.

---

## 1. Aesthetic Direction

**Industrial Monochrome + Lime Acid · HD-2D Pixel Dreamy**

- **Mood**: Precision engineering meets retro-futuristic HD-2D pixel craft. Quiet obsidian surfaces, razor-sharp 1px grid architecture, stepped pixel framing, subtle dreamy atmospheric light pillars, and surgical bursts of lime acid (`#CCFF00`) strictly for focal points, active signals, and interactive states.
- **Anti-Slop Rule**: Zero generic SaaS rounded cards, zero purple-blue neon gradients, zero glassmorphism blobs, zero drop-shadow stacks, and zero `JetBrains Mono`. Every visual element must feel flat, deliberate, high-contrast, and structurally grounded.

---

## 2. Color Palette & Tokens

| Token | CSS Variable | Hex | Role & Strict Usage |
| :--- | :--- | :--- | :--- |
| **Obsidian Void** | `--bg` | `#0D0D0D` | Primary page canvas, input interiors, deep contrast backing. |
| **Surface** | `--surface` | `#111111` | Primary cards, drawers, tables, modal shells, footer containers. |
| **Panel** | `--panel` | `#141414` | Elevated hover states, active tab fills, code blocks, inspector panels. |
| **Grid Rule** | `--rule` | `#242424` | All 1px structural borders, dividers, table rules, frame outlines. |
| **Paper Ink** | `--paper` | `#F2F2EE` | Primary headings, body copy, high-contrast labels. |
| **Steel Ink** | `--steel` | `#8A8A85` | Secondary descriptions, metadata, timestamps, inactive nav labels. |
| **Lime Acid** | `--acid` | `#CCFF00` | Primary CTAs, active borders, selection highlights, pixel flame hover, online status, Re-Odem helmet/visor. |
| **Critical Crimson** | `--critical` | `#FF3B30` | Destructive actions, validation errors, security intrusion alerts, Re-Odem angry visor. |

### Color Ratio Lock
- **85%** Dark Monochrome (`#0D0D0D`, `#111111`, `#141414`, `#242424`)
- **10%** High-Contrast Neutral Ink (`#F2F2EE`, `#8A8A85`)
- **5%** Signal Accent (`#CCFF00` primary signal; `#FF3B30` strictly for error/security alerts)

Never place `#CCFF00` text on light backgrounds, and never tint entire full-page backgrounds with `#CCFF00`.

---

## 3. Typography System

### Font Import
```css
@import url("https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Plus+Jakarta+Sans:wght@400;500;600;700&family=Silkscreen:wght@400;700&display=swap");
```

### Type Roles

| Role | Font Family | Weights | Usage |
| :--- | :--- | :---: | :--- |
| **Pixel Display** (`.font-pixel`) | `"Silkscreen", "IBM Plex Mono", monospace` | `400`, `700` | Hero `H1`, section `H2`, card `H3`, primary/secondary buttons, status badges, 404/Lockdown headlines, OG banners. |
| **Body & Editorial** | `"Plus Jakarta Sans", Arial, sans-serif` | `400`, `500`, `600`, `700` | Paragraphs, article prose, form labels, drawer body text, technical descriptions. |
| **Technical Mono** | `"IBM Plex Mono", ui-monospace, monospace` | `400`, `500` | Navigation links, URLs, timestamps, file sizes, KPI counters, table numbers, code snippets. |

### Typographic Rules
- **Tabular Numerals**: Always apply `font-variant-numeric: tabular-nums` to counters, timers, file sizes, dates, and table columns.
- **Readable Measure**: Constrain body paragraphs to `52ch–65ch` with `line-height: 1.65–1.75`.
- **Headline Scale**:
  - Hero `H1`: `30px` mobile -> `48px` tablet -> `60px` desktop (`line-height: 1.12`, `letter-spacing: 0.04em`).
  - Section `H2`: `24px` mobile -> `36px` desktop (`line-height: 1.15`).
  - Card `H3`: `14px–16px` (`font-pixel`).
  - Body: `14px–16px` (`Plus Jakarta Sans`).
  - Micro Meta / Mono Labels: `10px–12px` uppercase (`letter-spacing: 0.08em–0.12em`).

---

## 4. Geometry & Layout Invariants

1. **Strict `0px` Border Radius**:
   - Every card, button, input, modal, table, badge, and frame uses `border-radius: 0 !important`.
   - The **only** permitted circular element is the `6px × 6px` `.status-dot` (`ONLINE` indicator).
   - No `box-shadow` or `text-shadow` anywhere (`box-shadow: none !important; text-shadow: none !important`).
2. **Stepped Pixel Corners (`.pixel-frame`)**:
   - Use a 4px stepped polygonal `clip-path` on hero cards, CTAs, status pills, drawers, and focal containers to create crisp pixel-chamfered silhouettes without rounded corners.
3. **Nothing Above Headings (Hard Invariant)**:
   - Never place eyebrow pills, decorative icons, category tags, counters, or mascots directly above `H1`, `H2`, or `H3` headings—including mid-animation or on scroll. Headings must always lead cleanly at the top of their block.
4. **Structural Frame**:
   - Max container width: `1400px` centered (`.site-frame`) with `1px solid #242424` vertical side rules on desktop (`>= 760px`) and `1px solid #242424` horizontal section dividers (or `<PixelSectionDivider />`).
   - Section padding: `24px` mobile, `40px` desktop (`>= 1024px`).
   - Generous whitespace and clean separation—never overlap decorative badges over cards or text.

---

## 5. Component Specifications

### Primary Button (`.admin-primary.pixel-frame.pixel-flame`)
- Background: `#CCFF00`, Text: `#0D0D0D`, Border: `1px solid #CCFF00`
- Font: `Silkscreen`, `11px–12px`, uppercase, `letter-spacing: 0.08em`, padding `12px 20px` (or `14px 28px` for Hero CTAs)
- Hover: Background `#F2F2EE`, Border `#F2F2EE`, Text `#0D0D0D` + Green Pixel Flame rise

### Secondary Button (`.admin-secondary.pixel-frame.pixel-flame`)
- Background: `#0D0D0D`, Text: `#F2F2EE`, Border: `1px solid #242424`
- Hover: Border `#CCFF00`, Text `#CCFF00` + Green Pixel Flame rise

### Destructive Button (`.cms-terminate` / `.infra-danger`)
- Background: `#0D0D0D`, Text: `#FF3B30`, Border: `1px solid #FF3B30`
- Hover: Background `#FF3B30`, Text `#0D0D0D`

### Interactive Cards (`.pixel-frame.pixel-reticle`)
- Background: `#111111`, Border: `1px solid #242424`, Padding: `24px–28px`
- Hover: Border transitions to `#CCFF00`, corner targeting brackets (`.pixel-reticle::before/after`) snap in with `steps(3, end)`, subtle 3D tilt (`Tilt3DCard`) on pointer move.

### Navigation & Filter Tabs (`.pixel-flame-tab`)
- Inactive: `#8A8A85` (`IBM Plex Mono` or `Silkscreen`), transparent or `#111111` surface
- Active: `#CCFF00` text + `#CCFF00` border/underline indicator (`layoutId` spring transition)
- Hover: Green Pixel Flame rises from bottom edge

### Form Controls
- Height: `40px` (`h-10`), Background: `#0D0D0D`, Border: `1px solid #242424`, Text: `#F2F2EE`, Font: `IBM Plex Mono` or `Plus Jakarta Sans`
- Focus: `border-color: #CCFF00`, `outline: none` (keyboard focus-visible on interactive elements uses `outline: 1px solid #CCFF00; outline-offset: 3px`)

### Error Pages (`404` & Security Lockdown)
- No boxed card wrapper for `404`: large centered pixel-art `404` glitch vector directly on `#0D0D0D` canvas with explanation and primary CTA cleanly below.
- Security Lockdown: full-screen `#0D0D0D/96` overlay with scanlines, `#FF3B30` crimson frame, live tabular countdown, and Re-Odem rappel animation.

---

## 6. Motion & Micro-Interaction System

This design system uses a **dual-tempo motion grammar**:

1. **Fluid Structural Motion** (page reveals, scroll depth, drawers, layout tabs):
   - Easing: `cubic-bezier(0.16, 1, 0.3, 1)` (or `[0.22, 1, 0.36, 1]` in Framer Motion)
   - Durations: `150ms–250ms` micro-interactions, `350ms–600ms` section reveals
   - GPU-only properties: `transform`, `opacity`, `clip-path`
2. **Crisp Stepped Pixel Motion** (flames, sprites, reticles, glitch tears, page curtains):
   - Timing function: `steps(2, end)` to `steps(6, end)`
   - **Green Pixel Flame** (`.pixel-flame` / `.pixel-flame-tab`): `420ms steps(4, end) infinite` upward flame shimmer on hover/focus.
   - **Page Curtain** (`.pixel-dream-curtain`): stepped horizontal scan-band wipe with `2px solid #CCFF00` bottom edge on route transitions.
   - **Reduced Motion**: Every animation MUST disable cleanly under `@media (prefers-reduced-motion: reduce)`.

---

## 7. Mascot System — Re-Odem

**Re-Odem** is the industrial pixel engineer mascot across the ecosystem:

- **Visual Spec**: Pixel-art SVG (`image-rendering: pixelated`), `#CCFF00` safety helmet with `#99CC00` brim and blinking beacon, `#141414` head housing `#0D0D0D` visor with `#CCFF00` expressive pixel eyes (switching to `#FF3B30` when angry/alert), `#1C1C1C`/`#242424` work suit, `#CCFF00` boots.
- **Placement Rules**: Never placed above headings. Anchored cleanly on the Hero catwalk, beside section headers, hanging from tab strips (`pose="hang"`), or beside footer/auth bars.
- **Anti-Spam Dialogue**: Silent pixel chat bubble is **hidden by default** and appears only briefly (`~3.6s–4.2s`) on initial greet, user clicks/pokes, or occasional spontaneous reactions (letter heist, startled swipe, trip/fall, laugh, tantrum).
- **Active Defense Mode**: On honeypot or exploit triggers, Re-Odem rappels down from the top edge on a pixel cable, confronts the intruder, executes a randomized screen-glitch strike (`shoot`, `glitch`, `banhammer`, `emp`), and guards the temporary ban countdown.

---

## 8. OpenGraph Banner & SEO Head Standard

Every public page, subdomain, and custom endpoint must maintain:

- **Banner Format**: `1200×630` **Baseline JPEG (`image/jpeg`)** via `/api/og/banner.jpg` using `#0D0D0D` grid canvas, dual subtle lime-acid spectral pillars, `#111111` bordered card, `Silkscreen` title (nothing above it), `128px × 6px` `#CCFF00` divider bar, `DD` monogram badge, `ONLINE` pill, and Re-Odem pixel mark.
- **Head Length Targets**:
  - `<title>`: **50–60 characters** (auto-suffixed with `David Daryanto | VersaNexusIX` when short).
  - `<meta name="description">`: **120–155 characters**.
  - `og:description` & `twitter:description`: **<= 120 characters** (prevents mobile social truncation).
- **Required Tags**: `canonical`, `robots`, `googlebot`, `theme-color="#0D0D0D"`, `color-scheme="dark"`, full `og:*` (including `og:image:secure_url`, `og:image:type="image/jpeg"`, `1200×630`), full `twitter:*` (`summary_large_image`), and Schema.org JSON-LD `@graph` (`Person` + `WebSite` + page schema + `BreadcrumbList`).

---

## 9. Drop-In Starter CSS (`tokens.css`)

Copy this block into any new project, subdomain, or standalone HTML page to match the system immediately:

```css
@import url("https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Plus+Jakarta+Sans:wght@400;500;600;700&family=Silkscreen:wght@400;700&display=swap");

:root {
  --bg: #0D0D0D;
  --surface: #111111;
  --panel: #141414;
  --paper: #F2F2EE;
  --steel: #8A8A85;
  --rule: #242424;
  --acid: #CCFF00;
  --critical: #FF3B30;
  --ease: cubic-bezier(0.16, 1, 0.3, 1);
}

* { box-sizing: border-box; }
*:not(.status-dot) { border-radius: 0 !important; }
*, *::before, *::after { box-shadow: none !important; text-shadow: none !important; }

html, body {
  margin: 0;
  background: var(--bg);
  color: var(--paper);
  font-family: "Plus Jakarta Sans", Arial, sans-serif;
  overflow-x: clip;
}

::selection { background: var(--acid); color: var(--bg); }
:focus-visible { outline: 1px solid var(--acid); outline-offset: 3px; }

.font-pixel { font-family: "Silkscreen", "IBM Plex Mono", monospace; }
.font-mono { font-family: "IBM Plex Mono", ui-monospace, monospace; font-variant-numeric: tabular-nums; }
.status-dot { width: 6px; height: 6px; border-radius: 50% !important; background: var(--acid); display: inline-block; }

.pixel-frame {
  clip-path: polygon(
    0 4px, 4px 4px, 4px 0,
    calc(100% - 4px) 0, calc(100% - 4px) 4px, 100% 4px,
    100% calc(100% - 4px), calc(100% - 4px) calc(100% - 4px), calc(100% - 4px) 100%,
    4px 100%, 4px calc(100% - 4px), 0 calc(100% - 4px)
  );
}

.pixel-reticle { position: relative; }
.pixel-reticle::before,
.pixel-reticle::after {
  content: "";
  position: absolute;
  width: 8px;
  height: 8px;
  pointer-events: none;
  opacity: 0;
  transition: opacity 180ms steps(3, end), transform 180ms steps(3, end);
}
.pixel-reticle::before {
  top: 6px; left: 6px;
  border-top: 2px solid var(--acid); border-left: 2px solid var(--acid);
  transform: translate3d(4px, 4px, 0);
}
.pixel-reticle::after {
  right: 6px; bottom: 6px;
  border-right: 2px solid var(--acid); border-bottom: 2px solid var(--acid);
  transform: translate3d(-4px, -4px, 0);
}
.pixel-reticle:hover::before,
.pixel-reticle:hover::after { opacity: 1; transform: translate3d(0, 0, 0); }

.pixel-flame, .pixel-flame-tab { position: relative; overflow: hidden; isolation: isolate; }
.pixel-flame::before, .pixel-flame-tab::before {
  content: "";
  position: absolute;
  inset: auto 0 0 0;
  height: 100%;
  pointer-events: none;
  opacity: 0;
  z-index: -1;
  background-image:
    linear-gradient(0deg, rgba(204, 255, 0, 0.34) 0%, rgba(164, 255, 0, 0.14) 44%, transparent 82%),
    repeating-linear-gradient(90deg, rgba(204, 255, 0, 0.55) 0 4px, transparent 4px 10px, rgba(242, 242, 238, 0.35) 10px 14px, transparent 14px 20px);
  background-size: 100% 100%, 40px 10px;
  background-position: 0 100%, 0 100%;
  background-repeat: no-repeat, repeat-x;
  transition: opacity 160ms steps(3, end);
}
.pixel-flame:hover::before, .pixel-flame:focus-visible::before,
.pixel-flame-tab:hover::before, .pixel-flame-tab:focus-visible::before {
  opacity: 1;
  animation: pixel-flame-rise 420ms steps(4, end) infinite;
}
.pixel-flame:hover, .pixel-flame-tab:hover { border-color: var(--acid) !important; }

@keyframes pixel-flame-rise {
  0%   { background-position: 0 100%, 0 100%; transform: translate3d(0, 2px, 0); }
  33%  { background-position: 0 92%, 10px 84%; transform: translate3d(0, 0, 0); }
  66%  { background-position: 0 96%, 20px 72%; transform: translate3d(0, -1px, 0); }
  100% { background-position: 0 100%, 40px 100%; transform: translate3d(0, 2px, 0); }
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
```

---

## 10. Quick Consistency Checklist

- [ ] Canvas is `#0D0D0D`, cards are `#111111`, borders are `1px solid #242424`, accent is `#CCFF00`.
- [ ] Headings use `Silkscreen`, body uses `Plus Jakarta Sans`, technical data uses `IBM Plex Mono` (`tabular-nums`).
- [ ] Zero rounded corners (`0px`) except the `6px` `.status-dot`; focal cards/buttons use `.pixel-frame`.
- [ ] Nothing sits above `H1`, `H2`, or `H3` headings.
- [ ] Interactive buttons/tabs use `.pixel-flame` / `.pixel-flame-tab` and cards use `.pixel-reticle`.
- [ ] All animations respect `prefers-reduced-motion`.
- [ ] Every page has a `50–60` char `<title>`, `<= 120` char `og:description`, JSON-LD `@graph`, and `1200×630` `.jpg` pixel banner.
