---
name: TunnelTrace.AI
description: An editorial workstation for traceable IPsec packet investigations.
colors:
  ground: "#f0efe8"
  panel: "#f7f6f0"
  panel-recessed: "#e8e7df"
  charcoal: "#151714"
  ink: "#171815"
  ink-secondary: "#484a43"
  ink-muted: "#686a62"
  rule: "#d1d0c6"
  rule-strong: "#9e9e92"
  signal-lime: "#a8c400"
  signal-pressed: "#8ea600"
  signal-soft: "#e7edc8"
  danger: "#b83830"
  positive: "#495d3c"
typography:
  display:
    fontFamily: "Iowan Old Style, Palatino Linotype, Book Antiqua, Georgia, serif"
    fontSize: "clamp(2.4rem, 6.4vw, 6.7rem)"
    fontWeight: 500
    lineHeight: 0.93
    letterSpacing: "-0.065em"
  headline:
    fontFamily: "Iowan Old Style, Palatino Linotype, Book Antiqua, Georgia, serif"
    fontSize: "clamp(2.15rem, 4.2vw, 3.8rem)"
    fontWeight: 500
    lineHeight: 0.98
    letterSpacing: "-0.06em"
  title:
    fontFamily: "Iowan Old Style, Palatino Linotype, Book Antiqua, Georgia, serif"
    fontSize: "1.5rem"
    fontWeight: 500
    lineHeight: 1.04
    letterSpacing: "-0.055em"
  body:
    fontFamily: "Arial, Helvetica Neue, sans-serif"
    fontSize: "0.9rem"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: "SFMono-Regular, Consolas, Liberation Mono, monospace"
    fontSize: "0.65rem"
    fontWeight: 400
    lineHeight: 1.35
    letterSpacing: "0.11em"
rounded:
  none: "0px"
spacing:
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "32px"
components:
  button-primary:
    backgroundColor: "{colors.signal-lime}"
    textColor: "#15180a"
    rounded: "{rounded.none}"
    padding: "12px 20px"
  button-secondary:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "8px 16px"
  field:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    height: "44px"
    padding: "0 12px"
  card:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "20px 0"
---

# Design System: TunnelTrace.AI

## Overview

**Creative North Star: “The Evidence Register”**

TunnelTrace is an editorial field register for IPsec forensics. Warm paper, sharply ruled sections, oversized serif headlines, and compact instrument typography make complex protocol evidence feel legible without turning the application into a generic dashboard. The shell and investigation pages prioritize open space and asymmetry; dense technical records stay orderly and data-forward.

The light paper workspace is balanced by charcoal narrative panels. Muted lime marks active paths, important actions, and verified or live signals. Runtime status and investigation records come from the local API, while the home diagram is explicitly marked as a schematic. Motion traces paths and reveals content gently, with reduced-motion settings honored.

**Key Characteristics:**
- Editorial serif display paired with neutral sans and monospaced instrument labels.
- Warm paper and charcoal surfaces, divided by fine rules rather than card grids.
- Lime is a scarce signal color; red communicates genuine danger or failure.
- Asymmetric layouts and expansive typography frame precise, API-backed evidence.

## Colors

The palette is a warm, low-chroma paper register with charcoal contrast and one restrained lime signal.

### Primary
- **Muted Signal Lime** (`{colors.signal-lime}`): Primary actions, current workflow marks, key links in data visualizations, and selected states. It is an accent, not a surface theme.

### Neutral
- **Warm Ground** (`{colors.ground}`): Main page canvas and the exposed background around records.
- **Soft Paper** (`{colors.panel}`): Quiet input and inset surfaces.
- **Recessed Paper** (`{colors.panel-recessed}`): Secondary panels, hover fills, and subdued data surfaces.
- **Charcoal Field** (`{colors.charcoal}`): Narrative sections and schematic illustration backgrounds.
- **Ink** (`{colors.ink}`): Primary text and high-contrast controls.
- **Secondary Ink** (`{colors.ink-secondary}`): Supporting prose and secondary labels.
- **Muted Ink** (`{colors.ink-muted}`): Metadata and low-priority annotation.
- **Fine Rule** (`{colors.rule}`): Table and section separators.
- **Strong Rule** (`{colors.rule-strong}`): Emphasized borders and field outlines.

### Named Rules
**The Signal-Not-Wash Rule.** Keep lime to a small, meaningful signal. Use it for actions, active navigation, state markers, and selected data points; leave broad surfaces paper or charcoal.

**The Truthful-State Rule.** Render service health, scores, findings, and captures from actual application data. Red is reserved for real failures and critical risk.

## Typography

**Display Font:** Iowan Old Style (with Palatino Linotype, Book Antiqua, Georgia, serif fallbacks)  
**Body Font:** Arial (with Helvetica Neue, sans-serif fallbacks)  
**Label/Mono Font:** SFMono-Regular (with Consolas, Liberation Mono, monospace fallbacks)

**Character:** The serif carries the editorial voice in large headings; the sans keeps application reading neutral and familiar. Monospaced labels and numeric values make protocol details, identifiers, and state legible as instrument readouts.

### Hierarchy
- **Display** (500, fluid 2.4–6.7rem, line-height 0.93): Home statement and the strongest editorial declaration.
- **Headline** (500, fluid 2.15–3.8rem, line-height 0.98): Route titles and major section headings.
- **Title** (500, typically 1.5–3rem, tight tracking): Wordmark and subsection titles.
- **Body** (400, 0.9rem, line-height 1.55): Application content and supporting prose; longer copy is constrained to readable measure.
- **Label** (400, 0.65rem, line-height 1.35, tracked uppercase): Compact metadata, state labels, and technical annotations.

### Named Rules
**The Three-Voice Rule.** Use serif for editorial hierarchy, sans serif for readable interface copy, and mono for measurements, identifiers, and instrument labels.

## Layout

The shell uses a centered, wide reading field (up to 94rem) with responsive side insets that tighten on small screens. Large editorial surfaces use an asymmetric two-column composition; content-heavy routes retain compact tables, ruled lists, and aligned data columns. Sections are separated with whitespace and thin horizontal rules instead of repeated floating cards. At narrow widths, multi-column compositions collapse into a single reading sequence, and navigation becomes a compact expandable menu. Investigation routes expose their page index in an expandable region.

Spacing is built from repeated 8px steps, with 16px and 24–32px intervals for control padding and section rhythm. The home page gives display type and its schematic room to breathe; operational pages can increase information density while preserving label and value alignment.

## Elevation & Depth

Depth is predominantly tonal and structural: warm paper against recessed paper, charcoal narrative fields, and fine borders. Broad drop shadows are not a primary surface treatment; a small paper label may lift slightly over the schematic. Sticky navigation uses a translucent ground tint and blur. Use rules, background tone, and whitespace to establish hierarchy before adding elevation.

## Shapes

The form language is square and precise. Controls, panels, and navigation use zero-radius corners; boundaries come from one-pixel rules and changes in paper tone. Schematic geometry uses measured lines, nodes, and rectangular packet/evidence frames. Keep charts and diagrams clipped within their region rather than adding pill-shaped dashboard containers.

## Components

### Buttons
- **Character:** Compact, square controls with clear text and a restrained state transition.
- **Shape:** Square corners (0px).
- **Primary:** Muted lime fill with near-black text; medium and large sizes use 16–20px horizontal padding and 8–12px vertical padding.
- **Hover / Focus:** Primary deepens toward the brighter lime hover color; all controls receive a visible offset focus outline. Disabled controls reduce opacity and stop pointer interaction.
- **Secondary / Ghost:** Secondary is a fine ink outline that fills with ink on hover; ghost actions rely on an underline or text change.
- **Danger:** Red outline/text appears only for destructive or genuinely dangerous actions.

### Chips
- **Style:** Compact uppercase text with a small state dot and no pill background by default.
- **State:** Positive states use subdued green; queued/running states use restrained status tones; failed and critical states use red. Running and queued markers may pulse.

### Cards / Containers
- **Character:** Open register sections, not a field of rounded tiles.
- **Corner Style:** Square (0px).
- **Background:** Ground, soft/recessed paper, or charcoal according to hierarchy.
- **Shadow Strategy:** Flat by default; separators and tonal contrast carry depth.
- **Border:** Fine horizontal rules; stronger borders are reserved for fields and explicit boundaries.
- **Internal Padding:** Common vertical intervals are 20–28px; dense list rows use tighter rhythm.

### Inputs / Fields
- **Style:** Transparent fill, square corners, and a one-pixel strong-rule outline; standard controls are 44px tall.
- **Focus:** Ink border and a short underline cue, plus the global offset focus outline for keyboard navigation.
- **Error / Disabled:** Error copy and border use danger red; disabled controls lower opacity and cannot be activated.

### Navigation
- **Style:** Sticky, translucent paper header with wordmark, primary links, and a clear new-analysis action. Active route text is emphasized; hover shifts secondary ink toward primary ink.
- **Expandable navigation:** Workspace and Operations open full-width, ruled link panels with a short editorial introduction. Escape closes them, and route changes collapse them.
- **Mobile:** The full navigation becomes a menu button and vertically ruled link list.

### Packet Atlas
- **Character:** A custom SVG schematic joining observed packets, protocol state, and derived evidence.
- **Treatment:** Charcoal field, fine grid, pale paths, and a lime traveling path with restrained node pulses. Label it as a schematic so it cannot be mistaken for observed capture data.

### Investigation Register
- **Character:** API-backed rows that prioritize capture identity, analysis state, posture, findings, and update time.
- **Treatment:** Use thin row rules and tabular identifiers; preserve explicit loading, empty, and API-error states instead of substituting sample telemetry.

## Do's and Don'ts

### Do:
- **Do** use warm paper as the default reading surface and charcoal for deliberate narrative contrast.
- **Do** reserve the lime accent for real actions, active paths, and meaningful state indicators.
- **Do** keep status and evidence values tied to the backend; label illustrative diagrams as schematics.
- **Do** keep the serif/sans/mono roles distinct and honor reduced-motion preferences.
- **Do** use thin rules and aligned columns to organize dense investigation data.

### Don't:
- **Don't** introduce blue, cyan, purple, violet, pink, magenta, orange, or yellow as interface colors.
- **Don't** use lime as a broad background or decorate unrelated elements with it.
- **Don't** turn the shell into a sidebar-first, rounded-card dashboard.
- **Don't** imply service readiness, capture records, or security findings that the API has not supplied.
- **Don't** use red for ordinary emphasis or informational decoration.
