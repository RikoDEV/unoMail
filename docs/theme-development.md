# Writing themes

A theme is a package of design tokens, images and per-part styles. It contains no code: the
web client turns the tokens into its Material 3 theme. Installing themes is described in
[Plug-ins and themes](plugins.md). The complete example is
[`examples/themes/solarized`](examples/themes/solarized).

## Layout

```text
my-theme/
├── unomail.json
└── background.webp      optional images, referenced from the manifest
```

```json
{
  "schema": 2,
  "id": "solarized",
  "type": "theme",
  "name": "Solarized",
  "version": "2.0.0",
  "description": "…",
  "license": "MIT",
  "theme": {
    "mode": "light",
    "primary": "#268bd2",
    "images": { "page": "background.png" },
    "parts": { "sidebar": { "background": "#eee8d5", "opacity": 0.7, "blur": 12 } }
  }
}
```

- `schema`, `id`, `type`, `name` and `version` are required. `description`, `author`,
  `license` and `homepage` work as for [plug-ins](plugin-development.md#the-manifest).
- A theme may not declare `api`, `entry`, `permissions`, `settings` or `server`.
- `theme` must not contain `id` or `name`; they come from the manifest.
- Unknown tokens or parts, and values out of range, make the package invalid. The
  administrator sees why when fetching it.

## Tokens

| Token | Values | Effect |
| --- | --- | --- |
| `mode` | `light`, `dark`, `auto` (default) | Forces light or dark; `auto` follows the user's choice |
| `primary` | `#rrggbb` | Accent colour. The tonal colour scheme is generated from it. Without it, the user's own accent is used |
| `secondary`, `tertiary`, `error` | `#rrggbb` | Override those roles of the scheme |
| `background` | `#rrggbb` | The page behind the panes |
| `paper` | `#rrggbb` | Panes, cards and dialogs |
| `text` | `#rrggbb` | Body text |
| `radius` | 0–32 | Corner radius in pixels. From 12, shapes animate the Material 3 Expressive way |
| `spacing` | 4–12 | Pixels per spacing unit (default 8, compact 6) |
| `density` | `comfortable`, `compact` | Smaller controls and type |
| `fontScale` | 0.85–1.25 | Scales the base font size |
| `font` | `roboto`, `system`, `serif`, `mono` | Typeface; custom fonts aren't supported |
| `images` | object | See [Images](#images) |
| `imageFit` | `cover` (default), `contain`, `tile` | How images fill their place |
| `parts` | object | See [Parts](#parts) |

## Images

```json
"images": { "page": "art/background.webp", "sidebar": "art/sidebar.png", "login": "art/login.jpg" }
```

| Place | Where it shows |
| --- | --- |
| `page` | Behind the whole application. The page backgrounds become transparent so it shows through; make panes translucent with `parts` to see it behind them |
| `sidebar` | Behind the folder list and the settings and admin navigation |
| `login` | Behind the sign-in page |

- Files must be PNG, JPEG or WebP, at most 2 MB each, at relative paths inside the package.
- Their content must match the extension; this is checked when the package is fetched.
- They're served from `/package-asset/<id>/<commit>/<path>` with long caching. The address
  changes with every update.
- Remote images, SVG and CSS `url()` aren't accepted.
- For page images, choose a calm picture with the background colour's lightness, and test
  it in light and dark mode.

## Parts

Each part takes styles for one area of the interface:

| Part | Area |
| --- | --- |
| `appBar` | The top bar with the search box |
| `sidebar` | Folder list, settings and admin navigation |
| `messageList` | The list of messages |
| `messageRow` | One row of that list |
| `reader` | The open conversation |
| `composer` | The new-message window |
| `card` | Cards (settings, administration) |
| `dialog` | Dialog windows |
| `button` | Buttons |
| `input` | Text fields |
| `chip` | Chips and tags |

| Property | Values | Notes |
| --- | --- | --- |
| `background` | `#rrggbb`, or `linear-gradient(<0–360>deg, #rrggbb [<0–100>%], …)` | Gradients take 2 to 4 stops, written exactly like this |
| `color` | `#rrggbb` | Text colour |
| `borderColor` | `#rrggbb` | Adds a solid border (1 px unless `borderWidth`) |
| `borderWidth` | 0–4 | Pixels |
| `radius` | 0–32 | Pixels |
| `shadow` | `none`, `low`, `medium`, `high` | |
| `opacity` | 0.6–1 | Makes the part's background translucent; its text stays opaque |
| `blur` | 0–24 | Backdrop blur in pixels, for frosted panes over an image |
| `fontWeight` | 400–800, in steps of 100 | |
| `fontSize` | 0.8–1.3 | Relative to the inherited size |
| `textTransform` | `none`, `uppercase` | |

**What a theme can't do**
- Hide, move, resize or overlay anything: there are no `display`, `position`, `content`,
  `z-index` or sizes.
- Load anything from elsewhere.
- Make text unreadable. When a part's text has less than 3:1 contrast with every colour of
  its background, the theme's standard text colour is used instead.

## Skins pasted as JSON

Administrators can also paste skins under **Integrations → Skins** without a repository:

```json
[{ "id": "ocean", "name": "Ocean", "mode": "dark", "primary": "#0061a4", "parts": { "button": { "radius": 32 } } }]
```

They take the same tokens, except `images`, which only packages can carry.

## Testing

- Fetching the package in **Integrations** validates it without installing it.
- Pick the theme in **Settings → General** and check:
  - light and dark mode
  - the mail page, settings, administration and sign-in
  - a narrow window
- Change the version and push a new tag to update. Users who chose the theme get the new
  version on their next page load.
