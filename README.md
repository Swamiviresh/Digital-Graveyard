# Digital Graveyard — Frontend

A static, deployable three-page frontend for the Digital Graveyard AI website-risk analyzer. The original Stitch page layouts are retained, with connected navigation, scroll reveals, and background-free Halloween artwork across the landing page.

## Pages

- `/` — Landing page with scroll-triggered reveals and layered transparent PNG cutouts (ghost, pumpkin, raven, skull, tombstone and lantern/tree).
- `/scan/` — URL entry and staged scan-flow demonstration.
- `/report/` — Investigation report UI with expandable evidence sections and print-to-PDF support.

## Run locally

The site has no build step. From this folder, run:

```bash
python3 -m http.server 5173
```

Then open `http://localhost:5173`. Test the scanner at `http://localhost:5173/scan/`.

## Deploy to Vercel

1. Push this folder to a GitHub repository.
2. Import the repository into Vercel.
3. Select **Other** as the framework preset if Vercel asks.
4. Leave Build Command empty.
5. Set Output Directory to `.` (the project root).
6. Deploy.

The included `vercel.json` enables trailing-slash directory routing for `/scan/` and `/report/`.

## Deploy to Netlify

Import the repository into Netlify. The included `netlify.toml` sets the publish directory to `.` and redirects `/scan` and `/report` to their directory routes.

## Current demo behaviour

This package is a **frontend-only prototype**. The scanner validates and stores the submitted URL, animates the scan stages, then opens the report page. The report values are sample/demo values and are not the result of a live website scan. The frontend does not currently fetch the submitted website, perform SSL/domain/reputation checks, or call an LLM.

The submitted URL is kept in `sessionStorage` so the report page can display the hostname. The report's factor scores and findings remain illustrative until a real backend is connected.

## Backend integration point

When your scanner backend is ready, replace the demo stage sequence in `src/app.js` with a `fetch()` call to your API. A suggested contract is:

```http
POST /api/scan
Content-Type: application/json

{ "url": "https://example.com" }
```

Return a scan result containing a scan ID, evidence, factor scores, risk level and AI explanation. Then populate `/report/` from that result instead of the demo fixture values. Keep AWS credentials and Bedrock model calls on your backend; never expose AWS keys in browser code.

## Landing page imagery and motion

The landing page uses independent background-free PNG cutouts stored in `images/`: ghost, pumpkin, raven, tombstone, tree/lantern, and skull/candle. Each asset is a transparent image layered over the site's own dark background; there are no rectangular image backgrounds and no Three.js scene. The artwork is positioned responsively throughout the hero, process, feature, and closing sections.

IntersectionObserver-based scroll reveals use a restrained fade, lift and blur transition with staggered timing. Decorative artwork uses gentle CSS floating motion. Both effects respect the user's reduced-motion preference and are confined to the landing page.

## Report export

The report's Download buttons open the browser print dialog. Choose **Save as PDF** to export.

## Shared header and footer

All three routes use the same fixed, responsive header with the Digital Graveyard logo lockup, route navigation, online indicator, and scan CTA. On smaller screens the navigation collapses into an accessible menu button. The same footer appears on every route. The Platform and Security Protocols link columns shown in the reference screenshot have been removed, while the footer itself remains: it includes the homepage link, a live URL that is populated from the current site origin, the security-assessment disclaimer, the GitHub repository link, and the copyright notice. The URL therefore updates automatically on localhost, preview deployments, and the production domain.
