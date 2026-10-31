# Digital Graveyard — Frontend

A static, deployable three-page frontend for the Digital Graveyard AI website-risk analyzer. The original Stitch page layouts are retained and their navigation and interactions have been connected.

## Pages

- `/` — Landing page with procedural real-time Three.js ghost, pumpkin and vampire meshes.
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

## 3D scene

The Halloween characters are real Three.js procedural meshes generated in `src/landing-scene.js`, not still images. The scene is only loaded on the landing page. Three.js is imported from jsDelivr, while the Stitch styling uses Tailwind CDN, Google Fonts and Material Symbols CDN; an internet connection is required for these external resources.

## Report export

The report's Download buttons open the browser print dialog. Choose **Save as PDF** to export.
