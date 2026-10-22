# PHP2Shell Checker

Einfaches Tool: Domain eingeben → prüft per HTTP-Header, ob die Seite PHP
nutzt und ob die Version gegen die PHP2Shell-Lücken (CVE-2026-109618 /
CVE-2026-109619) gepatcht ist.

Reine Header-Heuristik (`X-Powered-By`, `PHPSESSID`-Cookie), kein aktiver
Exploit-Scan. Viele Hoster blenden diese Header bewusst aus – "kein PHP
erkannt" heißt nicht automatisch "sicher".

## Lokal starten

```bash
npm i -g vercel
vercel dev
```

Dann im Browser `http://localhost:3000` öffnen.

## Deployen

```bash
vercel        # erstellt/verknüpft das Projekt
vercel --prod # Produktions-Deploy
```

Oder: Repo auf GitHub pushen und in Vercel importieren (Dashboard →
"Add New Project" → Repo auswählen). Kein Build-Step nötig, Vercel
erkennt `/api/check.js` automatisch als Serverless Function und
serviert `index.html` statisch.

## Patch-Stand (Stand 22.10.2026)

Gepatchte Versionen: **8.5.12, 8.4.27, 8.3.36, 8.2.35**
Alles darunter (inkl. PHP < 8.2) gilt als verwundbar.
