// api/check.js
// Vercel Serverless Function (Node.js runtime)
// Prüft eine Domain per HTTP-Header-Analyse auf PHP-Nutzung und ordnet eine
// erkannte PHP-Version gegen den PHP2Shell-Patch-Stand ein (CVE-2026-109618 / CVE-2026-109619).
//
// WICHTIG: Das ist eine reine Informations-Heuristik, kein Sicherheits-Scan.
// Viele Server verstecken "X-Powered-By" bewusst - "nicht erkennbar" heißt
// nicht zwangsläufig "sicher".

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');

  const rawDomain = (req.query.domain || '').toString().trim();

  if (!rawDomain) {
    return res.status(400).json({
      error: 'Bitte eine Domain angeben, z.B. /api/check?domain=example.com',
    });
  }

  let targetUrl;
  try {
    const normalized = /^https?:\/\//i.test(rawDomain) ? rawDomain : `https://${rawDomain}`;
    targetUrl = new URL(normalized);
  } catch {
    return res.status(400).json({ error: 'Ungültige Domain.' });
  }

  // Gepatchte Mindestversionen je Minor-Branch (Stand: PHP-Release vom 21.10.2026)
  const PATCHED_PATCH_LEVEL = { 5: 12, 4: 27, 3: 36, 2: 35 };

  function evaluateVersion(major, minor, patch) {
    if (major < 8) return 'vulnerable'; // PHP < 8 nie gepatcht, EOL ohnehin
    if (major === 8 && minor < 2) return 'vulnerable'; // < 8.2 bekommt keinen Fix
    if (major > 8) return 'patched'; // zukünftige Hauptversion, vorsichtig optimistisch
    const minPatch = PATCHED_PATCH_LEVEL[minor];
    if (minPatch === undefined) return 'unknown_branch';
    return patch >= minPatch ? 'patched' : 'vulnerable';
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 6000);

  let response;
  try {
    response = await fetch(targetUrl.toString(), {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'User-Agent': 'PHP2Shell-Checker/1.0 (+informational header check, no exploitation)',
      },
    });
  } catch (err) {
    clearTimeout(timeoutId);
    const reason = err.name === 'AbortError' ? 'Zeitüberschreitung (Server antwortet nicht innerhalb von 6s).' : 'Seite nicht erreichbar.';
    return res.status(200).json({
      domain: targetUrl.toString(),
      status: 'error',
      message: `${reason} Keine Aussage möglich.`,
    });
  }
  clearTimeout(timeoutId);

  const headers = Object.fromEntries(response.headers.entries());
  const poweredBy = headers['x-powered-by'] || '';
  const server = headers['server'] || '';
  const setCookie = headers['set-cookie'] || '';
  const hasPhpSessionCookie = /PHPSESSID/i.test(setCookie);
  const looksLikePhp = /php/i.test(poweredBy) || hasPhpSessionCookie;

  const base = {
    domain: targetUrl.toString(),
    httpStatus: response.status,
    checkedHeaders: {
      server: server || null,
      poweredBy: poweredBy || null,
      phpSessionCookieFound: hasPhpSessionCookie,
    },
  };

  if (!looksLikePhp) {
    return res.status(200).json({
      ...base,
      status: 'not_detected',
      message:
        'Keine PHP-Signatur in den Response-Headern gefunden (kein "X-Powered-By: PHP", kein PHPSESSID-Cookie). ' +
        'Vermutlich nicht von PHP2Shell betroffen. Hinweis: Viele Hoster blenden diese Header bewusst aus - eine ' +
        '100%-sichere Aussage ist ohne Server-Zugriff nicht möglich.',
    });
  }

  const versionMatch = poweredBy.match(/PHP\/(\d+)\.(\d+)\.(\d+)/i);

  if (!versionMatch) {
    return res.status(200).json({
      ...base,
      status: 'php_version_unknown',
      message:
        'PHP-Nutzung erkannt, aber die genaue Version ist aus den Headern nicht ablesbar (oft bewusst versteckt). ' +
        'Bitte direkt beim Hosting-Provider bzw. Entwickler-Team nach dem aktuellen PHP-Versionsstand fragen ' +
        '(gepatcht sind: 8.5.12, 8.4.27, 8.3.36, 8.2.35).',
    });
  }

  const major = Number(versionMatch[1]);
  const minor = Number(versionMatch[2]);
  const patch = Number(versionMatch[3]);
  const phpVersion = `${major}.${minor}.${patch}`;
  const verdict = evaluateVersion(major, minor, patch);

  const messages = {
    patched: `PHP ${phpVersion} erkannt – das ist eine gepatchte Version. Nicht von PHP2Shell (CVE-2026-109618 / CVE-2026-109619) betroffen, sofern der Server nach dem Update neu gestartet wurde.`,
    vulnerable: `PHP ${phpVersion} erkannt – diese Version ist NICHT gepatcht und von PHP2Shell betroffen. Dringend auf 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 aktualisieren.`,
    unknown_branch: `PHP ${phpVersion} erkannt, aber für diesen Versions-Branch liegt kein bekannter Patch-Stand vor. Bitte manuell beim Hosting-Provider nachfragen.`,
  };

  return res.status(200).json({
    ...base,
    status: verdict,
    phpVersion,
    message: messages[verdict],
  });
}
