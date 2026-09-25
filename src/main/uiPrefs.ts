/**
 * UI preferences — per-install, not per-project.
 *
 * The walkthrough is the operator's, not the engagement's: having skipped it
 * once, they should not meet it again on the next project. That puts this
 * outside the project database, in `userData`. Reads must not be able to fail a
 * launch, so they fall back to defaults. Writes are the opposite: a write that
 * fails silently tells the operator their skip was saved when it was not, and
 * the walkthrough comes back on the next launch having promised it would not.
 * `writeUiPreferences` throws, and the IPC handler lets it through.
 *
 * All parsing and repair lives in `@shared/guide.js`, where it is pure and
 * covered by tests; this file is only the file IO.
 */

import { app } from 'electron';
import {
  readFileSync,
  writeFileSync,
  renameSync,
  mkdirSync,
  existsSync,
  unlinkSync,
} from 'node:fs';
import * as path from 'node:path';
import { defaultUiPreferences, parseUiPreferences, type UiPreferences } from '../shared/guide.js';

function prefsPath(): string {
  return path.join(app.getPath('userData'), 'ui-prefs.json');
}

export function readUiPreferences(): UiPreferences {
  try {
    const file = prefsPath();
    if (!existsSync(file)) return defaultUiPreferences();
    return parseUiPreferences(JSON.parse(readFileSync(file, 'utf8')));
  } catch {
    // A truncated or hand-mangled file is not a reason to refuse to start.
    return defaultUiPreferences();
  }
}

export function writeUiPreferences(prefs: UiPreferences): void {
  const file = prefsPath();
  // Write-then-rename: a preferences file half-written by a crash or a pulled
  // plug would otherwise come back as unparseable and silently reset the
  // operator's choices.
  const tmp = `${file}.${process.pid}.tmp`;
  try {
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(tmp, JSON.stringify(parseUiPreferences(prefs), null, 2), 'utf8');
    renameSync(tmp, file);
  } catch (err) {
    try {
      if (existsSync(tmp)) unlinkSync(tmp);
    } catch {
      /* the temp file is not worth a second failure */
    }
    // A read-only userData (roaming profile, AV lock, `attrib +R`) is the case
    // that matters: everything else keeps working, so nothing else would tell
    // the operator their preference never reached disk.
    throw new Error(
      `Could not save UI preferences to ${file}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}
