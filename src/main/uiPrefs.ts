/**
 * UI preferences — per-install, not per-project.
 *
 * The walkthrough is the operator's, not the engagement's: having skipped it
 * once, they should not meet it again on the next project. That puts this
 * outside the project database, in `userData`, which is also why it must not be
 * able to fail loudly — nothing here is worth failing a launch over. Reads fall
 * back to defaults; writes report failure to the caller without throwing.
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
  } catch {
    try {
      if (existsSync(tmp)) unlinkSync(tmp);
    } catch {
      /* the temp file is not worth a second failure */
    }
  }
}
