/** Key/value project metadata: project info, scope, engine config. */

import type { ScopeConfig } from '../../shared/scope.js';
import { emptyScope } from '../../shared/scope.js';
import type { EngineConfig } from '../../shared/config.js';
import type { ProjectInfo } from '../../shared/project.js';
import type { Database } from './database.js';

const KEY_INFO = 'project.info';
const KEY_SCOPE = 'project.scope';
const KEY_CONFIG = 'project.config';

/**
 * Freeze a scope config through to the individual rules.
 *
 * `getScope()` now hands every caller the SAME object — the proxy, the repeater,
 * the variation engine, the mesh and the AI tools all read it concurrently. An
 * in-place edit by any one of them (`rule.enabled = true`) would silently
 * rewrite the safety gate for all the others, without touching the database and
 * without surviving a reopen, which is the worst shape a scope bug can take.
 * Freezing makes that throw in strict mode instead.
 */
function freezeScope(scope: ScopeConfig): ScopeConfig {
  for (const list of [scope.include, scope.exclude]) {
    for (const rule of list) {
      Object.freeze(rule.schemes);
      Object.freeze(rule.ports);
      if (rule.path) Object.freeze(rule.path);
      Object.freeze(rule);
    }
    Object.freeze(list);
  }
  return Object.freeze(scope);
}

export class MetaRepo {
  constructor(private readonly db: Database) {}

  /**
   * Parsed scope, held so the gate does not re-read and re-parse it per request.
   *
   * `ProjectStore.scope` is a getter over this, and it is wired as
   * `getScope: () => project.scope` into the proxy — so before this cache, every
   * single proxied request did a SQLite SELECT plus a `JSON.parse` of the entire
   * scope blob. Measured against the real database: 7.4ms at 10,000 rules and
   * 45.5ms at 50,000, on the main process's event loop, which is what made the
   * window stop responding while traffic flowed.
   */
  private scopeCache?: ScopeConfig;

  getRaw(key: string): string | undefined {
    return this.db.get<{ value: string }>('SELECT value FROM project_meta WHERE key = ?', key)
      ?.value;
  }

  setRaw(key: string, value: string): void {
    this.db.run(
      `INSERT INTO project_meta (key, value) VALUES (?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
      key,
      value,
    );
    // Every scope write funnels through here (setScope -> setJson -> setRaw),
    // including any generic setRaw/setJson caller. Invalidating at this one
    // point is what makes it impossible to leave the gate enforcing a stale
    // scope — in particular a stale WIDER scope after the operator narrows it.
    if (key === KEY_SCOPE) delete this.scopeCache;
  }

  getJson<T>(key: string): T | undefined {
    const raw = this.getRaw(key);
    return raw === undefined ? undefined : (JSON.parse(raw) as T);
  }

  setJson(key: string, value: unknown): void {
    this.setRaw(key, JSON.stringify(value));
  }

  getInfo(): ProjectInfo | undefined {
    return this.getJson<ProjectInfo>(KEY_INFO);
  }
  setInfo(info: ProjectInfo): void {
    this.setJson(KEY_INFO, info);
  }

  getScope(): ScopeConfig {
    // Parse once per write, not once per read. See `scopeCache` above.
    return (this.scopeCache ??= freezeScope(this.getJson<ScopeConfig>(KEY_SCOPE) ?? emptyScope()));
  }
  setScope(scope: ScopeConfig): void {
    this.setJson(KEY_SCOPE, scope); // setRaw drops the cache
  }

  getConfig(): EngineConfig | undefined {
    return this.getJson<EngineConfig>(KEY_CONFIG);
  }
  setConfig(config: EngineConfig): void {
    this.setJson(KEY_CONFIG, config);
  }
}
