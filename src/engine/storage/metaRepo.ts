/** Key/value project metadata: project info, scope, engine config. */

import type { ScopeConfig } from '../../shared/scope.js';
import { emptyScope } from '../../shared/scope.js';
import type { EngineConfig } from '../../shared/config.js';
import type { ProjectInfo } from '../../shared/project.js';
import type { Database } from './database.js';

const KEY_INFO = 'project.info';
const KEY_SCOPE = 'project.scope';
const KEY_CONFIG = 'project.config';

export class MetaRepo {
  constructor(private readonly db: Database) {}

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
    return this.getJson<ScopeConfig>(KEY_SCOPE) ?? emptyScope();
  }
  setScope(scope: ScopeConfig): void {
    this.setJson(KEY_SCOPE, scope);
  }

  getConfig(): EngineConfig | undefined {
    return this.getJson<EngineConfig>(KEY_CONFIG);
  }
  setConfig(config: EngineConfig): void {
    this.setJson(KEY_CONFIG, config);
  }
}
