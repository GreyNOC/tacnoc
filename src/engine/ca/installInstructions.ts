/**
 * Per-platform guidance for trusting the project CA.
 *
 * Installing a CA is the one step this app deliberately refuses to automate:
 * adding a root of trust to a machine is the operator's decision, taken
 * knowingly, and reversed when the engagement ends. The wording pushes toward
 * the narrowest trust that works — a single browser profile over the system
 * store, current user over machine-wide — and always names the removal step.
 *
 * That principle is why this module hands back a COMMAND STRING rather than
 * running one. The operator pastes it into their own shell, sees exactly what it
 * will do, and owns the result. "TACNOC never modifies your OS trust store" stays
 * literally true, and the step stops being a paragraph of prose the operator has
 * to translate into clicks — which is what made it the step people got wrong.
 *
 * Every guide names its removal command next to its install command, because an
 * interception CA left trusted after an engagement is a standing risk and the
 * moment to learn how to remove it is before you install it.
 */

/** A single step in the guided setup. `command` is run by the OPERATOR, never by us. */
export interface CaInstallStep {
  title: string;
  detail: string;
  /** Copy-paste-able command. Absent for steps that are pure UI navigation. */
  command?: string;
  /** What to expect when the command runs (a prompt, a success line). */
  commandNote?: string;
}

export interface CaInstallGuide {
  platform: 'windows' | 'macos' | 'linux';
  platformLabel: string;
  /** The shell the commands are written for, named so nobody pastes into the wrong one. */
  shell: string;
  steps: CaInstallStep[];
  /** Removal — shown alongside install, never as a footnote. */
  removal: CaInstallStep;
  /**
   * Browsers that keep their own trust store and will NOT see an OS-level
   * install. Firefox is the usual surprise: the CA installs cleanly, the OS
   * agrees, and Firefox still refuses every intercepted connection.
   */
  separateTrustStoreNote: string;
}

/**
 * Placeholder substituted with the path the operator saved the certificate to.
 * Kept as a literal token so the guide can be built (and tested) before a file
 * exists, then rendered with the real path once one does.
 */
export const CERT_PATH_TOKEN = '<certificate-path>';

/** Quote a path for the target shell so a space in it cannot split the argument. */
function quotePath(path: string, platform: NodeJS.Platform): string {
  if (platform === 'win32') return `"${path}"`;
  // POSIX single quotes: literal everything except a single quote itself.
  return `'${path.replace(/'/g, `'\\''`)}'`;
}

/**
 * The structured, step-by-step guide for trusting the CA on this platform.
 *
 * @param certPath path the operator saved the certificate to. Omit to render the
 *   placeholder token, so the guide can be shown before anything is saved.
 */
export function caInstallGuide(
  certPath?: string,
  platform: NodeJS.Platform = process.platform,
): CaInstallGuide {
  const raw = certPath?.trim();
  const path = raw ? quotePath(raw, platform) : CERT_PATH_TOKEN;

  if (platform === 'win32') {
    return {
      platform: 'windows',
      platformLabel: 'Windows',
      shell: 'PowerShell or Command Prompt (no administrator rights needed)',
      steps: [
        {
          title: 'Trust it for your user account only',
          detail:
            'Adds the certificate to the CURRENT USER’s "Trusted Root Certification Authorities" store. It does not touch the machine-wide store and does not need elevation, so only your account trusts it.',
          command: `certutil -addstore -user Root ${path}`,
          commandNote:
            'Expect "Certificate added to store." A Windows security prompt asking you to confirm the root certificate is normal — it is asking whether you really mean to trust it.',
        },
        {
          title: 'Or do it by hand, if you prefer to see each step',
          detail:
            'Run certmgr.msc, open Trusted Root Certification Authorities → Certificates, then All Tasks → Import and choose the saved file. Same result as the command above.',
        },
      ],
      removal: {
        title: 'Remove it when the engagement ends',
        detail:
          'Deletes the CA from your user trust store. Run this the moment you are finished — a trusted interception CA is a standing risk for as long as it is installed.',
        command: 'certutil -delstore -user Root "TACNOC Project CA"',
      },
      separateTrustStoreNote:
        'Firefox and Tor Browser keep their own certificate stores and ignore the Windows one. For those, import the file at Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import, and tick "Trust this CA to identify websites".',
    };
  }

  if (platform === 'darwin') {
    return {
      platform: 'macos',
      platformLabel: 'macOS',
      shell: 'Terminal (no sudo needed)',
      steps: [
        {
          title: 'Trust it in your login keychain only',
          detail:
            'Adds the certificate to your own login keychain and marks it trusted for SSL. Deliberately not the System keychain: this way the trust belongs to your user account and disappears with it.',
          command: `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db ${path}`,
          commandNote:
            'macOS will prompt for your login password to modify the keychain. That prompt is the point — it is the moment you are agreeing to trust this CA.',
        },
        {
          title: 'Or do it by hand, if you prefer to see each step',
          detail:
            'Double-click the saved file to open it in Keychain Access (login keychain), open the certificate, expand Trust, and set "When using this certificate" to "Always Trust".',
        },
      ],
      removal: {
        title: 'Remove it when the engagement ends',
        detail:
          'Deletes the CA from your login keychain. Run this the moment you are finished — a trusted interception CA is a standing risk for as long as it is installed.',
        command: 'security delete-certificate -c "TACNOC Project CA"',
      },
      separateTrustStoreNote:
        'Firefox keeps its own certificate store and ignores the macOS keychain. For it, import the file at Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import, and tick "Trust this CA to identify websites".',
    };
  }

  return {
    platform: 'linux',
    platformLabel: 'Linux',
    shell: 'a terminal (no sudo needed — this is your browser’s own store)',
    steps: [
      {
        title: 'Trust it in your browser’s store, not system-wide',
        detail:
          'Chrome, Chromium, and Edge on Linux read the per-user NSS database. Installing here keeps the trust to your browser profile instead of every process on the machine. Install libnss3-tools first if certutil is missing.',
        command: `certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "TACNOC Project CA" -i ${path}`,
        commandNote:
          'No output means it worked. Restart the browser afterwards so it re-reads the store.',
      },
      {
        title: 'Firefox keeps a separate store again',
        detail:
          'Import the saved file at Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import, and tick "Trust this CA to identify websites".',
      },
    ],
    removal: {
      title: 'Remove it when the engagement ends',
      detail:
        'Deletes the CA from your browser’s NSS store. Run this the moment you are finished — a trusted interception CA is a standing risk for as long as it is installed.',
      command: 'certutil -d sql:$HOME/.pki/nssdb -D -n "TACNOC Project CA"',
    },
    separateTrustStoreNote:
      'Avoid installing this system-wide (/usr/local/share/ca-certificates). That would make every process on the machine trust the interception CA, which is far wider than an engagement needs.',
  };
}

/**
 * One-line summary of the same guidance.
 *
 * Kept because the certificate status carried to the AI mesh and the preflight
 * report wants a sentence, not a wizard.
 */
export function caInstallInstructions(platform: NodeJS.Platform = process.platform): string {
  switch (platform) {
    case 'win32':
      return 'Windows: import the saved .crt into "Trusted Root Certification Authorities" for the CURRENT USER (certmgr.msc → Trusted Root → All Tasks → Import, or `certutil -addstore -user Root <file>`). Only trust it while testing; remove it when finished.';
    case 'darwin':
      return 'macOS: open the saved .pem in Keychain Access (login keychain), then set it to "Always Trust" (or `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db <file>`). Remove trust when finished.';
    default:
      return 'Linux: install the saved .pem into your browser\'s certificate store (browsers usually manage their own trust; Chrome uses `certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "TACNOC Project CA" -i <file>`). Avoid adding it system-wide. Remove it when finished.';
  }
}
