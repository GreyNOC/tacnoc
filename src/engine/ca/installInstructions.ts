/**
 * Per-platform guidance for trusting the project CA.
 *
 * Installing a CA is the one step this app deliberately refuses to automate:
 * adding a root of trust to a machine is the operator's decision, taken
 * knowingly, and reversed when the engagement ends. The wording pushes toward
 * the narrowest trust that works — a single browser profile over the system
 * store, current user over machine-wide — and always names the removal step.
 */

export function caInstallInstructions(platform: NodeJS.Platform = process.platform): string {
  switch (platform) {
    case 'win32':
      return 'Windows: import the saved .crt into "Trusted Root Certification Authorities" for the CURRENT USER (certmgr.msc → Trusted Root → All Tasks → Import). Only trust it while testing; remove it when finished.';
    case 'darwin':
      return 'macOS: open the saved .pem in Keychain Access (login keychain), then set it to "Always Trust". Remove trust when finished.';
    default:
      return "Linux: install the saved .pem into your browser's certificate store (browsers usually manage their own trust). Avoid adding it system-wide. Remove it when finished.";
  }
}
