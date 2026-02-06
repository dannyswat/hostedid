/**
 * Device fingerprinting service
 * Collects browser and device characteristics to create a stable fingerprint
 * that helps recognize returning devices.
 */

export interface FingerprintComponents {
  userAgent: string;
  screenResolution: string;
  timezone: string;
  language: string;
  platform: string;
  webglRenderer: string;
  canvasHash: string;
  colorDepth: number;
  hardwareConcurrency: number;
  touchSupport: boolean;
}

/**
 * Collect device fingerprint components from the browser
 */
export async function collectFingerprint(): Promise<FingerprintComponents> {
  const components: FingerprintComponents = {
    userAgent: navigator.userAgent,
    screenResolution: `${screen.width}x${screen.height}`,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    language: navigator.language,
    platform: navigator.platform || 'unknown',
    webglRenderer: getWebGLRenderer(),
    canvasHash: await getCanvasHash(),
    colorDepth: screen.colorDepth,
    hardwareConcurrency: navigator.hardwareConcurrency || 0,
    touchSupport: 'ontouchstart' in window || navigator.maxTouchPoints > 0,
  };

  return components;
}

/**
 * Generate a fingerprint hash string from collected components
 * Uses the SubtleCrypto API for SHA-256 hashing
 */
export async function generateFingerprintHash(): Promise<string> {
  const components = await collectFingerprint();

  const input = [
    components.userAgent,
    components.screenResolution,
    components.timezone,
    components.language,
    components.platform,
    components.webglRenderer,
    components.canvasHash,
    String(components.colorDepth),
    String(components.hardwareConcurrency),
    String(components.touchSupport),
  ].join('|');

  // Use SubtleCrypto for hashing (available in all modern browsers)
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Get the WebGL renderer string, which is often unique to GPU/driver combinations
 */
function getWebGLRenderer(): string {
  try {
    const canvas = document.createElement('canvas');
    const gl =
      canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return 'none';

    const glContext = gl as WebGLRenderingContext;
    const debugInfo = glContext.getExtension('WEBGL_debug_renderer_info');
    if (!debugInfo) return 'unknown';

    return glContext.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || 'unknown';
  } catch {
    return 'error';
  }
}

/**
 * Generate a hash of a canvas rendering, which varies based on GPU, drivers, and fonts
 */
async function getCanvasHash(): Promise<string> {
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 200;
    canvas.height = 50;
    const ctx = canvas.getContext('2d');
    if (!ctx) return 'none';

    // Draw text with specific styling that produces different results across devices
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('HostedID fp', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('HostedID fp', 4, 17);

    // Convert to data URL and hash it
    const dataUrl = canvas.toDataURL();
    const encoder = new TextEncoder();
    const data = encoder.encode(dataUrl);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return 'error';
  }
}

// Local storage key for caching the fingerprint
const FINGERPRINT_CACHE_KEY = 'hostedid_device_fingerprint';

/**
 * Get or generate a device fingerprint hash.
 * Caches the result in localStorage for consistency across page loads.
 */
export async function getDeviceFingerprint(): Promise<string> {
  // Check cache first
  const cached = localStorage.getItem(FINGERPRINT_CACHE_KEY);
  if (cached) {
    return cached;
  }

  // Generate new fingerprint
  const fingerprint = await generateFingerprintHash();

  // Cache it
  localStorage.setItem(FINGERPRINT_CACHE_KEY, fingerprint);

  return fingerprint;
}

/**
 * Clear the cached fingerprint (useful when testing or resetting)
 */
export function clearFingerprintCache(): void {
  localStorage.removeItem(FINGERPRINT_CACHE_KEY);
}
