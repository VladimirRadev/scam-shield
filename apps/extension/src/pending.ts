/** Text handed from the background (context menu, page scan) to the side panel. */
export interface PendingText {
  text: string;
  source: string;
  tabId?: number;
  error?: string;
  nonce: number;
}

export const PENDING_KEY = 'scamShieldPending';
