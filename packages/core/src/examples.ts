import data from './examples.json' with { type: 'json' };
import type { Category } from './types';

export type Channel = 'email' | 'sms' | 'chat' | 'linkedin' | 'web' | 'call-script';

/** A synthetic, labelled message used for the demo chips and the heuristic evaluation. */
export interface Example {
  id: string;
  label: 'scam' | 'legit';
  category: Category;
  channel: Channel;
  /** Short chip title. */
  title: string;
  text: string;
}

export const EXAMPLES: Example[] = data as Example[];
