/**
 * Deterministic scam indicators. Each sign has an id, a weight (points added to the
 * heuristic score), a severity and a one-line explanation. Runs locally on the raw text.
 */
import { ABUSED_TLDS, findHosts, lookalikeOf, SHORTENERS, topLevelDomain } from './domains';
import { findSeedPhrases } from './redact';
import type { Category, Severity, Signal, Span } from './types';

export interface SignalDefinition {
  id: string;
  label: string;
  weight: number;
  severity: Severity;
  category: Category;
  explanation: string;
  patterns?: RegExp[];
  /** Skip a match when "never / don't / not" appears just before it in the same sentence. */
  negatable?: boolean;
  /** Custom detector for signs that are not a plain regular expression. */
  detect?: (text: string) => { spans: Span[]; explanation?: string } | null;
  /** Combination sign: fires only when all listed ids fired and `context` matches. */
  requires?: string[];
  context?: RegExp;
}

const NEGATION_BEFORE = /\b(?:never|not|don'?t|do not|won'?t|will not|no one|nobody|cannot|can'?t|nor)\b[^.!?\n]*$/i;

const JOB_CONTEXT =
  /\b(?:recruit\w*|hiring|hire|role|position|job|vacanc\w*|interview\w*|candidate|applicant|test task|take[- ]home|assignment|technical (?:test|task|assessment)|coding (?:test|task|challenge|assessment)|offer|salary|compensation|onboarding|talent)\b/i;

export const SIGNAL_DEFINITIONS: SignalDefinition[] = [
  {
    id: 'seed-phrase-request',
    label: 'Asks for your recovery phrase',
    weight: 50,
    severity: 'high',
    category: 'wallet-drainer',
    explanation: 'No real wallet, exchange or support team ever needs your recovery phrase or private key.',
    negatable: true,
    patterns: [
      /\b(?:enter|share|provide|send|type|submit|confirm|verify|import|input|validate|sync(?:hroni[sz]e)?|give|paste|upload|tell)\b[^.!?\n]{0,40}?\b(?:(?:12|twelve|24|twenty[- ]four)[- ]word|seed|recovery|secret|mnemonic|backup|wallet)\s*(?:phrase|words?|key)s?\b/gi,
      /\b(?:private key|seed phrase|recovery phrase|secret phrase|mnemonic(?: phrase)?)\b[^.!?\n]{0,30}?\b(?:to (?:verify|validate|restore|unlock|sync|claim|activate|recover)|is required|is needed)\b/gi,
      /\bwallet (?:validation|verification|synchroni[sz]ation|rectification|restoration|reactivation)\b/gi,
    ],
  },
  {
    id: 'seed-phrase-present',
    label: 'Contains a recovery phrase',
    weight: 35,
    severity: 'high',
    category: 'wallet-drainer',
    explanation: 'This looks like a wallet recovery phrase: anyone who sees it can empty the wallet.',
    detect: (text) => {
      const spans = findSeedPhrases(text);
      return spans.length ? { spans } : null;
    },
  },
  {
    id: 'wallet-connect',
    label: 'Asks you to connect or approve a wallet',
    weight: 20,
    severity: 'medium',
    category: 'wallet-drainer',
    explanation: 'Drainer sites ask you to connect a wallet or sign a request that hands over your tokens.',
    patterns: [
      /\b(?:connect|link|sync)\s+(?:your\s+)?(?:crypto\s+)?wallet\b/gi,
      /\bclaim\s+(?:your\s+)?(?:free\s+)?(?:airdrop|tokens?|nfts?|rewards?|allocation)\b/gi,
      /\b(?:approve|sign)\s+(?:the\s+|this\s+)?(?:transaction|message|permit|request)\s+(?:to|in your wallet)\b/gi,
      /\b(?:metamask|trust wallet|phantom|ledger|trezor)\b[^.!?\n]{0,40}\b(?:suspend|lock|disabl|expir|verif|validat|compromis)\w*/gi,
    ],
  },
  {
    id: 'run-code-request',
    label: 'Asks you to download and run code',
    weight: 15,
    severity: 'medium',
    category: 'malware-task',
    explanation: 'Running a stranger\'s project (npm install, start scripts) executes their code on your computer.',
    patterns: [
      /\b(?:git\s+clone|clone\s+(?:the|our|this|my)\s+(?:\w+\s+)?(?:repo(?:sitory)?|project|code(?:base)?))\b/gi,
      /\b(?:npm|yarn|pnpm)\s+(?:i|install|start|run\s+[\w:-]+)\b/gi,
      /\b(?:run|execute|launch|start)\s+(?:the|our|this)\s+(?:project|app|application|code|script|repo|program)\b/gi,
      /\b(?:download|open|extract|unzip)\s+(?:the|our|this)\s+(?:attached\s+)?(?:project|zip|archive|assignment|test task)\b/gi,
    ],
  },
  {
    id: 'recruiter-code-task',
    label: 'Job "test task" that runs code',
    weight: 35,
    severity: 'high',
    category: 'malware-task',
    explanation: 'Fake recruiters send "take-home tasks" whose install scripts steal wallets, passwords and SSH keys.',
    requires: ['run-code-request'],
    context: JOB_CONTEXT,
  },
  {
    id: 'paste-command',
    label: 'Asks you to paste a command',
    weight: 45,
    severity: 'high',
    category: 'malware-task',
    explanation: 'Pasting a command into Win+R, a terminal or PowerShell lets the sender run anything on your PC.',
    patterns: [
      /\b(?:win(?:dows)?(?:\s*key)?\s*\+\s*r)\b/gi,
      /\b(?:curl|wget)\s+[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/gi,
      /\b(?:powershell|pwsh)(?:\.exe)?\s+[^\n]{0,40}?(?:-e(?:nc(?:odedcommand)?)?\s|-w(?:indowstyle)?\s+hidden|\biex\b|invoke-expression|downloadstring|\biwr\b)/gi,
      /\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]{0,200}\|\s*iex\b/gi,
      /\bmshta(?:\.exe)?\s+https?:/gi,
      /\b(?:paste|copy)\b[^.!?\n]{0,60}\b(?:terminal|command prompt|powershell|console|cmd|run (?:box|dialog|window))\b/gi,
    ],
  },
  {
    id: 'executable-attachment',
    label: 'Executable file or macro',
    weight: 30,
    severity: 'high',
    category: 'malware-task',
    explanation: 'Program files, disk images and macros in a message are a classic way to install malware.',
    patterns: [
      /\b[\w-]+\.(?:exe|scr|bat|cmd|pif|vbs|vbe|jse|wsf|hta|msi|lnk|iso|img|apk|jar|ps1|dmg|pkg)\b/gi,
      /\b(?:enable (?:macros|content|editing)|password[- ]protected (?:zip|archive|file|rar|7z))\b/gi,
    ],
  },
  {
    id: 'off-platform',
    label: 'Moves you to Telegram / WhatsApp',
    weight: 20,
    severity: 'medium',
    category: 'off-platform-lure',
    explanation: 'Scammers move the chat to Telegram or WhatsApp, away from the platform\'s scam filters.',
    negatable: true,
    patterns: [
      /\b(?:contact|message|text|reach|add|chat with|talk to|write to|dm|ping|find|join)\s+(?:me|us|him|her|our\s+\w+(?:\s+\w+)?|the\s+\w+(?:\s+\w+)?)?\s*(?:on|via|at|through|in|over)\s+(?:telegram|whatsapp|signal|wechat|viber|line app|kik)\b/gi,
      /\b(?:move|continue|switch|take)\s+(?:this|our|the)\s+(?:conversation|chat|discussion|interview)\s+(?:to|on|over to)\s+(?:telegram|whatsapp|signal|wechat|viber)\b/gi,
      /\b(?:t\.me|wa\.me|telegram\.me|chat\.whatsapp\.com)\/[\w+/-]+/gi,
      /\b(?:telegram|whatsapp|signal)\s*(?:id|handle|username|number)?\s*[:：]?\s*(?:@\w{3,}|\+\d[\d\s-]{6,})/gi,
    ],
  },
  {
    id: 'credential-request',
    label: 'Asks for a password or code',
    weight: 30,
    severity: 'high',
    category: 'phishing',
    explanation: 'Banks and services never ask for your password, PIN or one-time code in a message.',
    negatable: true,
    patterns: [
      /\b(?:verify|confirm|update|validate|re-?enter|provide|enter|submit|share|send|reset|tell)\s+(?:us\s+|me\s+)?(?:your\s+)?(?:account\s+|login\s+|card\s+|bank(?:ing)?\s+)?(?:password|passcode|pin|otp|one[- ]time (?:code|password)|2fa code|verification code|security code|sms code|login details|credentials|cvv|cvc|card details|online banking details|sign-in details)\b/gi,
      /\b(?:read|give|send|forward|share|tell)\s+(?:me|us)\s+(?:the\s+)?(?:\d-digit\s+)?(?:code|otp|pin)\b/gi,
    ],
  },
  {
    id: 'account-threat',
    label: 'Threatens to lock your account',
    weight: 15,
    severity: 'medium',
    category: 'phishing',
    explanation: 'Threats of suspension or "unusual activity" are used to rush you into clicking.',
    negatable: true,
    patterns: [
      /\b(?:account|card|access|profile|service|mailbox|subscription|wallet|number)\s+(?:has been|have been|was|is|will be|may be|could be)\s+(?:temporarily\s+|permanently\s+)?(?:suspended|locked|limited|restricted|blocked|disabled|deactivated|closed|terminated|frozen|compromised|deleted|on hold)\b/gi,
      /\b(?:unusual|suspicious|unauthori[sz]ed)\s+(?:activity|sign[- ]?in|login|log-in|transaction|access|attempt)s?\b/gi,
      /\b(?:avoid|prevent)\s+(?:the\s+|permanent\s+)?(?:suspension|closure|deactivation|termination|losing access)\b/gi,
      /\b(?:verify|confirm|validate|update)\s+(?:your\s+)?(?:account|identity|information|details|billing)\b/gi,
    ],
  },
  {
    id: 'click-to-fix',
    label: 'Link to "verify" or "unlock"',
    weight: 15,
    severity: 'medium',
    category: 'phishing',
    explanation: 'A link that promises to unlock, verify or release something is the usual phishing hook.',
    patterns: [
      /\b(?:click|tap|follow|open|visit|use)\s+(?:on\s+)?(?:the\s+|this\s+)?(?:link|button|url|here)\b[^.!?\n]{0,40}?\b(?:to|and)\s+(?:verify|confirm|unlock|restore|update|reactivate|validate|secure|claim|avoid|keep|prevent|release|reschedule|pay|receive)\b/gi,
    ],
  },
  {
    id: 'urgency',
    label: 'Pressure to act now',
    weight: 10,
    severity: 'low',
    category: 'phishing',
    explanation: 'Artificial deadlines stop you from checking with someone you trust.',
    patterns: [
      /\b(?:urgent(?:ly)?|immediately|right away|asap|act now|final (?:notice|warning|reminder)|last (?:chance|warning|notice)|expires? (?:today|tonight|soon)|today only|time[- ]sensitive)\b/gi,
      /\b(?:within|in the next)\s+\d+\s*(?:hours?|hrs?|h|minutes?|mins?)\b/gi,
      /\bbefore it'?s too late\b/gi,
    ],
  },
  {
    id: 'payment-upfront',
    label: 'Fee to unlock money or a parcel',
    weight: 25,
    severity: 'medium',
    category: 'advance-fee',
    explanation: 'Paying a small "release", "customs" or "processing" fee first is the core of advance-fee fraud.',
    patterns: [
      /\b(?:pay|send|transfer|cover)\s+(?:a\s+|the\s+|an\s+)?(?:(?:small|one[- ]time|refundable|processing|release|clearance|customs|redelivery|registration|activation|verification|training|onboarding|insurance|unlock(?:ing)?|withdrawal|admin(?:istrative)?|handling|shipping|delivery|tax)\s+)+(?:fee|charge|deposit|payment|cost)s?\b/gi,
      /\b(?:processing|release|clearance|customs|redelivery|registration|activation|unlock|withdrawal|handling|administrative|delivery|shipping)\s+(?:fee|charge|duty)\s+(?:of\s+)?(?:[$€£]|usd|eur|gbp)?\s?\d/gi,
      /\b(?:purchase|buy)\s+(?:the\s+|your\s+)?(?:own\s+)?(?:equipment|laptop|software|starter kit|training materials?)\b[^.!?\n]{0,60}\b(?:reimburs\w*|refund\w*|we will (?:send|pay))/gi,
      /\bunpaid\s+(?:toll|fee|duty|customs|postage|shipping)\b/gi,
    ],
  },
  {
    id: 'gift-cards',
    label: 'Wants payment in gift cards',
    weight: 40,
    severity: 'high',
    category: 'other',
    explanation: 'No company, boss or government agency takes payment in gift-card codes.',
    patterns: [
      /\b(?:buy|purchase|get|send|pick up|scratch)\b[^.!?\n]{0,40}\bgift\s*cards?\b/gi,
      /\bgift\s*cards?\b[^.!?\n]{0,60}\b(?:codes?|pins?|numbers on the back|scratch)\b/gi,
      /\b(?:pay|payment)\b[^.!?\n]{0,30}\b(?:gift\s*cards?|itunes cards?|google play cards?|steam cards?)\b/gi,
    ],
  },
  {
    id: 'crypto-payment',
    label: 'Wants payment in crypto',
    weight: 15,
    severity: 'medium',
    category: 'other',
    explanation: 'Crypto payments cannot be reversed, which is why scammers ask for them.',
    patterns: [
      /\b(?:pay|send|deposit|transfer)\b[^.!?\n]{0,30}\b(?:bitcoin|btc|usdt|tether|eth(?:ereum)?|crypto(?:currency)?|usdc|trc-?20|erc-?20)\b/gi,
      /\b(?:bitcoin|crypto)\s+(?:atm|kiosk)s?\b/gi,
    ],
  },
  {
    id: 'bank-details-changed',
    label: 'Says the bank details changed',
    weight: 40,
    severity: 'high',
    category: 'fake-invoice',
    explanation: '"Our bank details have changed" is how invoice fraud redirects real payments; confirm by phone.',
    patterns: [
      /\b(?:our|my|the|company'?s?)\s+(?:bank(?:ing)?|payment|account|remittance|wire)\s+(?:details|information|info|account|instructions)\s+(?:have|has)\s+(?:been\s+)?(?:changed|updated|moved)\b/gi,
      /\b(?:pay|send|remit|transfer|wire)\b[^.!?\n]{0,40}\bto\s+(?:the|our)\s+new\s+(?:bank\s+)?account\b/gi,
      /\b(?:do not|don'?t|stop)\s+(?:use|pay(?:ing)? (?:in)?to|send(?:ing)? to)\s+(?:the|our)\s+(?:old|previous|former|usual)\s+(?:bank\s+)?account\b/gi,
      /\bnew\s+(?:bank(?:ing)?|payment|remittance)\s+(?:details|account|information|instructions)\b/gi,
    ],
  },
  {
    id: 'overpayment',
    label: 'Overpayment / refund the difference',
    weight: 20,
    severity: 'medium',
    category: 'fake-invoice',
    explanation: 'A "you were overpaid, send back the difference" story ends with a bounced payment.',
    patterns: [
      /\b(?:overpaid|over-?payment|sent (?:you )?(?:too much|extra|more than)|refund the (?:difference|excess|balance)|return the (?:extra|excess|difference))\b/gi,
    ],
  },
  {
    id: 'guaranteed-returns',
    label: 'Promises guaranteed profit',
    weight: 35,
    severity: 'high',
    category: 'investment-romance',
    explanation: 'Real investments never guarantee returns; daily-profit promises are a hallmark of investment scams.',
    patterns: [
      /\bguarantee[ds]?\s+(?:\w+\s+){0,2}(?:returns?|profits?|income|gains?|earnings?|payouts?)\b/gi,
      /\b(?:risk[- ]free|no[- ]risk)\s+(?:\w+\s+){0,2}(?:investment|returns?|profits?|trading|income|opportunit(?:y|ies))\b/gi,
      /\b\d{1,3}(?:\.\d+)?\s?%\s+(?:daily|per day|a day|weekly|per week|a week|every day)\b/gi,
      /\b(?:double|triple|10x)\s+your\s+(?:money|investment|crypto|bitcoin|funds?)\b/gi,
    ],
  },
  {
    id: 'investment-pitch',
    label: 'Unsolicited investment tip',
    weight: 15,
    severity: 'medium',
    category: 'investment-romance',
    explanation: 'A stranger with a trading "mentor" or platform is how pig-butchering scams start.',
    patterns: [
      /\b(?:my|our)\s+(?:uncle|aunt|mentor|cousin|financial advisor|analyst|teacher)\b[^.!?\n]{0,60}\b(?:trad\w*|invest\w*|crypto|platform|signals?|stocks?|gold|forex)\b/gi,
      /\b(?:trading|investment|mining|liquidity|arbitrage)\s+(?:platform|app|pool|program|plan|group|signals?)\b/gi,
      /\b(?:passive income|financial freedom|quit your (?:job|9-5)|make money from home)\b/gi,
    ],
  },
  {
    id: 'crypto-recovery',
    label: 'Offers to recover lost money',
    weight: 30,
    severity: 'high',
    category: 'investment-romance',
    explanation: '"Fund recovery" services target scam victims a second time.',
    patterns: [
      /\b(?:recover|retrieve|get back|reclaim)\s+(?:your\s+)?(?:lost|stolen|scammed)\s+(?:crypto|bitcoin|funds|money|assets|coins)\b/gi,
      /\b(?:funds?|asset|crypto) recovery (?:service|agency|specialist|expert|team)\b/gi,
    ],
  },
  {
    id: 'romance-lure',
    label: 'Romance or "wrong number" opener',
    weight: 15,
    severity: 'medium',
    category: 'investment-romance',
    explanation: 'Friendly "wrong number" texts and fast affection are classic romance-scam openers.',
    patterns: [
      /\b(?:wrong number|sorry to bother you|we met (?:at|on)|do you remember me)\b/gi,
      /\b(?:my dear|sweetheart|my love|darling|soulmate)\b/gi,
      /\b(?:widow(?:er)?|deployed (?:overseas|in)|oil rig|offshore (?:engineer|platform)|un (?:doctor|peacekeeper)|military doctor)\b/gi,
      /\b(?:i feel (?:a|such a) (?:connection|bond)|god brought us|destiny brought)\b/gi,
    ],
  },
  {
    id: 'too-good-job',
    label: 'Easy money job offer',
    weight: 20,
    severity: 'medium',
    category: 'fake-recruiter',
    explanation: 'High pay for simple online tasks with no experience is how task and job scams hook people.',
    patterns: [
      /\b(?:earn|make)\s+(?:up to\s+)?[$€£]?\s?\d[\d,.]*\s*(?:usd|eur|gbp|usdt|dollars|euros)?\s*(?:per|a|each|\/)\s*day\b/gi,
      /\b(?:no|without)\s+(?:prior\s+)?experience\s+(?:is\s+)?(?:needed|required|necessary)\b/gi,
      /\b(?:like|rate|review|boost|optimi[sz]e)\s+(?:youtube\s+)?(?:videos|products|apps|hotels|songs|orders)\b[^.!?\n]{0,60}\b(?:earn|commission|paid|salary|income)\b/gi,
      /\b(?:part[- ]time|flexible|remote|work from home)\b[^.!?\n]{0,60}\b(?:daily pay|paid daily|daily salary|commission)\b/gi,
    ],
  },
  {
    id: 'unsolicited-offer',
    label: 'Unsolicited "you were selected"',
    weight: 10,
    severity: 'low',
    category: 'fake-recruiter',
    explanation: 'Being "selected" for something you never applied for is a common opener.',
    patterns: [
      /\b(?:you(?:'ve| have)? been|you are|you were)\s+(?:(?:randomly|specially|personally)\s+)?(?:selected|chosen|hired|pre-?approved)\b/gi,
      /\b(?:hiring immediately|immediate start|start (?:today|tomorrow)|no interview)\b/gi,
    ],
  },
  {
    id: 'money-mule',
    label: 'Asks you to move money for them',
    weight: 35,
    severity: 'high',
    category: 'fake-recruiter',
    explanation: 'Receiving and forwarding money or parcels for a "company" makes you a money mule.',
    patterns: [
      /\b(?:receive|accept|process)\s+(?:payments?|funds|transfers?|money)\s+(?:on (?:our|their|the company'?s) behalf|for (?:our|the) (?:company|clients?)|into your (?:own\s+|personal\s+)?(?:bank\s+)?account)\b/gi,
      /\b(?:keep|retain)\s+\d{1,2}\s?%\s+(?:as|for)\s+(?:your\s+)?(?:commission|fee|salary|payment)\b/gi,
      /\b(?:reship|re-ship|forward)\s+(?:the\s+)?(?:packages|parcels|items|goods)\b/gi,
    ],
  },
  {
    id: 'prize-lottery',
    label: 'Prize, lottery or inheritance',
    weight: 35,
    severity: 'high',
    category: 'advance-fee',
    explanation: 'Unexpected winnings or inheritances always end with a fee you must pay first.',
    patterns: [
      /\b(?:you(?:'ve| have)?|your (?:email|number|phone))\s+(?:has\s+|have\s+)?(?:just\s+)?(?:won|been (?:selected|chosen) (?:as|to receive))\b/gi,
      /\b(?:lottery|jackpot|sweepstakes?|lucky draw|winning notification|claim (?:your )?(?:prize|winnings))\b/gi,
      /\b(?:inheritance|next of kin|unclaimed (?:funds|inheritance|estate|assets)|compensation fund|diplomatic (?:bag|courier)|consignment box|atm card worth)\b/gi,
      /\b(?:sum|amount|fund)s?\s+of\s+(?:us\s?)?[$€£]?\s?\d[\d,.]*\s*(?:million|m)\b/gi,
    ],
  },
  {
    id: 'tech-support',
    label: 'Fake virus or support alert',
    weight: 35,
    severity: 'high',
    category: 'tech-support',
    explanation: 'Microsoft, Apple and banks do not phone you or show pop-ups about viruses with a number to call.',
    patterns: [
      /\b(?:your\s+)?(?:computer|pc|device|laptop|windows|mac|iphone|system)\s+(?:has been|is|was|may be)\s+(?:infected|hacked|compromised|locked|blocked|at risk)\b/gi,
      /\b(?:virus(?:es)?|malware|trojan|spyware)\s+(?:detected|found|alert)\b/gi,
      /\b(?:call|contact|dial)\s+(?:the\s+)?(?:microsoft|windows|apple|google|amazon|norton|mcafee|geek squad|paypal|technical|tech|billing|refund)\s*(?:support|help ?desk|team|department|technicians?|security|service)?\b[^.!?\n]{0,40}?(?:\+?\d[\d\s().-]{7,}|toll[- ]free|immediately|now)/gi,
      /\b(?:subscription|membership|order|renewal)\b[^\n]{0,100}?\b(?:renew\w*|charged|deducted|debited)\b[^\n]{0,120}?\b(?:call|contact|dial)\b[^\n]{0,40}?\+?\d[\d\s().-]{8,}/gi,
      /\b(?:refund department|refund team|overcharged you|refund the excess)\b/gi,
    ],
  },
  {
    id: 'remote-access',
    label: 'Wants remote access to your PC',
    weight: 35,
    severity: 'high',
    category: 'tech-support',
    explanation: 'Remote-access tools such as AnyDesk give the caller full control of your computer and bank sessions.',
    patterns: [
      /\b(?:install|download|open|run|launch|use|get)\b[^.!?\n]{0,40}\b(?:anydesk|teamviewer|ultraviewer|rustdesk|quick ?support|quick ?assist|supremo|ammyy|logmein|screenconnect|splashtop)\b/gi,
      /\b(?:anydesk|teamviewer|ultraviewer|rustdesk|quick ?assist)\b[^.!?\n]{0,40}\b(?:code|id|number|session|access)\b/gi,
      /\bgive\s+(?:us|me|our technician|the technician)\s+(?:remote\s+)?access\s+to\s+your\s+(?:computer|pc|screen|laptop|device)\b/gi,
    ],
  },
  {
    id: 'authority-threat',
    label: 'Police, tax or legal threat',
    weight: 25,
    severity: 'medium',
    category: 'other',
    explanation: 'Agencies do not threaten arrest by message or ask for immediate payment.',
    patterns: [
      /\b(?:arrest warrant|warrant (?:for|of) (?:your )?arrest|you will be arrested|legal action (?:will be|against you)|lawsuit (?:has been|will be) filed|court summons|criminal (?:charges|case) against you|deportation)\b/gi,
      /\b(?:irs|hmrc|fbi|interpol|customs (?:office|department)|tax (?:office|authority))\b[^.!?\n]{0,60}\b(?:pay|fine|penalty|warrant|arrest|outstanding)\b/gi,
    ],
  },
  {
    id: 'personal-data-request',
    label: 'Asks for ID documents or SSN',
    weight: 20,
    severity: 'medium',
    category: 'other',
    explanation: 'Copies of your ID, SSN or date of birth are enough to open accounts in your name.',
    negatable: true,
    patterns: [
      /\b(?:send|provide|share|upload|submit|forward|give)\b[^.!?\n]{0,40}\b(?:ssn|social security (?:number|card)|passport (?:copy|scan|photo|number|details)|(?:copy|scan|photo) of your (?:id|passport|driver'?s licen[cs]e|national id)|date of birth|mother'?s maiden name|selfie with (?:your )?id)\b/gi,
    ],
  },
  {
    id: 'secrecy',
    label: 'Asks you to keep it secret',
    weight: 15,
    severity: 'medium',
    category: 'other',
    explanation: 'Being told not to tell your bank, family or colleagues is a strong manipulation sign.',
    patterns: [
      /\b(?:keep (?:this|it) (?:confidential|secret|between us|private|to yourself)|do(?:n'?t| not) (?:tell|inform|discuss (?:this )?with|share this with) (?:anyone|anybody|your (?:bank|family|friends|colleagues|manager))|strictly confidential)\b/gi,
    ],
  },
  {
    id: 'generic-greeting',
    label: 'Generic greeting',
    weight: 8,
    severity: 'low',
    category: 'phishing',
    explanation: 'Mass scams say "Dear Customer" because they do not know your name.',
    patterns: [
      /\b(?:dear|hello|hi)\s+(?:valued\s+|esteemed\s+)?(?:customer|user|client|member|account holder|beneficiary|friend|sir\/madam|sir or madam|winner|card ?holder|subscriber)\b/gi,
      /\bhello dear\b/gi,
      /\bdear (?:sir|madam)\b/gi,
    ],
  },
  {
    id: 'delivery-problem',
    label: 'Parcel problem story',
    weight: 15,
    severity: 'medium',
    category: 'phishing',
    explanation: 'Fake delivery texts invent an address problem so you click and pay a small fee.',
    patterns: [
      /\b(?:incomplete|incorrect|invalid|missing|unconfirmed)\s+(?:shipping\s+|delivery\s+|house\s+)?(?:address|street number|house number|postcode|zip code)\b/gi,
      /\b(?:schedule|arrange|request|confirm)\s+(?:a\s+|your\s+)?(?:redelivery|re-delivery|new delivery)\b/gi,
      /\b(?:parcel|package|shipment)\s+(?:is\s+|has been\s+|was\s+)?(?:on hold|held|suspended|stopped|returned to sender)\b/gi,
    ],
  },
  {
    id: 'lookalike-domain',
    label: 'Look-alike web address',
    weight: 35,
    severity: 'high',
    category: 'lookalike-domain',
    explanation: 'The link imitates a well-known brand but points to a different owner.',
    detect: (text) => {
      const spans: Span[] = [];
      let explanation: string | undefined;
      for (const h of findHosts(text)) {
        const hit = lookalikeOf(h.host, h.rd);
        if (!hit) continue;
        spans.push(h.span);
        if (!explanation) {
          const real = hit.brand.official[0];
          explanation = `"${hit.rd}" ${hit.reason}${real ? ` (the real site is ${real})` : ''}.`;
        }
      }
      return spans.length ? { spans, explanation } : null;
    },
  },
  {
    id: 'raw-ip-link',
    label: 'Link to a bare IP address',
    weight: 30,
    severity: 'high',
    category: 'phishing',
    explanation: 'Real companies link to their domain name, not to a numeric IP address.',
    patterns: [/\bhttps?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/[^\s]*)?/gi],
  },
  {
    id: 'cheap-domain',
    label: 'Throw-away domain ending',
    weight: 10,
    severity: 'low',
    category: 'phishing',
    explanation: 'Endings such as .top, .xyz or .icu are cheap and heavily used for short-lived scam sites.',
    detect: (text) => {
      const spans = findHosts(text)
        .filter((h) => ABUSED_TLDS.has(topLevelDomain(h.rd)))
        .map((h) => h.span);
      return spans.length ? { spans } : null;
    },
  },
  {
    id: 'link-shortener',
    label: 'Shortened link hides the destination',
    weight: 10,
    severity: 'low',
    category: 'phishing',
    explanation: 'Short links hide where they really go.',
    detect: (text) => {
      const spans = findHosts(text)
        .filter((h) => SHORTENERS.has(h.rd) || SHORTENERS.has(h.host))
        .map((h) => h.span);
      return spans.length ? { spans } : null;
    },
  },
  {
    id: 'prompt-injection',
    label: 'Tries to instruct the AI checker',
    weight: 40,
    severity: 'high',
    category: 'other',
    explanation: 'The text contains instructions aimed at AI filters, which honest messages never do.',
    patterns: [
      /\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding|your)\s+(?:instructions?|rules|prompts?|guidelines|directions)\b/gi,
      /\b(?:classify|mark|label|rate|report|treat|consider)\s+(?:this|the)\s+(?:message|email|text|mail)\s+as\s+(?:safe|legitimate|legit|not (?:a )?scam|trusted|benign)\b/gi,
      /\b(?:system prompt|developer mode|jailbreak)\b/gi,
    ],
  },
];

const MAX_SPANS = 8;

function runPatterns(text: string, def: SignalDefinition): Span[] {
  const spans: Span[] = [];
  for (const re of def.patterns ?? []) {
    for (const m of text.matchAll(re)) {
      if (!m[0]) continue;
      const start = m.index;
      if (def.negatable && NEGATION_BEFORE.test(text.slice(Math.max(0, start - 40), start))) continue;
      spans.push({ start, end: start + m[0].length });
    }
  }
  return dedupeSpans(spans);
}

function dedupeSpans(spans: Span[]): Span[] {
  const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);
  const out: Span[] = [];
  for (const s of sorted) {
    const last = out[out.length - 1];
    if (last && s.start < last.end) {
      last.end = Math.max(last.end, s.end);
      continue;
    }
    out.push({ ...s });
  }
  return out.slice(0, MAX_SPANS);
}

function toSignal(def: SignalDefinition, spans: Span[], explanation?: string): Signal {
  return {
    id: def.id,
    label: def.label,
    weight: def.weight,
    severity: def.severity,
    category: def.category,
    explanation: explanation ?? def.explanation,
    spans,
  };
}

/** Find all scam indicators in a text. Spans refer to the given text. */
export function signals(text: string): Signal[] {
  if (!text.trim()) return [];
  const found = new Map<string, Signal>();
  for (const def of SIGNAL_DEFINITIONS) {
    if (def.requires) continue;
    if (def.detect) {
      const r = def.detect(text);
      if (r && r.spans.length) found.set(def.id, toSignal(def, dedupeSpans(r.spans), r.explanation));
      continue;
    }
    const spans = runPatterns(text, def);
    if (spans.length) found.set(def.id, toSignal(def, spans));
  }
  for (const def of SIGNAL_DEFINITIONS) {
    if (!def.requires) continue;
    const parts = def.requires.map((id) => found.get(id));
    if (parts.some((p) => !p)) continue;
    if (def.context && !def.context.test(text)) continue;
    found.set(def.id, toSignal(def, dedupeSpans(parts.flatMap((p) => p!.spans))));
  }
  return [...found.values()].sort((a, b) => b.weight - a.weight);
}

export interface HeuristicScore {
  /** Sum of all sign weights, capped at 100. */
  total: number;
  /** Sum of high-severity sign weights, capped at 100: a floor the model cannot talk down. */
  hard: number;
  /** Points per category, used to pick the most likely scam family. */
  byCategory: Partial<Record<Category, number>>;
}

export function heuristicScore(list: Signal[]): HeuristicScore {
  let total = 0;
  let hard = 0;
  const byCategory: Partial<Record<Category, number>> = {};
  for (const s of list) {
    total += s.weight;
    if (s.severity === 'high') hard += s.weight;
    byCategory[s.category] = (byCategory[s.category] ?? 0) + s.weight;
  }
  return { total: Math.min(100, total), hard: Math.min(100, hard), byCategory };
}

/** Category with the most points, or null when nothing was found. */
export function dominantCategory(score: HeuristicScore): Category | null {
  let best: Category | null = null;
  let bestPts = 0;
  for (const [cat, pts] of Object.entries(score.byCategory) as Array<[Category, number]>) {
    // A specific family beats the generic buckets on a tie.
    const bonus = cat === 'other' || cat === 'phishing' || cat === 'lookalike-domain' ? 0 : 0.5;
    if (pts + bonus > bestPts) {
      best = cat;
      bestPts = pts + bonus;
    }
  }
  return best;
}
