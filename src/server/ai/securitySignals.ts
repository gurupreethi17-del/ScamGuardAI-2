import { AnalysisType, RiskLevel, ThreatIndicator } from '../../types/index.ts';

export interface SecurityInput {
  type: AnalysisType;
  content: string;
  metadata?: {
    sender?: string;
    subject?: string;
    url?: string;
    qrDecodedText?: string;
    imageMimeType?: string;
    imageDataBase64?: string;
  };
}

type SignalCategory = 'url' | 'content' | 'impersonation' | 'credential';

interface SecuritySignal {
  id: string;
  category: SignalCategory;
  weight: number;
  name: string;
  description: string;
  quote?: string;
}

export interface DeterministicAnalysis {
  classification: 'SAFE' | 'SUSPICIOUS' | 'SCAM';
  riskScore: number;
  riskLevel: RiskLevel;
  threatType: string;
  confidence: number;
  summary: string;
  explanation: string;
  indicators: ThreatIndicator[];
  socialEngineeringTactics: string[];
  technicalSignals: string[];
  recommendedActions: string[];
  preventionTips: string[];
  userSafetyWarning: string;
}

const CATEGORY_CAPS: Record<SignalCategory, number> = {
  url: 35,
  content: 30,
  impersonation: 15,
  credential: 20,
};

const TRUSTED_BRANDS: Array<{ name: string; domains: string[] }> = [
  { name: 'SBI', domains: ['sbi.co.in', 'onlinesbi.sbi'] },
  { name: 'HDFC', domains: ['hdfcbank.com'] },
  { name: 'ICICI', domains: ['icicibank.com'] },
  { name: 'Axis Bank', domains: ['axisbank.com'] },
  { name: 'Microsoft', domains: ['microsoft.com', 'live.com', 'outlook.com'] },
  { name: 'Google', domains: ['google.com', 'google.co.in', 'gmail.com'] },
  { name: 'Apple', domains: ['apple.com', 'icloud.com'] },
  { name: 'Amazon', domains: ['amazon.com', 'amazon.in'] },
  { name: 'PayPal', domains: ['paypal.com'] },
  { name: 'Paytm', domains: ['paytm.com'] },
  { name: 'PhonePe', domains: ['phonepe.com'] },
  { name: 'Netflix', domains: ['netflix.com'] },
  { name: 'WhatsApp', domains: ['whatsapp.com'] },
  { name: 'FedEx', domains: ['fedex.com'] },
  { name: 'DHL', domains: ['dhl.com'] },
];

const SHORTENER_HOSTS = new Set([
  'bit.ly', 't.co', 'tinyurl.com', 'is.gd', 'cutt.ly', 'rb.gy',
  'shorturl.at', 'ow.ly', 'rebrand.ly', 'buff.ly', 'lnkd.in',
]);

const SUSPICIOUS_TLDS = new Set([
  'click', 'top', 'xyz', 'zip', 'mov', 'work', 'buzz', 'rest', 'country',
]);

const CATEGORY_LABELS: Record<SignalCategory, string> = {
  url: 'URL',
  content: 'Message',
  impersonation: 'Impersonation',
  credential: 'Credential / payment',
};

const cleanQuote = (value: string) => value.trim().replace(/[.,!?;:)\]}]+$/g, '');

function firstMatch(text: string, patterns: RegExp[]): string | undefined {
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match?.[0]) return match[0].trim();
  }
  return undefined;
}

function isNegated(text: string, quote: string): boolean {
  const index = text.toLowerCase().indexOf(quote.toLowerCase());
  if (index < 0) return false;
  return /(?:never|don't|do not|shouldn't|should not|not to)\s+(?:ever\s+)?$/i.test(
    text.slice(Math.max(0, index - 36), index),
  );
}

function collectUrls(input: SecurityInput, text: string): string[] {
  const candidates = [
    ...(input.type === 'url' ? [input.content] : []),
    ...(input.type === 'qr' ? [input.metadata?.qrDecodedText || input.content] : []),
    ...(input.metadata?.url ? [input.metadata.url] : []),
    ...[...text.matchAll(/(?:https?:\/\/|www\.)[^\s<>"')\]]+/giu)].map((match) => match[0]),
  ];

  return [...new Set(candidates.map(cleanQuote).filter(Boolean))].slice(0, 20);
}

function parseUrl(value: string): URL | null {
  try {
    return new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : `https://${value}`);
  } catch {
    return null;
  }
}

function levenshteinWithinOne(left: string, right: string): boolean {
  if (Math.abs(left.length - right.length) > 1) return false;
  let i = 0;
  let j = 0;
  let edits = 0;
  while (i < left.length && j < right.length) {
    if (left[i] === right[j]) {
      i++;
      j++;
      continue;
    }
    edits++;
    if (edits > 1) return false;
    if (left.length > right.length) i++;
    else if (right.length > left.length) j++;
    else {
      i++;
      j++;
    }
  }
  if (i < left.length || j < right.length) edits++;
  return edits <= 1;
}

function domainBrand(hostname: string): string | undefined {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  const labels = host.split('.');
  for (const brand of TRUSTED_BRANDS) {
    const token = brand.name.toLowerCase().replace(/[^a-z0-9]/g, '');
    const official = brand.domains.some((domain) => host === domain || host.endsWith(`.${domain}`));
    if (official) continue;
    const containsBrand = labels.some((label) => label.replace(/[^a-z0-9]/g, '').includes(token));
    const closeLabel = token.length >= 5 && labels.some((label) =>
      levenshteinWithinOne(label.replace(/[^a-z0-9]/g, ''), token),
    );
    if (containsBrand || closeLabel) return brand.name;
  }
  return undefined;
}

function extractBrandFromText(text: string): string | undefined {
  for (const brand of TRUSTED_BRANDS) {
    const escaped = brand.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (new RegExp(`\\b${escaped}\\b`, 'i').test(text)) return brand.name;
  }
  return undefined;
}

function scoreLevel(score: number): RiskLevel {
  if (score < 25) return 'LOW';
  if (score < 50) return 'MEDIUM';
  if (score < 75) return 'HIGH';
  return 'CRITICAL';
}

function levelForSignal(weight: number): RiskLevel {
  if (weight >= 25) return 'HIGH';
  if (weight >= 13) return 'MEDIUM';
  return 'LOW';
}

function getThreatType(text: string, signals: SecuritySignal[]): string {
  const has = (id: string) => signals.some((signal) => signal.id === id);
  if (has('otp-request')) return 'OTP_SCAM';
  if (has('remote-access') && (has('brand-impersonation') || has('malware-threat'))) return 'TECH_SUPPORT_SCAM';
  if (has('prize-promotion') && has('advance-fee')) return 'PRIZE_SCAM';
  if (has('job-offer') && has('advance-fee')) return 'JOB_SCAM';
  if (has('guaranteed-return') && has('investment-pitch')) return 'INVESTMENT_SCAM';
  if (has('credential-request') || (has('account-verification') && (has('brand-impersonation') || has('lookalike-domain')))) {
    return 'PHISHING';
  }
  if (has('advance-fee') || has('money-transfer')) return 'FINANCIAL_SCAM';
  if (has('brand-impersonation')) return 'IMPERSONATION';
  if (signals.length) return 'SUSPICIOUS_ACTIVITY';
  if (/^upi:\/\//i.test(text.trim())) return 'PAYMENT_QR';
  return 'NO_SCAM_INDICATORS';
}

export function analyzeDeterministic(
  input: SecurityInput,
  supplementalText = '',
  options: { aiUnavailable?: boolean; visualInput?: boolean } = {},
): DeterministicAnalysis {
  const originalContent = input.content || '';
  const text = [
    originalContent,
    input.metadata?.sender || '',
    input.metadata?.subject || '',
    input.metadata?.url || '',
    input.metadata?.qrDecodedText || '',
    supplementalText,
  ].join('\n').slice(0, 40_000);
  const lower = text.toLowerCase();
  const signals: SecuritySignal[] = [];
  const technicalSignals = new Set<string>();
  const tactics = new Set<string>();
  const add = (
    id: string,
    category: SignalCategory,
    weight: number,
    name: string,
    description: string,
    quote?: string,
  ) => {
    if (!signals.some((signal) => signal.id === id)) {
      signals.push({ id, category, weight, name, description, quote });
    }
  };

  const urgency = firstMatch(text, [
    /\b(?:immediately|right away|act now|today only|within \d+\s*(?:minutes?|hours?|days?)|limited slots|final warning|last chance)\b/gi,
  ]);
  if (urgency) {
    add('urgency', 'content', 5, 'Pressure to act quickly', 'The message uses time pressure to encourage a rushed decision.', urgency);
    tactics.add('Artificial urgency');
  }

  const accountThreat = firstMatch(text, [
    /\b(?:account|card|service|parcel|order|benefit)\b.{0,55}\b(?:will be|has been|is being|may be)\s*(?:blocked|suspended|closed|cancelled|canceled|frozen|terminated)\b/gi,
    /\b(?:blocked|suspended|closed|cancelled|canceled|frozen|terminated)\b.{0,55}\b(?:account|card|service|parcel|order|benefit)\b/gi,
  ]);
  if (accountThreat) {
    add('account-threat', 'content', 12, 'Threat of account or service loss', 'The content threatens to block, suspend, or cancel an account or service.', accountThreat);
    tactics.add('Threat of loss');
  }

  const accountVerification = firstMatch(text, [
    /\b(?:verify|confirm|restore|reactivate|validate|update)\b.{0,55}\b(?:your\s+)?(?:account|bank|card|identity|profile|payment)\b/gi,
    /\b(?:account|bank|card|identity|profile|payment)\b.{0,45}\b(?:verification|validation|confirmation)\b/gi,
  ]);
  if (accountVerification) {
    add('account-verification', 'credential', 10, 'Account verification request', 'The content asks the recipient to verify or restore an account or payment profile.', accountVerification);
    tactics.add('Account verification pressure');
  }

  const otpRequest = firstMatch(text, [
    /\b(?:share|send|tell|provide|give|forward|read(?:\s+back)?)\b.{0,55}\b(?:the\s+)?(?:otp|one[- ]time(?:\s+password)?(?:\s+passcode)?|verification code)\b/gi,
    /\b(?:otp|one[- ]time(?:\s+password)?(?:\s+passcode)?|verification code)\b.{0,55}\b(?:share|send|tell|provide|give|forward)\b/gi,
  ]);
  if (otpRequest && !isNegated(text, otpRequest)) {
    add('otp-request', 'credential', 20, 'Request to share a verification code', 'A one-time password or verification code is being requested. Legitimate support should not ask you to disclose it.', otpRequest);
    tactics.add('One-time code capture');
  }

  const credentialRequest = firstMatch(text, [
    /\b(?:send|share|provide|enter|reply with|confirm|verify|give us|tell us|submit)\b.{0,55}\b(?:password|passcode|pin|card number|cvv|security code|bank details|login details)\b/gi,
    /\b(?:password|passcode|pin|card number|cvv|security code|bank details|login details)\b.{0,45}\b(?:send|share|provide|enter|reply with|give us|tell us)\b/gi,
  ]);
  if (credentialRequest && !isNegated(text, credentialRequest)) {
    const bankRequest = /\b(?:card number|cvv|bank details|login details)\b/i.test(credentialRequest);
    add('credential-request', 'credential', bankRequest ? 20 : 18, 'Request for private credentials', 'The content asks the recipient to disclose a password, PIN, card detail, or banking credential.', credentialRequest);
    tactics.add('Credential harvesting');
  }

  const advanceFee = firstMatch(text, [
    /\b(?:pay|send|transfer|deposit|wire|submit)\b.{0,60}\b(?:processing|registration|activation|release|customs|delivery|shipping|handling|withdrawal|clearance)\s+(?:fee|charge|deposit)\b/gi,
    /\b(?:processing|registration|activation|release|customs|delivery|shipping|handling|withdrawal|clearance)\s+(?:fee|charge|deposit)\b.{0,60}\b(?:pay|send|transfer|deposit|wire|submit)\b/gi,
    /\b(?:pay|send|transfer|deposit|wire)\b.{0,35}(?:₹|rs\.?\s?|inr\s?)\s?[\d,]+.{0,45}\b(?:to receive|to claim|to release|to activate|to complete)\b/gi,
  ]);
  if (advanceFee) {
    add('advance-fee', 'credential', 16, 'Upfront fee to receive a benefit', 'The message asks for money before a promised prize, job, refund, delivery, or other benefit.', advanceFee);
    tactics.add('Advance-fee request');
  } else {
    const moneyTransfer = firstMatch(text, [
      /\b(?:pay|send|transfer|deposit|wire)\b.{0,35}(?:₹|rs\.?\s?|inr\s?)\s?[\d,]+/gi,
      /\b(?:send|transfer)\s+(?:me|us|them)\s+(?:money|funds|crypto|bitcoin|gift cards?)\b/gi,
    ]);
    if (moneyTransfer) {
      add('money-transfer', 'credential', 8, 'Request to transfer money', 'Money is requested, but the content alone does not establish that the request is fraudulent.', moneyTransfer);
    }
  }

  const prizePromotion = firstMatch(text, [
    /\b(?:you have won|you won|congratulations.{0,30}won|claim your prize|lottery winner|prize money)\b/gi,
  ]);
  if (prizePromotion) {
    add('prize-promotion', 'content', 12, 'Unexpected prize or lottery claim', 'The content claims an unexpected prize or lottery win.', prizePromotion);
    tactics.add('Unexpected reward');
  }

  const deliveryPayment = firstMatch(text, [
    /\b(?:parcel|package|delivery|shipment|courier)\b.{0,70}\b(?:on hold|pay|payment|fee|customs|cancelled|canceled|cancel)\b/gi,
    /\b(?:on hold|pay|payment|fee|customs|cancelled|canceled|cancel)\b.{0,70}\b(?:parcel|package|delivery|shipment|courier)\b/gi,
  ]);
  if (deliveryPayment) {
    add('delivery-payment', 'content', 8, 'Delivery notice asks for payment or warns of a hold', 'The content links a delivery issue with payment or cancellation. Verify it in the carrier’s official app.', deliveryPayment);
  }

  const governmentPressure = firstMatch(text, [
    /\b(?:tax department|income tax|customs|police|court|government|immigration)\b.{0,80}\b(?:pay|fine|arrest|warrant|verify|urgent|summons|penalty)\b/gi,
    /\b(?:pay|fine|arrest|warrant|verify|urgent|summons|penalty)\b.{0,80}\b(?:tax department|income tax|customs|police|court|government|immigration)\b/gi,
  ]);
  if (governmentPressure) {
    add('government-pressure', 'content', 9, 'Government or law-enforcement pressure', 'The message claims official authority while demanding action; verify through the agency’s published contact details.', governmentPressure);
    tactics.add('Authority pressure');
  }

  const platformMove = firstMatch(text, [
    /\b(?:move|continue|switch|message|contact|chat)\b.{0,55}\b(?:telegram|whatsapp|signal|wechat|another platform|personal number)\b/gi,
    /\b(?:telegram|whatsapp|signal|wechat|personal number)\b.{0,55}\b(?:move|continue|switch|message|contact|chat)\b/gi,
  ]);
  if (platformMove) {
    add('platform-move', 'content', 6, 'Request to move the conversation', 'The sender asks to move the discussion to another platform or a personal contact channel.', platformMove);
    tactics.add('Request to move channels');
  }

  const cryptoRequest = firstMatch(text, [
    /\b(?:pay|send|transfer|deposit)\b.{0,65}\b(?:bitcoin|btc|ethereum|crypto(?:currency)?|wallet address)\b/gi,
    /\b(?:bitcoin|btc|ethereum|crypto(?:currency)?|wallet address)\b.{0,65}\b(?:pay|send|transfer|deposit)\b/gi,
  ]);
  if (cryptoRequest) {
    add('crypto-request', 'credential', 9, 'Request for cryptocurrency payment', 'The content requests payment in cryptocurrency; this payment method alone does not prove a scam.', cryptoRequest);
  }

  const emotionalPressure = firstMatch(text, [
    /\b(?:your (?:child|son|daughter|parent|mother|father|spouse|family member)\s+(?:is|has been)\s+(?:in danger|arrested|injured|detained)|act now to save|you will lose everything|your loved one needs money)\b/gi,
  ]);
  if (emotionalPressure) {
    add('emotional-pressure', 'content', 8, 'Emotional or family emergency pressure', 'The message uses fear for a loved one or a claimed emergency to prompt immediate action.', emotionalPressure);
    tactics.add('Emotional manipulation');
  }

  const jobOffer = firstMatch(text, [
    /\b(?:selected|hired|offered|work[- ]from[- ]home|remote)\b.{0,65}\b(?:job|position|employment|employee)\b/gi,
    /\b(?:job|position|employment|employee)\b.{0,65}\b(?:selected|hired|registration|activation)\b/gi,
  ]);
  if (jobOffer) {
    add('job-offer', 'content', 10, 'Job offer with an unusual setup', 'The content presents a job or employment offer; this is not by itself proof of fraud.', jobOffer);
  }

  const investmentPitch = firstMatch(text, [
    /\b(?:invest|investment|returns?|profit|trading|crypto(?:currency)?)\b/gi,
  ]);
  if (investmentPitch) {
    add('investment-pitch', 'content', 9, 'Investment or profit claim', 'The content promotes an investment or financial return.', investmentPitch);
  }
  const guaranteedReturn = firstMatch(text, [
    /\b(?:guaranteed|risk[- ]free|assured)\b.{0,50}\b(?:return|profit|earn|receive|double|triple)\b/gi,
    /\b(?:return|profit|earn|receive|double|triple)\b.{0,50}\b(?:guaranteed|risk[- ]free|assured)\b/gi,
  ]);
  if (guaranteedReturn) {
    add('guaranteed-return', 'content', 18, 'Guaranteed high return claim', 'The content promises a guaranteed or unusually large financial return.', guaranteedReturn);
    tactics.add('Unrealistic financial promise');
  }

  const remoteAccess = firstMatch(text, [
    /\b(?:give|grant|allow|enable|install|download)\b.{0,55}\b(?:remote access|remote control|screen sharing|anydesk|teamviewer|rustdesk)\b/gi,
    /\b(?:remote access|remote control|screen sharing|anydesk|teamviewer|rustdesk)\b.{0,55}\b(?:give|grant|allow|install|download)\b/gi,
    /\b(?:let us|allow us|give us)\b.{0,45}\b(?:control|access)\b.{0,30}\b(?:computer|device|phone|screen)\b/gi,
  ]);
  if (remoteAccess && !isNegated(text, remoteAccess)) {
    add('remote-access', 'credential', 20, 'Request for remote device access', 'The sender asks to control or access the recipient’s device remotely.', remoteAccess);
    tactics.add('Remote-access request');
  }

  const malwareThreat = firstMatch(text, [
    /\b(?:computer|device|phone|system)\b.{0,45}\b(?:infected|compromised|hacked|has a virus)\b/gi,
    /\b(?:infected|compromised|hacked|has a virus)\b.{0,45}\b(?:computer|device|phone|system)\b/gi,
  ]);
  if (malwareThreat) {
    add('malware-threat', 'content', 10, 'Unverified malware warning', 'The message claims a device is infected or compromised; verify this independently rather than installing software from the sender.', malwareThreat);
    tactics.add('Fear-based technical support claim');
  }

  const installRequest = firstMatch(text, [
    /\b(?:install|download)\b.{0,65}\b(?:application|app|software|program|tool|update)\b/gi,
  ]);
  if (installRequest) {
    add('software-install', 'content', 6, 'Request to install software', 'The content asks for software to be installed; this is risky when paired with unsolicited support or remote access.', installRequest);
  }

  const secrecy = firstMatch(text, [
    /\b(?:keep this (?:secret|confidential)|do not tell|don't tell|keep it between us|do not discuss this)\b/gi,
  ]);
  if (secrecy) {
    add('secrecy', 'content', 7, 'Instruction to keep the request secret', 'The sender discourages the recipient from checking with others.', secrecy);
    tactics.add('Secrecy pressure');
  }

  const urgencyPattern = /\b(?:immediately|right away|act now|today only|within \d+\s*(?:minutes?|hours?|days?)|limited slots|final warning|last chance)\b/i;
  const hasUrgency = urgencyPattern.test(text);
  const hasStrongRequest = Boolean(otpRequest || credentialRequest || remoteAccess || advanceFee);
  const statedBrand = extractBrandFromText(text);
  const urlCandidates = collectUrls(input, text);
  const observedBrands = new Set<string>();
  let suspiciousDomain = false;

  for (const candidate of urlCandidates) {
    const parsed = parseUrl(candidate);
    if (!parsed) {
      add(`malformed-url:${candidate}`, 'url', 4, 'URL could not be parsed', 'The submitted destination is not a well-formed web address; this alone does not show it is malicious.', candidate);
      continue;
    }
    const host = parsed.hostname.toLowerCase();
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || /^\[[\da-f:]+\]$/i.test(host)) {
      suspiciousDomain = true;
      add('ip-host', 'url', 14, 'URL uses an IP address as its host', 'The web address points directly to an IP address instead of a named domain.', candidate);
    }
    if (SHORTENER_HOSTS.has(host)) {
      suspiciousDomain = true;
      add('url-shortener', 'url', 9, 'URL shortener hides the destination', 'The short link obscures the final destination; check it independently before opening.', candidate);
    }
    if (host.includes('xn--')) {
      suspiciousDomain = true;
      add('punycode', 'url', 12, 'Internationalized domain encoding present', 'The hostname contains punycode. This can be legitimate, but lookalike characters cannot be assessed from the encoded form alone.', candidate);
    }
    if (host.length > 70) {
      add('long-host', 'url', 5, 'Unusually long hostname', 'The hostname is longer than typical; length alone is not proof of fraud.', candidate);
    }
    if (candidate.length > 200) {
      add('long-url', 'url', 5, 'Unusually long URL', 'The submitted web address is unusually long; inspect its full destination before interacting.', candidate);
    }
    if (parsed.username || parsed.password) {
      suspiciousDomain = true;
      add('url-userinfo', 'url', 10, 'URL contains user information before the host', 'The address includes text before @ that can make its actual hostname easy to misread.', candidate);
    }
    if (/[\\\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(candidate)) {
      suspiciousDomain = true;
      add('url-control-character', 'url', 10, 'URL contains a control or direction-changing character', 'The address contains characters that can obscure how a URL is displayed.', candidate);
    }
    const subdomainCount = host.split('.').length - 2;
    if (subdomainCount >= 4) {
      add('deep-subdomain', 'url', 5, 'Unusually deep subdomain structure', 'The address contains several nested subdomains that may make the actual registered domain harder to notice.', candidate);
    }
    const tld = host.split('.').pop() || '';
    if (SUSPICIOUS_TLDS.has(tld)) {
      add(`tld:${tld}`, 'url', 4, 'Less commonly used website ending', `The domain uses the .${tld} ending. A TLD alone does not establish malicious intent.`, candidate);
    }
    if (parsed.protocol === 'http:') {
      add('plain-http', 'url', 2, 'Connection does not use HTTPS', 'The link uses unencrypted HTTP. HTTPS also does not prove that a site is legitimate.', candidate);
    }
    const query = parsed.search.slice(1);
    const params = [...parsed.searchParams.entries()];
    if (params.length >= 6) {
      add('many-params', 'url', 6, 'URL has many query parameters', 'The URL carries an unusually large number of parameters; this is a weak signal by itself.', candidate);
    }
    if (/%(?:2f|3a|40|2e|5c)/i.test(query)) {
      add('encoded-params', 'url', 6, 'Encoded URL control characters in parameters', 'The query contains encoded separators or URL characters that can conceal a redirect destination.', candidate);
    }
    const redirectParam = params.find(([key]) => /^(?:url|redirect|redirect_uri|next|continue|return|target|destination|dest)$/i.test(key));
    if (redirectParam) {
      add('redirect-param', 'url', 7, 'URL contains a redirect parameter', 'A parameter appears to control a later destination; it was inspected as text and not followed.', candidate);
    }
    if (parsed.pathname.length > 90) {
      add('long-path', 'url', 4, 'Unusually long URL path', 'The path is unusually long; this is not evidence of malware by itself.', candidate);
    }
    let path = parsed.pathname.toLowerCase();
    try {
      path = decodeURIComponent(path.replace(/%(?![0-9a-f]{2})/gi, '%25'));
    } catch {
      add('invalid-path-encoding', 'url', 5, 'URL path encoding is malformed', 'The submitted path could not be decoded as valid URL text.', candidate);
    }
    if (/\b(?:login|signin|sign-in|verify|verification|account|secure|auth|password)\b/.test(path)) {
      add('credential-path', 'url', 6, 'URL path mentions account access or verification', 'The path refers to a login, account, or verification action; verify the destination independently.', candidate);
    }
    if (/\b(?:pay|payment|billing|invoice|checkout|wallet)\b/.test(path)) {
      add('payment-path', 'url', 5, 'URL path mentions payment', 'The path refers to a payment action; this is a caution signal, not proof of fraud.', candidate);
    }
    if (/\b(?:prize|claim|reward|winner|giveaway)\b/.test(path)) {
      add('prize-path', 'url', 6, 'URL path mentions a prize or claim', 'The path refers to claiming a prize or reward; check for a corresponding fee or sensitive-data request.', candidate);
    }
    if (/\b(?:download|install|update)\b/.test(path)) {
      add('download-path', 'url', 5, 'URL path requests a download or install', 'The path appears related to downloading or installing content; do not run untrusted files.', candidate);
    }
    let embeddedUrl = false;
    for (const [, value] of params) {
      try {
        const decoded = decodeURIComponent(value);
        if (/https?:\/\//i.test(decoded)) embeddedUrl = true;
      } catch {
        // Invalid percent-encoding is already exposed through the encoded-parameter signal.
      }
    }
    if (embeddedUrl) {
      add('embedded-url', 'url', 6, 'URL embeds another web address', 'A query parameter contains a second URL; its destination was not opened.', candidate);
    }

    const brand = domainBrand(host);
    if (brand) {
      suspiciousDomain = true;
      observedBrands.add(brand);
      add(`lookalike:${brand}`, 'url', 12, `Possible ${brand} lookalike domain`, `The hostname includes or resembles ${brand}, but does not match the checked official domains (${TRUSTED_BRANDS.find((item) => item.name === brand)?.domains.join(', ')}). This is an unverified lookalike signal, not a reputation verdict.`, candidate);
    }
  }

  const highIntent = /\b(?:verify|confirm|restore|reactivate|blocked|suspended|otp|password|payment|refund|prize|selected|support|infected|remote access)\b/i.test(text);
  if (statedBrand && highIntent && urlCandidates.length && !observedBrands.has(statedBrand)) {
    const host = urlCandidates.map(parseUrl).find(Boolean)?.hostname || '';
    const official = TRUSTED_BRANDS.find((item) => item.name === statedBrand)?.domains || [];
    if (host && !official.some((domain) => host === domain || host.endsWith(`.${domain}`))) {
      suspiciousDomain = true;
      add('brand-impersonation', 'impersonation', 15, `${statedBrand} brand and destination do not match`, `The content invokes ${statedBrand}, but the supplied link is not on the checked official domains (${official.join(', ')}). This comparison is heuristic and is not an external reputation check.`, urlCandidates[0]);
      tactics.add('Possible brand impersonation');
    }
  }
  for (const brand of observedBrands) {
    add('brand-impersonation', 'impersonation', 15, `Possible ${brand} impersonation`, `The destination uses ${brand}'s name on a hostname outside its checked official domains.`, urlCandidates[0]);
    tactics.add('Possible brand impersonation');
  }
  if (statedBrand && (remoteAccess || malwareThreat) && /\b(?:support|security|helpdesk|technician|agent)\b/i.test(text)) {
    add('brand-impersonation', 'impersonation', 15, `Possible ${statedBrand} support impersonation`, `The message claims to represent ${statedBrand} support while requesting access or making an unverified infection claim.`, firstMatch(text, [new RegExp(`\\b${statedBrand.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b.{0,70}\\b(?:support|security|helpdesk|technician|agent)\\b`, 'i')]));
    tactics.add('Possible support impersonation');
  }

  const brandVerificationRequest = Boolean(statedBrand && accountThreat && accountVerification && hasUrgency);
  if (brandVerificationRequest) suspiciousDomain = true;

  const componentScores = (Object.keys(CATEGORY_CAPS) as SignalCategory[]).map((category) => {
    const sum = signals.filter((signal) => signal.category === category).reduce((total, signal) => total + signal.weight, 0);
    return { category, score: Math.min(sum, CATEGORY_CAPS[category]), cap: CATEGORY_CAPS[category] };
  });
  const componentTotal = componentScores.reduce((total, item) => total + item.score, 0);
  let score = componentTotal;
  let combinationRule = '';
  const applyScoreFloor = (floor: number, reason: string) => {
    if (floor > score) {
      score = floor;
      combinationRule = reason;
    }
  };

  // A few explicit, high-impact combinations qualify as high risk on their own.
  if (otpRequest && !isNegated(text, otpRequest)) applyScoreFloor(52, 'explicit request to disclose an OTP');
  if (credentialRequest && !isNegated(text, credentialRequest)) applyScoreFloor(54, 'explicit request to disclose credentials');
  if (remoteAccess && (statedBrand || malwareThreat)) applyScoreFloor(78, 'remote-access request paired with an authority or infection claim');
  if (brandVerificationRequest && suspiciousDomain && urlCandidates.length) applyScoreFloor(78, 'urgent account threat and verification request paired with a mismatched brand domain');
  if (prizePromotion && advanceFee) applyScoreFloor(52, 'prize claim paired with an advance fee');
  if (jobOffer && advanceFee) applyScoreFloor(52, 'job offer paired with an advance fee');
  if (investmentPitch && guaranteedReturn) applyScoreFloor(54, 'investment pitch paired with a guaranteed return');
  if (/\bsend money to receive money\b/i.test(text)) applyScoreFloor(60, 'explicit send-money-to-receive-money request');
  score = Math.min(100, Math.round(score));

  const riskLevel = scoreLevel(score);
  const classification = score >= 50 ? 'SCAM' : score >= 25 ? 'SUSPICIOUS' : 'SAFE';
  const threatType = getThreatType(text, signals);
  const indicators = signals.map((signal) => ({
    name: signal.name,
    severity: levelForSignal(signal.weight),
    description: signal.quote
      ? `${signal.description} Observed: “${signal.quote.slice(0, 220)}”`
      : signal.description,
  }));

  if (/^upi:\/\//i.test(originalContent.trim())) {
    try {
      const upi = new URL(originalContent.trim());
      const payee = upi.searchParams.get('pn');
      const amount = upi.searchParams.get('am');
      technicalSignals.add(
        `QR payload is a UPI payment request${payee ? `; payee label: ${payee.slice(0, 80)}` : ''}${amount ? `; requested amount: ${amount}` : ''}. This identifies payment intent, not fraud.`,
      );
    } catch {
      technicalSignals.add('QR payload uses the UPI payment scheme; verify recipient and amount in your payment app before authorizing.');
    }
  }
  for (const component of componentScores) {
    technicalSignals.add(`${CATEGORY_LABELS[component.category]} signals: ${component.score}/${component.cap}`);
  }
  if (combinationRule) {
    technicalSignals.add(`Strong-pattern minimum applied: ${score}/100 because of an explicit ${combinationRule}.`);
  }
  technicalSignals.add('External reputation data was not available; no domain-age, WHOIS, blacklist, or malware lookup was performed.');
  if (options.aiUnavailable) technicalSignals.add('Gemini was unavailable; this result uses deterministic checks only.');
  if (options.visualInput) technicalSignals.add('Screenshot text and visual details are model-read and were not independently OCR-verified.');
  if (!urlCandidates.length && input.type !== 'url' && input.type !== 'qr') {
    technicalSignals.add('No URL was found in the submitted text.');
  }
  if (urlCandidates.length) {
    technicalSignals.add(`Inspected ${urlCandidates.length} submitted URL${urlCandidates.length === 1 ? '' : 's'} without visiting or resolving them.`);
  }

  const distinctCategories = new Set(signals.map((signal) => signal.category)).size;
  const confidence = Math.min(92, Math.max(52, 64 + distinctCategories * 6 + (signals.length >= 3 ? 6 : 0)));
  let summary: string;
  if (riskLevel === 'CRITICAL') {
    summary = 'Strong evidence of a severe scam pattern was found. Do not follow the request or interact with its links.';
  } else if (riskLevel === 'HIGH') {
    summary = 'Multiple concrete scam indicators were found. Treat this request as unsafe unless independently verified through an official channel.';
  } else if (riskLevel === 'MEDIUM') {
    summary = 'Some suspicious characteristics were found, but the available evidence is inconclusive. Verify independently before acting.';
  } else if (options.visualInput && !supplementalText.trim()) {
    summary = 'The screenshot could not be independently checked for visible text. Treat this result as incomplete and review the image carefully.';
  } else {
    summary = 'No meaningful scam indicators were found in the submitted content. This does not verify the sender or destination as safe.';
  }

  const componentExplanation = componentScores
    .map((item) => `${CATEGORY_LABELS[item.category]} ${item.score}/${item.cap}`)
    .join(' · ');
  const explanation = indicators.length
    ? `${indicators.map((indicator) => indicator.description).join(' ')} Score components: ${componentExplanation}. Signals are capped by category to reduce double-counting.${combinationRule ? ` A defined strong-pattern minimum also applies (${score}/100): ${combinationRule}.` : ''}`
    : `No known high-risk pattern matched the submitted content. Score components: ${componentExplanation}. A low result is not proof that the content or destination is safe.`;

  const recommendedActions = riskLevel === 'CRITICAL' || riskLevel === 'HIGH'
    ? [
        'Do not click the link, install software, transfer money, or share passwords, PINs, or one-time codes.',
        'Contact the named organization using the number or website from its official app or a trusted source—not the message.',
        'If you already shared credentials or money, contact your bank or service provider immediately and use the incident-response steps below.',
      ]
    : riskLevel === 'MEDIUM'
      ? [
          'Pause before replying, paying, downloading, or sharing personal information.',
          'Verify the request through a separate, known-good channel.',
          'For a link, inspect the full destination without signing in or entering information.',
        ]
      : [
          'No strong scam indicator was found, but do not share credentials or one-time codes in response to unsolicited messages.',
          'Verify unexpected payment, account, or support requests through an official channel.',
        ];

  return {
    classification,
    riskScore: score,
    riskLevel,
    threatType,
    confidence,
    summary,
    explanation,
    indicators,
    socialEngineeringTactics: [...tactics],
    technicalSignals: [...technicalSignals],
    recommendedActions,
    preventionTips: [
      'Open official services from a saved bookmark or their official app instead of message links.',
      'Never disclose a password, PIN, or one-time code to someone who contacts you.',
      'Treat unsolicited payment, prize, job, investment, and remote-support requests cautiously.',
    ],
    userSafetyWarning: score >= 50
      ? 'Do not send money, reveal credentials, or grant device access. Verify through an official channel.'
      : 'A low or medium score is not a guarantee of safety. No live domain reputation check was performed.',
  };
}

export function deriveClassification(score: number): 'SAFE' | 'SUSPICIOUS' | 'SCAM' {
  return score >= 50 ? 'SCAM' : score >= 25 ? 'SUSPICIOUS' : 'SAFE';
}
