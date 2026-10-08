import React, { useState, useRef } from 'react';
import jsQR from 'jsqr';
import { api } from '../lib/api.ts';
import { ThreatAnalysis, AnalysisType } from '../types/index.ts';
import {
  MessageSquare,
  Mail,
  Globe,
  Camera,
  QrCode,
  ShieldAlert,
  ArrowRight,
  Upload,
  AlertTriangle,
  Sparkles,
  ExternalLink,
  Copy,
  Check,
  RefreshCw,
} from 'lucide-react';

interface AnalyzerProps {
  onAnalysisComplete: (analysis: ThreatAnalysis) => void;
  onOpenAuth: () => void;
  user: any;
}

export const Analyzer: React.FC<AnalyzerProps> = ({ onAnalysisComplete, onOpenAuth, user }) => {
  const [activeType, setActiveType] = useState<AnalysisType>('message');

  // Input states
  const [messageText, setMessageText] = useState('');
  const [messageSender, setMessageSender] = useState('');

  const [emailSender, setEmailSender] = useState('');
  const [emailSubject, setEmailSubject] = useState('');
  const [emailBody, setEmailBody] = useState('');
  const [emailUrl, setEmailUrl] = useState('');

  const [urlInput, setUrlInput] = useState('');

  // Screenshot states
  const [screenshotData, setScreenshotData] = useState<string | null>(null);
  const [screenshotMime, setScreenshotMime] = useState<string>('image/png');
  const [screenshotNotes, setScreenshotNotes] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  // QR scanner states
  const [qrDecoded, setQrDecoded] = useState<string | null>(null);
  const [qrPreviewImage, setQrPreviewImage] = useState<string | null>(null);
  const [qrDecoding, setQrDecoding] = useState<boolean>(false);
  const qrInputRef = useRef<HTMLInputElement>(null);

  // Status
  const [analyzing, setAnalyzing] = useState(false);
  const analyzingRef = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Handle Screenshot file upload
  const handleScreenshotChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!['image/png', 'image/jpeg', 'image/jpg', 'image/webp'].includes(file.type)) {
      setError('Please upload a valid image file (PNG, JPG, or WEBP).');
      return;
    }

    if (file.size > 10 * 1024 * 1024) {
      setError('File size exceeds 10MB limit.');
      return;
    }

    setError(null);
    setScreenshotMime(file.type === 'image/jpg' ? 'image/jpeg' : file.type);
    const reader = new FileReader();
    reader.onload = (ev) => {
      setScreenshotData(ev.target?.result as string);
    };
    reader.readAsDataURL(file);
  };

  // Handle QR Code image decode via jsQR
  const handleQrImageChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setError(null);
    setQrDecoding(true);
    setQrDecoded(null);

    const reader = new FileReader();
    reader.onload = (ev) => {
      const dataUrl = ev.target?.result as string;
      setQrPreviewImage(dataUrl);

      const img = new Image();
      img.onload = () => {
        try {
          const canvas = document.createElement('canvas');
          canvas.width = img.width;
          canvas.height = img.height;
          const ctx = canvas.getContext('2d');
          if (!ctx) {
            setError('Canvas context initialization failed.');
            setQrDecoding(false);
            return;
          }
          ctx.drawImage(img, 0, 0, img.width, img.height);
          const imageData = ctx.getImageData(0, 0, img.width, img.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: 'attemptBoth',
          });

          if (code && code.data) {
            setQrDecoded(code.data);
          } else {
            setError('No QR code detected in this image. You can also paste decoded text manually.');
          }
        } catch (err: any) {
          setError('Error reading QR code from image: ' + err.message);
        } finally {
          setQrDecoding(false);
        }
      };
      img.src = dataUrl;
    };
    reader.readAsDataURL(file);
  };

  // Trigger analysis
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (analyzingRef.current) return;
    setError(null);

    if (!user) {
      onOpenAuth();
      return;
    }

    let payload: {
      type: AnalysisType;
      content?: string;
      metadata?: any;
    };

    if (activeType === 'message') {
      if (!messageText.trim()) {
        setError('Please enter message text to inspect.');
        return;
      }
      payload = {
        type: 'message',
        content: messageText.trim(),
        metadata: { sender: messageSender.trim() || undefined },
      };
    } else if (activeType === 'email') {
      if (!emailBody.trim()) {
        setError('Please enter email content to inspect.');
        return;
      }
      payload = {
        type: 'email',
        content: emailBody.trim(),
        metadata: {
          sender: emailSender.trim() || undefined,
          subject: emailSubject.trim() || undefined,
          url: emailUrl.trim() || undefined,
        },
      };
    } else if (activeType === 'url') {
      if (!urlInput.trim()) {
        setError('Please enter a website URL.');
        return;
      }
      payload = {
        type: 'url',
        content: urlInput.trim(),
        metadata: { url: urlInput.trim() },
      };
    } else if (activeType === 'screenshot') {
      if (!screenshotData) {
        setError('Please upload a screenshot image.');
        return;
      }
      payload = {
        type: 'screenshot',
        content: screenshotNotes.trim() || 'Uploaded screenshot',
        metadata: {
          imageDataBase64: screenshotData,
          imageMimeType: screenshotMime,
        },
      };
    } else {
      // QR
      if (!qrDecoded || !qrDecoded.trim()) {
        setError('Please upload an image with a QR code or paste decoded QR text.');
        return;
      }
      payload = {
        type: 'qr',
        content: qrDecoded.trim(),
        metadata: {
          qrDecodedText: qrDecoded.trim(),
          url: qrDecoded.trim().startsWith('http') ? qrDecoded.trim() : undefined,
        },
      };
    }

    analyzingRef.current = true;
    setAnalyzing(true);
    try {
      const result = await api.analyses.analyze(payload);
      onAnalysisComplete(result);
    } catch (err: any) {
      setError(err.message || 'Threat analysis failed. Please try again.');
    } finally {
      analyzingRef.current = false;
      setAnalyzing(false);
    }
  };

  const handleCopyQr = () => {
    if (qrDecoded) {
      navigator.clipboard.writeText(qrDecoded);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto space-y-6">
      {/* Header Info */}
      <div className="text-center sm:text-left flex flex-col sm:flex-row sm:items-end justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono uppercase tracking-wider mb-1">
            <ShieldAlert className="h-4 w-4" />
            Evidence-Based Threat Analysis
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            Analyze Digital Threat
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-xl">
            Inspect messages, emails, links, screenshots, and QR codes with evidence-based checks and optional Gemini analysis.
          </p>
        </div>
      </div>

      {/* Mode Selector Segmented Controls (Buttons per design rules) */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 p-1 bg-slate-900/80 rounded-lg border border-slate-800">
        <button
          type="button"
          onClick={() => { setActiveType('message'); setError(null); }}
          className={`flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer ${
            activeType === 'message'
              ? 'bg-slate-800 text-cyan-400 border border-cyan-500/30 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <MessageSquare className="h-3.5 w-3.5" />
          <span>Message</span>
        </button>

        <button
          type="button"
          onClick={() => { setActiveType('email'); setError(null); }}
          className={`flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer ${
            activeType === 'email'
              ? 'bg-slate-800 text-cyan-400 border border-cyan-500/30 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Mail className="h-3.5 w-3.5" />
          <span>Email</span>
        </button>

        <button
          type="button"
          onClick={() => { setActiveType('url'); setError(null); }}
          className={`flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer ${
            activeType === 'url'
              ? 'bg-slate-800 text-cyan-400 border border-cyan-500/30 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Globe className="h-3.5 w-3.5" />
          <span>URL / Link</span>
        </button>

        <button
          type="button"
          onClick={() => { setActiveType('screenshot'); setError(null); }}
          className={`flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer ${
            activeType === 'screenshot'
              ? 'bg-slate-800 text-cyan-400 border border-cyan-500/30 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Camera className="h-3.5 w-3.5" />
          <span>Screenshot</span>
        </button>

        <button
          type="button"
          onClick={() => { setActiveType('qr'); setError(null); }}
          className={`flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer col-span-2 sm:col-span-1 ${
            activeType === 'qr'
              ? 'bg-slate-800 text-cyan-400 border border-cyan-500/30 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <QrCode className="h-3.5 w-3.5" />
          <span>QR Scanner</span>
        </button>
      </div>

      {/* Main Analysis Form Box */}
      <form onSubmit={handleSubmit} className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 sm:p-6 shadow-xl space-y-4">
        {error && (
          <div className="flex items-start gap-2.5 rounded border border-rose-500/30 bg-rose-950/30 p-3 text-xs text-rose-300">
            <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400 mt-0.5" />
            <div className="flex-1">{error}</div>
          </div>
        )}

        {/* 1. MESSAGE MODE */}
        {activeType === 'message' && (
          <div className="space-y-3">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Sender Number or Handle <span className="text-slate-500 font-normal">(Optional)</span>
              </label>
              <input
                type="text"
                placeholder="+1 (800) 555-0199 or @username"
                value={messageSender}
                onChange={(e) => setMessageSender(e.target.value)}
                className="w-full rounded border border-slate-700 bg-slate-950 py-2 px-3 text-xs text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Message Content <span className="text-rose-400">*</span>
              </label>
              <textarea
                rows={5}
                required
                placeholder="Paste SMS, WhatsApp, Telegram, or social media message here... (e.g., Bank OTP requests, delivery notices, job offers)"
                value={messageText}
                onChange={(e) => setMessageText(e.target.value)}
                className="w-full rounded border border-slate-700 bg-slate-950 py-2 px-3 text-xs text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none resize-none"
              />
            </div>
            <div className="text-[11px] text-slate-500">
              ScamGuard inspects for phishing, impersonation, OTP capture, job fraud, and emotional manipulation tactics.
            </div>
          </div>
        )}

        {/* 2. EMAIL MODE */}
        {activeType === 'email' && (
          <div className="space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Sender Address <span className="text-slate-500 font-normal">(e.g., account@service.com)</span>
                </label>
                <input
                  type="text"
                  placeholder="billing@security-notice.net"
                  value={emailSender}
                  onChange={(e) => setEmailSender(e.target.value)}
                  className="w-full rounded border border-slate-700 bg-slate-950 py-2 px-3 text-xs text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Email Subject Line
                </label>
                <input
                  type="text"
                  placeholder="Immediate Action Required: Account Compromise"
                  value={emailSubject}
                  onChange={(e) => setEmailSubject(e.target.value)}
                  className="w-full rounded border border-slate-700 bg-slate-950 py-2 px-3 text-xs text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Contained Links <span className="text-slate-500 font-normal">(Optional)</span>
              </label>
              <input
                type="text"
                placeholder="https://login.verify-now.co/session"
                value={emailUrl}
                onChange={(e) => setEmailUrl(e.target.value)}
                className="w-full rounded border border-slate-700 bg-slate-950 py-2 px-3 text-xs text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Email Body Text <span className="text-rose-400">*</span>
              </label>
              <textarea
                rows={5}
                required
                placeholder="Paste the full email text here..."
                value={emailBody}
                onChange={(e) => setEmailBody(e.target.value)}
                className="w-full rounded border border-slate-700 bg-slate-950 py-2 px-3 text-xs text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none resize-none"
              />
            </div>
          </div>
        )}

        {/* 3. URL MODE */}
        {activeType === 'url' && (
          <div className="space-y-3">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Target URL or Web Address <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                required
                placeholder="https://suspicious-domain.com/login?auth=xyz"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                className="w-full rounded border border-slate-700 bg-slate-950 py-2.5 px-3 text-xs font-mono text-cyan-300 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div className="rounded border border-slate-800 bg-slate-950 p-3 text-xs space-y-1.5 text-slate-400">
              <div className="font-semibold text-slate-200">Advisory Isolation Protocol:</div>
              <p className="text-[11px]">
                ScamGuard examines the submitted URL structure and visible parameters without visiting, resolving, or executing content from it. No live domain-reputation lookup is performed.
              </p>
            </div>
          </div>
        )}

        {/* 4. SCREENSHOT MODE */}
        {activeType === 'screenshot' && (
          <div className="space-y-3">
            <input
              type="file"
              ref={fileInputRef}
              accept="image/png,image/jpeg,image/jpg,image/webp"
              className="hidden"
              onChange={handleScreenshotChange}
            />

            {!screenshotData ? (
              <div
                onClick={() => fileInputRef.current?.click()}
                className="flex flex-col items-center justify-center border-2 border-dashed border-slate-700 hover:border-cyan-500/60 rounded-lg p-8 bg-slate-950/60 cursor-pointer transition-colors text-center"
              >
                <div className="h-10 w-10 rounded-full bg-slate-800 flex items-center justify-center text-cyan-400 mb-3">
                  <Upload className="h-5 w-5" />
                </div>
                <div className="text-xs font-medium text-slate-200">
                  Click to upload screenshot or visual evidence
                </div>
                <div className="text-[11px] text-slate-500 mt-1">
                  Supports PNG, JPG, or WEBP up to 10MB
                </div>
              </div>
            ) : (
              <div className="space-y-3">
                <div className="relative rounded border border-slate-800 bg-slate-950 p-2 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <img
                      src={screenshotData}
                      alt="Uploaded screenshot"
                      className="h-16 w-24 object-cover rounded border border-slate-700"
                    />
                    <div>
                      <span className="text-xs font-medium text-slate-200 block">Screenshot ready for AI analysis</span>
                      <span className="text-[10px] text-slate-400 font-mono">Format: {screenshotMime}</span>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => { setScreenshotData(null); }}
                    className="px-2.5 py-1 text-xs text-rose-400 hover:text-rose-300 hover:bg-rose-950/30 rounded border border-rose-900/40 transition-colors cursor-pointer"
                  >
                    Change Image
                  </button>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Context or Where You Saw This <span className="text-slate-500 font-normal">(Optional)</span>
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. Popup appeared while browsing news site, or received on Instagram"
                    value={screenshotNotes}
                    onChange={(e) => setScreenshotNotes(e.target.value)}
                    className="w-full rounded border border-slate-700 bg-slate-950 py-2 px-3 text-xs text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
                  />
                </div>
              </div>
            )}
          </div>
        )}

        {/* 5. QR CODE MODE */}
        {activeType === 'qr' && (
          <div className="space-y-4">
            <input
              type="file"
              ref={qrInputRef}
              accept="image/*"
              className="hidden"
              onChange={handleQrImageChange}
            />

            <div className="flex flex-col sm:flex-row gap-3">
              <button
                type="button"
                onClick={() => qrInputRef.current?.click()}
                disabled={qrDecoding}
                className="w-full flex items-center justify-center gap-2 border border-slate-700 hover:border-cyan-500/50 bg-slate-950 hover:bg-slate-900 py-3 px-4 rounded text-xs font-medium text-slate-200 transition-colors cursor-pointer"
              >
                <Upload className="h-4 w-4 text-cyan-400" />
                <span>{qrDecoding ? 'Decoding QR...' : 'Upload Image with QR Code'}</span>
              </button>
            </div>

            {/* Display decoded content BEFORE opening it */}
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Decoded Content / URL <span className="text-rose-400">*</span>
              </label>
              <div className="relative">
                <textarea
                  rows={2}
                  required
                  placeholder="Upload a QR image above, or paste decoded content directly here..."
                  value={qrDecoded || ''}
                  onChange={(e) => setQrDecoded(e.target.value)}
                  className="w-full rounded border border-slate-700 bg-slate-950 py-2 px-3 pr-20 text-xs font-mono text-cyan-300 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none resize-none"
                />
                {qrDecoded && (
                  <button
                    type="button"
                    onClick={handleCopyQr}
                    className="absolute right-2 top-2 px-2 py-1 text-[11px] bg-slate-800 hover:bg-slate-700 text-slate-300 rounded flex items-center gap-1 transition-colors"
                  >
                    {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                )}
              </div>
            </div>

            {/* Security Notice for QR */}
            <div className="rounded border border-amber-500/30 bg-amber-950/20 p-3 text-xs text-amber-300/90 flex items-start gap-2.5">
              <ShieldAlert className="h-4 w-4 shrink-0 text-amber-400 mt-0.5" />
              <div>
                <span className="font-semibold block text-amber-200">Security Rule Active:</span>
                The decoded payload is analyzed as untrusted text. ScamGuard never opens a QR destination automatically.
              </div>
            </div>
          </div>
        )}

        {/* Submit Button */}
        <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3 border-t border-slate-800">
          <div className="text-[11px] text-slate-500 font-mono">
            Deterministic evidence scoring · Gemini assistance when configured
          </div>

          <button
            type="submit"
            disabled={analyzing}
            className="w-full sm:w-auto px-6 py-2.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-100 text-xs font-semibold flex items-center justify-center gap-2 transition-colors shadow-md disabled:opacity-50 cursor-pointer"
          >
            {analyzing ? (
              <>
                <RefreshCw className="h-4 w-4 animate-spin text-cyan-200" />
                <span>Running Threat Intelligence...</span>
              </>
            ) : (
              <>
                <span>Inspect Content</span>
                <ArrowRight className="h-4 w-4" />
              </>
            )}
          </button>
        </div>
      </form>

      {/* Loading HUD overlay indicator when scanning */}
      {analyzing && (
        <div className="rounded-lg border border-cyan-500/30 bg-slate-900/90 p-6 shadow-2xl text-center space-y-3">
          <div className="inline-flex h-12 w-12 items-center justify-center rounded-full bg-cyan-500/10 border border-cyan-500/40 text-cyan-400 animate-pulse">
            <Sparkles className="h-6 w-6" />
          </div>
          <div className="space-y-1">
            <h3 className="text-sm font-semibold text-slate-100">
              ScamGuard inspection in progress
            </h3>
            <p className="text-xs text-slate-400">
              Checking submitted text, URLs, and security signals without opening destinations...
            </p>
          </div>
          <div className="w-full max-w-xs mx-auto h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div className="h-full bg-gradient-to-r from-cyan-500 to-emerald-400 animate-pulse w-3/4 rounded-full" />
          </div>
        </div>
      )}
    </div>
  );
};
