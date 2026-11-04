/**
 * Let's Chat - Secure TextBee Authentication Backend
 * Connect Freely. Chat Privately.
 * 
 * Implements:
 * - POST /api/auth/send-otp
 * - POST /api/auth/verify-otp
 * - GET  /api/health
 * 
 * Official TextBee API Integration:
 * - Endpoint: POST https://api.textbee.dev/api/v1/gateway/send-sms
 * - Headers: x-api-key: <TEXTBEE_API_KEY>, Content-Type: application/json
 * - Body: { "recipients": ["+<E.164>"], "message": "...", "deviceId": "<OPTIONAL_DEVICE_ID>" }
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
// Enable trust proxy for Render, Railway, and Cloud reverse proxies
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_letschat_2026';
const TEXTBEE_API_KEY = process.env.TEXTBEE_API_KEY;
const TEXTBEE_DEVICE_ID = process.env.TEXTBEE_DEVICE_ID; // Optional: specific device ID
const OTP_EXPIRY_MS = (parseInt(process.env.OTP_EXPIRY_SECONDS, 10) || 300) * 1000; // 5 minutes default
const RESEND_COOLDOWN_MS = (parseInt(process.env.RESEND_COOLDOWN_SECONDS, 10) || 60) * 1000; // 60 seconds default
const MAX_VERIFY_ATTEMPTS = parseInt(process.env.MAX_ATTEMPTS, 10) || 5;

app.use(cors());
app.use(express.json());

// Global Rate Limiter: max 100 requests per 15 minutes per IP
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests from this IP. Please try again later.' }
});
app.use(globalLimiter);

// Specific stricter limiter for sending OTP: max 10 requests per 10 minutes per IP
const otpSendLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many OTP requests from this network. Please wait 10 minutes before trying again.' }
});

// Secure in-memory OTP store: Map<formattedPhoneNumber, OtpRecord>
// Note: In production scale, use Redis (e.g., redis-client) with TTL for multi-instance deployment.
const otpStore = new Map();

// Registered user database simulation (in-memory for auth session check)
const registeredUsers = new Map();

/**
 * Normalizes phone number to strict E.164 international format (+1234567890)
 */
function normalizeToE164(phone, countryCode) {
  let cleaned = (phone || '').toString().trim().replace(/[\s\-()]/g, '');
  if (!cleaned.startsWith('+')) {
    const code = (countryCode || '+91').toString().trim().replace(/[\s\-()]/g, '');
    const cleanCode = code.startsWith('+') ? code : `+${code}`;
    cleaned = `${cleanCode}${cleaned}`;
  }
  return cleaned;
}

/**
 * Validates E.164 format: begins with '+', followed by 8 to 15 digits
 */
function isValidE164(phone) {
  return /^\+[1-9]\d{7,14}$/.test(phone);
}

/**
 * Cryptographic HMAC SHA-256 hash of OTP with per-session salt
 */
function hashOtp(otp, salt) {
  return crypto.createHmac('sha256', salt).update(otp).digest('hex');
}

/**
 * Dispatches real SMS using the official TextBee API
 * Official Docs: POST https://api.textbee.dev/api/v1/gateway/send-sms
 * Header: x-api-key: YOUR_API_KEY
 */
async function sendTextBeeSms(recipientPhone, message) {
  if (!TEXTBEE_API_KEY || TEXTBEE_API_KEY.trim() === '' || TEXTBEE_API_KEY.includes('your_textbee_api_key')) {
    throw new Error('TextBee API key is not configured on the backend server. Set TEXTBEE_API_KEY in backend environment.');
  }

  const endpoint = 'https://api.textbee.dev/api/v1/gateway/send-sms';
  
  const payload = {
    recipients: [recipientPhone],
    message: message
  };

  // If a specific device ID is configured, add it to payload
  if (TEXTBEE_DEVICE_ID && TEXTBEE_DEVICE_ID.trim() !== '' && !TEXTBEE_DEVICE_ID.includes('your_textbee_device_id')) {
    payload.deviceId = TEXTBEE_DEVICE_ID.trim();
  }

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'x-api-key': TEXTBEE_API_KEY.trim(),
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });

  const responseBody = await response.json().catch(() => ({}));

  if (!response.ok) {
    const errorDetail = responseBody.message || responseBody.error || `HTTP ${response.status}`;
    throw new Error(`TextBee Gateway returned error: ${errorDetail}`);
  }

  return responseBody;
}

/**
 * GET /api/health
 * Public health check and TextBee gateway readiness verification
 */
app.get(['/api/health', '/api/v1/health'], (req, res) => {
  const isKeyConfigured = Boolean(
    TEXTBEE_API_KEY && 
    TEXTBEE_API_KEY.trim() !== '' && 
    !TEXTBEE_API_KEY.includes('your_textbee_api_key')
  );

  res.json({
    status: 'ONLINE',
    service: "Let's Chat TextBee Auth Gateway",
    smsGateway: 'TextBee',
    gatewayConfigured: isKeyConfigured,
    deviceSpecified: Boolean(TEXTBEE_DEVICE_ID && !TEXTBEE_DEVICE_ID.includes('your_textbee_device_id')),
    timestamp: Date.now()
  });
});

/**
 * POST /api/auth/send-otp
 * Generates secure OTP, hashes it, and sends real SMS via TextBee
 */
app.post(['/api/auth/send-otp', '/api/v1/auth/request-otp'], otpSendLimiter, async (req, res) => {
  try {
    const { phoneNumber, countryCode } = req.body;

    if (!phoneNumber) {
      return res.status(400).json({
        success: false,
        message: 'Phone number is required in international E.164 format (e.g. +919876543210).'
      });
    }

    const formattedPhone = normalizeToE164(phoneNumber, countryCode);

    if (!isValidE164(formattedPhone)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid phone number format. Please provide a valid international number (e.g. +919876543210).'
      });
    }

    // Check resend cooldown
    const existingRecord = otpStore.get(formattedPhone);
    if (existingRecord) {
      const elapsedMs = Date.now() - existingRecord.createdAt;
      if (elapsedMs < RESEND_COOLDOWN_MS) {
        const remainingSeconds = Math.ceil((RESEND_COOLDOWN_MS - elapsedMs) / 1000);
        return res.status(429).json({
          success: false,
          message: `Please wait ${remainingSeconds} seconds before requesting another code.`,
          retryAfterSeconds: remainingSeconds,
          cooldownSeconds: remainingSeconds
        });
      }
    }

    // Generate cryptographically secure six-digit OTP
    const rawOtp = crypto.randomInt(100000, 1000000).toString();
    const salt = crypto.randomBytes(16).toString('hex');
    const hashedOtp = hashOtp(rawOtp, salt);

    // Prepare SMS message
    const smsMessage = `Your Let's Chat verification code is: ${rawOtp}. Valid for 5 minutes. Never share this code with anyone.`;

    // Dispatch SMS through real TextBee Gateway
    try {
      await sendTextBeeSms(formattedPhone, smsMessage);
    } catch (textBeeError) {
      // Do not store OTP if SMS dispatch failed
      console.error('[TextBee Gateway Dispatch Failed]:', textBeeError.message);
      return res.status(502).json({
        success: false,
        message: `Failed to dispatch SMS: ${textBeeError.message}`
      });
    }

    // Store ONLY the secure hash and metadata (Never store plaintext OTP)
    otpStore.set(formattedPhone, {
      hashedOtp,
      salt,
      attempts: 0,
      createdAt: Date.now(),
      expiresAt: Date.now() + OTP_EXPIRY_MS
    });

    return res.status(200).json({
      success: true,
      message: 'Verification code sent successfully via SMS.',
      expiresInSeconds: Math.floor(OTP_EXPIRY_MS / 1000),
      cooldownSeconds: Math.floor(RESEND_COOLDOWN_MS / 1000)
    });

  } catch (err) {
    console.error('[Send OTP Internal Error]:', err);
    return res.status(500).json({
      success: false,
      message: 'Internal server error while dispatching verification SMS.'
    });
  }
});

/**
 * POST /api/auth/verify-otp
 * Validates entered OTP against secure hash, verifies expiration and attempts, issues JWT token
 */
app.post(['/api/auth/verify-otp', '/api/v1/auth/verify-otp'], async (req, res) => {
  try {
    const { phoneNumber, countryCode, otp } = req.body;

    if (!phoneNumber || !otp) {
      return res.status(400).json({
        success: false,
        message: 'Phone number and 6-digit verification code are required.',
        errorType: 'MISSING_FIELDS'
      });
    }

    const formattedPhone = normalizeToE164(phoneNumber, countryCode);
    const cleanOtp = (otp || '').toString().trim();

    if (!/^\d{6}$/.test(cleanOtp)) {
      return res.status(400).json({
        success: false,
        message: 'Please enter a valid 6-digit numeric verification code.',
        errorType: 'INVALID_FORMAT'
      });
    }

    const record = otpStore.get(formattedPhone);

    // If no active session found
    if (!record) {
      return res.status(400).json({
        success: false,
        message: 'No active OTP request found for this phone number, or the code was already used. Please request a new code.',
        errorType: 'INVALID_OTP'
      });
    }

    // Check expiration
    if (Date.now() > record.expiresAt) {
      otpStore.delete(formattedPhone);
      return res.status(410).json({
        success: false,
        message: 'Verification code has expired. Please request a new code.',
        errorType: 'EXPIRED'
      });
    }

    // Check attempt limits
    if (record.attempts >= MAX_VERIFY_ATTEMPTS) {
      otpStore.delete(formattedPhone);
      return res.status(429).json({
        success: false,
        message: 'Maximum verification attempts exceeded. Please request a new code.',
        errorType: 'RATE_LIMITED'
      });
    }

    record.attempts += 1;

    // Verify OTP using timing-safe comparison on hashed values
    const candidateHash = hashOtp(cleanOtp, record.salt);
    const isMatch = crypto.timingSafeEqual(
      Buffer.from(candidateHash, 'hex'),
      Buffer.from(record.hashedOtp, 'hex')
    );

    if (!isMatch) {
      const remaining = MAX_VERIFY_ATTEMPTS - record.attempts;
      return res.status(400).json({
        success: false,
        message: `Incorrect verification code. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`,
        errorType: 'INVALID_OTP'
      });
    }

    // Success! Immediately consume OTP so it cannot be used again
    otpStore.delete(formattedPhone);

    // Check if user has an existing completed profile
    const existingUser = registeredUsers.get(formattedPhone);
    const isNewUser = !existingUser;

    // Sign secure JWT session token
    const authToken = jwt.sign(
      {
        sub: formattedPhone,
        phone: formattedPhone,
        purpose: 'letschat_auth'
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    return res.status(200).json({
      success: true,
      authToken,
      isNewUser,
      userProfile: existingUser || null,
      message: 'OTP verified successfully.'
    });

  } catch (err) {
    console.error('[Verify OTP Internal Error]:', err);
    return res.status(500).json({
      success: false,
      message: 'Internal server error during verification.'
    });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`===============================================`);
  console.log(` Let's Chat Secure TextBee Backend Service`);
  console.log(` Listening on 0.0.0.0:${PORT}`);
  console.log(` Status: /api/health`);
  console.log(` TextBee API Key: ${TEXTBEE_API_KEY ? 'CONFIGURED' : 'NOT CONFIGURED (Add to .env)'}`);
  console.log(`===============================================`);
});
