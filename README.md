# Let's Chat - Secure TextBee Authentication Backend

This Node.js/Express service provides server-side OTP generation, cryptographic hashing, rate limiting, and real SMS delivery via the official **TextBee SMS Gateway API**.

---

## 1. Security Architecture

- **Zero Client Leakage**: The `TEXTBEE_API_KEY` and device identifiers reside exclusively on this backend server. They are never compiled into the Android APK, Java/Kotlin bytecode, resources, or client storage.
- **Server-Side OTP Lifecycle**:
  - The OTP is generated on the server using `crypto.randomInt()`.
  - Only a salted SHA-256 HMAC hash is retained in memory. Plaintext OTPs are never stored in databases or logs.
  - Expiry is enforced at 5 minutes (300 seconds).
  - Maximum 5 verification attempts before automatic invalidation.
  - Per-phone resend cooldown enforced at 60 seconds.
- **Authenticity Assurance**: The Android client never trusts client-side verification flags; authentication tokens are signed with JWT on the backend upon valid verification.

---

## 2. API Endpoints

### `POST /api/auth/send-otp`
Sends an OTP via SMS to the specified international phone number.
- **Request Body**:
  ```json
  {
    "phoneNumber": "+919876543210"
  }
  ```
- **Response (`200 OK`)**:
  ```json
  {
    "success": true,
    "message": "Verification code sent successfully via SMS.",
    "expiresInSeconds": 300,
    "cooldownSeconds": 60
  }
  ```

### `POST /api/auth/verify-otp`
Verifies an entered 6-digit OTP against the server hash.
- **Request Body**:
  ```json
  {
    "phoneNumber": "+919876543210",
    "otp": "582910"
  }
  ```
- **Response (`200 OK`)**:
  ```json
  {
    "success": true,
    "authToken": "<SIGNED_JWT_SESSION_TOKEN>",
    "isNewUser": true,
    "userProfile": null,
    "message": "OTP verified successfully."
  }
  ```

### `GET /api/health`
Health and readiness check to test connectivity from the Android app.
- **Response (`200 OK`)**:
  ```json
  {
    "status": "ONLINE",
    "service": "Let's Chat TextBee Auth Gateway",
    "smsGateway": "TextBee",
    "gatewayConfigured": true,
    "timestamp": 1730700000000
  }
  ```

---

## 3. Obtaining Your TextBee API Key

1. Log in to your dashboard at [https://textbee.dev](https://textbee.dev).
2. Ensure you have installed the TextBee Gateway app on your SMS dispatch Android phone and linked it to your account.
3. In the TextBee dashboard, navigate to **Account Settings -> API Keys**.
4. Generate and copy your `TEXTBEE_API_KEY`.
5. (Optional) Note your `deviceId` if you have multiple phones connected and wish to route SMS specifically through one.

---

## 4. Deploying to Obtain a Public HTTPS URL

### Option A: Deploy on Render (Recommended, Free & Fast)
1. Push this `backend-server` directory (or your repository) to GitHub.
2. In [Render.com](https://render.com), click **New + -> Web Service**.
3. Connect your repository, set the **Root Directory** to `backend-server`.
4. Set:
   - **Build Command**: `npm install`
   - **Start Command**: `node server.js`
5. In **Environment Variables**, add:
   - `TEXTBEE_API_KEY` = `<your_real_textbee_api_key>`
   - `TEXTBEE_DEVICE_ID` = `<optional_device_id>`
   - `JWT_SECRET` = `<a_random_32_char_secret_string>`
6. Click **Create Web Service**. Once deployed, Render provides your secure HTTPS URL:
   `https://letschat-auth-xxxx.onrender.com`

### Option B: Deploy on Railway
1. Go to [Railway.app](https://railway.app), create a **New Project -> Deploy from GitHub repo**.
2. Set Root Directory to `backend-server`.
3. Under **Variables**, add `TEXTBEE_API_KEY` and `JWT_SECRET`.
4. Generate a public domain under **Networking**.

### Option C: Local Testing with Android Emulator
For local testing on the Android Emulator before deploying to cloud:
1. `cd backend-server && npm install`
2. Create `.env` file with `TEXTBEE_API_KEY=<your_key>`
3. Run `npm start` (starts on `http://localhost:3000`).
4. In the Android Emulator, use `http://10.0.2.2:3000` (which loops back to the host machine).

---

## 5. Entering the Backend URL into the Let's Chat Android App

1. Launch **Let's Chat** on your Android device or emulator.
2. On the **Mobile Number Login** screen:
   - Tap the **Server Settings (DNS icon)** button in the top-right corner, OR
   - Tap the **TextBee SMS Delivery** banner card at the bottom of the screen.
3. In the **TextBee Backend** configuration dialog:
   - Enter your deployed HTTPS URL (e.g. `https://letschat-auth-xxxx.onrender.com`), or tap the **Emulator (10.0.2.2)** preset button if testing locally.
   - Tap **Test Connection** — the app will ping `/api/health` and show a green **"Server Online & Healthy"** badge.
   - Tap **Save & Apply**.
4. You are now connected! Enter your real phone number and tap **Continue** to receive a real SMS OTP dispatched via TextBee.
