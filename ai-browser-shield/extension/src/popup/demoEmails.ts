/**
 * Demo phishing emails for testing the extension
 * Locked hackathon scenarios for deterministic demo flow.
 */

export const DEMO_EMAILS = [
  {
    title: 'Obvious Phishing',
    expected: 'Phishing Likely (high score)',
    content: `From: security-alert@amaz0n-verify.xyz
Subject: URGENT: Amazon Account Suspended in 2 Hours

Dear Customer,

Your account access is blocked due to suspicious activity.

Click here immediately to restore access:
http://amaz0n-secure-check.xyz/login

Required verification:
- Login email and password
- Card details
- OTP confirmation

Failure to verify in 2 hours will lead to permanent suspension.`,
  },
  {
    title: 'Clean Phishing (Brand Spoof)',
    expected: 'Suspicious Email (mid/high score)',
    content: `From: Internshala Careers <placements@internshaIa-support.com>
Subject: Internship Selection Confirmed - Action Needed

Hi Candidate,

Congratulations, you are shortlisted for a paid internship.

To confirm your slot, complete verification below:
- Review details: https://internshaIa-support.com/offer
- Complete quick form today

This offer expires tonight.

Regards,
Hiring Team`,
  },
  {
    title: 'Legitimate Email',
    expected: 'Safe Email (low score)',
    content: `From: noreply@internshala.com
Subject: Your internship application was viewed

Hi,

An employer has viewed your internship application on Internshala.
You can track updates directly in your dashboard.

No payment or verification is required.

Regards,
Internshala Team`,
  },
];

export const DEMO_EMAIL_TITLES = DEMO_EMAILS.map(e => e.title);
