const unique = <T extends string>(items: T[]): T[] => Array.from(new Set(items));

export const TRUSTED_DOMAIN_WHITELIST = [
  'google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
  'linkedin.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
  'wikipedia.org', 'reddit.com', 'stackoverflow.com', 'cloudflare.com', 'stripe.com',
  'paypal.com', 'dropbox.com', 'slack.com', 'zoom.us', 'figma.com', 'notion.so',
  'vercel.app', 'netlify.app', 'heroku.com', 'aws.amazon.com', 'azure.microsoft.com',
  'cloud.google.com', 'nasa.gov', 'nih.gov', 'cdc.gov', 'who.int', 'un.org', 'europa.eu'
] as const;

export const GOV_EDU_SUFFIXES = ['.gov', '.edu', '.ac.uk', '.edu.in'] as const;

const searchBrands = [
  'google', 'bing', 'yahoo', 'duckduckgo', 'baidu', 'yandex', 'ask', 'aolsearch', 'naver', 'ecosia',
  'seznam', 'startpage', 'brave', 'qwant', 'sogou', 'dogpile', 'gigablast', 'mojeek', 'lycos', 'metacrawler'
];

const socialBrands = [
  'facebook', 'instagram', 'twitter', 'x', 'tiktok', 'snapchat', 'pinterest', 'reddit', 'tumblr', 'linkedin',
  'discord', 'telegram', 'whatsapp', 'wechat', 'line', 'viber', 'signal', 'threads', 'mastodon', 'quora',
  'weibo', 'vk', 'odnoklassniki', 'meetup', 'clubhouse', 'nextdoor', 'flickr', 'behance', 'dribbble', 'medium',
  'deviantart', 'patreon', 'substack', 'messenger', 'skype', 'kik', 'imo', 'groupme', 'houseparty', 'hike'
];

const techBrands = [
  'microsoft', 'apple', 'amazon', 'google', 'meta', 'netflix', 'adobe', 'oracle', 'ibm', 'salesforce',
  'sap', 'vmware', 'cisco', 'intel', 'amd', 'nvidia', 'qualcomm', 'samsung', 'huawei', 'xiaomi',
  'sony', 'lg', 'dell', 'hp', 'lenovo', 'asus', 'acer', 'razer', 'logitech', 'motorola',
  'oneplus', 'oppo', 'vivo', 'realme', 'blackberry', 'nokia', 'htc', 'toshiba', 'panasonic', 'sharp',
  'philips', 'bose', 'jbl', 'sennheiser', 'anker', 'belkin', 'canon', 'nikon', 'epson', 'brother',
  'xerox', 'siemens', 'bosch', 'arm', 'broadcom', 'mediatek', 'micron', 'seagate', 'western-digital', 'sandisk'
];

const cloudBrands = [
  'aws', 'azure', 'googlecloud', 'digitalocean', 'heroku', 'vercel', 'netlify', 'cloudflare', 'fastly', 'akamai',
  'linode', 'vultr', 'hetzner', 'ovh', 'render', 'flyio', 'railway', 'supabase', 'firebase', 'appwrite',
  'planetscale', 'neon', 'mongodb-atlas', 'upstash', 'cloudfront', 'cloudrun', 'lambda', 'gcp', 'openstack', 'rackspace'
];

const financeBrands = [
  'paypal', 'stripe', 'visa', 'mastercard', 'amex', 'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
  'barclays', 'santander', 'ubs', 'deutschebank', 'jpmorgan', 'goldman', 'schwab', 'robinhood', 'coinbase', 'binance',
  'kraken', 'bitfinex', 'opensea', 'metamask', 'uniswap', 'aave', 'compound', 'discover', 'capitalone', 'americanexpress',
  'wise', 'revolut', 'payoneer', 'skrill', 'square', 'cashapp', 'venmo', 'zelle', 'monzo', 'n26',
  'alipay', 'wechatpay', 'paytm', 'phonepe', 'gpay', 'worldpay', 'adyen', 'klarna', 'affirm', 'sofi',
  'fidelity', 'vanguard', 'morganstanley', 'tdameritrade', 'etoro', 'okx', 'kucoin', 'bybit', 'crypto-com', 'gemini'
];

const developerBrands = [
  'github', 'gitlab', 'bitbucket', 'stackoverflow', 'npmjs', 'pypi', 'dockerhub', 'kubernetes', 'terraform', 'ansible',
  'jenkins', 'jira', 'confluence', 'notion', 'figma', 'slack', 'zoom', 'teams', 'webex', 'whereby',
  'miro', 'linear', 'asana', 'trello', 'monday', 'postman', 'insomnia', 'sentry', 'datadog', 'newrelic',
  'grafana', 'prometheus', 'vercel', 'netlify', 'heroku', 'render', 'circleci', 'travisci', 'githubactions', 'gitkraken',
  'jetbrains', 'vscode', 'intellij', 'pycharm', 'webstorm', 'rubymine', 'phpstorm', 'kotlin', 'nodejs', 'typescript',
  'python', 'golang', 'rustlang', 'java', 'spring', 'laravel', 'django', 'flask', 'react', 'nextjs'
];

const shoppingBrands = [
  'amazon', 'ebay', 'etsy', 'shopify', 'walmart', 'target', 'bestbuy', 'aliexpress', 'alibaba', 'jd',
  'rakuten', 'flipkart', 'meesho', 'myntra', 'ajio', 'nykaa', 'costco', 'ikea', 'wayfair', 'newegg',
  'overstock', 'mercari', 'poshmark', 'shein', 'temu', 'noon', 'zalando', 'asos', 'nordstrom', 'macys',
  'homedepot', 'lowes', 'sephora', 'ulta', 'decathlon', 'carrefour', 'tesco', 'woolworths', 'kroger', 'instacart'
];

const streamingBrands = [
  'netflix', 'youtube', 'spotify', 'twitch', 'hulu', 'disney', 'hbomax', 'paramount', 'peacock', 'appletv',
  'primevideo', 'vimeo', 'soundcloud', 'deezer', 'tidal', 'applemusic', 'pandora', 'gaana', 'jiosaavn', 'wynk',
  'hotstar', 'sonyliv', 'zee5', 'crunchyroll', 'funimation', 'plex', 'roku', 'audible', 'kindle', 'podbean'
];

const travelBrands = [
  'airbnb', 'booking', 'expedia', 'kayak', 'tripadvisor', 'hotels', 'agoda', 'makemytrip', 'goibibo', 'cleartrip',
  'indigo', 'airasia', 'emirates', 'british', 'lufthansa', 'delta', 'united', 'americanairlines', 'southwest', 'ryanair',
  'easyjet', 'qatarairways', 'etihad', 'turkishairlines', 'singaporeairlines', 'airfrance', 'klm', 'marriott', 'hilton', 'hyatt'
];

const newsBrands = [
  'bbc', 'cnn', 'nytimes', 'theguardian', 'reuters', 'apnews', 'washingtonpost', 'wsj', 'bloomberg', 'forbes',
  'techcrunch', 'wired', 'theverge', 'engadget', 'arstechnica', 'hackernews', 'cnbc', 'foxnews', 'nbcnews', 'abcnews',
  'economist', 'financialtimes', 'axios', 'politico', 'npr', 'aljazeera', 'time', 'usatoday', 'guardian', 'newsweek'
];

const govHealthBrands = [
  'who', 'cdc', 'nih', 'nasa', 'fda', 'un', 'europa', 'gov', 'nhs', 'icrc',
  'redcross', 'who.int', 'cdc.gov', 'nih.gov', 'fda.gov', 'nasa.gov', 'un.org', 'europa.eu', 'gov.uk', 'healthcare',
  'medicare', 'medicaid', 'mayoclinic', 'webmd', 'clevelandclinic', 'hopkinsmedicine', 'redcrescent', 'unodc', 'interpol', 'fema'
];

const emailBrands = [
  'gmail', 'outlook', 'yahoo', 'protonmail', 'icloud', 'zoho', 'fastmail', 'tutanota', 'hotmail', 'live',
  'aol', 'mail', 'gmx', 'yandexmail', 'inbox', 'hey', 'mailchimp', 'sendgrid', 'postmark', 'mailgun'
];

const educationBrands = [
  'coursera', 'udemy', 'edx', 'khanacademy', 'duolingo', 'byju', 'unacademy', 'chegg', 'udacity', 'skillshare',
  'pluralsight', 'datacamp', 'codecademy', 'brilliant', 'futurelearn', 'simplilearn', 'greatlearning', 'upgrad', 'alison', 'masterclass'
];

const productivityBrands = [
  'googledrive', 'googledocs', 'googlesheets', 'googlemeet', 'googleworkspace', 'microsoftoffice', 'word', 'excel', 'powerpoint', 'onedrive',
  'dropbox', 'box', 'icloud', 'evernote', 'todoist', 'airtable', 'coda', 'basecamp', 'clickup', 'workday',
  'servicenow', 'sharepoint', 'onedrivebusiness', 'googleslides', 'onenote', 'teams', 'notion', 'figma', 'slack', 'zoom'
];

const typoTargets = [
  'goggle', 'gogle', 'facebok', 'amazom', 'netflx', 'paypa', 'micosoft', 'appl', 'gitub', 'linkedn',
  'instagarm', 'youube', 'twiter', 'whatsap', 'discrod', 'telegarm', 'snapchat', 'pinterst'
];

const miscBrands = [
  'uber', 'lyft', 'tesla', 'openai', 'anthropic', 'huggingface', 'canva', 'docusign', 'atlassian', 'intuit',
  'quickbooks', 'xero', 'steam', 'epicgames', 'riotgames', 'playstation', 'xbox', 'nintendo', 'ea', 'ubisoft',
  'fedex', 'dhl', 'ups', 'usps', 'shop', 'medium', 'substack', 'patreon', 'canva', 'adp',
  'okta', 'auth0', 'lastpass', '1password', 'dashlane', 'bitwarden', 'coinmarketcap', 'coingecko', 'glassdoor', 'indeed'
];

const globalBrandFamilies = [
  'google-drive', 'google-docs', 'google-sheets', 'google-cloud', 'google-meet', 'google-play', 'google-ads', 'google-pay', 'google-photos', 'google-calendar',
  'microsoft-office', 'microsoft-365', 'microsoft-teams', 'microsoft-azure', 'microsoft-onedrive', 'microsoft-defender', 'microsoft-authenticator', 'microsoft-store', 'microsoft-support', 'microsoft-security',
  'amazon-prime', 'amazon-pay', 'amazon-web-services', 'amazon-music', 'amazon-video', 'amazon-shopping', 'amazon-delivery', 'amazon-seller', 'amazon-support', 'amazon-photos',
  'apple-id', 'apple-pay', 'apple-music', 'apple-tv', 'apple-store', 'apple-support', 'apple-cloud', 'apple-wallet', 'applecare', 'applefitness',
  'paypal-business', 'paypal-support', 'paypal-invoice', 'paypal-security', 'paypal-wallet', 'paypal-checkout', 'paypal-credit', 'paypal-prepaid', 'paypal-merchant', 'paypal-resolution',
  'github-actions', 'github-enterprise', 'github-support', 'github-pages', 'github-packages', 'github-copilot', 'github-security', 'github-login', 'github-account', 'github-workflows',
  'linkedin-learning', 'linkedin-jobs', 'linkedin-premium', 'linkedin-sales', 'linkedin-support', 'linkedin-security', 'linkedin-ads', 'linkedin-auth', 'linkedin-signin', 'linkedin-campaign',
  'instagram-business', 'instagram-creator', 'instagram-login', 'instagram-help', 'instagram-security', 'instagram-ads', 'instagram-account', 'instagram-meta', 'instagram-store', 'instagram-reels',
  'netflix-account', 'netflix-billing', 'netflix-support', 'netflix-security', 'netflix-streaming', 'netflix-premium', 'netflix-family', 'netflix-help', 'netflix-login', 'netflix-update',
  'facebook-business', 'facebook-meta', 'facebook-login', 'facebook-marketplace', 'facebook-security', 'facebook-support', 'facebook-ads', 'facebook-account', 'facebook-messenger', 'facebook-pay',
  'coinbase-wallet', 'coinbase-commerce', 'coinbase-support', 'coinbase-security', 'coinbase-pro', 'coinbase-exchange', 'coinbase-login', 'coinbase-account', 'coinbase-card', 'coinbase-earn',
  'binance-pay', 'binance-us', 'binance-support', 'binance-security', 'binance-wallet', 'binance-earn', 'binance-login', 'binance-account', 'binance-chain', 'binance-launchpad',
  'metamask-wallet', 'metamask-login', 'metamask-support', 'metamask-security', 'metamask-extension', 'metamask-swap', 'metamask-portfolio', 'metamask-seed', 'metamask-recovery', 'metamask-account'
];

export const TRUSTED_BRANDS = unique([
  ...searchBrands,
  ...socialBrands,
  ...techBrands,
  ...cloudBrands,
  ...financeBrands,
  ...developerBrands,
  ...shoppingBrands,
  ...streamingBrands,
  ...travelBrands,
  ...newsBrands,
  ...govHealthBrands,
  ...emailBrands,
  ...educationBrands,
  ...productivityBrands,
  ...typoTargets,
  ...miscBrands,
  ...globalBrandFamilies,
  'adyen', 'airtable', 'algolia', 'alibaba-cloud', 'aliexpress', 'alphabet', 'americanairlines', 'android', 'angular', 'apollo',
  'asana', 'audible', 'autodesk', 'backblaze', 'bitdefender', 'booking-holdings', 'brex', 'calendly', 'capcut', 'carvana',
  'checkout', 'clickup', 'cointracker', 'courier', 'crowdstrike', 'databricks', 'deliveroo', 'discord-nitro', 'docuware', 'doordash',
  'elastic', 'evernote', 'expensify', 'fastlycdn', 'fiverr', 'freshbooks', 'frontapp', 'getresponse', 'godaddy', 'gong',
  'grubhub', 'hubspot', 'ifttt', 'indeed', 'intercom', 'jamf', 'jetblue', 'kahoot', 'kaspersky', 'lastpass',
  'loom', 'mailerlite', 'mailchimp', 'mailjet', 'manjaro', 'marriott-bonvoy', 'miro-board', 'mixpanel', 'mozilla', 'namecheap',
  'newrelic', 'norton', 'nuxt', 'okta', 'onedrive-personal', 'oppo-store', 'pagerduty', 'pandadoc', 'patreon-creator', 'payoneer-business',
  'perplexity', 'photon', 'pipedrive', 'prezi', 'protectli', 'protonvpn', 'quantcast', 'quicksight', 'raycast', 'recaptcha',
  'ringcentral', 'salesloft', 'segment', 'sendgrid', 'shop-pay', 'shoprunner', 'sketch', 'snowflake', 'sonarqube', 'splunk',
  'squareup', 'statuspage', 'surveymonkey', 'tableau', 'taobao', 'telegram-premium', 'temu-shop', 'trip-com', 'typeform', 'udacity',
  'veeam', 'vevo', 'visa-secure', 'voyager', 'webflow', 'wechat-work', 'wikimedia', 'wise-business', 'wordpress', 'xero-accounting',
  'yelp', 'zendesk', 'zerodha', 'zoho-mail', 'zoominfo', 'zulip', '1password', '2captcha', '3m', '7eleven'
]);

export const SUSPICIOUS_TLDS = unique([
  'zip', 'mov', 'phd', 'rest', 'cam', 'cyou', 'icu', 'sbs', 'monster', 'fin',
  'gq', 'tk', 'ml', 'ga', 'cf', 'pw', 'top', 'wang', 'work', 'click',
  'download', 'stream', 'online', 'site', 'website', 'space', 'fun', 'loan', 'win', 'review',
  'country', 'kim', 'cricket', 'party', 'trade', 'date', 'racing', 'accountant', 'science', 'faith',
  'webcam', 'men', 'bid', 'ninja', 'guru', 'rocks', 'wtf', 'lol', 'fail', 'gripe',
  'exposed', 'sucks', 'porn', 'xxx', 'adult', 'sex', 'tube', 'live', 'cams', 'chat',
  'link', 'buzz', 'promo', 'discount', 'sale', 'deals', 'today', 'news', 'media', 'digital',
  'tech', 'io', 'app', 'dev', 'run', 'code', 'ai', 'ml', 'bot', 'sh',
  'xyz', 'info', 'biz', 'us', 'mobi', 'tel', 'travel', 'cat', 'coop', 'aero',
  'museum', 'jobs', 'pro', 'name', 'ws', 'cc', 'tv', 'fm', 'am', 'bz',
  'ag', 'lc', 'vc', 'ms', 'nu', 'tm', 'gg', 'im', 'je', 'tf',
  'pm', 're', 'yt', 'sx', 'cw', 'bq', 'an', 'cs', 'tp', 'yu',
  'um', 'bu', 'dd', 'zr', 'zaire', 'su', 'nato', 'arpa', 'example', 'invalid',
  'local', 'localhost', 'test', 'internal', 'bar', 'bond', 'quest', 'host', 'gdn', 'life',
  'agency', 'solutions', 'center', 'systems', 'store', 'page', 'support', 'help', 'best', 'fit',
  'mom', 'xin', 'surf', 'asia', 'wiki', 'pics', 'photo', 'makeup', 'beauty', 'autos',
  'homes', 'boats', 'lat', 'rent', 'pet', 'press', 'ooo', 'secure', 'club', 'world',
  'cards', 'finance', 'shop', 'cloud', 'email', 'services', 'ltd', 'group', 'network', 'market',
  'exchange', 'capital', 'partners', 'ventures', 'vision', 'plus', 'global', 'social', 'watch', 'works',
  'city', 'town', 'zone', 'place', 'directory', 'guide', 'tips', 'expert', 'solutions', 'business'
]);

const authKeywords = [
  'login', 'signin', 'sign-in', 'signup', 'sign-up', 'register', 'auth', 'authenticate', 'authentication', 'oauth',
  'sso', '2fa', 'mfa', 'otp', 'verify', 'verification', 'confirm', 'confirmation', 'validate', 'validated',
  'approve', 'approval', 'authorize', 'authorization', 'reauth', 're-auth', 'one-time-password', 'passkey', 'challenge', 'captcha'
];

const accountKeywords = [
  'account', 'accounts', 'myaccount', 'profile', 'user', 'users', 'member', 'members', 'customer', 'client',
  'subscriber', 'subscribers', 'holder', 'identity', 'userid', 'username', 'mailbox', 'workspace', 'dashboard', 'portal',
  'console', 'tenant', 'organization', 'company', 'employee', 'staff', 'merchant', 'seller', 'buyer', 'beneficiary'
];

const securityKeywords = [
  'secure', 'security', 'safe', 'safety', 'protect', 'protection', 'alert', 'warning', 'urgent', 'important',
  'critical', 'immediate', 'suspend', 'suspended', 'suspension', 'disabled', 'blocked', 'limited', 'unusual', 'suspicious',
  'compromised', 'breach', 'hack', 'hacked', 'fraud', 'fraudulent', 'risk', 'threat', 'incident', 'detected',
  'quarantine', 'locked', 'lock', 'unlock', 'frozen', 'freeze', 'monitor', 'defender', 'antivirus', 'malware',
  'recovery', 'restore', 'backup', 'notice', 'attention', 'required', 'action-required', 'expired', 'expiry', 'expire'
];

const financeKeywords = [
  'bank', 'banking', 'payment', 'pay', 'checkout', 'billing', 'invoice', 'receipt', 'transaction', 'transfer',
  'wire', 'refund', 'money', 'cash', 'fund', 'funds', 'wallet', 'crypto', 'bitcoin', 'btc',
  'ethereum', 'eth', 'defi', 'nft', 'token', 'coin', 'currency', 'exchange', 'settlement', 'debit',
  'credit', 'card', 'debit-card', 'credit-card', 'cardholder', 'pin', 'cvv', 'bank-transfer', 'remit', 'swift',
  'iban', 'routing', 'tax', 'irs', 'vat', 'gst', 'payout', 'withdrawal', 'deposit', 'merchant'
];

const impersonationKeywords = [
  'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 'facebook', 'instagram', 'twitter', 'linkedin',
  'bank', 'chase', 'wellsfargo', 'citibank', 'hsbc', 'irs', 'fbi', 'interpol', 'police', 'government',
  'gov', 'official', 'meta', 'github', 'coinbase', 'binance', 'metamask', 'uniswap', 'opensea', 'stripe',
  'docusign', 'adobe', 'dropbox', 'slack', 'zoom', 'teams', 'notion', 'figma', 'icloud', 'gmail',
  'outlook', 'yahoo', 'protonmail', 'vercel', 'netlify', 'cloudflare', 'aws', 'azure', 'googlecloud', 'shopify'
];

const harvestKeywords = [
  'ssn', 'social-security', 'passport', 'license', 'drivers-license', 'credit-card', 'cvv', 'pin', 'password', 'passcode',
  'secret', 'private-key', 'recovery-phrase', 'seed-phrase', 'mnemonic', 'backup-code', 'security-answer', 'identity-card', 'tax-id', 'national-id',
  'aadhaar', 'pan', 'ifsc', 'routing-number', 'sort-code', 'dob', 'date-of-birth', 'otp-code', 'verification-code', 'api-key',
  'secret-key', 'wallet-address', 'keystore', 'rsa-key', 'ssh-key', 'token-code', 'auth-code', 'master-password', 'recovery-email', 'recovery-phone'
];

const piracyKeywords = [
  'filmyzilla', 'filmywap', 'movierulz', '9xmovies', 'jiorockers', 'tamilrockers', 'kuttymovies', 'isaimini', 'moviesda', 'bolly4u',
  'filmypur', 'mp4moviez', 'worldfree4u', 'downloadhub', 'movieverse', 'piracy', 'torrent', 'yts', 'rarbg', 'kickass',
  'thepiratebay', '1337x', 'eztv', 'limetorrents', 'fmovies', 'putlocker', 'solarmovie', '123movies', 'gomovies', 'gostream',
  'watchfree', 'couchtuner', 'tvmuse', 'alluc', 'streamfree', 'fullmovie', 'crack', 'keygen', 'warez', 'leak',
  'serialkey', 'activation-crack', 'mod-apk', 'premium-free', 'subscription-free', 'watch-online-free', 'download-now', 'webseries', 'camrip', 'dvdrip'
];

const lureKeywords = [
  'free', 'prize', 'winner', 'congratulations', 'claim', 'reward', 'bonus', 'gift', 'offer', 'deal',
  'discount', 'promo', 'limited', 'exclusive', 'special', 'unlock', 'activate', 'update', 'upgrade', 'renew',
  'renewal', 'expire', 'expiry', 'expired', 'click', 'here', 'now', 'asap', 'instant', 'limited-time',
  'act-now', 'last-chance', 'urgent-action', 'today-only', 'new-benefit', 'rebate', 'cashback', 'voucher', 'coupon', 'redeem'
];

const deliveryKeywords = [
  'delivery', 'shipment', 'tracking', 'fedex', 'dhl', 'ups', 'usps', 'courier', 'parcel', 'package',
  'customs', 'warehouse', 'dispatch', 'logistics', 'reschedule', 'held', 'pickup', 'invoice-pdf', 'proof-of-delivery', 'bill-of-lading'
];

const streamingKeywords = [
  'watch', 'stream', 'movie', 'episode', 'season', 'premium', 'vip', 'ott', 'live-tv', 'sports-live',
  'bypass', 'proxy', 'unblock', 'free-trial', 'adfree', 'playlist', 'iptv', 'webseries', 'reel', 'shorts'
];

export const PHISHING_KEYWORDS = unique([
  ...authKeywords,
  ...accountKeywords,
  ...securityKeywords,
  ...financeKeywords,
  ...impersonationKeywords,
  ...harvestKeywords,
  ...piracyKeywords,
  ...lureKeywords,
  ...deliveryKeywords,
  ...streamingKeywords,
  'apple-id', 'netflix-billing', 'amazon-support', 'verify-now', 'confirm-now', 'wallet-connect', 'ledger-live', 'secure-login', 'security-update', 'password-reset',
  'document-share', 'shared-file', 'open-document', 'view-file', 'download-file', 'salary-slip', 'hr-portal', 'employee-benefit', 'tax-refund', 'gov-benefit',
  'inheritance', 'lottery', 'airdrop', 'presale', 'staking', 'yield', 'liquidity', 'defi-wallet', 'connect-wallet', 'seed',
  'invoice-overdue', 'billing-failure', 'subscription-renewal', 'streaming-bypass', 'adult-content', 'private-video', 'webcam-chat', 'escort', 'dating', 'romance',
  'medical-record', 'insurance-claim', 'benefit-update', 'loan-approved', 'credit-score', 'foreclosure', 'bank-notice', 'legal-notice', 'court-order', 'summons',
  'federal', 'ministry', 'department', 'social-benefit', 'retirement', 'pension', 'docusign-envelope', 'signature-required', 'contract-review', 'nda'
]);

export const REDIRECT_PARAM_KEYS = ['url', 'redirect', 'return', 'next', 'goto', 'dest', 'target', 'continue', 'redir', 'to'] as const;

export const BRAND_TLD_MAP: Record<string, string[]> = {
  google: ['com'],
  youtube: ['com'],
  facebook: ['com'],
  instagram: ['com'],
  paypal: ['com'],
  github: ['com'],
  amazon: ['com'],
  apple: ['com'],
  microsoft: ['com'],
  netflix: ['com'],
  chase: ['com'],
  hsbc: ['com'],
  coinbase: ['com'],
  binance: ['com'],
  metamask: ['io'],
  openai: ['com'],
  stripe: ['com'],
  linkedin: ['com'],
  gmail: ['com'],
  outlook: ['com']
};

export const SAFE_FILE_EXTENSIONS = [
  'pdf', 'docx', 'xlsx', 'pptx', 'txt', 'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mp3', 'zip'
] as const;

export const URL_TYPE_SKIP_SCHEMES = ['chrome:', 'about:', 'chrome-extension:', 'devtools:', 'edge:'] as const;
