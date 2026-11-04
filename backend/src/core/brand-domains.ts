export interface BrandDomainRecord {
  brand: string;
  displayName: string;
  domains: string[];
}

export const BRAND_DOMAINS: BrandDomainRecord[] = [
  { brand: 'google', displayName: 'Google', domains: ['google.com', 'google.co.in', 'google.co.uk'] },
  { brand: 'microsoft', displayName: 'Microsoft', domains: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'] },
  { brand: 'apple', displayName: 'Apple', domains: ['apple.com', 'icloud.com'] },
  { brand: 'paypal', displayName: 'PayPal', domains: ['paypal.com', 'paypal.in', 'paypal.co.uk'] },
  { brand: 'amazon', displayName: 'Amazon', domains: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de'] },
  { brand: 'coinbase', displayName: 'Coinbase', domains: ['coinbase.com'] },
  { brand: 'binance', displayName: 'Binance', domains: ['binance.com'] },
  { brand: 'metamask', displayName: 'MetaMask', domains: ['metamask.io'] },
  { brand: 'facebook', displayName: 'Facebook', domains: ['facebook.com'] },
  { brand: 'instagram', displayName: 'Instagram', domains: ['instagram.com'] },
  { brand: 'netflix', displayName: 'Netflix', domains: ['netflix.com'] },
  { brand: 'steam', displayName: 'Steam', domains: ['steampowered.com', 'steamcommunity.com'] },
  { brand: 'sbi', displayName: 'State Bank of India', domains: ['sbi.co.in', 'sbi.bank.in', 'onlinesbi.sbi'] },
  { brand: 'hdfc', displayName: 'HDFC Bank', domains: ['hdfcbank.com'] },
  { brand: 'icici', displayName: 'ICICI Bank', domains: ['icicibank.com'] },
  { brand: 'axis', displayName: 'Axis Bank', domains: ['axisbank.com'] },
  { brand: 'kotak', displayName: 'Kotak Mahindra Bank', domains: ['kotak.com'] },
  { brand: 'paytm', displayName: 'Paytm', domains: ['paytm.com'] },
  { brand: 'phonepe', displayName: 'PhonePe', domains: ['phonepe.com'] },
  { brand: 'flipkart', displayName: 'Flipkart', domains: ['flipkart.com'] },
  { brand: 'irctc', displayName: 'IRCTC', domains: ['irctc.co.in'] },
  { brand: 'uidai', displayName: 'UIDAI', domains: ['uidai.gov.in'] },
  { brand: 'npci', displayName: 'NPCI', domains: ['npci.org.in'] },
  { brand: 'razorpay', displayName: 'Razorpay', domains: ['razorpay.com'] },
  { brand: 'cred', displayName: 'CRED', domains: ['cred.club'] },
  { brand: 'jio', displayName: 'Jio', domains: ['jio.com'] },
  { brand: 'airtel', displayName: 'Airtel', domains: ['airtel.in'] },
];
