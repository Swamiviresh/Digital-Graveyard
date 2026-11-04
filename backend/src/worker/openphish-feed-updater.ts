import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';

const region = process.env.AWS_REGION || 'ap-south-1';
const bucket = process.env.OPENPHISH_FEED_BUCKET || '';
const key = process.env.OPENPHISH_FEED_KEY || 'feed.txt';
const s3 = new S3Client({ region });

export async function handler() {
  if (!bucket) throw new Error('OPENPHISH_FEED_BUCKET is not configured.');
  const response = await fetch('https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt', {
    headers: { 'user-agent': 'DigitalGraveyardOpenPhishFeedUpdater/1.0' },
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw new Error('OpenPhish feed download returned HTTP ' + response.status + '.');
  const text = await response.text();
  const entries = text.split(/\r?\n/).map(line => line.trim()).filter(line => {
    try {
      const parsed = new URL(line);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
      return false;
    }
  });
  if (entries.length < 10) throw new Error('Downloaded OpenPhish feed failed validation; keeping the previous S3 snapshot.');
  await s3.send(new PutObjectCommand({
    Bucket: bucket,
    Key: key,
    Body: entries.join('\n') + '\n',
    ContentType: 'text/plain; charset=utf-8',
    ServerSideEncryption: 'AES256',
    Metadata: {
      source: 'openphish-community-feed',
      entryCount: String(entries.length),
      refreshedAt: new Date().toISOString(),
      refreshCadence: '12-hours',
    },
  }));
  console.log(JSON.stringify({
    level: 'info',
    component: 'openphish-feed-updater',
    message: 'OpenPhish feed snapshot refreshed.',
    entries: entries.length,
    bucket,
    key,
  }));
  return { ok: true, entries: entries.length, refreshedAt: new Date().toISOString() };
}
