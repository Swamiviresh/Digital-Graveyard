// Set this meta value at deployment time. Leave blank to use the explicitly labelled demo flow.
export const API_BASE_URL = (document.querySelector('meta[name="dg-api-base"]')?.content || '').trim().replace(/\/$/, '');
