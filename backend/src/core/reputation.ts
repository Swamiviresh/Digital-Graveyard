import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { safeFetch } from './safe-fetch.js';
import { config } from './config.js';
import type { Finding } from './types.js';
const secrets = new SecretsManagerClient({ region: config.region });
export interface ReputationProvider { readonly name:string; check(hostname:string):Promise<{available:boolean;data?:Record<string,unknown>;reason?:string;findings:Finding[]}>; }
export class VirusTotalProvider implements ReputationProvider {
  readonly name='VirusTotal';
  async check(hostname:string){
    if(!config.reputationSecretArn)return{available:false,reason:'Reputation provider is not configured.',findings:[]};
    try{
      const secret=await secrets.send(new GetSecretValueCommand({SecretId:config.reputationSecretArn}));
      const keys=JSON.parse(secret.SecretString||'{}') as {virusTotalApiKey?:string};
      if(!keys.virusTotalApiKey)return{available:false,reason:'No VirusTotal API key is configured.',findings:[]};
      const response=await safeFetch(new URL(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(hostname)}`),0,[],{'x-apikey':keys.virusTotalApiKey});
      if(response.status!==200)return{available:false,reason:`Provider returned HTTP ${response.status}.`,findings:[]};
      const doc=JSON.parse(response.body) as {data?:{attributes?:{last_analysis_stats?:Record<string,number>}}};
      const stats=doc.data?.attributes?.last_analysis_stats;
      if(!stats||typeof stats!=='object')return{available:false,reason:'VirusTotal has no completed analysis statistics for this domain.',findings:[]};
      const counts=Object.values(stats).map(value=>Number(value)).filter(value=>Number.isFinite(value)&&value>=0);
      const total=counts.reduce((a,b)=>a+b,0);
      if(total===0)return{available:false,reason:'VirusTotal returned no completed engine results for this domain.',findings:[]};
      const malicious=Number(stats.malicious||0),suspicious=Number(stats.suspicious||0);const findings:Finding[]=[];
      if(malicious>0){
        const ratio = total > 0 ? malicious / total : 0;
        const severity = malicious >= 5 || (total >= 20 && ratio >= 0.15) ? 'critical' : malicious >= 2 || (total >= 20 && ratio >= 0.05) ? 'high' : 'medium';
        const confidence = severity === 'critical' ? 0.97 : severity === 'high' ? 0.9 : 0.75;
        findings.push({id:'reputation-virustotal-malicious',category:'reputation',severity,title:'Threat feed reports malicious detections',description:'VirusTotal domain analysis reports one or more malicious detections. Detection count and engine coverage are included for context.',evidence:[`${malicious} malicious of ${total} engines; ${suspicious} suspicious`],confidence,signalType:'threat',recommendation:'Investigate detections and avoid submitting sensitive information until the result is understood.'});
      } else if(suspicious>0){
        const severity = suspicious >= 5 ? 'medium' : 'low';
        findings.push({id:'reputation-virustotal-suspicious',category:'reputation',severity,title:'Threat feed reports suspicious detections',description:'VirusTotal reported suspicious classifications. This is an indicator for review, not proof of maliciousness.',evidence:[`${suspicious} suspicious of ${total} engines`],confidence:0.65,signalType:'threat',recommendation:'Review provider results and confirm the domain owner.'});
      }
      return{available:true,data:{provider:this.name,checkedAt:new Date().toISOString(),stats,malicious,suspicious,total},findings};
    }catch{return{available:false,reason:'Provider request failed or credentials were invalid.',findings:[]};}
  }
}
export async function checkReputation(hostname:string):Promise<{result:Record<string,unknown>;findings:Finding[]}>{
  const providers:ReputationProvider[]=[new VirusTotalProvider()];const results=await Promise.all(providers.map(provider=>provider.check(hostname)));
  const findings=results.flatMap(result=>result.findings);const available=results.some(result=>result.available);
  return{result:{available,providers:results.map((result,index)=>({name:providers[index]!.name,available:result.available,...(result.reason?{reason:result.reason}:{}),...(result.data||{})}))},findings};
}
