import { createHash, randomUUID } from 'node:crypto';
import type { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { SQSClient, SendMessageCommand } from '@aws-sdk/client-sqs';
import { config } from '../core/config.js';
import { normalizeUrl, resolvePublic, ScanInputError } from '../core/url-safety.js';
import type { ScanRecord } from '../core/types.js';
const ddb=DynamoDBDocumentClient.from(new DynamoDBClient({region:config.region})); const sqs=new SQSClient({region:config.region});
function response(event:APIGatewayProxyEvent,statusCode:number,body:unknown):APIGatewayProxyResult {
  const origin=event.headers.origin||event.headers.Origin||'';
  const cors:Record<string,string>=origin&&config.allowedOrigins.includes(origin)?{'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Credentials':'false','Access-Control-Allow-Methods':'GET,POST,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization','Access-Control-Max-Age':'600','Vary':'Origin'}:{};
  return {statusCode,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...cors},body:statusCode===204?'':JSON.stringify(body)};
}
function route(event:APIGatewayProxyEvent):string{return `${event.httpMethod} ${event.resource||event.path}`;}
export async function handler(event:APIGatewayProxyEvent,_context:Context):Promise<APIGatewayProxyResult>{
  const method=event.httpMethod.toUpperCase();
  if(method==='OPTIONS') return response(event,204,{});
  const path=event.path||'';
  try {
    if(method==='POST' && path.endsWith('/api/scans')) {
      if((event.body||'').length>4096) return response(event,413,{error:{code:'REQUEST_TOO_LARGE',message:'Request body is too large.'}});
      const input=JSON.parse(event.body||'{}') as unknown;
      if(!input||typeof input!=='object'||Array.isArray(input)||!('url' in input)) return response(event,400,{error:{code:'INVALID_REQUEST',message:'Request JSON must include a URL field.'}});
      const target=normalizeUrl((input as {url:unknown}).url);
      const ip=event.requestContext.identity.sourceIp||'unknown'; const minute=Math.floor(Date.now()/60000);
      const rateKey=createHash('sha256').update(`${ip}:${minute}`).digest('hex');
      try { await ddb.send(new UpdateCommand({TableName:config.rateTable,Key:{rateKey},UpdateExpression:'SET #ttl = :ttl ADD hits :one',ConditionExpression:'attribute_not_exists(hits) OR hits < :max',ExpressionAttributeNames:{'#ttl':'ttl'},ExpressionAttributeValues:{':ttl':Math.floor(Date.now()/1000)+180,':one':1,':max':config.maxPerMinute}})); }
      catch(error){ if((error as {name?:string}).name==='ConditionalCheckFailedException') return response(event,429,{error:{code:'RATE_LIMITED',message:'Too many scans. Try again in a minute.'}}); throw error; }
      await resolvePublic(target.hostname.replace(/^\[|\]$/g,''));
      const now=new Date().toISOString(); const scanId=randomUUID();
      const record:ScanRecord={scanId,targetUrl:target.href,hostname:target.hostname,status:'QUEUED',progress:0,stage:'Queued for analysis',createdAt:now,updatedAt:now,ttl:Math.floor(Date.now()/1000)+7*86400};
      await ddb.send(new PutCommand({TableName:config.scanTable,Item:record,ConditionExpression:'attribute_not_exists(scanId)'}));
      try { await sqs.send(new SendMessageCommand({QueueUrl:config.queueUrl,MessageBody:JSON.stringify({scanId,targetUrl:target.href})})); }
      catch { await ddb.send(new UpdateCommand({TableName:config.scanTable,Key:{scanId},UpdateExpression:'SET #status=:failed, #error=:error, updatedAt=:now',ExpressionAttributeNames:{'#status':'status','#error':'error'},ExpressionAttributeValues:{':failed':'FAILED',':error':{code:'QUEUE_UNAVAILABLE',message:'Scan could not be queued.'},':now':new Date().toISOString()}})); throw new Error('queue unavailable'); }
      return response(event,202,{scanId,status:'queued',message:'Scan successfully queued'});
    }
    const scanId=event.pathParameters?.scanId;
    if(scanId && method==='GET') {
      const result=await ddb.send(new GetCommand({TableName:config.scanTable,Key:{scanId},ConsistentRead:true}));
      const record=result.Item as ScanRecord|undefined;
      if(!record) return response(event,404,{error:{code:'SCAN_NOT_FOUND',message:'Scan was not found or has expired.'}});
      if(path.endsWith('/report')) {
        if(record.status!=='COMPLETED'||!record.report) return response(event,409,{scanId,status:record.status.toLowerCase(),progress:record.progress,stage:record.stage,message:'Report is not ready yet.'});
        return response(event,200,record.report);
      }
      const {scanId:id,targetUrl,status,progress,stage,createdAt,updatedAt,error}=record;
      return response(event,200,{scanId:id,targetUrl,status,progress,stage,createdAt,updatedAt,...(error?{error}: {})});
    }
    return response(event,404,{error:{code:'NOT_FOUND',message:'API route not found.'}});
  } catch(error) {
    if(error instanceof ScanInputError) return response(event,error.statusCode,{error:{code:error.code,message:error.message}});
    if(error instanceof SyntaxError) return response(event,400,{error:{code:'INVALID_JSON',message:'Request body must be valid JSON.'}});
    console.error(JSON.stringify({level:'error',requestId:event.requestContext.requestId,route:route(event),error:error instanceof Error?error.message:'unknown'}));
    return response(event,503,{error:{code:'SERVICE_UNAVAILABLE',message:'The scan service is temporarily unavailable.'}});
  }
}
