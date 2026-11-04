import type { SQSEvent, SQSBatchResponse } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { assertTransition } from '../core/state.js';
import { config } from '../core/config.js';
import { runScan } from '../core/scanner.js';
import { describeScanFailure } from './errors.js';
const ddb=DynamoDBDocumentClient.from(new DynamoDBClient({region:config.region}));
export async function handler(event:SQSEvent):Promise<SQSBatchResponse>{
  const failures:{itemIdentifier:string}[]=[];
  for(const record of event.Records){
    try {
      const job=JSON.parse(record.body) as {scanId:string;targetUrl:string};
      const current=await ddb.send(new GetCommand({TableName:config.scanTable,Key:{scanId:job.scanId},ConsistentRead:true}));
      const currentStatus=(current.Item?.status||'QUEUED') as import('../core/types.js').ScanStatus;
      if(currentStatus==='COMPLETED'||currentStatus==='RUNNING'||currentStatus==='FAILED') continue;
      assertTransition(currentStatus,'RUNNING');
      try { await ddb.send(new UpdateCommand({TableName:config.scanTable,Key:{scanId:job.scanId},UpdateExpression:'SET #status=:running, stage=:stage, progress=:progress, updatedAt=:now REMOVE #error',ConditionExpression:'#status=:previous',ExpressionAttributeNames:{'#status':'status','#error':'error'},ExpressionAttributeValues:{':running':'RUNNING',':previous':currentStatus,':stage':'Starting evidence collection',':progress':3,':now':new Date().toISOString()}})); } catch(error) { if((error as {name?:string}).name==='ConditionalCheckFailedException') continue; throw error; }
      const progress=async(stage:string,value:number)=>{await ddb.send(new UpdateCommand({TableName:config.scanTable,Key:{scanId:job.scanId},UpdateExpression:'SET #status=:running, stage=:stage, progress=:progress, updatedAt=:now',ExpressionAttributeNames:{'#status':'status'},ExpressionAttributeValues:{':running':'RUNNING',':stage':stage,':progress':value,':now':new Date().toISOString()}}));};
      const report=await runScan(job.scanId,job.targetUrl,progress);
      await ddb.send(new UpdateCommand({TableName:config.scanTable,Key:{scanId:job.scanId},UpdateExpression:'SET #status=:complete, progress=:progress, stage=:stage, report=:report, updatedAt=:now REMOVE #error',ExpressionAttributeNames:{'#status':'status','#error':'error'},ExpressionAttributeValues:{':complete':'COMPLETED',':progress':100,':stage':'Report ready',':report':report,':now':new Date().toISOString()}}));
    } catch(error) {
      const failure = describeScanFailure(error);
      console.error(JSON.stringify({
        level: 'error',
        messageId: record.messageId,
        error: error instanceof Error ? error.message : 'unknown',
        failureCode: failure.code,
      }));
      let failureSaved = false;
      try {
        const job = JSON.parse(record.body) as { scanId: string };
        await ddb.send(new UpdateCommand({
          TableName: config.scanTable,
          Key: { scanId: job.scanId },
          UpdateExpression: 'SET #status=:failed, stage=:stage, updatedAt=:now, #error=:error',
          ExpressionAttributeNames: { '#status': 'status', '#error': 'error' },
          ExpressionAttributeValues: {
            ':failed': 'FAILED',
            ':stage': failure.stage,
            ':now': new Date().toISOString(),
            ':error': { code: failure.code, message: failure.message },
          },
        }));
        failureSaved = true;
      } catch(persistError) {
        console.error(JSON.stringify({
          level: 'error',
          messageId: record.messageId,
          error: 'Unable to save terminal scan failure; SQS will retry the message.',
          details: persistError instanceof Error ? persistError.message : 'unknown',
        }));
      }
      // Acknowledge a failed scan as soon as its FAILED state is persisted.
      // Only return the message to SQS when DynamoDB itself could not save that state.
      if (!failureSaved) failures.push({ itemIdentifier: record.messageId });
    }
  }
  return {batchItemFailures:failures};
}
