import type { ScanStatus } from './types.js';
const transitions:Record<ScanStatus,ScanStatus[]>={QUEUED:['RUNNING','FAILED'],RUNNING:['RUNNING','QUEUED','COMPLETED','FAILED'],COMPLETED:[],FAILED:[]};
export function canTransition(from:ScanStatus,to:ScanStatus):boolean{return transitions[from].includes(to);}
export function assertTransition(from:ScanStatus,to:ScanStatus):void{if(!canTransition(from,to))throw new Error(`Invalid scan state transition: ${from} -> ${to}`);}
