import test from 'node:test'; import assert from 'node:assert/strict';
import { canTransition,assertTransition } from '../src/core/state.js';
test('scan state machine permits queued, running, completion and retry paths',()=>{assert.equal(canTransition('QUEUED','RUNNING'),true);assert.equal(canTransition('RUNNING','COMPLETED'),true);assert.equal(canTransition('RUNNING','QUEUED'),true);assert.equal(canTransition('FAILED','RUNNING'),false);});
test('scan state machine rejects terminal completion changes',()=>{assert.equal(canTransition('COMPLETED','RUNNING'),false);assert.throws(()=>assertTransition('COMPLETED','FAILED'));});
