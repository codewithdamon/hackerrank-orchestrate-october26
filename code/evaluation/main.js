'use strict';
const fs = require('fs');
const path = require('path');
const { loadContext, classify, assignNumbers, authorization, buildIdentityMaps } = require('../main.js');
const root = path.resolve(__dirname, '..', '..');
const ds = path.join(root, 'dataset');
function csv(s) {
  const rows=[];let r=[],f='',q=false;
  for(let i=0;i<s.length;i++){const c=s[i];if(q){if(c==='"'&&s[i+1]==='"'){f+='"';i++;}else if(c==='"')q=false;else f+=c;}else if(c==='"')q=true;else if(c===','){r.push(f);f='';}else if(c==='\n'){r.push(f);rows.push(r);r=[];f='';}else if(c!=='\r')f+=c;}
  if(f||r.length){r.push(f);rows.push(r);}const h=rows.shift();return rows.filter(x=>x.some(y=>y)).map(x=>Object.fromEntries(h.map((k,i)=>[k,x[i]||''])));
}
function normStep(s){return {step_no:s.step_no,phase:s.phase,system_id:s.system_id,resource_id:s.resource_id,operation:s.operation,state:s.state,evidence_id:s.evidence_id};}
const ctx=loadContext();
const sampleRequests = csv(fs.readFileSync(path.join(ds,'sample_deletion_requests.csv'),'utf8'));
const actual=assignNumbers(sampleRequests.map(r=>classify(r,ctx)));
const pred=new Map(actual.map(r=>[r.case_id,r]));
const req=sampleRequests;
const gold=csv(fs.readFileSync(path.join(ds,'sample_output.csv'),'utf8'));
const goldBy=new Map(gold.map(r=>[r.case_id,r]));
let statusCorrect=0, sequenceCorrect=0, fieldCorrect=0, stepCorrect=0, goldSteps=0, predSteps=0;
const cases=[];
for(const q of req){const a=pred.get(q.case_id),g=goldBy.get(q.case_id);if(!g||!a)continue;
 const gs=JSON.parse(g.steps_json),as=a.steps.map(normStep); const sc=a.deletion_status===g.deletion_status; if(sc)statusCorrect++;
 const full=JSON.stringify(as)===JSON.stringify(gs);if(full)sequenceCorrect++;
 const n=Math.max(as.length,gs.length);let exact=0;for(let i=0;i<n;i++){const x=as[i],y=gs[i];if(x&&y&&JSON.stringify(x)===JSON.stringify(y))exact++;}
 stepCorrect+=exact;goldSteps+=gs.length;predSteps+=as.length;
 for(let i=0;i<n;i++){for(const k of ['step_no','phase','system_id','resource_id','operation','state','evidence_id'])if(as[i]?.[k]===gs[i]?.[k])fieldCorrect++;}
 cases.push({case_id:q.case_id,status_correct:sc,sequence_correct:full,predicted_status:a.deletion_status,expected_status:g.deletion_status,predicted_steps:as.length,expected_steps:gs.length});
}
console.log(JSON.stringify({sample_cases:cases.length,status_correct:statusCorrect,status_accuracy:statusCorrect/cases.length,sequence_correct:sequenceCorrect,sequence_accuracy:sequenceCorrect/cases.length,exact_steps:stepCorrect,gold_steps:goldSteps,predicted_steps:predSteps,step_precision:predSteps?stepCorrect/predSteps:0,step_recall:goldSteps?stepCorrect/goldSteps:0,field_correct:fieldCorrect,field_accuracy:fieldCorrect/(Math.max(goldSteps,predSteps)*7)},null,2));
console.log('CASE_DETAIL '+JSON.stringify(cases));
console.log('STATUS_MISMATCHES '+JSON.stringify(cases.filter(c=>!c.status_correct).map(c=>({case_id:c.case_id,predicted:c.predicted_status,expected:c.expected_status}))));
const custom = [
  { name: 'access request is not deletion', pass: authorization('Please send me a copy of all personal data you hold about me.') === false },
  { name: 'Spanish deletion intent', pass: authorization('Solicito eliminar permanentemente mi cuenta y mis datos personales.') === true },
  { name: 'negated deletion is not authorization', pass: authorization('Please do not delete my account; I only want to correct my phone number.') === false },
  { name: 'explicitly not asking for deletion', pass: authorization('I am not asking for deletion; please stop promotional emails.') === false },
  { name: 'account closure explicitly refused', pass: authorization('Do not close the account; I only need login help.') === false },
  { name: 'correction without record removal', pass: authorization('Please correct my surname without removing any records.') === false },
  { name: 'marketing list removal only', pass: authorization('Please remove me from marketing lists only.') === false },
  { name: 'information request excludes erasure', pass: authorization('This is an information request, not a request to erase it.') === false },
  { name: 'copy request explicitly forbids deletion', pass: authorization('Please send me a copy; please do not delete or change anything.') === false },
  { name: 'historical email resolves to stable user', pass: (() => { const m=buildIdentityMaps([{user_id:'u1',name:'A Person',email:'new@example.test',phone:'+1 202 555 0100',email_hash:'abc'}],[{user_id:'u1',field_name:'email',old_value:'old@example.test',new_value:'new@example.test'}]); return m.alias.get('old@example.test')?.has('u1') === true; })() },
  { name: 'nearby email does not resolve by substring', pass: (() => { const m=buildIdentityMaps([{user_id:'u1',name:'A Person',email:'amy@example.test',phone:'',email_hash:''}],[]); return m.alias.has('my@example.test') === false; })() },
];
console.log('CUSTOM_CASES '+JSON.stringify(custom));
if (custom.some(x=>!x.pass)) process.exitCode=1;
