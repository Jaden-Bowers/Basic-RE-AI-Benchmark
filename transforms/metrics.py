"""Deterministic pair classification metrics; no model calls."""
import math
import random

def make_pairs(provenance, seed, per_class=64):
    rng=random.Random(seed);same=[];different=[]
    for i,a in enumerate(provenance):
        for b in provenance[i+1:]:
            (same if a['stream']==b['stream'] else different).append((a['operation_id'],b['operation_id']))
    if not same or not different: return [],{}
    selected=[(pair,label) for label,pool in ((1,same),(0,different)) for pair in rng.sample(pool,min(per_class,len(pool)))]
    rng.shuffle(selected);public=[];private={}
    for i,(pair,label) in enumerate(selected):
        key=f'p{i:04d}';public.append({'pair_id':key,'left':pair[0],'right':pair[1]});private[key]=label
    return public,private

def pair_metrics(labels, predictions):
    if not isinstance(predictions,dict):raise ValueError('Predictions must map pair IDs to probabilities')
    if set(predictions)!=set(labels):raise ValueError('Predictions must contain every pair ID and no extras')
    scores=[]
    for key,y in labels.items():
        p=predictions[key]
        if isinstance(p,bool) or not isinstance(p,(int,float)) or not math.isfinite(p) or not 0<=p<=1:
            raise ValueError('Pair probabilities must be finite numbers in [0,1]')
        scores.append((y,float(p)))
    if not scores: return {'accuracy':None,'f1':None,'roc_auc':None,'count':0}
    tp=sum(y==1 and p>=.5 for y,p in scores);fp=sum(y==0 and p>=.5 for y,p in scores)
    fn=sum(y==1 and p<.5 for y,p in scores);tn=sum(y==0 and p<.5 for y,p in scores)
    positive=[p for y,p in scores if y];negative=[p for y,p in scores if not y]
    auc=sum((a>b)+.5*(a==b) for a in positive for b in negative)/(len(positive)*len(negative)) if positive and negative else None
    return {'accuracy':(tp+tn)/len(scores),'f1':2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0.,
            'roc_auc':auc,'count':len(scores),'positive_count':len(positive),'negative_count':len(negative),
            'threshold':.5,'confusion':{'tp':tp,'fp':fp,'fn':fn,'tn':tn}}

def resource_metrics(events):
    """Read operator/tool logs. Correctness is determined only after a run."""
    if not isinstance(events,list):raise ValueError('Events must be a list')
    previous=-1.;totals={'tokens':0,'tool_calls':0,'executions':0,'traces':0,'incorrect_hypotheses':0}
    observed=set();first=None;before_first=None;checkpoints=[];context_peak=None
    for event in events:
        t=event.get('elapsed_seconds')
        if isinstance(t,bool) or not isinstance(t,(int,float)) or not math.isfinite(t) or t<previous or t<0:
            raise ValueError('Events require nondecreasing nonnegative elapsed_seconds')
        previous=t
        if 'context_tokens' in event:
            n=event['context_tokens']
            if type(n) is not int or n<0:raise ValueError('context_tokens must be a nonnegative integer')
            context_peak=max(context_peak or 0,n)
        for key in totals:
            if key in event:
                n=event[key]
                if type(n) is not int or n<0:raise ValueError('Resource counts must be nonnegative integer deltas')
                totals[key]+=n;observed.add(key)
        if event.get('kind')=='checkpoint':
            checkpoints.append(event)
            if event.get('correct') is True and first is None:
                first=t;before_first=totals['incorrect_hypotheses'] if 'incorrect_hypotheses' in observed else None
    return {**{k:totals[k] if k in observed else None for k in totals},
            'elapsed_seconds':previous if events else None,'time_to_first_correct_seconds':first,
            'context_peak_tokens':context_peak,'incorrect_hypotheses_before_first_correct':before_first,
            'checkpoint_count':len(checkpoints),
            'note':'Correctness flags must be filled by offline grading after the run; null means unobserved.'}
