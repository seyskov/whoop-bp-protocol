package org.whoopbp.probe;

import java.util.*;

/** Bounded record-level optical integrity audit, never a clinical metric.
 * Only historical 0x2F records enter this capture. Live 0x28/0x2B/0x33 are
 * deliberately excluded. Windows are kept separately, not interpolated/joined.
 */
public final class WaveAudit {
    public static final int MAX_WINDOWS=2048, MAX_REFS=4096;
    private final Map<String,Window> windows=new LinkedHashMap<>();
    private final Map<String,Map<String,Object>> refs=new LinkedHashMap<>();
    public int repeats, conflictingRepeats, malformed, capacityDrops;
    public static final class Window {
        public final long tick, index;
        public final int rate, flags, pipCounter, state, morphology;
        public final int[] samples=new int[25], deltas=new int[24];
        public final byte[] encoded;
        public final Double motion;
        public final boolean saturated, impossible;
        Window(byte[] in){
            encoded=in.clone();index=Gen5Probe.u32(in,3);
            tick=Gen5Probe.u32(in,7)*32768+Gen5Probe.u16(in,11);
            flags=in[2]&255;rate=(flags&128)!=0?25:50;pipCounter=Gen5Probe.u16(in,13);
            state=Gen5Probe.u16(in,71);morphology=in[74]&255;
            samples[0]=(int)Gen5Probe.u32(in,15);boolean sat=false,bad=outside(samples[0]);
            for(int i=0;i<24;i++){
                int d=Gen5Probe.i16(in,19+2*i);deltas[i]=d;
                sat|=d== -32768 || d==32767;samples[i+1]=samples[i]+d;bad|=outside(samples[i+1]);
            }
            saturated=sat;impossible=bad;
            float f=Float.intBitsToFloat((int)Gen5Probe.u32(in,67));motion=Float.isNaN(f)||Float.isInfinite(f)?null:(double)f;
        }
        static boolean outside(int x){return x< -524288 || x>524287;}
        public boolean usableEncoding(){return !saturated && !impossible;}
        public int peakToPeak(){int min=samples[0],max=min;for(int n:samples){min=Math.min(min,n);max=Math.max(max,n);}return max-min;}
        Map<String,Object> export(long baseTick,long baseIndex){
            Map<String,Object> m=new LinkedHashMap<>();m.put("t_seconds",(tick-baseTick)/32768.0);m.put("record_index_relative",index-baseIndex);
            m.put("rate_hz_declared",rate);m.put("flags",flags);m.put("pip_counter",pipCounter);m.put("channel_state_word",state);
            m.put("morphology_raw",morphology);m.put("motion_delta_g",motion);m.put("first_adc",samples[0]);
            m.put("deltas",list(deltas));m.put("saturated_delta",saturated);m.put("impossible_reconstruction",impossible);
            return m;
        }
    }
    private static List<Integer> list(int[] a){List<Integer> out=new ArrayList<>();for(int n:a)out.add(n);return out;}
    public void accept(byte[] in){
        if(in.length<13 || (in[0]&255)!=0x2f)return;
        int v=in[1]&255;long tick=Gen5Probe.u32(in,7)*32768+Gen5Probe.u16(in,11);
        long index=Gen5Probe.u32(in,3);String key=index+":"+tick;
        if(v==26){
            if(in.length!=76 || Gen5Probe.u16(in,11)>=32768){malformed++;return;}
            Window old=windows.get(key);
            if(old!=null){if(Arrays.equals(old.encoded,in))repeats++;else conflictingRepeats++;return;}
            if(windows.size()>=MAX_WINDOWS){capacityDrops++;return;}windows.put(key,new Window(in));
        }else if(v==18 && in.length>=109 && Gen5Probe.u16(in,11)<32768 && refs.size()<MAX_REFS && !refs.containsKey(key)){
            // Device HR is a local corroboration channel, not an external ECG.
            // It is exported only in the local historical capture, never in summary.
            Map<String,Object> ref=new LinkedHashMap<>();ref.put("tick",tick);ref.put("index",index);
            int hr=in[14]&255;ref.put("device_hr_bpm",hr>=25 && hr<=230?hr:null);
            List<Integer> rr=new ArrayList<>();int n=in[15]&255;if(n<=4)for(int i=0;i<n;i++){int ms=Gen5Probe.i16(in,16+2*i);if(ms>=200 && ms<=2500)rr.add(ms);}
            ref.put("device_rr_ms",rr);refs.put(key,ref);
        }
    }
    public int size(){return windows.size();}
    public List<Window> sorted(){List<Window> out=new ArrayList<>(windows.values());out.sort(Comparator.comparingLong((Window w)->w.tick).thenComparingLong(w->w.index));return out;}
    private static Map<String,Object> distribution(List<Double> a){
        Map<String,Object> m=new LinkedHashMap<>();m.put("n",a.size());
        if(a.isEmpty()){m.put("median",null);m.put("p95",null);m.put("max",null);return m;}
        Collections.sort(a);m.put("median",quantile(a,.5));m.put("p95",quantile(a,.95));m.put("max",a.get(a.size()-1));return m;
    }
    private static double quantile(List<Double> a,double q){double at=(a.size()-1)*q;int lo=(int)at,hi=(int)Math.ceil(at);return a.get(lo)+(a.get(hi)-a.get(lo))*(at-lo);}
    public Map<String,Object> summary(){
        List<Window> sorted=sorted();int flat=0,rails=0,saturated=0,bad=0,positive=0,knownBadState=0;
        int gaps=0,overlaps=0,rateChanges=0,configChanges=0,compatible=0,zeroScaleEdges=0;
        List<Double> amplitudes=new ArrayList<>(),jumps=new ArrayList<>(),edgeRelative=new ArrayList<>(),missing=new ArrayList<>();
        for(int i=0;i<sorted.size();i++){
            Window w=sorted.get(i);int p2p=w.peakToPeak();amplitudes.add((double)p2p);if(p2p==0)flat++;
            if(w.saturated)saturated++;if(w.impossible)bad++;if(w.morphology==1)positive++;
            if((w.state&0xf000)!=0)knownBadState++;
            for(int n:w.samples)if(n== -524288 || n==524287)rails++;
            if(i==0)continue;Window previous=sorted.get(i-1);
            double dt=(w.tick-previous.tick)/32768.0;
            double gap=dt-25.0/previous.rate;
            if(previous.rate!=w.rate)rateChanges++;
            if(previous.state!=w.state)configChanges++;
            // Only timestamp compatibility is assessed. The first-sample
            // timestamp interpretation remains a hypothesis to test on data.
            double tolerance=2.0/32768;
            if(gap>tolerance){gaps++;missing.add(gap);}else if(gap< -tolerance){overlaps++;}else compatible++;
            if(Math.abs(gap)>tolerance || previous.rate!=w.rate || !previous.usableEncoding() || !w.usableEncoding())continue;
            double jump=Math.abs((double)w.samples[0]-previous.samples[24]);jumps.add(jump);
            List<Double> steps=new ArrayList<>();for(int d:previous.deltas)steps.add(Math.abs((double)d));for(int d:w.deltas)steps.add(Math.abs((double)d));Collections.sort(steps);
            double p95=quantile(steps,.95);if(p95>0)edgeRelative.add(jump/p95);else if(jump>0)zeroScaleEdges++;
        }
        Map<String,Object> m=new LinkedHashMap<>();m.put("windows",sorted.size());m.put("local_reference_records",refs.size());
        m.put("exact_replays",repeats);m.put("conflicting_replays",conflictingRepeats);m.put("malformed",malformed);m.put("capacity_drops",capacityDrops);
        m.put("flat_windows",flat);m.put("adc_rail_samples",rails);m.put("saturated_delta_windows",saturated);m.put("impossible_windows",bad);
        m.put("band_morphology_pass_windows",positive);m.put("processing_saturation_flag_windows",knownBadState);
        m.put("timestamp_compatible_pairs",compatible);m.put("timestamp_gap_pairs",gaps);m.put("timestamp_overlap_pairs",overlaps);
        m.put("rate_change_pairs",rateChanges);m.put("state_word_change_pairs",configChanges);m.put("jump_with_zero_intra_scale_pairs",zeroScaleEdges);
        m.put("peak_to_peak_adc",distribution(amplitudes));m.put("compatible_edge_jump_adc",distribution(jumps));
        m.put("edge_jump_over_adjacent_intra_p95",distribution(edgeRelative));m.put("timestamp_gap_seconds",distribution(missing));
        m.put("continuity_proven",false);m.put("bp_suitability_validated",false);return m;
    }
    public Map<String,Object> export(){
        List<Window> sorted=sorted();Map<String,Object> root=new LinkedHashMap<>();root.put("schema",1);
        root.put("record_source","historical_0x2f_only");root.put("sample_timestamp_alignment","record_time_as_window_start_hypothesis");
        root.put("summary",summary());List<Map<String,Object>> out=new ArrayList<>(),reference=new ArrayList<>();
        long baseTick=sorted.isEmpty()?0:sorted.get(0).tick,baseIndex=sorted.isEmpty()?0:sorted.get(0).index;
        for(Window w:sorted)out.add(w.export(baseTick,baseIndex));
        if(!sorted.isEmpty())for(Map<String,Object> ref:refs.values()){
            long t=((Number)ref.get("tick")).longValue();if(t<baseTick-5*32768 || t>sorted.get(sorted.size()-1).tick+5*32768)continue;
            Map<String,Object> m=new LinkedHashMap<>();m.put("t_seconds",(t-baseTick)/32768.0);m.put("record_index_relative",((Number)ref.get("index")).longValue()-baseIndex);
            m.put("device_hr_bpm",ref.get("device_hr_bpm"));m.put("device_rr_ms",ref.get("device_rr_ms"));reference.add(m);
        }
        root.put("windows",out);root.put("reference",reference);return root;
    }
}
