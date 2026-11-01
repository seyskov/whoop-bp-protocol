package org.whoopbp.probe;

import java.util.*;

/** RAM-only inspection of live 0x2B/20 buffers using the existing v20 geometry.
 * Recognition is deliberately strict: 2128-byte inner, 5x422-byte blocks,
 * <=50 sample slots, Q15 timestamp, explicit 25/50Hz rate. No BP inference.
 * snapshot() returns an in-memory object, never a serializable raw export.
 */
public final class LiveOpticalAudit {
    static final int MAX_CHUNKS=256;
    public int candidateFrames, malformed, capacityDrops, referencePackets, referenceWornPackets;
    final List<Integer> referenceHr=new ArrayList<>();
    final Map<String,Integer> rateFields=new TreeMap<>(), frameLengths=new TreeMap<>();
    final List<List<Chunk>> channels=new ArrayList<>();
    public LiveOpticalAudit(){for(int i=0;i<10;i++)channels.add(new ArrayList<>());}
    static final class Chunk {
        final long tick,index,receiveNs;
        final int fs,flagRate,source;
        final int[] samples;
        final String config;
        Chunk(long t,long i,long receive,int f,int flag,int source,int[] s,String c){tick=t;index=i;receiveNs=receive;fs=f;flagRate=flag;this.source=source;samples=s;config=c;}
    }
    public void accept(byte[] in,long receiveNs){
        if(in.length>=20 && (in[0]&255)==0x28 && in[1]==2){
            referencePackets++;int hr=in[8]&255;
            if(in[18]==1){referenceWornPackets++;if(hr>=25 && hr<=230 && referenceHr.size()<4096)referenceHr.add(hr);}
            return;
        }
        if(in.length<2 || (in[0]&255)!=0x2b || in[1]!=20)return;
        candidateFrames++;Gen5Probe.Stats.count(frameLengths,Integer.toString(in.length));
        if(in.length!=2128 || Gen5Probe.u16(in,11)>=32768){malformed++;return;}
        int fs=Gen5Probe.u16(in,15),flag=(in[2]&128)!=0?25:50;
        Gen5Probe.Stats.count(rateFields,Integer.toString(fs));
        long tick=Gen5Probe.u32(in,7)*32768+Gen5Probe.u16(in,11),index=Gen5Probe.u32(in,3);
        for(int b=0;b<5;b++){
            int start=18+b*422,n=in[start]&255;if(n>50){malformed++;continue;}if(n==0)continue;
            for(int path=0;path<2;path++){
                List<Chunk> rows=channels.get(b*2+path);if(rows.size()>=MAX_CHUNKS){capacityDrops++;continue;}
                int[] samples=new int[n];int offset=start+21+path*200;
                for(int j=0;j<n;j++){int raw=(int)Gen5Probe.u32(in,offset+4*j)&0xfffff;samples[j]=raw>=0x80000?raw-0x100000:raw;}
                int source=in[start+7+path*7]&255;
                String config=Arrays.toString(Arrays.copyOfRange(in,start+1,start+21));
                rows.add(new Chunk(tick,index,receiveNs,fs,flag,source,samples,config));
            }
        }
    }
    public Map<String,Object> progress(){
        Map<String,Object> m=new LinkedHashMap<>();m.put("live_samples_persisted",false);m.put("type20_frames",candidateFrames);
        m.put("frame_lengths",new TreeMap<>(frameLengths));m.put("explicit_rate_fields",new TreeMap<>(rateFields));m.put("malformed",malformed);
        m.put("capacity_drops",capacityDrops);m.put("reference_packets",referencePackets);m.put("reference_worn_packets",referenceWornPackets);
        List<Integer> counts=new ArrayList<>();for(List<Chunk> c:channels){int n=0;for(Chunk r:c)n+=r.samples.length;counts.add(n);}m.put("samples_by_path",counts);return m;
    }
    public LiveOpticalAudit snapshot(){
        LiveOpticalAudit s=new LiveOpticalAudit();s.candidateFrames=candidateFrames;s.malformed=malformed;s.capacityDrops=capacityDrops;
        s.referencePackets=referencePackets;s.referenceWornPackets=referenceWornPackets;s.referenceHr.addAll(referenceHr);
        s.rateFields.putAll(rateFields);s.frameLengths.putAll(frameLengths);
        for(int i=0;i<10;i++)s.channels.get(i).addAll(channels.get(i)); // Chunks are immutable.
        return s;
    }
    static double median(List<Double> a){if(a.isEmpty())return Double.NaN;Collections.sort(a);int n=a.size();return n%2==1?a.get(n/2):(a.get(n/2-1)+a.get(n/2))/2;}
    static Map<String,Object> dist(List<Double> a){Map<String,Object> m=new LinkedHashMap<>();m.put("n",a.size());if(a.isEmpty()){m.put("median",null);m.put("max",null);}else{m.put("median",median(a));m.put("max",Collections.max(a));}return m;}
    static boolean compatible(Chunk a,Chunk b,boolean state){return (a.fs==25||a.fs==50) && a.fs==b.fs && a.fs==a.flagRate && b.fs==b.flagRate
            && Math.abs((b.tick-a.tick)/32768.0-a.samples.length/(double)a.fs)<=2.0/32768
            && (b.index-a.index & 0xffffffffL)==1 && (!state || a.config.equals(b.config));}
    /** Descriptive signal checks on a worker. Returned maps have no samples or individual HR. */
    public Map<String,Object> analyze(){
        Map<String,Object> all=progress();all.put("bp_suitability_validated",false);all.put("sample_timestamp_alignment_confirmed",false);
        List<Double> hr=new ArrayList<>();for(int n:referenceHr)hr.add((double)n);double reference=median(hr);
        List<Map<String,Object>> reports=new ArrayList<>();
        for(int path=0;path<10;path++){
            List<Chunk> rows=new ArrayList<>(channels.get(path));rows.sort(Comparator.comparingLong((Chunk c)->c.tick).thenComparingLong(c->c.index));
            Map<String,Object> r=new LinkedHashMap<>();r.put("block",path/2);r.put("detector_path",path%2);r.put("buffers",rows.size());
            int n=0,flat=0,rail=0,configChanges=0,gaps=0,overlaps=0,rateDisagreements=0,duplicates=0;
            List<Double> steps=new ArrayList<>(),edgeRatios=new ArrayList<>(),effectiveRates=new ArrayList<>();Set<Integer> sources=new TreeSet<>();
            List<List<Chunk>> chains=new ArrayList<>(),temporalChains=new ArrayList<>();
            for(int i=0;i<rows.size();i++){
                Chunk c=rows.get(i);n+=c.samples.length;sources.add(c.source);if(c.fs!=c.flagRate)rateDisagreements++;
                int min=c.samples[0],max=min;for(int j=0;j<c.samples.length;j++){int x=c.samples[j];min=Math.min(min,x);max=Math.max(max,x);if(x== -524288 || x==524287)rail++;if(j>0)steps.add(Math.abs((double)x-c.samples[j-1]));}if(min==max)flat++;
                if(i>0){Chunk p=rows.get(i-1);double dt=(c.tick-p.tick)/32768.0;
                    if(dt==0 && c.index==p.index)duplicates++;
                    if(dt>0)effectiveRates.add(p.samples.length/dt);
                    if(!c.config.equals(p.config))configChanges++;
                    if(p.fs==25 || p.fs==50){double gap=dt-p.samples.length/(double)p.fs;if(gap>2.0/32768)gaps++;else if(gap< -2.0/32768)overlaps++;}
                    if(compatible(p,c,true)){
                        List<Double> local=new ArrayList<>();for(int j=1;j<p.samples.length;j++)local.add(Math.abs((double)p.samples[j]-p.samples[j-1]));for(int j=1;j<c.samples.length;j++)local.add(Math.abs((double)c.samples[j]-c.samples[j-1]));Collections.sort(local);
                        if(!local.isEmpty()){double p95=local.get((int)Math.floor(.95*(local.size()-1)));if(p95>0)edgeRatios.add(Math.abs((double)c.samples[0]-p.samples[p.samples.length-1])/p95);}
                    }
                }
                appendChain(chains,c,true);appendChain(temporalChains,c,false);
            }
            r.put("samples",n);r.put("flat_buffers",flat);r.put("adc_rail_samples",rail);r.put("source_ids",sources);r.put("config_change_pairs",configChanges);
            r.put("timestamp_gap_pairs",gaps);r.put("timestamp_overlap_pairs",overlaps);r.put("rate_field_flag_disagreements",rateDisagreements);r.put("duplicate_buffer_pairs",duplicates);
            r.put("effective_samples_per_timestamp_second",dist(effectiveRates));r.put("edge_jump_over_intra_p95",dist(edgeRatios));
            List<Chunk> best=longest(chains),temporal=longest(temporalChains);
            r.put("longest_same_config_samples",sampleCount(best));r.put("longest_temporal_samples",sampleCount(temporal));
            r.put("longest_same_config_seconds",best.isEmpty()?0:((best.get(0).fs==25||best.get(0).fs==50)?sampleCount(best)/(double)best.get(0).fs:null));
            if(!best.isEmpty() && (best.get(0).fs==25||best.get(0).fs==50) && best.get(0).fs==best.get(0).flagRate && sampleCount(best)>=best.get(0).fs*8){
                double[] values=new double[sampleCount(best)];int at=0;for(Chunk c:best)for(int x:c.samples)values[at++]=x;
                r.put("periodicity",periodicity(values,best.get(0).fs,reference));
            }else r.put("periodicity",null);
            reports.add(r);
        }
        all.put("paths",reports);all.put("device_reference_samples",referenceHr.size());return all;
    }
    static void appendChain(List<List<Chunk>> chains,Chunk c,boolean state){
        if(!chains.isEmpty()){List<Chunk> last=chains.get(chains.size()-1);if(compatible(last.get(last.size()-1),c,state)){last.add(c);return;}}
        List<Chunk> next=new ArrayList<>();next.add(c);chains.add(next);
    }
    static int sampleCount(List<Chunk> a){int n=0;for(Chunk c:a)n+=c.samples.length;return n;}
    static List<Chunk> longest(List<List<Chunk>> chains){List<Chunk> best=Collections.emptyList();for(List<Chunk> a:chains)if(sampleCount(a)>sampleCount(best))best=a;return best;}
    static Map<String,Object> periodicity(double[] x,int fs,double reference){
        Map<String,Object> m=new LinkedHashMap<>();int n=x.length;double duration=n/(double)fs,mean=0;for(double v:x)mean+=v;mean/=n;
        double xbar=(n-1)/2.0,cov=0,den=0;for(int i=0;i<n;i++){cov+=(i-xbar)*(x[i]-mean);den+=(i-xbar)*(i-xbar);}double slope=den>0?cov/den:0;
        double[] y=new double[n];double energy=0;for(int i=0;i<n;i++){y[i]=(x[i]-mean-slope*(i-xbar))*(.5-.5*Math.cos(2*Math.PI*i/(n-1)));energy+=y[i]*y[i];}
        m.put("duration_seconds",duration);m.put("frequency_resolution_hz",1/duration);m.put("sample_interval_ms",1000.0/fs);
        if(energy==0){m.put("flat",true);m.put("cardiac_band_power_fraction",null);return m;}
        double sum=0,peak=-1,peakF=Double.NaN;
        for(int k=(int)Math.ceil(.5*duration);k<=(int)Math.floor(4*duration);k++){
            double re=0,im=0;for(int i=0;i<n;i++){double angle=2*Math.PI*k*i/n;re+=y[i]*Math.cos(angle);im-=y[i]*Math.sin(angle);}double power=re*re+im*im;sum+=power;
            if(power>peak){peak=power;peakF=k/duration;}
        }
        m.put("cardiac_band_power_fraction",Math.max(0,Math.min(1,sum/(.5*n*energy))));m.put("peak_band_power_fraction",sum>0?peak/sum:null);
        m.put("device_hr_absolute_percent_error",Double.isFinite(reference)&&sum>0?Math.abs(peakF*60-reference)/reference*100:null);
        if(Double.isFinite(reference)){
            int lag=(int)Math.round(fs*60/reference);double xy=0,xx=0,yy=0;
            for(int i=lag;i<n;i++){double a=x[i]-mean,b=x[i-lag]-mean;xy+=a*b;xx+=a*a;yy+=b*b;}
            m.put("autocorrelation_at_device_period",xx>0&&yy>0?xy/Math.sqrt(xx*yy):null);
        }
        return m;
    }
    /** Local UI only; never include in report/export. */
    public int[] preview(){
        for(List<Chunk> channel:channels)if(!channel.isEmpty()){
            int count=Math.min(150,sampleCount(channel)),skip=sampleCount(channel)-count;int[] out=new int[count];int at=0,seen=0;
            for(Chunk c:channel)for(int x:c.samples){if(seen++>=skip)out[at++]=x;}return out;
        }return new int[0];
    }
    public List<int[]> previewWindows(){
        for(List<Chunk> channel:channels)if(!channel.isEmpty()){
            List<int[]> out=new ArrayList<>();for(int i=Math.max(0,channel.size()-6);i<channel.size();i++)out.add(channel.get(i).samples.clone());return out;
        }return Collections.emptyList();
    }
}
