package org.whoopbp.probe;

import java.util.*;
import java.util.zip.CRC32;

/** Diagnostic subset of this repository's Dart protocol, not a BP estimator.
 * Reference: lib/src/{band,framing,commands,gen5_records,control}.dart.
 * No non-volatile writes, time changes, flash ACKs, trim, or firmware commands.
 */
public final class Gen5Probe {
    private Gen5Probe() {}
    public static final String SERVICE = "fd4b0001-cce1-4033-93ce-002d5875f58a";
    public static final String WRITE = "fd4b0002-cce1-4033-93ce-002d5875f58a";
    public static final String[] NOTIFY = {
        "fd4b0003-cce1-4033-93ce-002d5875f58a",
        "fd4b0004-cce1-4033-93ce-002d5875f58a",
        "fd4b0005-cce1-4033-93ce-002d5875f58a"
    };
    public static final int HELLO=0x91, CLOCK=0x0b, RANGE=0x22,
        FLAG=0x80, HISTORY=0x16, ABORT=0x14, RAW_START=0x51, RAW_STOP=0x52;
    public static final List<String> FLAGS = Collections.unmodifiableList(Arrays.asList(
        "enable_r22_packets", "enable_r22_v2_packets", "enable_r22_v3_packets",
        "enable_r22_v4_packets", "enable_r22_v5_packets", "enable_r22_v6_packets",
        "enable_r22_v8_packets", "disable_pip_r26_packets"));

    public static byte[] command(int seq, int op, byte[] body) {
        // An allow-list, not merely a deny-list. In particular 0x17 ACK and
        // 0x78 SET_CONFIG can NEVER be emitted by this probe.
        switch(op) {
            case HELLO: case FLAG:
                if (body.length == 0 || body[0] != 1) throw new IllegalArgumentException("revision");
                if (op==HELLO && body.length!=1) throw new IllegalArgumentException("hello");
                if (op==FLAG && body.length!=33) throw new IllegalArgumentException("flag");
                break;
            case CLOCK: case RANGE: case HISTORY:
                if (body.length!=0) throw new IllegalArgumentException("empty body required"); break;
            case ABORT: if(body.length!=1 || body[0]!=0) throw new IllegalArgumentException("abort"); break;
            case RAW_STOP: if(body.length!=1 || body[0]!=1) throw new IllegalArgumentException("stop"); break;
            case RAW_START:
                if(body.length!=5 || body[0]!=2 || u32(body,1)<1 || u32(body,1)>60000)
                    throw new IllegalArgumentException("raw must be revision 2 and <=60s");
                break;
            default: throw new IllegalArgumentException("opcode forbidden by probe: "+op);
        }
        byte[] inner=new byte[(3+body.length+3)&~3];
        inner[0]=0x23; inner[1]=(byte)seq; inner[2]=(byte)op;
        System.arraycopy(body,0,inner,3,body.length);
        return frame(inner, false);
    }
    public static byte[] flagBody(String name) {
        if(!FLAGS.contains(name)) throw new IllegalArgumentException("flag not in diagnostic list");
        byte[] b=new byte[33]; b[0]=1;
        for(int i=0;i<name.length();i++) b[i+1]=(byte)name.charAt(i);
        return b;
    }
    public static byte[] rawBody(int ms) {
        if(ms<1 || ms>60000) throw new IllegalArgumentException("duration");
        byte[] b=new byte[5]; b[0]=2; put32(b,1,ms); return b;
    }
    public static int u16(byte[] b,int p) {return (b[p]&255)|((b[p+1]&255)<<8);}
    public static long u32(byte[] b,int p) {return (long)u16(b,p)|((long)u16(b,p+2)<<16);}
    public static int i16(byte[] b,int p) {return (short)u16(b,p);}
    static void put32(byte[] b,int p,long n){for(int i=0;i<4;i++)b[p+i]=(byte)(n>>(8*i));}
    public static int crc16(byte[] b,int from,int len) {
        int c=0xffff;
        for(int j=from;j<from+len;j++){c^=b[j]&255;for(int i=0;i<8;i++) c=(c&1)!=0?(c>>>1)^0xa001:c>>>1;}
        return c;
    }
    static long crc32(byte[] b,int from,int len){CRC32 c=new CRC32();c.update(b,from,len);return c.getValue();}
    /** Package-private fixture builder; this is NOT a transport command builder. */
    static byte[] frame(byte[] inner,boolean inbound){
        if(inner.length%4!=0)throw new IllegalArgumentException("padding");
        byte[] f=new byte[inner.length+12]; f[0]=(byte)0xaa;f[1]=1;
        int len=inner.length+4;f[2]=(byte)len;f[3]=(byte)(len>>8);
        f[4]=(byte)(inbound?1:0);f[5]=(byte)(inbound?0:1);
        int c=crc16(f,0,6);f[6]=(byte)c;f[7]=(byte)(c>>8);
        System.arraycopy(inner,0,f,8,inner.length);put32(f,8+inner.length,crc32(inner,0,inner.length));return f;
    }

    public interface Sink {void accept(byte[] inner);}
    /** One parser per characteristic; fragments from different GATT streams never mix. */
    public static final class Parser {
        private byte[] pending=new byte[0];
        public int badHeaders, badPayloads, unknownRevision, discardedBytes;
        private final Sink sink;
        public Parser(Sink s){sink=s;}
        public void feed(byte[] bytes){
            if(bytes.length>8192){discardedBytes+=bytes.length;return;}
            byte[] all=Arrays.copyOf(pending,pending.length+bytes.length);
            System.arraycopy(bytes,0,all,pending.length,bytes.length);int at=0;
            while(at+8<=all.length){
                if((all[at]&255)!=0xaa){at++;discardedBytes++;continue;}
                int declared=u16(all,at+2), total=8+declared;
                if(declared<4 || total>4096 || declared%4!=0 || crc16(all,at,6)!=u16(all,at+6)){
                    badHeaders++;at++;continue;
                }
                if(at+total>all.length)break;
                if(crc32(all,at+8,declared-4)!=u32(all,at+total-4)) {badPayloads++;at++;continue;}
                if(all[at+1]!=1){unknownRevision++;at+=total;continue;}
                sink.accept(Arrays.copyOfRange(all,at+8,at+total-4));at+=total;
            }
            pending=Arrays.copyOfRange(all,at,all.length);
            if(pending.length>8192){discardedBytes+=pending.length;pending=new byte[0];}
        }
        public int pendingBytes(){return pending.length;}
    }

    /** Shape/availability counters only. No raw waves, vitals, serials, or absolute dates in report. */
    public static final class Stats {
        public final WaveAudit waveAudit=new WaveAudit();
        public final Map<String,Integer> packetTypes=new TreeMap<>(), historicalVersions=new TreeMap<>(),
            liveRecordCandidates=new TreeMap<>(), declaredPpgRates=new TreeMap<>(), opticalRates=new TreeMap<>();
        public final Set<Long> seenPpg=new HashSet<>(), seenOptical=new HashSet<>();
        public final TreeSet<Long> ppgTimesQ15=new TreeSet<>(), opticalTimesQ15=new TreeSet<>();
        public int validFrames, historicalFrames, malformedOptical, malformedPip, pipRecords,
            pipRailWindows, pipOutOfRangeWindows, pipAcceptedWindows, opticalRecords,
            opticalSamples, opticalRailSamples, opticalActivePaths, opticalBadCounts;
        public final Set<String> opticalConfigs=new HashSet<>();
        public String firmware=null;
        public boolean helloSucceeded, sawHistoryEnd;
        public Boolean helloWorn=null;
        public int helloObservations;
        public int rawStartStatus=-1, rawStopStatus=-1;
        static void count(Map<String,Integer> m,String k){m.put(k,m.getOrDefault(k,0)+1);}
        public void accept(byte[] in){
            if(in.length==0)return;validFrames++;int type=in[0]&255;
            count(packetTypes,String.format(Locale.ROOT,"0x%02x",type));
            if(type==0x24 && in.length>=5){
                int op=in[2]&255,status=in[4]&255;
                if(op==RAW_START)rawStartStatus=status;if(op==RAW_STOP)rawStopStatus=status;
                // Successful gen5 hello has a 104-byte body after the 5-byte header.
                if(op==HELLO && status==1 && in.length>=109){
                    helloSucceeded=true;int b=5;
                    firmware=(in[b+91]&255)+"."+(in[b+92]&255)+"."+(in[b+93]&255)+"."+u32(in,b+94);
                    int worn=in[b+102]&255;helloWorn=worn==0?Boolean.FALSE:(worn==1?Boolean.TRUE:null);helloObservations++;
                }
            }
            if(type==0x2b && in.length>1)count(liveRecordCandidates,Integer.toString(in[1]&255));
            // A live wrapper is never silently decoded as historical data.
            if(type!=0x2f || in.length<13)return;
            waveAudit.accept(in);
            historicalFrames++;int v=in[1]&255;
            count(historicalVersions,Integer.toString(v));
            if(v==18 || v==20 || v==21 || v==26)count(declaredPpgRates,(in[2]&128)!=0?"25":"50");
            long id=u32(in,3), t=u32(in,7)*32768+u16(in,11);
            // No unbounded per-frame retention during the bounded diagnostic.
            if(v==26 && seenPpg.size()<10000 && seenPpg.add(id)){
                if(in.length!=76 || u16(in,11)>=32768){malformedPip++;return;}
                pipRecords++;ppgTimesQ15.add(t);
                long value=(int)u32(in,15);boolean rail=false,out=value< -524288 || value>524287;
                for(int p=19;p<67;p+=2){int d=i16(in,p);rail|=d== -32768 || d==32767;value+=d;out|=value< -524288 || value>524287;}
                if(rail)pipRailWindows++;if(out)pipOutOfRangeWindows++;
                if(in[74]==1)pipAcceptedWindows++;
            }
            if(v==20 && seenOptical.size()<10000 && seenOptical.add(id)){
                if(in.length!=2128 || u16(in,11)>=32768){malformedOptical++;return;}
                opticalRecords++;opticalTimesQ15.add(t);count(opticalRates,Integer.toString(u16(in,15)));
                for(int b=0;b<5;b++){
                    int start=18+b*422,n=in[start]&255;
                    if(n>50){opticalBadCounts++;continue;}if(n==0)continue;
                    for(int path=0;path<2;path++){
                        opticalActivePaths++;
                        // Keep metadata fingerprints only in RAM, report their count.
                        opticalConfigs.add(b+":"+path+":"+Arrays.toString(Arrays.copyOfRange(in,start+1,start+21)));
                        int base=start+21+path*200;
                        for(int j=0;j<n;j++){
                            long raw=u32(in,base+4*j)&0xfffff;int sample=(int)(raw>=0x80000?raw-0x100000:raw);
                            opticalSamples++;if(sample== -524288 || sample==524287)opticalRailSamples++;
                        }
                    }
                }
            }
        }
        static Map<String,Object> timing(TreeSet<Long> times){
            Map<String,Object> out=new LinkedHashMap<>();out.put("unique_timestamps",times.size());
            if(times.isEmpty()){out.put("span_seconds",null);out.put("max_record_gap_seconds",null);return out;}
            out.put("span_seconds",(times.last()-times.first())/32768.0);
            long prev=times.first(),maxGap=0;for(long t:times){maxGap=Math.max(maxGap,t-prev);prev=t;}
            out.put("max_record_gap_seconds",maxGap/32768.0);return out;
        }
        public Map<String,Object> report(){
            Map<String,Object> r=new LinkedHashMap<>();r.put("schema",1);r.put("blood_pressure_estimation_validated",false);
            r.put("raw_samples_persisted",false);r.put("persistent_config_writes",0);r.put("history_trim_acks",0);
            r.put("hello_succeeded",helloSucceeded);r.put("firmware",firmware);r.put("valid_frames",validFrames);
            r.put("last_hello_worn",helloWorn);r.put("hello_observations",helloObservations);r.put("waveform_audit",waveAudit.summary());
            r.put("packet_types",packetTypes);r.put("historical_versions",historicalVersions);
            r.put("live_record_candidates_not_decoded",liveRecordCandidates);r.put("declared_ppg_rate_flags_hz",declaredPpgRates);
            r.put("raw_start_status",rawStartStatus);r.put("raw_stop_status",rawStopStatus);
            Map<String,Object> p=new LinkedHashMap<>();p.put("records",pipRecords);p.put("malformed",malformedPip);
            p.put("samples_per_window",25);p.put("windows_with_saturated_delta",pipRailWindows);
            p.put("windows_with_impossible_reconstruction",pipOutOfRangeWindows);p.put("band_morphology_pass_windows",pipAcceptedWindows);
            p.put("timing",timing(ppgTimesQ15));r.put("r26_pip",p);
            Map<String,Object> o=new LinkedHashMap<>();o.put("records",opticalRecords);o.put("malformed",malformedOptical);
            o.put("rates_hz",opticalRates);o.put("sample_count",opticalSamples);o.put("adc_rail_samples",opticalRailSamples);
            o.put("active_detector_paths",opticalActivePaths);o.put("invalid_block_counts",opticalBadCounts);
            o.put("distinct_front_end_configurations",opticalConfigs.size());o.put("timing",timing(opticalTimesQ15));r.put("r20_optical",o);
            r.put("absence_interpretation","not_observed_in_this_bounded_capture_is_not_absent_on_device");
            return r;
        }
    }
}
