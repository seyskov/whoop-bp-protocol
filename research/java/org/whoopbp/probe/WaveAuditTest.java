package org.whoopbp.probe;

import java.util.*;

public final class WaveAuditTest {
    static int n;
    static void check(boolean x,String why){n++;if(!x)throw new AssertionError(why);}
    static byte[] window(int seq,int rate,int gapSeconds,int first,int step){
        byte[] in=new byte[76];in[0]=0x2f;in[1]=26;in[2]=(byte)(rate==25?128:0);
        Gen5Probe.put32(in,3,seq);Gen5Probe.put32(in,7,1000+gapSeconds);Gen5Probe.put32(in,15,first);
        for(int i=0;i<24;i++){in[19+i*2]=(byte)step;in[20+i*2]=(byte)(step>>8);}return in;
    }
    static int value(Map<String,Object> m,String key){return ((Number)m.get(key)).intValue();}
    public static void main(String[] args){
        WaveAudit audit=new WaveAudit();byte[] a=window(1,25,0,100,10),b=window(2,25,1,350,10);
        audit.accept(b);audit.accept(a);audit.accept(a);Map<String,Object> s=audit.summary();
        check(value(s,"windows")==2,"out-of-order sorted");check(value(s,"exact_replays")==1,"replays");
        check(value(s,"timestamp_compatible_pairs")==1,"one-second/25Hz compatibility");
        Map<?,?> ratios=(Map<?,?>)s.get("edge_jump_over_adjacent_intra_p95");check(((Number)ratios.get("median")).doubleValue()==1,"normal boundary equals normal delta");
        byte[] conflict=a.clone();conflict[19]++;audit.accept(conflict);check(value(audit.summary(),"conflicting_replays")==1,"conflict recorded, first never replaced");
        audit.accept(window(3,25,3,800,10));check(value(audit.summary(),"timestamp_gap_pairs")==1,"missing second not interpolated");
        audit.accept(window(4,50,4,1050,10));check(value(audit.summary(),"rate_change_pairs")==1,"rate switch split");
        audit.accept(window(5,50,5,1300,10));check(value(audit.summary(),"timestamp_gap_pairs")==2,"25 samples at 50Hz do not cover a second");
        byte[] live=window(6,25,6,0,0);live[0]=0x2b;audit.accept(live);check(audit.size()==5,"no live persistence");
        byte[] sat=window(6,25,6,0,32767);audit.accept(sat);check(value(audit.summary(),"saturated_delta_windows")==1,"lossy deltas count");
        check(value(audit.summary(),"impossible_windows")==1,"impossible cumsum count");
        audit.accept(window(7,25,7,10,0));check(value(audit.summary(),"flat_windows")==1,"flat window");
        WaveAudit negative=new WaveAudit();negative.accept(window(1,25,0, -524288,0));check(value(negative.summary(),"adc_rail_samples")==25,"absolute ADC clipping independent of delta saturation");
        Map<String,Object> exported=audit.export();check(!exported.toString().contains("tick="),"no absolute timestamp in export");
        check(Boolean.FALSE.equals(audit.summary().get("continuity_proven")),"compatible timestamps never claim proven physical continuity");
        System.out.println("PASS "+n+" waveform integrity/continuity checks");
    }
}
