package org.whoopbp.probe;

import java.util.*;

public final class LiveOpticalAuditTest {
    static int checks;
    static void check(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
    static byte[] frame(int sec,int shift){
        byte[] in=new byte[2128];in[0]=0x2b;in[1]=20;in[2]=(byte)128;
        Gen5Probe.put32(in,3,sec);Gen5Probe.put32(in,7,1000+sec+shift);in[15]=25;in[18]=25;in[25]=1;in[32]=2;
        for(int j=0;j<25;j++){
            int v=(int)Math.round(10000+1000*Math.sin(2*Math.PI*1.5*(sec+j/25.0)));
            Gen5Probe.put32(in,18+21+4*j,v);Gen5Probe.put32(in,18+221+4*j,v*2);
        }return in;
    }
    public static void main(String[] args){
        LiveOpticalAudit a=new LiveOpticalAudit();
        for(int sec=0;sec<16;sec++){
            a.accept(frame(sec,0),sec*1000000000L);
            byte[] hr=new byte[20];hr[0]=0x28;hr[1]=2;hr[8]=90;hr[18]=1;a.accept(hr,0);
        }
        Map<String,Object> result=a.snapshot().analyze();List<?> paths=(List<?>)result.get("paths");Map<?,?> first=(Map<?,?>)paths.get(0);
        check(((Number)first.get("samples")).intValue()==400,"correct buffer count");
        check(((Number)first.get("timestamp_gap_pairs")).intValue()==0,"continuous timing");
        Map<?,?> period=(Map<?,?>)first.get("periodicity");
        check(((Number)period.get("device_hr_absolute_percent_error")).doubleValue()<1,"known sinusoid matches reference");
        check(((Number)period.get("autocorrelation_at_device_period")).doubleValue()>.95,"periodic shape");
        check(!result.toString().contains("10000"),"summary does not export samples");
        check(Boolean.FALSE.equals(result.get("live_samples_persisted")),"RAM only");
        LiveOpticalAudit broken=new LiveOpticalAudit();broken.accept(frame(0,0),0);broken.accept(frame(1,1),0);
        Map<?,?> gap=(Map<?,?>)((List<?>)broken.analyze().get("paths")).get(0);
        check(((Number)gap.get("timestamp_gap_pairs")).intValue()==1,"missing second is not filled");
        byte[] wrong=frame(2,0);wrong[1]=21;broken.accept(wrong,0);check(broken.candidateFrames==2,"other record not misclassified");
        wrong=Arrays.copyOf(frame(2,0),2127);broken.accept(wrong,0);check(broken.malformed==1,"truncated buffer abstains");
        System.out.println("PASS "+checks+" RAM-only live waveform checks");
    }
}
