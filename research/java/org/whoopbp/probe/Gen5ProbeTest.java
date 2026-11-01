package org.whoopbp.probe;

import java.util.*;

public final class Gen5ProbeTest {
    private static int checks;
    static void check(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
    static byte[] hex(String h){byte[] b=new byte[h.length()/2];for(int i=0;i<b.length;i++)b[i]=(byte)Integer.parseInt(h.substring(i*2,i*2+2),16);return b;}
    static void forbidden(int op,byte[] body){try{Gen5Probe.command(0,op,body);throw new AssertionError("allowed "+op);}catch(IllegalArgumentException expected){checks++;}}
    public static void main(String[] args){
        // Same independently captured CRC-valid R26 golden as the Dart suite.
        byte[] gold=hex("aa015000010035412f1a80ad418401f0a3266aae470100c3c5050068faccfa8dfb46fc8bfd4cfebafedafe6dff56ffd5fffbff37ff6afce5f9d7f8dffa5efc98fddbfe5afe84fe15ff5cff405fb33c50080101006cb67c17");
        for(int split=0;split<=gold.length;split++){
            Gen5Probe.Stats s=new Gen5Probe.Stats();Gen5Probe.Parser p=new Gen5Probe.Parser(s::accept);
            p.feed(Arrays.copyOfRange(gold,0,split));p.feed(Arrays.copyOfRange(gold,split,gold.length));
            check(s.pipRecords==1,"fragment split "+split);check(p.pendingBytes()==0,"drained");
            check(s.declaredPpgRates.get("25")==1,"rate from flags, not sample count");
        }
        Gen5Probe.Stats stats=new Gen5Probe.Stats();Gen5Probe.Parser p=new Gen5Probe.Parser(stats::accept);
        byte[] broken=gold.clone();broken[31]^=1;
        p.feed(broken);p.feed(gold);check(stats.validFrames==1,"bad CRC not counted");check(p.badPayloads==1,"bad payload counted");
        p.feed(gold);check(stats.pipRecords==1,"replayed history deduplicated");
        byte[] in=Arrays.copyOfRange(gold,8,gold.length-4);in[2]=0;in[3]++;
        in[19]=(byte)0xff;in[20]=0x7f; // positive saturation rail
        p.feed(Gen5Probe.frame(in,true));check(stats.pipRailWindows==1,"positive saturation rejected");check(stats.declaredPpgRates.get("50")==1,"50Hz flag");
        in[3]++;in[19]=0;in[20]=(byte)0x80; // negative saturation rail
        p.feed(Gen5Probe.frame(in,true));check(stats.pipRailWindows==2,"negative saturation rejected");
        in[3]++;in[0]=0x2b;p.feed(Gen5Probe.frame(in,true));check(stats.pipRecords==3,"live not decoded as historical");
        byte[] optical=new byte[2128];optical[0]=0x2f;optical[1]=20;optical[15]=25;
        optical[18]=25;Gen5Probe.put32(optical,7,1000);p.feed(Gen5Probe.frame(optical,true));
        check(stats.opticalRecords==1 && stats.opticalSamples==50,"both detector paths counted");
        byte[] unknown=gold.clone();unknown[1]=2;int crc=Gen5Probe.crc16(unknown,0,6);unknown[6]=(byte)crc;unknown[7]=(byte)(crc>>8);
        int before=stats.validFrames;p.feed(unknown);check(stats.validFrames==before && p.unknownRevision==1,"unknown frame revision abstains");
        for(int op:new int[]{0x17,0x19,0x1d,0x20,0x21,0x78,0x77,0x99,0x9a,0x8e,0x8f,0x90,0x0a,0x0f})forbidden(op,new byte[]{1});
        forbidden(Gen5Probe.RAW_START,new byte[]{1});forbidden(Gen5Probe.RAW_START,new byte[]{2,0,0,0,0});
        check(Gen5Probe.command(1,Gen5Probe.RAW_START,Gen5Probe.rawBody(45000)).length==20,"bounded rev2 raw command");
        check(Gen5Probe.command(2,Gen5Probe.HELLO,new byte[]{1})[10]==(byte)0x91,"hello wire opcode");
        check(!stats.report().toString().contains("1780917232"),"report excludes absolute record timestamps");
        System.out.println("PASS "+checks+" protocol/fragmentation/saturation/safety checks");
    }
}
