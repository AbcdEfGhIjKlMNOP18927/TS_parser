package com.company;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.SQLIntegrityConstraintViolationException;
import java.util.*;
class TsParser{
    private byte[] data;
    public TsParser(String x) throws IOException {
        Path p=Paths.get(x);
        data=Files.readAllBytes(p);
    }
    public List<Byte> getPayload(int p_id){
        List<Byte> l=new ArrayList<>();
        int flag=0,cc=0;
        for(int i=0;i<data.length;i+=188){
            byte sync = data[i];
            boolean te = false, pusi = false, tp = false;
            te = (data[i + 1] & (1 << 7)) > 0;
            pusi = (data[i + 1] & (1 << 6)) > 0;
            tp = (data[i + 1] & (1 << 5)) > 0;
            int pid = ((((1 << 5) - 1) & (data[i + 1])) * 256) + data[i + 2];
            int transport_scrambling_control = (((1 << 2) - 1) & (data[i + 3] >> (6)));
            int adaptation_field = (((1 << 2) - 1) & (data[i + 3] >> (4)));
            int continuity_counter = ((1 << 4) - 1) & (data[i + 3]);
            int payloadstartindex=i+4;
            if(adaptation_field==2)
                continue;
            if(adaptation_field==3){
                payloadstartindex+=data[i+4]+1;
            }
            if(pid==p_id){
                //System.out.println("PUSI : "+ pusi +" adaptation field" + adaptation_field);
                if(pusi==true){
                    payloadstartindex+=data[payloadstartindex]+1;
                    // System.out.println(payloadstartindex);
                    if(flag==0){
                        cc=continuity_counter;
                        flag=1;
                        for(int y=payloadstartindex;y<i+188;y++){
                            l.add( data[y]);
                        }
                    }
                    else break;
                }
                else{
                    if(continuity_counter==cc+1 || (continuity_counter==0 && cc==15)){
                        for(int y=payloadstartindex;y<i+188;y++){
                            l.add(data[y]);
                        }
                        cc=continuity_counter;
                    }
                }
            }
        }
        return l;
    }
    public List<Integer> patAnalysis(){
        List<Byte> payloadPat=getPayload(0);
        List<Integer> pmtPid=new ArrayList<>();
        int tableid=payloadPat.get(0);
        int section_index_indicator=(payloadPat.get(1)>>7)&1;
        int section_length=(((1<<3)-1) & (payloadPat.get(1)))*256+(payloadPat.get(2));
        int transport_stream_id=(payloadPat.get(3)*256)+payloadPat.get(4);
        int version_number=((1<<5)-1)&(payloadPat.get(5)>>1);
        int current_next_indicator=(payloadPat.get(5)&1);
        int section_number=payloadPat.get(6);
        int last_section=payloadPat.get(7);
//        System.out.println("table_id: "+tableid);
//        System.out.println("section_index_indicator : "+section_index_indicator);
//        System.out.println("section_length : "+section_length);
//        System.out.println("transport_stream_id : "+transport_stream_id);
//        System.out.println("version_number : "+version_number);
//        System.out.println("current_next_indicator : "+current_next_indicator);
//        System.out.println("section_number : "+section_number);
//        System.out.println("last_section : "+last_section);
        for(int i=8;i<(8+section_length-9);i+=4) {
            int program_number = payloadPat.get(i) * 256 + payloadPat.get(i + 1);
            if (program_number != 0) {
                int program_id = (((1 << 5) - 1) & (payloadPat.get(i + 2))) * 256 + (payloadPat.get(i + 3));
                pmtPid.add(program_id);
                //System.out.println("Program Number : " + program_number + " Program_id : " + program_id);
            }
        }
        int crc_start_idx=3+section_length-4;
        //int temp=(int) ((v.get(crc_start_idx)<<24)|(v.get(crc_start_idx+1)<<16)|(v.get(crc_start_idx+2)<<8)|(v.get(crc_start_idx+3)));
        int crc=payloadPat.get(crc_start_idx)*16777216+payloadPat.get(crc_start_idx+1)*65536+payloadPat.get(crc_start_idx+2)*256+payloadPat.get(crc_start_idx+3);
        return pmtPid;
    }
    public List<List<Integer>> pmtAnalysis(){
        List<List<Integer>> res=new ArrayList<>();
        List<Integer> pmt_pid=patAnalysis();
        for(int i=0;i<pmt_pid.size();i++){
            List<Byte> l=getPayload(pmt_pid.get(i));
            int tableid=l.get(0);
            int section_syntax_indicator=(l.get(1)>>7)&1;
            int section_length=(((1<<4)-1)&l.get(1))*256+(l.get(2));
            int program_number=l.get(3)*256+l.get(4);
            int version_number=((1<<5)-1)&(l.get(5)>>1);
            int current_next_indicator=l.get(5)&1;
            int section_number=l.get(6);
            int last_section=l.get(7);
            int pcr_pid=(((1<<5)-1)&(l.get(8)))*256+l.get(9);
            int program_info_length=(((1<<4)-1)&(l.get(10)))*256+l.get(11);
//            System.out.println("table_id : "+tableid);
//            System.out.println("section_syntax_indicator : "+section_syntax_indicator);
//            System.out.println("section_length : "+section_length);
//            System.out.println("program_number : "+program_number);
//            System.out.println("version_number : "+version_number);
//            System.out.println("current_next_indicator : "+current_next_indicator);
//            System.out.println("section_number : "+section_number);
//            System.out.println("last_section : "+last_section);
//            System.out.println("PCR_PID : "+pcr_pid);
//            System.out.println("program_info_length : "+program_info_length);
            int endIndex=2+section_length-4;
            int startindex=12+program_info_length;
            List<Integer> temp=new ArrayList<>();
            while(startindex<endIndex){
                int stream_type=l.get(startindex);
                startindex++;
                int elementary_pid=(((1<<5)-1)&(l.get(startindex)))*256+l.get(startindex+1);
                startindex+=2;
                int es_info_lenght=(((1<<4)-1)&(l.get(startindex)))*256+l.get(startindex+1);
                startindex++;
                startindex+=(es_info_lenght+1);
                temp.add(elementary_pid);
//                System.out.println("stream type : " + stream_type);
//                System.out.println("elemantary pid : "+elementary_pid);
//                System.out.println("es_info_length :" +es_info_lenght);
            }
            res.add(temp);
            int crc=l.get(startindex)*16777216 + l.get(startindex+1)*65536 +l.get(startindex+2)*256 + l.get(startindex+3);
            //System.out.println("CRC : "+crc);
        }
        return res;
    }
    public List<List<Byte>> getPackets(int PID){
        int prev_cc=0;
        List<List<Byte>> l=new ArrayList<>();
        List<Byte> newtemp=new ArrayList<>();
        for(int i=0;i<data.length;i+=188) {
            byte sync = data[i];
            boolean te = false, pusi = false, tp = false;
            te = (data[i + 1] & (1 << 7)) > 0;
            pusi = (data[i + 1] & (1 << 6)) > 0;
            tp = (data[i + 1] & (1 << 5)) > 0;
            int pid = ((((1 << 5) - 1) & (data[i + 1])) * 256) + data[i + 2];
            int continuity_counter = ((1 << 4) - 1) & (data[i + 3]);
            int transport_scrambling_control = (((1 << 2) - 1) & (data[i + 3] >> (6)));
            int adaptation_field = (((1 << 2) - 1) & (data[i + 3] >> (4)));
            int payloadstartindex = i + 4;
            if (adaptation_field == 2)
                continue;
            if (adaptation_field == 3) {
                payloadstartindex += data[i + 4] + 1;
            }
            if (pid == PID) {
                if(pusi==true){
                    if(newtemp.size()>0){
                        l.add(new ArrayList<>(newtemp));
                        newtemp=new ArrayList<>();
                    }
                    prev_cc=continuity_counter;
                    for(int j=payloadstartindex;j<i+188;j++){
                        newtemp.add(data[j]);
                    }
                }
                else{
                    if(continuity_counter==prev_cc+1 || (continuity_counter==0 && prev_cc==15)){
                        for(int j=payloadstartindex;j<i+188;j++){
                            newtemp.add(data[j]);
                        }
                        prev_cc=continuity_counter;
                    }
                }
            }
        }
        l.add(newtemp);
        return l;
    }
    public void PES_Analysis_payload_extraction(List<Byte> l,List<Byte> store){
          //System.out.println("size : "+l.size());
          int packet_start_code_prefix=l.get(0)*65536+l.get(1)*256+l.get(2);
          int stream_id=l.get(3);
          int PES_packet_length=l.get(4)*256+l.get(5);
          if(stream_id!=188 && stream_id!=191 && stream_id!=240 && stream_id!=241 && stream_id!=255 && stream_id!=242 && stream_id!=248 && stream_id!=190) {
              int reserved_10 = ((1 << 2) - 1) & (l.get(6) >> 6);
              int PES_scrambling_control = ((1 << 2) - 1) & (l.get(6) >> 4);
              int PES_priority = (l.get(6) >> 3) & 1;
              int data_alignment_indicator = (l.get(6) >> 2) & 1;
              int copyright = (l.get(6) >> 1) & 1;
              int original_or_copy = l.get(6) & 1;
              int PTS_DTS_flags = (l.get(7) >> 6) & 3;
              int ESCR_flag = (l.get(7) >> 5) & 1;
              int ES_rate_flag = (l.get(7) >> 4) & 1;
              int DSM_trick_mode_flag = (l.get(7) >> 3) & 1;
              int additional_copy_info_flag = (l.get(7) >> 2) & 1;
              int PES_CRC_flag = (l.get(7) >> 1) & 1;
              int PES_extension_flag = l.get(7) & 1;
              int PES_header_data_length = l.get(8);
//              System.out.println(packet_start_code_prefix);
//              System.out.println(stream_id);
//              System.out.println(PES_packet_length);
//              System.out.println(reserved_10);
              int index = 9;
              int endindex = 5 + PES_packet_length;

              if (PTS_DTS_flags == 2) {
                  int reserved_4_0010 = ((1 << 4) - 1) & (l.get(index) >> 4);
                  int PTS = ((1 << 3) - 1) & (l.get(index) >> 1);
                  int marker_bit = l.get(index) & 1;
                  index++;
                  int PTS1 = l.get(index) * 128 + (l.get(index + 1) >> 1) & ((1 << 7) - 1);
                  int marker_bit1 = l.get(index + 1) & 1;
                  index += 2;
                  int PTS2 = l.get(index) * 128 + (l.get(index + 1) >> 1) & ((1 << 7) - 1);
                  int marker_bit2 = l.get(index + 1) & 1;
                  index += 2;
                  // final pts= pts*2^30+pts1*2^15+pts2;
              }
              if (PTS_DTS_flags == 3) {
                  int reserved_4_0010 = ((1 << 4) - 1) & (l.get(index) >> 4);
                  int PTS = ((1 << 3) - 1) & (l.get(index) >> 1);
                  int marker_bit = l.get(index) & 1;
                  index++;
                  int PTS1 = l.get(index) * 128 + (l.get(index + 1) >> 1) & ((1 << 7) - 1);
                  int marker_bit1 = l.get(index + 1) & 1;
                  index += 2;
                  int PTS2 = l.get(index) * 128 + (l.get(index + 1) >> 1) & ((1 << 7) - 1);
                  int marker_bit2 = l.get(index + 1) & 1;
                  index += 2;
                  int reserved_4_0001 = ((1 << 4) - 1) & (l.get(index) >> 4);
                  int DTS = ((1 << 3) - 1) & (l.get(index) >> 1);
                  int marker_bit_dts = l.get(index) & 1;
                  index++;
                  int DTS1 = l.get(index) * 128 + (l.get(index + 1) >> 1) & ((1 << 7) - 1);
                  int marker_bit1_dts = l.get(index + 1) & 1;
                  index += 2;
                  int DTS2 = l.get(index) * 128 + (l.get(index + 1) >> 1) & ((1 << 7) - 1);
                  int marker_bit2_dts = l.get(index + 1) & 1;
                  index += 2;
                  // final pts= pts*2^30+pts1*2^15+pts2;
                  // final dts= dts*2^30+dts1*2^15+dts2;
              }
              if (ESCR_flag == 1) {
                  int ESCR_base = ((1 << 3) - 1) & (l.get(index) >> 3);
                  int ESCR_base1 = (l.get(index) & 3) * 8192 + (l.get(index + 1)) * 32 + ((l.get(index + 2) >> 3) & ((1 << 5) - 1));
                  index += 2;
                  int ESCR_base2 = (l.get(index) & 3) * 8192 + (l.get(index + 1)) * 32 + ((l.get(index + 2) >> 3) & ((1 << 5) - 1));
                  index += 2;
                  int ESCR_extension = (l.get(index) & 3) * 128 + ((l.get(index + 1) >> 1) & ((1 << 7) - 1));
                  index += 2;
              }
              if (ES_rate_flag == 1) {
                  int ES_rate = (l.get(index) & ((1 << 7) - 1)) * 32768 + (l.get(index + 1) * 128) + (l.get(index + 2) >> 1 & ((1 << 7) - 1));
                  index += 3;
              }
              if (DSM_trick_mode_flag == 1) {
                  int trick_mode_control = (l.get(index) >> 5) & ((1 << 3) - 1);
                  index++;
              }
              if (additional_copy_info_flag == 1) {
                  index++;
              }
              if (PES_CRC_flag == 1) {
                  index += 2;
              }
              if (PES_extension_flag == 1) {
                  int PES_private_data_flag = (l.get(index) >> 7) & 1;
                  int pack_header_filed_flag = (l.get(index) >> 6) & 1;
                  int program_packet_sequence_counter_flag = (l.get(index) >> 5) & 1;
                  int P_STD_buffer_flag = (l.get(index) >> 4) & 1;
                  int PES_extension_flag_2 = l.get(index) & 1;
                  if (PES_private_data_flag == 1) {
                      index += 17;
                  }
                  if (pack_header_filed_flag == 1) {
                      index++;
                  }
                  if (program_packet_sequence_counter_flag == 1) {
                      index += 2;
                  }
                  if (P_STD_buffer_flag == 1) {
                      index += 2;
                  }
                  if (PES_extension_flag_2 == 1) {
                      int PES_extension_field_length = (l.get(index) & ((1 << 7) - 1));
                      index += (PES_extension_field_length + 1);
                  }
              }
              for(int i=9+PES_header_data_length;i<=endindex;i++){
                  store.add(l.get(i));
              }
          }
          else if(stream_id==188 || stream_id==191 || stream_id==240 || stream_id==241 || stream_id==255 || stream_id==242 || stream_id==248){
              for(int i=6;i<=5+PES_packet_length;i++) {
                  store.add(l.get(i));
              }
          }
          else if(stream_id==190){
              for(int i=6;i<=5+PES_packet_length;i++) {
                  //padding_byte
              }
          }

    }
    public void createBinaryfile() throws IOException {
        List<List<Integer>> list=pmtAnalysis();
        for(int i=0;i<list.size();i++){
            for(int j=0;j<list.get(i).size();j++){
                List<List<Byte>> packets=getPackets(list.get(i).get(j));
                //System.out.println(list.get(i).get(j));
                List<Byte> pesPacketPayload=new ArrayList<>();
                for(int x=0;x<packets.size();x++){
                    PES_Analysis_payload_extraction(packets.get(x),pesPacketPayload);
                }
                byte []arr=new byte[pesPacketPayload.size()];
                for(int l=0;l<pesPacketPayload.size();l++){
                    arr[l]=pesPacketPayload.get(l);
                }
                //System.out.println(pesPacketPayload.size());
                File f=new File("D:\\binary_files\\"+"Program_"+(i+1)+"_file"+(j+1)+".dat");
                FileOutputStream fos = new FileOutputStream(f);
                fos.write(arr);
                fos.close();
            }
        }
    }
}
public class Main {
    public static void PMT_analysis(byte[] data,List<Integer> l) {
        int cnt=0;
        // doubt whether a single pmt fits in single ts packet
        // assumed single packet contain one pmt
//        for(int i=0;i<l.size();i++){
//            System.out.println(l.get(i));
//        }
//        System.out.println("*************_______________________________********************");
        for (int j = 0; j < l.size(); j++) {
            for (int i = 0; i < data.length; i += 188) {
                byte sync = data[i];
                boolean te = false, pusi = false, tp = false;
                te = (data[i + 1] & (1 << 7)) > 0;
                pusi = (data[i + 1] & (1 << 6)) > 0;
                tp = (data[i + 1] & (1 << 5)) > 0;
                int pid = ((((1 << 5) - 1) & (data[i + 1])) * 256) + data[i + 2];
                int continuity_counter = ((1 << 4) - 1) & (data[i + 3]);
                int transport_scrambling_control = (((1 << 2) - 1) & (data[i + 3] >> (4)));
                int adaptation_field = (((1 << 2) - 1) & (data[i + 3] >> (6)));
                if(pid==l.get(j)){
//                    System.out.println("pusi = "+pusi);
//                    for(int k=i+4;k<=i+40;k++){
//                        System.out.println(data[k]);
//                    }
                    //System.out.println("adaptation field : " +adaptation_field);
                    System.out.println("***************************");
                    int table_id=data[i+5];
                    int section_syntax_indicator=(data[i+6]>>7)&1;
                    int section_length=(((1<<4)-1) &data[i+6])*256+data[i+7];
                    int program_number=data[i+8]*256+data[i+9];
                    int version_number=((1<<5)-1)&(data[i+10]>>1);
                    int current_next_indicator=(data[i+10]&1);
                    int section_number=data[i+11];
                    int last_section_number=data[i+12];
                    int PCR_PID=(((1<<5)-1)&data[i+13])*256+data[i+14];
                    int programinfolength=(((1<<4)-1)&data[i+15])*256+data[i+16];
                    System.out.println("i+5 : "+(i+5));
                    System.out.println(table_id);
                    System.out.println(section_syntax_indicator);
                    System.out.println(section_length);
                    System.out.println(program_number);
                    System.out.println(version_number);
                    System.out.println(current_next_indicator);
                    System.out.println(section_number);
                    System.out.println(last_section_number);
                    System.out.println(PCR_PID);
                    System.out.println(programinfolength);
                    //System.out.println(data[i+1]);
                    for(int x=i+17;x<i+17+programinfolength;x++){
                        // descriptor
                    }
                    for(int y=i+17+programinfolength;y<=i+26;y+=5){
//                        System.out.println("y = "+y);
//                         System.out.println(data[y] +" ," +data[y+1]+" ,"+data[y+2]+", "+data[y+3]+", "+data[y+4]);
                         int stream_type=data[y];
                         int elementary_pid=(((1<<5)-1)&(data[y+1]))*256+data[y+2];
                         int es_info_lenght=(((1<<4)-1)&data[y+3])*256+data[y+4];
                        System.out.println("stream type : " + stream_type);
                        System.out.println("elementary pid : " +elementary_pid);
                        System.out.println("ES Info Length : "+es_info_lenght);
                    }
                    cnt++;
                    if(cnt==4) {
                        break;
                    }
                }
            }
        }

    }
    public static void main(String[] args) throws IOException {
          String s="C:\\Users\\Abhishek\\Desktop\\new project\\ts-sample-video\\ts.ts";
          TsParser t=new TsParser(s);
          t.createBinaryfile();
//        List<Byte> l=t.getPayload(256);
//        t.PES_Analysis(l);
//        System.out.println("*******************************************");
        //List<Byte> list=new ArrayList<>();
//        Path path = Paths.get("C:\\Users\\Abhishek\\Desktop\\new project\\ts-sample-video\\ts.ts");
//        byte[] data = Files.readAllBytes(path);
//        int cnt=1;
//        for(int i=0;i< data.length;i+=188){
//            byte sync = data[i];
//            boolean te = false, pusi = false, tp = false;
//            te = (data[i + 1] & (1 << 7)) > 0;
//            pusi = (data[i + 1] & (1 << 6)) > 0;
//            tp = (data[i + 1] & (1 << 5)) > 0;
//            int pid = ((((1 << 5) - 1) & (data[i + 1])) * 256) + data[i + 2];
//            int transport_scrambling_control = (((1 << 2) - 1) & (data[i + 3] >> (6)));
//            int adaptation_field = (((1 << 2) - 1) & (data[i + 3] >> (4)));
//            int continuity_counter = ((1 << 4) - 1) & (data[i + 3]);
//            int payloadstartindex = i + 4;
//            if (adaptation_field == 2)
//                continue;
//            if (adaptation_field == 3) {
//                System.out.println(data[i+4]);
//                payloadstartindex += data[i + 4] + 1;
//            }
//            System.out.println("packet number : "+cnt);
//            System.out.println(pid+" "+adaptation_field);
//            cnt++;
//            if(cnt>=10)
//                break;
//        }
        //System.out.println(cnt1+" :: "+cnt2);
//        int prev_cc=0;
//        List<List<Byte>> l=new ArrayList<>();
//        List<Byte> newtemp=new ArrayList<>();
//        for(int i=0;i<data.length;i+=188) {
//            byte sync = data[i];
//            boolean te = false, pusi = false, tp = false;
//            te = (data[i + 1] & (1 << 7)) > 0;
//            pusi = (data[i + 1] & (1 << 6)) > 0;
//            tp = (data[i + 1] & (1 << 5)) > 0;
//            int pid = ((((1 << 5) - 1) & (data[i + 1])) * 256) + data[i + 2];
//            int continuity_counter = ((1 << 4) - 1) & (data[i + 3]);
//            int transport_scrambling_control = (((1 << 2) - 1) & (data[i + 3] >> (6)));
//            int adaptation_field = (((1 << 2) - 1) & (data[i + 3] >> (4)));
//            int payloadstartindex = i + 4;
//            if (adaptation_field == 2)
//                continue;
//            if (adaptation_field == 3) {
//                payloadstartindex += data[i + 4] + 1;
//            }
//            if (pid == 256) {
//                if(pusi==true){
//                    if(newtemp.size()>0){
//                        l.add(new ArrayList<>(newtemp));
//                        newtemp=new ArrayList<>();
//                    }
//                    prev_cc=continuity_counter;
//                    for(int j=payloadstartindex;j<i+188;j++){
//                        newtemp.add(data[j]);
//                    }
//                }
//                else{
//                    if(continuity_counter==prev_cc+1 || (continuity_counter==0 && prev_cc==15)){
//                        for(int j=payloadstartindex;j<i+188;j++){
//                            newtemp.add(data[j]);
//                        }
//                        prev_cc=continuity_counter;
//                    }
//                }
//            }
//        }
//        l.add(newtemp);
//        for(int i=0;i<l.size();i++){
//            System.out.println(l.get(i).get(0)+","+l.get(i).get(1)+","+l.get(i).get(2));
//        }

    }
}
